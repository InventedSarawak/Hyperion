package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// DefaultSubscriptionIndex is the index alert rules are percolated from.
const DefaultSubscriptionIndex = "hyperion-subscriptions"

// maxCandidates bounds one percolation. A rule set larger than this is a
// scaling problem to solve deliberately, not silently by truncating alerts.
const maxCandidates = 1000

// Percolator implements ports.AlertMatcher on Elasticsearch's percolator.
//
// A normal index stores documents and you search them with a query. A
// percolator index stores *queries* and you "search" it with a document,
// getting back the queries that document satisfies. That inversion is what
// lets one pass over an incoming vulnerability find every interested
// subscriber, instead of replaying every rule as a separate search.
type Percolator struct {
	http    *http.Client
	baseURL string
	name    string
}

// NewPercolator builds the matcher. An empty index name falls back to
// DefaultSubscriptionIndex.
func NewPercolator(httpClient *http.Client, baseURL, indexName string) *Percolator {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	if indexName == "" {
		indexName = DefaultSubscriptionIndex
	}
	return &Percolator{
		http:    httpClient,
		baseURL: strings.TrimRight(baseURL, "/"),
		name:    indexName,
	}
}

// percolatorMapping declares both the query field and the shape of the
// documents that will be percolated against it. Elasticsearch needs the
// document fields up front so it can parse and validate stored queries when
// they are registered rather than when they are run.
const percolatorMapping = `{
  "mappings": {
    "properties": {
      "query":             {"type": "percolator"},
      "subscription_id":   {"type": "keyword"},
      "tenant":            {"type": "keyword"},
      "cve_id":            {"type": "keyword", "fields": {"text": {"type": "text"}}},
      "title":             {"type": "text"},
      "description":       {"type": "text"},
      "severity_rank":     {"type": "integer"},
      "package_keys":      {"type": "keyword"},
      "ecosystems":        {"type": "keyword"}
    }
  }
}`

// Ready reports whether the cluster answers, creating the index if absent.
func (p *Percolator) Ready(ctx context.Context) error {
	resp, err := p.do(ctx, http.MethodHead, "/"+p.name, nil)
	if err != nil {
		return fmt.Errorf("percolator: head index: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	createResp, err := p.do(ctx, http.MethodPut, "/"+p.name, strings.NewReader(percolatorMapping))
	if err != nil {
		return fmt.Errorf("percolator: create index: %w", err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(createResp.Body, 512))
		return fmt.Errorf("percolator: create index status %d: %s",
			createResp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// Register stores a subscription's rule as a percolator query.
//
// The query is built from the structured rule rather than accepting raw query
// DSL from a caller: a subscriber describes what they care about, and this
// decides how to ask Elasticsearch. Letting rules carry DSL would make every
// subscription a way to run arbitrary queries against the cluster.
func (p *Percolator) Register(ctx context.Context, s model.Subscription) error {
	if err := s.Validate(); err != nil {
		return err
	}

	body, err := json.Marshal(map[string]any{
		"query":           ruleQuery(s.Rule),
		"subscription_id": s.ID,
		"tenant":          s.Tenant,
	})
	if err != nil {
		return fmt.Errorf("percolator: marshal rule %s: %w", s.ID, err)
	}

	// refresh=true so a rule is matchable immediately after it is created —
	// otherwise a subscription can miss the very advisory that prompted it.
	path := fmt.Sprintf("/%s/_doc/%s?refresh=true", p.name, s.ID)
	resp, err := p.do(ctx, http.MethodPut, path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("percolator: register %s: %w", s.ID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("percolator: register %s status %d: %s",
			s.ID, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}

// Deregister removes a rule from the index.
func (p *Percolator) Deregister(ctx context.Context, id string) error {
	path := fmt.Sprintf("/%s/_doc/%s?refresh=true", p.name, id)
	resp, err := p.do(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("percolator: deregister %s: %w", id, err)
	}
	defer resp.Body.Close()

	// A rule that is already gone is the state the caller wanted.
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("percolator: deregister %s status %d: %s",
			id, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}

// Match percolates a vulnerability and returns the subscriptions it satisfies.
func (p *Percolator) Match(ctx context.Context, v model.Vulnerability) ([]string, error) {
	body, err := json.Marshal(map[string]any{
		"size": maxCandidates,
		"query": map[string]any{
			"percolate": map[string]any{
				"field":    "query",
				"document": percolateDocument(v),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("percolator: marshal document %s: %w", v.CVEID, err)
	}

	resp, err := p.do(ctx, http.MethodPost, "/"+p.name+"/_search", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("percolator: match %s: %w", v.CVEID, err)
	}
	defer resp.Body.Close()

	// No rules have ever been registered, so the index does not exist yet.
	// Nobody is subscribed; that is an empty result, not a failure.
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("percolator: match %s status %d: %s",
			v.CVEID, resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out struct {
		Hits struct {
			Hits []struct {
				Source struct {
					SubscriptionID string `json:"subscription_id"`
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("percolator: decode match %s: %w", v.CVEID, err)
	}

	ids := make([]string, 0, len(out.Hits.Hits))
	for _, hit := range out.Hits.Hits {
		if hit.Source.SubscriptionID != "" {
			ids = append(ids, hit.Source.SubscriptionID)
		}
	}
	return ids, nil
}

// ruleQuery translates a domain rule into Elasticsearch query DSL. Conditions
// are AND-ed via `filter`, matching the domain's meaning exactly.
func ruleQuery(rule model.AlertRule) map[string]any {
	filters := make([]map[string]any, 0, 4)

	if term := strings.TrimSpace(rule.Term); term != "" {
		filters = append(filters, map[string]any{
			"multi_match": map[string]any{
				"query":  term,
				"fields": []string{"cve_id.text", "title", "description"},
			},
		})
	}
	if rule.MinSeverity.IsRanked() {
		filters = append(filters, map[string]any{
			"range": map[string]any{
				"severity_rank": map[string]any{"gte": severityRankOf(rule.MinSeverity)},
			},
		})
	}
	if keys := packageKeys(rule.Packages); len(keys) > 0 {
		filters = append(filters, map[string]any{
			"terms": map[string]any{"package_keys": keys},
		})
	}
	if len(rule.Ecosystems) > 0 {
		names := make([]string, 0, len(rule.Ecosystems))
		for _, e := range rule.Ecosystems {
			names = append(names, e.String())
		}
		filters = append(filters, map[string]any{
			"terms": map[string]any{"ecosystems": names},
		})
	}

	// A rule always has at least one condition (the domain rejects empty
	// ones), so this bool is never a match-all by accident.
	return map[string]any{"bool": map[string]any{"filter": filters}}
}

// percolateDocument shapes a vulnerability the way the mapping expects.
func percolateDocument(v model.Vulnerability) map[string]any {
	return map[string]any{
		"cve_id":        v.CVEID,
		"title":         v.Title,
		"description":   v.Description,
		"severity_rank": severityRankOf(v.TopSeverity()),
		"package_keys":  packageKeys(v.AffectedPackages),
		"ecosystems":    ecosystemNames(v.AffectedPackages),
	}
}

// severityRankOf mirrors the domain's ordering as an integer the index can
// compare. Unranked severities sort below every threshold, so an unscored
// finding never satisfies a "at least this bad" rule.
func severityRankOf(s model.Severity) int {
	for rank, level := range []model.Severity{
		model.SeverityNone, model.SeverityLow, model.SeverityMedium,
		model.SeverityHigh, model.SeverityCritical,
	} {
		if s == level {
			return rank
		}
	}
	return -1
}

func packageKeys(refs []valueobject.PackageRef) []string {
	keys := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.Validate() == nil {
			keys = append(keys, r.Key())
		}
	}
	return keys
}

func ecosystemNames(refs []valueobject.PackageRef) []string {
	seen := make(map[string]struct{}, len(refs))
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		name := r.Ecosystem.String()
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

// do issues one request against the cluster.
func (p *Percolator) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, p.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return p.http.Do(req)
}
