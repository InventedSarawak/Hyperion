// Package elasticsearch is an OUTBOUND adapter implementing ports.SearchIndex
// on Elasticsearch. All query DSL and document shaping lives here; the rest of
// cortex sees only domain types.
package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// DefaultIndexName is the index cortex writes vulnerabilities to.
const DefaultIndexName = "hyperion-vulnerabilities"

// Index talks to Elasticsearch over its REST API.
type Index struct {
	http    *http.Client
	baseURL string
	name    string
}

// New builds an Elasticsearch-backed search index. A nil httpClient gets a
// sane default; an empty index name falls back to DefaultIndexName.
func New(httpClient *http.Client, baseURL, indexName string) *Index {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	if indexName == "" {
		indexName = DefaultIndexName
	}
	return &Index{
		http:    httpClient,
		baseURL: strings.TrimRight(baseURL, "/"),
		name:    indexName,
	}
}

// Ready reports whether the cluster answers, creating the index if absent.
func (i *Index) Ready(ctx context.Context) error {
	if err := i.ping(ctx); err != nil {
		return err
	}
	return i.ensureIndex(ctx)
}

func (i *Index) ping(ctx context.Context) error {
	resp, err := i.do(ctx, http.MethodGet, "/", nil)
	if err != nil {
		return fmt.Errorf("elasticsearch: ping: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("elasticsearch: ping status %d", resp.StatusCode)
	}
	return nil
}

// indexMapping keeps the text fields analyzed for relevance scoring and the
// identifiers exact for filtering.
const indexMapping = `{
  "mappings": {
    "properties": {
      "cve_id":      {"type": "keyword", "fields": {"text": {"type": "text"}}},
      "aliases":     {"type": "keyword"},
      "kind":        {"type": "keyword"},
      "title":       {"type": "text"},
      "description": {"type": "text"},
      "references":  {"type": "keyword"},
      "sources":     {"type": "keyword"},
      "packages":      {"type": "keyword"},
      "package_names": {"type": "text"},
      "max_score":   {"type": "float"},
      "severity":    {"type": "keyword"},
      "published_at":{"type": "date"},
      "modified_at": {"type": "date"}
    }
  }
}`

// ensureIndex creates the index when it does not already exist.
func (i *Index) ensureIndex(ctx context.Context) error {
	resp, err := i.do(ctx, http.MethodHead, "/"+i.name, nil)
	if err != nil {
		return fmt.Errorf("elasticsearch: head index: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return i.ensureFields(ctx)
	}

	createResp, err := i.do(ctx, http.MethodPut, "/"+i.name, strings.NewReader(indexMapping))
	if err != nil {
		return fmt.Errorf("elasticsearch: create index: %w", err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(createResp.Body, 512))
		return fmt.Errorf("elasticsearch: create index status %d: %s", createResp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// addedFields are fields introduced after the index was first created.
// Elasticsearch allows adding fields to a live mapping, so an index created by
// an older cortex is upgraded in place instead of having to be rebuilt.
// Documents written before the upgrade lack the fields until they are
// re-indexed (cortex -reindex).
const addedFields = `{
  "properties": {
    "packages":      {"type": "keyword"},
    "package_names": {"type": "text"},
    "aliases":       {"type": "keyword"},
    "kind":          {"type": "keyword"}
  }
}`

// ensureFields adds any fields an existing index is missing. It is idempotent:
// re-declaring a field with the same type is a no-op.
func (i *Index) ensureFields(ctx context.Context) error {
	resp, err := i.do(ctx, http.MethodPut, "/"+i.name+"/_mapping", strings.NewReader(addedFields))
	if err != nil {
		return fmt.Errorf("elasticsearch: update mapping: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("elasticsearch: update mapping status %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// Index upserts the searchable document for v, keyed by CVE id.
func (i *Index) Index(ctx context.Context, v model.Vulnerability) error {
	doc, err := json.Marshal(toDocument(v))
	if err != nil {
		return fmt.Errorf("elasticsearch: marshal doc %s: %w", v.CVEID, err)
	}

	path := fmt.Sprintf("/%s/_doc/%s", i.name, v.CVEID)
	resp, err := i.do(ctx, http.MethodPut, path, bytes.NewReader(doc))
	if err != nil {
		return fmt.Errorf("elasticsearch: index %s: %w", v.CVEID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("elasticsearch: index %s status %d: %s", v.CVEID, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// maxWindow is Elasticsearch's default index.max_result_window: from+size
// beyond it is rejected. Offset paging cannot reach past it.
const maxWindow = 10000

// relevanceQuery is the scoring query. Five clauses are OR-ed so a query works
// the way an analyst expects:
//   - best_fields with AUTO fuzziness tolerates typos ("log4shel" -> log4shell)
//   - phrase_prefix matches partial tokens ("log4j" -> "Log4j2")
//   - a term match on cve_id or any alias makes an exact id lookup the top
//     hit, whichever of the finding's ids was typed and in whatever case
//   - a match on affected package names ranks a record that *affects* the
//     library above one that merely uses the word: "next" is both Next.js and
//     "fix next buffer leak" in a kernel changelog, and text alone cannot tell
//   - a term match on the exact package key ("npm:next") for precise lookups
//
// Fields are weighted so the CVE id outranks packages, which outrank the
// title, which outranks the body.
func relevanceQuery(text string) map[string]any {
	id := valueobject.NormalizeID(text)
	return map[string]any{
		"bool": map[string]any{
			"minimum_should_match": 1,
			"should": []any{
				map[string]any{"multi_match": map[string]any{
					"query":  text,
					"fields": []string{"cve_id.text^3", "title^2", "description"},
					// Two leading characters must match exactly. Without
					// it AUTO fuzziness lets "next" match "text", which is
					// a typo nobody made.
					"fuzziness":     "AUTO",
					"prefix_length": 2,
				}},
				map[string]any{"multi_match": map[string]any{
					"query":  text,
					"fields": []string{"title^2", "description"},
					"type":   "phrase_prefix",
				}},
				map[string]any{"term": map[string]any{"cve_id": map[string]any{
					"value": id, "boost": 5,
				}}},
				map[string]any{"term": map[string]any{"aliases": map[string]any{
					"value": id, "boost": 5,
				}}},
				// Affecting a library is categorical — a record either
				// does or it does not — so it is scored as a flat bonus
				// rather than as more text. A boosted *text* match still
				// competes on repetition, and a changelog saying "next" four
				// times would outrank the advisory that is actually about
				// Next.js. The bonus sits above any text score this corpus
				// produces (the best real matches score ~35), so affected
				// records form the upper band and text orders within it.
				map[string]any{"constant_score": map[string]any{
					"filter": map[string]any{"match": map[string]any{"package_names": text}},
					"boost":  packageBonus,
				}},
				map[string]any{"constant_score": map[string]any{
					"filter": map[string]any{"term": map[string]any{"packages": strings.ToLower(text)}},
					"boost":  packageBonus,
				}},
			},
		},
	}
}

// packageBonus is the flat score for "this record affects the library you
// named". See relevanceQuery for why it is constant and why it is this size.
const packageBonus = 50

// newestFirst orders by publication date. The CVE id breaks ties, because
// many records share a publication timestamp to the second and an unordered
// tie makes paging repeat or skip results.
var newestFirst = []any{
	map[string]any{"published_at": map[string]any{"order": "desc", "missing": "_last"}},
	map[string]any{"cve_id": "asc"},
}

// searchBody builds the request for one page.
func searchBody(q model.SearchQuery) map[string]any {
	text := strings.TrimSpace(q.Text)
	body := map[string]any{"from": q.Offset, "size": q.Size}

	switch {
	case q.Sort == model.SortNewest && text == "":
		// "The newest findings": a bounded, paged read, not a scan.
		body["query"] = map[string]any{"match_all": map[string]any{}}
		body["sort"] = newestFirst
	case q.Sort == model.SortNewest:
		body["query"] = relevanceQuery(text)
		body["sort"] = newestFirst
		body["track_scores"] = true // still report how well each one matched
	default:
		body["query"] = relevanceQuery(text)
		body["sort"] = append([]any{"_score"}, newestFirst...)
	}
	if len(q.Kinds) > 0 {
		body["query"] = map[string]any{"bool": map[string]any{
			"must":   body["query"],
			"filter": kindFilter(q.Kinds, text),
		}}
	}
	return body
}

// kindFilter keeps the requested kinds of finding, plus any record whose id
// is exactly what was typed: asking for an id by name is asking for that
// record, whatever it is. A document indexed before kinds existed has none,
// and counts as a vulnerability — which is all it could have been then.
func kindFilter(kinds []model.FindingKind, text string) map[string]any {
	names := make([]string, 0, len(kinds))
	var should []any
	for _, k := range kinds {
		names = append(names, string(k))
		if k == model.KindVulnerability {
			should = append(should, map[string]any{"bool": map[string]any{
				"must_not": map[string]any{"exists": map[string]any{"field": "kind"}},
			}})
		}
	}
	should = append(should, map[string]any{"terms": map[string]any{"kind": names}})
	if id := valueobject.NormalizeID(text); id != "" {
		should = append(should,
			map[string]any{"term": map[string]any{"cve_id": id}},
			map[string]any{"term": map[string]any{"aliases": id}},
		)
	}
	return map[string]any{"bool": map[string]any{"should": should, "minimum_should_match": 1}}
}

// Search runs one page of a query.
func (i *Index) Search(ctx context.Context, q model.SearchQuery) (model.SearchPage, error) {
	if q.Offset+q.Size > maxWindow {
		return model.SearchPage{}, fmt.Errorf(
			"elasticsearch: results beyond the first %d cannot be paged to; narrow the query", maxWindow)
	}

	raw, err := json.Marshal(searchBody(q))
	if err != nil {
		return model.SearchPage{}, fmt.Errorf("elasticsearch: marshal query: %w", err)
	}

	resp, err := i.do(ctx, http.MethodPost, "/"+i.name+"/_search", bytes.NewReader(raw))
	if err != nil {
		return model.SearchPage{}, fmt.Errorf("elasticsearch: search: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return model.SearchPage{}, fmt.Errorf("elasticsearch: search status %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out searchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return model.SearchPage{}, fmt.Errorf("elasticsearch: decode search: %w", err)
	}

	page := model.SearchPage{
		Hits:              make([]model.SearchHit, 0, len(out.Hits.Hits)),
		Total:             out.Hits.Total.Value,
		TotalIsLowerBound: out.Hits.Total.Relation == "gte",
	}
	for _, h := range out.Hits.Hits {
		score := 0.0
		if h.Score != nil {
			score = *h.Score
		}
		page.Hits = append(page.Hits, model.SearchHit{Vulnerability: h.Source.toDomain(), Score: score})
	}
	return page, nil
}

func (i *Index) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, i.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return i.http.Do(req)
}

// --- document mapping: domain <-> elasticsearch ---

type document struct {
	CVEID       string       `json:"cve_id"`
	Aliases     []string     `json:"aliases,omitempty"`
	Kind        string       `json:"kind,omitempty"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Scores      []model.CVSS `json:"scores"`
	References  []string     `json:"references"`
	Sources     []string     `json:"sources"`
	// Packages are the affected libraries' graph keys ("npm:next");
	// PackageNames their bare names, analyzed so "next" finds Next.js.
	Packages     []string   `json:"packages,omitempty"`
	PackageNames []string   `json:"package_names,omitempty"`
	MaxScore     float64    `json:"max_score"`
	Severity     string     `json:"severity"`
	PublishedAt  *time.Time `json:"published_at,omitempty"`
	ModifiedAt   *time.Time `json:"modified_at,omitempty"`
}

func toDocument(v model.Vulnerability) document {
	// Denormalize the worst score so results can be sorted/filtered cheaply.
	var maxScore float64
	severity := string(model.SeverityUnknown)
	for _, s := range v.Scores {
		if s.BaseScore >= maxScore {
			maxScore = s.BaseScore
			severity = string(s.Severity)
		}
	}
	kind := v.Kind
	if kind == "" {
		kind = model.KindVulnerability
	}
	return document{
		CVEID:        v.CVEID,
		Aliases:      v.Aliases,
		Kind:         string(kind),
		Title:        v.Title,
		Description:  v.Description,
		Scores:       v.Scores,
		References:   v.References,
		Sources:      v.Sources,
		Packages:     packageKeys(v.AffectedPackages),
		PackageNames: packageNames(v.AffectedPackages),
		MaxScore:     maxScore,
		Severity:     severity,
		PublishedAt:  nullableTime(v.PublishedAt),
		ModifiedAt:   nullableTime(v.ModifiedAt),
	}
}

func (d document) toDomain() model.Vulnerability {
	kind := model.FindingKind(d.Kind)
	if kind == "" {
		kind = model.KindVulnerability
	}
	v := model.Vulnerability{
		CVEID:       d.CVEID,
		Aliases:     d.Aliases,
		Kind:        kind,
		Title:       d.Title,
		Description: d.Description,
		Scores:      d.Scores,
		References:  d.References,
		Sources:     d.Sources,

		AffectedPackages: packagesFromKeys(d.Packages),
	}
	if d.PublishedAt != nil {
		v.PublishedAt = *d.PublishedAt
	}
	if d.ModifiedAt != nil {
		v.ModifiedAt = *d.ModifiedAt
	}
	return v
}

type searchResponse struct {
	Hits struct {
		Total struct {
			Value    int64  `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		Hits []struct {
			// A pointer, because a sort without _score returns null here.
			Score  *float64 `json:"_score"`
			Source document `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// packageNames returns the affected libraries' bare names, deduplicated.
func packageNames(refs []valueobject.PackageRef) []string {
	seen := make(map[string]struct{}, len(refs))
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.Validate() != nil {
			continue
		}
		if _, ok := seen[r.Name]; ok {
			continue
		}
		seen[r.Name] = struct{}{}
		out = append(out, r.Name)
	}
	return out
}

// packagesFromKeys rebuilds references from stored "ecosystem:name" keys.
// The version range is not indexed, so it does not come back.
func packagesFromKeys(keys []string) []valueobject.PackageRef {
	if len(keys) == 0 {
		return nil
	}
	out := make([]valueobject.PackageRef, 0, len(keys))
	for _, key := range keys {
		ecosystem, name, found := strings.Cut(key, ":")
		if !found {
			ecosystem, name = "", key
		}
		out = append(out, valueobject.NewPackageRef(ecosystem, name, ""))
	}
	return out
}

// idsPageSize is how many ids are fetched per request when listing the index.
const idsPageSize = 1000

// IDs lists every document id. It walks with search_after on the id rather
// than from/size, which Elasticsearch caps at 10,000 — an index larger than
// that could not otherwise be listed in full.
func (i *Index) IDs(ctx context.Context) ([]string, error) {
	var (
		ids   []string
		after []any
	)
	for {
		body := map[string]any{
			"size":    idsPageSize,
			"_source": false,
			"query":   map[string]any{"match_all": map[string]any{}},
			"sort":    []any{map[string]any{"cve_id": "asc"}},
		}
		if after != nil {
			body["search_after"] = after
		}
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("elasticsearch: marshal ids query: %w", err)
		}

		resp, err := i.do(ctx, http.MethodPost, "/"+i.name+"/_search", bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("elasticsearch: list ids: %w", err)
		}
		var out struct {
			Hits struct {
				Hits []struct {
					ID   string `json:"_id"`
					Sort []any  `json:"sort"`
				} `json:"hits"`
			} `json:"hits"`
		}
		status := resp.StatusCode
		decodeErr := json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if status >= 300 {
			return nil, fmt.Errorf("elasticsearch: list ids status %d", status)
		}
		if decodeErr != nil {
			return nil, fmt.Errorf("elasticsearch: decode ids: %w", decodeErr)
		}

		for _, h := range out.Hits.Hits {
			ids = append(ids, h.ID)
		}
		if len(out.Hits.Hits) < idsPageSize {
			return ids, nil
		}
		after = out.Hits.Hits[len(out.Hits.Hits)-1].Sort
	}
}

// Delete removes one document. An absent document is the state the caller
// wanted, so a 404 is success.
func (i *Index) Delete(ctx context.Context, id string) error {
	resp, err := i.do(ctx, http.MethodDelete, fmt.Sprintf("/%s/_doc/%s", i.name, url.PathEscape(id)), nil)
	if err != nil {
		return fmt.Errorf("elasticsearch: delete %s: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("elasticsearch: delete %s status %d: %s", id, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
