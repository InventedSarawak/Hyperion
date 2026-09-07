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
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
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
      "title":       {"type": "text"},
      "description": {"type": "text"},
      "references":  {"type": "keyword"},
      "sources":     {"type": "keyword"},
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
		return nil
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

// searchBody is the query DSL. Three clauses are OR-ed so that a query works
// the way an analyst expects:
//   - best_fields with AUTO fuzziness tolerates typos ("log4shel" -> log4shell)
//   - phrase_prefix matches partial tokens ("log4j" -> "Log4j2")
//   - a term match on cve_id makes an exact id lookup the top hit
//
// Fields are weighted so the CVE id outranks the title, which outranks the body.
const searchBody = `{
  "from": %d,
  "size": %d,
  "query": {
    "bool": {
      "minimum_should_match": 1,
      "should": [
        {
          "multi_match": {
            "query": %[3]s,
            "fields": ["cve_id.text^3", "title^2", "description"],
            "fuzziness": "AUTO"
          }
        },
        {
          "multi_match": {
            "query": %[3]s,
            "fields": ["title^2", "description"],
            "type": "phrase_prefix"
          }
        },
        {
          "term": {"cve_id": {"value": %[3]s, "boost": 5}}
        }
      ]
    }
  }
}`

// Search runs a full-text query and returns scored domain hits.
func (i *Index) Search(ctx context.Context, query string, size, offset int) ([]model.SearchHit, error) {
	q, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("elasticsearch: marshal query: %w", err)
	}
	body := fmt.Sprintf(searchBody, offset, size, string(q))

	resp, err := i.do(ctx, http.MethodPost, "/"+i.name+"/_search", strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("elasticsearch: search: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("elasticsearch: search status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out searchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("elasticsearch: decode search: %w", err)
	}

	hits := make([]model.SearchHit, 0, len(out.Hits.Hits))
	for _, h := range out.Hits.Hits {
		hits = append(hits, model.SearchHit{
			Vulnerability: h.Source.toDomain(),
			Score:         h.Score,
		})
	}
	return hits, nil
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
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Scores      []model.CVSS `json:"scores"`
	References  []string     `json:"references"`
	Sources     []string     `json:"sources"`
	MaxScore    float64      `json:"max_score"`
	Severity    string       `json:"severity"`
	PublishedAt *time.Time   `json:"published_at,omitempty"`
	ModifiedAt  *time.Time   `json:"modified_at,omitempty"`
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
	return document{
		CVEID:       v.CVEID,
		Title:       v.Title,
		Description: v.Description,
		Scores:      v.Scores,
		References:  v.References,
		Sources:     v.Sources,
		MaxScore:    maxScore,
		Severity:    severity,
		PublishedAt: nullableTime(v.PublishedAt),
		ModifiedAt:  nullableTime(v.ModifiedAt),
	}
}

func (d document) toDomain() model.Vulnerability {
	v := model.Vulnerability{
		CVEID:       d.CVEID,
		Title:       d.Title,
		Description: d.Description,
		Scores:      d.Scores,
		References:  d.References,
		Sources:     d.Sources,
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
		Hits []struct {
			Score  float64  `json:"_score"`
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
