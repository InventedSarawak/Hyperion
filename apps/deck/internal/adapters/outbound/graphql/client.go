// Package graphql is an OUTBOUND adapter implementing ports.IntelligenceAPI by
// calling the nexus gateway over HTTP.
//
// This is deck's default transport. Going through the gateway rather than
// straight to cortex means deck inherits whatever the edge enforces —
// authentication, rate limiting, per-tenant scoping, usage metering — instead
// of quietly bypassing all of it. The direct gRPC adapter still exists for
// operators debugging a cortex that the gateway cannot reach.
package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// DefaultEndpoint is the gateway's GraphQL endpoint in local development.
const DefaultEndpoint = "http://localhost:8080/graphql"

// Client queries the nexus gateway.
type Client struct {
	http     *http.Client
	endpoint string
}

// New builds a gateway client. An empty endpoint falls back to the default.
func New(endpoint string, httpClient *http.Client) *Client {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{http: httpClient, endpoint: endpoint}
}

// Close exists so the composition root can treat both transports alike.
func (c *Client) Close() error { return nil }

const searchQuery = `query Search($term: String, $sort: SearchSort, $pageSize: Int, $pageToken: String) {
  search(term: $term, sort: $sort, pageSize: $pageSize, pageToken: $pageToken) {
    nextPageToken
    totalResults
    totalIsLowerBound
    hits {
      score
      vulnerability {
        cveId title description references publishedAt modifiedAt sources
        scores { version baseScore vector severity }
        affectedPackages { package }
      }
    }
  }
}`

const blastRadiusQuery = `query BlastRadius($cveId: String!, $maxDepth: Int) {
  blastRadius(cveId: $cveId, maxDepth: $maxDepth) {
    cveId
    linked
    vulnerablePackages
    repositories { fullName authorName url viaPackage depth direct path }
  }
}`

const vulnerabilityQuery = `query Vulnerability($cveId: String!) {
  vulnerability(cveId: $cveId) {
    cveId title description references publishedAt modifiedAt sources
    scores { version baseScore vector severity }
    affectedPackages { package versionRange }
  }
}`

// Vulnerability fetches one finding in full through the gateway.
func (c *Client) Vulnerability(ctx context.Context, id string) (model.Vulnerability, error) {
	var out struct {
		Vulnerability vulnerability `json:"vulnerability"`
	}
	if err := c.do(ctx, vulnerabilityQuery, map[string]any{"cveId": id}, &out); err != nil {
		return model.Vulnerability{}, err
	}
	return out.Vulnerability.toModel(), nil
}

// Search returns one page of results through the gateway.
func (c *Client) Search(ctx context.Context, query string, sort model.SearchSort, pageSize int, pageToken string) (model.SearchPage, error) {
	var out struct {
		Search struct {
			NextPageToken     string  `json:"nextPageToken"`
			TotalResults      float64 `json:"totalResults"` // GraphQL Int is 32-bit, so the gateway sends a Float
			TotalIsLowerBound bool    `json:"totalIsLowerBound"`
			Hits              []struct {
				Score         float64       `json:"score"`
				Vulnerability vulnerability `json:"vulnerability"`
			} `json:"hits"`
		} `json:"search"`
	}
	variables := map[string]any{
		"term":      query,
		"sort":      gatewaySort(sort),
		"pageSize":  pageSize,
		"pageToken": pageToken,
	}
	if err := c.do(ctx, searchQuery, variables, &out); err != nil {
		return model.SearchPage{}, err
	}

	page := model.SearchPage{
		NextPageToken:     out.Search.NextPageToken,
		Total:             int64(out.Search.TotalResults),
		TotalIsLowerBound: out.Search.TotalIsLowerBound,
		Hits:              make([]model.SearchHit, 0, len(out.Search.Hits)),
	}
	for _, h := range out.Search.Hits {
		page.Hits = append(page.Hits, model.SearchHit{Vulnerability: h.Vulnerability.toModel(), Score: h.Score})
	}
	return page, nil
}

// gatewaySort maps the sort onto the gateway's GraphQL enum.
func gatewaySort(s model.SearchSort) string {
	if s == model.SortNewest {
		return "NEWEST"
	}
	return "RELEVANCE"
}

// BlastRadius asks the gateway which repositories a vulnerability reaches.
func (c *Client) BlastRadius(ctx context.Context, cveID string, maxDepth int) (model.BlastRadius, error) {
	var out struct {
		BlastRadius struct {
			CVEID              string   `json:"cveId"`
			Linked             bool     `json:"linked"`
			VulnerablePackages []string `json:"vulnerablePackages"`
			Repositories       []struct {
				FullName   string   `json:"fullName"`
				AuthorName string   `json:"authorName"`
				URL        string   `json:"url"`
				ViaPackage string   `json:"viaPackage"`
				Depth      int      `json:"depth"`
				Direct     bool     `json:"direct"`
				Path       []string `json:"path"`
			} `json:"repositories"`
		} `json:"blastRadius"`
	}
	if err := c.do(ctx, blastRadiusQuery, map[string]any{"cveId": cveID, "maxDepth": maxDepth}, &out); err != nil {
		return model.BlastRadius{}, err
	}

	radius := model.BlastRadius{
		CVEID:              out.BlastRadius.CVEID,
		VulnerablePackages: out.BlastRadius.VulnerablePackages,
	}
	for _, r := range out.BlastRadius.Repositories {
		radius.Repositories = append(radius.Repositories, model.ImpactedRepository{
			FullName:   r.FullName,
			AuthorName: r.AuthorName,
			URL:        r.URL,
			ViaPackage: r.ViaPackage,
			Depth:      r.Depth,
			Direct:     r.Direct,
			Path:       r.Path,
		})
	}
	return radius, nil
}

// do executes one GraphQL request and decodes `data` into out.
func (c *Client) do(ctx context.Context, query string, variables map[string]any, out any) error {
	body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return fmt.Errorf("gateway: encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("gateway: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("gateway %s: %w", c.endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("gateway %s: status %d: %s",
			c.endpoint, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	// GraphQL reports failures inside a 200 response, so the envelope has to
	// be inspected rather than trusting the status code.
	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("gateway: decode response: %w", err)
	}
	if len(envelope.Errors) > 0 {
		messages := make([]string, 0, len(envelope.Errors))
		for _, e := range envelope.Errors {
			messages = append(messages, e.Message)
		}
		return fmt.Errorf("gateway: %s", strings.Join(messages, "; "))
	}
	if len(envelope.Data) == 0 {
		return fmt.Errorf("gateway: response carried no data")
	}
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		return fmt.Errorf("gateway: decode data: %w", err)
	}
	return nil
}

// --- gateway wire shapes -> deck view models ---

type vulnerability struct {
	CVEID            string   `json:"cveId"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	References       []string `json:"references"`
	PublishedAt      string   `json:"publishedAt"`
	ModifiedAt       string   `json:"modifiedAt"`
	Sources          []string `json:"sources"`
	AffectedPackages []struct {
		Package      string `json:"package"`
		VersionRange string `json:"versionRange"`
	} `json:"affectedPackages"`
	Scores []struct {
		Version   string  `json:"version"`
		BaseScore float64 `json:"baseScore"`
		Vector    string  `json:"vector"`
		Severity  string  `json:"severity"`
	} `json:"scores"`
}

func (v vulnerability) toModel() model.Vulnerability {
	scores := make([]model.CVSS, 0, len(v.Scores))
	for _, s := range v.Scores {
		scores = append(scores, model.CVSS{
			Version:   s.Version,
			BaseScore: s.BaseScore,
			Vector:    s.Vector,
			Severity:  s.Severity,
		})
	}
	packages := make([]model.AffectedPackage, 0, len(v.AffectedPackages))
	for _, p := range v.AffectedPackages {
		packages = append(packages, model.AffectedPackage{Package: p.Package, VersionRange: p.VersionRange})
	}
	return model.Vulnerability{
		CVEID:            v.CVEID,
		Title:            v.Title,
		Description:      v.Description,
		Scores:           scores,
		References:       v.References,
		PublishedAt:      parseTime(v.PublishedAt),
		ModifiedAt:       parseTime(v.ModifiedAt),
		Sources:          v.Sources,
		AffectedPackages: packages,
	}
}

// parseTime accepts the RFC3339 timestamps the gateway renders as strings.
func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}
