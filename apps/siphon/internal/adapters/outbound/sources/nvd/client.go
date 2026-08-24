// Package nvd is an OUTBOUND adapter implementing ports.SourceClient against
// the NVD REST API 2.0. All NVD-specific detail (URL shape, JSON format) is
// contained here; it exposes only domain SourceSignals to the rest of siphon.
package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// DefaultBaseURL is the public NVD CVE 2.0 endpoint.
const DefaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// nvdTimeLayout is NVD's timestamp format (no zone, millisecond precision).
const nvdTimeLayout = "2006-01-02T15:04:05.000"

// Client fetches CVEs from the NVD API and maps them to domain signals.
type Client struct {
	http     *http.Client
	baseURL  string
	apiKey   string
	pageSize int
}

// New builds an NVD client. A nil httpClient gets a sane default; an empty
// baseURL falls back to the public endpoint. apiKey may be empty (unauthenticated
// access works but is rate-limited to ~5 requests / 30s).
func New(httpClient *http.Client, baseURL, apiKey string) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{http: httpClient, baseURL: baseURL, apiKey: apiKey, pageSize: 2000}
}

// Kind reports the source this client speaks for.
func (c *Client) Kind() valueobject.SourceKind { return valueobject.SourceKindNVD }

// Fetch returns CVEs modified at or after `since`. A zero `since` fetches the
// most recent page without a date filter.
func (c *Client) Fetch(ctx context.Context, since time.Time) ([]model.SourceSignal, error) {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("nvd: parse base url: %w", err)
	}
	q := u.Query()
	q.Set("resultsPerPage", strconv.Itoa(c.pageSize))
	if !since.IsZero() {
		q.Set("lastModStartDate", since.UTC().Format(nvdTimeLayout))
		q.Set("lastModEndDate", time.Now().UTC().Format(nvdTimeLayout))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("nvd: new request: %w", err)
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvd: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("nvd: unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("nvd: decode response: %w", err)
	}

	signals := make([]model.SourceSignal, 0, len(payload.Vulnerabilities))
	for _, v := range payload.Vulnerabilities {
		signals = append(signals, toSourceSignal(v.CVE))
	}
	return signals, nil
}

// --- NVD wire DTOs (private to the adapter) ---

type apiResponse struct {
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string         `json:"id"`
	Published    string         `json:"published"`
	LastModified string         `json:"lastModified"`
	Descriptions []nvdLangValue `json:"descriptions"`
	Metrics      nvdMetrics     `json:"metrics"`
	References   []nvdReference `json:"references"`
}

type nvdLangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdReference struct {
	URL string `json:"url"`
}

type nvdMetrics struct {
	CvssV31 []nvdCvssMetric `json:"cvssMetricV31"`
	CvssV30 []nvdCvssMetric `json:"cvssMetricV30"`
	CvssV2  []nvdCvssMetric `json:"cvssMetricV2"`
}

type nvdCvssMetric struct {
	CvssData struct {
		Version      string  `json:"version"`
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
		BaseSeverity string  `json:"baseSeverity"` // v3 carries severity here
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // v2 carries it at the metric level
}

// --- mapping: NVD wire -> domain ---

func toSourceSignal(cve nvdCVE) model.SourceSignal {
	return model.SourceSignal{
		CVEID:       cve.ID,
		Title:       cve.ID,
		Description: englishDescription(cve.Descriptions),
		Scores:      toScores(cve.Metrics),
		References:  toReferences(cve.References),
		PublishedAt: parseNVDTime(cve.Published),
		ModifiedAt:  parseNVDTime(cve.LastModified),
	}
}

func englishDescription(ds []nvdLangValue) string {
	for _, d := range ds {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(ds) > 0 {
		return ds[0].Value
	}
	return ""
}

func toReferences(refs []nvdReference) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.URL != "" {
			out = append(out, r.URL)
		}
	}
	return out
}

func toScores(m nvdMetrics) []model.CVSS {
	var out []model.CVSS
	appendMetrics := func(metrics []nvdCvssMetric) {
		for _, metric := range metrics {
			severity := metric.CvssData.BaseSeverity
			if severity == "" {
				severity = metric.BaseSeverity
			}
			out = append(out, model.CVSS{
				Version:   metric.CvssData.Version,
				BaseScore: metric.CvssData.BaseScore,
				Vector:    metric.CvssData.VectorString,
				Severity:  toSeverity(severity),
			})
		}
	}
	appendMetrics(m.CvssV31)
	appendMetrics(m.CvssV30)
	appendMetrics(m.CvssV2)
	return out
}

func toSeverity(s string) model.Severity {
	switch strings.ToUpper(s) {
	case "NONE":
		return model.SeverityNone
	case "LOW":
		return model.SeverityLow
	case "MEDIUM":
		return model.SeverityMedium
	case "HIGH":
		return model.SeverityHigh
	case "CRITICAL":
		return model.SeverityCritical
	default:
		return model.SeverityUnknown
	}
}

func parseNVDTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(nvdTimeLayout, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}
