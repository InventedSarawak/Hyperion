// Package nvd is an OUTBOUND adapter implementing ports.SourceClient against
// the NVD REST API 2.0. All NVD-specific detail (URL shape, JSON format,
// pagination, rate limiting) is contained here; it exposes only domain
// SourceSignals to the rest of siphon.
//
// Rate limits (https://nvd.nist.gov/developers/start-here):
//   - without an API key: 5 requests per rolling 30s window
//   - with an API key:   50 requests per rolling 30s window
//
// NVD's published best practice is to sleep ~6s between requests; with a key
// that can drop to ~0.6s. We stay conservative by default.
package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

const (
	// DefaultBaseURL is the public NVD CVE 2.0 endpoint.
	DefaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	// nvdTimeLayout is NVD's timestamp format (no zone, millisecond precision).
	nvdTimeLayout = "2006-01-02T15:04:05.000"

	// maxResultsPerPage is the API's hard ceiling for the CVE endpoint.
	maxResultsPerPage = 2000

	// maxWindow is the largest allowed span between lastModStartDate and
	// lastModEndDate. NVD rejects ranges beyond 120 consecutive days.
	maxWindow = 120 * 24 * time.Hour

	// delayWithoutKey / delayWithKey follow NVD's documented best practice.
	delayWithoutKey = 6 * time.Second
	delayWithKey    = 600 * time.Millisecond

	// maxRetries bounds the backoff loop for throttled/transient responses.
	maxRetries = 4
)

// Client fetches CVEs from the NVD API and maps them to domain signals.
type Client struct {
	http     *http.Client
	baseURL  string
	apiKey   string
	pageSize int
	limiter  *rate.Limiter
	maxPages int
}

// Option customizes the client.
type Option func(*Client)

// WithPageSize overrides the results-per-page (capped at the API maximum).
func WithPageSize(n int) Option {
	return func(c *Client) {
		if n > 0 {
			c.pageSize = min(n, maxResultsPerPage)
		}
	}
}

// WithMaxPages bounds how many pages a single Fetch will walk. Zero means
// unlimited (drain the whole result set).
func WithMaxPages(n int) Option {
	return func(c *Client) {
		if n >= 0 {
			c.maxPages = n
		}
	}
}

// WithRequestDelay overrides the pacing between requests.
func WithRequestDelay(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.limiter = rate.NewLimiter(rate.Every(d), 1)
		}
	}
}

// New builds an NVD client. A nil httpClient gets a sane default; an empty
// baseURL falls back to the public endpoint. apiKey may be empty (works, but
// with the much lower anonymous rate limit).
func New(httpClient *http.Client, baseURL, apiKey string, opts ...Option) *Client {
	if httpClient == nil {
		// A full 2000-record page is several MB; NVD is a bulk API and streaming
		// one page can take well over a minute.
		httpClient = &http.Client{Timeout: 180 * time.Second}
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}

	delay := delayWithoutKey
	if apiKey != "" {
		delay = delayWithKey
	}

	c := &Client{
		http:     httpClient,
		baseURL:  baseURL,
		apiKey:   apiKey,
		pageSize: maxResultsPerPage,
		limiter:  rate.NewLimiter(rate.Every(delay), 1),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Kind reports the source this client speaks for.
func (c *Client) Kind() valueobject.SourceKind { return valueobject.SourceKindNVD }

// Fetch returns CVEs modified at or after `since`, walking pagination until the
// result set is drained (or maxPages is reached). A zero `since` fetches the
// most recent page without a date filter.
func (c *Client) Fetch(ctx context.Context, since time.Time) ([]model.SourceSignal, error) {
	var (
		signals    []model.SourceSignal
		startIndex int
		pages      int
	)

	for {
		page, total, err := c.fetchPage(ctx, since, startIndex)
		if err != nil {
			return signals, err
		}
		signals = append(signals, page...)
		pages++

		startIndex += c.pageSize
		if startIndex >= total || len(page) == 0 {
			break
		}
		if c.maxPages > 0 && pages >= c.maxPages {
			break
		}
	}
	return signals, nil
}

// fetchPage retrieves one page and reports the total result count.
func (c *Client) fetchPage(ctx context.Context, since time.Time, startIndex int) ([]model.SourceSignal, int, error) {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, 0, fmt.Errorf("nvd: parse base url: %w", err)
	}

	q := u.Query()
	q.Set("resultsPerPage", strconv.Itoa(c.pageSize))
	if startIndex > 0 {
		q.Set("startIndex", strconv.Itoa(startIndex))
	}
	if !since.IsZero() {
		start, end := clampWindow(since, time.Now())
		q.Set("lastModStartDate", start.UTC().Format(nvdTimeLayout))
		q.Set("lastModEndDate", end.UTC().Format(nvdTimeLayout))
	}
	u.RawQuery = q.Encode()

	payload, err := c.doWithRetry(ctx, u.String())
	if err != nil {
		return nil, 0, err
	}

	signals := make([]model.SourceSignal, 0, len(payload.Vulnerabilities))
	for _, v := range payload.Vulnerabilities {
		signals = append(signals, toSourceSignal(v.CVE))
	}
	return signals, payload.TotalResults, nil
}

// doWithRetry performs a rate-limited GET, retrying throttled (403/429) and
// transient 5xx responses with exponential backoff.
func (c *Client) doWithRetry(ctx context.Context, endpoint string) (*apiResponse, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("nvd: rate limiter: %w", err)
		}

		payload, retryable, err := c.doOnce(ctx, endpoint)
		if err == nil {
			return payload, nil
		}
		lastErr = err
		if !retryable || attempt == maxRetries {
			break
		}

		backoff := time.Duration(1<<attempt) * 2 * time.Second
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}
	return nil, lastErr
}

// doOnce issues a single request. The bool reports whether a retry may help.
func (c *Client) doOnce(ctx context.Context, endpoint string) (*apiResponse, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false, fmt.Errorf("nvd: new request: %w", err)
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}
	req.Header.Set("User-Agent", "hyperion-siphon/1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		// Network/timeout errors are worth retrying, but not a cancelled context.
		return nil, !errors.Is(err, context.Canceled), fmt.Errorf("nvd: do request: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusForbidden,
		resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode >= 500:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, true, fmt.Errorf("nvd: throttled/transient status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, false, fmt.Errorf("nvd: unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, fmt.Errorf("nvd: decode response: %w", err)
	}
	return &payload, false, nil
}

// clampWindow keeps the requested range inside NVD's 120-day maximum.
func clampWindow(since, now time.Time) (time.Time, time.Time) {
	if now.Sub(since) > maxWindow {
		since = now.Add(-maxWindow)
	}
	return since, now
}

// --- NVD wire DTOs (private to the adapter) ---

type apiResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
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
	CvssV40 []nvdCvssMetric `json:"cvssMetricV40"`
	CvssV31 []nvdCvssMetric `json:"cvssMetricV31"`
	CvssV30 []nvdCvssMetric `json:"cvssMetricV30"`
	CvssV2  []nvdCvssMetric `json:"cvssMetricV2"`
}

type nvdCvssMetric struct {
	CvssData struct {
		Version      string  `json:"version"`
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
		BaseSeverity string  `json:"baseSeverity"` // v3/v4 carry severity here
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
	appendMetrics(m.CvssV40)
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
