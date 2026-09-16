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
	"sync"
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
	var filter *dateFilter
	if !since.IsZero() {
		start, end := clampWindow(since, time.Now())
		filter = &dateFilter{startParam: "lastModStartDate", endParam: "lastModEndDate", start: start, end: end}
	}

	var signals []model.SourceSignal
	err := c.walk(ctx, filter, c.maxPages, func(page []model.SourceSignal) error {
		signals = append(signals, page...)
		return nil
	})
	return signals, err
}

// Backfill walks every CVE *published* from `from` until now, handing each
// page to emit as it arrives.
//
// It exists because Fetch cannot reach history: NVD rejects any date range
// wider than 120 days, so a years-long lookback is silently clamped to the
// last four months. Backfill instead walks consecutive 120-day windows, and it
// filters on publication rather than modification — the question a backfill
// answers is "what was disclosed in this period", and last-modified would
// drag in decade-old records every time NVD touched their metadata.
//
// Pages are emitted rather than collected: ten years is roughly 280,000
// records, which should flow through, not pile up in memory. The page bound
// does not apply — a backfill that stops early leaves a hole nobody sees.
//
// Windows are fetched a few at a time. NVD takes ~40s to serve one 2,000-row
// page, so a serial walk spends almost all its time waiting on the server,
// not on the rate limit; the shared limiter still spaces every request. emit
// is never called concurrently.
func (c *Client) Backfill(ctx context.Context, from time.Time, emit func([]model.SourceSignal) error) error {
	windows := backfillWindows(from, time.Now())

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu      sync.Mutex // serializes emit and guards the error state
		emitErr error      // the consumer failed: stop everything
		failed  []error    // windows that could not be read: report, carry on
		wg      sync.WaitGroup
		next    = make(chan dateFilter)
	)
	serialEmit := func(page []model.SourceSignal) error {
		mu.Lock()
		defer mu.Unlock()
		if err := emit(page); err != nil {
			if emitErr == nil {
				emitErr = err
				cancel()
			}
			return err
		}
		return nil
	}

	for range min(backfillConcurrency, len(windows)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range next {
				err := c.walk(ctx, &w, 0, serialEmit)
				if err == nil || ctx.Err() != nil {
					continue
				}
				// One window NVD would not serve, even after retries, is a
				// hole to report, not a reason to abandon the other nine
				// years. The error names the window so it can be re-run.
				mu.Lock()
				failed = append(failed, fmt.Errorf("%s..%s: %w",
					w.start.Format(time.DateOnly), w.end.Format(time.DateOnly), err))
				mu.Unlock()
			}
		}()
	}

feed:
	for _, w := range windows {
		select {
		case next <- w:
		case <-ctx.Done():
			break feed
		}
	}
	close(next)
	wg.Wait()

	switch {
	case emitErr != nil:
		return emitErr
	case ctx.Err() != nil:
		return ctx.Err()
	case len(failed) > 0:
		return fmt.Errorf("nvd backfill: %d window(s) incomplete, re-run from the earliest: %w",
			len(failed), errors.Join(failed...))
	}
	return nil
}

// backfillConcurrency is how many publication windows are in flight at once.
const backfillConcurrency = 4

// backfillWindows splits [from, now) into consecutive ranges no wider than
// NVD allows, with no gaps between them.
func backfillWindows(from, now time.Time) []dateFilter {
	var out []dateFilter
	for start := from; start.Before(now); start = start.Add(maxWindow) {
		end := start.Add(maxWindow)
		if end.After(now) {
			end = now
		}
		out = append(out, dateFilter{startParam: "pubStartDate", endParam: "pubEndDate", start: start, end: end})
	}
	return out
}

// dateFilter selects one of NVD's two date ranges — last-modified for
// incremental polling, published for a backfill. Both share the 120-day cap.
type dateFilter struct {
	startParam, endParam string
	start, end           time.Time
}

// walk pages through one query, handing each page to emit, until the result
// set is drained or maxPages (when positive) is reached.
func (c *Client) walk(ctx context.Context, filter *dateFilter, maxPages int, emit func([]model.SourceSignal) error) error {
	startIndex, pages := 0, 0
	for {
		page, total, err := c.fetchPage(ctx, filter, startIndex)
		if err != nil {
			return err
		}
		if err := emit(page); err != nil {
			return err
		}
		pages++

		startIndex += c.pageSize
		if startIndex >= total || len(page) == 0 {
			return nil
		}
		if maxPages > 0 && pages >= maxPages {
			return nil
		}
	}
}

// fetchPage retrieves one page and reports the total result count.
func (c *Client) fetchPage(ctx context.Context, filter *dateFilter, startIndex int) ([]model.SourceSignal, int, error) {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, 0, fmt.Errorf("nvd: parse base url: %w", err)
	}

	q := u.Query()
	q.Set("resultsPerPage", strconv.Itoa(c.pageSize))
	if startIndex > 0 {
		q.Set("startIndex", strconv.Itoa(startIndex))
	}
	if filter != nil {
		q.Set(filter.startParam, filter.start.UTC().Format(nvdTimeLayout))
		q.Set(filter.endParam, filter.end.UTC().Format(nvdTimeLayout))
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
		// A page is several megabytes streamed over a minute, and the
		// connection can drop partway ("connection reset by peer"). That is a
		// transport failure worth retrying; only a body that arrived whole and
		// is not valid NVD JSON is final.
		return nil, !isMalformedJSON(err), fmt.Errorf("nvd: decode response: %w", err)
	}
	return &payload, false, nil
}

// isMalformedJSON reports whether a decode failed on the content itself rather
// than on reading it.
func isMalformedJSON(err error) bool {
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	return errors.As(err, &syntax) || errors.As(err, &typeErr)
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

// toSourceSignal leaves the title empty on purpose: NVD records have no title,
// only a description. Filling it with the CVE id looked harmless but was
// treated downstream as a real title — it hid the description in every list,
// and it overwrote the genuine titles GitHub and vendors had supplied.
func toSourceSignal(cve nvdCVE) model.SourceSignal {
	return model.SourceSignal{
		CVEID:       cve.ID,
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

// toReferences keeps each URL once. NVD lists a reference once per
// organization that submitted it, so the same link often appears two or three
// times in a row.
func toReferences(refs []nvdReference) []string {
	seen := make(map[string]struct{}, len(refs))
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.URL == "" {
			continue
		}
		if _, dup := seen[r.URL]; dup {
			continue
		}
		seen[r.URL] = struct{}{}
		out = append(out, r.URL)
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
