// Package shodan is an OUTBOUND adapter for Shodan's CVEDB.
//
// Important: Shodan's main host-search API (api.shodan.io) needs a PAID key.
// CVEDB (cvedb.shodan.io) is a separate, FREE service with no key, exposing
// CVE records enriched with exploit availability, KEV membership and EPSS
// scores — the ranking signal Hyperion actually wants. This adapter uses CVEDB,
// so the source works with no credential. An api.shodan.io key, if supplied,
// is only needed for host-exposure enrichment (not implemented yet).
// Docs: https://cvedb.shodan.io/
package shodan

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// DefaultBaseURL is the free CVEDB service.
const DefaultBaseURL = "https://cvedb.shodan.io"

// requestDelay: CVEDB publishes no explicit limit; ~1 req/s is courteous.
const requestDelay = time.Second

// Client fetches CVE records from CVEDB.
type Client struct {
	http    *sourcehttp.Client
	baseURL string
	limit   int
}

// New builds a CVEDB client. apiKey is accepted for future host-exposure
// enrichment but is not required by CVEDB.
func New(baseURL, apiKey string, opts ...sourcehttp.Option) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if apiKey != "" {
		opts = append(opts, sourcehttp.WithHeader("Authorization", "Bearer "+apiKey))
	}
	return &Client{http: sourcehttp.New(requestDelay, opts...), baseURL: baseURL, limit: 200}
}

// Kind reports the source this client speaks for.
func (c *Client) Kind() valueobject.SourceKind { return valueobject.SourceKindShodan }

// Fetch returns recent CVEs, filtered locally to those modified since `since`.
func (c *Client) Fetch(ctx context.Context, since time.Time) ([]model.SourceSignal, error) {
	u, err := url.Parse(c.baseURL + "/cves")
	if err != nil {
		return nil, fmt.Errorf("shodan: parse base url: %w", err)
	}
	q := u.Query()
	q.Set("limit", strconv.Itoa(c.limit))
	// Filter server-side by date. Sorting by EPSS instead would return the
	// historically most-exploitable CVEs (mostly years old), which an
	// incremental poll would then discard entirely.
	if !since.IsZero() {
		q.Set("start_date", since.UTC().Format("2006-01-02"))
		q.Set("end_date", time.Now().UTC().Format("2006-01-02"))
	}
	u.RawQuery = q.Encode()

	var payload response
	if err := c.http.GetJSON(ctx, u.String(), &payload); err != nil {
		return nil, fmt.Errorf("shodan cvedb: %w", err)
	}

	signals := make([]model.SourceSignal, 0, len(payload.CVEs))
	for _, rec := range payload.CVEs {
		modified := parseTime(rec.PublishedTime)
		if !since.IsZero() && !modified.IsZero() && modified.Before(since) {
			continue
		}
		signals = append(signals, toSourceSignal(rec, modified))
	}
	return signals, nil
}

// --- CVEDB wire DTOs (private to the adapter) ---

type response struct {
	CVEs []record `json:"cves"`
}

// CVEDB sends numbers as JSON numbers but uses null freely, and cvss_version
// is a float (4.0), not an int — hence FlexFloat throughout.
type record struct {
	CVEID         string               `json:"cve_id"`
	Summary       string               `json:"summary"`
	CVSS          sourcehttp.FlexFloat `json:"cvss"`
	CVSSVersion   sourcehttp.FlexFloat `json:"cvss_version"`
	CVSSV2        sourcehttp.FlexFloat `json:"cvss_v2"`
	CVSSV3        sourcehttp.FlexFloat `json:"cvss_v3"`
	CVSSV4        sourcehttp.FlexFloat `json:"cvss_v4"`
	EPSS          sourcehttp.FlexFloat `json:"epss"`
	Ranking       sourcehttp.FlexFloat `json:"ranking_epss"`
	KEV           bool                 `json:"kev"`
	ProposeAction string               `json:"propose_action"`
	RansomwareUse string               `json:"ransomware_campaign"`
	References    []string             `json:"references"`
	PublishedTime string               `json:"published_time"`
	Vendor        string               `json:"vendor"`
	Product       string               `json:"product"`
}

// --- mapping: CVEDB wire -> domain ---

func toSourceSignal(r record, modified time.Time) model.SourceSignal {
	// EPSS and KEV are what make this source distinctive: they say how likely
	// exploitation is, not just how severe the flaw is.
	description := r.Summary
	if r.EPSS.Float() > 0 {
		description += fmt.Sprintf("\n\nEPSS (exploit prediction): %.4f", r.EPSS.Float())
	}
	if r.KEV {
		description += "\nListed in CISA KEV: actively exploited in the wild."
	}
	if r.RansomwareUse != "" && r.RansomwareUse != "Unknown" {
		description += "\nRansomware campaign use: " + r.RansomwareUse
	}

	// Prefer the newest CVSS revision the record carries.
	var scores []model.CVSS
	switch {
	case r.CVSSV4.Float() > 0:
		scores = append(scores, cvss("4.0", r.CVSSV4.Float()))
	case r.CVSSV3.Float() > 0:
		scores = append(scores, cvss("3.1", r.CVSSV3.Float()))
	case r.CVSS.Float() > 0:
		scores = append(scores, cvss(strconv.FormatFloat(r.CVSSVersion.Float(), 'g', -1, 64), r.CVSS.Float()))
	}

	return model.SourceSignal{
		CVEID:       r.CVEID,
		Title:       r.CVEID + " (Shodan CVEDB)",
		Description: description,
		Scores:      scores,
		References:  r.References,
		PublishedAt: modified,
		ModifiedAt:  modified,
	}
}

// cvss builds a score entry with its qualitative band.
func cvss(version string, score float64) model.CVSS {
	return model.CVSS{Version: version, BaseScore: score, Severity: severityFromScore(score)}
}

// severityFromScore applies the standard CVSS v3 qualitative bands.
func severityFromScore(score float64) model.Severity {
	switch {
	case score == 0:
		return model.SeverityNone
	case score < 4:
		return model.SeverityLow
	case score < 7:
		return model.SeverityMedium
	case score < 9:
		return model.SeverityHigh
	default:
		return model.SeverityCritical
	}
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
