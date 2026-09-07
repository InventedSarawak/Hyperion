// Package mitre is an OUTBOUND adapter for the MITRE CVE List — the root
// source where CVE IDs are assigned, often ahead of NVD analysis.
//
// Strategy: the cvelistV5 repository publishes a small delta.json of recently
// created/updated CVE ids (a few KB), which we use as the change feed, then
// fetch each record from the public CVE Services API. Read access needs no
// credential; credentials are only required for CNAs submitting records.
package mitre

import (
	"context"
	"fmt"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

const (
	// DefaultBaseURL is the public CVE Services API root.
	DefaultBaseURL = "https://cveawg.mitre.org/api"

	// DefaultDeltaURL is the recent-changes feed from the cvelistV5 repo.
	DefaultDeltaURL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json"

	// cveOrgRecord is the human-facing record page.
	cveOrgRecord = "https://www.cve.org/CVERecord?id="

	// requestDelay paces per-record lookups; no limit is published, so be kind.
	requestDelay = 500 * time.Millisecond
)

// Client reads the delta feed and hydrates each changed CVE.
type Client struct {
	http     *sourcehttp.Client
	baseURL  string
	deltaURL string
	maxItems int
}

// New builds a MITRE client.
func New(baseURL string, opts ...sourcehttp.Option) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		http:     sourcehttp.New(requestDelay, opts...),
		baseURL:  baseURL,
		deltaURL: DefaultDeltaURL,
		maxItems: 50, // bound per-poll work; the delta is small by design
	}
}

// WithDeltaURL overrides the change feed (used in tests).
func (c *Client) WithDeltaURL(u string) *Client {
	if u != "" {
		c.deltaURL = u
	}
	return c
}

// Kind reports the source this client speaks for.
func (c *Client) Kind() valueobject.SourceKind { return valueobject.SourceKindMITRE }

// Fetch reads the delta feed, then hydrates each changed record.
func (c *Client) Fetch(ctx context.Context, since time.Time) ([]model.SourceSignal, error) {
	var delta deltaFeed
	if err := c.http.GetJSON(ctx, c.deltaURL, &delta); err != nil {
		return nil, fmt.Errorf("mitre: delta feed: %w", err)
	}

	changed := append(append([]deltaItem{}, delta.New...), delta.Updated...)

	var signals []model.SourceSignal
	for _, item := range changed {
		if len(signals) >= c.maxItems {
			break
		}
		updated := parseTime(item.DateUpdated)
		if !since.IsZero() && !updated.IsZero() && updated.Before(since) {
			continue
		}

		signal, err := c.hydrate(ctx, item.CveID, updated)
		if err != nil {
			// One unavailable record must not fail the whole poll.
			continue
		}
		signals = append(signals, signal)
	}
	return signals, nil
}

// hydrate fetches the full CVE record for one id.
func (c *Client) hydrate(ctx context.Context, id string, updated time.Time) (model.SourceSignal, error) {
	var record cveRecord
	if err := c.http.GetJSON(ctx, c.baseURL+"/cve/"+id, &record); err != nil {
		return model.SourceSignal{}, err
	}
	return toSourceSignal(id, record, updated), nil
}

// --- MITRE wire DTOs (private to the adapter) ---

type deltaFeed struct {
	FetchTime string      `json:"fetchTime"`
	New       []deltaItem `json:"new"`
	Updated   []deltaItem `json:"updated"`
}

type deltaItem struct {
	CveID       string `json:"cveId"`
	DateUpdated string `json:"dateUpdated"`
}

// cveRecord is the CVE 5.0 JSON schema, trimmed to what we map.
type cveRecord struct {
	CveMetadata struct {
		CveID             string `json:"cveId"`
		DatePublished     string `json:"datePublished"`
		DateUpdated       string `json:"dateUpdated"`
		AssignerShortName string `json:"assignerShortName"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Title        string `json:"title"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
			Metrics []struct {
				CvssV31 cvssData `json:"cvssV3_1"`
				CvssV30 cvssData `json:"cvssV3_0"`
				CvssV40 cvssData `json:"cvssV4_0"`
			} `json:"metrics"`
		} `json:"cna"`
	} `json:"containers"`
}

type cvssData struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
	BaseSeverity string  `json:"baseSeverity"`
}

// --- mapping: MITRE wire -> domain ---

func toSourceSignal(id string, r cveRecord, fallbackUpdated time.Time) model.SourceSignal {
	cna := r.Containers.CNA

	description := ""
	for _, d := range cna.Descriptions {
		if d.Lang == "en" || description == "" {
			description = d.Value
		}
		if d.Lang == "en" {
			break
		}
	}

	references := []string{cveOrgRecord + id}
	for _, ref := range cna.References {
		if ref.URL != "" {
			references = append(references, ref.URL)
		}
	}

	var scores []model.CVSS
	for _, m := range cna.Metrics {
		for _, d := range []cvssData{m.CvssV40, m.CvssV31, m.CvssV30} {
			if d.BaseScore == 0 && d.VectorString == "" {
				continue
			}
			scores = append(scores, model.CVSS{
				Version:   d.Version,
				BaseScore: d.BaseScore,
				Vector:    d.VectorString,
				Severity:  toSeverity(d.BaseSeverity),
			})
		}
	}

	title := cna.Title
	if title == "" {
		title = id
	}

	modified := parseTime(r.CveMetadata.DateUpdated)
	if modified.IsZero() {
		modified = fallbackUpdated
	}

	return model.SourceSignal{
		CVEID:       id,
		Title:       title,
		Description: description,
		Scores:      scores,
		References:  references,
		PublishedAt: parseTime(r.CveMetadata.DatePublished),
		ModifiedAt:  modified,
	}
}

func toSeverity(s string) model.Severity {
	switch s {
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
