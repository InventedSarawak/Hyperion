// Package gsd is an OUTBOUND adapter for the Global Security Database dataset,
// served through OSV.dev.
//
// GSD itself is distributed as a git repository; OSV.dev is the practical,
// actively-served API over the same community vulnerability data, in a
// machine-readable schema. No credential required.
// Docs: https://google.github.io/osv.dev/api/
package gsd

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/osv"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

const (
	// DefaultBaseURL is the OSV.dev API root.
	DefaultBaseURL = "https://api.osv.dev/v1"

	// deltaURL supplies the recently-changed CVE ids that we resolve against
	// OSV. OSV has no "list recent" endpoint, so the CVE Project change feed
	// drives which records to look up.
	deltaURL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json"

	requestDelay = 300 * time.Millisecond
)

// Client resolves recently changed CVE ids against OSV.
type Client struct {
	http     *sourcehttp.Client
	baseURL  string
	deltaURL string
	maxItems int
}

// New builds a GSD/OSV client.
func New(baseURL string, opts ...sourcehttp.Option) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		http:     sourcehttp.New(requestDelay, opts...),
		baseURL:  baseURL,
		deltaURL: deltaURL,
		maxItems: 50,
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
func (c *Client) Kind() valueobject.SourceKind { return valueobject.SourceKindGSD }

// Fetch resolves each recently changed CVE id through OSV. Records OSV does not
// carry are skipped: OSV covers open-source ecosystems, not every CVE.
func (c *Client) Fetch(ctx context.Context, since time.Time) ([]model.SourceSignal, error) {
	var delta deltaFeed
	if err := c.http.GetJSON(ctx, c.deltaURL, &delta); err != nil {
		return nil, fmt.Errorf("gsd: delta feed: %w", err)
	}

	changed := append(append([]deltaItem{}, delta.New...), delta.Updated...)

	var signals []model.SourceSignal
	for _, item := range changed {
		if len(signals) >= c.maxItems {
			break
		}
		if item.CveID == "" {
			continue
		}

		var record osv.Vulnerability
		if err := c.http.GetJSON(ctx, c.baseURL+"/vulns/"+item.CveID, &record); err != nil {
			// Not in OSV (or transient): skip, do not fail the poll.
			continue
		}

		signal, ok := osv.ToSourceSignal(record, since)
		if !ok {
			continue
		}
		signal.Title = strings.TrimSpace(signal.Title) + " (OSV/GSD)"
		signals = append(signals, signal)
	}
	return signals, nil
}

// WithHTTPClient lets tests target a local server.
func WithHTTPClient(h *http.Client) sourcehttp.Option { return sourcehttp.WithHTTPClient(h) }

// --- change-feed DTOs (private to the adapter) ---

type deltaFeed struct {
	New     []deltaItem `json:"new"`
	Updated []deltaItem `json:"updated"`
}

type deltaItem struct {
	CveID       string `json:"cveId"`
	DateUpdated string `json:"dateUpdated"`
}
