// Package cisakev is an OUTBOUND adapter for the CISA Known Exploited
// Vulnerabilities catalog: CVEs confirmed to be exploited in the wild.
//
// The catalog is one public JSON document (~1.6 MB), no credential required
// and no documented rate limit. It updates roughly daily, so we poll gently.
package cisakev

import (
	"context"
	"fmt"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/cveid"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/adapters/outbound/sources/sourcehttp"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// DefaultFeedURL is the published KEV catalog.
const DefaultFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// requestDelay keeps polling polite for a static file.
const requestDelay = 2 * time.Second

// Client fetches and maps the KEV catalog.
type Client struct {
	http    *sourcehttp.Client
	feedURL string
}

// New builds a KEV client. An empty feedURL falls back to the public catalog.
func New(feedURL string, opts ...sourcehttp.Option) *Client {
	if feedURL == "" {
		feedURL = DefaultFeedURL
	}
	return &Client{http: sourcehttp.New(requestDelay, opts...), feedURL: feedURL}
}

// Kind reports the source this client speaks for.
func (c *Client) Kind() valueobject.SourceKind { return valueobject.SourceKindCISAKEV }

// Fetch returns catalog entries added at or after `since`. The catalog has no
// server-side filter, so the whole document is fetched and filtered locally.
func (c *Client) Fetch(ctx context.Context, since time.Time) ([]model.SourceSignal, error) {
	var payload catalog
	if err := c.http.GetJSON(ctx, c.feedURL, &payload); err != nil {
		return nil, fmt.Errorf("cisa kev: %w", err)
	}

	signals := make([]model.SourceSignal, 0, len(payload.Vulnerabilities))
	for _, v := range payload.Vulnerabilities {
		added := parseDate(v.DateAdded)
		if !since.IsZero() && !added.IsZero() && added.Before(since) {
			continue
		}
		signals = append(signals, toSourceSignal(v, added))
	}
	return signals, nil
}

// --- CISA wire DTOs (private to the adapter) ---

type catalog struct {
	CatalogVersion  string  `json:"catalogVersion"`
	Vulnerabilities []entry `json:"vulnerabilities"`
}

type entry struct {
	CveID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	KnownRansomware   string `json:"knownRansomwareCampaignUse"`
	Notes             string `json:"notes"`
}

// --- mapping: CISA wire -> domain ---

func toSourceSignal(e entry, added time.Time) model.SourceSignal {
	description := e.ShortDescription
	if e.RequiredAction != "" {
		description = fmt.Sprintf("%s\n\nRequired action: %s", description, e.RequiredAction)
	}
	// KEV entries are, by definition, actively exploited — worth stating.
	if e.KnownRansomware == "Known" {
		description += "\n\nKnown to be used in ransomware campaigns."
	}

	title := e.VulnerabilityName
	if title == "" {
		title = fmt.Sprintf("%s %s", e.VendorProject, e.Product)
	}

	var references []string
	if e.Notes != "" {
		references = cveid.URLs(e.Notes)
	}

	return model.SourceSignal{
		CVEID:       e.CveID,
		Title:       title,
		Description: description,
		References:  references,
		PublishedAt: added,
		ModifiedAt:  added,
	}
}

func parseDate(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}
