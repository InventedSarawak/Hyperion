// Package vendor is an OUTBOUND adapter for vendor security advisories.
//
// Vendors publish more actionable detail than generic CVE entries: affected
// package versions, workarounds and patch links. This adapter uses Red Hat's
// Security Data API, which is public and needs no credential. Other vendors
// (MSRC, Cisco, Oracle) can be added behind the same adapter later.
// Docs: https://docs.redhat.com/en/documentation/red_hat_security_data_api
package vendor

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

// DefaultRedHatBaseURL is Red Hat's public security data root.
const DefaultRedHatBaseURL = "https://access.redhat.com/hydra/rest/securitydata"

// requestDelay: no published limit, so stay under ~1 req/s.
const requestDelay = time.Second

// Client fetches Red Hat CVE advisories.
type Client struct {
	http     *sourcehttp.Client
	baseURL  string
	pageSize int
}

// New builds a vendor-advisory client.
func New(redhatBaseURL string, opts ...sourcehttp.Option) *Client {
	if redhatBaseURL == "" {
		redhatBaseURL = DefaultRedHatBaseURL
	}
	return &Client{http: sourcehttp.New(requestDelay, opts...), baseURL: redhatBaseURL, pageSize: 200}
}

// Kind reports the source this client speaks for.
func (c *Client) Kind() valueobject.SourceKind { return valueobject.SourceKindVendorAdvisory }

// Fetch returns Red Hat advisories published at or after `since`.
func (c *Client) Fetch(ctx context.Context, since time.Time) ([]model.SourceSignal, error) {
	u, err := url.Parse(c.baseURL + "/cve.json")
	if err != nil {
		return nil, fmt.Errorf("vendor: parse base url: %w", err)
	}

	q := u.Query()
	q.Set("per_page", strconv.Itoa(c.pageSize))
	if !since.IsZero() {
		// The API filters on date only (YYYY-MM-DD).
		q.Set("after", since.UTC().Format("2006-01-02"))
	}
	u.RawQuery = q.Encode()

	var entries []redhatCVE
	if err := c.http.GetJSON(ctx, u.String(), &entries); err != nil {
		return nil, fmt.Errorf("vendor (red hat): %w", err)
	}

	signals := make([]model.SourceSignal, 0, len(entries))
	for _, e := range entries {
		if e.CVE == "" {
			continue
		}
		signals = append(signals, toSourceSignal(e))
	}
	return signals, nil
}

// --- Red Hat wire DTOs (private to the adapter) ---

type redhatCVE struct {
	CVE                 string `json:"CVE"`
	Severity            string `json:"severity"`
	PublicDate          string `json:"public_date"`
	BugzillaDescription string `json:"bugzilla_description"`
	// Red Hat returns these as JSON *strings* ("7.8"), so they need FlexFloat.
	CvssScore          sourcehttp.FlexFloat `json:"cvss_score"`
	CvssScoringVector  string               `json:"cvss_scoring_vector"`
	Cvss3Score         sourcehttp.FlexFloat `json:"cvss3_score"`
	Cvss3ScoringVector string               `json:"cvss3_scoring_vector"`
	CWE                string               `json:"CWE"`
	ResourceURL        string               `json:"resource_url"`
	AffectedPackages   []string             `json:"affected_packages"`
	Advisories         []string             `json:"advisories"`
}

// --- mapping: Red Hat wire -> domain ---

func toSourceSignal(e redhatCVE) model.SourceSignal {
	description := e.BugzillaDescription
	if e.CWE != "" {
		description = fmt.Sprintf("%s (%s)", description, e.CWE)
	}
	if len(e.AffectedPackages) > 0 {
		description = fmt.Sprintf("%s\n\nAffected packages: %v", description, e.AffectedPackages)
	}

	references := []string{}
	if e.ResourceURL != "" {
		references = append(references, e.ResourceURL)
	}
	references = append(references, e.Advisories...)

	var scores []model.CVSS
	switch {
	case e.Cvss3Score.Float() > 0:
		scores = append(scores, model.CVSS{
			Version:   "3.1",
			BaseScore: e.Cvss3Score.Float(),
			Vector:    e.Cvss3ScoringVector,
			Severity:  toSeverity(e.Severity),
		})
	case e.CvssScore.Float() > 0:
		scores = append(scores, model.CVSS{
			Version:   "2.0",
			BaseScore: e.CvssScore.Float(),
			Vector:    e.CvssScoringVector,
			Severity:  toSeverity(e.Severity),
		})
	}

	published := parseTime(e.PublicDate)
	return model.SourceSignal{
		CVEID:       e.CVE,
		Title:       e.CVE + " (Red Hat advisory)",
		Description: description,
		Scores:      scores,
		References:  references,
		PublishedAt: published,
		ModifiedAt:  published,
	}
}

func toSeverity(s string) model.Severity {
	switch s {
	case "low":
		return model.SeverityLow
	case "moderate", "medium":
		return model.SeverityMedium
	case "important", "high":
		return model.SeverityHigh
	case "critical":
		return model.SeverityCritical
	default:
		return model.SeverityUnknown
	}
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
