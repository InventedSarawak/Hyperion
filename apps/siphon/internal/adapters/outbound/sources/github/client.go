// Package github is an OUTBOUND adapter for the GitHub Advisory Database
// (global security advisories), which maps vulnerabilities to ecosystem
// packages (npm, PyPI, Maven, Go, ...).
//
// Auth is optional but strongly recommended: 60 requests/hour unauthenticated
// vs 5,000/hour with a personal access token. Public advisories need no scopes.
// Docs: https://docs.github.com/en/rest/security-advisories/global-advisories
package github

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

// DefaultBaseURL is the public GitHub REST API root.
const DefaultBaseURL = "https://api.github.com"

// Pacing: ~1 req/s authenticated stays far inside 5,000/hour; unauthenticated
// (60/hour) needs a full minute between calls to avoid exhausting the budget.
const (
	delayWithToken    = time.Second
	delayWithoutToken = 60 * time.Second
	maxPageSize       = 100
)

// Client fetches advisories and maps them to domain signals.
type Client struct {
	http     *sourcehttp.Client
	baseURL  string
	pageSize int
	maxPages int
}

// New builds a GitHub advisory client. An empty token still works, just slowly.
func New(baseURL, token string, opts ...sourcehttp.Option) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}

	// Without a token the hourly budget is only 60 requests, so take a single
	// page per poll; with a token we can afford to walk a few.
	delay, maxPages := delayWithoutToken, 1
	all := []sourcehttp.Option{
		sourcehttp.WithHeader("Accept", "application/vnd.github+json"),
		sourcehttp.WithHeader("X-GitHub-Api-Version", "2022-11-28"),
	}
	if token != "" {
		delay, maxPages = delayWithToken, 3
		all = append(all, sourcehttp.WithHeader("Authorization", "Bearer "+token))
	}
	all = append(all, opts...)

	return &Client{http: sourcehttp.New(delay, all...), baseURL: baseURL, pageSize: maxPageSize, maxPages: maxPages}
}

// Kind reports the source this client speaks for.
func (c *Client) Kind() valueobject.SourceKind { return valueobject.SourceKindGitHubAdvisory }

// Fetch returns advisories updated at or after `since`, walking pages.
//
// It makes two passes. The unfiltered feed is dominated by "unreviewed"
// advisories — automated NVD imports that carry no affected-package data at
// all — so a recency-sorted window buries the handful of reviewed advisories
// that do. Since those are the only ones that link a CVE to a library, and
// blast radius is worthless without that link, the reviewed feed is asked for
// explicitly rather than hoped for.
//
// Duplicates between the passes are dropped, so the extra request costs one
// page of quota and no repeated work downstream.
func (c *Client) Fetch(ctx context.Context, since time.Time) ([]model.SourceSignal, error) {
	var (
		signals []model.SourceSignal
		seen    = make(map[string]struct{})
	)

	for _, advisoryType := range []string{"", typeReviewed} {
		batch, err := c.fetchPass(ctx, since, advisoryType, seen)
		signals = append(signals, batch...)
		if err != nil {
			return signals, err
		}
	}
	return signals, nil
}

// typeReviewed selects the advisories GitHub curates by hand, which are the
// ones carrying ecosystem package linkage.
const typeReviewed = "reviewed"

// fetchPass walks the pages of one feed, skipping advisories already seen.
func (c *Client) fetchPass(ctx context.Context, since time.Time, advisoryType string, seen map[string]struct{}) ([]model.SourceSignal, error) {
	var signals []model.SourceSignal

	for page := 1; page <= c.maxPages; page++ {
		endpoint, err := c.pageURL(since, page, advisoryType)
		if err != nil {
			return signals, err
		}

		var batch []advisory
		if err := c.http.GetJSON(ctx, endpoint, &batch); err != nil {
			return signals, fmt.Errorf("github advisory: %w", err)
		}
		for _, a := range batch {
			if key := dedupeKey(a); key != "" {
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
			}
			signals = append(signals, toSourceSignal(a))
		}
		if len(batch) < c.pageSize {
			break // last page
		}
	}
	return signals, nil
}

// dedupeKey identifies an advisory across the two passes. The GHSA id is the
// stable one; the CVE id is a fallback for records that somehow lack it.
func dedupeKey(a advisory) string {
	if a.GHSAID != "" {
		return a.GHSAID
	}
	return a.CVEID
}

// pageURL builds one request URL. GitHub's `modified` filter takes an
// ISO-8601 range expression, e.g. ">=2024-01-02T03:04:05Z". An empty
// advisoryType asks for every type.
func (c *Client) pageURL(since time.Time, page int, advisoryType string) (string, error) {
	u, err := url.Parse(c.baseURL + "/advisories")
	if err != nil {
		return "", fmt.Errorf("github advisory: parse base url: %w", err)
	}

	q := u.Query()
	q.Set("per_page", strconv.Itoa(c.pageSize))
	q.Set("page", strconv.Itoa(page))
	q.Set("sort", "updated")
	q.Set("direction", "desc")
	if advisoryType != "" {
		q.Set("type", advisoryType)
	}
	if !since.IsZero() {
		q.Set("modified", ">="+since.UTC().Format(time.RFC3339))
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// --- GitHub wire DTOs (private to the adapter) ---

type advisory struct {
	GHSAID      string `json:"ghsa_id"`
	CVEID       string `json:"cve_id"`
	HTMLURL     string `json:"html_url"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	PublishedAt string `json:"published_at"`
	UpdatedAt   string `json:"updated_at"`
	CVSS        struct {
		Score        float64 `json:"score"`
		VectorString string  `json:"vector_string"`
	} `json:"cvss"`
	References []string `json:"references"`
	// Vulnerabilities lists the ecosystem packages this advisory affects.
	// GitHub is the richest source of this linkage, which is what connects
	// an advisory to the repositories that depend on the package.
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
	} `json:"vulnerabilities"`
}

// --- mapping: GitHub wire -> domain ---

func toSourceSignal(a advisory) model.SourceSignal {
	// Prefer the CVE id so records reconcile with other sources; fall back to
	// the GHSA id for advisories that have no CVE assigned.
	id := a.CVEID
	if id == "" {
		id = a.GHSAID
	}

	references := a.References
	if a.HTMLURL != "" {
		references = append([]string{a.HTMLURL}, references...)
	}

	var scores []model.CVSS
	if a.CVSS.Score > 0 || a.CVSS.VectorString != "" {
		scores = append(scores, model.CVSS{
			Version:   cvssVersion(a.CVSS.VectorString),
			BaseScore: a.CVSS.Score,
			Vector:    a.CVSS.VectorString,
			Severity:  toSeverity(a.Severity),
		})
	}

	return model.SourceSignal{
		CVEID:            id,
		Title:            a.Summary,
		Description:      a.Description,
		Scores:           scores,
		References:       references,
		PublishedAt:      parseTime(a.PublishedAt),
		ModifiedAt:       parseTime(a.UpdatedAt),
		AffectedPackages: toAffectedPackages(a),
	}
}

// toAffectedPackages maps the advisory's affected packages onto domain
// references, collapsing the repeats GitHub emits when one package is listed
// once per vulnerable version range.
func toAffectedPackages(a advisory) []valueobject.PackageRef {
	seen := make(map[string]struct{}, len(a.Vulnerabilities))
	out := make([]valueobject.PackageRef, 0, len(a.Vulnerabilities))

	for _, v := range a.Vulnerabilities {
		if v.Package.Name == "" {
			continue
		}
		ref := valueobject.NewPackageRef(v.Package.Ecosystem, v.Package.Name, v.VulnerableVersionRange)
		key := ref.Ecosystem.String() + ":" + ref.Name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ref)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// cvssVersion reads the version prefix out of a CVSS vector string.
func cvssVersion(vector string) string {
	switch {
	case len(vector) >= 8 && vector[:8] == "CVSS:4.0":
		return "4.0"
	case len(vector) >= 8 && vector[:8] == "CVSS:3.1":
		return "3.1"
	case len(vector) >= 8 && vector[:8] == "CVSS:3.0":
		return "3.0"
	default:
		return ""
	}
}

func toSeverity(s string) model.Severity {
	switch s {
	case "low":
		return model.SeverityLow
	case "medium", "moderate":
		return model.SeverityMedium
	case "high":
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
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}
