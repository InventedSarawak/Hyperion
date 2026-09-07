// Package osv holds the shared OSV.dev record shape and its mapping to the
// domain. Two adapters consume OSV — packagefeed (source 8, ecosystem
// watchlist) and gsd (source 10, the community CVE dataset) — so the schema
// and mapping live here rather than being duplicated.
package osv

import (
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// Vulnerability is an OSV record, trimmed to the fields we map.
type Vulnerability struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Modified  string   `json:"modified"`
	Published string   `json:"published"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	// Affected names the packages and version ranges the record applies to.
	// This is what links the finding into the dependency graph.
	Affected []Affected `json:"affected"`
}

// Affected is one package an OSV record applies to, with its version ranges.
type Affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Purl      string `json:"purl"`
	} `json:"package"`
	Ranges []AffectedRange `json:"ranges"`
}

// AffectedRange is one version range, expressed as ordered events.
type AffectedRange struct {
	Type   string `json:"type"`
	Events []struct {
		Introduced string `json:"introduced"`
		Fixed      string `json:"fixed"`
	} `json:"events"`
}

// ToSourceSignal maps an OSV record to a domain signal. It reports false when
// the record has no CVE alias (the domain keys signals by CVE id) or when it
// predates `since`.
func ToSourceSignal(v Vulnerability, since time.Time) (model.SourceSignal, bool) {
	cve := cveAlias(v)
	if cve == "" {
		return model.SourceSignal{}, false
	}

	modified := parseTime(v.Modified)
	if !since.IsZero() && !modified.IsZero() && modified.Before(since) {
		return model.SourceSignal{}, false
	}

	description := v.Details
	if description == "" {
		description = v.Summary
	}

	references := make([]string, 0, len(v.References))
	for _, r := range v.References {
		if r.URL != "" {
			references = append(references, r.URL)
		}
	}

	title := v.Summary
	if title == "" {
		title = v.ID
	}

	return model.SourceSignal{
		CVEID:            cve,
		Title:            title,
		Description:      description,
		Scores:           toScores(v),
		References:       references,
		PublishedAt:      parseTime(v.Published),
		ModifiedAt:       modified,
		AffectedPackages: toAffectedPackages(v),
	}, true
}

// toAffectedPackages maps OSV's affected[] onto domain package references.
//
// OSV ecosystem strings can carry a distribution suffix ("Debian:11",
// "Alpine:v3.18"); only the registry before the colon is the ecosystem. The
// affected range is recorded as the first "introduced" version, which is what
// the feed states rather than a resolved version.
func toAffectedPackages(v Vulnerability) []valueobject.PackageRef {
	seen := make(map[string]struct{}, len(v.Affected))
	out := make([]valueobject.PackageRef, 0, len(v.Affected))

	for _, a := range v.Affected {
		if a.Package.Name == "" {
			continue
		}
		ecosystem, _, _ := strings.Cut(a.Package.Ecosystem, ":")
		ref := valueobject.NewPackageRef(ecosystem, a.Package.Name, introducedVersion(a.Ranges))
		if _, ok := seen[ref.Ecosystem.String()+":"+ref.Name]; ok {
			continue
		}
		seen[ref.Ecosystem.String()+":"+ref.Name] = struct{}{}
		out = append(out, ref)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// introducedVersion returns the first non-zero "introduced" bound, which is
// the closest thing OSV offers to "the version this starts affecting".
func introducedVersion(ranges []AffectedRange) string {
	for _, r := range ranges {
		for _, e := range r.Events {
			if e.Introduced != "" && e.Introduced != "0" {
				return e.Introduced
			}
		}
	}
	return ""
}

// cveAlias finds the CVE identifier among an OSV record's aliases (or its own
// id, when the record is itself a CVE).
func cveAlias(v Vulnerability) string {
	if strings.HasPrefix(strings.ToUpper(v.ID), "CVE-") {
		return strings.ToUpper(v.ID)
	}
	for _, alias := range v.Aliases {
		if strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
			return strings.ToUpper(alias)
		}
	}
	return ""
}

// toScores reads CVSS vectors out of the OSV severity array.
func toScores(v Vulnerability) []model.CVSS {
	var out []model.CVSS
	for _, s := range v.Severity {
		if s.Score == "" {
			continue
		}
		out = append(out, model.CVSS{
			Version:  versionFromVector(s.Score),
			Vector:   s.Score,
			Severity: severityLabel(v.DatabaseSpecific.Severity),
		})
	}
	return out
}

func versionFromVector(vector string) string {
	switch {
	case strings.HasPrefix(vector, "CVSS:4.0"):
		return "4.0"
	case strings.HasPrefix(vector, "CVSS:3.1"):
		return "3.1"
	case strings.HasPrefix(vector, "CVSS:3.0"):
		return "3.0"
	default:
		return ""
	}
}

func severityLabel(s string) model.Severity {
	switch strings.ToUpper(s) {
	case "LOW":
		return model.SeverityLow
	case "MODERATE", "MEDIUM":
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
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
