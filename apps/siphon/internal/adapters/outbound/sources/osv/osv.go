// Package osv holds the shared OSV.dev record shape and its mapping to the
// domain. Two adapters consume OSV — packagefeed (source 8, ecosystem
// watchlist) and gsd (source 10, the community CVE dataset) — so the schema
// and mapping live here rather than being duplicated.
package osv

import (
	"regexp"
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
	// Withdrawn is set when the advisory was retracted — a false positive
	// or a duplicate. A withdrawn record must not raise a finding.
	Withdrawn string `json:"withdrawn"`
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
	// Versions enumerates affected releases exactly. Malware records use it
	// instead of ranges: one poisoned release is not a span of versions.
	Versions []string `json:"versions"`
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
// the record was withdrawn, carries no id at all, or predates `since`.
func ToSourceSignal(v Vulnerability, since time.Time) (model.SourceSignal, bool) {
	id, aliases := Identity(v)
	if id == "" || v.Withdrawn != "" {
		return model.SourceSignal{}, false
	}

	modified := parseTime(v.Modified)
	if !since.IsZero() && !modified.IsZero() && modified.Before(since) {
		return model.SourceSignal{}, false
	}

	description := cleanDetails(v.Details)
	if description == "" {
		description = v.Summary
	}

	references := make([]string, 0, len(v.References))
	for _, r := range v.References {
		if r.URL != "" {
			references = append(references, r.URL)
		}
	}

	kind := model.KindVulnerability
	if isMalware(v) {
		kind = model.KindMalware
	}

	// No summary means no title. Substituting the record id would pass a
	// placeholder off as a title, which is exactly what hid NVD descriptions.
	return model.SourceSignal{
		CVEID:            id,
		Aliases:          aliases,
		Kind:             kind,
		Title:            strings.TrimSpace(v.Summary),
		Description:      description,
		Scores:           scoresFor(v),
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
// version is the affected range written the way GitHub writes it (see
// affectedRange), so records from both feeds read the same.
func toAffectedPackages(v Vulnerability) []valueobject.PackageRef {
	seen := make(map[string]struct{}, len(v.Affected))
	out := make([]valueobject.PackageRef, 0, len(v.Affected))

	for _, a := range v.Affected {
		if a.Package.Name == "" {
			continue
		}
		ecosystem, _, _ := strings.Cut(a.Package.Ecosystem, ":")
		ref := valueobject.NewPackageRef(ecosystem, a.Package.Name, affectedRange(a))
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

// affectedRange renders the affected versions in GitHub's range syntax:
//
//	introduced 2.0.1, fixed 2.15.0   ->  ">= 2.0.1, < 2.15.0"
//	introduced 0, fixed 4.17.21      ->  "< 4.17.21"
//	two spans                        ->  ">= 1.0.0, < 1.2.3 || >= 2.0.0, < 2.0.4"
//	exact releases (malware)         ->  "= 1.14.1 || = 0.30.4"
//
// The upper bound is the point of it: "< 2.15.0" is what tells an analyst
// which release to upgrade to, and recording only where the range starts threw
// that away. "introduced 0" means "from the first release" and has no lower
// bound to print. GIT ranges are skipped — commit hashes mean nothing next to a
// version number.
func affectedRange(a Affected) string {
	var spans []string
	for _, r := range a.Ranges {
		if r.Type == "GIT" {
			continue
		}
		lower := ""
		for _, e := range r.Events {
			switch {
			case e.Introduced != "":
				lower = e.Introduced
			case e.Fixed != "":
				spans = append(spans, span(lower, "< "+e.Fixed))
				lower = ""
			}
		}
		if lower != "" {
			spans = append(spans, span(lower, "")) // still open: no fix yet
		}
	}
	if len(spans) == 0 {
		for _, v := range a.Versions {
			spans = append(spans, "= "+v)
		}
	}
	return strings.Join(spans, " || ")
}

// span joins a lower and upper bound, omitting the lower one when it is the
// very first release.
func span(introduced, upper string) string {
	if introduced == "" || introduced == "0" {
		if upper == "" {
			return ">= 0"
		}
		return upper
	}
	if upper == "" {
		return ">= " + introduced
	}
	return ">= " + introduced + ", " + upper
}

// Identity splits a record's ids into the one it leads with and the rest.
//
// OSV knows each finding by several names — its own id (GHSA-, PYSEC-, GO-,
// MAL-, …) plus the aliases other databases gave it — and every one of them is
// how some other feed, or some user, refers to it. All are kept: dropping the
// GHSA would stop GitHub's copy merging with this one, and dropping the MAL
// would make malware unfindable by the id its reports cite.
//
// The lead id follows the priority cortex stores findings under: a CVE, then
// a GHSA, then a MAL, then the record's own id. cortex re-derives it from the
// full set, so the choice here only keeps siphon's logs readable.
func Identity(v Vulnerability) (id string, aliases []string) {
	seen := make(map[string]struct{}, 1+len(v.Aliases))
	ids := make([]string, 0, 1+len(v.Aliases))
	for _, raw := range append([]string{v.ID}, v.Aliases...) {
		raw = strings.TrimSpace(raw)
		if isCVE(raw) {
			raw = strings.ToUpper(raw)
		}
		if raw == "" {
			continue
		}
		if _, dup := seen[raw]; dup {
			continue
		}
		seen[raw] = struct{}{}
		ids = append(ids, raw)
	}
	if len(ids) == 0 {
		return "", nil
	}

	lead := 0
	for i, candidate := range ids {
		if idRank(candidate) < idRank(ids[lead]) {
			lead = i
		}
	}
	for i, other := range ids {
		if i != lead {
			aliases = append(aliases, other)
		}
	}
	return ids[lead], aliases
}

// idRank orders id schemes by how widely they are shared.
func idRank(id string) int {
	switch {
	case isCVE(id):
		return 0
	case isGHSA(id):
		return 1
	case isMAL(id):
		return 2
	default:
		return 3
	}
}

func isCVE(id string) bool { return strings.HasPrefix(strings.ToUpper(id), "CVE-") }

// isGHSA is case-sensitive on purpose: GHSA ids are, and cortex keeps them so.
func isGHSA(id string) bool { return strings.HasPrefix(id, "GHSA-") }

// isMAL matches OSV's malicious-packages ids, which are issued for nothing else.
func isMAL(id string) bool { return strings.HasPrefix(strings.ToUpper(id), "MAL-") }

// scoresFor is the record's scores, exactly as the feed gave them.
//
// A malicious package used to get a fabricated entry here — severity critical,
// base score 0, no vector — because severity was only ever read off a score,
// and without one the axios compromise listed as UNKNOWN. That entry was a
// severity label wearing CVSS clothes: anything reading the number saw 0, so
// the first rule written as "score at least 7" would have excluded every
// malicious package, which are the findings such a rule most wants.
//
// The rating now lives on the finding itself (model.Vulnerability.Severity,
// set for malware in Normalized), so it can be critical without a score being
// invented for it.
func scoresFor(v Vulnerability) []model.CVSS {
	return toScores(v)
}

// isMalware reports whether the record is from OSV's malicious-package data.
func isMalware(v Vulnerability) bool {
	if isMAL(v.ID) {
		return true
	}
	for _, alias := range v.Aliases {
		if isMAL(alias) {
			return true
		}
	}
	return false
}

// perSourceMarker and sourceDigest are the scaffolding OSV's malware records
// wrap each contributor's report in: a separator, an editing notice, and a
// 64-character digest after each source name. None of it is the advisory.
var (
	perSourceMarker = regexp.MustCompile(`(?m)^\s*(---|_-= Per source details\. Do not edit below this line\.=-_)\s*$`)
	sourceDigest    = regexp.MustCompile(` \([0-9a-f]{64}\)`)
)

// cleanDetails strips that scaffolding and leaves the reports.
func cleanDetails(details string) string {
	details = perSourceMarker.ReplaceAllString(details, "")
	details = sourceDigest.ReplaceAllString(details, "")
	return strings.TrimSpace(details)
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

// PublishedOrModified is when the record was disclosed, falling back to its
// last change for records that omit publication.
func PublishedOrModified(v Vulnerability) time.Time {
	if t := parseTime(v.Published); !t.IsZero() {
		return t
	}
	return parseTime(v.Modified)
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
