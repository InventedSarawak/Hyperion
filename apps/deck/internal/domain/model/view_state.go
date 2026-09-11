// Package model holds deck's view models: the shapes the terminal UI renders.
// deck is a read-only client — it owns no business rules, only the vocabulary
// its views need, mapped from the wire contract at the adapter boundary.
package model

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

// CVSS is one scored assessment as deck displays it.
type CVSS struct {
	Version   string
	BaseScore float64
	Vector    string
	Severity  string
}

// Vulnerability is a finding as deck displays it.
type Vulnerability struct {
	CVEID       string
	Title       string
	Description string
	Scores      []CVSS
	References  []string
	PublishedAt time.Time
	ModifiedAt  time.Time
}

// TopScore returns the highest-scoring assessment, and whether there was one.
// Feeds disagree, and the worst case is the one an analyst needs to see first.
func (v Vulnerability) TopScore() (CVSS, bool) {
	var (
		best  CVSS
		found bool
	)
	for _, s := range v.Scores {
		if !found || s.BaseScore > best.BaseScore {
			best, found = s, true
		}
	}
	return best, found
}

// SeverityLabel is the qualitative rating to show, falling back to the score
// when a feed gave a number but no label.
func (v Vulnerability) SeverityLabel() string {
	top, ok := v.TopScore()
	if !ok {
		return "UNKNOWN"
	}
	if label := strings.ToUpper(strings.TrimSpace(top.Severity)); label != "" && label != "UNKNOWN" {
		return label
	}
	switch {
	case top.BaseScore >= 9.0:
		return "CRITICAL"
	case top.BaseScore >= 7.0:
		return "HIGH"
	case top.BaseScore >= 4.0:
		return "MEDIUM"
	case top.BaseScore > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// Headline is the one-line summary shown in the feed.
//
// Advisory titles routinely contain tabs and newlines — NVD and vendor feeds
// wrap their text — and those must not survive into a table row. A tab renders
// as up to eight columns while counting as one character, so a row containing
// one is wider on screen than any width calculation believes; it wraps, and the
// wrap desynchronises the frame diff, leaving fragments of the previous frame
// on screen. OneLine is what keeps that from happening.
func (v Vulnerability) Headline() string {
	title := OneLine(v.Title)
	if title == "" {
		title = OneLine(v.Description)
	}
	if title == "" {
		return v.CVEID
	}
	return title
}

// OneLine flattens text to a single line: every control character becomes a
// space, and runs of whitespace collapse to one.
func OneLine(s string) string {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(cleaned), " ")
}

// SearchHit is one scored result.
type SearchHit struct {
	Vulnerability Vulnerability
	Score         float64
}

// SearchSort orders the feed.
type SearchSort string

const (
	// SortNewest is the live feed: most recently published first.
	SortNewest SearchSort = "newest"
	// SortRelevance is best match first, for a search term.
	SortRelevance SearchSort = "relevance"
)

// Label is how the sort is named on screen.
func (s SearchSort) Label() string {
	if s == SortRelevance {
		return "best match"
	}
	return "newest"
}

// SearchPage is one page from the intelligence service.
type SearchPage struct {
	Hits              []SearchHit
	NextPageToken     string
	Total             int64
	TotalIsLowerBound bool
}

// Feed is the list of findings on screen: every page loaded so far, and how
// to fetch the next.
type Feed struct {
	Query             string
	Sort              SearchSort
	Hits              []SearchHit
	NextPageToken     string
	Total             int64
	TotalIsLowerBound bool
	UpdatedAt         time.Time
}

// HasMore reports whether another page can be loaded.
func (f Feed) HasMore() bool { return f.NextPageToken != "" }

// Append adds the following page, skipping results already in the feed.
//
// Paging a newest-first list by offset shifts when records arrive between two
// requests: one new finding pushes the last item of page one onto the start of
// page two. Deduplicating on the CVE id keeps that from showing up twice.
func (f Feed) Append(page SearchPage) Feed {
	seen := make(map[string]struct{}, len(f.Hits))
	for _, h := range f.Hits {
		seen[h.Vulnerability.CVEID] = struct{}{}
	}
	hits := append([]SearchHit{}, f.Hits...)
	for _, h := range page.Hits {
		if _, ok := seen[h.Vulnerability.CVEID]; ok {
			continue
		}
		seen[h.Vulnerability.CVEID] = struct{}{}
		hits = append(hits, h)
	}
	f.Hits = hits
	f.NextPageToken = page.NextPageToken
	f.Total, f.TotalIsLowerBound = page.Total, page.TotalIsLowerBound
	return f
}

// IndexOf returns the position of a CVE in the feed, or -1.
func (f Feed) IndexOf(cveID string) int {
	for i, h := range f.Hits {
		if h.Vulnerability.CVEID == cveID {
			return i
		}
	}
	return -1
}

// ImpactedRepository is one repository exposed to a vulnerability.
type ImpactedRepository struct {
	FullName   string
	AuthorName string
	URL        string
	ViaPackage string
	Depth      int
	Direct     bool
	Path       []string
}

// Chain renders the dependency path as an arrow-separated line.
func (r ImpactedRepository) Chain() string {
	if len(r.Path) == 0 {
		return r.FullName
	}
	return strings.Join(r.Path, " → ")
}

// Reach describes how the repository is exposed, for display.
func (r ImpactedRepository) Reach() string {
	if r.Direct {
		return "direct"
	}
	return fmt.Sprintf("%d hops", r.Depth)
}

// BlastRadius is the answer to "who is exposed to this CVE?".
type BlastRadius struct {
	CVEID              string
	VulnerablePackages []string
	Repositories       []ImpactedRepository
}

// Linked reports whether the CVE is connected to any library at all. When it
// is false, an empty result means the question could not be answered — not
// that nothing is affected.
func (b BlastRadius) Linked() bool { return len(b.VulnerablePackages) > 0 }

// ByPackage groups the impacted repositories under the vulnerable library each
// one was reached through, preserving the order the packages were reported in.
func (b BlastRadius) ByPackage() map[string][]ImpactedRepository {
	out := make(map[string][]ImpactedRepository, len(b.VulnerablePackages))
	for _, r := range b.Repositories {
		out[r.ViaPackage] = append(out[r.ViaPackage], r)
	}
	return out
}
