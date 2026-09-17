package model

import (
	"strconv"
	"strings"
)

// Publishers file findings in runs. The Linux kernel CNA is the extreme case:
// it publishes hundreds at a time, consecutively numbered, every one of them
// opening "In the Linux kernel, the following vulnerability has been
// resolved" — and since it assigns no CVSS at all, they arrive unscored too.
// Sorted newest-first they arrive adjacent, so one batch fills the screen and
// everything else published that day is pushed below the fold.
//
// Folding a run into a single row puts the rest of the day back on screen
// without hiding anything: the header carries the count and the worst rating
// inside, and the run opens where it stands.
const (
	// MinBatchRun is how many consecutive findings a run needs before it is
	// folded. Five or fewer read perfectly well as ordinary rows — it is the
	// hundred-long runs that cost a screen — so the fold starts at six.
	MinBatchRun = 6
	// minBatchWords is the shortest shared opening that counts as one
	// publisher's template. Long enough that unrelated advisories do not
	// collide on a stock phrase, short enough to catch the openings that
	// actually repeat.
	minBatchWords = 5
)

// LabelMalware stands in for the severity of a malicious package: not a
// rating, but it outranks every one.
const LabelMalware = "MALWARE"

// DisplayLabel is the rating a list shows for this finding.
func (v Vulnerability) DisplayLabel() string {
	if v.IsMalware() {
		return LabelMalware
	}
	return v.SeverityLabel()
}

// severityOrder ranks labels so a fold can report the worst thing inside it.
// UNKNOWN sits at the bottom rather than off the scale: a batch of unscored
// findings is precisely what this exists to fold, and it still has to report
// something. It is below NONE because "nobody has rated this" is a weaker
// claim than "somebody rated it harmless".
var severityOrder = map[string]int{
	"UNKNOWN":    0,
	"NONE":       1,
	"LOW":        2,
	"MEDIUM":     3,
	"HIGH":       4,
	"CRITICAL":   5,
	LabelMalware: 6,
}

// Batch is a run of consecutive findings that open with the same words: what
// one publisher filed in one go.
type Batch struct {
	// Signature is the shared opening, and the key the fold is remembered
	// under. Two runs with the same signature open and close together — to a
	// reader they are the same pile of findings, wherever they sit in the
	// list — and keying on the text rather than on a position means a fold
	// survives the next refresh instead of springing open when a new finding
	// joins the front of the run.
	Signature string
	Hits      []SearchHit
}

// Len is how many findings the batch holds.
func (b Batch) Len() int { return len(b.Hits) }

// Label is the shared opening as a reader should see it. Signature is folded
// to lower case so that a publisher which capitalises inconsistently still
// groups, which is the wrong thing to print; this takes the same words back
// out of the first member, in the casing it was published with.
func (b Batch) Label() string {
	if len(b.Hits) == 0 {
		return b.Signature
	}
	words := strings.Fields(b.Hits[0].Vulnerability.Headline())
	n := len(strings.Fields(b.Signature))
	if n > len(words) {
		n = len(words)
	}
	return strings.Join(words[:n], " ")
}

// Worst is the highest rating inside the batch, so folding a run can never
// bury the one finding in it that mattered.
func (b Batch) Worst() string {
	worst := "UNKNOWN"
	for _, h := range b.Hits {
		if label := h.Vulnerability.DisplayLabel(); severityOrder[label] > severityOrder[worst] {
			worst = label
		}
	}
	return worst
}

// Breakdown counts the batch by rating, worst first: "1 high · 63 medium ·
// 136 unknown". It is what makes the fold safe to leave closed.
func (b Batch) Breakdown() string {
	counts := map[string]int{}
	for _, h := range b.Hits {
		counts[h.Vulnerability.DisplayLabel()]++
	}
	order := []string{LabelMalware, "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}
	parts := make([]string, 0, len(counts))
	for _, label := range order {
		if n := counts[label]; n > 0 {
			parts = append(parts, strings.ToLower(label)+" "+strconv.Itoa(n))
		}
	}
	return strings.Join(parts, " · ")
}

// FeedRow is one line of the findings list: an ordinary finding, or the header
// of a folded run.
type FeedRow struct {
	// Batch is set on a fold's header row; Vulnerability on every other row.
	Batch *Batch
	// Vulnerability is the finding on this row, zero on a header.
	Vulnerability Vulnerability
	// Nested marks a finding shown because the run it belongs to is open,
	// which the list indents.
	Nested bool
}

// IsBatch reports whether the row is a fold's header.
func (r FeedRow) IsBatch() bool { return r.Batch != nil }

// Rows projects the feed into display lines, folding every run of MinBatchRun
// or more findings whose signature is not in expanded.
func (f Feed) Rows(expanded map[string]bool) []FeedRow {
	runs := batches(f.Hits)
	out := make([]FeedRow, 0, len(f.Hits))
	for _, run := range runs {
		if run.Len() < MinBatchRun {
			for _, h := range run.Hits {
				out = append(out, FeedRow{Vulnerability: h.Vulnerability})
			}
			continue
		}
		folded := run
		out = append(out, FeedRow{Batch: &folded})
		if !expanded[run.Signature] {
			continue
		}
		for _, h := range run.Hits {
			out = append(out, FeedRow{Vulnerability: h.Vulnerability, Nested: true})
		}
	}
	return out
}

// RowIndexOf returns the row a CVE occupies, or -1 when it is not on screen —
// including when it is inside a closed fold, which is not a row of its own.
func (f Feed) RowIndexOf(rows []FeedRow, cveID string) int {
	for i, r := range rows {
		if !r.IsBatch() && r.Vulnerability.CVEID == cveID {
			return i
		}
	}
	return -1
}

// batches splits hits into consecutive runs sharing an opening. The run's
// signature narrows as it grows: each candidate is kept only while the words
// every member still shares stay long enough to be a template rather than a
// coincidence, so a run ends exactly where the wording stops repeating.
func batches(hits []SearchHit) []Batch {
	var out []Batch
	for i := 0; i < len(hits); {
		words := headlineWords(hits[i].Vulnerability)
		shared := words
		j := i + 1
		for j < len(hits) {
			next := commonPrefix(shared, headlineWords(hits[j].Vulnerability))
			if len(next) < minBatchWords {
				break
			}
			shared, j = next, j+1
		}
		if j-i < MinBatchRun {
			// Not a fold, so it needs no signature: leaving it empty keeps
			// short runs from ever colliding in the expansion map.
			out = append(out, Batch{Hits: hits[i:j]})
		} else {
			out = append(out, Batch{Signature: strings.Join(shared, " "), Hits: hits[i:j]})
		}
		i = j
	}
	return out
}

// headlineWords is the finding's headline split for prefix comparison, folded
// to lower case so a publisher that capitalises inconsistently still groups.
func headlineWords(v Vulnerability) []string {
	return strings.Fields(strings.ToLower(v.Headline()))
}

// commonPrefix returns the words a and b start with in common.
func commonPrefix(a, b []string) []string {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return a[:i]
}
