package model

import (
	"slices"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// Exposure is one finding reaching one repository through one library — the
// row behind "which vulnerabilities does this repository have?", and blast
// radius read the other way round.
type Exposure struct {
	Repository string // "owner/name"
	// Finding is the full record, or only its id when the store has none.
	Finding Vulnerability
	// Package is the vulnerable library; its Version is what the manifest
	// nearest to it declares, e.g. "^5.11.0".
	Package          valueobject.PackageRef
	AffectedVersions string // what the advisory says is affected
	Verdict          valueobject.ExposureVerdict
	Depth            int      // DEPENDS_ON hops from the repository to the library
	Direct           bool     // true when the repository's own manifest names it
	Path             []string // the chain, nearest first, for display
}

// Severity is what the exposure is flagged by: the finding's worst rating,
// with malware counted as critical whatever a feed scored it — installing
// one means the machine is compromised.
func (e Exposure) Severity() Severity {
	if e.Finding.IsMalware() {
		return SeverityCritical
	}
	return e.Finding.TopSeverity()
}

// ExposureSummary counts the serious findings a repository may be exposed
// to, so it can be flagged in a list before anyone opens it.
type ExposureSummary struct {
	// Computed is false when the graph could not be asked, or the repository
	// has no dependencies read yet: the counts then mean "unknown", never
	// "nothing found".
	Computed         bool
	CriticalAffected int
	CriticalPossible int // possibly affected, or unknown
	HighAffected     int
	HighPossible     int
	Total            int // every finding it may be exposed to, any severity
}

// Summarize counts exposures once per finding, at the worst verdict any path
// to it reached. Findings the declared versions rule out are left out; an
// unknown verdict counts as possible, since it cannot be ruled out.
func Summarize(exposures []Exposure) ExposureSummary {
	worst := make(map[string]Exposure, len(exposures))
	for _, e := range exposures {
		if !e.Verdict.Exposed() {
			continue
		}
		if cur, ok := worst[e.Finding.CVEID]; !ok || e.Verdict.Worse(cur.Verdict) {
			worst[e.Finding.CVEID] = e
		}
	}
	s := ExposureSummary{Computed: true, Total: len(worst)}
	for _, e := range worst {
		affected := e.Verdict == valueobject.ExposureAffected
		switch e.Severity() {
		case SeverityCritical:
			if affected {
				s.CriticalAffected++
			} else {
				s.CriticalPossible++
			}
		case SeverityHigh:
			if affected {
				s.HighAffected++
			} else {
				s.HighPossible++
			}
		}
	}
	return s
}

// RepositoryExposure is everything one repository may be exposed to.
type RepositoryExposure struct {
	FullName string
	// Scanned is false when the graph has no such repository: its findings
	// are then unknown, not none.
	Scanned  bool
	Findings []Exposure
	Summary  ExposureSummary
}

// SortExposures orders worst first: by verdict, then severity, then id, so
// the list reads as a to-do list.
func SortExposures(es []Exposure) {
	slices.SortStableFunc(es, func(a, b Exposure) int {
		switch {
		case a.Verdict.Worse(b.Verdict):
			return -1
		case b.Verdict.Worse(a.Verdict):
			return 1
		}
		if ra, rb := a.Severity().rank(), b.Severity().rank(); ra != rb {
			return rb - ra
		}
		return strings.Compare(a.Finding.CVEID, b.Finding.CVEID)
	})
}
