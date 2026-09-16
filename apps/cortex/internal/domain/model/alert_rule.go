package model

import (
	"errors"
	"fmt"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// AlertRule is what a subscriber wants to hear about.
//
// Populated conditions are AND-ed, so each one narrows the match. A rule with
// no conditions is invalid rather than universal: matching everything is the
// alert fatigue this platform exists to prevent, and it is far too easy to
// create by accident.
type AlertRule struct {
	Term        string
	MinSeverity Severity
	Packages    []valueobject.PackageRef
	Ecosystems  []valueobject.Ecosystem
}

// ErrEmptyAlertRule is returned when a rule states no conditions.
var ErrEmptyAlertRule = errors.New("alert rule: state at least one condition")

// Validate enforces the value object's invariants.
func (r AlertRule) Validate() error {
	if r.IsEmpty() {
		return ErrEmptyAlertRule
	}
	return nil
}

// IsEmpty reports whether the rule constrains nothing.
func (r AlertRule) IsEmpty() bool {
	return strings.TrimSpace(r.Term) == "" &&
		!r.MinSeverity.IsRanked() &&
		len(r.Packages) == 0 &&
		len(r.Ecosystems) == 0
}

// Matches reports whether a vulnerability satisfies every stated condition.
//
// This is the authoritative definition of a match. The Elasticsearch
// percolator is an index that finds candidate rules quickly; this is what the
// rule actually means, and it is what the tests assert against.
func (r AlertRule) Matches(v Vulnerability) bool {
	return r.matchesTerm(v) && r.matchesSeverity(v) &&
		r.matchesPackages(v) && r.matchesEcosystems(v)
}

// Reason explains which conditions matched, for display in an alert.
func (r AlertRule) Reason(v Vulnerability) string {
	var parts []string
	if term := strings.TrimSpace(r.Term); term != "" {
		parts = append(parts, fmt.Sprintf("matched %q", term))
	}
	if r.MinSeverity.IsRanked() {
		parts = append(parts, fmt.Sprintf("severity >= %s", r.MinSeverity))
	}
	if names := matchedPackages(r.Packages, v); len(names) > 0 {
		parts = append(parts, "affects "+strings.Join(names, ", "))
	}
	if len(r.Ecosystems) > 0 {
		parts = append(parts, "ecosystem match")
	}
	if len(parts) == 0 {
		return "matched"
	}
	return strings.Join(parts, "; ")
}

func (r AlertRule) matchesTerm(v Vulnerability) bool {
	term := strings.ToLower(strings.TrimSpace(r.Term))
	if term == "" {
		return true
	}
	haystack := strings.ToLower(v.CVEID + " " + v.Title + " " + v.Description)
	return strings.Contains(haystack, term)
}

func (r AlertRule) matchesSeverity(v Vulnerability) bool {
	if !r.MinSeverity.IsRanked() {
		return true
	}
	return v.TopSeverity().AtLeast(r.MinSeverity)
}

func (r AlertRule) matchesPackages(v Vulnerability) bool {
	if len(r.Packages) == 0 {
		return true
	}
	return len(matchedPackages(r.Packages, v)) > 0
}

func (r AlertRule) matchesEcosystems(v Vulnerability) bool {
	if len(r.Ecosystems) == 0 {
		return true
	}
	for _, want := range r.Ecosystems {
		for _, affected := range v.AffectedPackages {
			if affected.Ecosystem == want {
				return true
			}
		}
	}
	return false
}

// matchedPackages returns the watched libraries the vulnerability affects.
// Version is ignored on purpose: a rule tracks a library, not a pin.
func matchedPackages(watched []valueobject.PackageRef, v Vulnerability) []string {
	affected := make(map[string]struct{}, len(v.AffectedPackages))
	for _, p := range v.AffectedPackages {
		affected[p.Key()] = struct{}{}
	}

	var names []string
	for _, w := range watched {
		if _, ok := affected[w.Key()]; ok {
			names = append(names, w.Key())
		}
	}
	return names
}
