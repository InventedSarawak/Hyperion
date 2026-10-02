package model

import (
	"strings"
	"time"
)

// Criteria is what an alert rule matches. Every stated condition must hold, so
// conditions narrow rather than widen.
type Criteria struct {
	Term        string
	MinSeverity string   // "LOW", "MEDIUM", "HIGH" or "CRITICAL"; empty is any severity
	Packages    []string // library keys, e.g. "npm:next"
	Ecosystems  []string
}

// IsEmpty reports whether no condition is stated. Such criteria would match
// every finding ever ingested — the alert fatigue the platform exists to
// prevent — so the gateway refuses them, and deck refuses them first.
func (c Criteria) IsEmpty() bool {
	return strings.TrimSpace(c.Term) == "" && strings.TrimSpace(c.MinSeverity) == "" &&
		len(c.Packages) == 0 && len(c.Ecosystems) == 0
}

// Summary is the criteria in one line, for a list:
//
//	"log4j" · high+ · npm:next
func (c Criteria) Summary() string {
	var parts []string
	if t := strings.TrimSpace(c.Term); t != "" {
		parts = append(parts, `"`+t+`"`)
	}
	if s := strings.TrimSpace(c.MinSeverity); s != "" {
		parts = append(parts, strings.ToLower(s)+"+")
	}
	parts = append(parts, c.Packages...)
	parts = append(parts, c.Ecosystems...)
	if len(parts) == 0 {
		return "anything"
	}
	return strings.Join(parts, " · ")
}

// AlertRule is a standing request to be told about matching findings.
type AlertRule struct {
	ID        string
	Tenant    string
	Name      string
	Criteria  Criteria
	CreatedAt time.Time
}

// Alert is one finding that matched one rule.
type Alert struct {
	ID       string
	RuleID   string
	RuleName string
	CVEID    string
	// Reason says which conditions matched, e.g. `matched "log4j"`.
	Reason    string
	CreatedAt time.Time
	// Vulnerability is the finding as it stands now, resolved when the alert
	// is read — so a later correction shows through rather than the alert
	// freezing what was true when it fired.
	Vulnerability Vulnerability
}

// Severities are the levels a rule can ask for, least severe first. The empty
// first entry is "any": a rule that cares only about its term.
var Severities = []string{"", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

// SeverityChoice names a severity for a picker.
func SeverityChoice(s string) string {
	if s == "" {
		return "any"
	}
	return strings.ToLower(s) + " and above"
}
