package model

import "time"

// Criteria is what a user wants to hear about. Every populated
// condition must hold, so conditions narrow rather than widen.
type Criteria struct {
	Term        string
	MinSeverity string
	Packages    []AffectedPackage
	Ecosystems  []string
}

// AlertRule is a standing request to be told about matching findings.
type AlertRule struct {
	ID        string
	Tenant    string
	Name      string
	Criteria  Criteria
	CreatedAt time.Time
}

// Alert is one finding matching one alert rule.
//
// The finding is resolved when the alert is read rather than copied into it,
// so a correction to the record shows through instead of the alert freezing
// whatever was true the moment it fired.
type Alert struct {
	ID            string
	RuleID        string
	RuleName      string
	Tenant        string
	CVEID         string
	Vulnerability Vulnerability
	Reason        string
	CreatedAt     time.Time
}
