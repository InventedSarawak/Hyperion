package model

import "time"

// AlertRule is what a subscriber wants to hear about. Every populated
// condition must hold, so conditions narrow rather than widen.
type AlertRule struct {
	Term        string
	MinSeverity string
	Packages    []AffectedPackage
	Ecosystems  []string
}

// Subscription is a standing request to be told about matching findings.
type Subscription struct {
	ID        string
	Tenant    string
	Name      string
	Rule      AlertRule
	CreatedAt time.Time
}

// Alert is one finding matching one subscription.
//
// The finding is resolved when the alert is read rather than copied into it,
// so a correction to the record shows through instead of the alert freezing
// whatever was true the moment it fired.
type Alert struct {
	ID               string
	SubscriptionID   string
	SubscriptionName string
	Tenant           string
	CVEID            string
	Vulnerability    Vulnerability
	Reason           string
	CreatedAt        time.Time
}
