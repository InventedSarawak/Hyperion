package model

import (
	"errors"
	"strings"
	"time"
)

// AlertRule is one user's standing interest in a class of
// vulnerability. It is the entity behind reverse search: instead of everyone
// polling for what they care about, the rule is stored once and every
// incoming finding is matched against it.
type AlertRule struct {
	ID        string
	Tenant    string
	Name      string
	Criteria  Criteria
	CreatedAt time.Time
}

// ErrMissingRuleName is returned when an alert rule is unnamed.
// The name is what a user sees in an alert, so an anonymous rule
// produces an alert nobody can act on.
var ErrMissingRuleName = errors.New("alert rule: name is required")

// DefaultTenant owns alert rules created before authentication exists.
// Naming it explicitly keeps the per-tenant query paths honest now, so v4 only
// has to supply a real identity rather than introduce the concept.
const DefaultTenant = "default"

// Validate enforces the entity's invariants.
func (s AlertRule) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return ErrMissingRuleName
	}
	return s.Criteria.Validate()
}

// WithDefaults returns the alert rule with its optional fields filled in.
func (s AlertRule) WithDefaults(now time.Time) AlertRule {
	if strings.TrimSpace(s.Tenant) == "" {
		s.Tenant = DefaultTenant
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now.UTC()
	}
	s.Name = strings.TrimSpace(s.Name)
	return s
}
