package model

import (
	"errors"
	"strings"
	"time"
)

// Subscription is one subscriber's standing interest in a class of
// vulnerability. It is the entity behind reverse search: instead of everyone
// polling for what they care about, the rule is stored once and every
// incoming finding is matched against it.
type Subscription struct {
	ID        string
	Tenant    string
	Name      string
	Rule      AlertRule
	CreatedAt time.Time
}

// ErrMissingSubscriptionName is returned when a subscription is unnamed.
// The name is what a subscriber sees in an alert, so an anonymous rule
// produces an alert nobody can act on.
var ErrMissingSubscriptionName = errors.New("subscription: name is required")

// DefaultTenant owns subscriptions created before authentication exists.
// Naming it explicitly keeps the per-tenant query paths honest now, so v4 only
// has to supply a real identity rather than introduce the concept.
const DefaultTenant = "default"

// Validate enforces the entity's invariants.
func (s Subscription) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return ErrMissingSubscriptionName
	}
	return s.Rule.Validate()
}

// WithDefaults returns the subscription with its optional fields filled in.
func (s Subscription) WithDefaults(now time.Time) Subscription {
	if strings.TrimSpace(s.Tenant) == "" {
		s.Tenant = DefaultTenant
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now.UTC()
	}
	s.Name = strings.TrimSpace(s.Name)
	return s
}
