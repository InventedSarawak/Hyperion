package model

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Alert is one vulnerability matching one subscription.
//
// It stores the CVE id rather than a copy of the record: advisories are
// corrected and re-scored constantly, and an alert that froze the description
// it was raised with would go stale and disagree with the record it points at.
type Alert struct {
	ID             string
	SubscriptionID string
	Tenant         string
	CVEID          string
	Reason         string
	CreatedAt      time.Time
}

// ErrIncompleteAlert is returned when an alert cannot identify what matched.
var ErrIncompleteAlert = errors.New("alert: subscription id and cve id are required")

// NewAlert builds an alert for a subscription that matched a vulnerability.
func NewAlert(sub Subscription, v Vulnerability, at time.Time) Alert {
	return Alert{
		ID:             AlertID(sub.ID, v.CVEID),
		SubscriptionID: sub.ID,
		Tenant:         sub.Tenant,
		CVEID:          v.CVEID,
		Reason:         sub.Rule.Reason(v),
		CreatedAt:      at.UTC(),
	}
}

// AlertID is deterministic: one subscription matching one CVE is one alert,
// however many times the record is re-observed. Re-ingesting a corrected
// advisory updates the alert rather than raising a second one.
func AlertID(subscriptionID, cveID string) string {
	return fmt.Sprintf("%s:%s", subscriptionID, cveID)
}

// Validate enforces the entity's invariants.
func (a Alert) Validate() error {
	if strings.TrimSpace(a.SubscriptionID) == "" || strings.TrimSpace(a.CVEID) == "" {
		return ErrIncompleteAlert
	}
	return nil
}

// DedupeKey identifies "this subscription, this CVE" for the suppression
// window, so a re-observed advisory does not alert the same person twice.
func (a Alert) DedupeKey() string { return "alert:" + a.ID }
