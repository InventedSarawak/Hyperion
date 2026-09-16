package queries

import (
	"context"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// Bounds on one page of alerts.
const (
	DefaultAlertLimit = 50
	MaxAlertLimit     = 500
)

// ListAlerting is the read side of alerting: what rules exist, and what they
// have raised.
type ListAlerting struct {
	subs   ports.SubscriptionRepo
	alerts ports.AlertRepo
}

// NewListAlerting wires the use case with its outbound ports.
func NewListAlerting(subs ports.SubscriptionRepo, alerts ports.AlertRepo) *ListAlerting {
	return &ListAlerting{subs: subs, alerts: alerts}
}

// Subscriptions returns a tenant's rules, or every rule when tenant is empty.
func (q *ListAlerting) Subscriptions(ctx context.Context, tenant string) ([]model.Subscription, error) {
	return q.subs.List(ctx, tenant)
}

// Alerts returns raised alerts, newest first.
func (q *ListAlerting) Alerts(ctx context.Context, tenant, subscriptionID string, limit int) ([]model.Alert, error) {
	switch {
	case limit <= 0:
		limit = DefaultAlertLimit
	case limit > MaxAlertLimit:
		limit = MaxAlertLimit
	}
	return q.alerts.List(ctx, tenant, subscriptionID, limit)
}
