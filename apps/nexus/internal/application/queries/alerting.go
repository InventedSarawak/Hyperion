package queries

import (
	"context"
	"fmt"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/ports"
)

// maxAlerts bounds one page of alerts, so a client asking for everything gets
// a page rather than the whole history.
const maxAlerts = 200

// Alerting is the gateway's view of alert rules and the alerts they raised.
//
// Read and write in one use case because they are one feature to a caller:
// there is no useful "list alert rules" without "create one", and splitting
// them would give the schema two objects to wire for one idea.
type Alerting struct {
	client ports.AlertingClient
}

// NewAlerting wires the use case with its outbound port.
func NewAlerting(client ports.AlertingClient) *Alerting { return &Alerting{client: client} }

// AlertRules lists standing requests to be told about findings.
func (q *Alerting) AlertRules(ctx context.Context, tenant string) ([]model.AlertRule, error) {
	return q.client.AlertRules(ctx, strings.TrimSpace(tenant))
}

// Create records a new alert rule.
//
// A rule with no conditions is refused here rather than at the far end: it
// would match every finding ever ingested, which is the alert fatigue the
// platform exists to prevent, and saying so at the edge gives the caller a
// straight answer instead of a gRPC status.
func (q *Alerting) Create(ctx context.Context, tenant, name string, rule model.Criteria) (model.AlertRule, error) {
	if strings.TrimSpace(name) == "" {
		return model.AlertRule{}, fmt.Errorf("an alert rule needs a name")
	}
	if isEmptyRule(rule) {
		return model.AlertRule{}, fmt.Errorf("a rule needs at least one condition: term, minSeverity, packages or ecosystems")
	}
	return q.client.CreateAlertRule(ctx, strings.TrimSpace(tenant), strings.TrimSpace(name), rule)
}

// Delete removes an alert rule, reporting whether it existed.
func (q *Alerting) Delete(ctx context.Context, id string) (bool, error) {
	if strings.TrimSpace(id) == "" {
		return false, fmt.Errorf("an alert rule id is required")
	}
	return q.client.DeleteAlertRule(ctx, strings.TrimSpace(id))
}

// Alerts lists what has already matched, newest first.
func (q *Alerting) Alerts(ctx context.Context, tenant, ruleID string, limit int) ([]model.Alert, error) {
	if limit <= 0 || limit > maxAlerts {
		limit = maxAlerts
	}
	return q.client.Alerts(ctx, strings.TrimSpace(tenant), strings.TrimSpace(ruleID), limit)
}

// isEmptyRule reports whether a rule states no conditions at all.
func isEmptyRule(r model.Criteria) bool {
	return strings.TrimSpace(r.Term) == "" &&
		strings.TrimSpace(r.MinSeverity) == "" &&
		len(r.Packages) == 0 &&
		len(r.Ecosystems) == 0
}
