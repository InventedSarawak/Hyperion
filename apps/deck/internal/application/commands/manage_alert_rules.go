package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/ports"
)

// alertLimit is how many alerts the Alerts tab asks for at once. Enough to
// scroll through a busy rule; anything older is a question for the API.
const alertLimit = 200

// ManageAlertRules drives the Alerts tab: the rules in place, what each has
// caught, and adding or removing rules. cortex owns the rules and decides
// what is valid; deck refuses only what it can tell is pointless before
// asking — an unnamed rule, or one with nothing to match on.
type ManageAlertRules struct {
	api ports.AlertingAPI
}

// NewManageAlertRules wires the use case with its outbound port.
func NewManageAlertRules(api ports.AlertingAPI) *ManageAlertRules {
	return &ManageAlertRules{api: api}
}

// Rules lists the alert rules in place.
func (c *ManageAlertRules) Rules(ctx context.Context) ([]model.AlertRule, error) {
	if c.api == nil {
		return nil, errNotConnected
	}
	return c.api.AlertRules(ctx)
}

// Create adds a rule.
func (c *ManageAlertRules) Create(ctx context.Context, name string, criteria model.Criteria) (model.AlertRule, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return model.AlertRule{}, fmt.Errorf("new rule: give it a name — it is what an alert says it came from")
	}
	criteria.Term = strings.TrimSpace(criteria.Term)
	criteria.MinSeverity = strings.ToUpper(strings.TrimSpace(criteria.MinSeverity))
	if criteria.IsEmpty() {
		return model.AlertRule{}, fmt.Errorf("new rule: give it a term or a severity — with neither it would match every finding")
	}
	if c.api == nil {
		return model.AlertRule{}, errNotConnected
	}
	return c.api.CreateAlertRule(ctx, name, criteria)
}

// Delete removes a rule. The alerts it raised go with it.
func (c *ManageAlertRules) Delete(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("remove: select a rule first")
	}
	if c.api == nil {
		return errNotConnected
	}
	return c.api.DeleteAlertRule(ctx, id)
}

// Alerts lists what has matched, newest first; an empty ruleID means every
// rule.
func (c *ManageAlertRules) Alerts(ctx context.Context, ruleID string) ([]model.Alert, error) {
	if c.api == nil {
		return nil, errNotConnected
	}
	return c.api.Alerts(ctx, ruleID, alertLimit)
}

var errNotConnected = fmt.Errorf("alerts: not connected to the intelligence service")
