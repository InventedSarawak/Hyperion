package graphql

import (
	"context"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

const alertRulesQuery = `query AlertRules {
  alertRules { id tenant name createdAt criteria { term minSeverity packages ecosystems } }
}`

const createAlertRuleMutation = `mutation CreateAlertRule($name: String!, $criteria: AlertCriteriaInput!) {
  createAlertRule(name: $name, criteria: $criteria) {
    id tenant name createdAt criteria { term minSeverity packages ecosystems }
  }
}`

const deleteAlertRuleMutation = `mutation DeleteAlertRule($id: String!) {
  deleteAlertRule(id: $id)
}`

const alertsQuery = `query Alerts($ruleId: String, $limit: Int) {
  alerts(ruleId: $ruleId, limit: $limit) {
    id ruleId ruleName cveId reason createdAt
    vulnerability {
      cveId aliases kind title description references publishedAt modifiedAt sources
      scores { version baseScore vector severity }
      affectedPackages { package versionRange }
    }
  }
}`

type alertRule struct {
	ID        string `json:"id"`
	Tenant    string `json:"tenant"`
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
	Criteria  struct {
		Term        string   `json:"term"`
		MinSeverity string   `json:"minSeverity"`
		Packages    []string `json:"packages"`
		Ecosystems  []string `json:"ecosystems"`
	} `json:"criteria"`
}

func (r alertRule) toModel() model.AlertRule {
	return model.AlertRule{
		ID:        r.ID,
		Tenant:    r.Tenant,
		Name:      r.Name,
		CreatedAt: parseTime(r.CreatedAt),
		Criteria: model.Criteria{
			Term:        r.Criteria.Term,
			MinSeverity: r.Criteria.MinSeverity,
			Packages:    r.Criteria.Packages,
			Ecosystems:  r.Criteria.Ecosystems,
		},
	}
}

// AlertRules lists the rules in place through the gateway.
func (c *Client) AlertRules(ctx context.Context) ([]model.AlertRule, error) {
	var out struct {
		Rules []alertRule `json:"alertRules"`
	}
	if err := c.do(ctx, alertRulesQuery, nil, &out); err != nil {
		return nil, err
	}
	rules := make([]model.AlertRule, 0, len(out.Rules))
	for _, r := range out.Rules {
		rules = append(rules, r.toModel())
	}
	return rules, nil
}

// CreateAlertRule adds a rule through the gateway.
func (c *Client) CreateAlertRule(ctx context.Context, name string, criteria model.Criteria) (model.AlertRule, error) {
	var out struct {
		Rule alertRule `json:"createAlertRule"`
	}
	input := map[string]any{"term": criteria.Term}
	// Absent rather than empty: an empty severity is not a severity, and the
	// gateway would have to guess which was meant.
	if criteria.MinSeverity != "" {
		input["minSeverity"] = criteria.MinSeverity
	}
	if len(criteria.Packages) > 0 {
		input["packages"] = criteria.Packages
	}
	if len(criteria.Ecosystems) > 0 {
		input["ecosystems"] = criteria.Ecosystems
	}
	if err := c.do(ctx, createAlertRuleMutation, map[string]any{"name": name, "criteria": input}, &out); err != nil {
		return model.AlertRule{}, err
	}
	return out.Rule.toModel(), nil
}

// DeleteAlertRule removes a rule through the gateway.
func (c *Client) DeleteAlertRule(ctx context.Context, id string) error {
	var out struct {
		Deleted bool `json:"deleteAlertRule"`
	}
	return c.do(ctx, deleteAlertRuleMutation, map[string]any{"id": id}, &out)
}

// Alerts lists what has matched through the gateway, newest first.
func (c *Client) Alerts(ctx context.Context, ruleID string, limit int) ([]model.Alert, error) {
	var out struct {
		Alerts []struct {
			ID            string        `json:"id"`
			RuleID        string        `json:"ruleId"`
			RuleName      string        `json:"ruleName"`
			CVEID         string        `json:"cveId"`
			Reason        string        `json:"reason"`
			CreatedAt     string        `json:"createdAt"`
			Vulnerability vulnerability `json:"vulnerability"`
		} `json:"alerts"`
	}
	if err := c.do(ctx, alertsQuery, map[string]any{"ruleId": ruleID, "limit": limit}, &out); err != nil {
		return nil, err
	}
	alerts := make([]model.Alert, 0, len(out.Alerts))
	for _, a := range out.Alerts {
		v := a.Vulnerability.toModel()
		if v.CVEID == "" {
			// The finding behind an old alert can be gone — purged as
			// withdrawn, say. The alert still names it.
			v.CVEID = a.CVEID
		}
		alerts = append(alerts, model.Alert{
			ID:            a.ID,
			RuleID:        a.RuleID,
			RuleName:      a.RuleName,
			CVEID:         a.CVEID,
			Reason:        a.Reason,
			CreatedAt:     parseTime(a.CreatedAt),
			Vulnerability: v,
		})
	}
	return alerts, nil
}
