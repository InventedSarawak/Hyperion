package grpc

import (
	"context"
	"strings"

	alertingv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/alerting/v1"
	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// AlertRules lists the rules in place.
func (c *Client) AlertRules(ctx context.Context) ([]model.AlertRule, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.alerting.ListAlertRules(ctx, &alertingv1.ListAlertRulesRequest{})
	if err != nil {
		return nil, describe(err)
	}
	out := make([]model.AlertRule, 0, len(resp.GetRules()))
	for _, r := range resp.GetRules() {
		out = append(out, toAlertRule(r))
	}
	return out, nil
}

// CreateAlertRule adds a rule.
func (c *Client) CreateAlertRule(ctx context.Context, name string, criteria model.Criteria) (model.AlertRule, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.alerting.CreateAlertRule(ctx, &alertingv1.CreateAlertRuleRequest{
		Name:     name,
		Criteria: toWireCriteria(criteria),
	})
	if err != nil {
		return model.AlertRule{}, describe(err)
	}
	return toAlertRule(resp.GetRule()), nil
}

// DeleteAlertRule removes a rule.
func (c *Client) DeleteAlertRule(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	if _, err := c.alerting.DeleteAlertRule(ctx, &alertingv1.DeleteAlertRuleRequest{Id: id}); err != nil {
		return describe(err)
	}
	return nil
}

// Alerts lists what has matched, newest first.
func (c *Client) Alerts(ctx context.Context, ruleID string, limit int) ([]model.Alert, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.alerting.ListAlerts(ctx, &alertingv1.ListAlertsRequest{RuleId: ruleID, Limit: int32(limit)})
	if err != nil {
		return nil, describe(err)
	}
	out := make([]model.Alert, 0, len(resp.GetAlerts()))
	for _, a := range resp.GetAlerts() {
		v := toViewModel(a.GetVulnerability())
		if v.CVEID == "" {
			v.CVEID = a.GetCveId()
		}
		out = append(out, model.Alert{
			ID:            a.GetId(),
			RuleID:        a.GetRuleId(),
			RuleName:      a.GetRuleName(),
			CVEID:         a.GetCveId(),
			Reason:        a.GetReason(),
			CreatedAt:     fromTimestamp(a.GetCreatedAt()),
			Vulnerability: v,
		})
	}
	return out, nil
}

func toAlertRule(r *alertingv1.AlertRule) model.AlertRule {
	c := r.GetCriteria()
	criteria := model.Criteria{Term: c.GetTerm()}
	// Unspecified is "any severity" here, not an unknown one.
	if c.GetMinSeverity() != commonv1.Severity_SEVERITY_UNSPECIFIED {
		criteria.MinSeverity = severityLabel(c.GetMinSeverity())
	}
	for _, p := range c.GetPackages() {
		criteria.Packages = append(criteria.Packages, packageLabel(p))
	}
	for _, e := range c.GetEcosystems() {
		criteria.Ecosystems = append(criteria.Ecosystems, ecosystemLabel(e))
	}
	return model.AlertRule{
		ID:        r.GetId(),
		Tenant:    r.GetTenant(),
		Name:      r.GetName(),
		Criteria:  criteria,
		CreatedAt: fromTimestamp(r.GetCreatedAt()),
	}
}

func toWireCriteria(c model.Criteria) *alertingv1.AlertCriteria {
	out := &alertingv1.AlertCriteria{Term: c.Term, MinSeverity: wireSeverity(c.MinSeverity)}
	for _, p := range c.Packages {
		// Packages travel as their graph key, "npm:next"; the contract wants
		// the two halves.
		ecosystem, name, found := strings.Cut(p, ":")
		if !found {
			ecosystem, name = "", p
		}
		out.Packages = append(out.Packages, &commonv1.PackageRef{Ecosystem: wireEcosystem(ecosystem), Name: name})
	}
	for _, e := range c.Ecosystems {
		out.Ecosystems = append(out.Ecosystems, wireEcosystem(e))
	}
	return out
}

func wireSeverity(name string) commonv1.Severity {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "LOW":
		return commonv1.Severity_SEVERITY_LOW
	case "MEDIUM":
		return commonv1.Severity_SEVERITY_MEDIUM
	case "HIGH":
		return commonv1.Severity_SEVERITY_HIGH
	case "CRITICAL":
		return commonv1.Severity_SEVERITY_CRITICAL
	default:
		return commonv1.Severity_SEVERITY_UNSPECIFIED
	}
}

// wireEcosystem is the inverse of ecosystemLabel.
func wireEcosystem(name string) commonv1.Ecosystem {
	name = strings.ToLower(strings.TrimSpace(name))
	for e := range commonv1.Ecosystem_name {
		if ecosystemLabel(commonv1.Ecosystem(e)) == name && name != "" {
			return commonv1.Ecosystem(e)
		}
	}
	return commonv1.Ecosystem_ECOSYSTEM_UNSPECIFIED
}
