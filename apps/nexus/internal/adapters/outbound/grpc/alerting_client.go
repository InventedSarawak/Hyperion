package grpc

import (
	"context"
	"fmt"
	"strings"

	alertingv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/alerting/v1"
	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
)

// AlertRules lists the standing requests to be told about findings.
func (c *Client) AlertRules(ctx context.Context, tenant string) ([]model.AlertRule, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timout)
	defer cancel()

	resp, err := c.alerting.ListAlertRules(ctx, &alertingv1.ListAlertRulesRequest{Tenant: tenant})
	if err != nil {
		return nil, fmt.Errorf("grpc: list alert rules: %w", err)
	}

	out := make([]model.AlertRule, 0, len(resp.GetRules()))
	for _, s := range resp.GetRules() {
		out = append(out, toAlertRule(s))
	}
	return out, nil
}

// CreateAlertRule records a new alert rule and returns it as stored.
func (c *Client) CreateAlertRule(ctx context.Context, tenant, name string, rule model.Criteria) (model.AlertRule, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timout)
	defer cancel()

	resp, err := c.alerting.CreateAlertRule(ctx, &alertingv1.CreateAlertRuleRequest{
		Tenant:   tenant,
		Name:     name,
		Criteria: toWireCriteria(rule),
	})
	if err != nil {
		return model.AlertRule{}, fmt.Errorf("grpc: create alert rule: %w", err)
	}
	return toAlertRule(resp.GetRule()), nil
}

// DeleteAlertRule removes one, reporting whether it existed.
func (c *Client) DeleteAlertRule(ctx context.Context, id string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timout)
	defer cancel()

	resp, err := c.alerting.DeleteAlertRule(ctx, &alertingv1.DeleteAlertRuleRequest{Id: id})
	if err != nil {
		return false, fmt.Errorf("grpc: delete alert rule: %w", err)
	}
	return resp.GetDeleted(), nil
}

// Alerts lists what has already matched, newest first.
func (c *Client) Alerts(ctx context.Context, tenant, ruleID string, limit int) ([]model.Alert, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timout)
	defer cancel()

	resp, err := c.alerting.ListAlerts(ctx, &alertingv1.ListAlertsRequest{
		Tenant: tenant,
		RuleId: ruleID,
		Limit:  int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("grpc: list alerts: %w", err)
	}

	out := make([]model.Alert, 0, len(resp.GetAlerts()))
	for _, a := range resp.GetAlerts() {
		out = append(out, model.Alert{
			ID:            a.GetId(),
			RuleID:        a.GetRuleId(),
			RuleName:      a.GetRuleName(),
			Tenant:        a.GetTenant(),
			CVEID:         a.GetCveId(),
			Vulnerability: toViewModel(a.GetVulnerability()),
			Reason:        a.GetReason(),
			CreatedAt:     fromTimestamp(a.GetCreatedAt()),
		})
	}
	return out, nil
}

// --- mapping: wire contract <-> view model ---

func toAlertRule(s *alertingv1.AlertRule) model.AlertRule {
	return model.AlertRule{
		ID:        s.GetId(),
		Tenant:    s.GetTenant(),
		Name:      s.GetName(),
		Criteria:  toCriteria(s.GetCriteria()),
		CreatedAt: fromTimestamp(s.GetCreatedAt()),
	}
}

func toCriteria(r *alertingv1.AlertCriteria) model.Criteria {
	if r == nil {
		return model.Criteria{}
	}
	rule := model.Criteria{
		Term:        r.GetTerm(),
		MinSeverity: severityLabel(r.GetMinSeverity()),
		Packages:    toAffectedPackages(r.GetPackages()),
	}
	for _, e := range r.GetEcosystems() {
		rule.Ecosystems = append(rule.Ecosystems, ecosystemLabel(e))
	}
	return rule
}

// toWireCriteria maps a rule from the edge onto the contract.
//
// The severity and ecosystem names arrive as the strings the GraphQL enums
// use, which are the same spellings the contract enums carry — so the mapping
// is a lookup rather than a translation table that could drift.
func toWireCriteria(r model.Criteria) *alertingv1.AlertCriteria {
	out := &alertingv1.AlertCriteria{
		Term:        r.Term,
		MinSeverity: wireSeverity(r.MinSeverity),
	}
	for _, p := range r.Packages {
		// A package arrives as its graph key, "npm:next", which is how every
		// other read surface spells it. The contract wants the two halves.
		ecosystem, name, found := strings.Cut(p.Package, ":")
		if !found {
			ecosystem, name = "", p.Package
		}
		out.Packages = append(out.Packages, &commonv1.PackageRef{
			Ecosystem: wireEcosystem(ecosystem),
			Name:      name,
			Version:   p.VersionRange,
		})
	}
	for _, e := range r.Ecosystems {
		out.Ecosystems = append(out.Ecosystems, wireEcosystem(e))
	}
	return out
}

func wireSeverity(name string) commonv1.Severity {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "NONE":
		return commonv1.Severity_SEVERITY_NONE
	case "LOW":
		return commonv1.Severity_SEVERITY_LOW
	case "MEDIUM":
		return commonv1.Severity_SEVERITY_MEDIUM
	case "HIGH":
		return commonv1.Severity_SEVERITY_HIGH
	case "CRITICAL":
		return commonv1.Severity_SEVERITY_CRITICAL
	default:
		// Unspecified means "any severity", which is what an omitted
		// condition should mean.
		return commonv1.Severity_SEVERITY_UNSPECIFIED
	}
}

func wireEcosystem(name string) commonv1.Ecosystem {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "GO":
		return commonv1.Ecosystem_ECOSYSTEM_GO
	case "NPM":
		return commonv1.Ecosystem_ECOSYSTEM_NPM
	case "PYPI":
		return commonv1.Ecosystem_ECOSYSTEM_PYPI
	case "MAVEN":
		return commonv1.Ecosystem_ECOSYSTEM_MAVEN
	case "CARGO":
		return commonv1.Ecosystem_ECOSYSTEM_CARGO
	case "RUBYGEMS":
		return commonv1.Ecosystem_ECOSYSTEM_RUBYGEMS
	case "NUGET":
		return commonv1.Ecosystem_ECOSYSTEM_NUGET
	case "PACKAGIST":
		return commonv1.Ecosystem_ECOSYSTEM_PACKAGIST
	default:
		return commonv1.Ecosystem_ECOSYSTEM_UNSPECIFIED
	}
}
