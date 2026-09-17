package grpc

import (
	"context"
	"fmt"
	"strings"

	alertingv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/alerting/v1"
	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
)

// Subscriptions lists the standing requests to be told about findings.
func (c *Client) Subscriptions(ctx context.Context, tenant string) ([]model.Subscription, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timout)
	defer cancel()

	resp, err := c.alerting.ListSubscriptions(ctx, &alertingv1.ListSubscriptionsRequest{Tenant: tenant})
	if err != nil {
		return nil, fmt.Errorf("grpc: list subscriptions: %w", err)
	}

	out := make([]model.Subscription, 0, len(resp.GetSubscriptions()))
	for _, s := range resp.GetSubscriptions() {
		out = append(out, toSubscription(s))
	}
	return out, nil
}

// CreateSubscription records a new subscription and returns it as stored.
func (c *Client) CreateSubscription(ctx context.Context, tenant, name string, rule model.AlertRule) (model.Subscription, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timout)
	defer cancel()

	resp, err := c.alerting.CreateSubscription(ctx, &alertingv1.CreateSubscriptionRequest{
		Tenant: tenant,
		Name:   name,
		Rule:   toWireRule(rule),
	})
	if err != nil {
		return model.Subscription{}, fmt.Errorf("grpc: create subscription: %w", err)
	}
	return toSubscription(resp.GetSubscription()), nil
}

// DeleteSubscription removes one, reporting whether it existed.
func (c *Client) DeleteSubscription(ctx context.Context, id string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timout)
	defer cancel()

	resp, err := c.alerting.DeleteSubscription(ctx, &alertingv1.DeleteSubscriptionRequest{Id: id})
	if err != nil {
		return false, fmt.Errorf("grpc: delete subscription: %w", err)
	}
	return resp.GetDeleted(), nil
}

// Alerts lists what has already matched, newest first.
func (c *Client) Alerts(ctx context.Context, tenant, subscriptionID string, limit int) ([]model.Alert, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timout)
	defer cancel()

	resp, err := c.alerting.ListAlerts(ctx, &alertingv1.ListAlertsRequest{
		Tenant:         tenant,
		SubscriptionId: subscriptionID,
		Limit:          int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("grpc: list alerts: %w", err)
	}

	out := make([]model.Alert, 0, len(resp.GetAlerts()))
	for _, a := range resp.GetAlerts() {
		out = append(out, model.Alert{
			ID:               a.GetId(),
			SubscriptionID:   a.GetSubscriptionId(),
			SubscriptionName: a.GetSubscriptionName(),
			Tenant:           a.GetTenant(),
			CVEID:            a.GetCveId(),
			Vulnerability:    toViewModel(a.GetVulnerability()),
			Reason:           a.GetReason(),
			CreatedAt:        fromTimestamp(a.GetCreatedAt()),
		})
	}
	return out, nil
}

// --- mapping: wire contract <-> view model ---

func toSubscription(s *alertingv1.Subscription) model.Subscription {
	return model.Subscription{
		ID:        s.GetId(),
		Tenant:    s.GetTenant(),
		Name:      s.GetName(),
		Rule:      toRule(s.GetRule()),
		CreatedAt: fromTimestamp(s.GetCreatedAt()),
	}
}

func toRule(r *alertingv1.AlertRule) model.AlertRule {
	if r == nil {
		return model.AlertRule{}
	}
	rule := model.AlertRule{
		Term:        r.GetTerm(),
		MinSeverity: severityLabel(r.GetMinSeverity()),
		Packages:    toAffectedPackages(r.GetPackages()),
	}
	for _, e := range r.GetEcosystems() {
		rule.Ecosystems = append(rule.Ecosystems, ecosystemLabel(e))
	}
	return rule
}

// toWireRule maps a rule from the edge onto the contract.
//
// The severity and ecosystem names arrive as the strings the GraphQL enums
// use, which are the same spellings the contract enums carry — so the mapping
// is a lookup rather than a translation table that could drift.
func toWireRule(r model.AlertRule) *alertingv1.AlertRule {
	out := &alertingv1.AlertRule{
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
