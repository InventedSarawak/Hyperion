package graphql

import (
	"context"

	"github.com/graphql-go/graphql"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
)

// AlertingResolver serves alert rules and the alerts they raised.
//
// Alerting reaches clients through the gateway like everything else a user
// touches: the edge is where authentication, API keys, rate limiting and
// per-tenant scoping land in v4, and a client that went straight to cortex
// would skip all of them. It was gRPC-only until now, which made `grpcurl` the
// only way to use the platform's headline feature.
type AlertingResolver interface {
	AlertRules(ctx context.Context, tenant string) ([]model.AlertRule, error)
	Create(ctx context.Context, tenant, name string, rule model.Criteria) (model.AlertRule, error)
	Delete(ctx context.Context, id string) (bool, error)
	Alerts(ctx context.Context, tenant, ruleID string, limit int) ([]model.Alert, error)
}

// WithAlerting serves the alerting queries and mutations.
func WithAlerting(r AlertingResolver) Option {
	return func(rs *resolvers) { rs.alerting = r }
}

// alertCriteriaType mirrors model.Criteria on the way out.
var alertCriteriaType = graphql.NewObject(graphql.ObjectConfig{
	Name:        "AlertCriteria",
	Description: "What a user wants to hear about. Every stated condition must hold, so conditions narrow rather than widen.",
	Fields: graphql.Fields{
		"term":        &graphql.Field{Type: graphql.String, Description: "Free text over id, title and description."},
		"minSeverity": &graphql.Field{Type: graphql.String, Description: "Least severity worth hearing about."},
		"packages":    &graphql.Field{Type: graphql.NewList(graphql.String), Description: `Library keys, e.g. "npm:next".`},
		"ecosystems":  &graphql.Field{Type: graphql.NewList(graphql.String)},
	},
})

// alertCriteriaInput is the same rule on the way in.
var alertCriteriaInput = graphql.NewInputObject(graphql.InputObjectConfig{
	Name:        "AlertCriteriaInput",
	Description: "At least one condition is required: a rule with none would match every finding ever ingested.",
	Fields: graphql.InputObjectConfigFieldMap{
		"term":        &graphql.InputObjectFieldConfig{Type: graphql.String},
		"minSeverity": &graphql.InputObjectFieldConfig{Type: graphql.String},
		"packages":    &graphql.InputObjectFieldConfig{Type: graphql.NewList(graphql.String)},
		"ecosystems":  &graphql.InputObjectFieldConfig{Type: graphql.NewList(graphql.String)},
	},
})

var alertRuleType = graphql.NewObject(graphql.ObjectConfig{
	Name:        "AlertRule",
	Description: "A standing request to be told about matching findings.",
	Fields: graphql.Fields{
		"id":        &graphql.Field{Type: graphql.String},
		"tenant":    &graphql.Field{Type: graphql.String},
		"name":      &graphql.Field{Type: graphql.String},
		"criteria":  &graphql.Field{Type: alertCriteriaType},
		"createdAt": &graphql.Field{Type: graphql.String},
	},
})

var alertType = graphql.NewObject(graphql.ObjectConfig{
	Name:        "Alert",
	Description: "One finding matching one alert rule.",
	Fields: graphql.Fields{
		"id":        &graphql.Field{Type: graphql.String},
		"ruleId":    &graphql.Field{Type: graphql.String},
		"ruleName":  &graphql.Field{Type: graphql.String},
		"tenant":    &graphql.Field{Type: graphql.String},
		"cveId":     &graphql.Field{Type: graphql.String},
		"reason":    &graphql.Field{Type: graphql.String, Description: "Which conditions matched."},
		"createdAt": &graphql.Field{Type: graphql.String},
		"vulnerability": &graphql.Field{
			Type:        vulnerabilityType,
			Description: "Resolved when the alert is read, so a later correction shows through rather than the alert freezing what was true when it fired.",
		},
	},
})

// alertingFields are the queries alerting adds.
func alertingFields(rs *resolvers) graphql.Fields {
	return graphql.Fields{
		"alertRules": &graphql.Field{
			Type:        graphql.NewList(alertRuleType),
			Description: "Standing requests to be told about findings.",
			Args: graphql.FieldConfigArgument{
				"tenant": &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				if rs.alerting == nil {
					return nil, errUnavailable
				}
				subs, err := rs.alerting.AlertRules(p.Context, argString(p, "tenant"))
				if err != nil {
					return nil, err
				}
				return alertRuleMaps(subs), nil
			},
		},
		"alerts": &graphql.Field{
			Type:        graphql.NewList(alertType),
			Description: "What has already matched, newest first.",
			Args: graphql.FieldConfigArgument{
				"tenant": &graphql.ArgumentConfig{Type: graphql.String},
				"ruleId": &graphql.ArgumentConfig{Type: graphql.String},
				"limit":  &graphql.ArgumentConfig{Type: graphql.Int},
			},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				if rs.alerting == nil {
					return nil, errUnavailable
				}
				alerts, err := rs.alerting.Alerts(p.Context,
					argString(p, "tenant"), argString(p, "ruleId"), argInt(p, "limit"))
				if err != nil {
					return nil, err
				}
				return alertMaps(alerts), nil
			},
		},
	}
}

// alertingMutations are the mutations alerting adds.
func alertingMutations(rs *resolvers) graphql.Fields {
	return graphql.Fields{
		"createAlertRule": &graphql.Field{
			Type:        alertRuleType,
			Description: "Start being told about findings that match a rule.",
			Args: graphql.FieldConfigArgument{
				"name":     &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"criteria": &graphql.ArgumentConfig{Type: graphql.NewNonNull(alertCriteriaInput)},
				"tenant":   &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				if rs.alerting == nil {
					return nil, errUnavailable
				}
				sub, err := rs.alerting.Create(p.Context,
					argString(p, "tenant"), argString(p, "name"), criteriaFromArgs(p.Args["criteria"]))
				if err != nil {
					return nil, err
				}
				return alertRuleMap(sub), nil
			},
		},
		"deleteAlertRule": &graphql.Field{
			Type:        graphql.Boolean,
			Description: "Stop being told. Reports whether the alert rule existed.",
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				if rs.alerting == nil {
					return nil, errUnavailable
				}
				return rs.alerting.Delete(p.Context, argString(p, "id"))
			},
		},
	}
}

// --- mapping: view model -> GraphQL ---

func criteriaFromArgs(raw any) model.Criteria {
	fields, ok := raw.(map[string]any)
	if !ok {
		return model.Criteria{}
	}

	rule := model.Criteria{}
	if term, ok := fields["term"].(string); ok {
		rule.Term = term
	}
	if severity, ok := fields["minSeverity"].(string); ok {
		rule.MinSeverity = severity
	}
	for _, p := range stringList(fields["packages"]) {
		rule.Packages = append(rule.Packages, model.AffectedPackage{Package: p})
	}
	rule.Ecosystems = stringList(fields["ecosystems"])
	return rule
}

func stringList(raw any) []string {
	values, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func alertRuleMaps(subs []model.AlertRule) []map[string]any {
	out := make([]map[string]any, 0, len(subs))
	for _, s := range subs {
		out = append(out, alertRuleMap(s))
	}
	return out
}

func alertRuleMap(s model.AlertRule) map[string]any {
	packages := make([]string, 0, len(s.Criteria.Packages))
	for _, p := range s.Criteria.Packages {
		packages = append(packages, p.Package)
	}
	return map[string]any{
		"id":     s.ID,
		"tenant": s.Tenant,
		"name":   s.Name,
		"criteria": map[string]any{
			"term":        s.Criteria.Term,
			"minSeverity": s.Criteria.MinSeverity,
			"packages":    packages,
			"ecosystems":  s.Criteria.Ecosystems,
		},
		"createdAt": formatTime(s.CreatedAt),
	}
}

func alertMaps(alerts []model.Alert) []map[string]any {
	out := make([]map[string]any, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, map[string]any{
			"id":            a.ID,
			"ruleId":        a.RuleID,
			"ruleName":      a.RuleName,
			"tenant":        a.Tenant,
			"cveId":         a.CVEID,
			"reason":        a.Reason,
			"createdAt":     formatTime(a.CreatedAt),
			"vulnerability": vulnerabilityMap(a.Vulnerability),
		})
	}
	return out
}

// argString reads a string argument, defaulting to empty.
func argString(p graphql.ResolveParams, name string) string {
	v, _ := p.Args[name].(string)
	return v
}

// argInt reads an int argument, defaulting to zero.
func argInt(p graphql.ResolveParams, name string) int {
	v, _ := p.Args[name].(int)
	return v
}
