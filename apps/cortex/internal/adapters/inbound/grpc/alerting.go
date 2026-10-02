package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	alertingv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/alerting/v1"
	commonv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/common/v1"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// AlertRuleManager creates and removes alert rules (consumer-side interface).
type AlertRuleManager interface {
	Create(ctx context.Context, tenant, name string, rule model.Criteria) (model.AlertRule, error)
	Delete(ctx context.Context, id string) error
}

// AlertingReader lists rules and the alerts they have raised.
type AlertingReader interface {
	AlertRules(ctx context.Context, tenant string) ([]model.AlertRule, error)
	Alerts(ctx context.Context, tenant, ruleID string, limit int) ([]model.Alert, error)
}

// VulnerabilityLookup resolves the record an alert points at, so a listing can
// show what actually happened rather than a bare CVE id.
type VulnerabilityLookup interface {
	GetByID(ctx context.Context, cveID string) (model.Vulnerability, error)
}

// AlertingServer implements alertingv1.AlertingServiceServer.
type AlertingServer struct {
	alertingv1.UnimplementedAlertingServiceServer
	manager AlertRuleManager
	reader  AlertingReader
	vulns   VulnerabilityLookup
}

// NewAlertingServer wires the gRPC adapter to the alerting use cases.
func NewAlertingServer(manager AlertRuleManager, reader AlertingReader, vulns VulnerabilityLookup) *AlertingServer {
	return &AlertingServer{manager: manager, reader: reader, vulns: vulns}
}

// CreateAlertRule registers a standing interest.
func (s *AlertingServer) CreateAlertRule(ctx context.Context, req *alertingv1.CreateAlertRuleRequest) (*alertingv1.CreateAlertRuleResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.Unavailable, "alerting: not configured")
	}

	sub, err := s.manager.Create(ctx, req.GetTenant(), req.GetName(), toDomainCriteria(req.GetCriteria()))
	if err != nil {
		return nil, mapAlertingError(err)
	}
	return &alertingv1.CreateAlertRuleResponse{Rule: toProtoAlertRule(sub)}, nil
}

// ListAlertRules returns the rules a tenant has.
func (s *AlertingServer) ListAlertRules(ctx context.Context, req *alertingv1.ListAlertRulesRequest) (*alertingv1.ListAlertRulesResponse, error) {
	if s.reader == nil {
		return nil, status.Error(codes.Unavailable, "alerting: not configured")
	}

	subs, err := s.reader.AlertRules(ctx, req.GetTenant())
	if err != nil {
		return nil, mapAlertingError(err)
	}

	out := make([]*alertingv1.AlertRule, 0, len(subs))
	for _, sub := range subs {
		out = append(out, toProtoAlertRule(sub))
	}
	return &alertingv1.ListAlertRulesResponse{Rules: out}, nil
}

// DeleteAlertRule removes a rule and stops it matching.
func (s *AlertingServer) DeleteAlertRule(ctx context.Context, req *alertingv1.DeleteAlertRuleRequest) (*alertingv1.DeleteAlertRuleResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.Unavailable, "alerting: not configured")
	}
	if err := s.manager.Delete(ctx, req.GetId()); err != nil {
		return nil, mapAlertingError(err)
	}
	return &alertingv1.DeleteAlertRuleResponse{Deleted: true}, nil
}

// ListAlerts returns what has matched, newest first, with each alert's
// vulnerability resolved from storage.
func (s *AlertingServer) ListAlerts(ctx context.Context, req *alertingv1.ListAlertsRequest) (*alertingv1.ListAlertsResponse, error) {
	if s.reader == nil {
		return nil, status.Error(codes.Unavailable, "alerting: not configured")
	}

	alerts, err := s.reader.Alerts(ctx, req.GetTenant(), req.GetRuleId(), int(req.GetLimit()))
	if err != nil {
		return nil, mapAlertingError(err)
	}

	// Rule names are looked up once rather than per alert: a listing
	// is usually many alerts from a handful of rules.
	names := s.ruleNames(ctx, req.GetTenant())

	out := make([]*alertingv1.Alert, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, &alertingv1.Alert{
			Id:            a.ID,
			RuleId:        a.RuleID,
			RuleName:      names[a.RuleID],
			Tenant:        a.Tenant,
			CveId:         a.CVEID,
			Vulnerability: s.lookup(ctx, a.CVEID),
			Reason:        a.Reason,
			CreatedAt:     toTimestamp(a.CreatedAt),
		})
	}
	return &alertingv1.ListAlertsResponse{Alerts: out}, nil
}

// ruleNames maps id -> name, tolerating a lookup failure: a missing
// name is cosmetic, and must not fail the listing.
func (s *AlertingServer) ruleNames(ctx context.Context, tenant string) map[string]string {
	names := map[string]string{}
	subs, err := s.reader.AlertRules(ctx, tenant)
	if err != nil {
		return names
	}
	for _, sub := range subs {
		names[sub.ID] = sub.Name
	}
	return names
}

// lookup resolves an alert's vulnerability, returning nil when it cannot be
// read — the alert itself is still worth showing.
func (s *AlertingServer) lookup(ctx context.Context, cveID string) *commonv1.Vulnerability {
	if s.vulns == nil {
		return nil
	}
	v, err := s.vulns.GetByID(ctx, cveID)
	if err != nil {
		return nil
	}
	return toProtoVulnerability(v)
}

// mapAlertingError translates domain failures into gRPC statuses.
func mapAlertingError(err error) error {
	switch {
	case errors.Is(err, model.ErrEmptyCriteria),
		errors.Is(err, model.ErrMissingRuleName),
		errors.Is(err, model.ErrIncompleteAlert):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ports.ErrAlertRuleNotFound):
		return status.Error(codes.NotFound, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// --- mapping ---

func toDomainCriteria(r *alertingv1.AlertCriteria) model.Criteria {
	if r == nil {
		return model.Criteria{}
	}
	rule := model.Criteria{
		Term:        r.GetTerm(),
		MinSeverity: fromProtoSeverity(r.GetMinSeverity()),
	}
	for _, p := range r.GetPackages() {
		rule.Packages = append(rule.Packages, toDomainPackageRef(p))
	}
	for _, e := range r.GetEcosystems() {
		rule.Ecosystems = append(rule.Ecosystems, fromProtoEcosystem(e))
	}
	return rule
}

func toProtoAlertRule(s model.AlertRule) *alertingv1.AlertRule {
	return &alertingv1.AlertRule{
		Id:        s.ID,
		Tenant:    s.Tenant,
		Name:      s.Name,
		Criteria:  toProtoCriteria(s.Criteria),
		CreatedAt: toTimestamp(s.CreatedAt),
	}
}

func toProtoCriteria(r model.Criteria) *alertingv1.AlertCriteria {
	out := &alertingv1.AlertCriteria{
		Term:        r.Term,
		MinSeverity: toProtoSeverity(r.MinSeverity),
		Packages:    toProtoPackageRefs(r.Packages),
	}
	for _, e := range r.Ecosystems {
		out.Ecosystems = append(out.Ecosystems, toProtoEcosystem(e))
	}
	return out
}

// fromProtoSeverity maps the wire enum back onto the domain scale.
func fromProtoSeverity(s commonv1.Severity) model.Severity {
	switch s {
	case commonv1.Severity_SEVERITY_NONE:
		return model.SeverityNone
	case commonv1.Severity_SEVERITY_LOW:
		return model.SeverityLow
	case commonv1.Severity_SEVERITY_MEDIUM:
		return model.SeverityMedium
	case commonv1.Severity_SEVERITY_HIGH:
		return model.SeverityHigh
	case commonv1.Severity_SEVERITY_CRITICAL:
		return model.SeverityCritical
	default:
		return model.SeverityUnknown
	}
}
