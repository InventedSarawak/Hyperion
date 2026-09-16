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

// SubscriptionManager creates and removes alert rules (consumer-side interface).
type SubscriptionManager interface {
	Create(ctx context.Context, tenant, name string, rule model.AlertRule) (model.Subscription, error)
	Delete(ctx context.Context, id string) error
}

// AlertingReader lists rules and the alerts they have raised.
type AlertingReader interface {
	Subscriptions(ctx context.Context, tenant string) ([]model.Subscription, error)
	Alerts(ctx context.Context, tenant, subscriptionID string, limit int) ([]model.Alert, error)
}

// VulnerabilityLookup resolves the record an alert points at, so a listing can
// show what actually happened rather than a bare CVE id.
type VulnerabilityLookup interface {
	GetByID(ctx context.Context, cveID string) (model.Vulnerability, error)
}

// AlertingServer implements alertingv1.AlertingServiceServer.
type AlertingServer struct {
	alertingv1.UnimplementedAlertingServiceServer
	manager SubscriptionManager
	reader  AlertingReader
	vulns   VulnerabilityLookup
}

// NewAlertingServer wires the gRPC adapter to the alerting use cases.
func NewAlertingServer(manager SubscriptionManager, reader AlertingReader, vulns VulnerabilityLookup) *AlertingServer {
	return &AlertingServer{manager: manager, reader: reader, vulns: vulns}
}

// CreateSubscription registers a standing interest.
func (s *AlertingServer) CreateSubscription(ctx context.Context, req *alertingv1.CreateSubscriptionRequest) (*alertingv1.CreateSubscriptionResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.Unavailable, "alerting: not configured")
	}

	sub, err := s.manager.Create(ctx, req.GetTenant(), req.GetName(), toDomainRule(req.GetRule()))
	if err != nil {
		return nil, mapAlertingError(err)
	}
	return &alertingv1.CreateSubscriptionResponse{Subscription: toProtoSubscription(sub)}, nil
}

// ListSubscriptions returns the rules a tenant has.
func (s *AlertingServer) ListSubscriptions(ctx context.Context, req *alertingv1.ListSubscriptionsRequest) (*alertingv1.ListSubscriptionsResponse, error) {
	if s.reader == nil {
		return nil, status.Error(codes.Unavailable, "alerting: not configured")
	}

	subs, err := s.reader.Subscriptions(ctx, req.GetTenant())
	if err != nil {
		return nil, mapAlertingError(err)
	}

	out := make([]*alertingv1.Subscription, 0, len(subs))
	for _, sub := range subs {
		out = append(out, toProtoSubscription(sub))
	}
	return &alertingv1.ListSubscriptionsResponse{Subscriptions: out}, nil
}

// DeleteSubscription removes a rule and stops it matching.
func (s *AlertingServer) DeleteSubscription(ctx context.Context, req *alertingv1.DeleteSubscriptionRequest) (*alertingv1.DeleteSubscriptionResponse, error) {
	if s.manager == nil {
		return nil, status.Error(codes.Unavailable, "alerting: not configured")
	}
	if err := s.manager.Delete(ctx, req.GetId()); err != nil {
		return nil, mapAlertingError(err)
	}
	return &alertingv1.DeleteSubscriptionResponse{Deleted: true}, nil
}

// ListAlerts returns what has matched, newest first, with each alert's
// vulnerability resolved from storage.
func (s *AlertingServer) ListAlerts(ctx context.Context, req *alertingv1.ListAlertsRequest) (*alertingv1.ListAlertsResponse, error) {
	if s.reader == nil {
		return nil, status.Error(codes.Unavailable, "alerting: not configured")
	}

	alerts, err := s.reader.Alerts(ctx, req.GetTenant(), req.GetSubscriptionId(), int(req.GetLimit()))
	if err != nil {
		return nil, mapAlertingError(err)
	}

	// Subscription names are looked up once rather than per alert: a listing
	// is usually many alerts from a handful of rules.
	names := s.subscriptionNames(ctx, req.GetTenant())

	out := make([]*alertingv1.Alert, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, &alertingv1.Alert{
			Id:               a.ID,
			SubscriptionId:   a.SubscriptionID,
			SubscriptionName: names[a.SubscriptionID],
			Tenant:           a.Tenant,
			CveId:            a.CVEID,
			Vulnerability:    s.lookup(ctx, a.CVEID),
			Reason:           a.Reason,
			CreatedAt:        toTimestamp(a.CreatedAt),
		})
	}
	return &alertingv1.ListAlertsResponse{Alerts: out}, nil
}

// subscriptionNames maps id -> name, tolerating a lookup failure: a missing
// name is cosmetic, and must not fail the listing.
func (s *AlertingServer) subscriptionNames(ctx context.Context, tenant string) map[string]string {
	names := map[string]string{}
	subs, err := s.reader.Subscriptions(ctx, tenant)
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
	case errors.Is(err, model.ErrEmptyAlertRule),
		errors.Is(err, model.ErrMissingSubscriptionName),
		errors.Is(err, model.ErrIncompleteAlert):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ports.ErrSubscriptionNotFound):
		return status.Error(codes.NotFound, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// --- mapping ---

func toDomainRule(r *alertingv1.AlertRule) model.AlertRule {
	if r == nil {
		return model.AlertRule{}
	}
	rule := model.AlertRule{
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

func toProtoSubscription(s model.Subscription) *alertingv1.Subscription {
	return &alertingv1.Subscription{
		Id:        s.ID,
		Tenant:    s.Tenant,
		Name:      s.Name,
		Rule:      toProtoRule(s.Rule),
		CreatedAt: toTimestamp(s.CreatedAt),
	}
}

func toProtoRule(r model.AlertRule) *alertingv1.AlertRule {
	out := &alertingv1.AlertRule{
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
