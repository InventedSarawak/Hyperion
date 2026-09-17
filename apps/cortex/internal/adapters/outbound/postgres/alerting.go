package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// SubscriptionRepo persists alert rules in PostgreSQL.
type SubscriptionRepo struct {
	pool *pgxpool.Pool
}

// NewSubscriptionRepo wraps a pgx pool as a ports.SubscriptionRepo.
func NewSubscriptionRepo(pool *pgxpool.Pool) *SubscriptionRepo {
	return &SubscriptionRepo{pool: pool}
}

const saveSubscriptionSQL = `
INSERT INTO subscriptions (id, tenant, name, rule, created_at)
VALUES ($1, $2, $3, $4::jsonb, $5)
ON CONFLICT (id) DO UPDATE SET
    tenant = EXCLUDED.tenant,
    name   = EXCLUDED.name,
    rule   = EXCLUDED.rule;`

// Save inserts or updates a subscription.
func (r *SubscriptionRepo) Save(ctx context.Context, s model.Subscription) error {
	if err := s.Validate(); err != nil {
		return err
	}
	rule, err := json.Marshal(toStoredRule(s.Rule))
	if err != nil {
		return fmt.Errorf("postgres: marshal rule %s: %w", s.ID, err)
	}
	createdAt := s.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	if _, err := r.pool.Exec(ctx, saveSubscriptionSQL,
		s.ID, s.Tenant, s.Name, string(rule), createdAt); err != nil {
		return fmt.Errorf("postgres: save subscription %s: %w", s.ID, err)
	}
	return nil
}

const getSubscriptionSQL = `
SELECT id, tenant, name, rule, created_at FROM subscriptions WHERE id = $1;`

// Get loads one subscription, or ports.ErrSubscriptionNotFound.
func (r *SubscriptionRepo) Get(ctx context.Context, id string) (model.Subscription, error) {
	var (
		s    model.Subscription
		rule []byte
	)
	err := r.pool.QueryRow(ctx, getSubscriptionSQL, id).
		Scan(&s.ID, &s.Tenant, &s.Name, &rule, &s.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Subscription{}, ports.ErrSubscriptionNotFound
	}
	if err != nil {
		return model.Subscription{}, fmt.Errorf("postgres: get subscription %s: %w", id, err)
	}

	s.Rule, err = decodeRule(rule)
	if err != nil {
		return model.Subscription{}, err
	}
	return s, nil
}

const listSubscriptionsSQL = `
SELECT id, tenant, name, rule, created_at
FROM subscriptions
WHERE ($1 = '' OR tenant = $1)
ORDER BY created_at DESC, id;`

// List returns a tenant's subscriptions, or every one when tenant is empty.
func (r *SubscriptionRepo) List(ctx context.Context, tenant string) ([]model.Subscription, error) {
	rows, err := r.pool.Query(ctx, listSubscriptionsSQL, tenant)
	if err != nil {
		return nil, fmt.Errorf("postgres: list subscriptions: %w", err)
	}
	defer rows.Close()

	var out []model.Subscription
	for rows.Next() {
		var (
			s    model.Subscription
			rule []byte
		)
		if err := rows.Scan(&s.ID, &s.Tenant, &s.Name, &rule, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan subscription: %w", err)
		}
		if s.Rule, err = decodeRule(rule); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Delete removes a subscription. Its alerts go with it (ON DELETE CASCADE).
func (r *SubscriptionRepo) Delete(ctx context.Context, id string) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM subscriptions WHERE id = $1;`, id); err != nil {
		return fmt.Errorf("postgres: delete subscription %s: %w", id, err)
	}
	return nil
}

// AlertRepo persists raised alerts in PostgreSQL.
type AlertRepo struct {
	pool *pgxpool.Pool
}

// NewAlertRepo wraps a pgx pool as a ports.AlertRepo.
func NewAlertRepo(pool *pgxpool.Pool) *AlertRepo { return &AlertRepo{pool: pool} }

const appendAlertSQL = `
INSERT INTO alerts (id, subscription_id, tenant, cve_id, reason, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (subscription_id, cve_id) DO UPDATE SET
    reason     = EXCLUDED.reason,
    created_at = EXCLUDED.created_at;`

// Append records an alert.
//
// Conflicts are resolved on (subscription, finding) rather than on the id. The
// id is derived from the finding's *current* key, and that key can change — a
// record first stored under a GHSA moves to its CVE when a feed links them —
// so an id-based upsert would insert a second alert about a finding the
// subscriber has already been told about.
func (r *AlertRepo) Append(ctx context.Context, a model.Alert) error {
	if err := a.Validate(); err != nil {
		return err
	}
	createdAt := a.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	if _, err := r.pool.Exec(ctx, appendAlertSQL,
		a.ID, a.SubscriptionID, a.Tenant, a.CVEID, a.Reason, createdAt); err != nil {
		return fmt.Errorf("postgres: append alert %s: %w", a.ID, err)
	}
	return nil
}

const listAlertsSQL = `
SELECT id, subscription_id, tenant, cve_id, reason, created_at
FROM alerts
WHERE ($1 = '' OR tenant = $1)
  AND ($2 = '' OR subscription_id = $2)
ORDER BY created_at DESC, id
LIMIT $3;`

// List returns alerts newest first.
func (r *AlertRepo) List(ctx context.Context, tenant, subscriptionID string, limit int) ([]model.Alert, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx, listAlertsSQL, tenant, subscriptionID, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list alerts: %w", err)
	}
	defer rows.Close()

	var out []model.Alert
	for rows.Next() {
		var a model.Alert
		if err := rows.Scan(&a.ID, &a.SubscriptionID, &a.Tenant, &a.CVEID, &a.Reason, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan alert: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// --- stored shapes ---

// storedRule is the JSON form of an alert rule. The domain type is not
// serialized directly so a rename in the domain is not a silent migration.
type storedRule struct {
	Term        string          `json:"term,omitempty"`
	MinSeverity string          `json:"min_severity,omitempty"`
	Packages    []storedPackage `json:"packages,omitempty"`
	Ecosystems  []string        `json:"ecosystems,omitempty"`
}

func toStoredRule(r model.AlertRule) storedRule {
	stored := storedRule{Term: r.Term, MinSeverity: string(r.MinSeverity)}
	stored.Packages = toStoredPackages(r.Packages)
	for _, e := range r.Ecosystems {
		stored.Ecosystems = append(stored.Ecosystems, e.String())
	}
	return stored
}

func decodeRule(raw []byte) (model.AlertRule, error) {
	var stored storedRule
	if err := json.Unmarshal(raw, &stored); err != nil {
		return model.AlertRule{}, fmt.Errorf("postgres: unmarshal rule: %w", err)
	}

	rule := model.AlertRule{
		Term:        stored.Term,
		MinSeverity: model.Severity(stored.MinSeverity),
		Packages:    fromStoredPackages(stored.Packages),
	}
	for _, e := range stored.Ecosystems {
		rule.Ecosystems = append(rule.Ecosystems, valueobject.ParseEcosystem(e))
	}
	return rule, nil
}
