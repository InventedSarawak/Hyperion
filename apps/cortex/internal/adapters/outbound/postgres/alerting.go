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

// AlertRuleRepo persists alert rules in PostgreSQL.
type AlertRuleRepo struct {
	pool *pgxpool.Pool
}

// NewAlertRuleRepo wraps a pgx pool as a ports.AlertRuleRepo.
func NewAlertRuleRepo(pool *pgxpool.Pool) *AlertRuleRepo {
	return &AlertRuleRepo{pool: pool}
}

const saveAlertRuleSQL = `
INSERT INTO alert_rules (id, tenant, name, criteria, created_at)
VALUES ($1, $2, $3, $4::jsonb, $5)
ON CONFLICT (id) DO UPDATE SET
    tenant = EXCLUDED.tenant,
    name   = EXCLUDED.name,
    criteria = EXCLUDED.criteria;`

// Save inserts or updates an alert rule.
func (r *AlertRuleRepo) Save(ctx context.Context, s model.AlertRule) error {
	if err := s.Validate(); err != nil {
		return err
	}
	criteria, err := json.Marshal(toStoredCriteria(s.Criteria))
	if err != nil {
		return fmt.Errorf("postgres: marshal criteria %s: %w", s.ID, err)
	}
	createdAt := s.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	if _, err := r.pool.Exec(ctx, saveAlertRuleSQL,
		s.ID, s.Tenant, s.Name, string(criteria), createdAt); err != nil {
		return fmt.Errorf("postgres: save alert rule %s: %w", s.ID, err)
	}
	return nil
}

const getAlertRuleSQL = `
SELECT id, tenant, name, criteria, created_at FROM alert_rules WHERE id = $1;`

// Get loads one alert rule, or ports.ErrAlertRuleNotFound.
func (r *AlertRuleRepo) Get(ctx context.Context, id string) (model.AlertRule, error) {
	var (
		s        model.AlertRule
		criteria []byte
	)
	err := r.pool.QueryRow(ctx, getAlertRuleSQL, id).
		Scan(&s.ID, &s.Tenant, &s.Name, &criteria, &s.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.AlertRule{}, ports.ErrAlertRuleNotFound
	}
	if err != nil {
		return model.AlertRule{}, fmt.Errorf("postgres: get alert rule %s: %w", id, err)
	}

	s.Criteria, err = decodeCriteria(criteria)
	if err != nil {
		return model.AlertRule{}, err
	}
	return s, nil
}

const listAlertRulesSQL = `
SELECT id, tenant, name, criteria, created_at
FROM alert_rules
WHERE ($1 = '' OR tenant = $1)
ORDER BY created_at DESC, id;`

// List returns a tenant's alert rules, or every one when tenant is empty.
func (r *AlertRuleRepo) List(ctx context.Context, tenant string) ([]model.AlertRule, error) {
	rows, err := r.pool.Query(ctx, listAlertRulesSQL, tenant)
	if err != nil {
		return nil, fmt.Errorf("postgres: list alert rules: %w", err)
	}
	defer rows.Close()

	var out []model.AlertRule
	for rows.Next() {
		var (
			s        model.AlertRule
			criteria []byte
		)
		if err := rows.Scan(&s.ID, &s.Tenant, &s.Name, &criteria, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan alert rule: %w", err)
		}
		if s.Criteria, err = decodeCriteria(criteria); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Delete removes an alert rule. Its alerts go with it (ON DELETE CASCADE).
func (r *AlertRuleRepo) Delete(ctx context.Context, id string) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM alert_rules WHERE id = $1;`, id); err != nil {
		return fmt.Errorf("postgres: delete alert rule %s: %w", id, err)
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
INSERT INTO alerts (id, rule_id, tenant, cve_id, reason, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (rule_id, cve_id) DO UPDATE SET
    reason     = EXCLUDED.reason,
    created_at = EXCLUDED.created_at;`

// Append records an alert.
//
// Conflicts are resolved on (alert rule, finding) rather than on the id. The
// id is derived from the finding's *current* key, and that key can change — a
// record first stored under a GHSA moves to its CVE when a feed links them —
// so an id-based upsert would insert a second alert about a finding the
// user has already been told about.
func (r *AlertRepo) Append(ctx context.Context, a model.Alert) error {
	if err := a.Validate(); err != nil {
		return err
	}
	createdAt := a.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	if _, err := r.pool.Exec(ctx, appendAlertSQL,
		a.ID, a.RuleID, a.Tenant, a.CVEID, a.Reason, createdAt); err != nil {
		return fmt.Errorf("postgres: append alert %s: %w", a.ID, err)
	}
	return nil
}

const listAlertsSQL = `
SELECT id, rule_id, tenant, cve_id, reason, created_at
FROM alerts
WHERE ($1 = '' OR tenant = $1)
  AND ($2 = '' OR rule_id = $2)
ORDER BY created_at DESC, id
LIMIT $3;`

// List returns alerts newest first.
func (r *AlertRepo) List(ctx context.Context, tenant, ruleID string, limit int) ([]model.Alert, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx, listAlertsSQL, tenant, ruleID, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list alerts: %w", err)
	}
	defer rows.Close()

	var out []model.Alert
	for rows.Next() {
		var a model.Alert
		if err := rows.Scan(&a.ID, &a.RuleID, &a.Tenant, &a.CVEID, &a.Reason, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan alert: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// --- stored shapes ---

// storedCriteria is the JSON form of an alert rule's criteria. The domain type is not
// serialized directly so a rename in the domain is not a silent migration.
type storedCriteria struct {
	Term        string          `json:"term,omitempty"`
	MinSeverity string          `json:"min_severity,omitempty"`
	Packages    []storedPackage `json:"packages,omitempty"`
	Ecosystems  []string        `json:"ecosystems,omitempty"`
}

func toStoredCriteria(r model.Criteria) storedCriteria {
	stored := storedCriteria{Term: r.Term, MinSeverity: string(r.MinSeverity)}
	stored.Packages = toStoredPackages(r.Packages)
	for _, e := range r.Ecosystems {
		stored.Ecosystems = append(stored.Ecosystems, e.String())
	}
	return stored
}

func decodeCriteria(raw []byte) (model.Criteria, error) {
	var stored storedCriteria
	if err := json.Unmarshal(raw, &stored); err != nil {
		return model.Criteria{}, fmt.Errorf("postgres: unmarshal criteria: %w", err)
	}

	rule := model.Criteria{
		Term:        stored.Term,
		MinSeverity: model.Severity(stored.MinSeverity),
		Packages:    fromStoredPackages(stored.Packages),
	}
	for _, e := range stored.Ecosystems {
		rule.Ecosystems = append(rule.Ecosystems, valueobject.ParseEcosystem(e))
	}
	return rule, nil
}
