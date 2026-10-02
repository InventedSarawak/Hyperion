package commands

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// ManageAlertRules creates and removes alert rules, keeping durable storage
// and the match index in step.
type ManageAlertRules struct {
	subs    ports.AlertRuleRepo
	matcher ports.AlertMatcher
	newID   func() string
	now     func() time.Time
	log     *slog.Logger
}

// NewManageAlertRules wires the use case with its outbound ports.
func NewManageAlertRules(subs ports.AlertRuleRepo, matcher ports.AlertMatcher) *ManageAlertRules {
	return &ManageAlertRules{
		subs: subs, matcher: matcher,
		newID: newAlertRuleID, now: time.Now, log: slog.Default(),
	}
}

// Create stores an alert rule and makes it matchable.
//
// If indexing fails the stored row is rolled back, because the alternative is
// worse than an error: an alert rule that exists, looks healthy in a listing,
// and silently never fires. A user who believes they are being watched
// and is not is in a more dangerous position than one whose create failed.
func (c *ManageAlertRules) Create(ctx context.Context, tenant, name string, rule model.Criteria) (model.AlertRule, error) {
	sub := model.AlertRule{
		ID:       c.newID(),
		Tenant:   tenant,
		Name:     name,
		Criteria: rule,
	}.WithDefaults(c.now())

	if err := sub.Validate(); err != nil {
		return model.AlertRule{}, err
	}
	if c.matcher == nil {
		return model.AlertRule{}, fmt.Errorf("alert rules: no match index configured")
	}

	if err := c.subs.Save(ctx, sub); err != nil {
		return model.AlertRule{}, err
	}

	if err := c.matcher.Register(ctx, sub); err != nil {
		if rollback := c.subs.Delete(ctx, sub.ID); rollback != nil {
			c.log.Error("alert rule stored but not indexed, and rollback failed; it will never fire",
				"rule", sub.ID, "error", rollback)
		}
		return model.AlertRule{}, fmt.Errorf("alert rules: index %s: %w", sub.Name, err)
	}

	c.log.Info("alert rule created", "rule", sub.ID, "name", sub.Name, "tenant", sub.Tenant)
	return sub, nil
}

// Delete removes an alert rule and stops it matching.
//
// The index is cleared first: a rule that is gone from storage but still
// indexed would raise alerts naming an alert rule nobody can look up.
func (c *ManageAlertRules) Delete(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("alert rules: id is required")
	}
	if c.matcher != nil {
		if err := c.matcher.Deregister(ctx, id); err != nil {
			return fmt.Errorf("alert rules: deindex %s: %w", id, err)
		}
	}
	if err := c.subs.Delete(ctx, id); err != nil {
		return err
	}
	c.log.Info("alert rule deleted", "rule", id)
	return nil
}

// Reindex re-registers every stored alert rule, repairing an index that was
// lost or rebuilt. Elasticsearch holds no truth of its own here — Postgres
// does — so the index can always be reconstructed from it.
func (c *ManageAlertRules) Reindex(ctx context.Context) (int, error) {
	if c.matcher == nil {
		return 0, nil
	}
	stored, err := c.subs.List(ctx, "")
	if err != nil {
		return 0, err
	}

	indexed := 0
	for _, sub := range stored {
		if err := c.matcher.Register(ctx, sub); err != nil {
			return indexed, fmt.Errorf("alert rules: reindex %s: %w", sub.ID, err)
		}
		indexed++
	}
	return indexed, nil
}

// newAlertRuleID returns an opaque, unguessable id. Alert rules are
// addressable over the API, so a predictable counter would let anyone
// enumerate other tenants' rules once the API is exposed.
func newAlertRuleID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is not recoverable and must not silently
		// degrade to a guessable id.
		panic(fmt.Sprintf("alert rules: read random: %v", err))
	}
	return "rule_" + hex.EncodeToString(buf)
}
