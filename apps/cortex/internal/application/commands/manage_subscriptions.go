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

// ManageSubscriptions creates and removes alert rules, keeping durable storage
// and the match index in step.
type ManageSubscriptions struct {
	subs    ports.SubscriptionRepo
	matcher ports.AlertMatcher
	newID   func() string
	now     func() time.Time
	log     *slog.Logger
}

// NewManageSubscriptions wires the use case with its outbound ports.
func NewManageSubscriptions(subs ports.SubscriptionRepo, matcher ports.AlertMatcher) *ManageSubscriptions {
	return &ManageSubscriptions{
		subs: subs, matcher: matcher,
		newID: newSubscriptionID, now: time.Now, log: slog.Default(),
	}
}

// Create stores a subscription and makes it matchable.
//
// If indexing fails the stored row is rolled back, because the alternative is
// worse than an error: a subscription that exists, looks healthy in a listing,
// and silently never fires. A subscriber who believes they are being watched
// and is not is in a more dangerous position than one whose create failed.
func (c *ManageSubscriptions) Create(ctx context.Context, tenant, name string, rule model.AlertRule) (model.Subscription, error) {
	sub := model.Subscription{
		ID:     c.newID(),
		Tenant: tenant,
		Name:   name,
		Rule:   rule,
	}.WithDefaults(c.now())

	if err := sub.Validate(); err != nil {
		return model.Subscription{}, err
	}
	if c.matcher == nil {
		return model.Subscription{}, fmt.Errorf("subscriptions: no match index configured")
	}

	if err := c.subs.Save(ctx, sub); err != nil {
		return model.Subscription{}, err
	}

	if err := c.matcher.Register(ctx, sub); err != nil {
		if rollback := c.subs.Delete(ctx, sub.ID); rollback != nil {
			c.log.Error("subscription stored but not indexed, and rollback failed; it will never fire",
				"subscription", sub.ID, "error", rollback)
		}
		return model.Subscription{}, fmt.Errorf("subscriptions: index %s: %w", sub.Name, err)
	}

	c.log.Info("subscription created", "subscription", sub.ID, "name", sub.Name, "tenant", sub.Tenant)
	return sub, nil
}

// Delete removes a subscription and stops it matching.
//
// The index is cleared first: a rule that is gone from storage but still
// indexed would raise alerts naming a subscription nobody can look up.
func (c *ManageSubscriptions) Delete(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("subscriptions: id is required")
	}
	if c.matcher != nil {
		if err := c.matcher.Deregister(ctx, id); err != nil {
			return fmt.Errorf("subscriptions: deindex %s: %w", id, err)
		}
	}
	if err := c.subs.Delete(ctx, id); err != nil {
		return err
	}
	c.log.Info("subscription deleted", "subscription", id)
	return nil
}

// Reindex re-registers every stored subscription, repairing an index that was
// lost or rebuilt. Elasticsearch holds no truth of its own here — Postgres
// does — so the index can always be reconstructed from it.
func (c *ManageSubscriptions) Reindex(ctx context.Context) (int, error) {
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
			return indexed, fmt.Errorf("subscriptions: reindex %s: %w", sub.ID, err)
		}
		indexed++
	}
	return indexed, nil
}

// newSubscriptionID returns an opaque, unguessable id. Subscriptions are
// addressable over the API, so a predictable counter would let anyone
// enumerate other tenants' rules once the API is exposed.
func newSubscriptionID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is not recoverable and must not silently
		// degrade to a guessable id.
		panic(fmt.Sprintf("subscriptions: read random: %v", err))
	}
	return "sub_" + hex.EncodeToString(buf)
}
