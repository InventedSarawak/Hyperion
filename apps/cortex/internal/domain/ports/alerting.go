package ports

import (
	"context"
	"errors"
	"time"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// ErrSubscriptionNotFound is returned when no subscription matches an id.
var ErrSubscriptionNotFound = errors.New("subscription not found")

// SubscriptionRepo is an OUTBOUND port: durable storage for alert rules.
type SubscriptionRepo interface {
	Save(ctx context.Context, s model.Subscription) error
	Get(ctx context.Context, id string) (model.Subscription, error)
	List(ctx context.Context, tenant string) ([]model.Subscription, error)
	Delete(ctx context.Context, id string) error
}

// AlertMatcher is an OUTBOUND port: reverse search. Where a normal index finds
// documents matching a query, this finds the queries matching a document —
// which is what lets one pass over an incoming vulnerability identify every
// subscriber who cares, instead of replaying every rule as a search.
//
// Implemented by the Elasticsearch percolator adapter.
type AlertMatcher interface {
	// Register makes a subscription's rule matchable.
	Register(ctx context.Context, s model.Subscription) error
	// Deregister removes it.
	Deregister(ctx context.Context, id string) error
	// Match returns the ids of the subscriptions a vulnerability satisfies.
	Match(ctx context.Context, v model.Vulnerability) ([]string, error)
	// Ready reports whether the backend is reachable and usable.
	Ready(ctx context.Context) error
}

// AlertRepo is an OUTBOUND port: durable storage for raised alerts.
type AlertRepo interface {
	// Append records an alert, replacing any earlier one with the same id.
	Append(ctx context.Context, a model.Alert) error
	// List returns alerts newest first, optionally filtered to one subscription.
	List(ctx context.Context, tenant, subscriptionID string, limit int) ([]model.Alert, error)
}

// DedupeStore is an OUTBOUND port: short-lived "have I seen this?" memory.
//
// Backed by Redis, and deliberately not by the alert table: suppression is a
// time window, not a permanent fact, and expiring it belongs to a store that
// does TTLs natively.
type DedupeStore interface {
	// FirstSeen records key and reports whether it was absent — true means
	// this is the first sighting inside the window and the caller should act.
	FirstSeen(ctx context.Context, key string, window time.Duration) (bool, error)
}
