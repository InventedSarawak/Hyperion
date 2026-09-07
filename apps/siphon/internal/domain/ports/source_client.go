// Package ports declares the interfaces siphon's core depends on. They are
// defined in the domain and implemented by adapters (dependency inversion):
// the core states what it needs; the edges supply how.
package ports

import (
	"context"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// SourceClient is an OUTBOUND port: fetch normalized signals from one upstream
// vulnerability feed. Implemented by adapters/outbound/sources/* (e.g. nvd),
// each of which parses its feed's native format into domain SourceSignals.
type SourceClient interface {
	// Kind reports which feed this client speaks for.
	Kind() valueobject.SourceKind
	// Fetch returns signals modified at or after `since`, for incremental polling.
	Fetch(ctx context.Context, since time.Time) ([]model.SourceSignal, error)
}
