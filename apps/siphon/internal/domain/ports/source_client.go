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

// Backfiller is an OUTBOUND port: walk a feed's history rather than its
// recent changes. It is separate from SourceClient because the two questions
// have different shapes — "what changed in the last two hours" is one small
// request, while "everything disclosed in ten years" is hundreds of thousands
// of records that must stream through rather than be returned in one slice.
// Implemented by the NVD adapter (published-date windows) and osvbulk (OSV's
// per-ecosystem exports).
type Backfiller interface {
	// Kind reports which feed this backfiller speaks for.
	Kind() valueobject.SourceKind
	// Backfill hands every signal published at or after `from` to emit, a
	// batch at a time. An emit error stops the walk and is returned.
	Backfill(ctx context.Context, from time.Time, emit func([]model.SourceSignal) error) error
}
