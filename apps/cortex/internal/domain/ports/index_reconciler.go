package ports

import (
	"context"
	"time"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// IndexReconciler is an OUTBOUND port: find and settle the records whose
// search document is behind the stored row.
//
// Kept apart from VulnerabilityRepo because it answers a different question.
// That port is about a finding; this one is about the gap between two stores —
// Postgres, which is the truth, and the index, which is derived from it and can
// fall behind whenever an index write fails while the row is already committed.
type IndexReconciler interface {
	// PendingIndex returns up to limit records whose index document is
	// missing or older than the row, oldest first.
	PendingIndex(ctx context.Context, limit int) ([]model.Vulnerability, error)
	// MarkIndexed records that these ids are now in the index as of at.
	MarkIndexed(ctx context.Context, at time.Time, ids ...string) error
}
