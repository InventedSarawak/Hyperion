package commands

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// ReconcileIndex settles the records whose search document is behind the row.
//
// Postgres is the truth and the index is derived from it, so they can disagree:
// an index write fails while the row is already committed, or a process stops
// between the two. Ingest tolerates that deliberately — losing the finding
// would be worse than it being briefly unsearchable — and this is the other
// half of that bargain, the part that makes "briefly" true.
//
// It is bounded work: only rows known to be behind are read, which is normally
// none of them. That is the difference from a full reindex, which rewrites
// every document to repair one.
type ReconcileIndex struct {
	pending ports.IndexReconciler
	index   ports.SearchIndex
	batch   int
	log     *slog.Logger
}

// NewReconcileIndex wires the use case.
func NewReconcileIndex(pending ports.IndexReconciler, index ports.SearchIndex) *ReconcileIndex {
	return &ReconcileIndex{pending: pending, index: index, batch: 500, log: slog.Default()}
}

// Run settles what it can and reports how many documents it wrote.
//
// One pass, not a loop until empty: ingest keeps running, so "empty" is not a
// state this can wait for. Whatever is still behind is picked up next time.
func (c *ReconcileIndex) Run(ctx context.Context) (int, error) {
	if c.index == nil || c.pending == nil {
		return 0, nil
	}

	behind, err := c.pending.PendingIndex(ctx, c.batch)
	if err != nil {
		return 0, fmt.Errorf("reconcile index: read pending: %w", err)
	}
	if len(behind) == 0 {
		return 0, nil
	}

	settled := make([]string, 0, len(behind))
	for _, v := range behind {
		if err := c.index.Index(ctx, v); err != nil {
			// Stop at the first failure: the index is evidently still unwell,
			// and the rest stay marked for the next pass.
			c.log.Warn("could not reconcile a record into the index",
				"cve", v.CVEID, "settled", len(settled), "error", err)
			break
		}
		settled = append(settled, v.CVEID)
	}

	if len(settled) == 0 {
		return 0, nil
	}
	if err := c.pending.MarkIndexed(ctx, time.Now(), settled...); err != nil {
		// The documents are written; failing to record that only costs a
		// repeat next pass.
		return len(settled), fmt.Errorf("reconcile index: mark: %w", err)
	}

	c.log.Info("search index reconciled", "records", len(settled), "still_behind", len(behind)-len(settled))
	return len(settled), nil
}
