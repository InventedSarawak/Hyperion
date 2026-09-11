package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// reindexBatch is how many records are read per round trip.
const reindexBatch = 500

// ReindexSearch rebuilds the search index from Postgres.
//
// Elasticsearch holds nothing Postgres does not, so it can always be rebuilt.
// That is how a mapping change reaches records written before it, and how an
// index that drifted — a failed write during ingest, an abrupt stop between the
// two — is brought back into line.
type ReindexSearch struct {
	repo  ports.VulnerabilityRepo
	index ports.SearchIndex
	log   *slog.Logger
}

// NewReindexSearch wires the use case.
func NewReindexSearch(repo ports.VulnerabilityRepo, index ports.SearchIndex) *ReindexSearch {
	return &ReindexSearch{repo: repo, index: index, log: slog.Default()}
}

// Report is what a reindex did.
type Report struct {
	Written int // documents rewritten from Postgres
	Removed int // documents deleted because Postgres has no such record
}

// Run rewrites every stored record into the index, then removes documents the
// store does not have, so the index ends up mirroring Postgres exactly.
func (c *ReindexSearch) Run(ctx context.Context) (Report, error) {
	if c.index == nil {
		return Report{}, fmt.Errorf("reindex: no search index configured")
	}

	report := Report{}
	written := make(map[string]struct{})
	after := ""
	for {
		batch, err := c.repo.Scan(ctx, after, reindexBatch)
		if err != nil {
			return report, fmt.Errorf("reindex: read after %q: %w", after, err)
		}
		if len(batch) == 0 {
			break
		}
		for _, v := range batch {
			if err := c.index.Index(ctx, v); err != nil {
				return report, fmt.Errorf("reindex %s: %w", v.CVEID, err)
			}
			written[v.CVEID] = struct{}{}
			report.Written++
		}
		after = batch[len(batch)-1].CVEID
		c.log.Info("reindex progress", "written", report.Written, "through", after)
	}

	removed, err := c.removeOrphans(ctx, written)
	report.Removed = removed
	return report, err
}

// removeOrphans deletes documents that have no record in Postgres.
//
// Every candidate is checked against the store before it is deleted, rather
// than trusting the set built during the walk. The ingest loop keeps running
// during a reindex: a record ingested after the walk passed its position is in
// Postgres and in the index, but not in the set — and ingest writes Postgres
// before the index, so asking Postgres directly is what keeps that record
// alive.
func (c *ReindexSearch) removeOrphans(ctx context.Context, written map[string]struct{}) (int, error) {
	indexed, err := c.index.IDs(ctx)
	if err != nil {
		return 0, fmt.Errorf("reindex: list indexed documents: %w", err)
	}

	removed := 0
	for _, id := range indexed {
		if _, ok := written[id]; ok {
			continue
		}
		_, err := c.repo.GetByID(ctx, id)
		switch {
		case err == nil:
			continue // arrived during the reindex; it belongs
		case !errors.Is(err, ports.ErrNotFound):
			return removed, fmt.Errorf("reindex: check %s: %w", id, err)
		}
		if err := c.index.Delete(ctx, id); err != nil {
			return removed, fmt.Errorf("reindex: remove orphan %s: %w", id, err)
		}
		removed++
	}
	if removed > 0 {
		c.log.Info("removed documents with no record in Postgres", "removed", removed)
	}
	return removed, nil
}
