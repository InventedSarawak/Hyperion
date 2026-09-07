// Package commands holds cortex's write-side use cases.
package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// IngestSignal stores an incoming vulnerability, reconciling it with any
// existing record via the domain's Merge rule, then makes it searchable.
type IngestSignal struct {
	repo  ports.VulnerabilityRepo
	index ports.SearchIndex
	log   *slog.Logger
}

// NewIngestSignal wires the use case with its storage and search ports.
func NewIngestSignal(repo ports.VulnerabilityRepo, index ports.SearchIndex) *IngestSignal {
	return &IngestSignal{repo: repo, index: index, log: slog.Default()}
}

// Handle validates, merges with any existing record, persists, and indexes.
// Postgres is the source of truth: a failure there fails the ingest, while a
// search-index failure is logged and tolerated (the record can be reindexed).
func (c *IngestSignal) Handle(ctx context.Context, incoming model.Vulnerability) error {
	if err := incoming.Validate(); err != nil {
		return err
	}

	existing, err := c.repo.GetByCVE(ctx, incoming.CVEID)
	switch {
	case err == nil:
		incoming = existing.Merge(incoming)
	case errors.Is(err, ports.ErrNotFound):
		// first time we've seen this CVE
	default:
		return fmt.Errorf("ingest: load existing %s: %w", incoming.CVEID, err)
	}

	if err := c.repo.Upsert(ctx, incoming); err != nil {
		return fmt.Errorf("ingest: upsert %s: %w", incoming.CVEID, err)
	}

	if c.index != nil {
		if err := c.index.Index(ctx, incoming); err != nil {
			c.log.Warn("indexing failed; record is stored but not searchable",
				"cve", incoming.CVEID, "error", err)
		}
	}
	return nil
}
