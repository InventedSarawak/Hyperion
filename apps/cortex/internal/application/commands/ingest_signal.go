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
	graph ports.DependencyGraph
	log   *slog.Logger
}

// NewIngestSignal wires the use case with its storage, search and graph ports.
// The graph may be nil or unavailable; storage is the only hard requirement.
func NewIngestSignal(repo ports.VulnerabilityRepo, index ports.SearchIndex, graph ports.DependencyGraph) *IngestSignal {
	return &IngestSignal{repo: repo, index: index, graph: graph, log: slog.Default()}
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

	// Connect the finding to the libraries it affects, so a blast-radius
	// traversal can reach it. Like indexing, this is best-effort: the record
	// is already stored, and a graph outage must not fail the ingest.
	if c.graph != nil && len(incoming.AffectedPackages) > 0 {
		if err := c.graph.LinkVulnerability(ctx, incoming.CVEID, incoming.AffectedPackages); err != nil {
			if errors.Is(err, ports.ErrGraphUnavailable) {
				c.log.Debug("graph disabled; vulnerability not linked to its packages",
					"cve", incoming.CVEID)
			} else {
				c.log.Warn("graph link failed; record is stored but has no blast radius",
					"cve", incoming.CVEID, "error", err)
			}
		}
	}
	return nil
}
