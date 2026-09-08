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
	repo    ports.VulnerabilityRepo
	index   ports.SearchIndex
	graph   ports.DependencyGraph
	alerter Alerter
	log     *slog.Logger
}

// Alerter raises alerts for the subscriptions a vulnerability matches
// (consumer-side interface; implemented by MatchSignal).
type Alerter interface {
	Handle(ctx context.Context, v model.Vulnerability) ([]model.Alert, error)
}

// NewIngestSignal wires the use case with its storage, search, graph and
// alerting ports. Only storage is a hard requirement; the rest enrich.
func NewIngestSignal(
	repo ports.VulnerabilityRepo,
	index ports.SearchIndex,
	graph ports.DependencyGraph,
	alerter Alerter,
) *IngestSignal {
	return &IngestSignal{repo: repo, index: index, graph: graph, alerter: alerter, log: slog.Default()}
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

	// Reverse search: tell whoever asked to hear about this. Best-effort like
	// the rest — the record is already stored, and a matcher outage must not
	// cost us the finding itself. A failure here is logged loudly because a
	// silent alerting outage is indistinguishable from "nothing happened".
	if c.alerter != nil {
		if _, err := c.alerter.Handle(ctx, incoming); err != nil {
			c.log.Error("alert matching failed; record is stored but nobody was told",
				"cve", incoming.CVEID, "error", err)
		}
	}
	return nil
}
