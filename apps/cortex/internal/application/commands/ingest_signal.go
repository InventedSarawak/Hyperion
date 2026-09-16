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

// maxStoreAttempts bounds the read-merge-write retry on ErrConflict. One
// retry resolves the race it exists for; more means something is wrong.
const maxStoreAttempts = 3

// Handle validates, merges with every existing record of the same finding,
// persists, and indexes. Postgres is the source of truth: a failure there
// fails the ingest, while a search-index failure is logged and tolerated (the
// record can be reindexed).
func (c *IngestSignal) Handle(ctx context.Context, incoming model.Vulnerability) error {
	incoming = incoming.Normalized()
	if err := incoming.Validate(); err != nil {
		return err
	}

	// Another worker can file a report of the same finding under a different
	// id between this one's read and its write (the consumer shards on the
	// canonical id, which two reports can disagree on until one links them).
	// The repo refuses to let one id name two findings; reading again sees
	// the other record and merges it.
	var (
		stored  model.Vulnerability
		retired []string
		err     error
	)
	for attempt := 1; ; attempt++ {
		stored, retired, err = c.store(ctx, incoming)
		if !errors.Is(err, ports.ErrConflict) || attempt == maxStoreAttempts {
			break
		}
	}
	if err != nil {
		return err
	}
	incoming = stored

	// A re-keyed finding's old search document would otherwise show it twice.
	if c.index != nil {
		for _, id := range retired {
			if err := c.index.Delete(ctx, id); err != nil {
				c.log.Warn("could not remove a re-keyed finding's old search document",
					"cve", incoming.CVEID, "old", id, "error", err)
			}
		}
	}

	if c.index != nil {
		if err := c.index.Index(ctx, incoming); err != nil {
			c.log.Warn("indexing failed; record is stored but not searchable",
				"cve", incoming.CVEID, "error", err)
		}
	}

	// Drop a re-keyed finding's old node before linking the new one; the
	// merged record carries every package the old node was linked to.
	if c.graph != nil && len(retired) > 0 {
		if err := c.graph.RemoveVulnerabilities(ctx, retired); err != nil && !errors.Is(err, ports.ErrGraphUnavailable) {
			c.log.Warn("could not remove a re-keyed finding's old graph node",
				"cve", incoming.CVEID, "old", retired, "error", err)
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

// store merges incoming with every record already filed under any of its
// ids and writes the result under its canonical id, retiring the keys it
// replaced. Several records merge when a report is the first to link them:
// GitHub filed an advisory under its GHSA before a CVE existed, and now OSV
// reports the two together.
func (c *IngestSignal) store(ctx context.Context, incoming model.Vulnerability) (model.Vulnerability, []string, error) {
	existing, err := c.repo.FindByIDs(ctx, incoming.IDs())
	if err != nil {
		return model.Vulnerability{}, nil, fmt.Errorf("ingest: load existing %s: %w", incoming.CVEID, err)
	}

	merged := incoming
	if len(existing) > 0 {
		merged = existing[0]
		for _, other := range existing[1:] {
			merged = merged.Merge(other)
		}
		merged = merged.Merge(incoming)
	}

	var retired []string
	for _, e := range existing {
		if e.CVEID != merged.CVEID {
			retired = append(retired, e.CVEID)
		}
	}
	if err := c.repo.Upsert(ctx, merged, retired...); err != nil {
		return model.Vulnerability{}, nil, fmt.Errorf("ingest: upsert %s: %w", merged.CVEID, err)
	}
	return merged, retired, nil
}
