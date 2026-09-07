package commands

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// IngestDependency records one read of a repository's manifests in the
// dependency graph: the repository, its owner, and everything it requires.
//
//	MERGE (r:Repository)-[:DEPENDS_ON]->(l:Library)
//
// Writing the whole snapshot as one unit keeps the graph consistent with the
// manifest it came from, and makes re-reading an unchanged manifest a no-op.
type IngestDependency struct {
	graph ports.DependencyGraph
	log   *slog.Logger
}

// NewIngestDependency wires the use case with the graph port.
func NewIngestDependency(graph ports.DependencyGraph) *IngestDependency {
	return &IngestDependency{graph: graph, log: slog.Default()}
}

// Handle validates the snapshot and writes it, returning how many dependency
// edges were written. A snapshot with no usable dependencies is not an error:
// a repository with no third-party requirements is a real, useful fact, and
// recording the repository itself lets a later manifest attach to it.
func (c *IngestDependency) Handle(ctx context.Context, snapshot model.RepositorySnapshot) (int, error) {
	if err := snapshot.Validate(); err != nil {
		return 0, err
	}
	if c.graph == nil {
		return 0, ports.ErrGraphUnavailable
	}

	written, err := c.graph.UpsertRepositorySnapshot(ctx, snapshot)
	if err != nil {
		return 0, fmt.Errorf("ingest dependencies for %s: %w", snapshot.Repository.FullName(), err)
	}

	c.log.Info("dependency snapshot ingested",
		"repository", snapshot.Repository.FullName(),
		"declared", len(snapshot.Dependencies),
		"written", written)
	return written, nil
}
