package ports

import (
	"context"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// DependencyGraph is an OUTBOUND port: the software supply chain as a graph.
// Implemented by adapters/outbound/neo4j; a no-op implementation is used when
// no graph backend is configured, so vulnerability ingest runs without it.
//
// The shape of the graph:
//
//	(:Author)-[:MAINTAINS]->(:Repository)-[:DEPENDS_ON]->(:Library)
//	(:Library)-[:AFFECTED_BY]->(:Vulnerability)
//
// Relational storage answers "what is CVE-X?"; this answers "who does CVE-X
// reach?" — a traversal Postgres would express as a recursive CTE and Neo4j
// expresses natively (AGENTS.md Rule 4, polyglot discipline).
type DependencyGraph interface {
	// UpsertRepositorySnapshot writes a manifest read as graph edges,
	// returning how many dependency edges were written. It is idempotent:
	// re-reading an unchanged manifest changes nothing.
	UpsertRepositorySnapshot(ctx context.Context, snapshot model.RepositorySnapshot) (int, error)

	// LinkVulnerability records that a CVE affects the given libraries,
	// creating library nodes that no repository has referenced yet.
	LinkVulnerability(ctx context.Context, cveID string, packages []valueobject.PackageRef) error

	// FindBlastRadius walks outwards from the libraries a CVE affects and
	// returns the repositories exposed to it, within maxDepth DEPENDS_ON hops.
	FindBlastRadius(ctx context.Context, cveID string, maxDepth, limit int) (model.BlastRadius, error)

	// Ready reports whether the backend is reachable and usable.
	Ready(ctx context.Context) error
}
