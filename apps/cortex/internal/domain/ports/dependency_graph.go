package ports

import (
	"context"
	"errors"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// ErrGraphUnavailable is returned when no graph backend is configured. It is
// surfaced rather than swallowed: an empty blast radius from a missing graph
// means "unknown", and reporting that as "nothing is affected" would be the
// most dangerous answer this service could give.
var ErrGraphUnavailable = errors.New("dependency graph: no backend configured")

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

	// RemoveVulnerabilities deletes findings' nodes and every edge to them.
	// It is how a finding re-keyed onto a new canonical id (a GHSA that
	// gained a CVE) stops appearing twice. Removing an absent node succeeds.
	RemoveVulnerabilities(ctx context.Context, ids []string) error

	// FindBlastRadius walks outwards from the libraries a CVE affects and
	// returns the repositories exposed to it, within maxDepth DEPENDS_ON hops.
	FindBlastRadius(ctx context.Context, cveID string, maxDepth, limit int) (model.BlastRadius, error)

	// FindRepositoryExposures walks from repositories through their
	// dependencies, up to maxDepth hops, to the findings affecting what they
	// reach: blast radius read the other way round. fullNames limits the walk
	// to those repositories (compared case-insensitively); empty means all.
	// Each row's Package carries the version the nearest manifest declares;
	// judging it is the caller's job.
	FindRepositoryExposures(ctx context.Context, fullNames []string, maxDepth int) ([]model.Exposure, error)

	// HasRepository reports whether a repository is in the graph at all.
	HasRepository(ctx context.Context, fullName string) (bool, error)

	// Ready reports whether the backend is reachable and usable.
	Ready(ctx context.Context) error

	RepositoryRemover
}
