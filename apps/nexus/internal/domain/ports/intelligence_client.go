// Package ports declares the interfaces nexus's core depends on.
package ports

import (
	"context"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
)

// IntelligenceClient is an OUTBOUND port: query the intelligence service
// (cortex). Implemented by adapters/outbound/grpc. The core knows nothing of
// gRPC — swap the transport and only the adapter changes.
type IntelligenceClient interface {
	// Search returns one page of results; kinds limits them to those kinds of
	// finding, and none means every kind.
	Search(ctx context.Context, query string, sort model.SearchSort, kinds []model.FindingKind, pageSize int, pageToken string) (model.SearchResult, error)
	// BlastRadius returns the repositories a vulnerability reaches through
	// the dependency graph.
	BlastRadius(ctx context.Context, cveID string, maxDepth, limit int) (model.BlastRadius, error)
	// Vulnerability returns one finding in full.
	Vulnerability(ctx context.Context, id string) (model.Vulnerability, error)
	// RepositoryExposure returns the findings a repository reaches, judged
	// by version; includeUnaffected keeps the ones its versions rule out.
	RepositoryExposure(ctx context.Context, fullName string, includeUnaffected bool) (model.RepositoryExposure, error)
}

// FindingStreamClient is an OUTBOUND port: cortex's live feed.
//
// Separate from IntelligenceClient on purpose. Everything there answers a
// question and returns; this subscribes and stays open, and the only thing
// that needs it is the endpoint that relays it. Folding it into the larger
// interface would oblige every caller — and every test stub — to implement a
// streaming method none of them use.
type FindingStreamClient interface {
	// StreamFindings delivers findings as they are ingested, until ctx is
	// cancelled. The channel is closed when the stream ends, for any reason:
	// a feed that has died looks exactly like one with nothing to say, so the
	// close is how it tells a reader which it is.
	StreamFindings(ctx context.Context, kinds []model.FindingKind) (<-chan model.Vulnerability, error)
}

// WatchlistClient is an OUTBOUND port: the repositories cortex tracks.
type WatchlistClient interface {
	TrackedRepositories(ctx context.Context) ([]model.TrackedRepository, error)
	DiscoverRepositories(ctx context.Context, owner string, limit int) ([]model.DiscoveredRepository, error)
	TrackRepositories(ctx context.Context, fullNames []string) ([]model.TrackedRepository, error)
	UntrackRepository(ctx context.Context, fullName string) (bool, error)
}
