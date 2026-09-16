// Package ports declares the interfaces deck's core depends on, implemented by
// adapters. deck knows nothing of gRPC: swap the transport and only the
// adapter changes.
package ports

import (
	"context"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// IntelligenceAPI is an OUTBOUND port: query the intelligence service.
// Implemented by adapters/outbound/graphql and adapters/outbound/grpc.
type IntelligenceAPI interface {
	// Search returns one page of results. An empty query is allowed only with
	// SortNewest; kinds limits the results to those kinds of finding (none
	// means every kind); pageToken is "" for the first page.
	Search(ctx context.Context, query string, sort model.SearchSort, kinds []model.FindingKind, pageSize int, pageToken string) (model.SearchPage, error)
	// BlastRadius returns the repositories a vulnerability reaches.
	BlastRadius(ctx context.Context, cveID string, maxDepth int) (model.BlastRadius, error)
	// Vulnerability returns one finding in full.
	Vulnerability(ctx context.Context, id string) (model.Vulnerability, error)
	// RepositoryExposure returns the findings a repository reaches, judged by
	// version; includeUnaffected keeps the ones its versions rule out.
	RepositoryExposure(ctx context.Context, fullName string, includeUnaffected bool) (model.RepositoryExposure, error)
}

// WatchlistAPI is an OUTBOUND port: the repositories Hyperion tracks.
type WatchlistAPI interface {
	TrackedRepositories(ctx context.Context) ([]model.TrackedRepository, error)
	DiscoverRepositories(ctx context.Context, owner string) ([]model.DiscoveredRepository, error)
	TrackRepositories(ctx context.Context, fullNames []string) ([]model.TrackedRepository, error)
	UntrackRepository(ctx context.Context, fullName string) error
}

// FindingStream is an OUTBOUND port: a live feed of findings as they are
// ingested.
//
// Separate from IntelligenceAPI because it is a different kind of thing —
// everything there answers a question and returns, while this subscribes and
// stays open. It is also optional: deck works without it, on a timer, which is
// what it did before there was a stream to listen to.
type FindingStream interface {
	// StreamFindings delivers findings until ctx is cancelled. The channel is
	// closed when the feed ends, however it ended.
	StreamFindings(ctx context.Context) (<-chan model.Vulnerability, error)
}
