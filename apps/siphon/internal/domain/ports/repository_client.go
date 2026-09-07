package ports

import (
	"context"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
)

// RepositoryClient is an OUTBOUND port: read one repository's dependency
// manifests from a source forge. Implemented by adapters/outbound/repos/github.
type RepositoryClient interface {
	// Scan reads every manifest it recognizes in the named repository and
	// returns one snapshot of what the repository requires.
	Scan(ctx context.Context, owner, name string) (model.RepositorySnapshot, error)
}

// DependencyPublisher is an OUTBOUND port: hand a manifest read to the
// intelligence service, which owns the dependency graph. siphon does not
// store; it observes and reports.
type DependencyPublisher interface {
	// Publish sends the snapshot and reports how many dependency edges the
	// receiving service wrote.
	Publish(ctx context.Context, snapshot model.RepositorySnapshot) (int, error)
}

// RepositoryDiscoverer is an OUTBOUND port: enumerate the repositories an
// owner has. It exists so the supply-chain graph is not limited to whatever
// someone remembered to write in a watchlist — an unlisted repository is
// invisible to blast radius, which makes exposure look smaller than it is.
type RepositoryDiscoverer interface {
	// Discover lists "owner/name" entries for an organization or user, newest
	// activity first, capped at limit. Forks and archived repositories are
	// excluded: neither tells us anything about what the owner actually ships.
	Discover(ctx context.Context, owner string, limit int) ([]string, error)
}
