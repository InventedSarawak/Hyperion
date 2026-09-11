package ports

import (
	"context"
	"errors"
	"fmt"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// ErrNotTracked is returned when a repository is not on the watchlist.
var ErrNotTracked = errors.New("repository is not tracked")

// ErrCatalogUnavailable is returned when no forge is reachable to list an
// owner's repositories.
var ErrCatalogUnavailable = errors.New("repository catalog: not configured")

// ErrOwnerNotFound is returned when the forge has no such user or org.
var ErrOwnerNotFound = errors.New("no such GitHub user or organization")

// OwnerNotFound reports a missing owner by name, in words fit to show the
// person who typed it, while still matching ErrOwnerNotFound.
func OwnerNotFound(owner string) error { return ownerNotFound(owner) }

type ownerNotFound string

func (o ownerNotFound) Error() string {
	return fmt.Sprintf("GitHub has no user or organization named %q", string(o))
}

func (o ownerNotFound) Is(target error) bool { return target == ErrOwnerNotFound }

// Watchlist is an OUTBOUND port: durable storage for the repositories
// Hyperion tracks. Implemented by adapters/outbound/postgres.
type Watchlist interface {
	// List returns every tracked repository, ordered by name.
	List(ctx context.Context) ([]model.TrackedRepository, error)
	// Track adds repositories as pending. One already tracked is re-queued
	// (set back to pending) and keeps its original AddedAt.
	Track(ctx context.Context, repos []model.TrackedRepository) ([]model.TrackedRepository, error)
	// Remove deletes one entry, reporting whether it existed.
	Remove(ctx context.Context, fullName string) (bool, error)
	// RecordScan stores a scan outcome, or ErrNotTracked when the repository
	// was untracked while the scan ran.
	RecordScan(ctx context.Context, outcome model.ScanOutcome) error
}

// RepositoryCatalog is an OUTBOUND port: the forge's list of an owner's
// repositories. Implemented by adapters/outbound/github.
type RepositoryCatalog interface {
	// ListOwnerRepositories lists a user's or organization's repositories,
	// most recently pushed first, up to limit. Tracked is left false.
	ListOwnerRepositories(ctx context.Context, owner string, limit int) ([]model.DiscoveredRepository, error)
}

// RepositoryRemover is the slice of the graph that untracking needs.
type RepositoryRemover interface {
	// RemoveRepository deletes a repository and the edges its manifest
	// contributed. Libraries stay: other repositories and advisories use them.
	RemoveRepository(ctx context.Context, fullName string) error
}
