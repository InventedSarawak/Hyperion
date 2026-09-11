package queries

import (
	"context"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// Bounds on how many of an owner's repositories one discovery lists. The
// default covers almost any user or team; large organizations own thousands,
// nobody picks from a list that long, and every hundred is another request
// against the forge's rate limit.
const (
	DefaultDiscoverLimit = 300
	MaxDiscoverLimit     = 1000
)

// ListWatchlist is the read side of the watchlist.
type ListWatchlist struct {
	watchlist ports.Watchlist
	catalog   ports.RepositoryCatalog
}

// NewListWatchlist wires the use case. The catalog may be nil, in which case
// discovery reports ports.ErrCatalogUnavailable and listing still works.
func NewListWatchlist(watchlist ports.Watchlist, catalog ports.RepositoryCatalog) *ListWatchlist {
	return &ListWatchlist{watchlist: watchlist, catalog: catalog}
}

// Repositories returns every tracked repository.
func (q *ListWatchlist) Repositories(ctx context.Context) ([]model.TrackedRepository, error) {
	return q.watchlist.List(ctx)
}

// Discover lists an owner's repositories on the forge and marks the ones
// already tracked, so a picker can show them checked instead of offering to
// add them twice.
func (q *ListWatchlist) Discover(ctx context.Context, owner string, limit int) ([]model.DiscoveredRepository, error) {
	if q.catalog == nil {
		return nil, ports.ErrCatalogUnavailable
	}
	switch {
	case limit <= 0:
		limit = DefaultDiscoverLimit
	case limit > MaxDiscoverLimit:
		limit = MaxDiscoverLimit
	}

	found, err := q.catalog.ListOwnerRepositories(ctx, owner, limit)
	if err != nil {
		return nil, err
	}
	tracked, err := q.watchlist.List(ctx)
	if err != nil {
		return nil, err
	}

	onList := make(map[string]struct{}, len(tracked))
	for _, t := range tracked {
		onList[strings.ToLower(t.FullName())] = struct{}{}
	}
	for i := range found {
		_, found[i].Tracked = onList[strings.ToLower(found[i].FullName)]
	}
	return found, nil
}
