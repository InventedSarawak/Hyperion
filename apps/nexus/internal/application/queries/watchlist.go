package queries

import (
	"context"
	"fmt"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/ports"
)

// Watchlist backs the watchlist queries and mutations. The gateway validates
// only what it can check without cortex — a present argument, a sane batch
// size — and leaves the rules about repository names to cortex, which owns
// the watchlist.
type Watchlist struct {
	client ports.WatchlistClient
}

// MaxTrackBatch bounds one track request. A picker sends at most one owner's
// listing; anything larger is a script that should batch.
const MaxTrackBatch = 300

// NewWatchlist wires the use case with its outbound port.
func NewWatchlist(client ports.WatchlistClient) *Watchlist { return &Watchlist{client: client} }

// Tracked returns every tracked repository.
func (w *Watchlist) Tracked(ctx context.Context) ([]model.TrackedRepository, error) {
	return w.client.TrackedRepositories(ctx)
}

// Discover lists an owner's repositories.
func (w *Watchlist) Discover(ctx context.Context, owner string, limit int) ([]model.DiscoveredRepository, error) {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil, fmt.Errorf("enter a GitHub user or organization")
	}
	return w.client.DiscoverRepositories(ctx, owner, limit)
}

// Track adds repositories to the watchlist.
func (w *Watchlist) Track(ctx context.Context, fullNames []string) ([]model.TrackedRepository, error) {
	if len(fullNames) == 0 {
		return nil, fmt.Errorf("name at least one repository to track, as owner/name")
	}
	if len(fullNames) > MaxTrackBatch {
		return nil, fmt.Errorf("track at most %d repositories at a time", MaxTrackBatch)
	}
	return w.client.TrackRepositories(ctx, fullNames)
}

// Untrack removes a repository from the watchlist.
func (w *Watchlist) Untrack(ctx context.Context, fullName string) (bool, error) {
	fullName = strings.TrimSpace(fullName)
	if fullName == "" {
		return false, fmt.Errorf("name the repository to stop tracking, as owner/name")
	}
	return w.client.UntrackRepository(ctx, fullName)
}
