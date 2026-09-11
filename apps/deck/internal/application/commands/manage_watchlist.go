package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/ports"
)

// ManageWatchlist drives the Repositories tab: what is tracked, what an owner
// has, and adding or removing repositories. The rules about what a valid
// repository name is live in cortex, which owns the list; deck only refuses
// requests that are empty.
type ManageWatchlist struct {
	api ports.WatchlistAPI
}

// NewManageWatchlist wires the use case with its outbound port.
func NewManageWatchlist(api ports.WatchlistAPI) *ManageWatchlist { return &ManageWatchlist{api: api} }

// Tracked lists the watchlist.
func (c *ManageWatchlist) Tracked(ctx context.Context) ([]model.TrackedRepository, error) {
	if c.api == nil {
		return nil, fmt.Errorf("repositories: not connected to the intelligence service")
	}
	return c.api.TrackedRepositories(ctx)
}

// Discover lists a GitHub user's or organization's repositories. A leading
// "@" or a pasted profile URL is accepted, since that is what people copy.
func (c *ManageWatchlist) Discover(ctx context.Context, owner string) ([]model.DiscoveredRepository, error) {
	owner = strings.TrimSpace(owner)
	owner = strings.TrimPrefix(owner, "https://")
	owner = strings.TrimPrefix(owner, "github.com/")
	owner = strings.Trim(strings.TrimPrefix(owner, "@"), "/")
	if owner == "" {
		return nil, fmt.Errorf("add: enter a GitHub user or organization")
	}
	if c.api == nil {
		return nil, fmt.Errorf("repositories: not connected to the intelligence service")
	}
	return c.api.DiscoverRepositories(ctx, owner)
}

// Track adds the chosen repositories.
func (c *ManageWatchlist) Track(ctx context.Context, fullNames []string) ([]model.TrackedRepository, error) {
	if len(fullNames) == 0 {
		return nil, fmt.Errorf("add: select at least one repository (space)")
	}
	if c.api == nil {
		return nil, fmt.Errorf("repositories: not connected to the intelligence service")
	}
	return c.api.TrackRepositories(ctx, fullNames)
}

// Untrack removes a repository.
func (c *ManageWatchlist) Untrack(ctx context.Context, fullName string) error {
	if strings.TrimSpace(fullName) == "" {
		return fmt.Errorf("remove: select a repository first")
	}
	if c.api == nil {
		return fmt.Errorf("repositories: not connected to the intelligence service")
	}
	return c.api.UntrackRepository(ctx, fullName)
}
