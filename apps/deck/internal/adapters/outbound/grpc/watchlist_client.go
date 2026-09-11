package grpc

import (
	"context"
	"strings"

	watchlistv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/watchlist/v1"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// TrackedRepositories lists the watchlist.
func (c *Client) TrackedRepositories(ctx context.Context) ([]model.TrackedRepository, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.watchlist.ListRepositories(ctx, &watchlistv1.ListRepositoriesRequest{})
	if err != nil {
		return nil, describe(err)
	}
	return toTracked(resp.GetRepositories()), nil
}

// DiscoverRepositories lists an owner's GitHub repositories.
func (c *Client) DiscoverRepositories(ctx context.Context, owner string) ([]model.DiscoveredRepository, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*c.timeout)
	defer cancel()

	resp, err := c.watchlist.DiscoverRepositories(ctx, &watchlistv1.DiscoverRepositoriesRequest{Owner: owner})
	if err != nil {
		return nil, describe(err)
	}
	out := make([]model.DiscoveredRepository, 0, len(resp.GetRepositories()))
	for _, r := range resp.GetRepositories() {
		out = append(out, model.DiscoveredRepository{
			FullName:    r.GetFullName(),
			Description: r.GetDescription(),
			Language:    r.GetLanguage(),
			Stars:       int(r.GetStars()),
			PushedAt:    fromTimestamp(r.GetPushedAt()),
			Fork:        r.GetFork(),
			Archived:    r.GetArchived(),
			Tracked:     r.GetTracked(),
		})
	}
	return out, nil
}

// TrackRepositories adds repositories to the watchlist.
func (c *Client) TrackRepositories(ctx context.Context, fullNames []string) ([]model.TrackedRepository, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.watchlist.TrackRepositories(ctx, &watchlistv1.TrackRepositoriesRequest{FullNames: fullNames})
	if err != nil {
		return nil, describe(err)
	}
	return toTracked(resp.GetRepositories()), nil
}

// UntrackRepository removes a repository from the watchlist.
func (c *Client) UntrackRepository(ctx context.Context, fullName string) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	if _, err := c.watchlist.UntrackRepository(ctx, &watchlistv1.UntrackRepositoryRequest{FullName: fullName}); err != nil {
		return describe(err)
	}
	return nil
}

func toTracked(repos []*watchlistv1.TrackedRepository) []model.TrackedRepository {
	out := make([]model.TrackedRepository, 0, len(repos))
	for _, r := range repos {
		out = append(out, model.TrackedRepository{
			FullName:        r.GetFullName(),
			URL:             r.GetUrl(),
			Status:          strings.ToLower(strings.TrimPrefix(r.GetStatus().String(), "SCAN_STATUS_")),
			AddedAt:         fromTimestamp(r.GetAddedAt()),
			LastScanAt:      fromTimestamp(r.GetLastScanAt()),
			LastError:       r.GetLastError(),
			DependencyCount: int(r.GetDependencyCount()),
		})
	}
	return out
}
