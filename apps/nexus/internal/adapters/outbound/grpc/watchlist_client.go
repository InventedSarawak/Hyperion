package grpc

import (
	"context"
	"strings"

	watchlistv1 "github.com/inventedsarawak/hyperion/packages/contracts/gen/hyperion/watchlist/v1"

	"github.com/inventedsarawak/hyperion/apps/nexus/internal/domain/model"
)

// TrackedRepositories lists the watchlist.
func (c *Client) TrackedRepositories(ctx context.Context) ([]model.TrackedRepository, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timout)
	defer cancel()

	resp, err := c.watchlist.ListRepositories(ctx, &watchlistv1.ListRepositoriesRequest{})
	if err != nil {
		return nil, describe(err)
	}
	return toTracked(resp.GetRepositories()), nil
}

// DiscoverRepositories lists an owner's GitHub repositories. It gets a longer
// deadline than the other calls: a large organization is several pages of
// GitHub API behind the one request.
func (c *Client) DiscoverRepositories(ctx context.Context, owner string, limit int) ([]model.DiscoveredRepository, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*c.timout)
	defer cancel()

	resp, err := c.watchlist.DiscoverRepositories(ctx, &watchlistv1.DiscoverRepositoriesRequest{
		Owner: owner, Limit: int32(limit),
	})
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
	ctx, cancel := context.WithTimeout(ctx, c.timout)
	defer cancel()

	resp, err := c.watchlist.TrackRepositories(ctx, &watchlistv1.TrackRepositoriesRequest{FullNames: fullNames})
	if err != nil {
		return nil, describe(err)
	}
	return toTracked(resp.GetRepositories()), nil
}

// UntrackRepository removes a repository from the watchlist and the graph.
func (c *Client) UntrackRepository(ctx context.Context, fullName string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timout)
	defer cancel()

	resp, err := c.watchlist.UntrackRepository(ctx, &watchlistv1.UntrackRepositoryRequest{FullName: fullName})
	if err != nil {
		return false, describe(err)
	}
	return resp.GetRemoved(), nil
}

func toTracked(repos []*watchlistv1.TrackedRepository) []model.TrackedRepository {
	out := make([]model.TrackedRepository, 0, len(repos))
	for _, r := range repos {
		out = append(out, model.TrackedRepository{
			FullName:        r.GetFullName(),
			URL:             r.GetUrl(),
			Status:          scanStatusLabel(r.GetStatus()),
			AddedAt:         fromTimestamp(r.GetAddedAt()),
			LastScanAt:      fromTimestamp(r.GetLastScanAt()),
			LastError:       r.GetLastError(),
			DependencyCount: int(r.GetDependencyCount()),
			Exposure:        toSummary(r.GetExposure()),
		})
	}
	return out
}

// scanStatusLabel turns SCAN_STATUS_PENDING into "pending".
func scanStatusLabel(s watchlistv1.ScanStatus) string {
	if s == watchlistv1.ScanStatus_SCAN_STATUS_UNSPECIFIED {
		return "unknown"
	}
	return strings.ToLower(strings.TrimPrefix(s.String(), "SCAN_STATUS_"))
}
