package graphql

import (
	"context"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

const trackedQuery = `query Tracked {
  trackedRepositories { fullName url status addedAt lastScanAt lastError dependencyCount
    exposure { computed criticalAffected criticalPossible highAffected highPossible total } }
}`

const discoverQuery = `query Discover($owner: String!) {
  discoverRepositories(owner: $owner) { fullName description language stars pushedAt fork archived tracked }
}`

const trackMutation = `mutation Track($fullNames: [String!]!) {
  trackRepositories(fullNames: $fullNames) { fullName url status addedAt lastScanAt lastError dependencyCount
    exposure { computed criticalAffected criticalPossible highAffected highPossible total } }
}`

const untrackMutation = `mutation Untrack($fullName: String!) {
  untrackRepository(fullName: $fullName)
}`

type trackedRepository struct {
	FullName        string `json:"fullName"`
	URL             string `json:"url"`
	Status          string `json:"status"`
	AddedAt         string `json:"addedAt"`
	LastScanAt      string `json:"lastScanAt"`
	LastError       string `json:"lastError"`
	DependencyCount int    `json:"dependencyCount"`
	Exposure        *struct {
		Computed         bool `json:"computed"`
		CriticalAffected int  `json:"criticalAffected"`
		CriticalPossible int  `json:"criticalPossible"`
		HighAffected     int  `json:"highAffected"`
		HighPossible     int  `json:"highPossible"`
		Total            int  `json:"total"`
	} `json:"exposure"`
}

func (r trackedRepository) toModel() model.TrackedRepository {
	var exposure model.ExposureSummary
	if e := r.Exposure; e != nil {
		exposure = model.ExposureSummary{
			Computed: e.Computed, CriticalAffected: e.CriticalAffected, CriticalPossible: e.CriticalPossible,
			HighAffected: e.HighAffected, HighPossible: e.HighPossible, Total: e.Total,
		}
	}
	return model.TrackedRepository{
		Exposure:        exposure,
		FullName:        r.FullName,
		URL:             r.URL,
		Status:          r.Status,
		AddedAt:         parseTime(r.AddedAt),
		LastScanAt:      parseTime(r.LastScanAt),
		LastError:       r.LastError,
		DependencyCount: r.DependencyCount,
	}
}

func toTracked(in []trackedRepository) []model.TrackedRepository {
	out := make([]model.TrackedRepository, 0, len(in))
	for _, r := range in {
		out = append(out, r.toModel())
	}
	return out
}

// TrackedRepositories lists the watchlist through the gateway.
func (c *Client) TrackedRepositories(ctx context.Context) ([]model.TrackedRepository, error) {
	var out struct {
		Tracked []trackedRepository `json:"trackedRepositories"`
	}
	if err := c.do(ctx, trackedQuery, nil, &out); err != nil {
		return nil, err
	}
	return toTracked(out.Tracked), nil
}

// DiscoverRepositories lists an owner's GitHub repositories.
func (c *Client) DiscoverRepositories(ctx context.Context, owner string) ([]model.DiscoveredRepository, error) {
	var out struct {
		Discovered []struct {
			FullName    string `json:"fullName"`
			Description string `json:"description"`
			Language    string `json:"language"`
			Stars       int    `json:"stars"`
			PushedAt    string `json:"pushedAt"`
			Fork        bool   `json:"fork"`
			Archived    bool   `json:"archived"`
			Tracked     bool   `json:"tracked"`
		} `json:"discoverRepositories"`
	}
	if err := c.do(ctx, discoverQuery, map[string]any{"owner": owner}, &out); err != nil {
		return nil, err
	}

	found := make([]model.DiscoveredRepository, 0, len(out.Discovered))
	for _, r := range out.Discovered {
		found = append(found, model.DiscoveredRepository{
			FullName:    r.FullName,
			Description: r.Description,
			Language:    r.Language,
			Stars:       r.Stars,
			PushedAt:    parseTime(r.PushedAt),
			Fork:        r.Fork,
			Archived:    r.Archived,
			Tracked:     r.Tracked,
		})
	}
	return found, nil
}

// TrackRepositories adds repositories to the watchlist.
func (c *Client) TrackRepositories(ctx context.Context, fullNames []string) ([]model.TrackedRepository, error) {
	var out struct {
		Tracked []trackedRepository `json:"trackRepositories"`
	}
	if err := c.do(ctx, trackMutation, map[string]any{"fullNames": fullNames}, &out); err != nil {
		return nil, err
	}
	return toTracked(out.Tracked), nil
}

// UntrackRepository removes a repository from the watchlist.
func (c *Client) UntrackRepository(ctx context.Context, fullName string) error {
	var out struct {
		Removed bool `json:"untrackRepository"`
	}
	return c.do(ctx, untrackMutation, map[string]any{"fullName": fullName}, &out)
}
