package commands

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// ErrNothingToTrack is returned when a track request names no repository.
var ErrNothingToTrack = errors.New("track: no repositories given")

// ManageWatchlist is the write side of the watchlist: adding repositories,
// removing them, and recording how their scans went.
type ManageWatchlist struct {
	watchlist ports.Watchlist
	graph     ports.RepositoryRemover
}

// NewManageWatchlist wires the use case with its outbound ports.
func NewManageWatchlist(watchlist ports.Watchlist, graph ports.RepositoryRemover) *ManageWatchlist {
	return &ManageWatchlist{watchlist: watchlist, graph: graph}
}

// Track validates every name before storing any of them, so a batch with one
// typo is rejected whole rather than half-applied — the caller would otherwise
// have to work out which ones landed. Duplicates within the batch collapse.
func (c *ManageWatchlist) Track(ctx context.Context, fullNames []string) ([]model.TrackedRepository, error) {
	var (
		repos   []model.TrackedRepository
		invalid []string
		seen    = make(map[string]struct{}, len(fullNames))
	)
	for _, raw := range fullNames {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		repo, err := model.ParseTrackedRepository(raw)
		if err != nil {
			invalid = append(invalid, fmt.Sprintf("%q", raw))
			continue
		}
		key := strings.ToLower(repo.FullName())
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		repos = append(repos, repo)
	}

	if len(invalid) > 0 {
		return nil, fmt.Errorf("%w: %s", model.ErrInvalidRepositoryName, strings.Join(invalid, ", "))
	}
	if len(repos) == 0 {
		return nil, ErrNothingToTrack
	}
	return c.watchlist.Track(ctx, repos)
}

// Untrack removes a repository from the graph first and the watchlist
// second. In that order a failure leaves it still tracked — visible, and safe
// to retry. The other way round would drop it from the list while its edges
// stayed in the graph, and blast radius would keep reporting a repository
// nobody can see or remove.
func (c *ManageWatchlist) Untrack(ctx context.Context, fullName string) (bool, error) {
	repo, err := model.ParseTrackedRepository(fullName)
	if err != nil {
		return false, err
	}

	if c.graph != nil {
		// No graph configured means there is nothing in it to remove.
		if err := c.graph.RemoveRepository(ctx, repo.FullName()); err != nil &&
			!errors.Is(err, ports.ErrGraphUnavailable) {
			return false, fmt.Errorf("untrack %s: %w", repo.FullName(), err)
		}
	}
	return c.watchlist.Remove(ctx, repo.FullName())
}

// RecordScan stores what the scanner found. A report for a repository that
// was untracked mid-scan is dropped: the user's removal wins over a scan they
// no longer want.
func (c *ManageWatchlist) RecordScan(ctx context.Context, outcome model.ScanOutcome) error {
	repo, err := model.ParseTrackedRepository(outcome.FullName)
	if err != nil {
		return err
	}
	outcome.FullName = repo.FullName()
	if err := c.watchlist.RecordScan(ctx, outcome); err != nil && !errors.Is(err, ports.ErrNotTracked) {
		return err
	}
	return nil
}
