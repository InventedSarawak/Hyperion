package workflows

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/ports"
)

// ScanWatchlist reads the repositories on the intelligence service's
// watchlist that are due for a scan, and reports each outcome back.
//
// It runs on a short timer (seconds, not hours) so a repository added in the
// UI is scanned almost at once; each pass is cheap when nothing is due, since
// the only cost is one call to list the watchlist. What is due is decided by
// TrackedRepository.DueForScan.
type ScanWatchlist struct {
	watchlist ports.Watchlist
	client    ports.RepositoryClient
	publisher ports.DependencyPublisher
	rescan    time.Duration
	retry     time.Duration
	now       func() time.Time
	log       *slog.Logger
}

// NewScanWatchlist wires the use case with its outbound ports.
func NewScanWatchlist(
	watchlist ports.Watchlist,
	client ports.RepositoryClient,
	publisher ports.DependencyPublisher,
	rescan, retry time.Duration,
) *ScanWatchlist {
	return &ScanWatchlist{
		watchlist: watchlist,
		client:    client,
		publisher: publisher,
		rescan:    rescan,
		retry:     retry,
		now:       time.Now,
		log:       slog.Default(),
	}
}

// Run scans every due repository and returns the dependency edges written.
// The `since` watermark is ignored, as for any manifest scan.
//
// A failed scan is reported to the watchlist rather than returned: it is an
// expected, per-repository state the user sees in the list ("failed: rate
// limited"), not a failure of the pass. Only failing to reach the watchlist
// itself fails the run.
func (s *ScanWatchlist) Run(ctx context.Context, _ time.Time) (int, error) {
	tracked, err := s.watchlist.Tracked(ctx)
	if err != nil {
		return 0, fmt.Errorf("scan watchlist: list: %w", err)
	}

	var (
		total int
		errs  []error
		now   = s.now()
	)
	for _, repo := range tracked {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		if !repo.DueForScan(now, s.rescan, s.retry) {
			continue
		}

		written, scanErr := scanAndPublish(ctx, s.client, s.publisher, repo.Owner, repo.Name)
		outcome := model.ScanOutcome{
			FullName:        repo.FullName(),
			Succeeded:       scanErr == nil,
			DependencyCount: written,
			ScannedAt:       s.now(),
		}
		if scanErr != nil {
			outcome.Error = scanErr.Error()
			s.log.Warn("watched repository scan failed", "repository", repo.FullName(), "error", scanErr)
		} else {
			total += written
			s.log.Info("watched repository scanned", "repository", repo.FullName(), "written", written)
		}

		if err := s.watchlist.ReportScan(ctx, outcome); err != nil {
			errs = append(errs, fmt.Errorf("scan watchlist: report %s: %w", repo.FullName(), err))
		}
	}
	return total, errors.Join(errs...)
}
