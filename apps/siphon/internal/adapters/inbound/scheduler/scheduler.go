// Package scheduler is an INBOUND adapter: it drives the application on a timer.
// It knows nothing of NVD or Kafka — only how to invoke a Poller periodically.
package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/ports"
)

// Poller is the use case this adapter drives. Defined here (consumer side) so
// the scheduler depends on a narrow interface, not the concrete workflow.
type Poller interface {
	Run(ctx context.Context, since time.Time) (int, error)
}

// Scheduler invokes a Poller immediately, then every interval, tracking the
// last successful run time as the incremental `since` watermark.
type Scheduler struct {
	poller   Poller
	interval time.Duration
	lookback time.Duration
	since    time.Time
	now      func() time.Time
	log      *slog.Logger

	// checkpoint, when set, makes the watermark outlive the process.
	checkpoint     ports.CheckpointStore
	checkpointName string
}

// New builds a scheduler. lookback sets how far back the first poll reaches.
func New(poller Poller, interval, lookback time.Duration) *Scheduler {
	return &Scheduler{
		poller:   poller,
		interval: interval,
		lookback: lookback,
		now:      time.Now,
		log:      slog.Default(),
	}
}

// WithCheckpoint persists the watermark under name, so a restart continues
// from where the last successful poll finished instead of from now - lookback.
//
// It is optional because not every scheduled job has a meaningful watermark:
// the watchlist scanner reads whatever a manifest currently says, so "how far
// have I read" means nothing to it.
func (s *Scheduler) WithCheckpoint(store ports.CheckpointStore, name string) *Scheduler {
	if store != nil && name != "" {
		s.checkpoint = store
		s.checkpointName = name
	}
	return s
}

// Start blocks, polling until ctx is cancelled (then it returns ctx.Err()).
func (s *Scheduler) Start(ctx context.Context) error {
	if s.since.IsZero() {
		s.since = s.resume(ctx)
	}
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	s.pollOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.pollOnce(ctx)
		}
	}
}

// resume decides where this run starts reading.
//
// A stored watermark wins over the lookback, however far back it reaches: the
// gap left by an outage is exactly what must be re-read, and the sources clamp
// an over-long window themselves. A store that cannot be read falls back to the
// lookback rather than refusing to start — degraded ingestion beats none.
func (s *Scheduler) resume(ctx context.Context) time.Time {
	fallback := s.now().Add(-s.lookback)
	if s.checkpoint == nil {
		return fallback
	}

	at, found, err := s.checkpoint.Load(ctx, s.checkpointName)
	switch {
	case err != nil:
		s.log.Warn("could not read the stored watermark; falling back to the lookback window",
			"name", s.checkpointName, "lookback", s.lookback.String(), "error", err)
		return fallback
	case !found:
		s.log.Info("no stored watermark yet; starting from the lookback window",
			"name", s.checkpointName, "lookback", s.lookback.String())
		return fallback
	}

	s.log.Info("resuming from the stored watermark",
		"name", s.checkpointName, "since", at.UTC().Format(time.RFC3339),
		"behind", s.now().Sub(at).Round(time.Second).String())
	return at
}

// persist records the new watermark. A failure here is worth a line but not
// worth failing the poll: the events were published either way, and the only
// cost of losing the write is that a restart re-reads this window.
func (s *Scheduler) persist(ctx context.Context, at time.Time) {
	if s.checkpoint == nil {
		return
	}
	// Deliberately not the poll's context: a poll that succeeded on the way to
	// shutdown should still record where it reached.
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	if err := s.checkpoint.Save(saveCtx, s.checkpointName, at); err != nil {
		s.log.Warn("could not persist the ingestion watermark; a restart will re-read this window",
			"name", s.checkpointName, "error", err)
	}
}

// pollOnce runs the use case once. A fetch/publish error is logged, not fatal,
// and the watermark is only advanced on success so nothing is skipped.
func (s *Scheduler) pollOnce(ctx context.Context) {
	start := s.now()
	n, err := s.poller.Run(ctx, s.since)
	if err != nil {
		s.log.Error("poll failed", "error", err)
		return
	}
	s.since = start
	s.persist(ctx, start)
	// A pass that found nothing is the normal case for the watchlist
	// scanner, which checks every few seconds; at Info it would drown the log.
	if n == 0 {
		s.log.Debug("poll complete", "published", n)
		return
	}
	s.log.Info("poll complete", "published", n)
}
