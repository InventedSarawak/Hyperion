// Package scheduler is an INBOUND adapter: it drives the application on a timer.
// It knows nothing of NVD or Kafka — only how to invoke a Poller periodically.
package scheduler

import (
	"context"
	"log/slog"
	"time"
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

// Start blocks, polling until ctx is cancelled (then it returns ctx.Err()).
func (s *Scheduler) Start(ctx context.Context) error {
	if s.since.IsZero() {
		s.since = s.now().Add(-s.lookback)
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
	s.log.Info("poll complete", "published", n)
}
