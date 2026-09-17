// Package scheduler is an INBOUND adapter: it drives the application on a timer.
// It knows nothing of NVD, Kafka, or how far anything has read — only how often
// to invoke a Poller.
package scheduler

import (
	"context"
	"log/slog"
	"time"
)

// Poller is the use case this adapter drives. Defined here (consumer side) so
// the scheduler depends on a narrow interface, not the concrete workflow.
//
// It takes no window. How far back to read is a question only the poller can
// answer — the advisory poll keeps a watermark per source, each with its own
// cadence, while a manifest read has no meaningful position at all. A scheduler
// that handed down one "since" for all of them could only ever be wrong for
// most of them.
type Poller interface {
	Run(ctx context.Context) (int, error)
}

// Scheduler invokes a Poller immediately, then every interval.
type Scheduler struct {
	poller   Poller
	interval time.Duration
	log      *slog.Logger
}

// New builds a scheduler that runs poller every interval.
func New(poller Poller, interval time.Duration) *Scheduler {
	if interval <= 0 {
		interval = time.Minute
	}
	return &Scheduler{poller: poller, interval: interval, log: slog.Default()}
}

// Start blocks, polling until ctx is cancelled (then it returns ctx.Err()).
func (s *Scheduler) Start(ctx context.Context) error {
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

// pollOnce runs the use case once. A failure is logged, not fatal: the next
// tick tries again, and whatever the poller uses to track its position is
// untouched by a run that did not succeed.
func (s *Scheduler) pollOnce(ctx context.Context) {
	n, err := s.poller.Run(ctx)
	if err != nil {
		s.log.Error("poll failed", "error", err)
		return
	}
	// A pass that found nothing is the normal case for the watchlist scanner,
	// which checks every few seconds; at Info it would drown the log.
	if n == 0 {
		s.log.Debug("poll complete", "published", n)
		return
	}
	s.log.Info("poll complete", "published", n)
}
