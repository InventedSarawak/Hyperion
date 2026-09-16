package workflows

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/events"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/ports"
)

// Backfill walks the history of every configured feed and publishes it, so a
// fresh deployment starts with years of findings instead of the last poll
// window. It is a one-off job, not part of the polling loop: polling keeps
// data current, backfill fills in what polling can never reach.
//
// The same events polling would produce are published, so cortex needs no
// separate import path — a backfilled record merges with a polled one exactly
// as two polls would.
type Backfill struct {
	sources   []ports.Backfiller
	publisher ports.SignalPublisher
	now       func() time.Time
	log       *slog.Logger
	// progressEvery is how many published events pass between progress logs.
	progressEvery int
}

// NewBackfill wires the use case with its outbound ports.
func NewBackfill(sources []ports.Backfiller, publisher ports.SignalPublisher) *Backfill {
	return &Backfill{
		sources:       sources,
		publisher:     publisher,
		now:           time.Now,
		log:           slog.Default(),
		progressEvery: 10000,
	}
}

// Run backfills every source from `from` and returns the number of events
// published. One source failing does not stop the others — errors are joined
// and returned after all have been attempted — but a publish failure stops the
// run outright, because it means nothing downstream is listening.
func (b *Backfill) Run(ctx context.Context, from time.Time) (int, error) {
	var (
		total int
		errs  []error
	)
	for _, source := range b.sources {
		kind := source.Kind()
		started := b.now()
		b.log.Info("backfill starting", "source", kind.String(), "from", from.Format(time.DateOnly))

		n, err := b.runSource(ctx, source, from)
		total += n

		var publishErr publishError
		switch {
		case errors.As(err, &publishErr):
			return total, publishErr.err
		case err != nil:
			b.log.Error("backfill incomplete", "source", kind.String(), "published", n, "error", err)
			errs = append(errs, err)
		default:
			b.log.Info("backfill complete", "source", kind.String(), "published", n,
				"took", b.now().Sub(started).Round(time.Second).String())
		}
	}
	return total, errors.Join(errs...)
}

// runSource streams one source, publishing each batch as it arrives.
func (b *Backfill) runSource(ctx context.Context, source ports.Backfiller, from time.Time) (int, error) {
	kind := source.Kind()
	published := 0

	err := source.Backfill(ctx, from, func(batch []model.SourceSignal) error {
		discoveredAt := b.now()
		for _, sig := range batch {
			if sig.Validate() != nil {
				continue
			}
			evt := events.NewSignalDiscovered(kind, sig, discoveredAt, "")
			if err := b.publisher.Publish(ctx, evt); err != nil {
				return publishError{fmt.Errorf("backfill %s: publish %s: %w", kind, sig.CVEID, err)}
			}
			published++
			b.log.Debug("published", "source", kind.String(), "id", sig.CVEID,
				"kind", string(sig.Kind), "packages", len(sig.AffectedPackages))
			if b.progressEvery > 0 && published%b.progressEvery == 0 {
				b.log.Info("backfill progress", "source", kind.String(), "published", published)
			}
		}
		return nil
	})
	return published, err
}

// publishError marks a failure to hand an event downstream, as opposed to a
// failure reading the source.
type publishError struct{ err error }

func (e publishError) Error() string { return e.err.Error() }
func (e publishError) Unwrap() error { return e.err }
