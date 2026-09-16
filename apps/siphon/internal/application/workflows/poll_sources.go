package workflows

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// PollSources fans a poll out across every active source. One failing source
// does not stop the others: errors are collected and returned together, after
// all sources have been attempted.
type PollSources struct {
	pollers []*PollSource
	log     *slog.Logger
}

// NewPollSources builds the multi-source use case from the active clients.
func NewPollSources(clients []ports.SourceClient, publisher ports.SignalPublisher) *PollSources {
	pollers := make([]*PollSource, 0, len(clients))
	for _, c := range clients {
		pollers = append(pollers, NewPollSource(c, publisher))
	}
	return &PollSources{pollers: pollers, log: slog.Default()}
}

// WithDedupe applies the same suppression to every source's poll.
func (p *PollSources) WithDedupe(store ports.DedupeStore, window time.Duration) *PollSources {
	for _, poller := range p.pollers {
		poller.WithDedupe(store, window)
	}
	return p
}

// Run polls every source that is due and reports the total published.
//
// Due, rather than all of them: each source has its own interval, because ten
// feeds that publish at wildly different rates should not be asked at the same
// one. Polling Exploit-DB as often as NVD wastes requests on a feed that
// changes a few times a week; polling NVD as rarely as Exploit-DB would leave
// findings sitting unseen for hours.
func (p *PollSources) Run(ctx context.Context) (int, error) {
	var (
		total int
		errs  []error
		now   = time.Now()
	)
	for _, poller := range p.pollers {
		kind := poller.Kind().String()
		if !poller.Due(now) {
			p.log.Debug("source not due yet", "source", kind,
				"next", poller.NextDue().UTC().Format(time.RFC3339),
				"every", poller.Interval().String())
			continue
		}

		n, err := poller.RunDue(ctx)
		total += n
		if err != nil {
			p.log.Error("source poll failed", "source", kind, "published", n, "error", err)
			errs = append(errs, err)
			continue
		}
		p.log.Info("source poll complete", "source", kind, "published", n)
	}
	return total, errors.Join(errs...)
}

// WithCadence sets each source's own interval and lookback from a lookup keyed
// by source kind.
func (p *PollSources) WithCadence(cadence func(valueobject.SourceKind) (time.Duration, time.Duration)) *PollSources {
	for _, poller := range p.pollers {
		interval, lookback := cadence(poller.Kind())
		poller.WithCadence(interval, lookback)
	}
	return p
}

// WithCheckpoint gives every source its own persisted watermark.
func (p *PollSources) WithCheckpoint(store ports.CheckpointStore) *PollSources {
	for _, poller := range p.pollers {
		poller.WithCheckpoint(store)
	}
	return p
}
