// Package workflows holds siphon's application use cases: orchestration that
// coordinates domain types through ports. It depends on interfaces only, never
// on concrete adapters, transport, or storage.
package workflows

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/events"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// PollSource is the use case: pull signals from one source and publish each as
// a domain event.
type PollSource struct {
	source    ports.SourceClient
	publisher ports.SignalPublisher
	now       func() time.Time
	log       *slog.Logger

	// dedupe, when set, suppresses observations already published.
	dedupe       ports.DedupeStore
	dedupeWindow time.Duration

	// Cadence and position, per source. Ten feeds publish at rates that
	// differ by orders of magnitude — NVD hundreds a day, Exploit-DB a
	// handful a week — so one interval and one window cannot suit them all.
	interval   time.Duration
	lookback   time.Duration
	nextDue    time.Time
	since      time.Time
	checkpoint ports.CheckpointStore
}

// NewPollSource wires the use case with its outbound ports. Concrete adapters
// are chosen by the composition root (main.go), not here.
func NewPollSource(source ports.SourceClient, publisher ports.SignalPublisher) *PollSource {
	return &PollSource{
		source:    source,
		publisher: publisher,
		now:       time.Now,
		log:       slog.Default(),
		interval:  10 * time.Minute,
		lookback:  2 * time.Hour,
	}
}

// WithDedupe suppresses publishing an observation that has already been
// published inside the window.
//
// A poll re-reads a whole window every time, so most of what it finds is
// something it already published — at a 10m interval over a 2h lookback, each
// advisory is seen about twelve times. Only the first is worth sending.
func (p *PollSource) WithDedupe(store ports.DedupeStore, window time.Duration) *PollSource {
	if store != nil {
		p.dedupe = store
		if window > 0 {
			p.dedupeWindow = window
		}
	}
	return p
}

// WithCadence sets how often this source is polled and how far back the first
// poll reaches when nothing has been stored yet.
func (p *PollSource) WithCadence(interval, lookback time.Duration) *PollSource {
	if interval > 0 {
		p.interval = interval
	}
	if lookback > 0 {
		p.lookback = lookback
	}
	return p
}

// WithCheckpoint persists this source's own watermark, so a restart resumes
// each feed where it left off rather than all of them at one shared point.
func (p *PollSource) WithCheckpoint(store ports.CheckpointStore) *PollSource {
	p.checkpoint = store
	return p
}

// Due reports whether this source is ready to be polled again.
func (p *PollSource) Due(now time.Time) bool { return !now.Before(p.nextDue) }

// NextDue reports when this source will next be polled.
func (p *PollSource) NextDue() time.Time { return p.nextDue }

// Interval reports how often this source is polled.
func (p *PollSource) Interval() time.Duration { return p.interval }

// RunDue polls this source from its own watermark and, on success, advances
// it and schedules the next poll.
//
// A failed poll advances nothing: the window it could not read is read again
// next time, which is the whole reason the watermark only moves on success.
// The retry is not immediate though — a source that is failing should not be
// hammered — so the next attempt waits out the interval like any other.
func (p *PollSource) RunDue(ctx context.Context) (int, error) {
	started := p.now()
	since := p.resume(ctx, started)

	n, err := p.Run(ctx, since)
	p.nextDue = started.Add(p.interval)
	if err != nil {
		return n, err
	}

	p.since = started
	p.persist(ctx, started)
	return n, nil
}

// resume decides where this source starts reading: its stored watermark, else
// what it read last in this process, else its own lookback window.
func (p *PollSource) resume(ctx context.Context, now time.Time) time.Time {
	if !p.since.IsZero() {
		return p.since
	}

	fallback := now.Add(-p.lookback)
	if p.checkpoint == nil {
		return fallback
	}

	at, found, err := p.checkpoint.Load(ctx, p.watermarkName())
	switch {
	case err != nil:
		p.log.Warn("could not read the stored watermark; falling back to the lookback window",
			"source", p.source.Kind().String(), "lookback", p.lookback.String(), "error", err)
		return fallback
	case !found:
		return fallback
	}

	p.log.Info("resuming from the stored watermark",
		"source", p.source.Kind().String(), "since", at.UTC().Format(time.RFC3339),
		"behind", now.Sub(at).Round(time.Second).String())
	return at
}

// persist records the new watermark. A failure is worth a line but not worth
// failing the poll: the events went out either way, and the cost of losing the
// write is that a restart re-reads this window.
func (p *PollSource) persist(ctx context.Context, at time.Time) {
	if p.checkpoint == nil {
		return
	}
	// Deliberately not the poll's context: a poll that succeeded on the way to
	// shutdown should still record where it reached.
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	if err := p.checkpoint.Save(saveCtx, p.watermarkName(), at); err != nil {
		p.log.Warn("could not persist the ingestion watermark; a restart will re-read this window",
			"source", p.source.Kind().String(), "error", err)
	}
}

// watermarkName keys this source's position. One key per source, so adding a
// feed cannot disturb another's place in the queue.
func (p *PollSource) watermarkName() string { return "source:" + p.source.Kind().String() }

// Run fetches signals discovered since `since`, wraps each valid one as a
// SignalDiscovered event, and publishes it. It returns the number published.
// Invalid signals are skipped; a publish failure stops the run and is returned.
//
// The run is not complete until the publisher has been flushed. On a broker,
// Publish only buffers — returning success before the flush would let the
// scheduler advance its watermark past events the broker never received, and
// those signals would never be fetched again.
func (p *PollSource) Run(ctx context.Context, since time.Time) (int, error) {
	signals, err := p.source.Fetch(ctx, since)
	if err != nil {
		return 0, fmt.Errorf("poll source %s: fetch: %w", p.source.Kind(), err)
	}

	discoveredAt := p.now()
	published, suppressed := 0, 0
	for _, sig := range signals {
		if err := sig.Validate(); err != nil {
			continue // skip malformed signals rather than abort the batch
		}
		evt := events.NewSignalDiscovered(p.source.Kind(), sig, discoveredAt, "")

		if !p.worthPublishing(ctx, evt) {
			suppressed++
			continue
		}

		if err := p.publisher.Publish(ctx, evt); err != nil {
			return published, fmt.Errorf("poll source %s: publish %s: %w", p.source.Kind(), sig.CVEID, err)
		}
		published++
		// One line per finding is far too much for a poll of thousands, and
		// exactly what is wanted when following a single one through.
		p.log.Debug("published", "source", p.source.Kind().String(), "id", sig.CVEID,
			"kind", string(sig.Kind), "packages", len(sig.AffectedPackages))
	}

	if err := p.publisher.Flush(ctx); err != nil {
		return published, fmt.Errorf("poll source %s: flush: %w", p.source.Kind(), err)
	}
	if suppressed > 0 {
		p.log.Info("suppressed observations already published",
			"source", p.source.Kind().String(), "suppressed", suppressed, "published", published)
	}
	return published, nil
}

// worthPublishing reports whether this observation has not been published
// before. With no dedupe store, everything is worth publishing.
//
// A store that errors also answers yes. Publishing a duplicate costs a record
// and a merge that changes nothing; suppressing a real signal because Redis
// was briefly unreachable loses it until the advisory is next amended. Those
// are not comparable, so this fails open.
func (p *PollSource) worthPublishing(ctx context.Context, evt events.SignalDiscovered) bool {
	if p.dedupe == nil {
		return true
	}

	first, err := p.dedupe.FirstSeen(ctx, evt.Fingerprint(), p.dedupeWindow)
	if err != nil {
		p.log.Warn("dedupe store unavailable; publishing without it",
			"source", p.source.Kind().String(), "id", evt.Signal.CVEID, "error", err)
		return true
	}
	return first
}

// Kind reports which source this use case polls.
func (p *PollSource) Kind() valueobject.SourceKind { return p.source.Kind() }
