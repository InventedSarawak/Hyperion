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
}

// NewPollSource wires the use case with its outbound ports. Concrete adapters
// are chosen by the composition root (main.go), not here.
func NewPollSource(source ports.SourceClient, publisher ports.SignalPublisher) *PollSource {
	return &PollSource{
		source:    source,
		publisher: publisher,
		now:       time.Now,
		log:       slog.Default(),
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
