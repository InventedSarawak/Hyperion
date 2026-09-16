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
	published := 0
	for _, sig := range signals {
		if err := sig.Validate(); err != nil {
			continue // skip malformed signals rather than abort the batch
		}
		evt := events.NewSignalDiscovered(p.source.Kind(), sig, discoveredAt, "")
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
	return published, nil
}

// Kind reports which source this use case polls.
func (p *PollSource) Kind() valueobject.SourceKind { return p.source.Kind() }
