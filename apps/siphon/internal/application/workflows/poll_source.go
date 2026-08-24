// Package workflows holds siphon's application use cases: orchestration that
// coordinates domain types through ports. It depends on interfaces only, never
// on concrete adapters, transport, or storage.
package workflows

import (
	"context"
	"fmt"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/events"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/ports"
)

// PollSource is the use case: pull signals from one source and publish each as
// a domain event.
type PollSource struct {
	source    ports.SourceClient
	publisher ports.SignalPublisher
	now       func() time.Time
}

// NewPollSource wires the use case with its outbound ports. Concrete adapters
// are chosen by the composition root (main.go), not here.
func NewPollSource(source ports.SourceClient, publisher ports.SignalPublisher) *PollSource {
	return &PollSource{
		source:    source,
		publisher: publisher,
		now:       time.Now,
	}
}

// Run fetches signals discovered since `since`, wraps each valid one as a
// SignalDiscovered event, and publishes it. It returns the number published.
// Invalid signals are skipped; a publish failure stops the run and is returned.
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
	}
	return published, nil
}
