package workflows

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/ports"
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

// Run polls every source in turn and reports the total number of events
// published across all of them.
func (p *PollSources) Run(ctx context.Context, since time.Time) (int, error) {
	var (
		total int
		errs  []error
	)
	for _, poller := range p.pollers {
		kind := poller.Kind().String()

		n, err := poller.Run(ctx, since)
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
