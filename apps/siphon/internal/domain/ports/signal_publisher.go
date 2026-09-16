package ports

import (
	"context"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/events"
)

// SignalPublisher is an OUTBOUND port: publish a discovered signal to the event
// backbone. Implemented by adapters/outbound/publisher — stdout for a pipe or a
// backfill, Kafka for the real backbone. The adapter is where the domain event
// is mapped onto the hyperion.events.v1.SignalDiscovered protobuf.
type SignalPublisher interface {
	// Publish hands one event to the transport. A nil error means the event
	// was accepted, which is not the same as durable — see Flush.
	Publish(ctx context.Context, evt events.SignalDiscovered) error

	// Flush blocks until everything published so far is durable, and reports
	// the first failure if there was one.
	//
	// The port has this method because publishing is asynchronous on a real
	// broker: records are batched, and Publish returns before the broker has
	// them. Anything that records progress — the scheduler's watermark, a
	// "poll complete" line, a checkpoint — must Flush first and act on its
	// error, or it will remember work that was never stored.
	Flush(ctx context.Context) error
}
