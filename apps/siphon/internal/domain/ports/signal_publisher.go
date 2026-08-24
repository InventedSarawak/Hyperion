package ports

import (
	"context"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/events"
)

// SignalPublisher is an OUTBOUND port: publish a discovered signal to the event
// backbone. Implemented by adapters/outbound/* — a stdout publisher first, a
// Kafka publisher later. The adapter is where the domain event is mapped onto
// the hyperion.events.v1.SignalDiscovered protobuf.
type SignalPublisher interface {
	Publish(ctx context.Context, evt events.SignalDiscovered) error
}
