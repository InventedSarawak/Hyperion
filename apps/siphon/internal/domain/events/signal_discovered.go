// Package events holds siphon's domain events: facts about something that
// happened, which the service publishes for other services to react to.
package events

import (
	"fmt"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// SignalDiscovered is emitted when siphon observes a vulnerability signal from
// an upstream source. It is the domain event; an outbound adapter maps it onto
// the wire contract (hyperion.events.v1.SignalDiscovered) at the boundary.
type SignalDiscovered struct {
	SignalID     string // stable dedupe / idempotency key
	Source       valueobject.SourceKind
	Signal       model.SourceSignal
	DiscoveredAt time.Time
	RawRef       string // pointer to the archived raw payload, if any
}

// NewSignalDiscovered builds the event and derives its identity. The SignalID
// is deterministic (source + CVE id) so re-observing the same signal yields the
// same key — that dedupe rule is domain logic, not adapter concern.
func NewSignalDiscovered(source valueobject.SourceKind, sig model.SourceSignal, discoveredAt time.Time, rawRef string) SignalDiscovered {
	return SignalDiscovered{
		SignalID:     fmt.Sprintf("%s:%s", source, sig.CVEID),
		Source:       source,
		Signal:       sig,
		DiscoveredAt: discoveredAt,
		RawRef:       rawRef,
	}
}
