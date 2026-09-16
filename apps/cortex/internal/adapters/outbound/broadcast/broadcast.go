// Package broadcast is an OUTBOUND adapter implementing ports.FindingNotifier
// by fanning findings out to whoever is currently watching, in memory.
//
// In memory is the whole design: this is a live feed, not a record. Everything
// stored is already in Postgres and the search index, so a subscriber that was
// not connected has not lost anything it cannot ask for — and a feed that
// tried to be durable would be a second, worse copy of the topic cortex
// already consumes.
package broadcast

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
)

// DefaultBuffer is how many findings a subscriber can fall behind by before
// it starts missing them. A backfill delivers thousands per second and no
// terminal reads at that rate; the buffer covers an ordinary burst, and the
// drop that follows is the point rather than a failure.
const DefaultBuffer = 256

// Broadcaster fans findings out to current subscribers.
type Broadcaster struct {
	mu          sync.RWMutex
	subscribers map[int64]chan model.Vulnerability
	nextID      int64
	buffer      int

	delivered atomic.Int64
	dropped   atomic.Int64
}

// New builds a broadcaster. A buffer of zero takes the default.
func New(buffer int) *Broadcaster {
	if buffer <= 0 {
		buffer = DefaultBuffer
	}
	return &Broadcaster{subscribers: map[int64]chan model.Vulnerability{}, buffer: buffer}
}

// Notify sends the finding to every current subscriber.
//
// A subscriber whose buffer is full is skipped, not waited for. That is the
// one rule that matters here: ingest calls this on its hot path, and a
// terminal that stopped reading — because someone switched tabs, or the ssh
// session froze — must not be able to stall the pipeline.
func (b *Broadcaster) Notify(_ context.Context, v model.Vulnerability) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, ch := range b.subscribers {
		select {
		case ch <- v:
			b.delivered.Add(1)
		default:
			b.dropped.Add(1)
		}
	}
}

// Subscribe returns a channel of findings and a function that stops the
// subscription. The channel is closed when the subscription ends, so a reader
// ranging over it simply finishes.
//
// Callers must call the returned function — a subscription nobody cancels is a
// channel Notify keeps writing to for the life of the process.
func (b *Broadcaster) Subscribe() (<-chan model.Vulnerability, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.nextID++
	id := b.nextID
	ch := make(chan model.Vulnerability, b.buffer)
	b.subscribers[id] = ch

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			if existing, ok := b.subscribers[id]; ok {
				delete(b.subscribers, id)
				close(existing)
			}
		})
	}
}

// Subscribers reports how many feeds are currently open.
func (b *Broadcaster) Subscribers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subscribers)
}

// Stats reports how many findings have been delivered and how many were
// dropped because a subscriber was not keeping up.
func (b *Broadcaster) Stats() (delivered, dropped int64) {
	return b.delivered.Load(), b.dropped.Load()
}
