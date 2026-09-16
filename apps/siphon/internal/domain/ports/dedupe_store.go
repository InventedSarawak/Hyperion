package ports

import (
	"context"
	"time"
)

// DedupeStore is an OUTBOUND port: remember observations already published, so
// an unchanged signal is not published again on every poll.
//
// Each poll re-reads a whole window, so the same advisory is observed over and
// over — at a 10m interval and a 2h lookback, roughly twelve times. Publishing
// each one costs a record on the topic and a full read-merge-write in cortex
// to arrive back at the record that was already there.
type DedupeStore interface {
	// FirstSeen records key and reports whether it was absent — that is,
	// whether this observation is new. It must be atomic: two pollers checking
	// and then setting separately would both believe they were first.
	//
	// The window bounds how long an observation is remembered. It is not a
	// correctness boundary but a cost one: forgetting early means republishing
	// something unchanged, which is merely wasteful.
	FirstSeen(ctx context.Context, key string, window time.Duration) (bool, error)
}
