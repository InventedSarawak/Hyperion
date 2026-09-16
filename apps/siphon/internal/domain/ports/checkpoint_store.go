package ports

import (
	"context"
	"time"
)

// CheckpointStore is an OUTBOUND port: remember how far ingestion has read.
//
// Without it the watermark lives only in memory, so every restart reaches back
// exactly `now - SIPHON_LOOKBACK` — re-fetching a window that was already read
// (wasted rate-limit budget), and, if the process was down for longer than that
// window, never fetching what it missed at all. The second is the one that
// matters: those signals are simply never seen.
type CheckpointStore interface {
	// Load returns the watermark stored under name. The bool reports whether
	// one was stored at all — "nothing recorded yet" and "recorded as the zero
	// time" are different answers, and only the first should fall back to the
	// configured lookback.
	Load(ctx context.Context, name string) (time.Time, bool, error)

	// Save records the watermark a successful poll reached.
	Save(ctx context.Context, name string, at time.Time) error
}
