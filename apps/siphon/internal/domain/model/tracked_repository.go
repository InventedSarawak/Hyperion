package model

import "time"

// ScanStatus is where a tracked repository is in its scan lifecycle, as the
// intelligence service reports it.
type ScanStatus string

const (
	ScanPending ScanStatus = "pending"
	ScanScanned ScanStatus = "scanned"
	ScanFailed  ScanStatus = "failed"
)

// TrackedRepository is one watchlist entry: a repository someone asked
// Hyperion to read. The watchlist itself belongs to cortex; siphon only needs
// to know what is on it and when each entry was last read.
type TrackedRepository struct {
	Owner      string
	Name       string
	Status     ScanStatus
	LastScanAt time.Time
}

// FullName is "owner/name".
func (t TrackedRepository) FullName() string { return t.Owner + "/" + t.Name }

// DueForScan reports whether the repository should be read now. Pending
// always is — someone just asked for it. A scanned one is due once its
// manifests may have changed (every `rescan`). A failed one is retried after
// `retry`, which is far shorter, so a transient failure does not leave a
// repository missing from the graph for hours — but not so short that a
// permanently broken one burns GitHub quota on every pass.
func (t TrackedRepository) DueForScan(now time.Time, rescan, retry time.Duration) bool {
	switch t.Status {
	case ScanScanned:
		return now.Sub(t.LastScanAt) >= rescan
	case ScanFailed:
		return now.Sub(t.LastScanAt) >= retry
	default:
		return true
	}
}

// ScanOutcome is what siphon reports after reading one repository.
type ScanOutcome struct {
	FullName        string
	Succeeded       bool
	Error           string
	DependencyCount int
	ScannedAt       time.Time
}
