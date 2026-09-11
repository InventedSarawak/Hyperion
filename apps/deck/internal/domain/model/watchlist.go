package model

import "time"

// Scan states a tracked repository can be in.
const (
	ScanPending = "pending"
	ScanScanned = "scanned"
	ScanFailed  = "failed"
)

// TrackedRepository is one repository on the watchlist, as deck shows it.
type TrackedRepository struct {
	FullName        string
	URL             string
	Status          string // ScanPending, ScanScanned or ScanFailed
	AddedAt         time.Time
	LastScanAt      time.Time
	LastError       string
	DependencyCount int
}

// DiscoveredRepository is a repository an owner has on GitHub, offered in the
// picker when adding repositories.
type DiscoveredRepository struct {
	FullName    string
	Description string
	Language    string
	Stars       int
	PushedAt    time.Time
	Fork        bool
	Archived    bool
	Tracked     bool // already on the watchlist
}
