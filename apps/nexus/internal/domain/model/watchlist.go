package model

import "time"

// TrackedRepository is one repository on the watchlist, as clients see it.
type TrackedRepository struct {
	FullName        string
	URL             string
	Status          string // "pending", "scanned" or "failed"
	AddedAt         time.Time
	LastScanAt      time.Time
	LastError       string
	DependencyCount int
	Exposure        ExposureSummary
}

// DiscoveredRepository is a repository an owner has on GitHub.
type DiscoveredRepository struct {
	FullName    string
	Description string
	Language    string
	Stars       int
	PushedAt    time.Time
	Fork        bool
	Archived    bool
	Tracked     bool
}
