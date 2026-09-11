package model

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ScanStatus is where a tracked repository is in its scan lifecycle.
type ScanStatus string

const (
	// ScanPending: tracked, and waiting for the scanner — either never
	// scanned or re-queued by the user.
	ScanPending ScanStatus = "pending"
	// ScanScanned: the last scan read the manifests and wrote the graph.
	ScanScanned ScanStatus = "scanned"
	// ScanFailed: the last scan could not complete; LastError says why.
	ScanFailed ScanStatus = "failed"
)

// TrackedRepository is one entry on the watchlist: a repository whose
// manifests Hyperion reads so blast radius can reach it. It is a separate
// entity from the graph's Repository on purpose — a repository is tracked the
// moment someone asks for it, long before (and whether or not) a scan ever
// succeeds, and "asked for but unreadable" must stay visible rather than
// silently absent from the graph.
type TrackedRepository struct {
	Owner           string
	Name            string
	Status          ScanStatus
	AddedAt         time.Time
	LastScanAt      time.Time // last attempt, successful or not
	LastError       string
	DependencyCount int
}

// FullName is the repository's identity, e.g. "vercel/next.js".
func (t TrackedRepository) FullName() string { return t.Owner + "/" + t.Name }

// URL is where the repository lives on the forge.
func (t TrackedRepository) URL() string { return "https://github.com/" + t.FullName() }

// ErrInvalidRepositoryName is returned for anything that is not owner/name.
var ErrInvalidRepositoryName = errors.New("repository: expected owner/name")

// githubName matches the characters GitHub allows in an owner or repository
// name. Checking here keeps a typo from sitting on the watchlist as a
// permanently failing scan, and keeps arbitrary text out of API paths.
var githubName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$`)

// ParseTrackedRepository reads "owner/name" — tolerating a pasted
// https://github.com/ URL or a trailing .git — into a pending entry.
func ParseTrackedRepository(raw string) (TrackedRepository, error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "github.com/")
	s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")

	owner, name, ok := strings.Cut(s, "/")
	if !ok || !githubName.MatchString(owner) || !githubName.MatchString(name) || strings.Contains(name, "/") {
		return TrackedRepository{}, fmt.Errorf("%w: %q", ErrInvalidRepositoryName, raw)
	}
	return TrackedRepository{Owner: owner, Name: name, Status: ScanPending}, nil
}

// DiscoveredRepository is a repository an owner has on the forge, offered
// for tracking. It is a read model: nothing about it is stored.
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

// ScanOutcome is what the scanner reports after reading one repository.
type ScanOutcome struct {
	FullName        string
	Succeeded       bool
	Error           string
	DependencyCount int
	ScannedAt       time.Time
}
