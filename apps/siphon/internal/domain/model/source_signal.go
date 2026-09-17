// Package model holds siphon's domain entities: the normalized shapes the
// service reasons about, independent of any transport or storage format.
package model

import (
	"errors"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// Severity is the domain's qualitative rating for a score.
type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityNone     Severity = "none"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// CVSS is a single scored assessment of a signal.
type CVSS struct {
	Version   string
	BaseScore float64
	Vector    string
	Severity  Severity
}

// FindingKind separates flaws in legitimate software from packages published
// to do harm. Only advisory feeds that track malware (GitHub, OSV) ever say
// the latter; everything else reports vulnerabilities.
type FindingKind string

const (
	KindVulnerability FindingKind = "vulnerability"
	KindMalware       FindingKind = "malware"
)

// SourceSignal is the normalized, source-agnostic form of one vulnerability
// signal after siphon has parsed an upstream feed. It is a domain type: it
// knows nothing about NVD JSON, protobuf, or Kafka.
type SourceSignal struct {
	// CVEID is the id the source leads with: a CVE when the finding has one,
	// else a GHSA, else a MAL, else whatever the feed numbered it. The name
	// predates GHSA and MAL support.
	CVEID string
	// Aliases are the other ids the source knows the finding by. Keeping them
	// is what lets cortex recognise one finding reported under different ids.
	Aliases     []string
	Kind        FindingKind
	Title       string
	Description string
	Scores      []CVSS
	References  []string
	PublishedAt time.Time
	ModifiedAt  time.Time
	// Withdrawn marks a finding the source has retracted — an NVD record whose
	// vulnStatus is Rejected. Such a record is still published: a CVE is often
	// rejected after it was stored, and the only way for cortex to learn that
	// is to be told.
	Withdrawn bool
	// AffectedPackages are the libraries the source names as vulnerable.
	// Only advisory-shaped feeds (GitHub Advisory, OSV) supply these; they
	// are what lets cortex connect a CVE into the dependency graph, so a
	// feed that omits them yields a finding with no blast radius.
	AffectedPackages []valueobject.PackageRef
}

// ErrMissingCVEID is returned when a signal lacks an identifier.
var ErrMissingCVEID = errors.New("source signal: an id is required")

// Validate enforces the entity's invariants.
func (s SourceSignal) Validate() error {
	if s.CVEID == "" {
		return ErrMissingCVEID
	}
	return nil
}
