// Package model holds siphon's domain entities: the normalized shapes the
// service reasons about, independent of any transport or storage format.
package model

import (
	"errors"
	"time"
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

// SourceSignal is the normalized, source-agnostic form of one vulnerability
// signal after siphon has parsed an upstream feed. It is a domain type: it
// knows nothing about NVD JSON, protobuf, or Kafka.
type SourceSignal struct {
	CVEID       string
	Title       string
	Description string
	Scores      []CVSS
	References  []string
	PublishedAt time.Time
	ModifiedAt  time.Time
}

// ErrMissingCVEID is returned when a signal lacks its canonical identifier.
var ErrMissingCVEID = errors.New("source signal: cve id is required")

// Validate enforces the entity's invariants.
func (s SourceSignal) Validate() error {
	if s.CVEID == "" {
		return ErrMissingCVEID
	}
	return nil
}
