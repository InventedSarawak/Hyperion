// Package noopdedupe is the OUTBOUND adapter used when no Redis is configured.
//
// It reports every key as unseen, so alerting still works — just without
// suppression. That is the safe direction: a duplicate alert is an annoyance,
// a suppressed one is a missed vulnerability.
package noopdedupe

import (
	"context"
	"time"
)

// Store implements ports.DedupeStore by never suppressing anything.
type Store struct{}

// New builds the pass-through store.
func New() *Store { return &Store{} }

// FirstSeen always reports true.
func (s *Store) FirstSeen(context.Context, string, time.Duration) (bool, error) {
	return true, nil
}
