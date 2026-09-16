// Package redis is an OUTBOUND adapter implementing ports.DedupeStore on
// Redis. Suppression is a time window rather than a permanent fact, so it
// belongs in a store that expires keys natively instead of in a table someone
// has to sweep.
package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultAddr is Redis in local development.
const DefaultAddr = "localhost:6379"

// Store remembers recently-seen keys.
type Store struct {
	client *redis.Client
}

// Connect opens a client and verifies the server answers.
func Connect(ctx context.Context, addr string) (*Store, error) {
	if addr == "" {
		addr = DefaultAddr
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis: connect %s: %w", addr, err)
	}
	return &Store{client: client}, nil
}

// Close releases the connection pool.
func (s *Store) Close() error { return s.client.Close() }

// Ready reports whether the server answers.
func (s *Store) Ready(ctx context.Context) error {
	if err := s.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis: not ready: %w", err)
	}
	return nil
}

// FirstSeen records key and reports whether it was absent.
//
// SET NX EX is one atomic round trip: checking and then setting would let two
// concurrent ingests both believe they were first and alert the same person
// twice.
func (s *Store) FirstSeen(ctx context.Context, key string, window time.Duration) (bool, error) {
	if window <= 0 {
		window = time.Hour
	}
	ok, err := s.client.SetNX(ctx, key, time.Now().UTC().Format(time.RFC3339), window).Result()
	if err != nil {
		return false, fmt.Errorf("redis: first seen %s: %w", key, err)
	}
	return ok, nil
}
