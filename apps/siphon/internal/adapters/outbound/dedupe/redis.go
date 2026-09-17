// Package dedupe holds OUTBOUND adapters implementing ports.DedupeStore.
// Suppression is a time window rather than a permanent fact, so it belongs in
// a store that expires keys natively instead of a table someone has to sweep.
package dedupe

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultAddr is Redis in local development.
const DefaultAddr = "localhost:6379"

// keyPrefix namespaces siphon's fingerprints away from everything else sharing
// the server — siphon's own watermark and cortex's alert deduplication both
// live in the same Redis.
const keyPrefix = "hyperion:siphon:seen:"

// Redis remembers the fingerprints of recently published observations.
type Redis struct {
	client *redis.Client
}

// Connect opens a client and verifies the server answers.
func Connect(ctx context.Context, addr string) (*Redis, error) {
	if addr == "" {
		addr = DefaultAddr
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("dedupe: connect %s: %w", addr, err)
	}
	return &Redis{client: client}, nil
}

// Close releases the connection pool.
func (r *Redis) Close() error { return r.client.Close() }

// FirstSeen records key and reports whether it was absent.
//
// SET NX EX is one atomic round trip: checking and then setting would let two
// polls overlapping at a source boundary both conclude they were first.
func (r *Redis) FirstSeen(ctx context.Context, key string, window time.Duration) (bool, error) {
	if window <= 0 {
		window = 24 * time.Hour
	}
	ok, err := r.client.SetNX(ctx, keyPrefix+key, time.Now().UTC().Format(time.RFC3339), window).Result()
	if err != nil {
		return false, fmt.Errorf("dedupe: first seen %s: %w", key, err)
	}
	return ok, nil
}
