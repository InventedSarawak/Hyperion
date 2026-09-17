// Package checkpoint holds OUTBOUND adapters implementing
// ports.CheckpointStore. The watermark is a single small value that has to
// outlive the process, which is all Redis is being asked for here.
package checkpoint

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultAddr is Redis in local development.
const DefaultAddr = "localhost:6379"

// keyPrefix namespaces siphon's watermarks away from everything else sharing
// the server — cortex's alert deduplication lives in the same Redis.
const keyPrefix = "hyperion:siphon:watermark:"

// Redis stores watermarks as RFC3339 strings, one key per named poller.
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
		return nil, fmt.Errorf("checkpoint: connect %s: %w", addr, err)
	}
	return &Redis{client: client}, nil
}

// Close releases the connection pool.
func (r *Redis) Close() error { return r.client.Close() }

// Load reads the watermark for name, reporting whether one was stored.
//
// An unreadable value is treated as absent rather than as an error: a watermark
// that cannot be parsed is no more useful than none, and refusing to start over
// it would leave ingestion down for a corrupted string.
func (r *Redis) Load(ctx context.Context, name string) (time.Time, bool, error) {
	raw, err := r.client.Get(ctx, keyPrefix+name).Result()
	switch {
	case errors.Is(err, redis.Nil):
		return time.Time{}, false, nil
	case err != nil:
		return time.Time{}, false, fmt.Errorf("checkpoint: load %s: %w", name, err)
	}

	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false, nil
	}
	return at, true, nil
}

// Save records the watermark. It is deliberately set without an expiry: a
// watermark that quietly expired would send the next start back to the
// configured lookback, which is the failure this store exists to prevent.
func (r *Redis) Save(ctx context.Context, name string, at time.Time) error {
	if err := r.client.Set(ctx, keyPrefix+name, at.UTC().Format(time.RFC3339Nano), 0).Err(); err != nil {
		return fmt.Errorf("checkpoint: save %s: %w", name, err)
	}
	return nil
}
