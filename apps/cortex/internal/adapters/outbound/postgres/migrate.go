package postgres

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Connect opens a pgx connection pool and verifies it with a ping.
func Connect(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return pool, nil
}

// migrationsTableSQL records what has been applied.
//
// The table is created by the runner rather than by a migration, because it is
// what decides whether a migration runs: it has to exist before the first one
// is considered.
const migrationsTableSQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     text PRIMARY KEY,
    checksum    text NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now()
);`

// Migrate applies any embedded schema file that has not been applied yet, in
// filename order, each in its own transaction.
//
// Every file used to run on every boot, and correctness rested entirely on
// each one being written with IF NOT EXISTS. That held for creating things and
// stopped holding the moment a migration needed to *change* data: a backfill
// written that way would re-run at every start, undoing whatever had happened
// since. Recording what has been applied is what makes a one-time migration
// possible at all.
//
// Applied files are also checksummed. Editing a migration that has already run
// is a silent way for two databases to end up with different schemas from the
// same source tree, so it is reported rather than ignored.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, migrationsTableSQL); err != nil {
		return fmt.Errorf("postgres: create schema_migrations: %w", err)
	}

	applied, err := appliedMigrations(ctx, pool)
	if err != nil {
		return err
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("postgres: read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		sqlBytes, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("postgres: read migration %s: %w", name, err)
		}
		sum := checksum(sqlBytes)

		if previous, ok := applied[name]; ok {
			if previous != sum {
				return fmt.Errorf(
					"postgres: migration %s has changed since it was applied (recorded %s, now %s); "+
						"add a new migration instead of editing one that has run", name, previous, sum)
			}
			continue
		}

		if err := applyMigration(ctx, pool, name, string(sqlBytes), sum); err != nil {
			return err
		}
	}
	return nil
}

// applyMigration runs one file and records it, both or neither.
//
// In one transaction on purpose: a migration that succeeded but was not
// recorded would run again on the next boot, which is exactly the failure this
// runner exists to prevent.
func applyMigration(ctx context.Context, pool *pgxpool.Pool, name, body, sum string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin migration %s: %w", name, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, body); err != nil {
		return fmt.Errorf("postgres: apply migration %s: %w", name, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`, name, sum); err != nil {
		return fmt.Errorf("postgres: record migration %s: %w", name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit migration %s: %w", name, err)
	}
	return nil
}

// appliedMigrations reads what the database says it already has.
func appliedMigrations(ctx context.Context, pool *pgxpool.Pool) (map[string]string, error) {
	rows, err := pool.Query(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("postgres: read schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := map[string]string{}
	for rows.Next() {
		var version, sum string
		if err := rows.Scan(&version, &sum); err != nil {
			return nil, fmt.Errorf("postgres: read schema_migrations: %w", err)
		}
		applied[version] = sum
	}
	return applied, rows.Err()
}

// checksum identifies the exact text that was applied.
func checksum(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
