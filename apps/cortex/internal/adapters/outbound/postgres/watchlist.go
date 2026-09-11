package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// Watchlist persists tracked repositories in PostgreSQL.
type Watchlist struct {
	pool *pgxpool.Pool
}

// NewWatchlist wraps a pgx pool as a ports.Watchlist.
func NewWatchlist(pool *pgxpool.Pool) *Watchlist { return &Watchlist{pool: pool} }

const watchlistColumns = `owner, name, status, added_at, last_scan_at, last_error, dependency_count`

const listWatchlistSQL = `
SELECT ` + watchlistColumns + `
FROM tracked_repositories
ORDER BY lower(owner), lower(name);`

// List returns every tracked repository, ordered by name.
func (w *Watchlist) List(ctx context.Context) ([]model.TrackedRepository, error) {
	rows, err := w.pool.Query(ctx, listWatchlistSQL)
	if err != nil {
		return nil, fmt.Errorf("postgres: list watchlist: %w", err)
	}
	defer rows.Close()

	out := make([]model.TrackedRepository, 0)
	for rows.Next() {
		t, err := scanTracked(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list watchlist: %w", err)
	}
	return out, nil
}

// trackSQL inserts a pending entry, or re-queues an existing one. The
// conflict target is the case-folded unique index, so re-tracking with
// different casing re-queues the same row; added_at is left as it was.
const trackSQL = `
INSERT INTO tracked_repositories (owner, name, status, added_at)
VALUES ($1, $2, 'pending', $3)
ON CONFLICT (lower(owner), lower(name)) DO UPDATE SET
    status     = 'pending',
    last_error = ''
RETURNING ` + watchlistColumns + `;`

// Track adds repositories as pending, re-queuing any already tracked, in one
// transaction so a batch is tracked whole or not at all.
func (w *Watchlist) Track(ctx context.Context, repos []model.TrackedRepository) ([]model.TrackedRepository, error) {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("postgres: track: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // a no-op once committed

	now := time.Now().UTC()
	out := make([]model.TrackedRepository, 0, len(repos))
	for _, r := range repos {
		t, err := scanTracked(tx.QueryRow(ctx, trackSQL, r.Owner, r.Name, now))
		if err != nil {
			return nil, fmt.Errorf("postgres: track %s: %w", r.FullName(), err)
		}
		out = append(out, t)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("postgres: track: commit: %w", err)
	}
	return out, nil
}

const removeTrackedSQL = `
DELETE FROM tracked_repositories
WHERE lower(owner) = lower($1) AND lower(name) = lower($2);`

// Remove deletes one entry, reporting whether it existed.
func (w *Watchlist) Remove(ctx context.Context, fullName string) (bool, error) {
	owner, name, _ := strings.Cut(fullName, "/")
	tag, err := w.pool.Exec(ctx, removeTrackedSQL, owner, name)
	if err != nil {
		return false, fmt.Errorf("postgres: untrack %s: %w", fullName, err)
	}
	return tag.RowsAffected() > 0, nil
}

// recordScanSQL stores an outcome. A failed scan keeps the dependency count
// from the last good one: the graph still holds those edges, and zeroing the
// count would misreport what blast radius can currently see.
const recordScanSQL = `
UPDATE tracked_repositories SET
    status           = $3,
    last_scan_at     = $4,
    last_error       = $5,
    dependency_count = CASE WHEN $3 = 'scanned' THEN $6 ELSE dependency_count END
WHERE lower(owner) = lower($1) AND lower(name) = lower($2);`

// RecordScan stores a scan outcome, or ports.ErrNotTracked when the
// repository was untracked while its scan was running.
func (w *Watchlist) RecordScan(ctx context.Context, outcome model.ScanOutcome) error {
	owner, name, _ := strings.Cut(outcome.FullName, "/")
	status := model.ScanFailed
	if outcome.Succeeded {
		status = model.ScanScanned
	}
	scannedAt := outcome.ScannedAt
	if scannedAt.IsZero() {
		scannedAt = time.Now().UTC()
	}

	tag, err := w.pool.Exec(ctx, recordScanSQL,
		owner, name, string(status), scannedAt, outcome.Error, outcome.DependencyCount)
	if err != nil {
		return fmt.Errorf("postgres: record scan %s: %w", outcome.FullName, err)
	}
	if tag.RowsAffected() == 0 {
		return ports.ErrNotTracked
	}
	return nil
}

func scanTracked(row pgx.Row) (model.TrackedRepository, error) {
	var (
		t          model.TrackedRepository
		status     string
		lastScanAt *time.Time
	)
	if err := row.Scan(&t.Owner, &t.Name, &status, &t.AddedAt, &lastScanAt, &t.LastError, &t.DependencyCount); err != nil {
		return model.TrackedRepository{}, fmt.Errorf("postgres: scan tracked repository: %w", err)
	}
	t.Status = model.ScanStatus(status)
	if lastScanAt != nil {
		t.LastScanAt = *lastScanAt
	}
	return t, nil
}
