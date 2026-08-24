// Package postgres is an OUTBOUND adapter implementing ports.VulnerabilityRepo
// on PostgreSQL via pgx. All SQL and JSON encoding lives here; the rest of
// cortex sees only domain types.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

// Repo persists vulnerabilities in PostgreSQL.
type Repo struct {
	pool *pgxpool.Pool
}

// NewRepo wraps a pgx pool as a VulnerabilityRepo.
func NewRepo(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool} }

const upsertSQL = `
INSERT INTO vulnerabilities
    (cve_id, title, description, scores, reference_urls, sources, published_at, modified_at, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb, $7, $8, now(), now())
ON CONFLICT (cve_id) DO UPDATE SET
    title          = EXCLUDED.title,
    description    = EXCLUDED.description,
    scores         = EXCLUDED.scores,
    reference_urls = EXCLUDED.reference_urls,
    sources        = EXCLUDED.sources,
    published_at   = EXCLUDED.published_at,
    modified_at    = EXCLUDED.modified_at,
    last_seen_at   = now();`

// Upsert inserts or overwrites the row for v.CVEID. The application layer has
// already merged with any existing record, so overwrite is the correct action.
func (r *Repo) Upsert(ctx context.Context, v model.Vulnerability) error {
	scores, err := json.Marshal(v.Scores)
	if err != nil {
		return fmt.Errorf("postgres: marshal scores: %w", err)
	}
	refs, err := json.Marshal(v.References)
	if err != nil {
		return fmt.Errorf("postgres: marshal references: %w", err)
	}
	sources, err := json.Marshal(v.Sources)
	if err != nil {
		return fmt.Errorf("postgres: marshal sources: %w", err)
	}

	_, err = r.pool.Exec(ctx, upsertSQL,
		v.CVEID, v.Title, v.Description,
		string(scores), string(refs), string(sources),
		nullableTime(v.PublishedAt), nullableTime(v.ModifiedAt),
	)
	if err != nil {
		return fmt.Errorf("postgres: upsert %s: %w", v.CVEID, err)
	}
	return nil
}

const getByCVESQL = `
SELECT cve_id, title, description, scores, reference_urls, sources, published_at, modified_at
FROM vulnerabilities
WHERE cve_id = $1;`

// GetByCVE loads one vulnerability, or ports.ErrNotFound.
func (r *Repo) GetByCVE(ctx context.Context, cveID string) (model.Vulnerability, error) {
	var (
		v                   model.Vulnerability
		scores, refs, srcs  []byte
		published, modified *time.Time
	)
	err := r.pool.QueryRow(ctx, getByCVESQL, cveID).Scan(
		&v.CVEID, &v.Title, &v.Description, &scores, &refs, &srcs, &published, &modified,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Vulnerability{}, ports.ErrNotFound
	}
	if err != nil {
		return model.Vulnerability{}, fmt.Errorf("postgres: get %s: %w", cveID, err)
	}

	if err := json.Unmarshal(scores, &v.Scores); err != nil {
		return model.Vulnerability{}, fmt.Errorf("postgres: unmarshal scores: %w", err)
	}
	if err := json.Unmarshal(refs, &v.References); err != nil {
		return model.Vulnerability{}, fmt.Errorf("postgres: unmarshal references: %w", err)
	}
	if err := json.Unmarshal(srcs, &v.Sources); err != nil {
		return model.Vulnerability{}, fmt.Errorf("postgres: unmarshal sources: %w", err)
	}
	if published != nil {
		v.PublishedAt = *published
	}
	if modified != nil {
		v.ModifiedAt = *modified
	}
	return v, nil
}

// Count returns the number of stored vulnerabilities.
func (r *Repo) Count(ctx context.Context) (int, error) {
	var n int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM vulnerabilities;`).Scan(&n); err != nil {
		return 0, fmt.Errorf("postgres: count: %w", err)
	}
	return n, nil
}

func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
