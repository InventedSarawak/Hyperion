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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// Repo persists vulnerabilities in PostgreSQL.
type Repo struct {
	pool *pgxpool.Pool
}

// NewRepo wraps a pgx pool as a VulnerabilityRepo.
func NewRepo(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool} }

// selectVulnerability reads rows with their aliases folded in.
const selectVulnerability = `
SELECT v.cve_id, v.kind, v.title, v.description, v.scores, v.reference_urls, v.sources,
       v.affected_packages, v.published_at, v.modified_at,
       COALESCE((SELECT array_agg(a.alias) FROM finding_aliases a WHERE a.cve_id = v.cve_id), '{}'),
       COALESCE(v.description_source, ''), COALESCE(v.scores_source, ''),
       COALESCE(v.severity, '')
FROM vulnerabilities v`

const upsertSQL = `
INSERT INTO vulnerabilities
    (cve_id, kind, title, description, scores, reference_urls, sources, affected_packages,
     published_at, modified_at, first_seen_at, last_seen_at, description_source, scores_source,
     severity)
VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, $9, $10, COALESCE($11::timestamptz, now()), now(), $12, $13,
        NULLIF($14, ''))
ON CONFLICT (cve_id) DO UPDATE SET
    kind               = EXCLUDED.kind,
    title              = EXCLUDED.title,
    description        = EXCLUDED.description,
    description_source = EXCLUDED.description_source,
    scores             = EXCLUDED.scores,
    scores_source      = EXCLUDED.scores_source,
    severity           = EXCLUDED.severity,
    reference_urls    = EXCLUDED.reference_urls,
    sources           = EXCLUDED.sources,
    affected_packages = EXCLUDED.affected_packages,
    published_at      = EXCLUDED.published_at,
    modified_at       = EXCLUDED.modified_at,
    first_seen_at     = LEAST(vulnerabilities.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at      = now();`

// conflictSQL finds an id of the record being written that already names a
// finding the write is not replacing: as another finding's alias ($1 is
// every id, $2 the canonical one), or as another finding's key ($4 is the
// aliases alone). $3 is the keys being replaced.
const conflictSQL = `
SELECT a.alias FROM finding_aliases a
WHERE a.alias = ANY($1::text[]) AND a.cve_id <> $2 AND a.cve_id <> ALL($3::text[])
UNION ALL
SELECT v.cve_id FROM vulnerabilities v
WHERE v.cve_id = ANY($4::text[]) AND v.cve_id <> ALL($3::text[])
LIMIT 1;`

// Upsert writes v under its canonical id and retires the keys it replaces,
// all in one transaction, so a re-keyed finding is never missing or doubled.
// The application layer has already merged every record involved, so
// overwriting is the correct action.
func (r *Repo) Upsert(ctx context.Context, v model.Vulnerability, replaces ...string) error {
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
	packages, err := json.Marshal(toStoredPackages(v.AffectedPackages))
	if err != nil {
		return fmt.Errorf("postgres: marshal affected packages: %w", err)
	}

	// Never nil: pgx sends a nil slice as NULL, and "<> ALL(NULL)" is NULL,
	// which would quietly let every conflict through.
	aliases := append([]string{}, v.Aliases...)
	retired := make([]string, 0, len(replaces))
	for _, id := range replaces {
		if id != v.CVEID {
			retired = append(retired, id)
		}
	}
	kind := v.Kind
	if kind == "" {
		kind = model.KindVulnerability
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: upsert %s: begin: %w", v.CVEID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Retiring a key is how two records become one finding: the loser's row
	// goes and its id lives on as an alias of the winner. An id the winner
	// does not carry has nowhere to live on — the row would be deleted and
	// nothing would resolve that id afterwards, which is a finding
	// disappearing rather than merging. The store refuses rather than
	// allowing it: there is no caller for whom that is the intent.
	if lost := retiredWithoutHome(v, retired); len(lost) > 0 {
		return fmt.Errorf("postgres: upsert %s: refusing to retire %v, which %s does not carry: %w",
			v.CVEID, lost, v.CVEID, ports.ErrOrphanedRetire)
	}

	var taken string
	err = tx.QueryRow(ctx, conflictSQL, append([]string{v.CVEID}, aliases...), v.CVEID, retired, aliases).Scan(&taken)
	switch {
	case err == nil:
		return fmt.Errorf("postgres: upsert %s: %s: %w", v.CVEID, taken, ports.ErrConflict)
	case !errors.Is(err, pgx.ErrNoRows):
		return fmt.Errorf("postgres: upsert %s: check ids: %w", v.CVEID, asConflict(err))
	}

	// The finding was first seen when its earliest key was.
	var firstSeen *time.Time
	if len(retired) > 0 {
		if err := tx.QueryRow(ctx,
			`SELECT min(first_seen_at) FROM vulnerabilities WHERE cve_id = ANY($1::text[]);`, retired,
		).Scan(&firstSeen); err != nil {
			return fmt.Errorf("postgres: upsert %s: read retired keys: %w", v.CVEID, asConflict(err))
		}
		// Alerts point at a finding by id; keep them pointing at it. An alert
		// already raised under the surviving id wins — the subscriber was
		// told then, and that is the moment worth keeping — so a colliding
		// one from the retired key is dropped rather than moved.
		if _, err := tx.Exec(ctx,
			`DELETE FROM alerts a USING alerts b
			  WHERE a.cve_id = ANY($2::text[])
			    AND b.cve_id = $1
			    AND a.subscription_id = b.subscription_id;`, v.CVEID, retired,
		); err != nil {
			return fmt.Errorf("postgres: upsert %s: drop duplicate alerts: %w", v.CVEID, asConflict(err))
		}
		if _, err := tx.Exec(ctx,
			`UPDATE alerts SET cve_id = $1 WHERE cve_id = ANY($2::text[]);`, v.CVEID, retired,
		); err != nil {
			return fmt.Errorf("postgres: upsert %s: move alerts: %w", v.CVEID, asConflict(err))
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM vulnerabilities WHERE cve_id = ANY($1::text[]);`, retired,
		); err != nil {
			return fmt.Errorf("postgres: upsert %s: retire old keys: %w", v.CVEID, asConflict(err))
		}
	}

	if _, err := tx.Exec(ctx, upsertSQL,
		v.CVEID, string(kind), v.Title, v.Description,
		string(scores), string(refs), string(sources), string(packages),
		nullableTime(v.PublishedAt), nullableTime(v.ModifiedAt), firstSeen,
		v.DescriptionSource, v.ScoresSource, string(v.Severity),
	); err != nil {
		return fmt.Errorf("postgres: upsert %s: %w", v.CVEID, asConflict(err))
	}

	if _, err := tx.Exec(ctx, `DELETE FROM finding_aliases WHERE cve_id = $1;`, v.CVEID); err != nil {
		return fmt.Errorf("postgres: upsert %s: clear aliases: %w", v.CVEID, asConflict(err))
	}
	if len(aliases) > 0 {
		if _, err := tx.Exec(ctx,
			`INSERT INTO finding_aliases (alias, cve_id) SELECT unnest($1::text[]), $2;`, aliases, v.CVEID,
		); err != nil {
			return fmt.Errorf("postgres: upsert %s: write aliases: %w", v.CVEID, asConflict(err))
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: upsert %s: commit: %w", v.CVEID, asConflict(err))
	}
	return nil
}

// asConflict reports a lost race as the domain's conflict, which the caller
// answers by reading again and merging: a unique violation (two writers
// claiming one id at the same moment, past the check above), a deadlock
// (Postgres aborts one of two writers waiting on each other's rows), or a
// serialization failure. Anything else is a real failure and stays one.
func asConflict(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505", "40P01", "40001":
			return fmt.Errorf("%w (%s)", ports.ErrConflict, pgErr.Message)
		}
	}
	return err
}

// findByIDsSQL resolves ids through both keys and aliases. Written as a join
// on a union rather than an OR so each side is an index lookup.
const findByIDsSQL = `
WITH hits AS (
    SELECT unnest($1::text[]) AS cve_id
    UNION
    SELECT cve_id FROM finding_aliases WHERE alias = ANY($1::text[])
)` + selectVulnerability + `
JOIN hits h ON h.cve_id = v.cve_id
ORDER BY v.cve_id;`

// FindByIDs loads every finding known by any of ids.
func (r *Repo) FindByIDs(ctx context.Context, ids []string) ([]model.Vulnerability, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := r.pool.Query(ctx, findByIDsSQL, ids)
	if err != nil {
		return nil, fmt.Errorf("postgres: find %v: %w", ids, err)
	}
	return collectVulnerabilities(rows)
}

// GetByID loads the finding known by id, or ports.ErrNotFound.
func (r *Repo) GetByID(ctx context.Context, id string) (model.Vulnerability, error) {
	found, err := r.FindByIDs(ctx, []string{id})
	if err != nil {
		return model.Vulnerability{}, err
	}
	if len(found) == 0 {
		return model.Vulnerability{}, ports.ErrNotFound
	}
	return found[0], nil
}

const scanSQL = selectVulnerability + `
WHERE v.cve_id > $1
ORDER BY v.cve_id
LIMIT $2;`

// Scan walks the table in canonical-id order, one page at a time.
func (r *Repo) Scan(ctx context.Context, afterCVE string, limit int) ([]model.Vulnerability, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := r.pool.Query(ctx, scanSQL, afterCVE, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: scan: %w", err)
	}
	return collectVulnerabilities(rows)
}

// collectVulnerabilities decodes every row of a selectVulnerability query.
func collectVulnerabilities(rows pgx.Rows) ([]model.Vulnerability, error) {
	defer rows.Close()
	var out []model.Vulnerability
	for rows.Next() {
		var (
			v                        model.Vulnerability
			kind, severity           string
			scores, refs, srcs, pkgs []byte
			published, modified      *time.Time
			aliases                  []string
		)
		if err := rows.Scan(&v.CVEID, &kind, &v.Title, &v.Description, &scores, &refs, &srcs, &pkgs,
			&published, &modified, &aliases, &v.DescriptionSource, &v.ScoresSource, &severity); err != nil {
			return nil, fmt.Errorf("postgres: scan row: %w", err)
		}
		v.Kind = model.FindingKind(kind)
		v.Severity = model.Severity(severity)
		if len(aliases) > 0 {
			valueobject.SortIDs(aliases)
			v.Aliases = aliases
		}
		if err := decodeVulnerability(&v, scores, refs, srcs, pkgs, published, modified); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// decodeVulnerability fills the JSON and nullable columns of a row into v.
func decodeVulnerability(v *model.Vulnerability, scores, refs, srcs, pkgs []byte, published, modified *time.Time) error {
	if err := json.Unmarshal(scores, &v.Scores); err != nil {
		return fmt.Errorf("postgres: unmarshal scores: %w", err)
	}
	if err := json.Unmarshal(refs, &v.References); err != nil {
		return fmt.Errorf("postgres: unmarshal references: %w", err)
	}
	if err := json.Unmarshal(srcs, &v.Sources); err != nil {
		return fmt.Errorf("postgres: unmarshal sources: %w", err)
	}
	var stored []storedPackage
	if err := json.Unmarshal(pkgs, &stored); err != nil {
		return fmt.Errorf("postgres: unmarshal affected packages: %w", err)
	}
	v.AffectedPackages = fromStoredPackages(stored)
	if published != nil {
		v.PublishedAt = *published
	}
	if modified != nil {
		v.ModifiedAt = *modified
	}
	return nil
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

// storedPackage is the JSON shape of an affected package in the row. The
// domain value object is not serialized directly: a storage format that
// changes whenever a domain type is renamed is a migration waiting to happen.
type storedPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

func toStoredPackages(refs []valueobject.PackageRef) []storedPackage {
	out := make([]storedPackage, 0, len(refs))
	for _, r := range refs {
		if r.Validate() != nil {
			continue
		}
		out = append(out, storedPackage{
			Ecosystem: r.Ecosystem.String(),
			Name:      r.Name,
			Version:   r.Version,
		})
	}
	return out
}

func fromStoredPackages(stored []storedPackage) []valueobject.PackageRef {
	if len(stored) == 0 {
		return nil
	}
	out := make([]valueobject.PackageRef, 0, len(stored))
	for _, s := range stored {
		out = append(out, valueobject.NewPackageRef(s.Ecosystem, s.Name, s.Version))
	}
	return out
}

// --- index reconciliation ---

// pendingIndexSQL reads the rows whose search document is behind.
//
// Oldest first, so a backlog is worked through in the order it appeared rather
// than repeatedly re-reading the same newest rows.
const pendingIndexSQL = selectVulnerability + `
WHERE v.indexed_at IS NULL OR v.indexed_at < v.last_seen_at
ORDER BY v.last_seen_at
LIMIT $1;`

// PendingIndex returns records whose index document is missing or stale.
func (r *Repo) PendingIndex(ctx context.Context, limit int) ([]model.Vulnerability, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := r.pool.Query(ctx, pendingIndexSQL, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: pending index: %w", err)
	}
	return collectVulnerabilities(rows)
}

// markIndexedSQL settles the rows that have just been written to the index.
const markIndexedSQL = `
UPDATE vulnerabilities SET indexed_at = $1 WHERE cve_id = ANY($2);`

// MarkIndexed records that these ids are in the index as of at.
func (r *Repo) MarkIndexed(ctx context.Context, at time.Time, ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := r.pool.Exec(ctx, markIndexedSQL, at, ids); err != nil {
		return fmt.Errorf("postgres: mark indexed: %w", err)
	}
	return nil
}

// deleteSQL removes findings by canonical id. Aliases go with them: the
// finding_aliases rows are ON DELETE CASCADE.
const deleteSQL = `DELETE FROM vulnerabilities WHERE cve_id = ANY($1);`

// Delete removes the findings known by these ids.
func (r *Repo) Delete(ctx context.Context, ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := r.pool.Exec(ctx, deleteSQL, ids); err != nil {
		return fmt.Errorf("postgres: delete %v: %w", ids, err)
	}
	return nil
}

// retiredWithoutHome lists the ids a retire would delete without the surviving
// record carrying them.
func retiredWithoutHome(v model.Vulnerability, retired []string) []string {
	if len(retired) == 0 {
		return nil
	}
	carried := make(map[string]struct{}, 1+len(v.Aliases))
	for _, id := range v.IDs() {
		carried[valueobject.NormalizeID(id)] = struct{}{}
	}

	var lost []string
	for _, id := range retired {
		if _, ok := carried[valueobject.NormalizeID(id)]; !ok {
			lost = append(lost, id)
		}
	}
	return lost
}
