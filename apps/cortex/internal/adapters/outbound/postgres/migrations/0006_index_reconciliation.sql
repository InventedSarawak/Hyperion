-- Postgres is the store of record and Elasticsearch is derived from it, so the
-- two can disagree: an index write can fail while the row is already committed,
-- and ingest deliberately tolerates that rather than losing the finding. Until
-- now that disagreement was only a log line, and the index stayed wrong until
-- someone ran a full reindex by hand.
--
-- This column records when a row was last written to the index. A row whose
-- indexed_at is null, or older than its last_seen_at, is known to be behind and
-- can be repaired on its own — bounded work, rather than rebuilding 500,000
-- documents to fix one.
--
-- The column and its backfill are in one conditional block on purpose. The
-- migration runner re-runs every file on every boot, so a bare UPDATE would
-- mark rows as settled each time cortex started — including the rows that are
-- genuinely behind, which is precisely the thing this is meant to find. Doing
-- it only when the column is created means it happens exactly once.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'vulnerabilities' AND column_name = 'indexed_at'
    ) THEN
        ALTER TABLE vulnerabilities ADD COLUMN indexed_at timestamptz;

        -- Rows that predate this column were indexed under the old behaviour;
        -- there is simply no record of when. Treating them as settled is the
        -- accurate reading: `task reindex` is what settles any drift that
        -- built up before there was a way to see it.
        UPDATE vulnerabilities SET indexed_at = last_seen_at;
    END IF;
END $$;

-- Only the rows that are behind, which is normally none of them. A partial
-- index keeps the reconciliation query cheap no matter how large the table
-- grows, because it never covers the rows that are already in step.
CREATE INDEX IF NOT EXISTS vulnerabilities_pending_index_idx
    ON vulnerabilities (last_seen_at)
    WHERE indexed_at IS NULL OR indexed_at < last_seen_at;
