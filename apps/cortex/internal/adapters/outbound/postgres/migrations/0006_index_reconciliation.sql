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
DO $$
BEGIN
    -- Scoped through the search path (regclass), not by table name alone:
    -- information_schema.columns matches every schema, so a throwaway schema
    -- would see the column on the real table and skip creating its own.
    IF NOT EXISTS (
        SELECT 1 FROM pg_attribute
        WHERE attrelid = 'vulnerabilities'::regclass
          AND attname = 'indexed_at'
          AND NOT attisdropped
    ) THEN
        ALTER TABLE vulnerabilities ADD COLUMN indexed_at timestamptz;

        -- Rows that predate this column were indexed under the old behaviour;
        -- there is simply no record of when. Treating them as settled is the
        -- accurate reading: `task reindex` settles any drift that built up
        -- before there was a way to see it.
        UPDATE vulnerabilities SET indexed_at = last_seen_at;
    END IF;

    -- Only the rows that are behind, which is normally none of them. A partial
    -- index keeps the reconciliation query cheap however large the table grows,
    -- because it never covers the rows already in step.
    --
    -- EXECUTE, so it is planned when it runs rather than when the file is
    -- parsed: a plain statement here would be planned before the column above
    -- exists, and fail on a fresh database.
    EXECUTE 'CREATE INDEX IF NOT EXISTS vulnerabilities_pending_index_idx
             ON vulnerabilities (last_seen_at)
             WHERE indexed_at IS NULL OR indexed_at < last_seen_at';
END $$;
