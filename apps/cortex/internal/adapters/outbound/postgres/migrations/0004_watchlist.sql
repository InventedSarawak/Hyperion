-- The watchlist: repositories Hyperion tracks, and how their last scan went.
-- It replaces the SIPHON_REPO_WATCHLIST environment variable, so tracking a
-- repository is something done in the product rather than in a config file.
CREATE TABLE IF NOT EXISTS tracked_repositories (
    owner            text        NOT NULL,
    name             text        NOT NULL,
    status           text        NOT NULL DEFAULT 'pending',
    added_at         timestamptz NOT NULL DEFAULT now(),
    last_scan_at     timestamptz,
    last_error       text        NOT NULL DEFAULT '',
    dependency_count integer     NOT NULL DEFAULT 0
);

-- GitHub names are case-insensitive: "Vercel/Next.js" is "vercel/next.js".
-- The unique key is on the folded name so the two cannot both be tracked,
-- while the columns keep the casing the user (or GitHub) gave.
CREATE UNIQUE INDEX IF NOT EXISTS tracked_repositories_name_idx
    ON tracked_repositories (lower(owner), lower(name));
