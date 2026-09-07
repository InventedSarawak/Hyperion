-- cortex initial schema: the vulnerabilities read/write store.
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id         text PRIMARY KEY,
    title          text        NOT NULL DEFAULT '',
    description    text        NOT NULL DEFAULT '',
    scores         jsonb       NOT NULL DEFAULT '[]',
    reference_urls jsonb       NOT NULL DEFAULT '[]',
    sources        jsonb       NOT NULL DEFAULT '[]',
    published_at   timestamptz,
    modified_at    timestamptz,
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now()
);
