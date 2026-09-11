-- A finding is known by several ids — its CVE, GitHub's GHSA, OSV's MAL for
-- malware, ecosystem ids such as PYSEC- and GO- — and feeds report it under
-- whichever they hold. The row stays keyed on the canonical id (CVE, else
-- GHSA, else MAL, else other; the column keeps its historical name) and every
-- other id maps to it here. Keying the alias makes "no id names two findings"
-- a constraint rather than a hope, and a lookup by any id is two index hits.
CREATE TABLE IF NOT EXISTS finding_aliases (
    alias  text PRIMARY KEY,
    cve_id text NOT NULL REFERENCES vulnerabilities (cve_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS finding_aliases_cve_id_idx ON finding_aliases (cve_id);

-- Malware is recorded, not dropped: it is the most urgent thing a dependency
-- can be, and it never gets a CVE. The kind lets readers tell it apart.
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'vulnerability';
