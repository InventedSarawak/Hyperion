-- Affected packages link a CVE to the libraries it compromises, which is what
-- the dependency graph traverses. Stored here as well as in Neo4j so the
-- union across sources survives a restart: NVD re-reporting a CVE that only
-- GitHub named a package for must not erase the linkage.
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS affected_packages jsonb NOT NULL DEFAULT '[]';
