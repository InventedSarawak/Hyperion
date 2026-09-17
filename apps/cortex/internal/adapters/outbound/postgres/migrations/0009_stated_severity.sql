-- Severity is not always a CVSS score. A malicious package never gets one, and
-- a CNA may rate a finding "High" without publishing a vector — the Linux
-- kernel CNA publishes thousands of CVEs a year and scores none of them.
-- model.Vulnerability has carried a Severity of its own for exactly that, but
-- the store had no column for it, so the rating survived ingestion (where
-- Normalized runs) and was lost on every read back: a reindex rebuilt the
-- search index from Postgres and downgraded those findings to UNKNOWN.
--
-- Null means "no stated rating" — the finding is rated from its scores, as
-- before. It is not the same as 'unknown', which would be a source saying it
-- does not know.
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS severity text;
