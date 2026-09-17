-- One subscription hearing about one finding is one alert. That was expressed
-- only through the alert's id, `subscription:cve`, which holds right up until
-- the finding changes its id: a record first stored under a GHSA moves to its
-- CVE when a feed links the two, and the same subscription then alerts a second
-- time under the new key.
--
-- Expressed as a constraint here instead, so it holds however the id is spelled
-- and whatever the application does.
--
-- Duplicates already in the table are collapsed first, keeping the oldest —
-- when someone was told about a finding is the fact worth preserving.
DELETE FROM alerts a
    USING alerts b
WHERE a.subscription_id = b.subscription_id
  AND a.cve_id = b.cve_id
  AND (a.created_at, a.id) > (b.created_at, b.id);

CREATE UNIQUE INDEX IF NOT EXISTS alerts_subscription_finding_idx
    ON alerts (subscription_id, cve_id);
