-- Alerting: standing subscriptions, and the alerts they have raised.
CREATE TABLE IF NOT EXISTS subscriptions (
    id         text PRIMARY KEY,
    tenant     text        NOT NULL,
    name       text        NOT NULL,
    rule       jsonb       NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS subscriptions_tenant_idx ON subscriptions (tenant);

-- An alert stores the CVE id rather than a copy of the advisory: records are
-- corrected constantly, and a frozen copy would drift from what it points at.
--
-- ON DELETE CASCADE because an alert only means something alongside the rule
-- that raised it: "you asked to hear about X" is the whole content of the
-- alert, so orphaning them would leave rows nobody can interpret.
CREATE TABLE IF NOT EXISTS alerts (
    id              text PRIMARY KEY,
    subscription_id text        NOT NULL REFERENCES subscriptions (id) ON DELETE CASCADE,
    tenant          text        NOT NULL,
    cve_id          text        NOT NULL,
    reason          text        NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS alerts_tenant_created_idx ON alerts (tenant, created_at DESC);
CREATE INDEX IF NOT EXISTS alerts_subscription_idx ON alerts (subscription_id);
