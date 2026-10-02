-- "Subscription" meant a standing alert rule: tell me when a finding like this
-- arrives. Billing is coming (credits, Lago), and it has subscriptions of its
-- own — the kind people pay for. Two unrelated things under one name in one
-- database is a misread waiting to happen, so the alerting one is called what
-- it is: an alert rule, whose conditions are its criteria.
--
-- Renames rather than a new table and a copy: the rows, their ids and the
-- alerts pointing at them are unchanged, and every index and constraint moves
-- with the table it belongs to. Only the names are renamed to match.
ALTER TABLE subscriptions RENAME TO alert_rules;
ALTER TABLE alert_rules RENAME COLUMN rule TO criteria;
ALTER INDEX subscriptions_pkey RENAME TO alert_rules_pkey;
ALTER INDEX subscriptions_tenant_idx RENAME TO alert_rules_tenant_idx;

ALTER TABLE alerts RENAME COLUMN subscription_id TO rule_id;
ALTER TABLE alerts RENAME CONSTRAINT alerts_subscription_id_fkey TO alerts_rule_id_fkey;
ALTER INDEX alerts_subscription_finding_idx RENAME TO alerts_rule_finding_idx;
ALTER INDEX alerts_subscription_idx RENAME TO alerts_rule_idx;
