-- Description and scores are single values, so two feeds reporting one finding
-- differently means choosing between them. The choice is made by ranking the
-- feeds (see model.Merge), which only works if the record remembers which feed
-- the value it holds came from — otherwise every restart falls back to
-- whichever observation happens to arrive next.
--
-- Null means "stored before this was recorded", and any attributed value
-- replaces it, so the existing corpus settles into order as feeds re-report.
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS description_source text,
    ADD COLUMN IF NOT EXISTS scores_source      text;
