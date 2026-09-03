-- Grant lifetime (Phase 240): a standing target grant or safe membership may
-- carry an expiry instant and/or a recurring weekly time frame
-- ("Mon-Fri 08:00-18:00 Europe/Madrid", see internal/timeframe). NULL /
-- empty — every row that predates this migration — keeps the old meaning:
-- unbounded. The authorization reads (EffectiveTargetGrants, the reach view)
-- exclude an expired or out-of-frame row; the expiry sweeper deletes expired
-- rows and audits each one.
ALTER TABLE target_grants ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE target_grants ADD COLUMN IF NOT EXISTS time_frame TEXT NOT NULL DEFAULT '';
ALTER TABLE safe_members  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE safe_members  ADD COLUMN IF NOT EXISTS time_frame TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS target_grants_expires_at_idx ON target_grants (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS safe_members_expires_at_idx  ON safe_members  (expires_at) WHERE expires_at IS NOT NULL;
