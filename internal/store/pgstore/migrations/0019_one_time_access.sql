-- One-time (single-use) access (Phase 26): a single-use approval admits exactly
-- one privileged use, then is consumed.
--   one_time:    the approval is single-use; the first connect/reveal/checkout/
--                tool call that relies on it burns it (consume-on-use).
--   consumed_at: when the approval was burned; NULL = still usable. A consumed
--                approval is no longer active anywhere.
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS one_time BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ;
