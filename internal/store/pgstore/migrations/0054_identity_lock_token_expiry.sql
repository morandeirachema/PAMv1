-- Identity lock and token expiry (Phase 242). locked_reason non-empty is an
-- administrator's lock: the user's token and login sessions stop resolving,
-- no new session is issued, and locked_until (nullable) lifts the lock by
-- itself when it passes. token_expires_at (nullable) is the instant the
-- user's access token stops authenticating; NULL — every token minted before
-- this migration — never expires. Both default to "no change" for every
-- existing row.
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMPTZ;
