-- Per-session MFA (Phase 244). require_session_mfa on a target or a safe
-- makes every session to it (or to any target in the safe) require a fresh
-- second factor, strictest-wins with the deployment-wide PAM_SESSION_MFA —
-- the same fold require_approval takes. sessions.target_id binds a
-- session-MFA ticket (scope "session_mfa") to the ONE target it was minted
-- for; NULL for every other session row, which is every row that exists
-- before this migration.
ALTER TABLE targets ADD COLUMN IF NOT EXISTS require_session_mfa BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE safes ADD COLUMN IF NOT EXISTS require_session_mfa BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS target_id BIGINT REFERENCES targets (id) ON DELETE CASCADE;
