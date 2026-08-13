-- Phase 120: recurring access requests + password reuse history.
--
-- access_requests gets the same recur_days/next_run_at shape campaigns
-- already have (migration 0029) — additive, default 0/NULL, so every
-- existing request keeps meaning exactly what it meant: a one-off.
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS recur_days  INT NOT NULL DEFAULT 0;
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS next_run_at TIMESTAMPTZ;

-- The scheduler asks one question on every tick; give it an index rather than
-- a scan of every access request ever filed.
CREATE INDEX IF NOT EXISTS access_requests_due_idx
  ON access_requests (next_run_at)
  WHERE status = 'approved' AND recur_days > 0;

-- password_history holds SHA-256 hashes of past rotated secrets, never the
-- secrets themselves, so a rotation can refuse to reissue a recently-used
-- password (PAM_PASSWORD_HISTORY_COUNT). Deleting the credential deletes its
-- history; there is nothing left for the history to be evidence of.
CREATE TABLE IF NOT EXISTS password_history (
    id            BIGSERIAL PRIMARY KEY,
    credential_id BIGINT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    secret_hash   TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS password_history_cred_idx
  ON password_history (credential_id, created_at DESC, id DESC);
