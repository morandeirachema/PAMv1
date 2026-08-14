-- Device-aware access control (Phase 133): a local (bearer-token) user can be
-- bound to one enrolled client-certificate fingerprint. Empty (the default)
-- is unbound, so this column changes no existing user's behavior until an
-- admin opts them in, even when PAM_DEVICE_HEADER is set deployment-wide.
ALTER TABLE users ADD COLUMN IF NOT EXISTS device_fingerprint TEXT NOT NULL DEFAULT '';
