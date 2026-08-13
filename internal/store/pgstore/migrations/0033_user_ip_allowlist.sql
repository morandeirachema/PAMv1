-- CIDR/network-based connect & login authorization (Phase 118): a local
-- (bearer-token) user can be restricted to a set of source-address ranges.
-- Empty (the default) is unrestricted, so this column changes no existing
-- user's behavior until an admin opts them in.
ALTER TABLE users ADD COLUMN IF NOT EXISTS ip_allowlist TEXT NOT NULL DEFAULT '';
