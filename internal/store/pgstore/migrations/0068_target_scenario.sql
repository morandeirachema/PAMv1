-- Startup scenarios (Phase 279): a target's SEND/EXPECT script — the login
-- dialogue of a telnet target, or a scripted first step in an SSH shell.
-- It names ${login} and ${password}; the secret itself stays in the vault.
-- Empty for every existing row: nothing runs that did not run before.
ALTER TABLE targets ADD COLUMN IF NOT EXISTS scenario TEXT NOT NULL DEFAULT '';
