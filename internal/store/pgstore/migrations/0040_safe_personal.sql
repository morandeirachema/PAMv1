-- Personal/private safes (Phase 139): a safe marked personal is invisible to
-- the unconditional admin bypass auth.CanConnectTarget otherwise grants —
-- only the safe's own members, or a principal holding the narrow
-- CapUnlimitedVaultAccess override, may reach a target inside it. Additive,
-- defaults false, so every existing safe stays exactly as open to admins as
-- it always was.
ALTER TABLE safes ADD COLUMN IF NOT EXISTS personal BOOLEAN NOT NULL DEFAULT false;
