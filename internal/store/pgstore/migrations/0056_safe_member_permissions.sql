-- Safe permission sets (Phase 246). What a membership confers on the targets
-- in its safe, as a comma-separated subset of "use" (sessions, brokered
-- commands, operator certificates), "retrieve" (reveal, checkout) and
-- "approve" (decide access requests for the safe's targets). can_manage stays
-- the right to manage the member list. The default is what every membership
-- conferred before this migration, so the ALTER backfills every existing row
-- with exactly the access it already had.
ALTER TABLE safe_members ADD COLUMN IF NOT EXISTS permissions TEXT NOT NULL DEFAULT 'use,retrieve';
