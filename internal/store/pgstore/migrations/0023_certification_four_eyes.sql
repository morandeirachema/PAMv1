-- Per-item four-eyes on certification (Phase 46). Phase 39 delegated the
-- certification decision to CapApprove, but nothing stopped the principal who
-- CREATED a grant from certifying it themselves — the reviewer and the grantor
-- could be the same person, which is what an access review exists to prevent.
--
-- Record who created each access grant, and snapshot that into the campaign
-- item at campaign creation, so the decision check needs no live lookup and
-- still works after the underlying grant row is deleted. Existing rows keep an
-- empty creator: four-eyes cannot be enforced retroactively on grants whose
-- creator was never recorded, and pretending otherwise would block every
-- legacy review.
ALTER TABLE target_grants  ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT '';
ALTER TABLE safe_members   ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT '';
ALTER TABLE campaign_items ADD COLUMN IF NOT EXISTS granted_by TEXT NOT NULL DEFAULT '';
