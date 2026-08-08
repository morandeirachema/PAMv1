-- Phase 69: an item has an owner.
--
-- Additive with an empty default, so every existing campaign and item keeps
-- meaning what it meant: no reviewer named, anyone with `approve` decides.
ALTER TABLE campaigns      ADD COLUMN IF NOT EXISTS reviewer TEXT NOT NULL DEFAULT '';
ALTER TABLE campaign_items ADD COLUMN IF NOT EXISTS reviewer TEXT NOT NULL DEFAULT '';

-- A reviewer's queue is "my pending items across every open campaign", which is
-- the read this feature exists to make possible.
CREATE INDEX IF NOT EXISTS campaign_items_reviewer_idx
  ON campaign_items (reviewer, decision)
  WHERE reviewer <> '';
