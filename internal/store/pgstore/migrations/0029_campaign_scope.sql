-- Phase 68: campaigns you can scope and schedule.
--
-- Every column is additive with a default that reproduces the old behaviour, so
-- an existing campaign keeps meaning exactly what it meant: scope_kind '' is the
-- whole estate, recur_days 0 is a one-off.
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS scope_kind    TEXT   NOT NULL DEFAULT '';
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS scope_subject TEXT   NOT NULL DEFAULT '';
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS recur_days    INT    NOT NULL DEFAULT 0;
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS next_run_at   TIMESTAMPTZ;

-- ON DELETE SET NULL rather than CASCADE: deleting a safe must not delete the
-- record that its access was once reviewed. The campaign survives as evidence,
-- with its scope pointer emptied.
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS scope_safe_id BIGINT
  REFERENCES safes(id) ON DELETE SET NULL;

-- The scheduler asks one question on every tick; give it an index rather than a
-- scan of every campaign ever run.
CREATE INDEX IF NOT EXISTS campaigns_due_idx
  ON campaigns (next_run_at)
  WHERE status = 'open' AND recur_days > 0;
