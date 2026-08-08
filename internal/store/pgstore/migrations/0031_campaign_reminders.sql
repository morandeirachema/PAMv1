-- Phase 70: a campaign nudges before it lapses.
--
-- NULL means "no reminder scheduled", which is what every existing campaign gets
-- and what a campaign with no due date keeps: there is nothing to be early for.
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS remind_at TIMESTAMPTZ;

-- The scheduler asks this on every tick.
CREATE INDEX IF NOT EXISTS campaigns_remind_idx
  ON campaigns (remind_at)
  WHERE status = 'open' AND remind_at IS NOT NULL;
