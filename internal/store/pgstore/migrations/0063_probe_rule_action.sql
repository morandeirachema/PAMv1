-- Probe rule actions (Phase 271): a rule may NOTIFY — report the match as an
-- audited event without ending the process — as well as kill. Every row that
-- predates this migration kills, which is what it did.
ALTER TABLE probe_rules ADD COLUMN IF NOT EXISTS action TEXT NOT NULL DEFAULT 'kill';
ALTER TABLE probe_rules ADD CONSTRAINT probe_rules_action_check CHECK (action IN ('kill', 'notify'));
