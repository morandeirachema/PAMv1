-- Critical targets (Phase 277): a flag whose only effect is notification —
-- every connection opened to the target raises an alert and an audit row
-- target.critical_connect, and the reports mark it. FALSE for every existing
-- row, so nothing starts alerting when this runs.
ALTER TABLE targets ADD COLUMN IF NOT EXISTS critical BOOLEAN NOT NULL DEFAULT FALSE;
