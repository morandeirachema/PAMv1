-- Phase 33 follow-on: per-target RDP clipboard policy override.
-- '' = inherit the global PAM_RDP_CLIPBOARD / PAM_RDP_CLIPBOARD_AUDIT; when
-- set, the effective policy is the STRICTER of global and target, so a
-- high-sensitivity target can deny what the fleet allows but never the reverse.

ALTER TABLE targets ADD COLUMN IF NOT EXISTS rdp_clipboard       TEXT NOT NULL DEFAULT '';
ALTER TABLE targets ADD COLUMN IF NOT EXISTS rdp_clipboard_audit TEXT NOT NULL DEFAULT '';
