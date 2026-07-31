-- Phase 58: safe-scoped access policy. A safe can now carry its own approval
-- requirement and a dual-control floor, binding every target placed in it —
-- so "everything in the production safe needs two approvers" is one setting,
-- not a per-target flag somebody forgets on the next onboarding.
--
-- Both default to the previous behaviour (no safe-imposed requirement), so an
-- existing deployment sees no change until an operator sets them. The policy
-- is strictest-wins with the global and per-target settings: a safe may
-- tighten what they allow, never loosen it.

ALTER TABLE safes ADD COLUMN IF NOT EXISTS require_approval BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE safes ADD COLUMN IF NOT EXISTS min_approvers    INTEGER NOT NULL DEFAULT 0;
