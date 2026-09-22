-- Approval depth (Phase 274): an approver's comment on a decision, a cancel of
-- an approved request, a pending request that timed out. notes holds one
-- "<approver>: <text>" line per comment; the new statuses 'cancelled' and
-- 'expired' are never "approved", so HasActiveApproval's predicate excludes
-- them without change.
ALTER TABLE access_requests ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT '';
