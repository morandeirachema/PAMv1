-- Level-tiered and direct-manager approval (Phase 256). A target or a safe
-- may carry an ORDERED approval chain ("manager; approver:2; admin", see
-- internal/store/approvaltiers.go): an access request is granted only once
-- every tier is satisfied, in order, and an approval counts only toward the
-- first unsatisfied tier the approver qualifies for. Empty - every row that
-- predates this migration - is the untiered N-of-M count every request had
-- before, so no request's requirements change on upgrade.
--
-- users.manager names an identity's direct manager (a local username) for
-- the "manager" tier. Empty - every existing user - means none: a request
-- against a policy with a manager tier is refused at creation until one is
-- set, rather than left waiting for an approval nobody can give.
ALTER TABLE targets ADD COLUMN IF NOT EXISTS approval_tiers TEXT NOT NULL DEFAULT '';
ALTER TABLE safes   ADD COLUMN IF NOT EXISTS approval_tiers TEXT NOT NULL DEFAULT '';
ALTER TABLE users   ADD COLUMN IF NOT EXISTS manager        TEXT NOT NULL DEFAULT '';
