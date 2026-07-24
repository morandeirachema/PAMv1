-- Third-party vendor access gate (Phase 29): a vendor is an external identity
-- (linked to a users row by username) whose access to a target is bounded by a
-- customer-approved, time-boxed CONTRACT grant. A vendor may reach a target only
-- while an approved, unrevoked grant is active; offboarding revokes every grant
-- at once.
CREATE TABLE IF NOT EXISTS vendors (
    id         BIGSERIAL PRIMARY KEY,
    username   TEXT NOT NULL UNIQUE, -- the vendor's login identity (a users row)
    org        TEXT NOT NULL DEFAULT '',
    disabled   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A contract grant: the vendor may log in as `principal` on `target_id` only
-- while status='approved', not revoked, and now within [not_before, not_after].
-- Approval must come from a customer approver (never the vendor).
CREATE TABLE IF NOT EXISTS vendor_grants (
    id          BIGSERIAL PRIMARY KEY,
    vendor_id   BIGINT NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
    target_id   BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    principal   TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending', -- pending | approved | revoked
    not_before  TIMESTAMPTZ,
    not_after   TIMESTAMPTZ NOT NULL,
    approver    TEXT NOT NULL DEFAULT '',
    approved_at TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS vendor_grants_vendor_idx ON vendor_grants (vendor_id);
CREATE INDEX IF NOT EXISTS vendor_grants_target_idx ON vendor_grants (target_id);
