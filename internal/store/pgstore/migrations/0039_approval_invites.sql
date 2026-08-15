-- Magic-link access-request approval (Phase 137): a named person can decide
-- a pending access request from an emailed link, without ever logging into
-- pamv1 — BeyondTrust's out-of-band approval, the buildable "link" half.
-- Unlike session_share_invites there is no separate meta-approval stage:
-- minting an invite already requires CapApprove, so token_hash/expires_at
-- are set at creation, not on a later decision.
CREATE TABLE IF NOT EXISTS approval_invites (
    id                 BIGSERIAL PRIMARY KEY,
    access_request_id  BIGINT NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
    email              TEXT NOT NULL,
    created_by         TEXT NOT NULL,
    token_hash         TEXT NOT NULL UNIQUE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    decision           TEXT NOT NULL DEFAULT '', -- '' | approved | denied
    consumed_at        TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS approval_invites_request_idx ON approval_invites (access_request_id);
