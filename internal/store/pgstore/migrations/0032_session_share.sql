-- Live session-sharing (Phase 116): a second party can join a running SSH
-- session, view-only or view-control, via a request-then-approve (four-eyes)
-- invite. Kind distinguishes the two invite surfaces: 'internal' resolves
-- invitee as an existing PAMv1 username, redeemed by an SSH login; 'external'
-- resolves email as an unauthenticated contact address, redeemed via a
-- mailed link + QR code by a browser. Nothing is redeemable until
-- status='approved' — token_hash and expires_at are set only at that point,
-- so the redemption window always starts from the approval instant, not the
-- (possibly much earlier) request instant.
CREATE TABLE IF NOT EXISTS session_share_invites (
    id          BIGSERIAL PRIMARY KEY,
    session_id  TEXT NOT NULL,
    mode        TEXT NOT NULL, -- view_only | view_control
    kind        TEXT NOT NULL, -- internal | external
    invitee     TEXT NOT NULL DEFAULT '',
    email       TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending', -- pending | approved | denied | revoked
    requester   TEXT NOT NULL,
    approver    TEXT NOT NULL DEFAULT '',
    token_hash  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at  TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS session_share_invites_session_idx ON session_share_invites (session_id);
-- token_hash is empty ('') for every not-yet-approved row, so the uniqueness
-- constraint that matters is only among LIVE, redeemable tokens — a partial
-- index (rather than a bare UNIQUE column) is what lets that empty default
-- coexist across arbitrarily many pending/denied rows.
CREATE UNIQUE INDEX IF NOT EXISTS session_share_invites_token_idx
    ON session_share_invites (token_hash) WHERE token_hash <> '';

-- Vendor.Email (Phase 116): an optional on-file contact address, used to
-- auto-fill a session-share invite issued in this vendor's context. Unrelated
-- to username, which is the vendor's own login identity, not necessarily
-- reachable by mail.
ALTER TABLE vendors ADD COLUMN IF NOT EXISTS email TEXT NOT NULL DEFAULT '';
