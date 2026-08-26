-- Operator-issued SSH certificates (Phase 28): pamv1 signs an operator's own
-- public key into a short-lived certificate scoped to a target account. The row
-- is the revocation handle — a KRL revoking `serial` is published for targets,
-- and a revoked cert is cut off before it expires.
--   serial:       the certificate serial (unique per issue; fits int64)
--   revoked_at:   NULL until revoked; a revoked serial goes into the KRL
CREATE TABLE IF NOT EXISTS ssh_certificates (
    id           BIGSERIAL PRIMARY KEY,
    serial       BIGINT NOT NULL UNIQUE,
    key_id       TEXT NOT NULL DEFAULT '',
    principal    TEXT NOT NULL DEFAULT '',
    actor        TEXT NOT NULL DEFAULT '',
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_before TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    revoked_by   TEXT NOT NULL DEFAULT ''
);

-- The KRL query lists only revoked serials, so index the revoked subset.
CREATE INDEX IF NOT EXISTS ssh_certificates_revoked_idx
    ON ssh_certificates (serial) WHERE revoked_at IS NOT NULL;
