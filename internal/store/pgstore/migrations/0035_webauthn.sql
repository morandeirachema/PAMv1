-- Phase 124: FIDO2/WebAuthn passwordless MFA. A user may register more than
-- one authenticator, so unlike mfa_enrollments (username PRIMARY KEY),
-- credentials get their own surrogate id and username is a lookup column.
-- public_key is NOT vault-encrypted, deliberately: it is a public key, not a
-- shared secret like mfa_enrollments.secret_enc.

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id                 BIGSERIAL PRIMARY KEY,
    username           TEXT NOT NULL,
    credential_id      BYTEA NOT NULL,
    public_key         BYTEA NOT NULL,
    attestation_type   TEXT NOT NULL DEFAULT '',
    attestation_format TEXT NOT NULL DEFAULT '',
    transports         TEXT NOT NULL DEFAULT '',
    aaguid             BYTEA,
    sign_count         BIGINT NOT NULL DEFAULT 0,
    clone_warning      BOOLEAN NOT NULL DEFAULT false,
    name               TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at       TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS webauthn_credentials_credential_id_key ON webauthn_credentials (credential_id);
CREATE INDEX IF NOT EXISTS webauthn_credentials_username_idx ON webauthn_credentials (username);

-- Ephemeral ceremony state between the browser's two-step exchange
-- (navigator.credentials.create/.get), the same atomic
-- put/take-with-expiry shape as oidc_states. purpose is "register" or
-- "login"; a fresh Begin for the same (username, purpose) simply supersedes
-- an abandoned one, so no cleanup job is needed beyond the expiry check.
CREATE TABLE IF NOT EXISTS mfa_webauthn_challenges (
    username     TEXT NOT NULL,
    purpose      TEXT NOT NULL,
    session_data BYTEA NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (username, purpose)
);

CREATE INDEX IF NOT EXISTS mfa_webauthn_challenges_expiry_idx ON mfa_webauthn_challenges (expires_at);
