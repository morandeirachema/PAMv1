-- Shared custody of long-lived key material (Phase 42). The SSH proxy host key
-- and the Zero Standing Privilege CA key were persisted to a LOCAL FILE, so in a
-- multi-replica deployment every pod generated its own: operators saw host-key
-- changes that look like a MITM, a certificate minted by one pod was not trusted
-- by targets configured with another pod's CA, and the operator-certificate
-- challenge (an HMAC keyed off the CA private key) failed across pods.
--
-- Custody moves here. The value is the vault envelope of the PEM — the database
-- never holds usable key material, exactly like credentials — and the primary key
-- makes the claim atomic: N replicas starting simultaneously all attempt an
-- insert, exactly one wins, and the losers read back the winner's key. That
-- convergence is the whole point of the table.
CREATE TABLE IF NOT EXISTS key_material (
    name       TEXT PRIMARY KEY,
    value      TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
