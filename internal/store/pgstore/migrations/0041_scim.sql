-- SCIM 2.0 user provisioning (Phase 149): push-based IdP provisioning to
-- complement the existing pull-based POST /api/identity/reconcile.

-- external_id is the IdP's own correlation key for a user (SCIM's
-- "externalId"), distinct from username. Empty default so every existing
-- row is unaffected; the partial unique index below leaves any number of
-- rows sharing the empty default alone while still refusing two SCIM-managed
-- users to claim the same non-empty externalId.
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_id TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS users_external_id_idx ON users (external_id) WHERE external_id <> '';

-- active is SCIM's deprovisioning switch: false blocks this user's own local
-- token from resolving (see auth.Resolver.Resolve) without deleting the row,
-- so a re-enable (or a delete-and-recreate at the IdP) restores access
-- without re-minting a token. Defaults true so every existing user's access
-- is completely unchanged by this migration.
ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT true;

-- SCIM client identity keys: bearer keys (only the SHA-256 hash is stored),
-- the same shape as agent_keys/app_keys — a non-human identity narrowly
-- scoped to the /scim/v2/Users surface, never a human's own capability set.
CREATE TABLE IF NOT EXISTS scim_keys (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    owner      TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL UNIQUE,
    disabled   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
