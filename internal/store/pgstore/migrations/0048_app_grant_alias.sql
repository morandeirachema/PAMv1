-- Phase 197: a stable name for an application's secret grant.
--
-- The application-secrets API addressed a secret by its credential ROW ID
-- (`GET /v1/app-secrets/{id}`). That is fine for a script that just looked the id
-- up, and wrong for anything declarative: a BIGSERIAL is not stable across
-- environments, across a restore, or across deleting and re-creating a
-- credential — and an External Secrets Operator SecretStore puts that identifier
-- in a manifest that lives in git.
--
-- The alias goes on the GRANT rather than on the credential, for three reasons.
-- The grant must exist for the app to read the secret at all, so naming it adds
-- no authorization surface — only a name for one that is already there. It is
-- scoped per app, so two applications may call the same credential different
-- things and neither can collide with the other. And `credentials` has no
-- uniqueness on (target_id, username), so there is no safe credential-side name
-- to use instead.
--
-- Nullable, so every existing grant keeps working unchanged and addressing by id
-- continues to work. The partial unique index applies only where an alias is
-- actually set.
ALTER TABLE app_secret_grants ADD COLUMN IF NOT EXISTS alias TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS app_secret_grants_alias_key
    ON app_secret_grants (app_id, alias) WHERE alias IS NOT NULL;
