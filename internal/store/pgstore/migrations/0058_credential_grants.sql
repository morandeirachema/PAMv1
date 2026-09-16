-- Credential-level grants (Phase 252 - CyberArk's object-level access
-- control). A target grant may name ONE credential on its target; the subject
-- may then use or retrieve that credential and no other. NULL is the whole
-- target, which is every grant that predates this migration, so no existing
-- access changes.
--
-- Uniqueness widens to the scope: a whole-target grant and a scoped one for
-- the same subject are different rows, as are two scoped to different
-- credentials. The original inline constraint is replaced by an expression
-- index so that "NULL credential" is one value rather than a distinct one per
-- row - a plain UNIQUE over a nullable column would let the same subject be
-- granted the whole target twice.
ALTER TABLE target_grants ADD COLUMN IF NOT EXISTS credential_id BIGINT REFERENCES credentials (id) ON DELETE CASCADE;
ALTER TABLE target_grants DROP CONSTRAINT IF EXISTS target_grants_target_id_subject_type_subject_key;
CREATE UNIQUE INDEX IF NOT EXISTS target_grants_scope_unique_idx
    ON target_grants (target_id, subject_type, subject, COALESCE(credential_id, 0));
CREATE INDEX IF NOT EXISTS target_grants_credential_idx ON target_grants (credential_id) WHERE credential_id IS NOT NULL;
