-- Phase 129: Zero Standing Privilege for database targets. A credential can
-- be marked as its target's provisioner — the real, stored, elevated
-- credential a db_zsp dial uses to CREATE/DROP the ephemeral role a session
-- actually connects as. Additive, defaults false, no behavior change for any
-- existing credential.
ALTER TABLE credentials ADD COLUMN is_provisioner BOOLEAN NOT NULL DEFAULT false;
