-- Per-subject restriction rules (Phase 275): what a user or role may not do
-- inside a session, per sub-protocol — WALLIX's user-group Restrictions tab.
-- A pattern is a regular expression over the command (ssh_exec, winrm, sql,
-- kubernetes, or '*' for every one) or, on sftp, a size rule:
-- '$filesize:>10m' (an upload larger than that) / '$downsize:>100m' (a
-- download larger than that). action: kill ends the session (or refuses the
-- call where there is no session), notify audits the match and lets it
-- through. Rules add up across a user's roles.
CREATE TABLE IF NOT EXISTS restriction_rules (
    id           BIGSERIAL PRIMARY KEY,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('user', 'role')),
    subject      TEXT NOT NULL,
    subprotocol  TEXT NOT NULL DEFAULT '*',
    pattern      TEXT NOT NULL,
    action       TEXT NOT NULL DEFAULT 'kill' CHECK (action IN ('kill', 'notify')),
    note         TEXT NOT NULL DEFAULT '',
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS restriction_rules_subject_idx ON restriction_rules (subject_type, subject);
