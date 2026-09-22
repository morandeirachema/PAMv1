-- Sub-protocol rights (Phase 270): what a session may do inside the protocol
-- it was admitted to — shell, exec, sftp, port forwarding, X11 on SSH; drive,
-- printer, audio in/out on RDP. A target's set narrows the deployment's
-- switches for everyone; a grant's set narrows the target's for its subject.
-- Empty — every row before this migration — is "no narrowing here", so no
-- existing session gains or loses anything when this runs.
ALTER TABLE targets ADD COLUMN IF NOT EXISTS rights TEXT NOT NULL DEFAULT '';
ALTER TABLE target_grants ADD COLUMN IF NOT EXISTS rights TEXT NOT NULL DEFAULT '';
