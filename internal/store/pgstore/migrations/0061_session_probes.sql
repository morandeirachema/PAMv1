-- Session probes (Phase 266): a second KIND of endpoint agent. A tunnel
-- (Phase 153) holds a reverse forward for a target pamv1 cannot dial; a
-- probe runs INSIDE an operator's logon session on a Windows target, with
-- that user's own token, and reports the session's processes and network
-- connections — enforcing the block rules below by terminating what they
-- match. The two never mix on one connection, so the "one live agent per
-- target" index becomes one per (target, kind): a target may carry both.
ALTER TABLE endpoint_agents ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'tunnel';
DROP INDEX IF EXISTS endpoint_agents_one_live_per_target;
CREATE UNIQUE INDEX IF NOT EXISTS endpoint_agents_one_live_per_target_kind
    ON endpoint_agents (target_id, kind) WHERE revoked_at IS NULL;

-- The rules a probe enforces. target_id NULL = every probed target. A
-- process rule matches an image name/path glob; a connection rule matches a
-- remote address (IP or CIDR; '' = any), port (0 = any) and protocol ('' =
-- either). Deleting the target deletes its rules; global rules stay.
CREATE TABLE IF NOT EXISTS probe_rules (
    id         BIGSERIAL PRIMARY KEY,
    target_id  BIGINT REFERENCES targets(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('process', 'connection')),
    match      TEXT NOT NULL DEFAULT '',
    port       INTEGER NOT NULL DEFAULT 0,
    proto      TEXT NOT NULL DEFAULT '',
    note       TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
