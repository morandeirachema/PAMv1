-- Outbound-only endpoint agents (Phase 153, BeyondTrust "Jump Client"-style):
-- an agent installed on a target pamv1 cannot dial into dials OUT to the SSH
-- listener with a bearer key (only its SHA-256 hash is stored, the same shape
-- as agent_keys/app_keys/scim_keys) and holds a reverse tunnel open; the
-- proxy then reaches that target through the tunnel instead of Target.Host.
--
-- Exactly one unrevoked agent per target: the partial unique index lets any
-- number of revoked rows accumulate as history while refusing a second live
-- binding, since "which agent do I tunnel through" must never be ambiguous.
-- Deleting the target cascades — an agent row without its target is
-- meaningless (it authenticates only to reach that one target).
CREATE TABLE IF NOT EXISTS endpoint_agents (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    target_id  BIGINT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    key_hash   TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS endpoint_agents_one_live_per_target
    ON endpoint_agents (target_id) WHERE revoked_at IS NULL;
