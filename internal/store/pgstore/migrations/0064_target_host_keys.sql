-- Per-target SSH host keys, trust-on-first-use (Phase 272). The key a target
-- presented the first time the proxy reached it, kept so every later
-- connection is checked against it — WALLIX's "server pubkey store" with its
-- check modes (see PAM_SSH_HOST_KEY_CHECK). One row per target; deleting the
-- target deletes its pin, and an administrator resets a pin explicitly
-- (DELETE /api/targets/{id}/host-key, audited) when a host is re-keyed.
CREATE TABLE IF NOT EXISTS target_host_keys (
    target_id   BIGINT PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
    key_type    TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
);
