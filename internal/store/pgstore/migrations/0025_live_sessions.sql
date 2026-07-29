-- Phase 55: cross-replica live monitoring — the shared live-session inventory.
-- Each replica upserts the sessions it hosts (heartbeat-refreshed via seen_at);
-- listings filter on seen_at freshness so a crashed replica's rows age out
-- without any distributed cleanup.
--
-- UNLOGGED on purpose: the rows describe in-flight sessions and are rebuilt by
-- the heartbeats within seconds, so crash-losing them is correct (the sessions
-- died with their server) and skipping WAL keeps the per-session write cheap.
-- The same property means a physical standby promoted by failover starts with
-- the table empty — the next heartbeat round repopulates it.

CREATE UNLOGGED TABLE IF NOT EXISTS live_sessions (
    id       TEXT PRIMARY KEY,
    actor    TEXT NOT NULL,
    target   TEXT NOT NULL,
    protocol TEXT NOT NULL,
    remote   TEXT NOT NULL DEFAULT '',
    replica  TEXT NOT NULL,
    started  TIMESTAMPTZ NOT NULL,
    seen_at  TIMESTAMPTZ NOT NULL
);

-- A restarting replica deletes its own previous rows by this column.
CREATE INDEX IF NOT EXISTS live_sessions_replica_idx ON live_sessions (replica);
