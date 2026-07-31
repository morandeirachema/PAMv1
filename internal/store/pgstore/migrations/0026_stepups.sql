-- Phase 56: cross-replica step-up decisions — the shared pending-pause
-- inventory. A paused statement blocks in the memory of the replica hosting the
-- session; each Await mirrors it here so every replica's pending list shows it,
-- and deletes the row when the pause is claimed (decision or timeout). Rows a
-- crashed replica leaves behind fall out of listings at expires_at — exactly
-- when the pause they mirrored would have timed out.
--
-- The statement column carries CIPHERTEXT: the session layer seals it under the
-- cluster's shared-custody bus key (bound to id/actor/replica as AAD), so a
-- database observer reads nothing and a fabricated row fails to open and is
-- never shown to a supervisor.
--
-- UNLOGGED for the same reason as live_sessions: the rows describe in-flight
-- pauses whose real state lives in a replica's memory; crash-losing them is
-- correct, and a promoted standby starts empty until the next pause.

CREATE UNLOGGED TABLE IF NOT EXISTS stepups (
    id         TEXT PRIMARY KEY,
    actor      TEXT NOT NULL DEFAULT '',
    statement  TEXT NOT NULL DEFAULT '',
    replica    TEXT NOT NULL DEFAULT '',
    requested  TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
