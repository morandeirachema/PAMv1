-- 0050: the compare-and-spend ledger behind the agent budget and the per-token
-- ceiling (Phase 219).
--
-- 2026-08-26 audit, M-3 (reservation half). Both limits were count-then-call
-- over audit_events: two calls arriving together each read the same count, both
-- passed, and the budget over-ran by the burst's width. A reservation row is
-- written HERE, under a per-agent advisory lock, at the instant the decision is
-- made, and deleted again if the call then did no work — so the count the gate
-- compares against and the row it adds are one decision. audit_events stays the
-- record an operator reads; this table is only what the gate serialises on, and
-- a row older than the rolling window is purged by the next reservation for
-- that agent, so it never holds more than one window per agent.
CREATE TABLE IF NOT EXISTS agent_call_reservations (
    id       BIGSERIAL PRIMARY KEY,
    agent    TEXT NOT NULL,
    token_id TEXT NOT NULL DEFAULT '',
    ts       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS agent_call_reservations_agent_ts_idx
    ON agent_call_reservations (agent, ts);
