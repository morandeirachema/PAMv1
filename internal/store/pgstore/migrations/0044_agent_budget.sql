-- Cumulative per-agent call budget (Phase 167). Until now the only volume
-- control on an AI agent was an opt-in per-minute rate limit, which bounds a
-- burst but never a day: an agent capped at 60 calls/minute may still make
-- 86,400 privileged tool calls in 24 hours, and nobody ever chose that number
-- as a policy. A budget is the "how much, in total, over a day" limit a rate
-- limit cannot express.
--
-- Nullable on purpose, and NOT backfilled. Three states must stay
-- distinguishable, and each maps to a different decision at the enforcement
-- gate:
--
--   NULL  -- no per-agent setting; the server-wide default budget applies.
--   0     -- an explicit hard stop: this agent may make no calls at all.
--   > 0   -- that many brokered tool calls per day.
--
-- A DEFAULT 0 (or a backfill to 0) would silently convert every existing key
-- from "use the server default" into "forbidden", locking out every agent the
-- moment this migration ran. NULL is the value that means exactly what those
-- rows already meant before the column existed, so adding it changes nothing
-- for them -- the same reasoning 0043 used for expires_at.
--
-- No CHECK constraint: a negative budget is meaningless, but rejecting it here
-- and not in memstore would make the two backends disagree, and the contract
-- suite holds them to identical behaviour. Validation belongs at the API edge,
-- where a bad value can be reported to the caller.
ALTER TABLE agent_keys ADD COLUMN IF NOT EXISTS budget_per_day INT;

-- Supporting index for CountAgentToolCallsSince, which runs on the hot path:
-- every brokered tool call asks "how many has this agent already spent today?"
-- before deciding. That query filters audit_events on actor + action + ts, and
-- audit_events is the largest table in the system and only grows. The existing
-- indexes are on (ts) and (action) alone, neither of which is selective enough
-- here -- one agent's day of calls is a needle in the whole trail -- so without
-- this the budget check degrades into a scan of the entire audit history on
-- every call. Column order matches the query: equality columns first, the
-- range column last.
CREATE INDEX IF NOT EXISTS audit_events_actor_action_ts_idx
    ON audit_events (actor, action, ts);
