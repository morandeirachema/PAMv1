-- AI-agent identity lifecycle (Phase 159). Until now an agent_keys row could
-- only be created or destroyed: the `disabled` column existed and was honoured
-- on read, but nothing could ever set it, and a key had no end date and no
-- record of use — an immortal standing bearer credential that no report could
-- flag as dormant. These two additive columns close that.
--
-- expires_at NULL means "never expires", which is exactly the behaviour every
-- existing row already had, so adding the column changes nothing for them.
-- last_used_at is stamped on each successful agent authentication; NULL means
-- "not used since this column existed", which a dormant-credential review
-- reads the same way as "never used".
ALTER TABLE agent_keys ADD COLUMN IF NOT EXISTS expires_at   TIMESTAMPTZ;
ALTER TABLE agent_keys ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;

-- Quarantine: the local stop-switch on one agent identity.
--
-- Deliberately its own table keyed by a free-form subject, NOT a boolean
-- column on agent_keys, because the set of agents PAMv1 authenticates is
-- larger than the set of rows in agent_keys: an SVID-authenticated agent
-- proves its identity through the SPIFFE workload API and never received a key
-- from us, so it has no agent_keys row to flag. Keying on the canonical
-- identity name — the agent-key name for a static key, the full SPIFFE ID for
-- an SVID — gives one containment control that covers every authentication
-- path. It also means an agent can be quarantined pre-emptively, before any
-- key for that name exists, and that lifting quarantine (a DELETE) leaves the
-- agent_keys row and its own disabled/expiry state untouched: two independent
-- controls, neither overwriting the other.
--
-- subject is UNIQUE so quarantine is set membership: a duplicate insert is a
-- conflict the store surfaces as ErrConflict rather than silently stacking
-- rows that would then need reference counting to release correctly.
CREATE TABLE IF NOT EXISTS agent_quarantine (
    id         BIGSERIAL PRIMARY KEY,
    subject    TEXT NOT NULL UNIQUE,
    reason     TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
