-- 0049: at most one ACTIVE agent key per name.
--
-- 2026-08-26 audit, M-3. The per-agent budget and the audit actor key on
-- agent_keys.name, but only token_hash was UNIQUE — so two keys could share a
-- name, pooling one usage count under two different budget_per_day limits, with
-- audit rows indistinguishable between them. A partial unique index (active
-- rows only) forbids that while preserving the legitimate rotation of revoking
-- a key and minting a fresh one with the same name: the revoked row has
-- disabled = TRUE and is excluded from the index. Mirrors the partial unique
-- index checkouts already use.
CREATE UNIQUE INDEX IF NOT EXISTS agent_keys_active_name_unique
    ON agent_keys (name)
    WHERE disabled = FALSE;
