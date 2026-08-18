-- Owner registry for SPIFFE-attested agent identities (Phase 170).
--
-- Two shipped controls are keyed on "who owns this agent", and both silently
-- no-opped for an agent authenticated by a SPIFFE JWT-SVID, because that
-- identity kind has no agent_keys row and therefore no owner column anywhere:
--
--   * Four-eyes approval refuses the human who owns an agent from approving
--     that agent's own parked tool call. The comparison is against
--     Identity.OnBehalfOf, which for an SVID is a SPIFFE ID and can never equal
--     a person's username — so the refusal could not fire, and the human
--     operating an agent could approve its privileged calls single-handed.
--   * Deleting a human suspends every agent key they owned (Phase 159's
--     offboarding cascade). With no key row there is nothing to suspend.
--
-- This table is what both read. It is an OWNER registry, not enrollment and not
-- attestation: recording an owner does not admit a workload (the trust domain
-- already did) and does not attest one (SPIRE workload attestation stays
-- infra-bound). It answers only "who do we hold responsible for this SPIFFE
-- ID", which is the question both controls were already asking.
--
-- spiffe_id is UNIQUE because one identity has exactly one accountable owner: a
-- second row would make "who is accountable" ambiguous at the precise moment it
-- must not be — the four-eyes decision. Reassignment is an UPDATE of owner, not
-- a delete plus insert, so created_at/created_by keep saying when the identity
-- was first registered and by whom.
--
-- No foreign key to users: an owner may legitimately be a team address or a
-- service account name that is not a pamv1 login, and the same free-text
-- looseness agent_keys.owner already has. The offboarding cascade matches on
-- the username string, exactly as ListAgentKeysByOwner does.
CREATE TABLE IF NOT EXISTS agent_identities (
    id         BIGSERIAL PRIMARY KEY,
    spiffe_id  TEXT NOT NULL UNIQUE,
    owner      TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The offboarding cascade asks "which identities does this person own?" on
-- every user deletion, and the four-eyes gate asks by spiffe_id (already
-- covered by the UNIQUE constraint's index) on every approval decision.
CREATE INDEX IF NOT EXISTS agent_identities_owner_idx ON agent_identities (owner);
