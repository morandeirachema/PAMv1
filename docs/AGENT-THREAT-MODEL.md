# pamv1 — AI-agent access broker: threat model

> 🟢 **Living document** — updated in the same change as the broker code (see the [docs hub](README.md)).
>
> Last updated: 2026-08-14 · Reflects: Phases 0–126. Phases 58–94 change nothing in the agent trust model: Phase 67 added a read-only console view of the delegations this document describes, the Phase 91–94 adversarial review **confirmed the broker four-eyes path sound**, and the rest is certification, session-proxy, deploy and release work — including 116's live session-sharing, a human-to-human feature the `agent` role cannot reach (its two capabilities, `read_inventory` and `call_tool`, cover none of the new routes), 118's CIDR allowlist, which binds `store.User.IPAllowlist` on a bearer-token principal — a non-human `RoleAgent` is resolved from a SPIFFE SVID, not a `store.User` row, so it has no allowlist to be bound by and is unaffected either way — 120's recurring access requests, password policy and checkout extension, all human-to-human paths (`CapConnect`/`CapApprove`/`CapRevealSecret`) the agent role's two capabilities cannot reach either — 122's suspend/resume, gated on `CapApprove`, likewise a human-to-human decision the agent role has no path to — and 124's WebAuthn MFA, entirely a password-login-path feature: `RoleAgent` is resolved from a SPIFFE SVID via the broker, never through `POST /api/login`, so it has no second factor to satisfy and no `MFAPending` state it can ever occupy — and 126's portal color themes, a purely cosmetic, client-side console preference no agent identity ever renders and so cannot be affected by either.
>
> Scope: the **AI-agent access broker** (Phases 13, 27, 30, 38, 39, 40, 43, 52c, 52d) — `internal/broker`,
> `internal/policy`, `internal/agentid`, `internal/auditchain`, `internal/mcp`,
> and the `/v1/*` + `/mcp` surface. For the human/operator paths see
> [ARCHITECTURE-LOW-LEVEL.md](ARCHITECTURE-LOW-LEVEL.md).

## The core stance

> **Trust the chokepoint, not the agent.**

An agent is assumed to be **fallible or actively subverted** — by prompt
injection, a poisoned tool description, a compromised upstream model, or a
malicious operator of the agent. pamv1 never relies on the agent behaving well.
Instead every privileged action an agent can take is funnelled through one
server-side broker that:

1. holds **only** an identity key for the agent — never a target credential;
2. decides `allow / deny / require_approval` from **policy over the tool *and its
   arguments***, first-match-wins, default-deny;
3. executes an approved action **server-side**, injecting the credential
   just-in-time, and returns **only the result**; and
4. writes every step to a **keyed-HMAC hash-chained, ed25519-checkpointed** audit
   log.

The agent's compromise is therefore bounded by *what policy allows*, not by what
the agent decides to attempt.

## OWASP Top 10 for LLM Applications (2025) → broker controls

| # | Risk | How it reaches a privileged action | Broker control |
|---|---|---|---|
| **LLM01** | Prompt injection | A crafted prompt makes the agent call a dangerous tool / arguments | Policy is evaluated on the **tool + arguments** server-side; a call outside policy is denied regardless of what convinced the agent to make it. The agent never holds a credential to misuse directly. |
| **LLM02** | Sensitive information disclosure | Agent is coaxed into exfiltrating a secret | `reveal_credential` is **default-deny**; secret-bearing results are delivered **once** and never retained in the poll cache; for the exec tools the credential is injected inside `Execute` and never appears in the result; `reveal_credential` marks its result `Sensitive`, which strips it from the poll cache, from the approver's view and from `GET /v1/tool-calls/{id}` unconditionally — it reaches only the requesting agent, once, through the single-use resume token. |
| **LLM03** | Supply chain (poisoned model/tool) | A subverted model emits malicious tool calls | Same chokepoint: the tool registry is server-defined, not agent-defined; unknown tools are denied; the capability backstop requires the agent principal to actually hold the tool's capability, so policy YAML is never the sole gate. |
| **LLM04** | Data & model poisoning | — | Out of the broker's scope (it governs *actions*, not training data); noted so the boundary is explicit. |
| **LLM05** | Improper output handling | Downstream trusts the agent's output | The broker's output is a **structured result of a policy-approved action**, audited; it does not execute agent-authored code. |
| **LLM06** | Excessive agency | Agent granted broad standing capability | **Least privilege by construction**: `RoleAgent` may only call broker tools; per-rule `scope` templating narrows each grant to the exact resource; `require_approval` puts a **human in the loop** with separation of duties (Phase 27). |
| **LLM07** | System prompt leakage | — | No pamv1 secret lives in a prompt; bootstrap secrets are sourced server-side (SOPS/Conjur), never handed to an agent. |
| **LLM08** | Vector/embedding weaknesses | — | Out of scope (no RAG in the broker). |
| **LLM09** | Misinformation / overreliance | Operator over-trusts an agent's claim | The **verifiable audit chain** + signed checkpoints let a human independently confirm what actually executed, rather than trust a narrative. |
| **LLM10** | Unbounded consumption | Agent floods the broker | An **opt-in** per-agent rate limit (`PAM_BROKER_RATE_PER_MIN`, **`0` = off, which is the default**), an **argument-size cap** that *is* on by default (16 KiB), and a fixed **parked-approval cap** (1024, fail-closed, swept by TTL so stale entries cannot hold the budget) bound tool-call volume, payload size, and pending approvals. |

## MITRE ATLAS techniques → broker controls

| ATLAS technique | In this system | Broker control |
|---|---|---|
| **LLM Prompt Injection** (AML.T0051) | The primary threat: subverting the agent to act | Policy-over-arguments chokepoint; default-deny; no standing credential |
| **LLM Jailbreak** (AML.T0054) | Bypassing the agent's own guardrails | Irrelevant to authorization — the broker's gate is external to the model |
| **Gate parity** | Agent bypasses a gate a human obeys | Until Phase 52c, `reveal_credential` and `rotate_credential` checked target grants and stopped, while the human reveal path ran the full gate — so with `require_approval` set, a human needed an approved request and an agent permitted the tool got the plaintext at any hour, outside every window. The least-trusted actor had the weakest gate | Both now run `enforceApproval`, consuming an approved access request that honours four-eyes, the ITSM ticket and the maintenance window. A call parked by `require_approval` and then approved by a human executes as already-approved, so that decision satisfies the gate rather than demanding a second request |
| **Supervision** | Unsupervised long-running execution (excessive agency) | An agent's command ran outside the session registry — unlistable, unkillable, uncounted | Phase 40: every brokered execution goes through the same supervision as a human's. The concurrent-session cap is enforced **before** the just-in-time decrypt, and the run is registered — listed by `GET /api/sessions`, killable by `DELETE /api/sessions/{id}`, counted against `PAM_MAX_SESSIONS_PER_USER`/`_TOTAL`, and reachable by the analytics auto-response and the vendor sweeper |
| **Command control** | Dangerous command through `ssh_exec` | The deny policy lived in the proxy and the broker never consulted it | Phase 38: command control runs **before** the credential is fetched, refusing with the same `command.blocked` audit event an operator's `ssh target "cmd"` would produce. One policy, human and agent alike |
| **Valid Accounts / credential access** | Stealing the target credential the agent uses | The agent has **no** target credential; ZSP-style JIT injection; `reveal` default-deny |
| **Exfiltration via the model** | Reading a secret out through tool output | `Sensitive` results delivered once, never cached; injection stays inside `Execute` |
| **Erode ML model integrity / evade detection** | Tampering with the record of what happened | Keyed-HMAC chain + periodic ed25519 in-chain checkpoints + JWKS-published signer keys make edits and truncation detectable |

## Separation of duties & the human in the loop (Phase 27)

`require_approval` rules name **approver groups** (`approvers:`). A parked call is
executed only after a human who **belongs to one of those groups** approves it
(`internal/broker` `approverPermitted`), enforced at decision time — an approver
outside the group is refused (`broker.approval.refused`, HTTP 403) and the call
stays parked for someone authorized. Four-eyes still holds: the human who **owns**
the agent may not approve their own agent's call, and an administrator is the
documented superuser bypass (as everywhere in pamv1). A parked call is also
**re-validated at decision time** — an agent key revoked, or an SVID expired,
since parking is refused rather than executed on approval.

**MCP elicitation** (Phase 27) lets an elicitation-capable client's running user
be prompted over the SSE stream when their agent's call parks. Declining
**withdraws the requester's own** pending call (`broker.tool_call.withdrawn`) — it
needs no approver because you may always cancel what you asked for. Accepting only
records intent (`broker.elicit.accepted`); it **does not** satisfy the four-eyes
approver gate, because the running user is the requester, not an independent
approver.

## Audit integrity guarantees

- **Content edits / mid-history deletion** — caught by the keyed-HMAC recomputation
  (`Verify` → `broke_at_id`).
- **HMAC-key compromise** (attacker edits history *and* recomputes HMACs) — caught
  by the **ed25519 in-chain checkpoints**: the signed head no longer matches the
  recomputed running head (`VerifyFloor` → `bad_checkpoint`). The attacker cannot
  forge a signature without the ed25519 key.
- **Tail truncation** — caught by the **min-entries floor** (`?min_entries=N`, from
  a previously archived checkpoint count) and by the out-of-band signed head
  (`/v1/audit/head`).
- **Signing-key rotation** — the checkpoint signer can be rotated with an overlap
  window (`PAM_BROKER_AUDIT_SIGN_PREV`); both current and rotated-out public keys
  are published as a **JWKS** (`/v1/audit/jwks`) so an external verifier validates
  checkpoints across the rotation.
- **Key custody** — when `PAM_BROKER_AUDIT_KEY` / `PAM_BROKER_AUDIT_SIGN_SEED`
  are not set in the environment, both keys are generated once and held under
  shared custody: sealed by the vault KEK into the store's `key_material`, so
  they are never plaintext at rest, every replica converges on the same chain
  key and signer identity (a replica with its own key would make honest events
  read as tampering), and `-rotate-kek` re-wraps them with every other vaulted
  secret. An explicit environment value always wins **and is written through to
  the same custody**, so a mixed fleet or a later unset cannot fork the chain:
  an explicit HMAC key that disagrees with custody refuses to start, and an
  explicit sign seed that disagrees is the signer rotation — custody converges
  to it, so the replaced signer cannot silently return.
- **SIEM forwarding** — the trail exports as **OCSF** (`/api/audit/ocsf`, API
  Activity 6003 + Detection Finding 2004) for detection engineering off-box.


## Which controls are proven, and by what

Every mitigation this document claims is asserted by a test. That was not true
until 2026-07-28: three of the controls named above had **never executed** in the
test suite, which is a poor footing for a threat model.

| Control | Proven by |
|---|---|
| Delegated approver-group separation of duties (Phase 27) | `api.TestBrokerDelegatedApproverGroupGrants` — every other successful broker approval in the suite decides as the bootstrap admin, so `approverPermitted` short-circuits on `IsAdmin` and the group-matching loop had never once returned true |
| Capability backstop — policy YAML is never the sole gate | `broker.TestCapabilityBackstopDeniesWhatPolicyAllows`, on **both** the immediate and the post-approval path: a human approval must not confer a capability the agent does not hold |
| Withdrawal is limited to the requester | `broker.TestWithdrawRejectsForeignRequester` and `TestSameAgentIdentityMatching`, the latter pinning the case-folded **name fallback** used whenever an identity carries no static-key row id — which is every SVID-authenticated agent, i.e. the intended production posture |
| Fail-closed on an unavailable audit chain | `broker.TestProcessCallFailsClosedWhenAuditUnavailable` and its previously-missing twin `TestDecideFailsClosedWhenAuditUnavailable` |

Each was verified to **fail against the code with the control removed**, not
merely to pass with it present.

## Known boundaries (documented, not hidden)

- **Administrator bypass** — a built-in admin may approve any group and connect
  anywhere; SoD binds *delegated* approvers, not the superuser. This matches
  pamv1's model everywhere (break-glass, connect gates).
- **In-band truncation floor** — deleting the tail *and* every checkpoint after a
  point removes the in-chain evidence; the out-of-band signed head (archived by an
  auditor) is the backstop, as with any in-band scheme.
- **Deferred (infra-bound)** — SPIRE workload attestation needs a SPIRE
  deployment; see [EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md). RFC 8693
  token *exchange* (minting) was on this list and should not have been — no
  external STS is involved when the broker is the issuer; it **shipped in
  Phase 57** (`POST /v1/token`).
- **What a minted delegation is, and is not** — an exchanged token proves *who
  is acting for whom*, not *what they may do*: `scope` is refused, so every
  delegated call is still decided per call by policy over its arguments. The
  chain is bounded (`PAM_BROKER_MAX_DELEGATION_DEPTH`, enforced at mint as well
  as at ingress) and an exchange cannot erase the intermediary — impersonation
  is unsupported by design, because the accountable human at the end of the
  chain is the whole point of the audit record. A delegated token is a bearer
  credential for this broker for its (short, delegator-capped) lifetime: there
  is no revocation list for one, so the TTL is the containment.
