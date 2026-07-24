# pamv1 — AI-agent access broker: threat model

> 🟢 **Living document** — updated in the same change as the broker code (see the [docs hub](README.md)).
>
> Scope: the **AI-agent access broker** (Phases 13, 27) — `internal/broker`,
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
| **LLM02** | Sensitive information disclosure | Agent is coaxed into exfiltrating a secret | `reveal_credential` is **default-deny**; secret-bearing results are delivered **once** and never retained in the poll cache; the credential is injected inside `Execute` and never serialized back to the agent (`Result.Sensitive`). |
| **LLM03** | Supply chain (poisoned model/tool) | A subverted model emits malicious tool calls | Same chokepoint: the tool registry is server-defined, not agent-defined; unknown tools are denied; the capability backstop requires the agent principal to actually hold the tool's capability, so policy YAML is never the sole gate. |
| **LLM04** | Data & model poisoning | — | Out of the broker's scope (it governs *actions*, not training data); noted so the boundary is explicit. |
| **LLM05** | Improper output handling | Downstream trusts the agent's output | The broker's output is a **structured result of a policy-approved action**, audited; it does not execute agent-authored code. |
| **LLM06** | Excessive agency | Agent granted broad standing capability | **Least privilege by construction**: `RoleAgent` may only call broker tools; per-rule `scope` templating narrows each grant to the exact resource; `require_approval` puts a **human in the loop** with separation of duties (Phase 27). |
| **LLM07** | System prompt leakage | — | No pamv1 secret lives in a prompt; bootstrap secrets are sourced server-side (SOPS/Conjur), never handed to an agent. |
| **LLM08** | Vector/embedding weaknesses | — | Out of scope (no RAG in the broker). |
| **LLM09** | Misinformation / overreliance | Operator over-trusts an agent's claim | The **verifiable audit chain** + signed checkpoints let a human independently confirm what actually executed, rather than trust a narrative. |
| **LLM10** | Unbounded consumption | Agent floods the broker | **Per-agent rate limits**, an **argument-size cap**, and a **parked-approval cap** (fail-closed) bound tool-call volume, payload size, and pending approvals. |

## MITRE ATLAS techniques → broker controls

| ATLAS technique | In this system | Broker control |
|---|---|---|
| **LLM Prompt Injection** (AML.T0051) | The primary threat: subverting the agent to act | Policy-over-arguments chokepoint; default-deny; no standing credential |
| **LLM Jailbreak** (AML.T0054) | Bypassing the agent's own guardrails | Irrelevant to authorization — the broker's gate is external to the model |
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
- **SIEM forwarding** — the trail exports as **OCSF** (`/api/audit/ocsf`, API
  Activity 6003 + Detection Finding 2004) for detection engineering off-box.

## Known boundaries (documented, not hidden)

- **Administrator bypass** — a built-in admin may approve any group and connect
  anywhere; SoD binds *delegated* approvers, not the superuser. This matches
  pamv1's model everywhere (break-glass, connect gates).
- **In-band truncation floor** — deleting the tail *and* every checkpoint after a
  point removes the in-chain evidence; the out-of-band signed head (archived by an
  auditor) is the backstop, as with any in-band scheme.
- **Deferred (infra-bound)** — SPIRE workload attestation and RFC 8693 token
  *exchange* (minting) need an STS/SPIRE deployment; see
  [EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md).
