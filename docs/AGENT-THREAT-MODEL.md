# pamv1 — AI-agent access broker: threat model

> 🟢 **Living document** — updated in the same change as the broker code (see the [docs hub](README.md)).
>
> Last updated: 2026-08-21 · Reflects: Phases 0–185. Phases 58–94 change nothing in the agent trust model: Phase 67 added a read-only console view of the delegations this document describes, the Phase 91–94 adversarial review **confirmed the broker four-eyes path sound**, and the rest is certification, session-proxy, deploy and release work — including 116's live session-sharing, a human-to-human feature the `agent` role cannot reach (its two capabilities, `read_inventory` and `call_tool`, cover none of the new routes), 118's CIDR allowlist, which binds `store.User.IPAllowlist` on a bearer-token principal — a non-human `RoleAgent` is resolved from a SPIFFE SVID, not a `store.User` row, so it has no allowlist to be bound by and is unaffected either way — 120's recurring access requests, password policy and checkout extension, all human-to-human paths (`CapConnect`/`CapApprove`/`CapRevealSecret`) the agent role's two capabilities cannot reach either — 122's suspend/resume, gated on `CapApprove`, likewise a human-to-human decision the agent role has no path to — and 124's WebAuthn MFA, entirely a password-login-path feature: `RoleAgent` is resolved from a SPIFFE SVID via the broker, never through `POST /api/login`, so it has no second factor to satisfy and no `MFAPending` state it can ever occupy — and 126's portal color themes, a purely cosmetic, client-side console preference no agent identity ever renders and so cannot be affected by either — and 128's account discovery, gated on `manage_targets`, a capability `RoleAgent`'s fixed two-capability set (`read_inventory`, `call_tool`) does not include, so the route is unreachable through the broker regardless — and 129's Zero Standing Privilege for PostgreSQL, reached only through the existing `:5433` proxy's `CapConnect` gate, a capability `RoleAgent` likewise lacks; the broker's own database access (where it exists at all) goes through the tool-call model's typed arguments, never a raw proxy connection, so an agent identity has no path to a db_zsp credential either way — and 131's command allow-listing is the one item in this stretch that *does* reach the agent path: the broker's `ssh_exec`/`winrm_exec` tools share the exact same `cmdguard` call sites human sessions use, so a configured `PAM_COMMAND_ALLOW_FILE` constrains agent-issued commands exactly as it does an operator's; no new capability and no change to the broker's four-eyes or typed-argument model, just a stricter existing gate both paths already shared — and 133's device-aware access control is, unlike 131, entirely unreachable by an agent identity, not by an explicit exemption but structurally: the new live-posture gate sits in `gates.go`'s `admit()` and the REST `authz` middleware, and the broker's `ssh_exec`/`winrm_exec` tools run over `rotate.SSHConnector`, a separate one-shot execution path that never calls `admit()` at all, while an agent authenticates through `agentAuth`, never `authz`; the device-identity binding is REST-only by design and gated the same way. So a `PAM_POSTURE_ATTEST_URL` or `PAM_DEVICE_HEADER` deployment constrains only human operator sessions, never a broker tool call — worth stating plainly, since 131 just established the precedent that a command-control gate CAN reach the agent path, and this phase's two gates are the exception to that, not the rule — and 135's DoubleLock is back to the rule, not the exception: `POST`/`DELETE /api/credentials/{id}/doublelock` and the reveal/checkout paths it gates all require `CapRevealSecret`, which is not in `RoleAgent`'s fixed two-capability set (`read_inventory`, `call_tool`) either, so a DoubleLocked credential is exactly as unreachable to an agent identity as any other credential's reveal always was — no new exposure, no new exemption to reason about — and 137's magic-link approval and session watermarking are both unreachable too, for two separate reasons rather than one shared one: creating an `ApprovalInvite` requires `CapApprove`, absent from `RoleAgent`'s fixed two-capability set, and the whole access-request approve/deny workflow it delegates is human-to-human in the same way 120's and 122's already were, so a broker identity was never a party to it to begin with, delegable or not; and the watermark banner is published via `p.live.Publish(sid, ...)` immediately after a session is registered in `p.sessions`, but the broker's `ssh_exec`/`winrm_exec` tools run over `rotate.SSHConnector`, the same one-shot path 133 already established never calls `admit()` or registers a live session at all — so no `sid` is ever minted for a broker-run command, and there is no session for a watermark to attach to in the first place, not an exemption carved out for it — and 139's personal safes reach the broker's own connect/reveal paths (`authorizeAgentTarget`/`authorizeAgentCredential` both compute `EffectiveSafePersonal` and pass it to `CanConnectTarget`, for correctness — an agent must be default-deny on a personal safe like anyone else), but the new override capability can never actually fire there: `RoleAgent`'s fixed two-capability set (`read_inventory`, `call_tool`) does not and cannot include `unlimited_vault_access`, deliberately absent from every built-in role's matrix, and an agent identity is never assigned a custom profile. So a personal safe is exactly as reachable to an agent as any other safe it isn't a member of — never — and the loud `safe.personal_override_used` audit can likewise never fire for an agent actor — and 141's port-forwarding is unreachable for a reason simpler than any capability check: `direct-tcpip` channels are only ever read from `handleConn`'s channel-accept loop, which exists only for a real, multiplexed SSH client connection to the `:2222` proxy — the shape an interactive operator's `ssh` client presents, never the broker's `ssh_exec`/`winrm_exec` tools, which run over `rotate.SSHConnector`'s separate one-shot connector and never hold an SSH channel an agent identity could request `direct-tcpip` on in the first place. There is no gate to bypass because there is no channel loop for a broker call to ever reach. **143's ICAP file-transfer scanning is unreachable for the same underlying reason 141's port-forwarding and 137's watermarking already established, not a new one**: `newSFTPCapture` — and the `icapClient` it now optionally carries — is constructed exactly once, inside `handleSession`, only when a channel's requested subsystem is `sftp`; the broker's `ssh_exec`/`winrm_exec` tools run over `rotate.SSHConnector`'s separate one-shot connector, which never opens an interactive session channel, never requests the `sftp` subsystem, and so never constructs a `sftpCapture` value at all. There is no file-transfer surface for ICAP to scan because there is no SFTP subsystem for a broker call to ever open — an agent's typed tool arguments are not file bytes flowing through a wire-negotiated subsystem, so `PAM_ICAP_URL` constrains only a human operator's interactive SFTP session, exactly as `PAM_SSH_SFTP_CAPTURE` already did before it. **145's file-attachment secrets introduce no new agent exposure, in either direction.** Creating one is unreachable: `POST /api/credentials` requires `CapManageCredentials`, absent from `RoleAgent`'s fixed two-capability set, and none of the broker's six tools (`list_targets`, `list_credentials`, `reveal_credential`, `rotate_credential`, `ssh_exec`, `winrm_exec`) wraps credential creation — an agent cannot provision a `file`-type credential, or any other kind. Reading one, once a human has created it, goes through the exact same two paths every other secret type already does: `list_credentials` now calls the new `ListCredentialsMeta` specifically, which cannot return `SecretEnc` even in principle (the query never selects the column) — a small, welcome hardening of a path this document already treated as metadata-only, not a behavior change; `reveal_credential` can return a file secret's raw content exactly as it already could a password's, gated by the same default-deny broker policy and `PAM_REVEAL_DISABLED` this document already covers for every secret type. Nothing about `secret_type: "file"` changes which tool an agent can call or what either tool is authorized to return. **147's browser-extension autofill is unreachable by an agent identity, back to the rule 135 already established, not a new exception**: minting `POST /api/extension-token` requires `CapRevealSecret`, absent from `RoleAgent`'s fixed two-capability set (`read_inventory`, `call_tool`) — and even setting that aside, the `ExtensionOnly` flag it produces is read off `Resolve()`'s ordinary session-token row, the identical path `SessionScopeRDP`/`VNC`/`MFAPending` already use and `RoleAgent` has never once entered, since a broker identity authenticates exclusively through `agentAuth`/SPIFFE SVID. The reveal route's new `authzExtOK` exception exists for exactly one bearer-token shape a broker identity can never hold — no new exposure, no new exemption to reason about. **149's SCIM 2.0 user provisioning is unreachable by an agent identity, structurally, the same way 133/141/143 already established**: `/scim/v2/Users` authenticates through the new `scimAuth`, which resolves a `*store.ScimKey`, never an `auth.Principal` and never `agentAuth`/SPIFFE SVID — there is no mechanism by which a `RoleAgent` identity could hold or present a SCIM key in the first place, since the two identity kinds are unrelated bearer-key types authenticated on entirely separate code paths. The admin key-management routes (`/v1/scim-keys`) need `CapManageUsers` too, absent from `RoleAgent`'s fixed two-capability set regardless. No new exposure in either direction. **151's SAML login is likewise unreachable by an agent identity**: it is a browser SSO flow that ends in `issueSession` for a human principal mapped from IdP group claims via `MatchedRoles` — `RoleAgent` is never one of the four mapped roles, and an agent authenticates through the broker's SVID path, never through `/api/auth/saml/*`; the three new routes are public rate-limited login endpoints, not tools, so the broker's typed tool-call model never sees them. No new exposure in either direction. **153's outbound-only endpoint agents are a different thing with a similar name, and unreachable by an AI agent identity too**: `store.EndpointAgent` is a tunnel-holding piece of infrastructure authenticated by its own bearer key on the SSH listener (`endpoint-agent:<name>`), never an `auth.Principal`, with no capability set — an AI `RoleAgent` cannot mint one (`POST /api/endpoint-agents` needs `manage_targets`, absent from its fixed two-capability set) and cannot present one (the login form is refused for anything but an endpoint-agent key). Conversely an endpoint agent's connection can open no channel and call no tool: it only carries streams pamv1 opens toward it. The one thing the broker's `ssh_exec` tool gains is transparent: a target bound to an endpoint agent is dialed through the tunnel by the same `dialUpstream`, with the same gates — no new exposure in either direction. **155's Kubernetes brokering is deliberately NOT exposed as a broker tool**: `POST /api/targets/{id}/kubectl` is gated on `CapConnect`, which `RoleAgent`'s fixed two-capability set (`read_inventory`, `call_tool`) does not include, and no `kubectl` tool exists in the broker's toolset — so an AI agent cannot reach a cluster through pamv1 at all. That is a scope decision, not an oversight: a tool whose argument is a manifest would need policy over arbitrary YAML, which `internal/policy`'s typed-argument model does not express today. **157 changes nothing for an agent identity either**: the post-session reconstruction fires only for INTERACTIVE SSH sessions through the proxy, which a `RoleAgent` cannot open (it holds `read_inventory` and `call_tool`, never `connect`); the broker's own `ssh_exec` tool already audits every discrete command it runs, so it has no PTY blind spot to reconstruct. If anything, the phase narrows the agent story's asymmetry: a human's obfuscated shell command now leaves the same kind of structured record an agent's typed tool call always did. **161 is the first phase to change what
the broker WRITES rather than what it allows**: the primary audit trail now
records a tool call's outcome in the action name and carries the run-correlation
fields, which is why the two sections below are new. **163 then changed what the broker
ALLOWS**, and found the batch's sharpest defect: a policy guard that could be
defeated by sending less data. **169 is about the DELEGATED path specifically**:
quarantine now follows a token's whole actor chain rather than stopping at
whoever presented it, and the two inventory tools answer for the targets the
calling agent may reach instead of for the whole estate. **170 stays on that
path and gives it an owner** — the fact four-eyes and offboarding were both
silently missing for an attested agent. **171 then makes the policy file's two
grant-shaped fields tell the truth**: `ttl_seconds` bounds a real approval
window, and `scope` is documented as the audit label it always was. **173 gives
policy a principal side** — until then a rule could say what, never who, and any
identity a condition matched was one the agent asserted itself.
>
> Scope: the **AI-agent access broker** (Phases 13, 27, 30, 38, 39, 40, 43, 52c, 52d, 159, 161, 163, 165, 167) — `internal/broker`,
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


## Containing an agent already in flight (Phase 159)

Everything above decides whether a *call* is allowed. This section is about the
identity itself, and it exists because a 2026-08-17 research pass over this very
subsystem found the answer to "an agent is misbehaving, stop it" was weaker than
this document implied.

**What was wrong.** `store.AgentKey.Disabled` was honoured on read by both store
backends — and nothing could set it: creation hardcoded `false` and no update
method existed. The only lever was deleting the key, which destroys the row an
investigation needs and silently invalidates whatever that agent had parked
awaiting approval. And `revalidateAgent` consulted the store only when
`KeyID > 0`, which an **SVID identity never is** — so in the posture this
document calls the intended production one, containment was "wait for the SVID
to expire".

**What holds now.**

| Question | Control |
|---|---|
| Pause one agent, reversibly | `POST /v1/agents/{id}/disable` / `/enable` (`manage_users`), audited `agent.disable`/`agent.enable` |
| Stop an agent that has no key row (SVID) | `POST /v1/agents/quarantine` on its **subject** — the agent-key name for a static key, the **full SPIFFE ID** for an SVID, because `Identity.AgentName` *is* the SPIFFE ID there |
| Stop what is already parked | both checks run again in `revalidateAgent` at approval time, so a suspended, expired or quarantined agent cannot have a held call approved for it later |
| Stop the sub-agents a compromised agent already delegated to (Phase 169) | the quarantine check follows the presented token's **whole RFC 8693 actor chain**, not just its subject, at both moments an identity is consulted — ingress (`agentAuth`) and approval-time revalidation. Quarantining a root stops every token minted from it, and the refusal names the chain member that did the stopping (`agent.quarantine_refused … subject:<root>`) |
| Age out a forgotten identity | `expires_in_days` at creation, enforced in `StaticVerifier.Verify` and carried as `Identity.ExpiresAt` so the SVID-shaped expiry logic covers static keys too |
| Notice a dormant identity | `last_used_at`, stamped best-effort on every successful authentication (never blocking one) |
| The owner left | deleting the human suspends every agent key they owned, audited `reason:owner-offboarded` — and, since Phase 170, **quarantines every SPIFFE identity they owned**, which is the only stop an attested agent has |
| Know who to hold responsible for an attested agent (Phase 170) | `POST /v1/agents/identities` records the accountable human for a SPIFFE ID (`manage_users`, console menu 26 → **F8**). Not attestation: it admits nothing and proves nothing, it names somebody |
| Know which attested identities exist at all (Phase 174) | pamv1 records every SVID that authenticates — an unowned **seen** row, first/last sighting stamps, audited once — so the inventory is what calls, not what somebody typed |
| Review whether a non-human identity should still exist (Phase 175) | certification campaigns snapshot agent keys and SPIFFE identities as items of their own (`SubjectType "agent"`), with owner, state and dormancy; revoking one **suspends** a key or **quarantines** an attested subject rather than deleting it |
| See, as the approver, how many hands a call passed through (Phase 183) | `GET /v1/approvals` carries `actor_chain` and console menu 20 shows a HOPS column — a direct call and one delegated three times no longer look identical to the human deciding |
| Join a minted delegated token to the calls made with it (Phase 183) | the presented token's `jti` is parsed and recorded as `svid_jti:` on every brokered call, matching the `jti:` `broker.token.exchanged` has carried since Phase 161 |
| Pin who a delegated token may be handed to next (Phase 181) | the delegator passes `may_act` on the exchange; the issued token carries the RFC 8693 §4.4 claim and the next exchange refuses anyone it does not name. Bounded to eight in-domain parties, never the subject itself, and recorded on `broker.token.exchanged` |
| Require the agent's workload to be healthy, not just authenticated (Phase 180) | `PAM_BROKER_POSTURE_REQUIRED` extends the existing posture webhook to agent identities, checked last among the admission gates so a stopped identity never reaches it. Refusals audit `agent.posture_denied`. **What it proves is narrower than a laptop's**: the webhook answers about a verified NAME, not about the process holding the credential |
| Know when four-eyes could not be checked at all (Phase 176) | an owner nobody holds can never equal the approver, so the gate passes silently. The decision is audited `broker.approval.four_eyes_unverified`, and `PAM_BROKER_REQUIRE_KNOWN_OWNER` refuses it instead |
| Notice an owner offboarding can never reach (Phase 175, corrected in 176) | `owner_known` on both agent listings, and a WARNING inside the campaign item — an owner is free text and the cascade matches it as a username string, so a typo silently orphans an agent |
| Refuse a workload nobody has claimed (Phase 174) | `PAM_BROKER_REQUIRE_ENROLLED_SVID` — off by default; on, an unenrolled identity is refused at the door (`agent.not_enrolled`) while still being listed, since an operator enrols from that list |

Two properties are deliberate. A quarantine check that errors **fails closed** —
a stop button that stops working when the database hiccups is not a stop button.
And every one of these is *suspend*, never *delete*: the accountable human is
gone or the agent is suspect, so it must stop, but the record must not.

**Narrowed by Phase 169, and stated precisely rather than implied**: a *minted
delegated token* (Phase 57) still has no revocation list of its own, but it is
no longer true that a token already in an agent's hands runs until it expires.
Because every such token carries its delegation chain in the `act` claim, and
because the quarantine check now reads that whole chain, quarantining the
delegator's subject stops the delegated tokens too — immediately, at both the
front door and the approval gate. What remains is narrower and worth naming:
containment is by **subject**, so a responder has to be able to NAME the subject
to stop it, and pamv1 keeps no enrollment inventory of SVID identities to name
them from (any workload in the trust domain is an agent — see Known boundaries).
The verifier also allows 60 seconds of clock leeway past `exp`, which is normal
JWT practice but runs permissive in a system where a delegated token's TTL is
its other containment.

## Seeing what an agent is doing (Phase 161)

The controls above decide what an agent *may* do. This section is about noticing
what it *did* — and it exists because the same 2026-08-17 research pass that
produced Phase 159 found that an agent's behaviour was invisible to both of
pamv1's detection surfaces at once, for two different reasons that happened to
compound.

**The trail said nothing about the outcome.** Every brokered tool call — executed,
denied, parked for approval — was written to the primary audit trail as the same
action, `broker.tool_call`, with the outcome buried in the detail text. Both
consumers of that trail key on the action name:

- `internal/ocsf` classified `broker.tool_call.denied` as a Detection Finding, but
  that name was only ever written to the hash-chained broker audit, which the OCSF
  exporter does not read. The classification had never once fired. This is the
  precise failure mode the exporter's own header warns about twice from earlier
  incidents: a name in the map that no code can emit reads to a SIEM author as
  coverage that does not exist.
- `internal/analytics`, the behavioural risk engine, had **no agent action in any
  signal map at all**. An agent could execute privileged tool calls at any rate,
  at any hour, against hosts it had never touched, and score exactly zero.

Together: an agent refused a privileged call every minute for a week produced
nothing on either surface.

Now the action carries the outcome (`broker.tool_call.executed` / `.denied` /
`.pending_approval` / `.failed` / `.resumed`, spelled once as constants in
`internal/broker` so both trails and the SIEM classifier agree), an executed call
counts as **activity** for velocity, peer-outlier and new-target novelty scoring,
and a denial, a refused approval or a **quarantined agent still knocking**
(`agent.quarantine_refused`, Phase 159) all count as `command_blocked` — the
signal class that is permitted to drive an automated response, unlike
`auth_failure`, because all three require the actor to have already
authenticated.

Making agents visible turned out to risk making humans *less* visible, which is
worth stating because it is the kind of trade that normally ships unnoticed. The
peer-outlier signal compares an actor's volume against the median of everyone
else, and agents are high-volume by nature: dropping them into one shared pool
would have raised the threshold enough to hide a human doing ten times their
normal work behind a crowd of busier machines. The comparison is now **per
class** — agents against agents, humans against humans — each pool keeping its
own minimum-peer-group guard, so a class too small to compare simply falls
silent rather than being compared against an unrelated population. An actor is
counted as an agent only if their activity is *entirely* brokered: mistaking a
person for a machine would drop them into a pool where nothing they could
plausibly do looks unusual, and an agent identity cannot open a session at all,
so the strict rule costs nothing.

**One deliberate asymmetry: an agent is exempt from the off-hours signal.** An AI
agent working at 03:00 is normal operation, not an anomaly. Scoring it would mark
every agent permanently and near the per-signal cap, and a detector that fires on
every member of a class every day is one operators learn to scroll past. Activity
yes, off-hours no.

## Reconstructing one agent run (Phase 161)

A human operator's session has a recording that ties its actions together. An
agent run had nothing: each tool call was an unrelated audit row, and the
`session_id` the API had accepted since Phase 13 was **never written anywhere**.

Three fields now make a run reassemblable, and it is worth being precise about
what each is worth:

| Field | Where it comes from | Trust |
|---|---|---|
| `session:` | the agent's declared run id (REST `session_id`; over MCP, the protocol session) | **Declared, unverified** |
| `client:` | the agent's declared software/model (REST `client`; over MCP, `clientInfo` from `initialize`) | **Declared, unverified** |
| `jti:` | the SHA-256 of the single-use resume token pamv1 minted | pamv1's own, verifiable |

The first two are provenance an investigator wants and an attacker can lie about,
so they are recorded and **never consulted for a decision** — they are quoted and
bounded on the way in (`auditfmt.Field`), because an unverified string reaching a
`key:value` audit detail is exactly how a record gets forged. The third is
pamv1's own and joins the park event, the approval decision and the collection to
one token and one `broker_tokens` row.

That collection step is itself new to the tamper-evident chain. Until this phase
the chain ended at the human's approval decision; the moment the agent actually
**took** the result — which for `reveal_credential` is the moment a secret left
pamv1 — appeared only in the primary trail, which is not the authoritative
record.

The model itself is still self-declared, and pamv1 has no way to verify which
model produced a call — that limit is listed under *Known boundaries* rather than
papered over.

## A guard you can defeat by sending less (Phase 163)

The policy engine is the broker's decision layer, and it had a hole in the
operator-facing direction rather than the attacker-facing one — which is worse,
because it produced rules that *read* correctly.

A condition using `not` or `not_in` was satisfied when the argument was
**absent**. Combine that with a tool whose filter is optional and the guard
inverts. `list_credentials` lists **every** credential's metadata when `target`
is omitted, so:

```yaml
- id: not-the-vault
  tool: list_credentials
  effect: allow
  when: { args.target: { not_in: [vault-prod, hsm-root] } }
```

admitted exactly the call it existed to stop: omit `target`, satisfy the
block-list by absence, and list the two targets the rule names. **The rule reads
as a restriction and is defeated by sending less data** — no injection, no stolen
credential, no race, just a smaller JSON object.

Three changes close it and the space around it:

1. **Every operator requires the argument to be present**, matching the positive
   and numeric operators, which always did. An omitted argument now matches no
   condition, so the call falls through to the implicit deny.
2. **`present: true|false`** expresses absence deliberately, since the engine has
   no OR and there would otherwise be no way to say "this argument must not be
   supplied" — which is precisely how an operator writes "the unscoped,
   list-everything form of this call is not allowed".
3. **Arguments are validated against the tool's own declared schema before the
   policy engine sees them.** An undeclared argument is refused rather than
   ignored (the engine only inspects fields a rule names, so an undeclared
   argument passed no guard at all, and a typo like `targt` silently became "not
   supplied"); a missing required argument is refused (the tools read arguments
   with Go's comma-ok assertion, so a missing string quietly became `""`); a
   wrong type is refused, because the engine compares a **stringified** value
   while the tool reads the raw JSON one, and a type they disagree about is a
   value a rule can be made to match while the tool does something else with it;
   and a supplied-but-**empty** string is refused, because `""` is *present* for
   policy while meaning "no filter" to the tool — the same bypass at one
   character's remove.

The honest limit: this makes a block-list mean what it says, but a block-list is
still the weaker shape. An `in:` allow-list bounds what a rule admits to what it
names, and nothing about presence semantics changes that.

## How much an agent can pull (Phase 165)

Arguments have been capped since Phase 13. Results never were — which is the
wrong way round when the caller is a language model, and it left three holes of
the same shape.

**The host.** The SSH exec primitive read remote output with `CombinedOutput`,
which grows until the command stops. It backs `ssh_exec`, account discovery,
rotation verification and the post-session forensics pull, so a policy-allowed
`cat /var/log/huge` was a memory-exhaustion vector against the PAM host itself —
no bypass required, just a large file. Bounded at 4 MiB now, matching the WinRM
path that has had that cap since Phase 13.

**The agent's context.** An unbounded result travels through the API and into a
model's context window, where megabytes of attacker-influenced log text is both a
cost and a prompt-injection surface far larger than anything the agent asked for.
`PAM_BROKER_MAX_RESULT_BYTES` bounds it. Truncation, not refusal: by the time a
result exists the command has already run, so failing the call would hide the
output while keeping the side effect. A **secret-bearing** result is never
truncated — a secret cut in half is not a smaller secret, it is a broken one.

**The record.** `ssh_exec` was the last brokered-command path with no durable
transcript, which is precisely the path where an agent runs commands on a Linux
host. It now writes `.ssh.log` like every sibling, and that is what makes capping
the agent's copy honest rather than lossy: the full output is kept, hashed into
the audit trail and replayable from the console.

One consequence worth stating rather than discovering later: **a truncated read
is reported, never inferred from silence.** A shortened `/etc/passwd` parses
perfectly and simply lists fewer accounts, so account discovery marks the scan
`partial` rather than filing a clean bill of health; the forensic artifact marks
itself truncated; and `ssh_exec` sets a structural `truncated` field rather than
leaving an agent to match a marker embedded in output the **remote host
controls**.

## How much an agent may do in total (Phase 167)

Phase 165 bounded how much data one call can return. This bounds how many calls
there are.

The only volume control before it was an opt-in per-minute rate limit, and a rate
limit answers a different question than the one an operator is asking. Sixty
calls a minute is 86,400 privileged tool calls a day — a number nobody chose, it
is just what falls out of the only knob that existed. `PAM_BROKER_BUDGET_PER_DAY`
and its per-agent override answer the real one: *how much, in total, is this
agent allowed to do?*

Four decisions in it are worth stating, because each could reasonably have gone
the other way:

- **A rolling 24 hours, not a calendar day.** A calendar reset hands every agent a
  predictable instant at which its quota refills — precisely when work that was
  refused would be queued to land — and it forces pamv1 to choose a timezone for
  something unrelated to anyone's working day.
- **Counted from the audit trail, not a side counter.** The number an operator
  reads and the number the gate enforces are the same number, and cannot drift.
  Only `executed` and `resumed` calls count: `executed` is work done, `resumed`
  is the agent collecting the result of a call a human approved — the *other* way
  work happens, and free otherwise. Denials and failures deliberately do not
  consume budget, or a misconfigured agent would burn its own quota on refusals
  and then be refused a legitimate call for the wrong reason.
- **New work only.** Collecting the result of an already-approved call is never
  refused for budget: the work is done, and withholding the output would hide it
  while keeping the side effect.
- **Fails closed.** A count that cannot be read refuses the call — which sounds
  harsh for a resource control until you notice the count is read from the audit
  trail, so if it is unreadable the call could not have been recorded either, and
  the broker already refuses to execute what it cannot audit.

**Known limitation, stated rather than hidden**: a SPIFFE/SVID-authenticated
agent has no local key row, so it inherits the server-wide default and cannot
carry a per-agent budget. The fix is per-identity budgets keyed on the SPIFFE ID
— the shape Phase 159's quarantine already uses to cover both identity kinds —
and it is not built yet.

## What an agent is allowed to KNOW (Phase 169)

Every section above is about what an agent may *do*. This one is about what it
may *learn*, which had a different answer than the rest of the model claimed.

`list_targets` discarded its principal — the parameter was literally `_` — and
returned every target pamv1 knows: name, hostname, OS and protocol. Its sibling
`list_credentials`, called without the optional `target` filter, returned every
credential's account name. So an agent whose grants entitled it to exactly one
host could still enumerate the estate: which hosts exist, what they run, and
which privileged accounts live on them. Nothing about that is a secret in the
vault sense — no `SecretEnc` was ever read — but it is the reconnaissance step
of an attack path, handed for free to the least-trusted actor in the system,
and it was the one place in `broker_tools.go` that ignored the grant check every
acting tool applies.

Both tools now answer through the same `auth.CanConnectTarget` evaluation the
acting tools use (`agentCanSeeTarget`), over direct grants unioned with safe
membership. Three consequences worth stating plainly:

- **Ungated targets stay visible.** A target with no grants and no safe is open
  to everyone everywhere else in pamv1, and this does not invent a second
  authorization model for the broker. Narrowing an agent's view is a matter of
  granting the targets it should reach — which also gates the rest.
- **Naming an ungranted target is refused, not emptied.** `list_credentials`
  with `target: <ungranted>` returns the same "agent not authorized for target"
  refusal every other tool gives. An empty list would conflate "you may not"
  with "there is nothing", and an operator debugging a policy needs those apart.
- **It costs two store reads per target** on an unfiltered listing, because
  grants are stored target-side and pamv1 has no subject-indexed grant query.
  That is the honest price of not maintaining a second, drifting definition of
  what a grant means; the alternative is a cache that can disagree with the gate.

This does not make an agent's view of the estate private in the strong sense: a
policy rule that allows `ssh_exec` on a target the agent has no grant on will
still tell it the target exists by refusing differently than for a name that
does not exist. Enumeration through refusal is a boundary this model has always
had, and it is not closed here.

## Who owns an attested agent (Phase 170)

Separation of duties in the broker rests on one comparison: the human who owns
the agent may not approve that agent's parked call. On the static-key path it
worked — an agent key carries its owner, and Phase 159 made that owner
mandatory precisely so the comparison could not be defeated by leaving it blank.

On the SPIFFE path it could not work at all. An SVID's accountable party
(`Identity.OnBehalfOf`) is the outermost SPIFFE ID in its delegation chain, and
a SPIFFE ID can never equal a person's username — so `EqualFold(owner, approver)`
was always false, and **the human operating an agent could approve their own
agent's privileged call single-handed**, in the deployment posture this document
calls the intended one. Nothing in the tree mapped a SPIFFE ID to a person, so
the comparison had nothing to be right about. It is the Phase 159 defect's shape
for the third time in this batch: a control written against the identity kind
pamv1 issues, silently inert for the kind it merely verifies.

**What is now recorded.** `agent_identities` maps a SPIFFE ID to an accountable
human, with a note, who registered it and when (`POST`/`GET /v1/agents/identities`,
`POST /v1/agents/identities/{id}/owner` for a handover, `DELETE …/{id}`, all
`manage_users`; console menu 26 → F8). Registration is deliberately **not**
enrollment: it admits no workload — the trust domain already decided who may
authenticate — and attests nothing, because a name in a table is not attestation
(SPIRE workload attestation stays infra-bound, see
[EXTERNAL-INFRA-GAPS](EXTERNAL-INFRA-GAPS.md)). It answers exactly one question:
who does pamv1 hold responsible.

**How the gate uses it.** The whole delegation chain is resolved, not only the
accountable party at its end — a call made by a sub-agent was requested,
transitively, by whoever owns the agents it acts for, so an approver owning any
link is on the requesting side of the rule. That is the same reasoning Phase 169
applied to quarantine: an identity's delegates are its reach, for containment and
for separation of duties alike.

**It fails closed in two distinct ways, and both matter:**

- An identity nobody has claimed cannot have its calls approved **by anyone**
  (403, `reason:agent-has-no-owner subject:<spiffe-id>`). Four-eyes cannot be
  proven when one side of it is unknown. The call **stays parked**, so recording
  an owner unblocks the decision rather than forcing the agent to ask again.
- A registry that cannot be read refuses the decision too (503,
  `reason:owner-lookup-failed`). An unreadable table is not evidence that nobody
  owns the agent.

**Operational consequence, stated plainly**: a SPIFFE deployment must register
owners before parked calls can be approved. That is not a side effect to work
around — it is what the gate finally working looks like.

**And offboarding now reaches both kinds.** Deleting a human suspends the agent
keys they owned; for a SPIFFE identity there is no key to suspend, so the
cascade quarantines the subject instead — the stop switch that exists precisely
because that identity kind has nothing else. An already-quarantined subject is
left alone, so a second cascade cannot overwrite who stopped it and why.

**Closed since, by Phase 174**: pamv1 now keeps an inventory. Every attested
identity that authenticates is recorded on sight — an unowned, **seen** row with
first- and last-seen stamps, audited once on the first sighting — so the list an
operator reviews is what actually calls rather than what somebody remembered to
type. Claiming one (setting an owner) is what **enrolled** means, and
`PAM_BROKER_REQUIRE_ENROLLED_SVID` makes the claim mandatory: with it on, the
trust domain's word is necessary but no longer sufficient. A row with no owner
is treated as unattributed by the four-eyes gate, exactly as a missing row is —
a row existing is not somebody answering for it.

Enrollment is still **not attestation**: it admits no workload and proves nothing
about the process holding the SVID. That distinction is the whole reason SPIRE
workload attestation stays in the infra-bound catalogue.

## A control that was only a word (Phase 171)

`ttl_seconds` was in the policy schema, in the shipped example policy, and in
every operator's mental model of what a rule could do. It was read by nothing.
`policy.Rule.TTLSeconds` reached `Decision.TTL` and no non-test caller ever
looked at it, so a rule saying "this grant lasts 60 seconds" produced a call
that stayed approvable for `PAM_BROKER_TOKEN_TTL_MIN` — fifteen minutes by
default. The shipped `deploy/broker-policy.example.yaml` presented exactly that
setting as *"a scoped, short-lived grant"*, which made it worse than a missing
feature: the example taught operators to rely on it.

This is the failure class Phase 159 named and this phase closes for the last
field that had it. **A dead field that reads like a control is worse than an
absent one**, because absence prompts a question and a dead field answers one.

**What it does now.** The rule's value narrows the deployment's window
(`Broker.effectiveTTL`), one deadline is computed at park time and used for
both the parked call and its resume token, and `SweepExpiredParked` evicts per
call rather than against a single global TTL. The narrowing is one-directional
on purpose: a policy file is edited more often, and by more people, than a
deployment's configuration, so a line of YAML must not be able to hand an agent
a longer-lived approval than the deployment allows.

It is also **refused where it would mean nothing**: on an `allow` rule the call
executes and returns in the same request, and on a `deny` there is nothing to
bound, so a `ttl_seconds` there is a policy **load error** rather than a
silently ignored setting. That is the same fail-loud stance the engine already
took for an approval rule with no approvers.

**And `scope` is described rather than promoted.** It renders a template into
the audit record; it cannot narrow what a call does, because the arguments are
fixed before policy runs and the broker executes exactly those. What it does do
is assert presence — a template naming `{target}` fails to render for a call
without that argument, and a render failure is a deny. So: a label with a
fail-closed required-argument check. Enforcing it into anything more would be
theatre, and saying so is the honest half of this phase.

**Visible before it bites**: the parked outcome carries `expires_at`, the
approval queue carries it per entry, and console menu 20 shows a DECIDE BY
column — an agent told only "pending" cannot otherwise tell a decision worth
waiting for from one that can no longer happen.

## Policy that knows who is calling (Phase 173)

The engine's entire input was `(tool, args)`. The verified identity existed one
line above the call site in the broker and was never passed. Two consequences,
both of which an operator met the first time they tried to write a real policy:

**A rule had no principal side.** `Rule` had no agent field, so one `allow` for
`reveal_credential` enabled it for *every* agent the deployment authenticates.
The package's own sudoers analogy was incomplete — sudoers has a user column —
and three vendors model exactly this axis independently: CyberArk's
principal×resource pairs, Teleport's per-role `mcp.tools`, StrongDM's
per-agent-per-destination rules.

**Anything identity-shaped a rule matched was self-asserted.** A condition could
only read the arguments, so "match on the calling agent" really meant "match on a
string the agent chose to send" — a control whose subject is chosen by the party
it constrains.

**What holds now.**

| Question | How a rule says it |
|---|---|
| Only this agent may use this tool | `agents: [rotation-bot]` — an agent-key name or a full SPIFFE ID; an absent list still matches everyone, so existing policies are unchanged |
| This lineage may not use this tool | `not_agents: [spiffe://…/planner]` — matches **any** identity the call is attributable to (presenter, chain, accountable party), so it cannot be escaped by delegating one hop |
| Not through a delegated token | `when: { caller.delegation_depth: { gte: 1 } }` with `effect: deny` — hops, so 0 is an undelegated call for both identity kinds |
| Attested workloads only | `when: { caller.identity_kind: spiffe } }`, or its mirror `caller.spiffe_id: { present: false }` for "a static key" |
| Scoped to one accountable party | `when: { caller.on_behalf_of: alice }` |

The asymmetry between `agents` and `not_agents` is deliberate: the granting side
matches the presenter only, the excluding side matches the whole lineage. Both
choices narrow what a rule admits, which is the direction a mistake should fall.

**Why `caller.*` is a reserved namespace and not a convention.** A `caller.` key
is a different lookup from an argument key — it never touches the argument map —
so an agent sending `{"caller.agent": "rotation-bot"}` cannot satisfy
`caller.agent: rotation-bot`. Over the wire it does not even get that far: the
tool's argument schema refuses an undeclared argument outright (Phase 163). And
an unknown `caller.*` attribute is a **load error**, not a condition that quietly
never matches — the same lesson as Phase 171's misplaced `ttl_seconds`.

**Still open**: a rule cannot yet match on the agent's *owner* as a first-class
fact — `caller.on_behalf_of` is the accountable party as the identity carries it
(a human username for a static key, a SPIFFE ID for an SVID), not the registry
owner Phase 170 records for the attested path. Resolving that inside the engine
would require the engine to read the store, which it deliberately does not do;
the plumbing belongs in the broker and is not built.

## Which controls are proven, and by what

Every mitigation this document claims is asserted by a test. That was not true
until 2026-07-28: three of the controls named above had **never executed** in the
test suite, which is a poor footing for a threat model.

| Control | Proven by |
|---|---|
| Delegated approver-group separation of duties (Phase 27) | `api.TestBrokerDelegatedApproverGroupGrants` — every other successful broker approval in the suite decides as the bootstrap admin, so `approverPermitted` short-circuits on `IsAdmin` and the group-matching loop had never once returned true |
| Capability backstop — policy YAML is never the sole gate | `broker.TestCapabilityBackstopDeniesWhatPolicyAllows`, on **both** the immediate and the post-approval path: a human approval must not confer a capability the agent does not hold |
| Withdrawal is limited to the requester | `broker.TestWithdrawRejectsForeignRequester` and `TestSameAgentIdentityMatching`, the latter pinning the case-folded **name fallback** used whenever an identity carries no static-key row id — which is every SVID-authenticated agent, i.e. the intended production posture |
| An agent identity can be stopped, reversibly, in both authentication paths (Phase 159) | `api.TestAgentSuspendResume` and `api.TestAgentQuarantineCoversBothIdentityKinds` over HTTP, plus `api.TestRevalidateAgentQuarantineCoversSVIDIdentities` in-package — the `KeyID == 0` parked-call path is the one the phase exists for and no HTTP request can reach it without a SPIFFE deployment, so it is asserted directly. Verified to FAIL with the quarantine check removed, not merely to pass with it present |
| Policy can name WHO a rule applies to (Phase 173) | `policy.TestRulePrincipalSide` (a named agent matches, an unnamed one falls through to the default deny, a rule with no list still matches everyone), `policy.TestNotAgentsExcludesTheWholeChain` (an exclusion survives one delegation hop) and `api.TestBrokerPolicyHasAPrincipalSide` end to end over HTTP. Verified to FAIL against the pre-173 engine, where the second agent executed the same call |
| An identity condition cannot be forged by the party it constrains (Phase 173) | `policy.TestCallerAttributesCannotBeForgedByArguments` — arguments named `caller.agent`, `agent` and a nested `caller` object all fail to satisfy `caller.agent`, and the genuine caller still matches with those same arguments present — plus `api.TestCallerConditionCannotBeForgedOverTheWire`, which also pins that the schema check refuses the undeclared argument first |
| An attribute that does not exist is refused, not silently unmatched (Phase 173) | `policy.TestUnknownCallerAttributeIsRefusedAtLoad` |
| A rule's `ttl_seconds` really bounds the approval window (Phase 171) | `broker.TestRuleTTLBoundsTheApprovalWindow` (a 60-second rule under a 30-minute deployment TTL: the reported deadline, the approver queue's deadline and the sweep all follow the rule), `broker.TestRuleTTLCannotExceedTheDeploymentTTL` (a 3600-second rule under a 1-minute deployment TTL narrows, never extends) and `broker.TestNoRuleTTLKeepsTheDeploymentWindow`. The first was verified to FAIL against the pre-171 code, where the rule's value was read by nothing |
| A setting that would do nothing is refused, not ignored (Phase 171) | `policy.TestTTLIsRefusedWhereItBoundsNothing` — `ttl_seconds` on an allow rule, on a deny rule, and a negative value are all load errors; on a `require_approval` rule it loads and reaches the decision |
| An agent refused at the door is visible to both detection surfaces (Phase 185) | `analytics.TestAgentAdmissionRefusalsScoreAsBlocked` (every admission refusal counts as a blocked command; the one non-refusal deliberately does not) and `ocsf.TestRefusalShapedActionsAreClassified`, the guard that found five older refusals exporting as routine activity on its first run |
| A delegation is visible to the approver and joinable in the trail (Phase 183) | `api.TestDelegatedCallJoinsItsMintAndShowsItsChain` — the queue carries the chain, and the exchange row's `jti` equals the call row's `svid_jti`, proving they are the same token. Verified to FAIL against the pre-183 queue, which named the agent and nothing about its lineage |
| A delegated token can pin its next hop (Phase 181) | `api.TestMayActPinsTheNextHop` — the pinned actor may act, a stranger is refused with the claim named, the pin is on the trail, and an out-of-domain party cannot be pinned at all. Verified to FAIL with the emission removed, where the stranger was delegated to successfully — plus `agentid.TestValidateMayActBounds` for the narrowing rules |
| Posture covers the agent path, opt-in and in the right order (Phase 180) | `api.TestAgentPostureIsEnforcedAndOptIn` (off by default, refuses an agent the webhook does not vouch for, admits one it does, and asserts the webhook is told `kind: agent`), `api.TestAgentPostureRefusalIsAudited`, and `api.TestAgentPostureIsNotAskedAboutAStoppedAgent` — the last pinning that a quarantined identity is refused locally and never becomes traffic somebody's EDR system has to absorb |
| A reachability flag matches the control it reports on (Phase 176) | `api.TestOwnerKnownMatchesTheControlItReportsOn` — a case-mismatched owner is flagged AND is then proven unreachable by actually deleting the user and watching which agent gets suspended. Verified to FAIL against Phase 175's case-insensitive check, which called that agent fine |
| An unverifiable four-eyes is recorded, and refusable (Phase 176) | `api.TestFourEyesRecordsWhatItCouldNotVerify` — both directions of the new knob, with the refused decision leaving the call parked |
| The inventory covers a delegation chain, and does not write on every call (Phase 176) | `api.TestDelegationChainIsInventoried` — presenter and root both listed, the indirect sighting marked `via:`, one first-sighting record each, no extra rows from a repeat call |
| Non-human identities are recertified like everyone else (Phase 175) | `api.TestCampaignCertifiesAgentIdentities` — both kinds appear as items reviewed AS agents, with the dormancy signal; revoking suspends the key and quarantines the SPIFFE subject, deletes neither, and audits both under `reason:certification-revoked` |
| An owner no cascade can reach is reported, not hidden (Phase 175) | `api.TestCampaignFlagsAnOwnerNobodyCanOffboard` — exactly the typo'd owner is flagged, in the listing and in the review |
| The attested-agent inventory builds itself (Phase 174) | `api.TestSVIDInventoryBuildsItself` — an unknown SVID's first call creates a seen, unowned row with both stamps and one audit record; a second call adds neither row nor record; registering the same id **adopts** the discovered row rather than colliding, and re-registering an enrolled one is a 409 |
| Only claimed workloads may call, when the deployment says so (Phase 174) | `api.TestRequireEnrolledSVIDRefusesTheUnclaimed` — refused and audited, still listed so it can be enrolled, admitted once enrolled, and a static agent key unaffected throughout |
| A row without an owner is not an attribution (Phase 174) | `api.TestDiscoveredIdentityIsUnattributedForFourEyes` — a parked call from a discovered identity is refused at approval exactly as one from an unregistered identity is, until somebody claims it |
| Four-eyes holds on the SPIFFE path (Phase 170) | `api.TestFourEyesHoldsOnTheSPIFFEPath` — the approver owns the ROOT of a delegated chain, not the agent that made the call, and is refused; the call stays parked; handing the root to somebody else lets the same approver decide. Plus `api.TestApprovalRefusedWhenSPIFFEAgentHasNoOwner` for the fail-closed half, which then registers owners and approves the SAME parked call. Both verified to FAIL against the pre-170 owner comparison — where the self-approval executed |
| Offboarding reaches the identity kind with no key row (Phase 170) | `api.TestOffboardingQuarantinesOwnedSPIFFEIdentities` — deleting a human quarantines the SPIFFE identities they owned and leaves everyone else's alone |
| Containment follows delegation (Phase 169) | `api.TestAgentQuarantineFollowsDelegationChain` over HTTP — a real signed SVID whose `act` claim names a quarantined root is refused although its own subject is clean, and works again the moment the root is released — plus `api.TestRevalidateAgentQuarantineFollowsTheChain` in-package for the parked-call half, the one a responder is actually racing. Both verified to FAIL against the pre-169 single-subject check |
| An agent is told only about the targets it may reach (Phase 169) | `api.TestBrokerInventoryToolsScopedToGrants` — `list_targets` omits an ungranted target, the unfiltered `list_credentials` omits its accounts, and naming that target outright is refused rather than answered with an empty list. Verified to FAIL against the pre-169 unscoped listing |
| An agent's outcome is visible to both detection surfaces (Phase 161) | `api.TestBrokeredCallAuditsTheOutcome` asserts the denial appears in the ACTION and that the same action exports as an OCSF Detection Finding, and `analytics.TestBrokerRefusalsAreCommandBlockedAndDriveResponse` asserts it reaches the signal class permitted to drive a response. Verified to FAIL with the outcome-bearing action reverted to the flat `broker.tool_call`, not merely to pass with it present |
| An agent run is reconstructible, and its declared provenance cannot forge the record (Phase 161) | `api.TestBrokeredCallAuditRecordsTheRun`, `api.TestBrokeredRunFieldsCannotForgeAuditFields` (a run id of `r1 actor:admin status:executed` survives only inside one quoted token), and `api.TestResumeIsRecordedInTheChain` — which also asserts the trail holds the token's hash and never the spendable token |
| The agent off-hours exemption is deliberate, not an oversight | `analytics.TestOffHoursExemptsBrokeredCallsButNotHumans` — one test, both actors, the same 03:00 timestamp |
| A SIEM classification cannot silently name an action nothing emits | `ocsf.TestFindingExactActionsAreEmittable` walks the tree and fails on any classified action no code can write — the guard for the bug class this phase found live |
| A negative policy guard cannot be bypassed by omitting the argument it guards (Phase 163) | `policy.TestNegativeOperatorsRequirePresence` at the engine, and `api.TestNegativeGuardCannotBeBypassedByOmission` end to end over HTTP — which also pins the empty-string variant, since `""` is *present* for policy but means "no filter" to the tool |
| A tool never acts on arguments it did not declare (Phase 163) | `broker.TestValidateArgsRefusesWhatTheSchemaDoesNot` and `api.TestToolCallRejectsUndeclaredArgument` / `TestToolCallRejectsWrongArgumentType`, the latter asserting the tool did NOT run — plus `api.TestUnknownToolIsStillDenied`, which pins that validation did not displace the fail-closed default for an unregistered tool |
| An agent cannot pull unbounded data through the broker (Phase 165) | `rotate.TestSSHExecTruncatesOversizeOutput` at the connector, `broker.TestCapResult*` at the result, and `api.TestBrokeredResultIsCappedButTheTranscriptIsWhole` end to end — the last one asserting both halves at once: the agent's copy is bounded and marked, the stored transcript is byte-complete |
| A secret is never delivered truncated | `broker.TestCapResultNeverTruncatesASecret` |
| An agent's total volume is bounded, not just its burst rate (Phase 167) | `api.TestBudgetStopsAnAgentARateLimitCannotStop`, plus `TestPerAgentBudgetOverridesTheServerDefault` and `TestBudgetZeroIsAHardStop` — the last pinning that an explicit per-agent `0` is a hard stop and not "unlimited", a collapse that would turn the strictest setting into the most permissive one (and which the first implementation of this phase actually got wrong, caught by that test) |
| A budget bounds new work without hiding finished work | `api.TestBudgetDoesNotBlockCollectingAnApprovedResult` |
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
