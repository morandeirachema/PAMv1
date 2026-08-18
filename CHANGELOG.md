# Changelog

All notable released changes to pamv1 are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) with 0.x semantics — breaking
changes may land in minor versions until 1.0.

pamv1 is built phase by phase, and the full per-phase history — what shipped in
each phase, in what order, and why — lives in [ROADMAP.md](ROADMAP.md). This
file records **releases**: the tagged, signed points you can actually deploy.

## [0.48.0] — 2026-08-18

A minor that closes **three live defects in the AI-agent broker**, all found by
re-reading the tree at HEAD after the 159–167 batch shipped. Two of them made a
control that reads as covering every agent silently inert for the identity kind
pamv1 does not issue keys to — a SPIFFE/SVID-authenticated agent, which is the
intended production posture. **Schema change** — new migration `0045` (a new
table; applied on startup, no backfill). Four new routes, no new env var.

**Two upgrade notes below.** Both are the consequence of a control finally
working, not a workaround.

### Fixed

- **Quarantine now follows a delegated token's whole actor chain** (Phase 169).
  It was checked against the presenter's subject only, while a delegated
  JWT-SVID names its delegator solely in the RFC 8693 `act` claim — so
  quarantining a compromised root left every sub-agent token it had already
  minted working until that token's TTL expired. An incident responder pressed
  the stop button and watched the compromise continue. The check now walks the
  presenter plus every actor in the chain, at both moments an agent identity is
  consulted: the front door (`agentAuth`) and the approval-time re-check
  (`revalidateAgent`) — the second being precisely the parked call a responder is
  racing. The refusal names which link stopped the call
  (`agent.quarantine_refused … subject:<id>`). A static key's owner is
  deliberately not in that set: it is a person's username, and stopping every
  agent one human owns is offboarding, a different action with its own trail.
- **Four-eyes self-approval prevention now works on the SPIFFE path**
  (Phase 170). The gate compares a parked call's accountable owner against the
  approving human's username; for an SVID that owner is a SPIFFE ID, which can
  never equal a person's name — so the refusal could not fire and **the human
  operating an agent could approve their own agent's privileged call**. Nothing
  mapped a SPIFFE ID to a person, so pamv1 now records one (below), and the gate
  resolves owners for the **whole delegation chain**: whoever owns any link is on
  the requesting side of four-eyes.
- **A policy rule's `ttl_seconds` is a real bound** (Phase 171). It was parsed
  and read by nothing: a rule advertising a 60-second grant got
  `PAM_BROKER_TOKEN_TTL_MIN` (15 minutes), and the shipped example policy
  marketed exactly that setting as "a scoped, short-lived grant". It now bounds
  how long a `require_approval` call stays decidable and its resume token stays
  spendable, and may only *narrow* the deployment-wide limit, never extend it.
- **A long value no longer pushes columns off the approvals screen** (Phase 171).
  Four user-controlled cells on console menu 20 used a pad that does not
  truncate.

### Added

- **An owner registry for SPIFFE-attested agents** (Phase 170):
  `POST`/`GET /v1/agents/identities`, `POST /v1/agents/identities/{id}/owner`
  (handover keeps the row, so first-registered-by/when survives) and
  `DELETE /v1/agents/identities/{id}`, all `manage_users`; console menu 26 → **F8**.
  It is an owner registry, **not enrollment and not attestation**: registering
  admits no workload — your trust domain already decided who may authenticate —
  and proves nothing about one.
- **The offboarding cascade reaches both identity kinds** (Phase 170). Deleting a
  human suspends the agent keys they owned, and now quarantines the SPIFFE
  identities they owned — an attested agent has no key to suspend.
- **The approval deadline is visible** (Phase 171): `expires_at` on a parked
  call's outcome and on every entry of `GET /v1/approvals`, and a **DECIDE BY**
  column on console menu 20.

### Changed

- **Broker inventory tools answer only for the targets the calling agent may
  reach** (Phase 169). `list_targets` discarded its principal entirely and
  returned every target's name, host, OS and protocol; the unfiltered
  `list_credentials` added every account name on them. Both now apply the same
  direct-grant ∪ safe-membership check every acting tool applies. Ungated targets
  (no grants, no safe) stay visible to everyone, as everywhere else in pamv1;
  naming an ungranted target explicitly is refused rather than answered with an
  empty list. **An agent whose estate is gated by grants now sees less than it
  did.**
- New audit actions: `agent.identity_register`, `agent.identity_owner_set`,
  `agent.identity_remove`, `agent.quarantine_failed`.

### Upgrade notes

- **Register owners for your SPIFFE agents before upgrading a deployment that
  uses them.** A SPIFFE identity with no recorded owner cannot have its parked
  calls approved by anyone: four-eyes cannot be established, so the decision is
  refused (403) and the call **stays parked** — recording the owner unblocks it.
  Register every identity in a delegation chain, since the gate resolves all of
  them. Static agent keys are unaffected; their owner has been mandatory since
  v0.42.0.
- **A policy carrying `ttl_seconds` on an `allow` or `deny` rule now fails to
  load.** The setting never did anything there — an allow executes and returns in
  the same request — and the error says where it belongs. Move it onto the
  `require_approval` rule whose window you meant to bound, or delete it.

## [0.47.0] — 2026-08-18

A minor: AI-agent identities gain a **cumulative call budget**, the volume
control a rate limit cannot express. **Schema change** — new migration `0044`
(additive column plus one index; applied on startup, no backfill). One new env
var, one new route.

### Added

- **A daily budget per agent.** `PAM_BROKER_BUDGET_PER_DAY` (default `0` =
  unlimited) caps how many brokered tool calls one agent may make in a **rolling
  24 hours**, with a per-agent override at
  `POST /v1/agents/{id}/budget` (`manage_users`). Until now the only volume
  control was an opt-in per-minute rate limit, which bounds a burst and nothing
  else: an agent capped at 60 calls a minute may still make 86,400 privileged
  calls a day, and nobody chose that number.

  Details that matter in operation:

  - The window is **rolling**, not a calendar day — no reset instant for queued
    work to land on, and no timezone to configure.
  - Usage is counted **from the audit trail** (`broker.tool_call.executed` and
    `.resumed` only), so the number on the screen and the number the gate
    enforces are the same number. Denied and failed calls do **not** consume
    budget: a misconfigured agent must not burn its own quota on refusals and
    then be refused a legitimate call for the wrong reason.
  - The check bounds **new work only**. Collecting the result of a call a human
    already approved is never refused for budget — the work is done, and
    withholding the output would hide it while keeping the side effect.
  - It **fails closed**. A count that cannot be read refuses the call: the count
    comes from the audit trail, so if that is unreadable the call could not have
    been recorded either.
  - A per-agent budget of **`0` is a hard stop** — that agent may make no
    brokered call at all — and is deliberately distinct from having no per-agent
    budget, which inherits the server default. The console shows the two
    differently and says so on screen.
  - Enforced identically on REST and MCP.

- `GET /v1/agents` now reports `budget_per_day` (omitted when the agent inherits
  the default), `budget_used_today` and `budget_limit_effective`. Console menu
  26 gains a **Budget** column and `7=Budget` to set or clear one, so an
  operator can see who is near their ceiling instead of learning it from a
  refused call.
- New audit actions `agent.budget_set`, `agent.budget_exhausted` and
  `agent.budget_check_failed`.

### Fixed

- PostgreSQL's `CreateAgentKey` silently dropped a column that the in-memory
  store kept, so an agent key created with a field set came back without it on
  Postgres only. Found while adding the budget column, which would have inherited
  the same bug.

## [0.46.0] — 2026-08-18

A minor that closes a **memory-exhaustion vector against the pamv1 host** and
bounds how much data an AI agent can pull through the broker. No schema change
(migration high-water mark stays `0043`). One new env var.

### Fixed

- **One-shot SSH command output was unbounded.** `rotate.SSHConnector.Exec` read
  remote output with `CombinedOutput`, which grows a buffer until the command
  stops — and it is the primitive behind the broker's `ssh_exec`, authenticated
  account discovery, credential-rotation verification and the post-session
  forensic pull. A policy-allowed `cat /var/log/huge` (or a hostile target
  answering a routine command with an endless stream) pulled the whole thing
  into pam-server's heap. Now capped at **4 MiB**, matching the WinRM path,
  which has had exactly that cap since 0.14.0 — with the truncation visible in
  the output and reported as `ExecResult.Truncated`.
- **A truncated read is now reported rather than inferred from silence.** This
  matters most for account discovery: a shortened `/etc/passwd` parses perfectly
  and simply lists fewer accounts, so an unmanaged — possibly privileged —
  account would have gone unreported while the scan looked like a clean bill of
  health. `GET /api/targets/{id}/accounts` now returns `partial: true` and the
  `target.accounts_scanned` audit event carries `partial:true`. The forensic
  artifact marks itself truncated, and `ssh_exec` sets a structural `truncated`
  field rather than leaving an agent to match a marker inside output the remote
  host controls.

### Added

- **`PAM_BROKER_MAX_RESULT_BYTES`** (default `65536`) caps how much of a tool's
  result reaches the agent. Oversized results are **shortened, never refused** —
  by the time a result exists the command has already run, so failing the call
  would hide the output while keeping the side effect. The agent is told plainly
  (a visible marker in the text plus `truncated: true` and `original_bytes`),
  the shortening is deterministic, and a **secret-bearing result is never
  truncated**: a secret cut in half is not a smaller secret, it is a broken one.
  Set to `0` to restore the previous unbounded behaviour.
- **`ssh_exec` now writes a durable `.ssh.log` transcript**, the last brokered
  command path without one (WinRM since 0.10.0, Kubernetes since 0.41.0, the
  forensic reconstruction since 0.42.0, human SSH sessions since the beginning).
  It carries the **full** output, which is what makes capping the agent's copy
  honest rather than lossy, and it is listed, classified and replayable from the
  console like every other transcript.

## [0.45.0] — 2026-08-18

A minor that closes a **real authorization bypass** in the AI-agent broker's
policy engine. No schema change (migration high-water mark stays `0043`).

**Read the *Changed* section before upgrading**: policy semantics change, and a
rule that relied on the old behaviour will now match fewer calls (which is the
point — it was matching calls it should not have).

### Fixed

- **A negative policy guard could be bypassed by omitting the argument it
  guards.** A `not` / `not_in` condition was satisfied when the argument was
  **absent**. Combined with a tool whose filter is optional, that inverts the
  guard: `list_credentials` lists **every** credential's metadata when `target`
  is omitted, so

  ```yaml
  - id: not-the-vault
    tool: list_credentials
    effect: allow
    when: { args.target: { not_in: [vault-prod, hsm-root] } }
  ```

  admitted exactly the call it existed to stop — omit `target`, satisfy the
  block-list by absence, list the two targets the rule names. No injection, no
  stolen credential: a smaller JSON object. Every condition operator now requires
  the argument to be **present**, matching `eq` / `in` / the numeric comparators,
  which always did. An omitted argument matches no condition, so the call falls
  through to the implicit deny.
- **The same bypass with an empty string.** `target: ""` is *present* as far as
  policy is concerned — satisfying both a block-list and a presence check — while
  a tool with an optional filter reads it as "no filter" and returns everything.
  A supplied-but-empty string argument is now refused outright; omit the argument
  instead.
- **An MCP client was told a policy denial was not an error** (`isError: false`),
  so a client that trusts the flag read a refusal as a successful call that
  returned some text. A denial is now flagged. A call parked for approval is
  deliberately still *not* an error: it has not failed, it is waiting for a
  human.

### Added

- **`present: true|false` policy operator.** With absence no longer satisfying
  the negative operators, this is how a rule says "this argument must be
  supplied" or "this argument must NOT be supplied" — the latter being how an
  operator writes "the unscoped, list-everything form of this call is not
  allowed". The shipped example policy gains exactly that rule for
  `list_credentials`. Presence means *supplied*, not non-empty.
- **Tool arguments are validated against the tool's own declared schema**, before
  the policy engine evaluates the call. An argument the tool does not declare is
  **refused rather than ignored** (a typo like `targt` used to become "not
  supplied" silently, which for an optional filter is the difference between
  listing one thing and listing everything); a missing required argument is
  refused instead of arriving as an empty string; and a wrong type is refused,
  which matters because the policy engine compares a *stringified* value while
  the tool reads the raw JSON one. An unregistered tool still falls through to
  the implicit deny rather than becoming a validation failure.
- **`required` in the MCP `tools/list` schema**, so a well-behaved client gets a
  call right the first time instead of learning the contract from a refusal.

### Changed

- **Policy semantics**: every condition operator now requires the argument to be
  present. Rules using `not` / `not_in` that were (knowingly or not) relying on
  absence to match must add an explicit `present: false` rule to keep that
  behaviour.
- Tool calls carrying undeclared, missing, mistyped or empty-string arguments now
  come back `failed` with a reason, where they previously ran with the offending
  value silently defaulted.

## [0.44.0] — 2026-08-17

A minor: agent behaviour becomes visible to detection and an agent run becomes
reconstructible. **No schema change** (migration high-water mark stays `0043`).
One **audit-vocabulary change** and one **SIEM wire-format change** — see
*Changed* below before upgrading if you have rules keyed on either.

### Added

- **A brokered tool call's outcome is now in its audit action.** The primary
  trail records `broker.tool_call.executed` / `.denied` / `.pending_approval` /
  `.failed` / `.resumed` / `.withdrawn` / `.requested` instead of a flat
  `broker.tool_call` with the outcome buried in the detail text. Declared once
  as exported `broker.ActionToolCall*` constants, so the hash chain, the primary
  trail and the OCSF classifier cannot drift apart.
- **AI agents are scored by the risk engine.** An executed brokered call counts
  as *activity* (session velocity, peer-outlier comparison, new-target novelty);
  a denied call, an approval refused for separation of duties, and a quarantined
  agent that keeps knocking count as *blocked command* — the signal class that
  may drive an automated response. **Agents are deliberately exempt from the
  off-hours signal**: an agent at 03:00 is normal operation, and scoring it
  would flag every agent permanently. The peer comparison is computed **per
  actor class** (agents against agents, people against people), so a crowd of
  busy agents cannot raise the bar far enough to hide a human outlier.
- **An agent run can be reconstructed.** `POST /v1/tool-calls` accepts an
  optional `client` alongside the `session_id` it has accepted since Phase 13,
  and both now reach the trail as `session:` / `client:` — **declared by the
  caller, never verified, and never consulted for a decision**. Over MCP they
  come from the protocol session and `initialize`'s `clientInfo`. A brokered
  call's detail also carries `target:` when the arguments name one, and `jti:`,
  the resume token's id, joining a parked call to its approval and its eventual
  collection. The response gained `session_id` and `tool` so an async caller can
  correlate its own concurrent calls.
- **The hash chain records collection.** `broker.tool_call.resumed` is now
  appended to the tamper-evident chain, which previously ended at the human's
  approval decision — the moment an agent actually *took* a result (for
  `reveal_credential`, the moment a secret left pamv1) was recorded only in the
  ordinary trail.
- Regression guard `ocsf.TestFindingExactActionsAreEmittable`: walks the source
  tree and fails on any action classified for SIEM export that no code can emit.

### Changed

- **Audit vocabulary.** `broker.tool_call` is no longer written. SIEM rules,
  saved audit filters and dashboards keyed on that exact name must move to the
  outcome-bearing names above.
- **OCSF export.** `isFinding` now matches `.denied` / `.failed` as well as
  `_denied` / `_failed`. Dotted failure actions therefore export as **Detection
  Finding (2004, severity 3, status 2)** instead of API Activity (6003).

### Fixed

- `internal/ocsf` classified `broker.tool_call.denied` as a Detection Finding
  while no code could write that name to the trail the exporter reads — the rule
  had **never fired** since 0.14.0. The same file's header warns about exactly
  this: a classification for an unemittable action reads to a SIEM author as
  coverage that does not exist.
- The `_failed` suffix rule never matched dotted action names, so 0.43.0's
  `agent.disable.failed` (an agent suspension that did not stick while
  offboarding its owner) exported as routine API Activity rather than a finding.

## [0.43.0] — 2026-08-17

A minor: one new capability, and the first release driven by gap research
aimed at pamv1's **own AI-agent broker** rather than at its human-operator
paths. Schema change — new migration `0043` (additive; applied on startup).

### Added

- **Agent identity lifecycle and a stop button.** An AI-agent identity can now
  be **suspended and resumed** (`POST /v1/agents/{id}/disable` and `/enable`),
  given an **expiry** at creation (`expires_in_days`, enforced at
  authentication), and **quarantined by subject**
  (`POST`/`GET /v1/agents/quarantine`, `DELETE /v1/agents/quarantine/{id}`) —
  a list that stops an identity in **both** authentication paths, including
  SPIFFE/SVID agents that have no local row to disable, because an SVID
  agent's canonical name *is* its SPIFFE ID. Quarantine is checked at the
  front door **and** again when a parked call comes up for approval, and a
  store error **fails closed**: a stop button that stops working when the
  database hiccups is not a stop button. Every successful authentication also
  stamps `last_used_at`, so a dormant agent credential is reportable, and
  deleting a human user now **suspends** every agent key they owned
  (`reason:owner-offboarded`).

  Suspend, never delete: the agent must stop, the record must not. Deletion
  was previously the *only* way to stop an agent — it destroyed the row an
  investigation needs and silently invalidated that agent's parked approvals.

  New `agent.disable` / `agent.enable` / `agent.quarantine` /
  `agent.quarantine_released` / `agent.quarantine_refused` audit actions;
  console menu 26 gains status, expiry and last-used columns, `5=Suspend`,
  `6=Resume` and `F7` for the quarantine screens. No new env var.

### Fixed

- `AgentKey.Disabled` was honoured on read by both store backends while **no
  code path could ever set it** — dead state that read as a control.
- `revalidateAgent` gated its store check on `KeyID > 0`, which a SPIFFE/SVID
  identity never is, so in the intended production posture a parked call from
  a revoked agent revalidated **true**. The quarantine check now runs first
  and unconditionally.

## [0.42.0] — 2026-08-17

A minor: one new capability, and the close of the 15-phase
BeyondTrust/Delinea/Teleport/StrongDM batch (phases 129–158). No schema change.

### Added

- **Post-session forensic reconstruction.** After an interactive SSH session
  ends, pamv1 runs ONE fixed, read-only command over that target's own
  vaulted credential on a fresh connection, pulls the TARGET's own kernel
  audit records (auditd), filters them to that session's window and stores
  them beside the recording as a hash-chained, replayable `.forensics.log`.
  A session recording shows what was **typed**; this shows what **ran** — an
  obfuscated `… | base64 -d | sh` or an unechoed command is reconstructed
  decoded. `PAM_SESSION_FORENSICS` (off by default),
  `PAM_SESSION_FORENSICS_MAX_EVENTS`, `PAM_SESSION_FORENSICS_TIMEOUT_SEC`;
  new `session.forensics` / `_unavailable` / `_failed` audit actions. "The
  target could not tell us" (no auditd, no permission) is an audited
  **finding**, never silence. Audit-only, interactive SSH only, and only as
  trustworthy as the target's own logs — which the artifact states.

  This replaces the eBPF mechanism the phase was planned around, which a
  **go/no-go established is architecturally impossible for a proxy**: an
  operator's shell runs in the target's kernel, so a probe on the pam-server
  host observes zero events per brokered session. That limitation is now
  documented in `docs/EXTERNAL-INFRA-GAPS.md` rather than carried as a to-do.

### Fixed

- Session artifacts written by the Kubernetes broker (`.k8s.log`, 0.41.0)
  were audited but **invisible** to the recordings listing and unreachable by
  the playback route. Both it and the new `.forensics.log` are now listed,
  classified and servable, so an auditor can actually reach the evidence.

## [0.41.0] — 2026-08-16

A minor: one new capability. No schema change.

### Added

- **Kubernetes targets (discrete operations).** A new `kubernetes` target
  protocol — a cluster's API server rather than a host, so there is no
  session to proxy — with a vaulted service-account bearer token
  (`k8s_token`) and `POST /api/targets/{id}/kubectl` brokering ONE audited
  operation at a time: `get`, `logs`, `apply` (server-side apply,
  `fieldManager=pamv1`) and `delete`. The token is injected just-in-time
  and never shown to the operator; what it may do inside the cluster is
  decided by the cluster's own RBAC, whose refusal comes back as its own
  `403` in the response envelope. Same gates, command control (`kubectl …`
  is what deny/allow patterns match), transcript, live-session registry and
  audit contract as the WinRM REST endpoint. New `PAM_K8S_CA_FILE`,
  `PAM_K8S_INSECURE_SKIP_VERIFY`, `PAM_K8S_TIMEOUT_SEC`,
  `PAM_K8S_MAX_RESPONSE_KB`; new `k8s.*` audit family; console option 6 on
  *Work with Targets*. The client is hand-rolled on the standard library
  (no `client-go`, no discovery walk). `exec`/`attach`/`port-forward`,
  client-certificate credentials and API discovery are documented v1
  exclusions. Not verified against a real cluster.

### Fixed

- A target's protocol change could **strand a protocol-bound credential**:
  the guard keyed off "is the new protocol ssh", so `postgres` → `mssql`
  (where a `db_zsp` credential stays valid) was wrongly refused, while
  `postgres` → `ssh` was wrongly allowed and left a `db_zsp` credential no
  code path could serve. Both ends now derive from one table.

## [0.40.0] — 2026-08-16

A minor: one new capability and a second deployable binary. New migration
`0042`.

### Added

- **Outbound-only endpoint agents (Jump Client-style reachability).** For
  targets pamv1 cannot dial into — NAT'd branch boxes, CGNAT'd contractor
  laptops, hosts with no inbound firewall rule — a new `pam-agent` binary
  (published on this Release as `pam-agent_linux_amd64` /
  `pam-agent_linux_arm64` + `SHA256SUMS`) dials OUT to the existing `:2222`
  SSH listener as `endpoint-agent:<name>` with its own bearer key, holds an
  RFC 4254 reverse tunnel, and the proxy reaches the bound target through it
  — JIT injection, known_hosts pinning, recording, monitoring and every
  admission gate unchanged inside the tunnel. `PAM_ENDPOINT_AGENTS_ENABLED`
  (default off); `POST/GET /api/endpoint-agents`, `DELETE
  /api/endpoint-agents/{id}`; console menu 28. One live agent per target;
  a bound target is tunnel-or-nothing (never a silent direct fallback);
  revoke drops the live tunnel at once; SSH targets only. The agent alone
  chooses the one local address it exposes, pins pam-server's SSH host key
  (`PAM_AGENT_SERVER_HOST_KEY`, required) and can carry nothing toward
  pamv1. Per replica: list every replica in `PAM_AGENT_SERVERS`. New audit
  family `endpoint_agent.*` and a `via:endpoint-agent:<name>` marker on
  `session.start`. Not verified across a real NAT path (see
  EXTERNAL-INFRA-GAPS.md).

### Changed

- New migration `0042` (`endpoint_agents`); `store.Store` grows a
  `EndpointAgentStore` role (190 → 196 methods).
- The SSH proxy accepts one `tcpip-forward` global request — from an
  endpoint-agent identity only; every other connection's global requests
  are still discarded, and an operator connection cannot register a forward.

## [0.39.0] — 2026-08-16

A minor: one new capability. No schema change.

### Added

- **SAML 2.0 single sign-on (Service Provider).** pamv1 can act as a SAML
  SP in the SP-initiated Web Browser SSO profile, for identity providers
  that speak SAML but not OIDC — on-prem AD FS above all, plus SAML-only
  Okta/OneLogin/Entra applications. New routes `GET /api/auth/saml/start`
  (AuthnRequest, HTTP-Redirect), `POST /api/auth/saml/acs` (the IdP's
  signed Response, HTTP-POST) and `GET /api/auth/saml/metadata` (the SP
  descriptor an IdP administrator imports). `PAM_SAML_SP_URL` enables it;
  IdP metadata from `PAM_SAML_IDP_METADATA_URL` or `_FILE`; group/role
  attribute values map to roles via `PAM_SAML_ROLE_*`; optional
  `PAM_SAML_SP_KEY_FILE`/`_CERT_FILE` sign AuthnRequests and accept
  encrypted assertions. Wired exactly like OIDC (hot-swappable, same role
  mapper, same portal landing); the AuthnRequest ID reuses the existing
  single-use OIDC-state table, so no migration. XML-DSig verification is
  delegated to `crewjam/saml` + `goxmldsig` — the second deliberate
  crypto-verification library exception after WebAuthn, reasoned in
  ROADMAP.md (Phase 151). Proven against a real in-process SAML IdP,
  including tampered, stripped, wrong-audience/issuer, expired and
  signature-wrapped Responses; interop with a live IdP is not verified.

### Changed

- The OIDC callback now refuses a login-state row that belongs to the SAML
  flow (cross-protocol guard on the shared single-use table).
- `PAM_OT_AIRGAP` additionally refuses `PAM_SAML_IDP_METADATA_URL`; use
  `PAM_SAML_IDP_METADATA_FILE` inside the enclave.
- New direct Go dependencies: `github.com/crewjam/saml`,
  `github.com/russellhaering/goxmldsig`, `github.com/beevik/etree`.

## [0.38.0] — 2026-08-16

A minor: one new capability.

### Added

- **SCIM 2.0 user provisioning.** New `/scim/v2/Users` (RFC 7643/7644),
  authenticated by a new non-human `ScimKey` bearer identity mirroring
  `AgentKey`/`AppKey`, for push-based IdP user lifecycle — complementing
  the existing pull-based `POST /api/identity/reconcile`. Every
  SCIM-provisioned user gets the fixed, least-privileged `user` role.
  `PAM_SCIM_ENABLED` (default off).

### Changed

- `store.User` gains `ExternalID` and `Active`. Deactivating (`PATCH
  active:false` or `DELETE`, a soft-delete) now actually blocks that
  user's own local token from authenticating —
  `auth.Resolver.Resolve()` fails closed, proven end to end.
  `CreateUser` in both backends now always creates an active user
  regardless of the input struct's `Active` field.

## [0.37.0] — 2026-08-16

A minor: one new capability.

### Added

- **Browser-extension password autofill.** A real Manifest V3 extension
  (`extension/`) calls the existing, already-audited
  `POST /api/credentials/{id}/reveal` — no new secrets-disclosure surface.
  Authenticates with a new narrow bearer-token shape
  (`auth.SessionScopeExtension`/`Principal.ExtensionOnly`, minted via
  `POST /api/extension-token`, `reveal_secret` required) refused on every
  other route. `PAM_EXTENSION_TOKEN_TTL_HOURS` (default 24, max 720).

### Changed

- `authz` is now a thin wrapper over a new `authzCore(cap, allowExtension,
  next)`, with a second wrapper `authzExtOK` used at exactly the reveal
  route — the shared checklist lives in one place instead of a second,
  driftable copy of it.

## [0.36.0] — 2026-08-16

A minor: one new capability.

### Added

- **Generic file-attachment secrets.** A new `secret_type: "file"` for
  license keys, cert bundles and short documents — the same
  `vault.Encrypt`/`Decrypt` pathway and `POST /api/credentials` route every
  other secret type already uses, base64-encoded by the client.
  `PAM_CREDENTIAL_FILE_MAX_KB` (default 1024, max 10240) refuses an
  over-cap file secret before it is ever encrypted or a row is ever
  inserted. No migration (`secret_type` is a plain `TEXT` column).

### Fixed

- `store.Store` gained `ListCredentialsMeta`, a metadata-only sibling to
  `ListCredentials` used only by callers that display a credential list and
  never decrypt from it. `ListCredentials` itself is unchanged and stays
  full-fidelity — several real internal callers (`-rotate-kek`, the
  credential lifecycle reconciler, the PostgreSQL/RDP/VNC/WinRM JIT-decrypt
  paths) depend on that.

## [0.35.0] — 2026-08-15

A minor: one new capability.

### Added

- **ICAP-based file-transfer scanning.** `PAM_ICAP_URL` submits every
  finalized SFTP transfer's captured bytes whole to an ICAP (RFC 3507)
  RESPMOD AV/DLP gateway, via a new minimal `internal/icap` client. This is
  **detection, not prevention**: a whole-object scan needs a complete file,
  which by the time it exists has already reached the target (upload) or the
  operator (download) through the existing per-packet relay — proven by a
  test where an unreachable ICAP server still lets the transfer through. A
  flagged file is audited `sftp.icap_flagged` naming the vendor's own reason;
  a scan failure is audited `sftp.icap_scan_failed`; a capped or broken
  capture is skipped rather than scanned incomplete (`sftp.icap_skipped`).
  Requires `PAM_SSH_SFTP_CAPTURE` and `PAM_SSH_SFTP_CAPTURE_MAX_MB` already
  set — the same byte cap bounds the in-memory scan buffer. Joins the
  `PAM_OT_AIRGAP` conflict list.

## [0.34.0] — 2026-08-15

A minor: one new capability.

### Added

- **Raw TCP port-forwarding, same-target only.** `ssh -L`-style forwarding:
  a client-initiated `direct-tcpip` channel is admitted only to the
  connected target's own host — any port, since the target's own
  configured port is its SSH port, not the service the operator actually
  wants — closing what would otherwise be an SSRF pivot into the target's
  network. `localhost`/`127.0.0.1`/`::1` count as the target too, since
  the forward dials out through the already-authenticated upstream
  connection. Always refused in an observer session, or while
  `PAM_REQUIRE_LIVE_SUPERVISION`/`PAM_REQUIRE_RECORDING` are set — none of
  those mechanisms cover a raw, unrecordable byte stream.
  `PAM_SSH_PORT_FORWARD` (default true) turns the feature off
  deployment-wide. New audit actions `forward.start`/`forward.end`/
  `forward.refused`.

## [0.33.0] — 2026-08-15

A minor: one new capability. Schema change (migration `0040`).

### Added

- **Personal/private safes.** A safe marked `personal` (`POST /api/safes`
  with `personal:true` and a required `owner`, seeded as the safe's first
  `can_manage` member) is invisible to the admin auto-bypass every other
  safe still grants: `auth.CanConnectTarget` requires a new, narrow
  `unlimited_vault_access` capability instead — deliberately absent from
  the built-in admin role, grantable only through a custom profile. A
  matching fix in `canManageSafe` stops `manage_targets` alone from being
  a side door around it. Using the override is audited loudly
  (`safe.personal_override_used`), mirroring break-glass. Inventory
  listing and safe deletion/rename are unaffected — only connect, reveal
  and checkout are gated. New `internal/store/personalsafe.go`; new
  migration `0040`.

### Changed

- `auth.CanConnectTarget` gained a fourth parameter (`personal bool`).
  Every in-repo call site was updated; an out-of-tree caller of this
  function needs the same.

## [0.32.0] — 2026-08-15

A minor: two new capabilities.

### Added

- **Magic-link access-request approval.** An `ApprovalInvite` mirrors the
  Phase 116 session-share invite: creating one already requires
  `CapApprove`, so the invite itself is the delegation. Redemption is a
  safe, non-consuming preview `GET` plus a single-use decision `POST`,
  fired only from an explicit button click on the new `approve.html` page
  — deliberately unlike `share.html`'s auto-redeem-on-load, since deciding
  an access request is higher-stakes than joining a session. A second
  four-eyes check at invite *creation* time (`createApprovalInvite`) stops
  a requester self-approving through their own emailed link — a hole the
  redemption path's synthetic actor alone would not have closed.
  `PAM_APPROVAL_INVITE_TTL_MIN` (default 1440). New
  `internal/api/approvalinvite_handlers.go`; new migration `0039`.
- **Session watermarking.** RDP/VNC sessions show a client-side DOM overlay
  naming the operator, target and start time; SSH/PostgreSQL/SQL Server
  sessions get the same identity as a one-time `Hub.Publish` banner. New
  `internal/proxy/watermark.go`.

## [0.31.0] — 2026-08-15

A minor: one new capability. Schema change (migration `0038`).

### Added

- **DoubleLock.** A named person's password, additionally required (on top
  of `reveal_secret`) to reveal or check out a credential's plaintext —
  even a compromised admin account can't read it alone, and disabling it
  requires the same password, so an admin alone can't strip the protection
  either. `POST`/`DELETE /api/credentials/{id}/doublelock`. Kept
  deliberately independent of the vault/KEK: `DoubleLockEnc` is a second
  encryption of the secret keyed directly by PBKDF2(password), never
  KEK-wrapped, so `-rotate-kek` needs no special case for it. Rotating the
  credential's secret clears DoubleLock. New `internal/api/doublelock.go`;
  new migration `0038`.

## [0.30.0] — 2026-08-14

A minor: one new capability. Schema change (migration `0037`).

### Added

- **Device-aware access control.** A live EDR/posture webhook
  (`PAM_POSTURE_ATTEST_URL`) is re-checked on every connect and every
  authenticated call, not just at approval. An optional device-identity
  binding (`PAM_DEVICE_HEADER` + a per-user `device_fingerprint`) trusts a
  reverse-proxy-injected client-certificate fingerprint — REST surface
  only, since the SSH/PostgreSQL/SQL Server proxies have no HTTP layer.
  Both break-glass exempt; neither reaches the AI-agent broker. New
  `internal/posture` package; new migration `0037`.

## [0.29.0] — 2026-08-14

A minor: one new capability. No schema change.

### Added

- **Command allow-listing.** `PAM_COMMAND_ALLOW_FILE` (sibling to the
  existing `PAM_COMMAND_DENY_FILE`) narrows every command-control path —
  SSH `exec`, WinRM, SQL statements, the broker's `ssh_exec`/`winrm_exec`
  tools — to only the listed patterns; deny still wins when both match.
  Closes the Delinea SSH Command Menus gap. New `cmdguard.Guard.Allowed`.

## [0.28.0] — 2026-08-14

A minor: two new capabilities. Schema change (migration `0036`).

### Added

- **Authenticated post-login account discovery.** `POST
  /api/targets/{id}/discover-accounts` (`manage_targets`) dials an ssh/winrm
  target with its own vaulted credential and runs a fixed, read-only
  enumeration command, then cross-references every discovered account name
  against every credential already vaulted for that target — an account
  with no match comes back unmanaged, the CyberArk-DNA-style finding.
  New `internal/accountscan` package; console menu 1, option 9.

- **Zero Standing Privilege for PostgreSQL.** A new `db_zsp` credential
  type stores no secret; at connect time pamv1 provisions a fresh,
  randomly-named database role via a separately vaulted `provisioner`
  credential, connects the session as that role, and drops it when the
  session ends — extending Phase 22's SSH-only ZSP to databases. RDP has
  no equivalent (a confirmed Guacamole/FreeRDP protocol limitation); SQL
  Server is deferred.

## [0.27.0] — 2026-08-14

A minor: one new capability. No schema change.

### Added

- **Portal color themes.** Every hardcoded color in the management console's
  stylesheet became a CSS custom property; two new dark palettes (`amber`,
  `slate`) sit alongside the existing green. Press **F2** anywhere in the
  portal to cycle between them — a client-only preference persisted in
  `localStorage`, no new store table, route or audit event.

## [0.26.0] — 2026-08-14

A minor: one new capability. Schema change (migration `0035`).

### Added

- **FIDO2/WebAuthn passwordless MFA.** A second, independent second-factor
  type alongside TOTP — either alone satisfies MFA. `PAM_WEBAUTHN_RP_ID`/
  `_RP_ORIGIN` (presence enables it, same idiom as OIDC) turn it on;
  self-service `POST /api/webauthn/register/{begin,finish}` registers a key,
  `GET`/`DELETE /api/webauthn/credentials{,/{id}}` manage them. A
  WebAuthn-enrolled user with no confirmed TOTP gets a narrow, 5-minute
  `MFAPending` session on password success — good for nothing but the
  two-call WebAuthn login ceremony the console drives automatically. A user
  may register more than one key. Verified by `github.com/go-webauthn/webauthn`
  rather than hand-rolled. New migration; store surface 164 → 171.

## [0.25.0] — 2026-08-14

A minor: one new capability. No schema change.

### Added

- **Suspend vs. terminate a live session.** `POST /api/sessions/{id}/suspend`/
  `.../resume` (`approve`) freeze and unfreeze an operator's input without
  ending the session, reusing the input mux session-sharing introduced rather
  than new plumbing; `GET .../suspend` (`read_audit`) reports current state.
  Idempotent; the operator gets a `Stderr` banner on either transition.
  Replica-local, like sharing. Console: an amber *SUSPENDED* banner on the
  live-watch pane, **F8** to toggle. New audit actions
  `session.suspended`/`session.resumed`; no new migration.

## [0.24.0] — 2026-08-14

A minor: one new capability (three related additions). Schema change (migration `0034`).

### Added

- **Recurring access requests, configurable password policy, checkout
  extension.** Three additive policy-richness gaps. An access request with
  `recur_days` set becomes, once approved, the anchor of a recurring series:
  a fresh pending (never pre-approved) successor is auto-filed every N days
  on its own worker; `POST /api/access-requests/{id}/stop-recurrence` ends
  it. Generated-password shape is now config-driven
  (`PAM_PASSWORD_MIN_LENGTH`/`_MIN_LOWER`/`_MIN_UPPER`/`_MIN_DIGIT`/
  `_MIN_SYMBOL`, defaults unchanged from before) and reuse-prevention is
  opt-in (`PAM_PASSWORD_HISTORY_COUNT`, default 0, tracked as SHA-256
  hashes only). `POST /api/credentials/{id}/checkout/extend` (holder-or-
  admin) pushes an active checkout's expiry out, capped at
  `PAM_CHECKOUT_MAX_EXTEND_MIN` (default 240) total from check-out. Console:
  a recur-days field + Recur column + stop-recur option on access requests,
  an extend option on checkouts. New migration `0034`; store surface
  157 → 164 methods.

## [0.23.0] — 2026-08-13

A minor: one new capability. Schema change (migration `0033`).

### Added

- **CIDR/network-based connect & login authorization.** A per-user,
  comma-separated CIDR allowlist (`ip_allowlist`) restricting where a
  bearer-token principal may connect from, enforced at both the REST
  `authz` middleware and the session-proxy `admit()` gate (SSH/PostgreSQL/
  SQL Server) — break-glass exempt, like every other admission gate. Empty
  is unrestricted; directory/OIDC-authenticated principals are unaffected
  in v1 (no backing `store.User` row to source a list from). `POST
  /api/users` and `PUT /api/users/{id}` accept `ip_allowlist`; on update it
  is omit-to-leave-alone, explicit-`""`-to-clear. Console: a new field on
  the user-add/change forms and an "IP" column on the user list. New
  migration `0033` (Postgres); store surface 156 → 157 methods.

## [0.22.0] — 2026-08-13

A minor: one new capability. Schema change (migration `0032`).

### Added

- **Live session-sharing ("Session Invite").** A running SSH session can be
  shared with a second party, view-only or view-control, via a four-eyes
  request→approve workflow (`POST /api/sessions/{id}/share`, decided by a
  *different* principal). Internal invites (a named pamv1 user) redeem over
  SSH as `join:<token>`; external/vendor invites are delivered by email with
  an embedded QR code, valid 15 minutes, single-use, and redeemed through a
  new unauthenticated guest page (`/share.html`) — never through the SSH
  path. Multiple simultaneous view-control joiners are supported natively.
  Console: the live-watch pane gains a joined-parties roster with a kick
  action; F6/F7 file and manage invites. New audit actions
  `session.share_{requested,approved,denied,revoked,joined,join_denied,ended,kicked}`,
  two of them fail-closed. New env vars `PAM_SESSION_SHARE_INVITE_TTL_SEC`
  (default 900) and `PAM_SESSION_SHARE_GUEST_TTL_MIN` (default 240); reuses
  `PAM_ALERT_EMAIL_*` for the invite email. New migration `0032` (Postgres);
  store surface 149 → 156 methods. `PAM_OT_AIRGAP` now also disables the
  external/vendor invite email path (it dials SMTP directly and was not
  previously covered by the alerter's own air-gap no-op).

## [0.21.0] — 2026-08-13

A minor: one new capability. No schema change.

### Added

- **A live, control-mapped NIS2 compliance report.** `GET
  /api/compliance/nis2?since=&until=` scores window-scoped audit activity
  against the existing Art. 21(2) control matrix: each control's status is
  architectural (same as docs/NIS2-COMPLIANCE.md), and controls with a
  natural audit signal carry a count of matching events bucketed by action
  family, plus (for incident handling) the audit chain's integrity result.
  Same digest/determinism/self-audit conventions as the existing raw export.
  Console: F8 from *Display Audit Trail*. NIS2 only — PCI-DSS/ISO27001/SOX
  are not attempted.

## [0.20.0] — 2026-08-13

A minor: one new capability. No schema change.

### Added

- **Interactive SSH sessions can now require an actively-watching supervisor.**
  `PAM_REQUIRE_LIVE_SUPERVISION=true` holds a session's channel open — before it
  dials the target — until a supervisor attaches `GET /api/sessions/{id}/stream`
  or `PAM_LIVE_SUPERVISION_TIMEOUT_SEC` (default 120s) elapses, in which case the
  session is refused and audited `session.unsupervised`. Observer sessions and
  break-glass access are exempt. SSH only for now; the database and WinRM
  proxies are left for a future phase.

## [0.19.0] — 2026-08-12

A minor: one new capability. No schema or env-var change.

### Added

- **SSH session recordings are now searchable by content.** `GET
  /api/recordings/search?q=` finds text anywhere in a stored recording's
  output, even split across several separate writes (the shape interactive
  terminal echo actually takes), and reports each match's snippet plus the
  playback time to jump to. The 5250 console gains a search screen (F4 from
  *Session Recordings*) that seeks a replay straight to a hit. Requires
  `read_audit`, the same capability that already lists and plays back every
  recording; every search is itself audited (`session.search`) with the
  query. RDP/VNC and WinRM recordings are not covered by this pass.

## [0.18.2] — 2026-08-12

A patch: audit-fidelity and access-control fixes surfaced by two review passes
(Phase 96, Phase 108), plus operational-logging and audit-timestamp
consistency. No schema, route or API change.

### Changed

- **Operational logs from the session subsystem now carry `service=session`,**
  including the cross-replica authentication-refusal lines — previously they
  landed on the untagged default logger, invisible to a SIEM rule that filters
  by service. The API's internal-error log path likewise carries `service=api`.
- **Webhook alert timestamps and the live-session inventory are serialized in
  UTC,** matching the syslog and email channels, so a SIEM never receives a
  mixed local/UTC zone.

### Security

- **The AI-agent broker's tools now pass the vendor-contract gate.** A vendor
  identity is refused an out-of-contract target on the SSH, PostgreSQL, SQL
  Server and RDP/VNC-viewer paths, but the broker's `ssh_exec`, `winrm_exec`,
  `reveal_credential` and `rotate_credential` tools did not check it — so a
  vendor holding the broker capability could reach an account it was refused
  everywhere else. The account-scoped gate now runs in every tool once the
  credential is resolved (Phase 96, Phase 29).
- **A vendor-contract refusal on the SSH proxy is now audited as
  `access.denied`,** matching the SQL proxies, the viewer tunnel and the REST
  paths. It had been `session.denied`, a name the OCSF exporter and the risk
  analytics do not key on — so SSH vendor refusals had been silently excluded
  from SIEM export and risk scoring.
- **The PostgreSQL and SSH session-deny paths bound the operator-supplied login
  before it reaches an audit row** (quoted and length-capped, as the SQL Server
  listener already did), closing an audit-detail injection vector on an
  attacker-controlled startup username.
- **The PostgreSQL and SQL Server proxies no longer write two contradictory
  `db.session.denied` rows for one refused connection** (a tunnel-scoped viewer
  token or an MFA-enrollment-only session) — one audit row per refusal now,
  matching every other admission gate.
- **`PUT /api/targets/{id}` refuses to change a target's protocol away from
  `ssh` while it still holds an `ssh_ca` (Zero Standing Privilege) credential**,
  mirroring the check `POST /api/credentials` already made at creation time —
  closing a gap where retargeting the target could strand the credential with
  no secret and no certificate path (Phase 108).

### Fixed

- **The proxy's WinRM command loop withholds output when its `winrm.run` audit
  cannot be written,** the same fail-closed contract the REST WinRM endpoint has
  always had.
- **`pam-server -split-key` refuses an unparsable `PAM_BREAK_GLASS_SHARES` /
  `PAM_BREAK_GLASS_THRESHOLD`** instead of silently falling back to a default,
  so a typo cannot mint a share set with a different quorum than the server
  would accept at startup.

## [0.18.1] — 2026-08-09

Findings from an adversarial review of the crown-jewel subsystems (vault, the SFTP
guard, the database proxies, the broker four-eyes). A **patch**: one security fix,
plus test and documentation hardening. No schema, route or API change.

### Security

- **Read-only SFTP forwarded a native mutating operation as if it were a read.**
  The request inspector enumerated the mutating packets and forwarded everything
  else, so `SSH_FXP_LINK` (the SFTP v6 hard/symlink op) and the `BLOCK`/`UNBLOCK`
  locks slipped through read-only mode against any SFTP server that speaks them —
  a write in a session meant to permit none. (The openssh `hardlink@openssh.com`
  extension twin was already refused.) Read-only now forwards only the read
  family and refuses any other request type, matching the extension handler.
  Allow mode is unchanged, except a native `LINK` is now audited.

## [0.18.0] — 2026-08-09

A **patch**-level audit-integrity fix, released as a minor for the pin currency:
a step-up decision that was recorded but did not take effect could leave a false
four-eyes record. No schema change; upgrading from 0.17.x needs nothing.

### Fixed

- **A step-up decision that was recorded but did not take effect left a false
  "decided" record.** The four-eyes `session.stepup_decided` audit is written
  before the decision's side effect (a released statement must never outlive the
  evidence of who released it) — but a failed cross-replica dispatch, or a lost
  local race, then left that record standing for a release that never happened. A
  compensating `session.stepup_decision_voided` now nets the trail out.

### Docs

- Reconciled `docs/SECURITY-GAPS.md`: five findings (AO–AS) were marked Open
  though they had been fixed (four in Phase 63, AO's residual here). The record of
  what is open now matches reality.

## [0.17.0] — 2026-08-09

A **minor**: threat analytics learns two history-relative signals and a gentler
automated response — and a review of that work closed a way the automated
responses could be turned against a bystander. No schema change; upgrading from
0.16.x needs nothing.

### Security

- **The threat-analytics automated responses could be aimed at any account by an
  unauthenticated attacker.** The risk score counts auth failures, and a failed
  login records the *presented* username as the actor — so failing login under a
  victim's name scored *them* high/critical, and with `PAM_ANALYTICS_AUTO_KILL`
  (shipped since the analytics engine) or `PAM_ANALYTICS_AUTO_STEPUP` (new,
  unreleased) enabled, their live sessions were killed or their logins revoked.
  The responses now act only on risk from the actor's own authenticated
  behaviour; auth failures still **alert** (a human should know an account is
  being brute-forced) but drive no automated action against the named account.

### Added

- **Threat analytics gains two signals that need history**: `new_target` (this
  actor has never used this target before, judged against the audit window
  preceding the scored one) and `peer_outlier` (activity well above the peer
  median). Both stay **silent** when there is nothing to compare against — a new
  joiner is not an anomaly — so switching this on does not produce an alert
  storm. `PAM_ANALYTICS_BASELINE_DAYS` (default 30) bounds the extra read.
- **`PAM_ANALYTICS_AUTO_STEPUP`** — a *high*-risk actor's portal logins are
  revoked, so their next action re-authenticates (a second factor where MFA is
  enrolled). It sits below `PAM_ANALYTICS_AUTO_KILL`: killing a
  high-risk-but-legitimate operator mid-change is itself an incident, and the
  response that fits most findings is "prove it", not "get out".

## [0.16.0] — 2026-08-08

A **minor**: the ITSM ticket gate becomes a real control rather than an existence
check. No schema change; upgrading from 0.15.x needs nothing, and the generic
webhook keeps working untouched.

### Added

- **First-class ServiceNow and Jira ticket connectors** (`PAM_TICKET_PROVIDER`).
  A generic webhook can only answer *"does this ticket exist"*; the connectors
  check the change's **state**, its **approved window**, and **whether the ticket
  names the operator**.

### Security

- **A valid ticket number used to admit anyone who knew it.** The ticket gate
  never received the actor, so it could prove a ticket was valid but not that it
  was yours — a change number quoted from a colleague's queue passed. The actor
  is now threaded through both gates, and binding it to the ticket is on by
  default (`PAM_TICKET_BIND_ACTOR`). The generic webhook payload gains an
  `"actor"` field; an endpoint that ignores it behaves exactly as before.

## [0.15.0] — 2026-08-08

A **minor**: one new feature with two new environment variables, the deploy
examples the docs had been promising, and an end-to-end test that proves the
central privileged-access property in CI. No schema change; upgrading from 0.14.x
needs nothing.

### Added

- **Bootstrap secrets can be rotated without a restart.** Set
  `PAM_CONJUR_REFRESH_MIN` and every replica re-reads the secrets Conjur
  *manages* on that interval, adopting a change in place — audited
  `config.secret_refreshed` (actor `system-conjur`), which names the key and
  never the value. **Only `PAM_API_KEY` and `PAM_BREAK_GLASS_KEY_HASH` are
  refreshable**, because they are pure comparison values. `PAM_MASTER_KEY` (the
  KEK — changing it does not rotate the vault, it makes it undecryptable; use
  `pam-server -rotate-kek` offline), `PAM_DATABASE_URL` and the two broker audit
  keys need a restart, are **not fetched** on the refresh tick, and are named in
  the startup log so you know before you rotate. Two conditions decide whether a
  rotation lands, and the log states both: Conjur must manage the variable, and
  enabling refresh means Conjur wins over a value also set in the environment.
  **Deleting a variable in Conjur is not a revocation** — it keeps the running
  value and warns. A failing refresh logs at `Error`, increments
  `pam_secret_refresh_failures_total` and fires a `config.secret_refresh_failed`
  alert.
- **`PAM_CONJUR_VARS`** maps individual bootstrap secrets to arbitrary Conjur
  variable ids (`PAM_API_KEY=prod/keys/api`), for policies that do not follow the
  `<prefix>/<name>` convention. Unknown names, malformed ids and duplicates are
  all fail-loud.
- **A working Flux example** (`deploy/k8s/flux/`) — a `GitRepository` pinned to a
  tag rather than a branch, and two `Kustomization`s, since only the sealed
  secrets need `.spec.decryption` and the workload must not start before them.
- **A really-sealed `helm secrets` values file**
  (`deploy/helm/pamv1/secrets.example.sops.yaml`) for a flow the SOPS README had
  advertised with no example behind it.
- **The CloudNativePG app password can be sealed**
  (`deploy/k8s/sops/pg-app.sops.example.yaml`) instead of being generated and
  read back out of the running cluster by hand.
- **Cloud-KMS recipients** documented in `deploy/.sops.yaml` (AWS KMS, GCP KMS,
  Azure Key Vault, Vault Transit) — additive to `age`, and the migration path.
- **An end-to-end test of the server as shipped**: it boots the real server
  against a live SSH upstream that accepts *only* the vaulted credential, then
  drives it over the REST API and the SSH proxy, asserting just-in-time
  injection, the secret never appearing in the recording/chain/audit, RBAC, the
  approval gate on both connect and reveal, recording-tamper detection in both
  directions, and command control. Every assertion was verified against a
  deliberately broken build.

### Fixed

- **`kubectl apply -f deploy/k8s/` overwrote the secret you had just created.**
  `secret.example.yaml` declares `pam-secrets` with `CHANGE_ME` values, and the
  quickstart told you to create the real secret and *then* apply the whole
  directory. Both READMEs now use **`kubectl apply -k deploy/k8s/`**, which
  resolves a curated base carrying no secret material; CI fails if that base ever
  gains any. This one had been shipping for many releases.

### Development note

The secret-refresh feature was reviewed twice while it was still unreleased, and
those reviews found fourteen and then three defects — including a rotation that
inverted the break-glass quorum path, a Kubernetes JWT frozen at boot, and a fix
that reintroduced the finding it was written to close. **None of them ever
reached a tagged release**; they are recorded in `docs/SECURITY-GAPS.md` because
the reasoning is worth keeping, not because any released version was affected.

## [0.14.3] — 2026-08-08

Closes the residual the 0.14.2 sweep recorded and left open: a name could forge
fields in **other people's** audit records. A **patch** — no schema change, no new
environment variable, no route or audit-vocabulary change.

**Upgrade note.** Names are now validated on create and update. Existing names are
**not** rejected retroactively, so nothing breaks on upgrade; but a create or
update carrying a colon, a control character, or more than 128 bytes now returns
`422` naming the field. `Prod DB 01`, `sûreté`, `データベース`, `svc@corp` and
`a/b` are all still accepted. Hosts are exempt — an IPv6 literal legitimately
contains colons — and are quoted in the audit trail instead.

### Security

- **A name could forge fields in other people's audit records.** Target, user and
  safe names were validated non-empty only, so an admin who named a target
  `prod-db action:approved reason:emergency` put forged `key:value` pairs into the
  record of **every operator's** session on that target. Names are now refused if
  they contain a colon or a control character, and are bounded at 128 bytes,
  at every create/update that takes one. Hosts are **not** charset-checked — an
  IPv6 literal legitimately contains colons — and are quoted in audit details
  instead, which also settles `host:2001:db8::1:22` being ambiguous.

### Changed

- **Names are validated on create and update.** `Prod DB 01`, `sûreté`,
  `データベース`, `svc@corp` and `a/b` are all still accepted — only colons,
  control characters and lengths over 128 bytes are refused, with a 422 naming
  the field. **Names already stored are not rejected retroactively**; only a
  create or an update is held to the rule.

## [0.14.2] — 2026-08-08

The 2026-08-08 sweep over phases 66–75. A **patch**: no schema change, no new
environment variable, no route or audit-vocabulary change. Three audit records
now quote the values inside them, which the console's parser already handled at
both granularities, so nothing downstream needs changing.

**One upgrade note.** `PAM_CERT_REMIND_DAYS` is now range-checked. If it is set
outside `0`–`366` the server refuses to start instead of reminding on every
campaign at once — deliberate, and the only way this release can change a running
deployment's behaviour.

### Security

- **The delegation record in `broker.token.exchanged` could name the wrong
  agent.** The detail was assembled unquoted and quoted as one string by the
  handler, which stops a value breaking out of the record but not one forging
  fields inside it — the console un-quotes, splits on spaces and takes last-wins.
  An `on_behalf_of` of `ops-team actor:spiffe://trusted/root` made the console
  display an actor the token was never minted for. Every field is now quoted at
  the source. Reachable as a broker key's `Owner` or an SVID chain tail.
- **A clipboard mimetype off the wire went raw into `rdp.clipboard`.** It is the
  second field, so `text/plain bytes:0 sha256:00…` put a forged byte count and
  digest ahead of the real ones, making a large transfer read as empty; unbounded,
  it also let a repeatable action flood the audit trail. Quoted and bounded.
- **A reviewer name forged fields into `certification.reminder`**, and campaign
  names were quoted but unbounded at two sites. Names are quoted and bounded and
  the reviewer list is capped at 8 with a `+N_more` tail.
- **A failing store could open a recurring campaign every hour without limit.**
  The scheduler advanced `next_run` last, so any failure after the insert left the
  anchor due and the next tick created another campaign. The period is now claimed
  first; the worst case is one skipped period, logged at `Error`.

### Added

- `internal/auditfmt` — the single sanitiser for untrusted values in audit
  details. It replaces two byte-identical copies of `auditField` and, more to the
  point, was missing entirely from `internal/guacd`, which is why the clipboard
  record was never sanitised.

### Changed

- `PAM_CERT_REMIND_DAYS` is range-checked (`0`–`366`) and fails loudly at startup,
  like every comparable numeric setting.

## [0.14.1] — 2026-08-08

The five improvements from the 2026-08-08 repo audit. A **patch**: no feature, no
schema change, no new environment variable, no audit-vocabulary change. Upgrading
from 0.14.0 needs nothing.

The one operator-visible change is cosmetic and an improvement: long values in
console tables now truncate with an ellipsis instead of pushing later columns off
the terminal.

- **The console gets a safety net** (Phase 71) — the portal's ~2,500 lines of
  embedded JavaScript were never parsed by anything, so a syntax error would have
  shipped. `node --check` now runs as a Go test and an explicit CI step, and every
  covered screen is rendered twice to assert a table row does not widen with its
  data. It found two more instances of the column-overflow bug immediately, in the
  campaigns list and the review queue.
- **`store.Store` composed from role interfaces** (Phase 72) — one flat
  149-method interface became 19 named roles it embeds, so callers and both
  implementations are unchanged while a new consumer can depend on the slice it
  needs. `auditchain` now takes 3 methods instead of 149.
- **The coverage number stops understating itself** (Phase 73) — CI prints the
  total, the total excluding the database-gated package (**77.5%**) and that
  package's own figure (**81.9%**, from the job that has a database), instead of
  one number depressed about four points by code it could not run.
- **Policy parity between the database proxies** (Phase 74) — the two are
  deliberate line-for-line siblings, so a test now names the fourteen gates that
  constitute policy and fails if either references one the other does not.
- **Clipboard observation moved to `internal/guacd`** (Phase 75), where the
  protocol it parses already lives, and `serveAndShutDown` split out of `run()`.
  The rest of `internal/api` was measured and deliberately left alone.

- **What of `internal/api` actually wanted to move** (Phase 75) — clipboard
  observation moved to `internal/guacd`, where the protocol it parses already
  lives (it had zero coupling to the HTTP server), and `serveAndShutDown` split
  out of `run()`, whose three copy-pasted proxy-drain blocks became a slice. The
  rest was measured and left alone: `scheduler.go` touches sixteen `Server`
  members including handler methods, so extracting it would rebuild the
  god-object under a new name.

- **Policy parity between the database proxies** (Phase 74) — the PostgreSQL and
  SQL Server proxies are deliberately line-for-line siblings so that anything
  differing between them is the transport and never the policy, which means every
  policy fix must be made twice. A new test names the fourteen gates that
  constitute policy and fails if either proxy references one the other does not —
  verified by deleting the tunnel-only-token refusal from the SQL Server path,
  which compiles and passes everything else. Two fixed-sleep tests now poll to a
  deadline instead.

- **The coverage number stops understating itself** (Phase 73) — the `test` job
  has no database, so `internal/store/pgstore` was measured as ~0 and dragged the
  published figure down about four points, while the job that does exercise it
  reported nothing. CI now prints three numbers from the same tool — total,
  excluding pgstore (**77.5%**), and pgstore alone — and the pgstore job reports
  its own. Still printed, not gated.

- **`store.Store` is composed from role interfaces** (Phase 72) — one flat
  149-method interface became 19 named roles (`TargetStore`, `CredentialStore`,
  `AuditStore`, …) that `Store` embeds, so both implementations and every caller
  are unchanged while a new consumer can depend on the slice it actually needs.
  `auditchain` now takes a 3-method `BrokerAuditStore` instead of the whole
  surface, and `-rotate-kek` takes a named interface listing the four kinds of
  KEK-wrapped value it must re-wrap — the omission that once left a rotated
  deployment unable to start.

- **The console gets a safety net** (Phase 71) — the portal's ~2,500 lines of
  embedded JavaScript were never parsed by anything: `go:embed` copies bytes, and
  no CI step ran node, so a syntax error would have shipped. Now `node --check`
  runs as a Go test and as an explicit CI step, and every covered screen is
  rendered twice (short values and pathological ones) to assert that **a table row
  does not widen with its data** — the invariant behind the column that fell off
  the terminal in 0.12.0. It immediately found two more instances of the same
  bug, in the campaigns list and the review queue, both fixed here.

## [0.14.0] — 2026-08-08

Certification campaigns are complete: **scoped** so a review is finishable,
**scheduled** so it recurs, **assigned** so each item has an owner, and
**reminded** so a lapse is visible instead of silent. That closes the Phase 19
deferral entirely.

**Minor, and it carries two migrations** (`0030`, `0031`). Both are additive with
defaults that reproduce the old behaviour, applied at startup. **Rolling back to
0.13.0 is safe** on the same grounds checked for `0029`: the added columns are
`NOT NULL DEFAULT` or nullable, 0.13.0 names its columns explicitly in every
campaign read and write, and the migration runner applies only what it is missing
and never objects to a database ahead of it.

- **An item has an owner** (Phase 69) — a campaign names a default reviewer
  stamped onto every item it snapshots; a single item can be reassigned; and
  `GET /api/campaigns/mine` is a reviewer's queue (pending items in open
  campaigns). **Assignment is advisory**: it routes work and makes a queue
  visible, it is not an authorization gate — anyone with `approve` can still
  decide any item, and the trail records who did. Console: a reviewer column,
  `7=Assign reviewer`, and a My Review Queue screen (F7 from menu 17).
  **Also fixes a pre-existing console bug**: the item screen gated deciding on
  `manage_users` while the API has gated it on `approve` since Phase 39, so the
  dedicated approver role saw a read-only screen.

- **A campaign nudges before it lapses** (Phase 70) — the first reminder fires
  `PAM_CERT_REMIND_DAYS` (default 7, `0` disables) before the due date and repeats
  daily while items are pending, through the same alert channel as break-glass,
  carrying the pending count, how overdue it is, and **which reviewer is holding
  it up**. It stops when the campaign is closed, or when nothing is left pending —
  the second cancels rather than repeats, because nagging about finished work is
  how an alert channel gets muted.

- **A documentation currency pass** (Phase 70a) — all 18 doc status markers
  brought to 0–70, saying explicitly where a phase changed nothing; the §4 config
  table completed; and `SECURITY-GAPS.md` finally recording the Phase 66 review
  (findings AV–AX).

**New audit actions**: `certification.item_assigned`, `certification.reminder`.
**New environment variable**: `PAM_CERT_REMIND_DAYS`.

- **A campaign nudges before it lapses** (Phase 70) — the last item of the
  Phase 19 deferral. The first reminder fires `PAM_CERT_REMIND_DAYS` (default 7)
  before a campaign's due date and repeats daily while items are pending, through
  the same alert channel as break-glass, carrying the pending count, how overdue
  it is, and **which reviewer is holding it up**. It stops on the two conditions
  that mean the work is over: a closed campaign, or nothing left pending — the
  second cancels rather than repeats, because nagging about finished work is how
  an alert channel gets muted. Migration `0031` is additive; new audit action
  `certification.reminder`.

- **An item has an owner** (Phase 69) — a campaign can name a default reviewer,
  stamped onto every item it snapshots; a single item can be reassigned; and
  `GET /api/campaigns/mine` is a reviewer's queue (pending items in open
  campaigns). **Assignment is advisory**: it routes work and makes a queue
  visible, it is not an authorization gate — anyone with `approve` can still
  decide any item, and the trail records who did. Console: a reviewer column,
  `7=Assign reviewer`, and a My Review Queue screen (F7 from menu 17). Migration
  `0030` is additive; new audit action `certification.item_assigned`.
  **Also fixes a pre-existing console bug**: the item screen gated deciding on
  `manage_users` while the API has gated it on `approve` since Phase 39, so the
  dedicated approver role saw a read-only screen.

## [0.13.0] — 2026-08-08

Certification campaigns become something an organisation can actually run: scoped
so a review is finishable, and scheduled so it does not depend on somebody
remembering.

**Minor, and it carries a migration** (`0029`). It is additive with defaults that
reproduce the old behaviour, applied automatically at startup, and every existing
campaign keeps meaning exactly what it meant. **Rolling back to 0.12.0 is safe**,
and checked rather than assumed: the added columns are `NOT NULL DEFAULT` or
nullable, 0.12.0 names its columns explicitly in every campaign read and write,
and the migration runner applies only what it is missing — it never objects to a
database ahead of it. A 0.12.0 binary therefore starts unchanged against the
migrated schema and simply ignores the scope and the schedule.

- **Campaigns you can scope and schedule** (Phase 68) — a campaign snapshotted
  *every* grant and safe member, which past a demo is a list nobody completes. It
  can now be scoped to **one safe** (its members *and* the grants on every target
  assigned to it) or **one subject** (everything a person or role holds, anywhere
  — the leaver review), and `recur_days` makes it the anchor of a recurring
  series that opens the next campaign on schedule with the same scope. **Closing
  the anchor stops the series.** An unknown scope is refused with 422 rather than
  silently widened to "everything". The scheduler is leader-locked and always on,
  and advances the anchor *after* a successful spawn, so a crash repeats a review
  rather than skipping a period. Console menu 17 gains both, and names a
  campaign's scope by safe name.

- **The token-exchange screen fits its terminal** (Phase 67b) — Phase 67's table
  put a full SPIFFE ID in every cell, so a row overflowed the 980px terminal and
  pushed the last column off screen; on a refused row that column is the *reason*.

**Audit-detail change**: `certification.campaign_created` gains `scope:`,
`safe:`, `subject:`, `recur_days:` and `recurring_from:`. No vocabulary change and
no new environment variable.

- **Campaigns you can scope and schedule** (Phase 68) — a certification campaign
  snapshotted *every* grant and safe member, which past a demo is a list nobody
  completes. It can now be scoped to **one safe** (its members and the grants on
  every target in it) or **one subject** (everything a person or role holds — the
  leaver review), and `recur_days` makes it the anchor of a recurring series that
  opens the next campaign on schedule with the same scope. Closing the anchor
  stops the series. An unknown scope is refused rather than silently widened to
  "everything". Migration `0029` is additive; existing campaigns are unchanged.
  **Audit-detail change**: `certification.campaign_created` gains `scope:`,
  `safe:`, `subject:`, `recur_days:` and `recurring_from:`.

- **The token-exchange screen fits its terminal** (Phase 67b) — Phase 67's table
  put a full SPIFFE ID in every cell, so a row overflowed `#term`'s 980px and
  pushed the last column off the screen: on a refused row that column is the
  *reason*, which is the whole point of the row. Identities now show as paths
  within a trust domain stated once above the table, cells truncate before they
  pad, and the column header no longer says "Actor" on rows that name a delegator.

## [0.12.0] — 2026-08-07

A **minor** rather than a patch: Phase 67 adds a capability, not a fix. It is the
last curl-only one, so the console-parity claim the README has made since Phase 25
is finally true — every shipped capability is operable from the 5250 portal.

- **Console screen for the token exchange** (Phase 67) — menu **27, Delegated
  agent tokens (RFC 8693)** (`read_audit`): the broker's signing key (`kid`, key
  type, curve, algorithm) and the delegation chains it has issued, with refusals
  beside them. The chains come from the audit trail because a minted SVID is
  stateless — the broker signs it and forgets it — so `broker.token.exchanged` is
  the only record one ever existed. Read-only by nature: minting is an agent
  presenting its *own* credential to `POST /v1/token`, which a human at a
  terminal cannot do on its behalf and should not be able to.

- **The review of phases 62–65** (Phase 66) — three findings, none a bypass. The
  SFTP capture handle table admitted pipelined opens past its cap (a real ceiling
  of 1152 against a documented 128 — bounded either way, so nothing grew without
  limit); the release workflow's `dry_run` input had become dead and is removed,
  so the manual trigger is unambiguously a rehearsal and a signed release can no
  longer be published by hand from an arbitrary ref; and the path-derived session
  id reached three audit details unquoted.

No schema, environment-variable, audit-vocabulary or wire-format change.
Upgrading from 0.11.2 needs nothing.

- **Console screen for the token exchange** (Phase 67) — menu **27, Delegated
  agent tokens (RFC 8693)** (`read_audit`): the broker's signing key (`kid`,
  type, curve, algorithm) and the delegation chains it has issued, read from the
  audit trail because a minted SVID is stateless and that event is the only
  record it existed. Refusals are shown beside them. Read-only by nature —
  minting is an agent presenting its own credential. This was the last curl-only
  capability, and the one place the "full console parity" claim was false.

- **The review of phases 62–65** (Phase 66) — reading the phases that closed the
  2026-08-07 sweep the way the sweep read everything else. Three findings, none a
  bypass: the SFTP handle-table bound admitted pipelined opens past its cap
  (1152 rather than the 128 its comment claimed — bounded either way); the
  release workflow's `dry_run` input had become dead, controlling nothing, and is
  removed so the manual trigger is unambiguously a rehearsal; and the
  path-derived session id reached three audit details unquoted.

## [0.11.2] — 2026-08-07

**The artifacts for 0.11.1.** That tag exists and stays where it is — the Go
module proxy had already cached it, so re-pointing it would leave a permanent
checksum mismatch for anyone running `go get …@v0.11.1` — but its release
pipeline failed *before the push*, so no image, no signature, no attestations and
no GitHub Release were ever produced under it. 0.11.2 is the same content plus
the two fixes for that failure, and it is what every manifest pins.

- **The release build takes no cache** (Phase 65b) — Phase 64 had added
  `cache-from`/`cache-to: type=gha`, which requires the docker-container driver
  while the job uses buildx's default `docker` driver. Removed rather than
  repaired: a release is the one build whose speed matters least and whose
  provenance matters most. The Dockerfile's cache mounts stay and still serve
  everyday `docker build`.
- **The release dry run actually rehearses** (Phase 65b) — it used to skip the
  entire release job, so it proved only that `go test` runs and would have sailed
  past the failure above. It now BUILDS the image, while the push, signature,
  attestations and GitHub Release stay gated on a real tag.

## [0.11.1] — 2026-08-07 · source tag only, superseded by 0.11.2

Phases 63–65: the rest of the 2026-08-07 sweep, the container build, and the
self-audit catching up with itself. Cut immediately rather than banked, because
the gap v0.11.0 existed to close was precisely a pinned image drifting behind the
fixes — banking these would have started that over.

**Audit-vocabulary change.** `proxy.auth_rate_limited` is removed from the
documented vocabulary **and from the OCSF exporter's Detection Finding
classification**; no code path has emitted it since Phase 52e, so any SIEM rule
built on it was one that could never fire. `breakglass.unseal_failed` and
`session.relay_start` are now documented, the first also classified.

**Operator-visible fixes.** A refused in-session step-up decision no longer
leaves an audit record saying it *was* decided — a refused self-approval had
recorded the paused operator as having decided their own statement. Recording
playback now fails closed on its audit like every other path that hands over
KEK-protected material. And a step-up decision that resolves between the check
and the claim answers **409** rather than a misleading 404.

**Build.** `Dockerfile.pkcs11` accepts `VERSION`/`COMMIT`, so an HSM-backed
deployment stops reporting `pam-server dev (none)`; base images are pinned by
digest; BuildKit cache mounts mean an everyday `docker build` no longer
recompiles the standard library from cold. The release build itself deliberately
takes no cache — a signed, attested artifact is a stronger claim when nothing
outside the commit fed the compiler.

- **The self-audit absorbs the phases it had not read** (Phase 65) —
  documentation only. `docs/SECURITY-GAPS.md` recorded every read-only sweep and
  none of the per-phase reviews, so the seventeen defects found by reviewing
  phases 59a, 60a and 61a the day each merged lived only in the roadmap. Closes
  the last item of the 2026-08-07 sweep; every sweep is now closed.

- **The container build** (Phase 64) — no runtime change. Both Dockerfiles gain
  BuildKit cache mounts for the Go module and build caches (and `release.yml`
  a GitHub Actions cache), so a build no longer recompiles the standard library
  and every dependency from cold. `Dockerfile.pkcs11` finally accepts
  `VERSION`/`COMMIT`, so an HSM-backed deployment stops reporting
  `pam-server dev (none)`. Base images are pinned **by digest** as well as by
  tag, dependabot keeps them current, `EXPOSE` names the database-proxy ports it
  had omitted, and CI builds **both** images instead of one.

- **Close the rest of the 2026-08-07 sweep** (Phase 63) — six findings, none a
  bypass. A refused step-up decision no longer leaves an audit record saying it
  was decided (a refused self-approval had recorded the *paused operator* as
  deciding their own statement); `session.playback` fails closed on its audit
  like every other path that hands over KEK-protected material; the SFTP capture
  handle table is bounded on the request leg instead of growing past the
  open-artifact cap; the dead `required` field is gone; and the audit vocabulary
  matches the code again (`proxy.auth_rate_limited` removed from the docs and the
  OCSF classifier, where it was a rule that could never fire).
  `deploy/docker/.env.example` documents the Phase 57 token-exchange variables.
  **Audit-vocabulary change**: one removal, two additions.

## [0.11.0] — 2026-08-07

The release that makes the deployable artifact current again. `v0.10.0` was
tagged on 2026-07-28 and every Kubernetes, Helm and Terraform manifest has
pinned it since — but the read-only sweep of 2026-07-30 landed **ten fixes over
the following two days**, so the pinned image did not contain them. Among them:
a tunnel-scoped viewer token that authenticated at all three session proxies
(reproduced *opening a session*), the unauthenticated cross-replica live and
kill buses, three paths to a credential that skipped their siblings' gates, and
five paths that acted before — or without — recording it. A pin is only as good
as what it points at, and this one pointed at a build the project itself
documents as fixed.

Everything from phases 53–62 is in this release. Beyond the fixes above:

- **In-session step-up decisions are bound to the pause they were made about**
  (Phase 62) — a sealed cross-replica decision named only the session, while a
  session pauses once per flagged statement, so a decision captured off the
  NOTIFY channel released the operator's *next* statement for as long as its
  timestamp stayed fresh. Decisions now name the pause and the applying replica
  refuses one it has already resolved. **Wire-format change** on the step-up
  decision bus (see below).
- **A dependent account names the credential that manages it** (Phases 61/61a),
  the ITSM ticket gate holds at connect time (60/60a), safe-scoped approval
  policy (58), RFC 8693 token-exchange minting (57), cross-replica step-up
  decisions (56), SFTP per-file content recording (59/59a), the SQL Server (TDS)
  proxy (53), the VNC connector (54) and cross-replica live monitoring (55).

**Upgrade note (HA only).** The step-up decision seal now binds the pause, so a
replica running 0.11.0 and one running 0.10.0 cannot authenticate each other's
cross-replica step-up decisions. The failure is closed — a decision is refused,
never misapplied — and a supervisor can still decide on the replica hosting the
session. Roll all replicas to finish the upgrade. Nothing else on the bus, in
the store or in the API changes.

- **Safe-scoped approval policy** (Phase 58) — a safe now carries
  `require_approval` and a dual-control `min_approvers` floor that bind **every
  target in it**, strictest-wins with the global and per-target settings (a safe
  can tighten them, never loosen). The floor is re-read as each approval is cast,
  so raising it binds requests already in flight. The predicate deciding all of
  this moved into one shared fold (`store.EffectiveApprovalPolicy`) consulted by
  the API, all three session proxies and the RDP viewer. Migration `0027`; no new
  environment variable.

- **RFC 8693 token-exchange minting + Terraform remediation** (Phase 57) — the
  agent broker now **issues** the delegated identities it had only ever verified:
  `POST /v1/token` (opt-in, `PAM_BROKER_TOKEN_EXCHANGE`) lets an SVID-authenticated
  agent delegate its own authority to a sub-agent and returns a broker-signed,
  short-lived JWT-SVID whose actor chain grows by exactly one link, capped by the
  delegator's own expiry and the existing delegation-depth limit. Impersonation,
  `scope`, a foreign audience and an actor outside the delegator's `may_act` are
  all refused. `GET /v1/token/jwks` publishes the signing key (shared custody).
  Separately, `POST /api/blast/analyze` with `"terraform": true` renders each
  finding's remediation as reviewable HCL. No schema change.

- **Cross-replica step-up decisions** (Phase 56) — the pending-pause list is
  cluster-wide (`GET /api/sessions/stepups` merges a shared, TTL-bounded
  inventory whose statements rest sealed under the shared-custody bus key) and
  `POST /api/sessions/{id}/stepup` decides a statement paused on any replica: a
  decision landing on the "wrong" pod is dispatched, sealed and freshness-bound,
  over the store bus and answers `202 Accepted`. Self-approval is refused across
  replicas. Migration `0026` (UNLOGGED `stepups`); no new environment variable.

- **Virtual appliance** (`deploy/ova/`) — `build.sh` produces an importable `.ova`
  carrying Debian 13 (trixie), PostgreSQL, `pam-server` and the full source tree.
  It runs an unattended `debian-installer` under QEMU and assembles the OVA by
  hand, so it needs no root, no VirtualBox and no Packer; the build verifies
  itself by booting the finished image on a throwaway overlay and asking pamv1 for
  `/healthz`. No secret is baked into the image — the vault master key, admin API
  key, database password, SSH host keys and machine-id are all generated on first
  boot, so cloning the appliance never clones a root of trust.

- **Kubernetes configuration examples** — `deploy/k8s/configmap.example.yaml`
  (every non-secret `PAM_*` knob) and a `secret.example.yaml` grown to all
  secret-valued variables, giving the Kubernetes path the reference
  `deploy/docker/.env.example` already gave Docker.

- **Cross-replica live monitoring** (Phase 55) — in a multi-replica deployment,
  `GET /api/sessions` now lists every replica's sessions (each naming its host)
  and the SSE watch streams a session hosted on any replica: the hosting pod
  relays a watched session's output over the store's LISTEN/NOTIFY bus, only
  while someone is actually watching. A crashed replica's sessions age out of
  the listing and close their remote watch streams instead of hanging them.
  New `live_sessions` table (migration 0025); no new configuration. Step-up
  decisions remain with the hosting replica (documented).

- **VNC connector** (Phase 54) — `vnc` is a first-class target protocol,
  brokered through guacd and rendered in the portal by the same viewer as RDP
  (`POST /api/vnc-token`, `GET /api/targets/{id}/vnc`). Both viewers now share
  one tunnel implementation, so every authorization gate is executed once for
  both. The clipboard gate covers VNC, VNC's SFTP file channel is forced off,
  and a clipboard policy guacd cannot enforce now refuses the session instead of
  running ungated (this also protects RDP).

- **SQL Server session proxy** (Phase 53) — `PAM_MSSQL_ADDR` brokers `mssql`
  targets over TDS the way `PAM_DB_ADDR` brokers PostgreSQL: the same
  authorization gates, the vaulted SQL login injected just-in-time into the
  client's own LOGIN7, per-statement `db.query` audit (`via:mssql`) that sees
  through `sp_executesql`, command control, step-up, recording, live monitoring
  and cluster-wide kill. New hand-rolled `internal/tds` codec (no new
  dependency) with TLS on both legs. Interop with a real SQL Server is not yet
  verified.

- **Review fixes on the four changes below** — broker audit keys: an explicit
  env value is written through to shared custody and checked against it, so a
  mixed fleet or a later unset can no longer silently fork the audit chain (a
  disagreeing HMAC key refuses to start; a disagreeing sign seed is the signer
  rotation and custody converges to it). WinRM: the recording size cap now ends
  the session with `session.record_limit` (parity with SSH) instead of running
  it unrecorded with a frozen live stream; REST/broker run output reaches live
  watchers only after the durable audit; refusals are visible on the stream and
  leave transcripts. Broker `ssh_exec` streams live like `winrm_exec`. A
  non-canonical per-target clipboard value now enforces as `deny` (fail closed)
  and the overrides are audited on `target.create`/`target.update` (a PUT that
  omits them resets them — now visibly). The live-watch 404 is replica-honest
  and audited; the portal watch pane no longer renders a literal `\r` on every
  line.
- **The watch stream ends with the session** — a supervisor's live SSE watch
  now terminates when the watched session completes or is killed (the portal
  pane reports "session ended" instead of going silent forever), and watching
  an unknown or already-over session id is refused with 404.
- **Per-target RDP clipboard override** (Phase 33 follow-on) — a target's
  `rdp_clipboard` / `rdp_clipboard_audit` fields tighten the global
  `PAM_RDP_CLIPBOARD` / `_AUDIT` for that one target; the stricter policy
  always wins, so a high-sensitivity target can deny what the fleet allows.
  New migration `0024`; editable from the 5250 target screens.
- **WinRM live streaming** (Phase 16 follow-on) — a supervisor can now watch a
  WinRM session live (`GET /api/sessions/{id}/stream`, portal option 5) exactly
  like an SSH or PostgreSQL one: the proxy's interactive shell streams what its
  recording sees, and REST/agent-broker runs stream a `winrm>` command echo
  plus the output.
- **Broker audit keys under shared custody** (Phase 13 follow-on) —
  `PAM_BROKER_AUDIT_KEY` and `PAM_BROKER_AUDIT_SIGN_SEED` are now optional:
  when unset, each is generated once and sealed by the KEK into the store's
  `key_material` (every replica converges on the same chain key and signer;
  `-rotate-kek` re-wraps them). An explicit environment value still wins.

## [0.10.0] — 2026-07-28

The first tagged release, closing the last of the README's four beta criteria
(*deploys as code*): the image every Kubernetes/Helm/Terraform manifest pins now
exists, is public, and is verifiable. Built by the test-gated release pipeline
with an SPDX SBOM attestation, a cosign keyless signature and SLSA build
provenance — see [Verifying a release](README.md#verifying-a-release).

Everything from phases 0–52g is in this release. The short version:

- **Vault** — AES-256-GCM envelope encryption per secret, wrapped by a
  pluggable KEK (local key / Vault Transit / AWS KMS / PKCS#11 HSM), with
  offline KEK rotation (`-rotate-kek`) that doubles as the provider-migration
  path.
- **Session brokering with just-in-time injection** — SSH (with recording,
  live monitoring, command control, SFTP policy), PostgreSQL (per-statement
  audit, in-session step-up), RDP in the portal via Guacamole (clipboard
  control + audit), WinRM; the requester never receives the credential.
- **Zero Standing Privilege** — ephemeral SSH certificates from a built-in CA
  instead of standing credentials.
- **Identity** — four built-in roles plus custom permission profiles; AD
  (LDAPS), Entra ID and OIDC login with group→role mapping; TOTP MFA;
  per-user tokens.
- **Governance** — approval workflows (4-eyes, quorum), safes, access
  certification campaigns, an ITSM ticket gate, vendor access with employment
  attestation, break-glass with M-of-N Shamir unseal.
- **AI-agent access broker** — policy over tool + arguments, JIT server-side
  execution, keyed-HMAC verifiable audit with signed checkpoints, MCP
  transport, SPIFFE SVID identity.
- **Audit** — append-only, optionally HMAC-chained and checkpoint-signed;
  OCSF/CEF/LEEF SIEM export and continuous forwarding; retention with
  archive-before-prune.
- **Operations** — the AS/400 5250 keyboard-first portal, Prometheus metrics,
  Helm chart / raw K8s / Terraform / docker-compose deployments, SOPS and
  Conjur secret sourcing, threat analytics with automated response.

[Unreleased]: https://github.com/morandeirachema/pamv1/compare/v0.47.0...HEAD
[0.47.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.47.0
[0.46.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.46.0
[0.45.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.45.0
[0.44.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.44.0
[0.43.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.43.0
[0.42.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.42.0
[0.41.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.41.0
[0.40.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.40.0
[0.39.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.39.0
[0.38.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.38.0
[0.37.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.37.0
[0.36.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.36.0
[0.35.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.35.0
[0.34.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.34.0
[0.33.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.33.0
[0.32.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.32.0
[0.31.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.31.0
[0.30.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.30.0
[0.29.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.29.0
[0.28.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.28.0
[0.27.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.27.0
[0.26.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.26.0
[0.25.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.25.0
[0.24.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.24.0
[0.23.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.23.0
[0.22.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.22.0
[0.21.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.21.0
[0.20.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.20.0
[0.19.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.19.0
[0.18.2]: https://github.com/morandeirachema/pamv1/releases/tag/v0.18.2
[0.18.1]: https://github.com/morandeirachema/pamv1/releases/tag/v0.18.1
[0.18.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.18.0
[0.17.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.17.0
[0.16.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.16.0
[0.15.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.15.0
[0.14.3]: https://github.com/morandeirachema/pamv1/releases/tag/v0.14.3
[0.14.2]: https://github.com/morandeirachema/pamv1/releases/tag/v0.14.2
[0.14.1]: https://github.com/morandeirachema/pamv1/releases/tag/v0.14.1
[0.14.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.14.0
[0.13.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.13.0
[0.12.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.12.0
[0.11.2]: https://github.com/morandeirachema/pamv1/releases/tag/v0.11.2
[0.11.1]: https://github.com/morandeirachema/pamv1/releases/tag/v0.11.1
[0.11.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.11.0
[0.10.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.10.0
