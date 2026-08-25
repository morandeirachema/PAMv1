# pamv1 — Security Gaps (findings, fixes, and remaining work)

> 🟢 **Living document** — updated in the same change as the code, without a separate ask (see the [docs hub](README.md)).

> **Purpose.** This is a self-audit of pamv1 against the security posture expected
> of a Privileged Access Management system. It records every gap found in a
> read-only review of the codebase, whether each was **fixed**, **mitigated**, or
> **deferred** (a whole subsystem / new roadmap phase), and where the change
> lives. pamv1 is educational ("for learning purposes") — this document is part of
> that: it shows the reasoning, not just the result.
>
> Last updated: 2026-08-25 · Reflects: Phases 0–200 + the 2026-07 hardening
> passes, including the **post-beta sweep of 2026-07-27** (thirty findings, all
> closed), the **sweep of 2026-08-07** over phases 56–61a (nine findings: two
> closed by Phase 62, six by Phase 63, half of one withdrawn as a false
> positive), the **per-phase reviews of 56–61a**, and the **2026-08-12 audit
> sweep** (two findings, both closed by Phase 108) — the section immediately
> below. 109–161 are feature phases, not review sweeps; their security-relevant
> properties are described where they ship ([ADMIN-GUIDE.md](ADMIN-GUIDE.md),
> [PROTOCOLS-AND-CRYPTO.md](PROTOCOLS-AND-CRYPTO.md)) rather than re-audited
> here — **except where a research pass found a live defect rather than a gap in
> capability**, which the 2026-08-17/18 passes aimed at the AI-agent broker did
> five times over (section below: four-eyes inert on the SPIFFE path, a
> quarantine that stopped at the presenter, an inventory tool that discarded its
> principal, two advertised policy controls that enforced nothing, and a policy
> engine with no principal side — all closed by phases 169–173). **Two later
> self-sweeps (phases 176 and 182) then audited that batch's own output** and
> found three more of the same shape, one of them a single phase old — recorded
> in the section above the research one, along with what that says about relying
> on per-phase review. The first of
> those passes had already produced **one detection-integrity finding**: it found
> that `internal/ocsf` classified
> `broker.tool_call.denied` as a Detection Finding while no code could write
> that name to the trail the exporter reads, and that `isFinding`'s
> `_denied`/`_failed` suffix rules never matched pamv1's DOTTED action names, so
> `agent.disable.failed` exported as routine activity. Both are the same class
> of defect — **a control that reads as coverage and provides none**, which is
> worse than a missing control because nobody goes looking for it. Both were
> closed in Phase 161, and the class is now guarded by
> `ocsf.TestFindingExactActionsAreEmittable`, which walks `internal/` and `cmd/`
> and fails on any classified action no code can emit.

## How the review was run

Six independent read-only passes over the ~20k-LOC tree, one per security-critical
dimension — at-rest crypto & secret leakage, authentication/RBAC/break-glass, the
session proxy (SSH + PostgreSQL), the REST API surface & audit completeness, the
tamper-evident audit chain & logging, and deployment/IaC — cross-checked against
each other. The system's central invariant held throughout: **the operator never
receives the vaulted credential** (JIT decryption happens strictly after every
authorization gate, proven against a real upstream that accepts only the vaulted
secret), AAD parity is exact across all encrypt/decrypt sites, `SecretEnc` never
serializes, and no secret is written to logs. The gaps clustered on the **trust
boundaries around** that core — upstream authentication, audit integrity, and a
few authorization edges.

A **second full sweep on 2026-07-27**, run right after the beta milestone,
covered six dimensions in parallel — the authorization surface re-derived from
the route table, concurrency and resource lifetime, fail-open error handling,
cryptography and secret handling, input validation, and the correctness of the
newest code (phases 44–51). Its findings are in
[the 2026-07-27 sweep section](#the-2026-07-27-post-beta-sweep--all-30-findings-now-closed).
The core invariant held again; what it found clustered at the edges rather than
the centre — the one HTTP handler that authenticated itself, cancellation and
deadlines around the session path, and an offline maintenance command that had
not kept pace with the features built around it. All thirty are now fixed.

A **fourth sweep on 2026-08-07** covered phases 56–61a, the ~4k lines that had
never been read as a whole, and is in
[the 2026-08-07 sweep section](#the-2026-08-07-sweep--the-six-phases-nobody-had-read-as-a-whole).
Its lesson is the one this document keeps re-learning from a different angle: the
two findings that mattered were both **a control that was correct about the wrong
noun**. A decision bus seal bound the *session* when a session pauses many times,
and an image pin named a *version* when what was needed was the version's
contents. Neither is a missing control; both are a control aimed one level off.

## Status legend

- **Fixed** — code changed + test; the gap is closed.
- **Mitigated** — a fail-closed opt-in / hardening knob was added; the insecure
  behavior is no longer the *only* option (default kept for the demo where a hard
  change would break the quickstart).
- **Deferred** — a missing capability that is a new roadmap phase, not a bug.

---

## Tier 1 — Authorization & audit integrity (fixed)

| # | Gap | Status | Fix |
|---|-----|--------|-----|
| 1 | **Empty-safe default-allow.** A target placed in a safe with no members fell through `CanConnectTarget`'s "no grants ⇒ open" branch, so it was reachable by *any* connect-capable user — the opposite of safe containment. | **Fixed** | `CanConnectTarget` now takes a `safeScoped` flag: a safe-scoped target with no matching grant is default-DENY. All five call sites pass `target.SafeID != nil`. Tests: `auth.TestCanConnectSafeScoped`. |
| 2 | **DB proxy skipped the MFA enroll-only gate.** `PAM_MFA_REQUIRED` was bypassable for PostgreSQL targets — the SSH proxy and HTTP API rejected enroll-only sessions, the DB proxy did not. | **Fixed** | `internal/proxy/dbproxy.go` now rejects `principal.EnrollOnly` before any other gate. Test: `proxy.TestDBProxyEnrollOnlyRejected`. |
| 3 | **Fail-open auditing.** A credential reveal/checkout/app-fetch was returned even if the durable audit write failed — violating "every secret use appends an audit event." | **Fixed** | New `mustAudit`/`mustAuditAs` (API) and `appendAuditErr` (proxy) fail CLOSED: no durable audit ⇒ HTTP 503 / session refused. Applies to reveal, checkout, app-secret, and both proxies' session-start (audited *before* decryption). Test: `api.TestRevealFailsClosedWithoutAudit`. |
| 4 | **Upstream SSH host key / DB TLS unverified by default.** Both legs carry the JIT-decrypted credential; the DB leg had *no* way to verify at all. | **Fixed (DB) / Mitigated (SSH)** | DB proxy: `PAM_DB_UPSTREAM_CA` (pinned bundle) or `PAM_DB_UPSTREAM_TLS_VERIFY` (system roots) now verifies the upstream cert fail-closed, and refuses plaintext when verification is demanded. SSH host-key pinning via `PAM_SSH_KNOWN_HOSTS` already existed (loud warning when unset). |
| 5 | **No brute-force throttling on the proxy auth paths.** SSH (:2222) and DB (:5433) were an unthrottled online oracle against the operator-chosen `PAM_API_KEY`. | **Fixed** | Per-source-IP fixed-window limiter (`PAM_PROXY_AUTH_RATE_LIMIT`, default 10/min) on both proxies, mirroring the API limiter. Tests: `proxy.TestAuthRateLimiter`. |
| 6 | **Rate limiter blind to `X-Forwarded-For`.** Behind the documented TLS-terminating reverse proxy, every client shared one bucket. | **Fixed** | `PAM_TRUSTED_PROXY_HOPS` selects the real client IP from the trusted tail of XFF; 0 (default) keeps the anti-spoofing RemoteAddr behavior. Test: `api.TestClientIPTrustedProxy`. |

### Second pass (2026-07-26, Phase 37)

A later read-only sweep — route→capability map, child-resource handlers, and the
four authentication surfaces compared against each other — found two more
authorization gaps and one class of missing control. All three are **fixed**;
what the same sweep found and did **not** fix is listed under
[Open findings](#open-findings-from-the-2026-07-26-sweep) below.

| # | Gap | Status | Fix |
|---|-----|--------|-----|
| 24 | **Cross-safe member deletion.** `deleteSafeMember` ran `canManageSafe` against the safe **in the path**, then deleted by the member's *global* id — so a delegated `can_manage` member of one safe could strip a member from **any** safe by its id. Delegated safe administration became a lever to remove access anywhere. | **Fixed** | The member must belong to the safe in the path (404 otherwise), matching `deleteTargetGrant`/`deleteAppSecretGrant`, which already scoped correctly. Test: `api.TestSafeMemberDeleteScopedToSafe`. |
| 25 | **Dependency delete ignored its parent.** `deleteDependency` never read the `{id}` credential in its route, so one credential's route could unlink another's consumer, and the audit detail (`dependency:%d`) recorded no credential. | **Fixed** | Scoped to the path credential; the audit now names it (`credential:%d dependency:%d`). Admin-capability-gated, so this was audit fidelity + correctness, not privilege escalation. Test: `api.TestDependencyDeleteScopedToCredential`. |
| 26 | **Bearer auth failures neither throttled nor audited.** Gap #5 closed this for the SSH/DB proxies, but a wrong `X-API-Key`, agent key or **application** key was only `log.Warn`ed. Token guessing against `/api/*`, `/v1/tool-calls` and `/v1/app-secrets` (the last vends plaintext secrets to machines) was an unthrottled online oracle, and because the failures never reached the audit trail they were invisible to the risk engine (`analytics.authFailActions`) and the Phase-35 SIEM forwarder. | **Fixed** | `Server.authFailed` handles all three surfaces: a per-source-IP **failure** limiter (own window on the `PAM_AUTH_RATE_LIMIT` budget) → 429 past the budget, and each admitted failure appends **`api.auth_failed`** with the surface, method, path and client IP — never the presented credential. The append is skipped once throttled, so a flood can't amplify into the audit trail. `api.auth_failed` is scored as an auth-failure signal. Tests: `api.Test{APIKey,AppKey,AgentKey}FailureThrottledAndAudited`. |

## Tier 2 — Consistency & hardening (fixed / mitigated)

| # | Gap | Status | Fix |
|---|-----|--------|-----|
| 7 | Break-glass not audited on `authenticated`-only endpoints (`/me`, `/logout`, `/mfa/*`). | **Fixed** | The `authenticated` middleware now calls `noteBreakGlass`. |
| 8 | Directory (AD/SSO) login sessions never revoked on disable; no admin session-kill. | **Fixed** | New `GET /api/login-sessions` + `POST /api/login-sessions/revoke` (CapManageUsers); identity reconcile now also revokes sessions whose directory subject is disabled/absent. Store gains `ListSessions` + `DeleteSessionsByUsername`. Test: `api.TestRevokeLoginSessions`. |
| 9 | `exportAudit` and `listBrokerAudit` were unbounded (auditor-gated memory exhaustion). | **Fixed** | `exportAudit` defaults to a 90-day window when `since` is unset; `listBrokerAudit` clamps `limit` to 1..500 like `listAudit`. |
| 10 | App-secret fetch bypassed the reveal-disabled kill switch. | **Fixed** | `fetchAppSecret` now honors `revealDisabled`. |
| 11 | SCRAM server-signature not verified on the DB upstream (forfeits SCRAM mutual auth). | **Fixed** | `scramAuth` recomputes and constant-time-compares the ServerSignature. Test: `proxy.TestSCRAMMutualAuthVerified` (an honest upstream is accepted; a tampered signature and a foreign nonce are refused; unsupported mechanisms never downgrade). |
| 12 | PostgreSQL fast-path (`FunctionCall`) evaded per-statement audit. | **Fixed** | The relay now audits `FunctionCall` frames. |
| 13 | No strength floor on `PAM_API_KEY` (a 1-char admin key started). | **Mitigated** | Rejected below 16 chars on a real (non-`memory`) database, unless `PAM_ALLOW_WEAK_API_KEY=true`; the in-memory demo is exempt so the quickstart still works. Tests in `config`. |
| 14 | `-rotate-kek` only handled local→local master-key rotation; KMS/HSM KEKs had no re-wrap path, and no audit event. | **Fixed** | `-rotate-kek` now builds both KEKs from `PAM_KEK_*` / `PAM_NEW_KEK_*` (any provider — enables local→KMS migration) and writes a `vault.kek_rotated` audit event. |
| 15 | Plaintext HTTP by default; TLS opt-in. | **Mitigated** | `PAM_REQUIRE_HTTPS` refuses to start without native TLS; a loud warning is logged otherwise. (Default kept permissive for the loopback demo.) |
| 16 | DB proxy operator leg cleartext by default. | **Mitigated** | `PAM_REQUIRE_DB_CLIENT_TLS` refuses to start the DB proxy without operator-leg TLS. |
| 17 | No K8s NetworkPolicy in any deploy flavor. | **Fixed** | `deploy/k8s/networkpolicy.yaml` (default-deny) + a gated Helm template (`networkPolicy.enabled`). |
| 18 | `:latest` image tags in the terraform and conjur manifests. | **Fixed 2026-07-28** | Pinned to `0.10.0` (matching the raw k8s deployment) with a comment to pin by digest. Was **reopened** the same day because `0.10.0` had never been published — a pin to a nonexistent image is a dangling pointer, not a fix — and closed hours later when **v0.10.0 was actually released**: the tag ran the test-gated pipeline, which published `ghcr.io/morandeirachema/pamv1:0.10.0` (digest `sha256:ab2a5fa5db27fae805f9096dfdf526497ddff4cc3774b33469ab108b98637b39`, public, anonymous pull verified) with a cosign keyless signature, SPDX SBOM attestation and SLSA provenance. |
| 19 | Container healthcheck hard-coded `http://`, breaking under native TLS. | **Fixed** | `runHealthcheck` matches the served scheme (`https` when `PAM_TLS_CERT/KEY` set). |
| 20 | SSH-proxy grant check used a stripped principal (dropped multi-group/custom-profile — fail-closed but denied valid users). | **Fixed** | The handshake now carries the full role set (`ext["roles"]`), reconstructed for `CanConnectTarget`. |
| 21 | Alert webhook accepted `http://` with no warning. | **Mitigated** | A startup warning is logged for a non-HTTPS, non-loopback webhook. |
| 22 | Revoking access left in-flight proxied sessions running (grants/users checked only at connect time). | **Fixed** | Revoking a login, a directory-disable during reconcile, or deleting a *user* grant now kills the matching live sessions (`session.killed`). Role-grant deletions affect only new connections. Since Phase 34 the kill is **cluster-wide** (broadcast over the store, applied on whichever replica hosts the session). |
| 23 | No cap on concurrent sessions or recording size (resource-exhaustion DoS; a runaway session could fill the recording disk). | **Fixed** | `PAM_MAX_SESSIONS_PER_USER`/`PAM_MAX_SESSIONS_TOTAL` cap concurrent proxied sessions (checked before decrypt); `PAM_MAX_RECORDING_MB` terminates a session that exceeds the recording cap (`session.record_limit`) rather than run it unrecorded. All default off; per-replica in HA. |

## Not changed by design (documented trade-offs)

- **Command control (`cmdguard`) is exec-path only** and best-effort — interactive
  PTY shells stream unparsed, and the exec path is regex over the command string.
  This is inherent (real containment needs a parsing shell/PTY layer) and already
  documented; it must not be read as an enforcement boundary. Use observer sessions
  or restrict shell access for true containment. **SFTP is the exception:** as of
  Phase 32 the proxy parses the SFTP subsystem stream (a distinct binary protocol,
  not raw PTY keystrokes) to audit every file operation and, under
  `PAM_SSH_SFTP=readonly`/`deny`, refuse writes or the subsystem outright — so file
  *transfer* is now audited and gatable even though interactive shell *content* is
  not. **Phase 51** added the missing dimension: `PAM_SSH_SFTP_DENY_FILE` gates by
  **path** (the same regex-denylist engine as command control), refused in every
  mode including reads and on both sides of a rename, since a path an operator can
  still download is not denied at all. (File transfer initiated as `scp` over an interactive shell, or shell
  redirection, still rides the unparsed PTY and is out of scope — use `readonly`
  plus shell restriction for containment.) The **RDP** viewer got the same treatment in Phase 33: `PAM_RDP_CLIPBOARD` gates the Guacamole clipboard bridge (copy-out / paste-in) and drive redirection is always disabled, so the graphical session's side-channels are audited/gatable too. **Phase 50** added the observation half: `PAM_RDP_CLIPBOARD_AUDIT` records each transfer's direction, mimetype, size and SHA-256 as `rdp.clipboard` (content only under an explicit `full` opt-in — a privileged clipboard routinely carries a just-copied password, and the trail is auditor-readable).
- **SFTP inspection is fail-open; TDS statement inspection is fail-closed** — a
  deliberate asymmetry, recorded here because the two now sit side by side. The
  SFTP inspector (`internal/proxy/sftpguard.go`) parses the subsystem stream to
  audit and gate file operations, but a stream it cannot frame is audited once
  (`sftp.parse_error`) and then forwarded **un-inspected** for the rest of the
  session — after that neither the audit, the path denylist nor the `readonly`
  refusals apply. The SQL Server proxy took the opposite choice in Phase 53: a
  statement it cannot parse is **refused** when a command guard is configured,
  because forwarding an unfilterable statement is the bypass the guard exists to
  prevent. For fail-closed file transfer today, use `PAM_SSH_SFTP=deny`. Making
  the SFTP path refuse-on-unparseable (under the same "only when a policy is
  configured" rule) is the obvious follow-on.
- **Session recording is fail-open unless `PAM_REQUIRE_RECORDING`** — the opt-in
  fail-closed control exists **for the SSH, WinRM-over-proxy and PostgreSQL
  paths**; the default is kept permissive for demos. The 2026-07-27 sweep found
  it does **not** reach the in-portal RDP viewer or the REST WinRM endpoint
  (finding Z above), so on those two the flag is currently a no-op — that is a
  gap to close, not a trade-off.
- **Decrypted plaintext lives in Go `string`s** (only the data key is zeroed) —
  inherent to idiomatic Go; strings are immutable and can't be wiped.
- **Inventory listing is not scoped by per-target grants** — `CapReadInventory`
  exposes target/credential *metadata* (never secrets); connect/reveal/checkout are
  grant-scoped. This is the documented access model, not a leak.
- **Credential create is two store calls** (insert row → encrypt secret under its
  row id), so a crash between them can orphan an empty-secret row. Inherent to the
  AAD-binds-row-id design; a client cancel already rolls back.
- **Audit retention is refused while the HMAC chain is on** (Phase 36). Deleting
  the oldest audit rows breaks `VerifyAuditChain` (it requires the first row's
  `prev_hash` to be nil), so the retention worker prunes audit rows only for the
  *unchained* table and skips (loudly) when the chain is enabled. This is a
  deliberate integrity-over-convenience choice: tamper-evidence is never silently
  traded for disk space. Since **Phase 49** `PAM_RETENTION_ARCHIVE_DIR` makes the
  scheduled **WORM export** happen automatically even with the chain on (JSON
  Lines, digest-stamped into `audit.archived`) — only the delete stays a manual
  re-anchor — and for the unchained table the prune runs **only if that archive
  succeeded**. Recording-file pruning always runs (it preserves the `.chain` head),
  and with an archive configured aged recordings are moved there rather than deleted.

## Open findings from the 2026-07-26 sweep

Found by the same pass, **not** fixed in it — each is a phase-sized change or a
deliberate design decision to take, not a one-line correction. They are recorded
here rather than left implicit. **Every finding has since shipped** (Phases
38–45, struck through below); what remains planned are the smaller follow-ons
listed in the **[ROADMAP](../ROADMAP.md#what-is-left-)**, which is the
authoritative place for what happens next — this table is the finding, the
roadmap is the plan.

| # | Finding | Why it matters | Direction |
|---|---|---|---|
| ~~A~~ | ~~**Session recordings are stored unencrypted.**~~ | Was: credentials got envelope encryption while the recording — everything the operator typed and saw — got file permissions only, readable by anyone with volume, backup or snapshot access. | **Fixed in Phase 41** (opt-in, `PAM_RECORDING_ENCRYPT`) — `internal/recording` seals a recording as a stream of AES-256-GCM chunks under a per-recording data key wrapped by the deployment's KEK, so it inherits the same root of trust as the vault. The SHA-256 is taken over the bytes **on disk**, so the audited hash and the recording hash chain keep describing the stored artifact unchanged. Chunked rather than one blob so a killed session still decrypts up to its last complete chunk; each chunk's AAD binds it to its recording and index, so chunks cannot be reordered or spliced. Playback detects the format per file, so recordings written before it was enabled still replay. **The name was covered later:** `PAM_RECORDING_OPAQUE_NAMES` (Phase 48) names recordings `<unixnano>_<random hex>`, moving the target/actor mapping into the audited `session.record`/`winrm.run` event — where reading it needs `read_audit`, the same gate as replaying the recording. Tests: `recording` (round-trip, tamper, splice, truncation, KEK failure), `proxy.TestSessionRecordingIsSealedOnDisk`, `api.TestRecordingSealedAtRestButReplayable`. |
| ~~B~~ | ~~**Per-pod SSH host key and ZSP CA key.**~~ | Was: scaling past one replica gave each pod its own host key (operators saw host-key-changed warnings indistinguishable from a MITM) and its own CA (a certificate minted on one pod was not trusted where another's CA was installed), and broke the operator-cert challenge that is keyed off the CA private key. | **Fixed in Phase 42** — `internal/keycustody` claims both keys in the store, vault-encrypted with an AAD binding each envelope to its name, via an atomic `EnsureKeyMaterial` (migration `0022`; `INSERT … ON CONFLICT DO NOTHING` then read back) so racing replicas converge on one key. An existing on-disk key **seeds** custody, so upgrading a single node does not rotate its host key; other replicas adopt and mirror it. A key that cannot be unwrapped is fatal — never a silent regeneration. Recording scatter is unrelated and stays open (see §HA). Tests: `keycustody` (8 replicas converge, file seeds, sealed + name-bound, unwrap failure fatal) and the store contract, which runs against live PostgreSQL in CI. |
| ~~C~~ | ~~**Command control does not cover every path with a discrete command.**~~ | Was: a pattern blocked for a human on the SSH proxy ran freely through the REST WinRM endpoint and the agent broker — the least-trusted actor. | **Fixed in Phase 38** — the guard moved to `internal/cmdguard` and one instance is shared by both proxies and the API server. `Server.guardCommand` enforces it in `execWinRM` (the chokepoint the REST endpoint and the broker's `winrm_exec` share) and in `sshExecTool.Execute`, **before** the JIT decrypt, auditing `command.blocked` with the matched pattern. Tests: `api.TestWinRMRunCommandBlocked`, `api.TestBrokerWinRMCommandBlocked`, `api.TestBrokerSSHExecCommandBlocked`. |
| ~~D~~ | ~~**The REST WinRM endpoint runs outside the live-session registry.**~~ | Was: a WinRM run was absent from `GET /api/sessions`, unkillable, uncounted against `PAM_MAX_SESSIONS_*`, and out of reach of the analytics auto-kill and the vendor sweeper. | **Fixed in Phase 40** — a new `Server.superviseSession` caps, registers and cancels a brokered execution, and **every** execution path uses it: the REST WinRM endpoint *and* the agent broker's `winrm_exec`/`ssh_exec` tools (which had the same hole). The cap runs before the just-in-time decrypt, so a refused run never causes a secret to exist; a kill cancels the run's context and it returns 503. Test: `api.TestWinRMRunIsASupervisedSession`. |
| ~~E~~ | ~~**Step-up decisions are gated on `CapReadAudit`.**~~ | Was: the role defined as read-only could release a statement the step-up policy flagged — an execution-authorizing power. | **Fixed in Phase 39** — `POST /api/sessions/{id}/stepup` now requires `CapApprove`. Listing paused statements stays `CapReadAudit` (the live-monitor gate), so a supervisor still sees everything they watch; only the release is an approver's act. Test: `api.TestStepUpEndpoints`. |
| ~~F~~ | ~~**Certification decisions have no separation of duties.**~~ | Was: only `CapManageUsers` (i.e. an admin) could certify or revoke, so the principal who grants access was the only one who could attest to it. | **Fixed in Phases 39 + 46** — Phase 39 moved the decision to `CapApprove`, so a dedicated `approver` runs the recertification without holding the access-granting capability (creating/closing a campaign stay `CapManageUsers`). Phase 46 closed the remaining hole with **per-item four-eyes**: every grant records its creator (`target_grants.created_by`, `safe_members.created_by`, migration `0023`), the campaign snapshot carries it (`campaign_items.granted_by`, shown as "granted by X" in the item detail), and certifying an item you granted yourself is refused 403 + audited `certification.decision_denied`. Self-revoke stays allowed (it reduces access); pre-migration rows with no recorded creator are not blocked retroactively. Tests: `api.TestCertificationAuthz`, `api.TestCertificationFourEyes`, the store contract. |
| ~~G~~ | ~~**Console parity has drifted since Phase 25.**~~ | Was: nine capabilities had no screen. Two of them — a parked agent tool call and a paused SQL statement — are human decisions **with a deadline**, which is what made curl-only actually cost something. | **Fixed across Phases 43 + 45** — Phase 43 shipped the two time-critical screens (*Approve AI-agent tool calls*, menu 20, showing the arguments the policy matched on; *In-session step-up decisions*, menu 21). Phase 45 shipped the other seven: vendors & contract grants (22), operator SSH certificates (23), identity blast radius (24), login-session revocation (25), agent keys (26), credential dependencies (option 9 on a credential), and the audit chain verify / signed head / OCSF export on the audit screen. One deliberate new route: `GET /api/ca/ssh/certs` (CapReadInventory) — the issued-cert serials a revocation needs were listable in the store but invisible over HTTP. All verified against a running server; the console is back at **full parity**. |
| ~~H~~ | ~~**No update endpoints and no pagination.**~~ | Was: the `Store` interface had create/delete but no update for targets, safes, users or vendors — fixing a target's port meant delete + recreate, cascading away its credentials, grants, dependencies and safe assignment — and no list method except the audit reads was bounded (an authenticated memory-exhaustion vector). | **Fixed in Phase 44** — `UpdateTarget`/`UpdateSafe`/`UpdateUserRole`/`UpdateVendorOrg` + `PUT` routes with create-equivalent validation and authorization (the user edit re-runs the privilege-escalation guard; tokens survive a role change), audited `*.update`; the seven top-level list reads take an id-ascending `(limit, afterID)` window and every list endpoint clamps `?limit=&after=` to 1..500 (default 100) the way `listAudit` already did. Grants and safe members deliberately stay create + delete (no dependents to lose; two audited events beat one mutated row), and usernames stay immutable (they are the subject key in grants/sessions/vendor rows). Console: cursor-draining fetches + 2=Change screens. Tests: the store contract (both stores, live PostgreSQL in CI) + `api/update_test.go`. |

## The 2026-08-19/21 self-sweeps — auditing the batch's own output

Two passes over what phases 159–181 had just shipped, run because the per-phase
reviews had proven insufficient: they read each change against its own intent,
and neither of these findings contradicts an intent. Both are the same shape as
the research findings above, which is the point — **the batch reproduced the
defect class it was closing**, twice, in its own code and its own configuration.

The first pass (Phase 176) read the code: dead-field scan, store surface, audit
vocabulary emit parity, fail-open branches in every gate-shaped function, and
bool flags honoured on read but never set. The second (Phase 182) read what the
code was *deployed with*: environment variables, the shipped examples, and the
in-memory state a long-lived process accumulates.

| # | Finding | Why it matters | Status |
|---|---|---|---|
| ~~CN~~ | ~~**A reachability flag claimed a reachability the control does not have.**~~ Phase 175's `owner_known` — "the offboarding cascade can reach this agent" — compared owners case-insensitively, while every owner lookup in pamv1 is a literal match (`WHERE owner = $1`). | An agent owned by `Carol` while the user is `carol` reported as fine and is unreachable: deleting that user suspends nothing. A report that is wrong in the *reassuring* direction is the same class as a dead field that reads like a control, and it shipped one phase before it was caught. | **Fixed** — Phase 176, exact-case, with the deliberate asymmetry recorded: the four-eyes comparison stays case-INSENSITIVE, because matching more broadly there *refuses* more. `api.TestOwnerKnownMatchesTheControlItReportsOn` proves the claim by deleting the user and watching which agent gets suspended. |
| ~~CO~~ | ~~**Four-eyes could not be verified and did not say so.**~~ The gate refuses `owner == approver`, so an owner nobody holds — a typo, or a team address — can never match. | The real owner could approve their own agent's privileged call, with the row still reading as though somebody were accountable. Four-eyes silently not applying is worse than four-eyes visibly absent. | **Fixed** — Phase 176: the decision is audited `broker.approval.four_eyes_unverified` naming the owner, and `PAM_BROKER_REQUIRE_KNOWN_OWNER` refuses it outright. Off by default, because a team-owned agent is a legitimate arrangement and the trail is honest either way. |
| ~~CP~~ | ~~**Three refusals that could never fire.**~~ `PAM_BROKER_REQUIRE_ENROLLED_SVID` without a trust-domain JWKS, `PAM_BROKER_POSTURE_REQUIRED` without a posture webhook, and any broker refusal with no policy file. | Each reads to an operator as "the agents are gated" and does nothing at all — the batch's own failure class, one level up: not a dead field in the code, but a live field in the **configuration** whose prerequisite is absent. | **Fixed** — Phase 182: each fails the startup loudly, the idiom the validator already used for `PAM_BROKER_TOKEN_EXCHANGE`, checked as a group so the next knob is a list entry. `config.TestInertBrokerKnobsFailStartup`. |
| — | **Hardening: two unbounded accumulations, one real.** Phase 176's write damper (`svidSeen`) kept an entry per distinct SPIFFE ID for the life of the process; MCP SSE sessions were checked and are deleted on close. | Small in a stable trust domain, unbounded where a per-pod identity is minted — a slow leak in the exact deployment shape SPIFFE encourages. | **Fixed** — Phase 182: capped at 4096 with a whole-map drop, since the entries are interchangeable and the worst case is one extra row write per identity while the damper re-learns. |

**What the two sweeps say about the process**, recorded because it is the more
useful finding: a per-phase review cannot catch a defect whose author believed
the phase was correct. Both live findings came from reading the batch as a
whole, with scans that do not care what any phase intended — and one of them was
one phase old.

## The 2026-08-17/18 AI-agent-broker research — five passes, five findings

The first read-only passes aimed at the **broker itself** rather than at the
tree as a whole: MCP specification security, agent-identity standards, vendor
AI-agent controls, agentic threat frameworks, and a follow-on pass re-read at
HEAD *after* the first phases of the batch had shipped. Every claim carried a
`file:line`; the standards citations were fetched rather than recalled.

Two of the five are the reason this section exists rather than the findings
being left in the roadmap as feature work: they are **live authorization
defects**, not missing capability. Both have the same shape, and it is the shape
Phase 159 had already found once — **a control written against the identity kind
pamv1 issues, silently inert for the kind it merely verifies**. A SPIFFE/SVID
agent has no `agent_keys` row and its canonical name is a URI, so any check keyed
on a row id or compared against a username passes it through while reading, in
code and in documentation, as though it covered everything.

The other three are the class this document keeps returning to from a different
angle: **a field that reads like a control and enforces nothing**. `ttl_seconds`
was parsed and ignored for six phases while the shipped example policy marketed
it; `scope` was described as a grant when it is an audit label; and an inventory
tool answered for the whole estate because it discarded the principal.

| # | Finding | Why it matters | Status |
|---|---|---|---|
| ~~CI~~ | ~~**Four-eyes self-approval prevention was inert on the SPIFFE path.**~~ `decideBrokerApproval` compared the parked call's `Identity.OnBehalfOf` against the approving human's username. For an SVID that value is a SPIFFE ID, which can never equal a person's name — and nothing in the tree mapped one to the other. | The human operating an agent could approve their own agent's privileged tool call single-handed, in the deployment posture the roadmap calls the intended production one. The only test of the invariant covered static keys. | **Fixed** — Phase 170. New `agent_identities` owner registry (migration `0045`, four `manage_users` routes, console menu 26 → F8); the gate resolves owners for the **whole delegation chain** and fails closed twice over — an unattributed identity refuses the decision (403, the call stays parked) and an unreadable registry refuses it too (503). `api.TestFourEyesHoldsOnTheSPIFFEPath` + `TestApprovalRefusedWhenSPIFFEAgentHasNoOwner`, both verified to fail against the pre-fix gate, where the self-approval executed. |
| ~~CJ~~ | ~~**Quarantine was not chain-aware.**~~ `IsAgentQuarantined` was asked about the presenter's subject only, while a delegated JWT-SVID names its delegator solely in the RFC 8693 `act` chain. | Quarantining a compromised root left every sub-agent token it had already minted working until that token's TTL expired — an incident responder pressing the stop button and watching the compromise continue. Aggravating: the verifier allows 60s of clock leeway past `exp`, which is ordinary JWT practice but runs permissive when a delegated token's TTL is the *other* containment. | **Fixed** — Phase 169. Both gates (`agentAuth` at ingress, `revalidateAgent` at approval time — the parked call a responder is actually racing) now walk the presenter plus every chain actor, deduped, still fail-closed on a store error, and the refusal names the link that stopped it. A static key's `OnBehalfOf` is deliberately excluded: it is a human's username, and stopping every agent one person owns is offboarding. `api.TestAgentQuarantineFollowsDelegationChain` + the in-package parked-call twin. |
| ~~CK~~ | ~~**`list_targets` leaked the whole estate.**~~ Its principal parameter was literally `_`; `list_credentials` without its optional `target` did the same for account names. | An agent with zero grants learned every hostname, OS, protocol and privileged login name pamv1 knows — the reconnaissance step of an attack path, handed to the least-trusted actor in the system. It was the only place in `broker_tools.go` that skipped the grant check its siblings enforce. | **Fixed** — Phase 169. Both tools answer through `agentCanSeeTarget`/`agentVisibleTargets`, the same direct-grant ∪ safe-membership evaluation the acting tools use; the acting helpers were refactored onto it so the two cannot drift. Naming an ungranted target explicitly is refused rather than answered with an empty list. |
| ~~CL~~ | ~~**`ttl_seconds` and `scope` were advertised controls that constrained nothing.**~~ `Rule.TTLSeconds` reached `Decision.TTL` and no non-test caller ever read it; `Scope` was rendered only into audit text. | A rule advertising a 60-second grant got the deployment-wide `PAM_BROKER_TOKEN_TTL_MIN` — fifteen minutes — and the shipped `deploy/broker-policy.example.yaml` presented exactly that setting as "a scoped, short-lived grant". A dead field that reads like a control is worse than an absent one, and worst of all when the example teaches operators to rely on it. | **Fixed** — Phase 171. `ttl_seconds` now narrows the deployment window per call (narrow only, never extend), one deadline drives both the parked call and its resume token, the sweep evicts per call, and on an `allow`/`deny` rule — where there is no window — it is a **load error**. `scope` is documented for what it is: an audit label whose template failure is a deny, i.e. a fail-closed required-argument check. |
| ~~CM~~ | ~~**Policy was identity-blind, and had no principal side.**~~ `Evaluate(tool, args)` never received the verified identity, which sat one line above the call site; `Rule` had no agent field. | One `allow` for `reveal_credential` enabled it for **every** agent the deployment authenticates, and any rule keyed on "which agent is this" was really keyed on a string the agent chose to send — a control whose subject is picked by the party it constrains. | **Fixed** — Phase 173. `Evaluate(caller, tool, args)` with `agents:`/`not_agents:` on a rule (empty matches all; `agents` matches the presenter, `not_agents` the whole lineage) and a reserved `caller.*` condition namespace that arguments cannot forge, since a `caller.` key never touches the argument map. An unknown `caller.*` attribute is a load error. |

What the same research left as **capability rather than defect** — SVID
enrollment and inventory, a subject-indexed "what can this agent reach?",
recertification for non-human identities, posture on the agent path, `may_act`
emission, and the approver's view of a delegation chain — is tracked in
[ROADMAP §3b](../ROADMAP.md#3b-the-ai-agent-broker-batch-2026-08-1718-research)
rather than here, because none of it is a control that is wrong today.

## The 2026-08-12 audit sweep (Phase 108)

Four independent read-only passes over the tree as it stood after Phase 107 —
cross-path control parity, test coverage in security-critical code, a security
self-audit, and doc-vs-code currency. Two genuine findings; three coverage
gaps recorded as hardening. The dead-code removal and the two doc-drift items
the same sweep found are recorded in the [ROADMAP entry](../ROADMAP.md) rather
than repeated here, since neither is a security finding.

| # | Finding | Why it matters | Status |
|---|---|---|---|
| ~~CG~~ | ~~**The PostgreSQL and SQL Server proxies wrote two contradictory `db.session.denied` rows for one refused connection**, on the `gateTunnelOnly`/`gateEnrollOnly` gates only.~~ `refuse()` audited the denial explicitly, then called `deny()`, which independently audits the same action via `sqlDeny` — two rows, two different `reason:` strings (the explicit call omitted `queryTag()`). Predates Phase 102, which preserved it faithfully from both proxies' pre-refactor code. | **Audit fidelity.** `db.session.denied` feeds the risk-analytics `authFailActions` signal and is OCSF-classified for SIEM export; a doubled count skews both, and a self-contradictory trail (two reasons for one event) is the defect class this document treats as first-class. | **Fixed in Phase 108.** Audited once (the short reason slug already shared by the SSH proxy and the HTTP authz middleware for the same two conditions), failing the wire directly instead of through `deny()`. Tests: row-count assertions on `TestDBProxyRefusesTunnelOnlyToken`, `TestDBProxyEnrollOnlyRejected`, `TestMSSQLProxyEnrollOnlyRejected`, and a new `TestMSSQLProxyRefusesTunnelOnlyToken` (the SQL Server proxy had no tunnel-only test at all). |
| ~~CH~~ | ~~**An `ssh_ca` (Zero Standing Privilege) credential could be stranded on a target retargeted away from `ssh`.**~~ `POST /api/credentials` refuses to create one unless the target's protocol is `ssh`; `PUT /api/targets/{id}` never re-checked the invariant. | **A state a JIT-injection PAM should never reach.** The credential's `SecretEnc` is empty by design (ZSP mints a certificate JIT instead of storing a secret); reaching it through a WinRM path — no certificate to mint, no secret to inject — is silent breakage with no audit distinguishing it from an ordinary session, on an endpoint gated only by `CapManageTargets`, not `CapManageCredentials`. | **Fixed in Phase 108.** `updateTarget` refuses a protocol change away from `ssh` while any `ssh_ca` credential exists on the target (`hasZSPCredential`), mirroring the create-time check. Test: `api.TestZSPCredentialBlocksProtocolChange`. |
| — | **Hardening: three untested fail paths in security-critical code** — `mfaVerify`'s own OTP-rejection branch, `vault.NewTransitKEK`'s non-loopback-HTTP rejection, and PostgreSQL MD5 upstream auth (`md5Password`) had never been exercised by a test (the first two had only ever seen their *passing* branch; the third had none at all). | A regression in any of the three would ship silently: code that lets any string confirm an MFA enrollment, a weakened Vault Transit HTTPS guard, or a broken MD5 hash. | **Phase 108** added `TestMFAEnrollmentAndLogin`'s wrong-OTP-at-verify step, `vault.TestNewTransitKEKRequiresHTTPS`, and `proxy.TestMD5Password` (three independently-computed vectors, plus a salt-is-mixed-in check). |

## The 2026-08-10 refactor-hardening pass (Phases 97–106)

The refactor sweep continued behind the code review. Most of it was
behaviour-preserving structure work, verified sound; two items are security
findings worth recording, and two are hardening.

| # | Finding | Why it matters | Status |
|---|---|---|---|
| ~~CF~~ | ~~**The proxy-family unification (Phase 102) introduced a per-connection `sync.Map` that could leak.**~~ To pass the *real* `*auth.Principal` from `authenticate` to `handleConn`, the SSH proxy stashed it in a package-level map keyed by a token, deleted by `handleConn` (`LoadAndDelete`). But if authentication succeeded and `ssh.NewServerConn` then failed *after* the callback — a post-auth handshake abort — `handleConn` never ran to delete the entry. | **A slow unbounded-growth vector the original code did not have.** Auth-gated and tiny per entry, so not a practical DoS, but a security proxy should introduce no unbounded map. The workflow's adversarial verifiers (gate order, refusal encodings, fail-closed) did not look for it; a **hand review of the diff did**. | **Fixed in Phase 102** before merge: a stale-entry sweep in `authenticate` evicts entries older than one handshake, bounding the map to in-flight handshakes. |
| — | **Hardening: the wire parsers had no fuzz coverage.** `internal/tds` and the SFTP inspector parse ~2,900 lines of attacker-influenced bytes. | A parser panic or hang is a denial of service on the gateway. | **Phase 103** added Go native fuzz targets (`FuzzParsePreLogin`/`SQLBatch`/`RPC`, `FuzzSFTPInspector`); ~2M executions found nothing, and a `fuzz smoke` CI step now hunts on every run. |
| — | **Hardening: gosec `G304`/`G101` were globally excluded**, so a new tainted-path file read or hardcoded credential would pass silently. | Enforcement that documents but does not gate. | **Phase 104** dropped both from the exclude list (nine file-read sites annotated), so a new violation now fails the build. |

## The 2026-08-09 refactor review — the same control, enforced the same way on every path

A structural review of the session-proxy family (`internal/proxy` —
`proxy.go`/`dbproxy.go`/`mssqlproxy.go`) and the shared helpers, looking not for
a wrong control but for a **right control applied unevenly**. A fix that lands on
one of three sibling paths and not the other two is a latent gap the moment
anyone reaches the system through the path that was missed. The review found
three of that shape (two of them genuine authorization/audit gaps), plus two
smaller fail-closed/validation inconsistencies. All fixed in **Phase 96** with
tests verified against the pre-fix code.

| # | Finding | Why it matters | Status |
|---|---|---|---|
| ~~CA~~ | ~~**The AI-agent broker's exec/credential tools skipped the vendor-contract gate.**~~ Every other target-reaching path — the SSH proxy (`proxy.go`), the PostgreSQL proxy (`dbproxy.go`), the SQL Server proxy (`mssqlproxy.go`) and the in-portal RDP/VNC viewer (`viewer_handlers.go`) — calls `store.VendorSessionAllowed` before injecting a secret. `authorizeAgentTarget`/`authorizeAgentCredential` (the shared broker gates) did not. | **A vendor reached, through the broker, an account it was refused everywhere else.** The vendor gate (Phase 29) is the control that keeps a third party inside its approved, in-window contract; the broker is the *least*-trusted actor in the model, and it was the one path that skipped it. A vendor identity holding `CapCallTool` (or `reveal_credential`/`rotate_credential` by policy) could `ssh_exec`/`winrm_exec`/reveal/rotate a target account outside its contract window entirely. | **Fixed in Phase 96.** New `Server.vendorGateAgent(ctx, principal, target, account)`, applied by each of `winrm_exec`, `ssh_exec`, `reveal_credential` and `rotate_credential` the moment the credential (and thus the login account it is scoped to) is resolved — always before any secret exists. A refusal is audited under the shared `access.denied … reason:vendor-contract`, so broker refusals reach SIEM/analytics like every other path. Test: `api.TestBrokerVendorContractGate` (all four tools, before and after an approved grant). |
| ~~CB~~ | ~~**A vendor-contract refusal on the SSH proxy was audited as `session.denied`, not `access.denied`.**~~ The SQL listeners, the viewer tunnel and the REST paths all record the same refusal under `access.denied`. | **The audit vocabulary is an interface.** The OCSF exporter and the risk-analytics engine key off the action name; a lone `session.denied` on the SSH path meant every SSH vendor refusal was silently excluded from SIEM export and risk scoring, while the identical PostgreSQL/MSSQL/viewer refusal was included. The exact drift class the codebase warns about elsewhere ("a fresh action name would silently exclude every … session"). | **Fixed in Phase 96.** The SSH proxy emits `access.denied … reason:vendor-contract`, unifying all paths. Pinned by `proxy.TestVendorContractGateProxy`, which now asserts the action name. |
| ~~CC~~ | ~~**The PostgreSQL and SSH deny/log paths interpolated the operator-supplied login raw into audit details.**~~ The PostgreSQL startup `user` parameter and the SSH login are attacker-chosen bytes; `deny()` and several `session.denied` sites wrote `login:"+login` unquoted. The SQL Server listener already bounded the same value with `auditField`. | **Audit-detail injection.** An audit detail is a space-separated `key:value` string parsed by the SIEM forwarder; a login of `eve\nactor:admin action:break-glass.used` could inject a newline to break the row and forge fields — flooding or restructuring the trail from an unauthenticated connection. The MSSQL sibling was safe; its two siblings were not. | **Fixed in Phase 96.** Every login interpolation on the PostgreSQL and SSH deny/log paths is now `auditField(login, 64)` (bounded + quoted), matching MSSQL. Test: `proxy.TestDBProxyDenyBoundsHostileLogin` feeds a newline + forged pair + 300 bytes of padding and asserts no audit row carries a raw newline or a free-standing forged field. |
| ~~CD~~ | ~~**The proxy's WinRM command loop audited `winrm.run` best-effort, after streaming output.**~~ The REST WinRM endpoint (`execWinRM`) has always audited fail-closed — output withheld if the durable audit cannot land — but its proxy twin (`winrmRun`) wrote output to the operator first and audited afterwards, ignoring the error. | **Two ways to run a WinRM command, two evidence guarantees.** The fail-closed contract is "nobody acts on output the system of record never accounted for"; the proxy path quietly did not honour it, so a WinRM command run through the recording proxy could deliver output the audit trail never recorded. | **Fixed in Phase 96.** `winrmRun` audits `winrm.run` before streaming and withholds output (telling the operator) when the audit write fails, matching `execWinRM`. Test: `proxy.TestWinRMRunAuditFailClosed` (a store that fails the `winrm.run` append). |
| ~~CE~~ | ~~**`pam-server -split-key` silently fell back to a default on an unparsable share/threshold.**~~ `getenvInt` swallowed a parse error and returned the default, so `PAM_BREAK_GLASS_THRESHOLD=oops` produced a 3-of-5 split with no error, while `config.Load` rejects the same value (2..255, shares ≥ threshold) at server start. | **A key ceremony that lies about its quorum.** The break-glass shares are minted once, by hand, and distributed to custodians; a typo producing a different quorum than intended — or than the server will later accept — is discovered only when the emergency unseal fails. `Config.BreakGlassShares` was in fact the only config field the one consumer that should read it never did. | **Fixed in Phase 96.** `getenvInt` now returns `(int, error)` and `-split-key` refuses an unparsable value rather than defaulting; `shamir.Split`'s own bounds still apply. Test: updated `cmd/pam-server.TestGetenvInt`. |

## The 2026-08-09 review — the command/step-up gate is best-effort, and said so only for shells

Found reading the database proxies adversarially (the review that produced Phases
91–92). The proxies themselves came through **sound** — both Query and Parse are
gated so a prepared statement cannot evade (postgres), every call and every
SQL-bearing parameter in a multi-call RPC is gated with an unparseable request
failing **closed** (mssql, more thorough than postgres), statement text is quoted
into audit details with `auditCmd`, step-up is fail-closed on timeout, and the
`sid==""` step-up skip is unreachable in the shipped binary (`main` always wires
a session Registry). One honesty gap remained.

| # | Finding | Why it matters | Status |
|---|---|---|---|
| ~~BZ~~ | ~~**The command and step-up gates are regex over un-normalized statement text, but the docs disclaimed only the interactive shell.**~~ `cmdguard.Guard.Blocked` runs each pattern against the raw string with no comment-stripping or case-folding, so `DROP/**/TABLE` and odd whitespace evade `(?i)drop\s+table`, and on the simple-query path an anchored pattern misses a statement smuggled after a benign one (`SELECT 1; DROP TABLE …`). | **A four-eyes control believed stronger than it is.** The enforcement table presented the SSH-`exec`, WinRM and database-statement paths as reliably refusing a matching statement, while only interactive shells carried the "not a containment boundary" caveat. So an operator or auditor could believe `PAM_DB_STEPUP_FILE` guarantees a sensitive statement cannot run without supervisor approval — when a determined operator can obfuscate past the regex. The gate is genuinely useful as defense-in-depth plus a complete audit trail (the statement is recorded whether or not it matched); the gap was the docs, not the code. | **Fixed in Phase 93** (docs only). §9.4 now extends the best-effort caveat to every discrete-command path and to the step-up gate, recommends unanchored `(?i)` patterns, and says plainly that a hard guarantee must come from database-side roles/permissions — the proxy embeds no SQL parser by design. No code change: comment-stripping SQL correctly needs the parser the design deliberately omits, and a fragile stripper would break legitimate queries or manufacture false matches. |

## The 2026-08-09 review — the SFTP read-only containment gap

Found reading the SFTP guard adversarially (the review that also produced Phase
91's vault pass). One finding, in a stated **containment** control.

| # | Finding | Why it matters | Status |
|---|---|---|---|
| ~~BY~~ | ~~**Read-only SFTP forwarded a native mutating op as if it were a read.**~~ `sftpInspector.handlePacket`'s request switch enumerated the mutating packets (WRITE, SETSTAT, REMOVE, RENAME, SYMLINK, …) and sent everything else to `default: return true`. `SSH_FXP_LINK` (21 — the v6 hard/symlink op), `BLOCK`/`UNBLOCK` (22/23) were not enumerated, so they were forwarded. | **A containment bypass in read-only mode.** `readonly` exists so a semi-trusted operator cannot mutate the target, and the openssh EXTENDED twin `hardlink@openssh.com` was already governed by `handleExtended` — but the **native** op slipped straight through against any SFTP server that speaks it (SFTP v6). OpenSSH's server does not implement native v6 LINK (it uses the extension, which was caught), so OpenSSH targets were unaffected; a non-OpenSSH v6 server was not. The two default arms had opposite postures: `handleExtended` refused an ungoverned extension, while the native switch forwarded an ungoverned request — and a containment control must not depend on the target's SFTP implementation for its correctness. | **Fixed in Phase 92.** The native default now fails closed in read-only mode: it forwards only the read family (`LSTAT/FSTAT/OPENDIR/READDIR/REALPATH/STAT/READLINK`) and refuses anything else with a synthesized `SSH_FX_PERMISSION_DENIED`, matching `handleExtended`. Allow mode is unchanged except that a native `LINK` is now audited `sftp.modify op:link` (the explicit cases audited their mutations; this one had no case, so an allow-mode hard/symlink was invisible in the trail). Tests: `proxy.TestSFTPReadOnlyRefusesNativeMutations` (LINK/BLOCK/UNBLOCK refused, the read family still forwarded) and `TestSFTPAllowForwardsNativeLink`, verified to fail against the pre-fix fail-open default. |

## The 2026-08-09 review of Phase 86 — the response that could be turned on a victim

One finding, and it is the kind a review exists to catch: a security feature that
an unauthenticated attacker could aim at a bystander.

Phase 86 added an automated step-up response (`PAM_ANALYTICS_AUTO_STEPUP`) beside
the existing auto-kill (Phase 23). Both act on the actor of a high/critical risk
finding — revoking that actor's logins, or killing their live sessions. The risk
score, though, counts **auth failures**, and an auth failure records the
**presented** username as the actor: `login.failed` stores `in.Username` raw, and
anyone can present any username unauthenticated. So "many auth failures for X"
means *someone is attacking X*, never *X is misbehaving* — and the response
punished X.

| # | Finding | Why it matters | Status |
|---|---|---|---|
| ~~BX~~ | ~~**An automated response could be aimed at any account by an unauthenticated attacker.**~~ The risk score counts auth failures, whose actor is the attacker-chosen presented username; the auto-kill and auto-step-up responses fired on the finding's Level and acted on its Actor with no check that the risk came from the actor's own authenticated behaviour. | **A denial of service delivered through the defence itself.** Confirmed by execution: **7** failed logins under a victim's name reach *high* (score 56) → with `AUTO_STEPUP` on, the victim's portal logins are revoked; **10** reach *critical* (80) → with `AUTO_KILL` on, the victim's **live privileged sessions are killed mid-work**. The attacker needs only a username, which is not a secret. Auto-kill has shipped since Phase 23, so this is a fix to released behaviour, not only to the unreleased Phase 86 half. | **Fixed in Phase 87.** `analytics.Finding` gains `ResponseScore`/`ResponseLevel`, which exclude the signals a stranger can attribute to a name they do not control (`auth_failure` is the only one — every other signal requires the actor to have authenticated and acted). The responses gate on `ResponseLevel`; the **alert** still fires on `Level`, because a human should be told an account is being brute-forced. An attacker can no longer push even a legitimately-active actor over the response threshold by adding failed logins under their name. Robust regardless of which auth-failure path quoted the name. Tests: `analytics.TestResponseScoreExcludesAuthFailures` and `api.TestAnalyticsPassIgnoresAuthFailureOnlyActor`, both verified to fail against the pre-fix code (the second kills the victim's session). |

## A control that proved the wrong thing (closed in Phase 84)

Not from a sweep — found while building the ticket-gate connector, by asking what
the gate actually establishes.

| # | Finding | Why it matters | Status |
|---|---|---|---|
| ~~BW~~ | ~~**The ITSM ticket gate could prove a ticket was valid, never that it was yours.**~~ The webhook payload was `{"ticket": id}`; the actor was known at both call sites and passed to neither. | **A change number worked as a shared password.** Anyone who could read the change queue — or who was told a number by a colleague — satisfied "no access without an approved change ticket" for a ticket raised by, assigned to and approved for somebody else. The control's whole purpose is to tie privileged access to an authorised, attributable piece of work, and it established only that the work existed. Neither the regex nor a 2xx webhook can close this: the endpoint was never told who was asking. | **Fixed in Phase 84.** `Validate` takes the actor at both gates (at the connect-time fold it is the person *connecting*, not the approval's recorded requester), the webhook payload gains `"actor"` (backward compatible), and the new ServiceNow/Jira connectors refuse a ticket that does not name the operator — `PAM_TICKET_BIND_ACTOR`, on by default. They also enforce the change's **state** and **window**, so a cancelled change or one outside its approved hours stops admitting sessions. Tests: `ticket.TestServiceNowRefusesAnotherPersonsChange`, `TestJiraRefusesWrongStatusAndWrongPerson`, `TestServiceNowEnforcesStateAndWindow` — the person and window checks each verified against a deliberately broken build. |

## The 2026-08-08 review of Phases 79–81 — a fix that reintroduced its own finding

Three findings, and the first is the interesting one: **Phase 80's fix for
finding BM reintroduced BM, one layer down, inside the fix itself.**

BM was "the startup log promises rotations that every tick then skips". Phase 80
fixed the *ownership* definition — from "Conjur filled this at boot" to "Conjur
manages this" — and added a warning for the genuinely ambiguous case, a secret
both pinned in the environment and managed in Conjur: *"enabling refresh means
Conjur wins for it."* Then it seeded the change-detection digest from **what
Conjur held**, so the opening tick compared Conjur against Conjur, found no
change, and skipped. Forever. The promise in the log was false in exactly the
configuration the log was printed for — which is every shipped deployment, since
docker-compose hard-requires `PAM_API_KEY`, the Kubernetes secret ships it and
the OVA generates it.

The lesson is narrow and reusable: **a fix that adds a claim to a log has to be
checked against the claim, not against the bug it replaced.** Both halves were
implemented and neither was run against the other.

| # | Finding | Why it matters | Status |
|---|---|---|---|
| ~~BT~~ | ~~**A secret pinned in the environment and managed in Conjur was never refreshed**, while the startup log said Conjur wins.~~ `NewRefresher` seeded `applied` from Conjur's value rather than the running process's. | **The feature silently did nothing in every shipped deployment** — the same outcome as BM, reached by a different route, and now with a log line actively asserting the opposite. An operator rotating the key in Conjur would see a successful tick and a server still accepting the retired key. Reproduced: `changed=[] applied=""` with the environment on one value and Conjur on another. | **Fixed in Phase 82**: seeded from `os.Getenv` at construction — a single read of what the process booted with, which is not the finding-BH mistake of using the environment as the *last-applied store* across ticks. Test: `conjur.TestRefreshAdoptsConjurWhenTheEnvironmentDiverges`, verified to fail against the old seeding. |
| ~~BU~~ | ~~**Two comments in `config.Load`'s validation had drifted from the statements they document.**~~ Three explanatory blocks had stacked with no code between them. | A reader reasoning about the 1 PiB SFTP bound found that reasoning sitting above the *Conjur refresh interval* check. Each insertion (Phase 76, then 78) landed between a comment and its `if`. Cosmetic, but this repo's comments carry the reasoning, so a misattributed one is a wrong explanation rather than a missing one. | **Fixed in Phase 82**: each comment re-paired with its statement. |
| ~~BV~~ | ~~**An applier keyed on a name that is not a sourceable secret was a silent no-op.**~~ The probe iterates `bootstrapSecrets`, so a typo'd key was never visited. | Never fetched, never applied, never audited — and indistinguishable from "Conjur does not manage it". The applier map is *the* definition of what is refreshable (finding BK), so a typo in it silently shrinks that definition. | **Fixed in Phase 82**: refused at wiring time, naming the sourceable secrets. Test: `conjur.TestRefresherRefusesAnApplierItWouldNeverCall`. |

**Phase 79 and Phase 81 came through clean.** The deploy examples were verified
by building both kustomize bases and round-tripping all three sealed files, and
the end-to-end test's six assertions were each checked against a deliberately
broken build before it landed.

## The 2026-08-08 review of Phase 78 — a feature that did not work where it was aimed

Phase 78 (runtime secret refresh) was reviewed the day it merged, in the 52a–52g
tradition that the review of a change is part of the change. It found **fourteen
defects in one phase** — the worst return of any review in this repo — and the
shape of them is worth more than the count. Three classes:

**Claims checked one level too shallow.** The phase asserted, in the architecture
doc and the admin guide, that "a single swap reaches every authentication
surface". The *resolver* sharing was verified; whether anything else held a copy
of the same value was not. `api.Server` did.

**A feature inert exactly where it was aimed.** Ownership was defined as "Conjur
filled this at boot", and sourcing only fills what the environment left empty —
while docker-compose hard-requires `PAM_API_KEY`, the Kubernetes secret ships it
and the OVA generates it. So the one secret the feature existed to rotate was
never refreshable in any shipped deployment, while the startup log said it was.
Separately, the Kubernetes projected JWT was read once at boot and re-sent
forever, so on the repo's own authn-jwt manifest every refresh 401s ten minutes
into the process's life.

**A test that could not fail**, guarding the phase's headline safety claim.

| # | Finding | Why it matters | Status |
|---|---|---|---|
| ~~BE~~ | ~~**Rotating the break-glass hash inverted the quorum-unseal path.**~~ `api.Server` decoded `Options.BreakGlassHashHex` once at construction; `SetBootstrapSecrets` updated only `auth.Resolver`. | **The retired emergency key kept minting full-admin sessions, and the new one was rejected** — on the one path that exists for when nothing else works, reachable unauthenticated at `POST /api/breakglass/unseal`. Reproduced end to end over HTTP: shares of the *retired* key returned 201 with a break-glass token and a `breakglass.unseal` audit line. Two inputs for one value, and the test harness had already drifted them apart without anything noticing. | **Fixed in Phase 80** by deleting the second copy rather than adding a second setter: the hash lives once, in the resolver, behind `MatchesBreakGlass`/`BreakGlassEnabled`, and `Options.BreakGlassHashHex` is gone. Test: `api.TestBreakGlassRotationReachesTheQuorumPath`, verified to fail against the old shape. |
| ~~BF~~ | ~~**On Kubernetes the refresh could never succeed.**~~ The authn-jwt token was read once in `Source` and frozen into the client. | **The feature was permanently inert on the deployment it exists for**, with only a `Warn`. The repo's own manifest projects a token with `expirationSeconds: 600`; the kubelet rewrites the *file*, and the in-memory copy never changed. Harmless while the client authenticated once at boot; permanent failure the moment Phase 78 put it on a timer. Every refresh test used the api-key path, so the JWT path had zero coverage. | **Fixed in Phase 80**: `Config.JWTFile` is re-read on every authenticate. |
| ~~BG~~ | ~~**A refreshed `PAM_API_KEY` bypassed the strength check `config.Load` enforces.**~~ The only filter was non-empty. | **A running server could adopt a three-character admin key** — the SSH and database proxy password — that the same binary refuses to start with, so the next restart CrashLooped on the error the running process had walked past. Values were also untrimmed, so a trailing newline silently became a different key. | **Fixed in Phase 80**: `config.ValidateBootstrapAPIKey` is one rule used by both paths, and values are trimmed. |
| ~~BH~~ | ~~**A failed environment write silently reinstated the retired key.**~~ The refresher read its last-applied state back from `os.Getenv` and committed the digest *before* the best-effort `os.Setenv`. | A value `os.Setenv` rejects (a NUL byte) left the resolver on the new key and the environment on the old one; the next tick re-seeded from the environment and pushed the **retired** key back, with an audit line naming a different secret. Treating a process-global this package does not own as its state store is the root cause. | **Fixed in Phase 80**: last-applied state lives in the `Refresher`, and the environment is no longer written. |
| ~~BI~~ | ~~**One malformed value blocked every rotation.**~~ The applier took both secrets at once, so `SetBootstrapSecrets` rejected the pair. | A single bad break-glass hash — a trailing newline from `conjur variable set` was enough — blocked a perfectly good API-key rotation on every tick, forever, with only a `Warn`. It could even be blocked by a value Conjur did not manage. | **Fixed in Phase 80**: appliers are per-secret, and the resolver gained `SetBootstrapAPIKey`/`SetBreakGlassHash`. |
| ~~BJ~~ | ~~**The test guarding the phase's headline safety claim could not fail.**~~ `TestRefreshNeverTouchesPinnedSecrets` built its needles from env names (`master_key`) while variable ids use hyphens (`pamv1/master-key`). | **All four `Contains` checks were false regardless of behaviour.** Mutation-proved: with *both* skip guards removed, the fake server recorded fetches of the KEK, the database URL and both audit keys — and the test still passed. The anti-vacuity guard it did carry only proved the list was non-empty. | **Fixed in Phase 80**: it now asserts the positive form — the set of ids fetched must be exactly the refreshable ones — and the same mutation fails it. |
| ~~BK~~ | ~~**A secret with no consumer could be audited as refreshed.**~~ Detection was driven by a `refreshable` map while application was hard-wired to two names. | Adding a third name produced `config.secret_refreshed` for a KEK rotation that never happened — a durable compliance record asserting something false — while the process environment held the new value and every in-memory consumer held the old one. Latent, with only a comment enforcing it. | **Fixed in Phase 80**: the applier map is the single definition of refreshable, so a secret with no applier is never fetched, applied or audited. |
| ~~BL~~ | ~~**The refresh audit was fail-open and written after the fact.**~~ | A store blip on the one tick that rotated a key meant the change was applied, never recorded, and never retried — the digest had already moved. The repo names fail-closed audit on secret paths as a do-not-regress invariant (§6.4), and the phase built retry-on-failure for the applier but not for the audit. | **Fixed in Phase 80**: the audit precedes the swap and a failure to record skips it, so a change cannot outlive the evidence of it. Test: `conjur.TestRefreshIsFailClosedOnAudit`. |
| ~~BM~~ | ~~**The startup log promised rotations that every tick then skipped.**~~ It printed the static refreshable list, not the intersection with what Conjur owned — and the undocumented "Conjur must have FILLED it at boot" precondition excluded `PAM_API_KEY` in every shipped deployment. | Exactly the "watching nothing happen" outcome the log was written to prevent. | **Fixed in Phase 80**: ownership is *probed* at startup (Conjur manages it, not Conjur filled it), the log names what will really be refreshed, and a value both pinned in the environment and managed in Conjur gets a warning naming it. |
| ~~BN~~ | ~~**Deleting a variable in Conjur was a silent no-op.**~~ | Keeping the value is the right fail-safe — a policy edit must not disable break-glass — but it was unobservable at any log level, so an operator revoking a key by deletion saw a successful tick while the compromised key kept granting admin on every replica. | **Fixed in Phase 80**: warned, naming the variable and saying that deletion does not revoke. |
| ~~BO~~ | ~~**A permanently failing refresh had no signal beyond a log line.**~~ No metric, no alert, no effect on `/readyz`. | A revocation control that fails open, invisibly. Combined with BF, a cluster could spend a week 401ing on every tick while the portal, the audit trail and `/metrics` looked identical to a healthy one. The repo's own pattern for a security-relevant event is metrics + log + alert together. | **Fixed in Phase 80**: `pam_secret_refresh_failures_total`, a `config.secret_refresh_failed` alert, and `Error` rather than `Warn`. |
| ~~BP~~ | ~~**`PAM_CONJUR_VARS` validated only the left-hand side.**~~ | `PAM_API_KEY=prod/keys/apy` parsed clean, 404'd at boot and left the operator with the silent nothing the function's own doc promises is impossible. A duplicated name silently last-won. | **Fixed in Phase 80**: the variable id is shape-checked and duplicates are refused. |
| ~~BQ~~ | ~~**`PAM_CONJUR_REFRESH_MIN` was silently ignored when Conjur was disabled**, and a refresher with nothing to do still authenticated every tick.~~ | An operator on SOPS/env who set it, or who typo'd `PAM_CONJUR_URL`, got a clean startup and no refresh with nothing saying so. | **Fixed in Phase 80**: every declining branch logs, and no refresher is started when Conjur manages none of the refreshable secrets. |
| ~~BR~~ | ~~**`Actor: "system"` was outside the documented actor vocabulary**, and the failure closure logged at `Warn` where its sibling logs at `Error`.~~ | Every other background writer self-describes (`system-scheduler`, `system-analytics`, `kek-rotation`, `relay`); filtering the trail by actor returned background events under two conventions. | **Fixed in Phase 80**: `system-conjur`, documented in §5. |
| ~~BS~~ | ~~**The Kubernetes Conjur docs and IaC were not updated with the phase.**~~ The README listed runtime refresh and the override map under "Deferred" — the opposite of what shipped — and none of the three K8s surfaces enumerating `PAM_CONJUR_*` gained the new variables. | Kubernetes + authn-jwt is the deployment this integration exists for, so an operator there had no documented or wired way to enable it. `CODE-GUIDE.md` and `PORTS-AND-FLOWS.md` were stale too. | **Fixed in Phase 80.** |

**One reported finding was refuted**: that the Phase 78 commit carried
`deploy/.sops.yaml` hunks labelled "(Phase 79)". `git log` puts that change in
`9fc7c14` (Phase 79), not `1393d2e` (Phase 78) — the reviewer read a working tree
with the next phase already in progress. Worth recording, because "a commit
contains next-phase work" is a claim about history that history can settle.

## The 2026-08-08 sweep — phases 66–75, and one class found three times

A fifth read-only sweep, over the ten phases since the last one: the review of
62–65 (66), the token-exchange console screen (67/67a/67b), campaign scope and
recurrence (68/68a), reviewer assignment (69), reminders (70/70a/70b), the
console safety net (71), the store's role interfaces (72), honest coverage (73),
database-proxy policy parity (74) and the `internal/api` extraction (75/75a).
Dimensions as before: the authorization surface of the new routes, fail-open /
fail-closed consistency, concurrency and resource bounds, crypto and secret
handling, audit completeness, and documented-claim-versus-code drift.

The authorization surface held. The new routes are scoped the way the rest of the
API is — `PUT /api/campaigns/{id}/items/{itemID}/reviewer` refuses an item id
belonging to another campaign, `GET /api/campaigns/mine` reads only the caller's
own queue, and reviewer assignment is **advisory by design**, said so in the code,
the API docs and on the screen, so it is not a control anyone can mistake for one.
The store's split into nineteen role interfaces changed no behaviour: the method
set is pinned at 149 by `store.TestStoreMethodSetIsUnchanged`.

What the sweep actually found was **one class, in three unrelated places** — an
untrusted value interpolated raw into an audit detail — plus the structural reason
it kept happening: `auditField` existed as two byte-identical copies, in
`internal/api` and `internal/proxy`, and **not at all** in `internal/guacd`, which
also writes audit details. A sanitiser that has to be re-typed in every package
that needs it will be missing from the next one. Phase 76 makes it one function,
`internal/auditfmt.Field`, used by all four packages.

| # | Finding | Why it matters | Status |
|---|---|---|---|
| ~~AY~~ | ~~**A hostile agent identity forged the actor in the delegation record.**~~ `agentid.Exchange` assembled `broker.token.exchanged` unquoted and the handler quoted the whole string with `auditField(issued.Audit, 512)`. | **A forged identity in the record an investigator opens to answer "which agent did this".** Whole-quoting stops a value breaking *out* of the record; it does not stop one forging fields *inside* it, because the console un-quotes the detail and then splits on spaces, and its parser takes **last-wins**. Reproduced against the shipped console script: an `on_behalf_of` of `ops-team actor:spiffe://trusted/root on_behalf_of:ceo` made `detailFields` report `actor: spiffe://trusted/root` — an identity the token was never minted for. `OnBehalfOf` is reachable as a static broker key's `Owner` (set when the agent is registered) or the tail of a presented SVID chain. The **refusal** path three lines above already quoted per value, so the two halves of one feature disagreed. | **Fixed in Phase 76.** Every field quoted and bounded at the source; the handler no longer re-quotes. Test: `agentid.TestExchangeAuditResistsFieldForgery`, driven through the real `Exchange` call and verified to fail against the old code. |
| ~~AZ~~ | ~~**A clipboard mimetype off the wire went raw into the record evidencing a copy.**~~ `guacd.ClipTransfer.Detail` interpolated `mimetype:%s` from `clipboard,<stream>,<mimetype>`, unquoted and unbounded. | **The one record whose entire purpose is to evidence that data moved.** The mimetype is chosen by whoever is at the far end of the tunnel — the operator's browser or a compromised RDP/VNC host — and it is the **second** field, so a mimetype of `text/plain bytes:0 sha256:00…` put a forged byte count and digest *ahead* of the real ones and a first-wins reader believed them: a large exfiltration reading as an empty transfer. Unbounded, it was also an audit-flooding primitive, since clipboard transfers are repeatable at will. The `content` field beside it was already quoted, which is what makes the omission a slip rather than a decision. | **Fixed in Phase 76.** Quoted and bounded at 128 through `auditfmt.Field`. Tests: `guacd.TestClipDetailResistsMimetypeForgery` and `TestClipDetailBoundsTheMimetype`, both verified to fail against the old code. |
| ~~BA~~ | ~~**A reviewer name forged fields into a certification reminder.**~~ `reviewerBreakdown` interpolated `%s(%d)` per name, and the campaign name used `%q` — quoted but unbounded — at two sites. | **A nudge that states the opposite of the truth, over the channel people trust to tell them otherwise.** A reviewer name is only `TrimSpace`d on the way in, so it may hold spaces, colons and newlines. Reproduced: a reviewer called `carol pending:0 due:in_999d reviewers:nobody` produced `… pending:1 due:overdue_by_2d reviewers:carol pending:0 due:in_999d reviewers:nobody(1)`, where the forged pairs land **after** the real ones — so the same last-wins parser reads an overdue campaign as having nothing pending. The same string goes to the alert webhook. Written one phase after `certification.item_assigned`, three lines away, got `auditField` correctly. | **Fixed in Phase 76.** Names quoted and bounded, the reviewer list capped at 8 with a `+N_more` tail, campaign names bounded at both sites. Test: `api.TestCampaignReminderResistsAuditInjection`, verified to fail against the old code. |
| ~~BB~~ | ~~**A failing store opened a new campaign every hour, forever.**~~ `spawnDueCampaigns` created the child campaign, snapshotted access and audited, and advanced the anchor's `next_run` **last**. | **An unbounded write loop driven by a partial failure.** Both intermediate failure paths `continue` without advancing the schedule, so the anchor stays due and the next hourly tick creates *another* campaign — and the comment on one of them says "the next tick tries again rather than silently skipping the period", which is what the author intended and not what the code does, because the campaign already exists. A persistently failing `snapshotAccess` (an unreadable target list) opens an empty campaign per tick, flooding every reviewer's queue and the audit trail. | **Fixed in Phase 76.** The period is claimed **before** anything is written, so a failure to claim skips the anchor with nothing created — a genuinely safe retry — and a failure after the claim costs at most one skipped period, logged at `Error` naming the period. The trade is deliberate: a missed review is bounded and loud, an unbounded run of duplicates is neither. |
| ~~BC~~ | ~~**`PAM_CERT_REMIND_DAYS` was the one numeric knob with no range check.**~~ | **A typo that silently means "remind immediately, every day, forever".** `firstReminder` clamps a due date already inside the window to *now*, which is correct behaviour and turns a fat-fingered `3650` into a reminder on every campaign at once. Every comparable knob in `config.go` is range-checked. | **Fixed in Phase 76**: `0`–`366`, fail-loud at startup like its neighbours. |
| ~~BD~~ | ~~**Repo-wide, the same class remains open at roughly 145 sites, one layer up.**~~ Target names, usernames and safe names are validated **non-empty only** — no charset restriction, no length bound — and they are interpolated as `target:%s`, `user:%s`, `safe:%s` into audit details across `internal/api` and `internal/proxy`. | **The audit trail is evidence against insiders, which is why four-eyes and break-glass exist at all.** An admin who names a target `prod-db action:approved reason:emergency` puts forged fields into the record of **every operator's** session on that target, not just their own. Requires a management capability to inject, which is why it is a hardening gap rather than a bypass — but "only an admin can forge the trail" is the wrong resting place for a PAM. | **Fixed in Phase 77**, at the boundary rather than the sinks. `api.validName` refuses exactly two things — **control characters** and **the colon** — and nothing else, so `Prod DB 01`, `sûreté` and `データベース` still work while `prod-db action:approved` does not; plus a 128-byte bound, because a value whose length the submitter chooses is an audit row whose size they choose. Applied to every create/update that takes a human-chosen name: targets, users, safes, campaigns (name *and* reviewer), profiles, app secrets, agent keys (name *and* the owner four-eyes is keyed on), vendors, credentials, and the `subject` of a target grant and a safe membership. **Values that legitimately contain colons cannot be validated this way and are quoted at the sink instead**: the six `host:%s` sinks now use `auditField` — an IPv6 literal made `host:2001:db8::1:22` ambiguous even with nobody attacking it — and SPIFFE IDs stay quoted as AY left them. Tests: `api.TestNamesAreValidatedAtEveryBoundary` (42 hostile values across seven boundaries, all previously accepted), `TestGrantSubjectIsValidated`, and `TestOrdinaryNamesStillWork`, which is the half that decides whether the rule survives — a validator that rejects real names gets removed. **Residual, deliberate:** names already stored are not rejected retroactively, the same call Phase 46 made for grants with no recorded creator. |

## The per-phase reviews of 56–61a (2026-07-31 → 2026-08-07)

Three of those six phases were reviewed the day they merged, in the 52a–52g
tradition that the review of a fix is part of the fix. Those reviews found
**seventeen defects** between them, several of them bypasses of the very
containment their phase existed to provide. All are closed; they are recorded
here because a self-audit that only records the sweeps it ran misses the defects
that were caught by the practice of reviewing new code immediately — which is,
on this codebase's own evidence, where most of them are.

The generalisable finding across all three is one shape: **a new control that
governs a set, and a member of the set that was missed.** Three OpenSSH SFTP
extensions gated and a fourth left open; a re-check performed on one approval and
a consume performed on another; a credential reference read as configuration when
every sibling reference is a use.

### Phase 59a — fifteen defects in SFTP content capture (2026-08-02)

Phase 59 shipped per-file content recording; a max-effort read of it the next day
found fifteen defects, five reproduced by running code. Grouped by what they cost:

| Class | What was wrong | Why it mattered |
|---|---|---|
| **Three ways past capture** | An `SSH_FXP_OPEN` with **no access flag** was treated as neither read nor write and went untracked; a **reused request id** let an unrelated response resolve a pending OPEN, orphaning the handle; a **WRITE offset overflowing** `offset+len` skipped the range check and broke the artifact from inside the encoder, and `broken` is sticky. | Each was a complete bypass of the containment the phase exists for. OpenSSH's own server maps `pflags=0` to a working `O_RDONLY` handle, so **one packet bought an entirely uncaptured download**. Closed by: absence of write intent reads as read intent; an id may name only one outstanding request while capture is on (released by every response kind, including the ones capture ignores, whose ids would otherwise leak until the bound refused honest work); the bound is a subtraction; and a broken artifact refuses in **every** mode. |
| **The artifact name escaped** | It was built from the **raw** session title while the sibling `.cast` used `sanitize`. | A target named `x/../../pwned` wrote outside the recording directory with `O_CREATE\|O_TRUNC` and operator-chosen bytes; a target named `web 01` produced evidence the playback allowlist rejects — invisible, unarchivable, and still deleted on schedule by retention. `sanitize` now also forbids a leading `.`, since a dotfile is skipped by the archiver and *preserved* by the pruner; that flaw was latent for `.cast` too. |
| **`lsetstat@openssh.com`** | Phase 59 gated `posix-rename` and `hardlink` and left the third path-mutating OpenSSH extension ungoverned. | It bypassed both the read-only refusal and the path denylist, unaudited. Extensions are now an explicit list: benign ones pass, mutating ones are gated, `copy-data@openssh.com` is **refused under capture** (it moves content server-side, so the artifact would close attesting `bytes_up:0` — a false statement, worse than a gap), and anything unrecognized is refused under read-only or capture rather than forwarded because it is unfamiliar. |
| **Audit-field forgery through a path** | Quoting kept spaces and colons *inside* the quotes, and a detail is read as text. | A file uploaded to a path named `evade sha256:<hash>` put that exact substring into the trail — which is what playback's tamper check matches. **An operator could vouch for a recording they had altered.** Colons in audited paths are now escaped, which takes every `key:value` token out of reach at once. |
| **The cap was not a limit** | It counted only delivered bytes. | A pipelined download — every real client — ran 16 MiB past a 1 MiB cap before the first refusal. A READ now claims the bytes it asks for when admitted and releases the remainder when it resolves. |
| **A reachable panic, and a lie about truncation** | `ReconstructSFTP` skipped zero-length chunks when sizing but not when copying; `DecodeSFTPFile` reported any malformed line as a torn tail. | One empty WRITE — which the proxy records verbatim — **crashed every attempt to read that file's evidence back**. And "partial but genuine" was rendered for damage anywhere in the file, not only a truncated last line. |
| **Two stream-integrity fixes** | The response leg forwarded raw 32 KiB reads into the same serialized writer that carries synthesized refusals; attestations were written through the live auditor. | A mid-transfer refusal could land inside a half-written `DATA` packet and shift every later boundary. And a session drained by shutdown could leave `.sftp` files whose hash appears nowhere — indistinguishable from tampering — while the chain head had already advanced. |
| **Smaller** | A blackholed KMS hung the session once per *file*; audit writes happened under the mutex both SFTP legs need; `?raw=0` meant raw; an empty write won the direction election and hid a download; the console discarded the tamper verdict on a captured-file download; `PAM_SSH_SFTP_CAPTURE_MAX_MB` could overflow into a negative cap. | Each closed, each with a test. |

Two of Phase 59's own tests were also repaired: the extension test's fake upstream
now records extended requests, so "it never reached the target" is an assertion
rather than a hope, and the fail-closed test no longer blocks to the suite timeout
in the very failure mode it guards. The two most load-bearing new tests were run
against the pre-fix code first and fail there — which is the only thing that makes
them evidence.

### Phase 60a — the gate opened on a ticket it had not checked (2026-08-06)

| Finding | Why it matters | Fix |
|---|---|---|
| **The use-time ticket re-check and the approval consume could disagree about which approval was being spent.** `ClaimApproval` validated the ticket on the approval `ActiveApproval` returned, then called `ConsumeApproval`, which re-ran its own selection. The fold's own comment called this "a small race" and accepted it. | It was not small, and it failed **open**: two connections racing each validated the front-runner's open change, and the second one's consume took the approval *behind* it — a cancelled change whose ticket was never put to the ITSM at all. The gate Phase 60 exists to provide opened on a ticket it had not checked. | `ConsumeApprovalByID` claims the id that was just validated, or reports that somebody else got there first. `ActiveApproval` (singular) is **replaced** rather than kept alongside, so the single-approval peek is not left in the interface for the next caller. |
| **One cancelled change locked an operator out of their whole window.** The mirror image, and worse in daily use: an approval with a rejected ticket shadowed every valid approval behind it *permanently*, because the fold refused before consuming and so could never clear it. | Anyone who could get a change cancelled could deny an operator access for the rest of the approval window. | `ClaimApproval` walks the candidates (bounded at 8, one shared ITSM deadline for the whole walk so several approvals cannot multiply the wait on an SSH handshake); a refused candidate is skipped rather than fatal, and the use is denied only when none passes. |

### Phase 61a — a credential reference that was a credential use (2026-08-07)

| Finding | Why it matters | Fix |
|---|---|---|
| **`createDependency` read `management_credential_id` as configuration.** It checked only that the id named an existing row. | Naming a credential means pamv1 will later decrypt that secret and present it, over WinRM, to a host **chosen freely on the same request**. That is a reveal with extra steps: a caller holding `CapManageCredentials` and nothing else could name a credential they may neither reveal nor rotate, point `host` at a machine they control, rotate any credential they *are* allowed to rotate, and receive the named secret. Proven end to end against a profile holding `manage_credentials` + `read_inventory` only, against a domain-admin credential on a target granted to somebody else. | `gateManagementCredential` applies the **reveal bar** to the management credential's own target: `CapRevealSecret`, the per-target grant, the approval requirement and the vendor contract gate. The capability is checked **before** the store lookup, so it is not an existence oracle. It checks the approval requirement with `HasActiveApproval` rather than claiming one — declaring is not the use — the single deliberate difference from `gateCredentialAccess`. A management credential must hold a **password**: an `ssh_key` in a WinRM password field is not authentication but disclosure of the whole key, and `ssh_ca` holds no secret at all; both are refused at declaration **and again** at use, so a row written straight into the database cannot leak one either. |

## The 2026-08-07 review of 62–65 — reading the fixes

The sweep above was closed by phases 62–65; those phases were then read the same
way, on the argument the 52a–52g rounds established — the review of a fix is part
of the fix, and the author is the worst person to be its only reader. Three
findings, **all in code written by the pass that closed the sweep**, none a
bypass. Closed in Phase 66.

| id | Finding | Why it matters | Status |
|---|---|---|---|
| ~~AV~~ | **The SFTP handle-table bound was nine times what its own comment claimed.** Phase 63 bounded `files` at OPEN time but checked `len(c.files)` alone, so every OPEN a client pipelined before the first HANDLE returned saw an empty table and was admitted. | Bounded either way — the ceiling was `sftpCaptureMaxPending + sftpCaptureMaxOpen` = **1152**, not the 128 the comment stated — so the Phase 63 finding stayed closed and nothing grew without limit. But a bound nobody can derive from its own comment is the same defect as a comment describing a knob that does not exist, which is what Phase 63 *removed* two files away. Reproduced at 600 admitted opens. | **Fixed in Phase 66**: opens in flight count toward the bound; the test fails against the old check. |
| ~~AW~~ | **`release.yml`'s `dry_run` input had become dead.** Once Phase 65b stopped skipping the release job on `workflow_dispatch`, `REAL` derived from the event name alone and the boolean controlled nothing — `dry_run: false` behaved exactly like `true`. | A pipeline whose own interface promises a choice it cannot make. Same class as the dead `sftpCapture.required` field Phase 63 removed, one phase later and in the release path. | **Fixed in Phase 66**: the input is removed, so `workflow_dispatch` is unambiguously the rehearsal — which also removes the ability to publish a signed release by hand from an arbitrary ref, a control rather than a loss. |
| ~~AX~~ | **The path-derived session id reached three audit details raw**, while the `mustAudit` call three lines away quoted and bounded it. | Not reachable with hostile text today — only a value matching a real pending session id gets to those branches — so it was safe **by circumstance**, and circumstance is what changes when somebody adds a branch. | **Fixed in Phase 66**: `auditField` at all three sites. |

**A process finding from the same period, recorded because it invalidated
reporting rather than code.** Three low-level change-log entries (Phases 65b, 67b
and 68) were written by a build script using `str.replace` with an anchor that did
not match. `replace` is a silent no-op on a miss, so the documents were reported
updated when they were not, and the gap was only found by counting entries. It is
the same shape as most findings in this document — an operation that does nothing
when its precondition fails and says nothing about it — arriving through tooling
instead of the product. Every such replacement now asserts its anchor first.

## The 2026-08-07 sweep — the six phases nobody had read as a whole

A fourth read-only sweep, over phases **56–61a**: cross-replica step-up decisions
(56), RFC 8693 token-exchange minting and Terraform remediation (57), safe-scoped
policy (58), SFTP per-file content recording (59/59a), the connect-time ticket
gate (60/60a) and dependency management credentials (61/61a). Phases 60a and 61a
had each been reviewed on their own, but the six had never been read together,
which is where the newest ~4k lines of production code were. Dimensions: the
authorization surface of the new routes and gates, fail-open/fail-closed
consistency, concurrency and resource bounds in the two new state machines,
crypto and secret handling on the new bus payloads and the minted tokens, audit
completeness, and documented-claim-versus-code drift.

The central invariant held again, and so did the two most load-bearing new
mechanisms: the token-exchange minter's actor chain round-trips exactly against
`svid.go`'s verifier with the depth cap consistent at both ends and delegated
expiry bounded by the delegator's; and `blast/terraform.go` escapes every
interpolation site, so no attacker-influenced id reaches generated HCL unescaped.
Nine findings. **All are now closed** — AM/AN in Phase 62, AO–AU across Phases
62–63, and AO's residual in Phase 89. These Status cells lagged that reality: the
closures were tracked in
[ROADMAP §0](../ROADMAP.md#0-open-findings-from-the-2026-08-07-sweep) and here they
sat marked "Open", which is **finding AT recurring** — the self-audit of record
asserting open defects that were fixed. Phase 89 reconciled the table.

| # | Finding | Why it matters | Status |
|---|---|---|---|
| ~~AM~~ | ~~**A sealed cross-replica step-up decision could be replayed onto the session's NEXT pause.**~~ The seal bound `{session, verdict, decider}` with a ±2 min freshness window, but `StepUp.pending` is keyed by session id and a session pauses **once per flagged statement** — so a decision named a session, not a pause. | **Bypass, plus a false audit record.** PostgreSQL `NOTIFY` has no privilege model, so anything holding a database session can read a genuine approval off the channel and publish it back. Inside the window the replay released the operator's next flagged statement with no supervisor in the loop, and the applying replica audited `session.stepup_decided … decider:<the supervisor who decided the previous statement> via:bus`. The code's own claim — "a replay inside the window finds the entry already claimed" — held only if the session did not pause again, and for a database session under a step-up policy pausing twice inside two minutes is the ordinary case. | **Fixed in Phase 62a.** `StepUpDecision.Pause` carries the pause's registration time (microseconds, so it survives the `timestamptz` round trip), bound into the AAD because it is the field a replay would want to change; `StepUp.claim` refuses an entry whose pause differs and reports it distinctly, so a stale message is told apart from "not hosted here". Refused replays are **logged, not audited** — the payload is readable to any database session, and a row per arrival would let a flood amplify into a trail the retention worker will not prune with the chain on. Test: `session.TestStepUpBusDecisionCannotBeReplayedOntoTheNextPause`, verified to fail against the old code, where the replay released the second statement. |
| ~~AN~~ | ~~**Every documented deployment path pinned an image that predated ten security fixes.**~~ `v0.10.0` was tagged 2026-07-28; the 2026-07-30 sweep's fixes landed over the following two days. | **The whole of the sweep above, undelivered.** `deploy/k8s/deployment.yaml`, `deploy/k8s/conjur/deployment.yaml`, `deploy/terraform/variables.tf` and the Helm chart all resolved `0.10.0`, so an operator following the README got a build containing the tunnel-scoped viewer token that authenticated at all three session proxies (reproduced *opening a session*), the unauthenticated live and kill buses, and the rest. Finding 18's shape exactly — a pin is only as good as what it points at — and it silently undid the fourth beta criterion, since "deploys as code" had come to mean "deploys the pre-fix code". | **Fixed in Phase 62b.** `v0.11.0` cut through the test-gated pipeline; all four pins moved together (the Helm chart to `0.2.0`/`appVersion 0.11.0`); `[Unreleased]` promoted with the bus wire-format upgrade note; both READMEs now state the current release rather than the first. |
| ~~AO~~ | ~~**`session.stepup_decided` is written before the outcome is known.**~~ `decideStepUp` calls `mustAudit` first, then `DecideBy`; the self-approval 403 and the cluster-wide 404 both return afterwards. | **Audit fidelity at a four-eyes decision point.** A refused self-approval leaves a positive "decided" record attributed to the session's *own operator* — precisely what the self-approval refusal exists to prevent — and any `approve`-capable principal can write decision records for sessions that were never paused, into a chained trail the retention worker will not prune. The pre-audit is correct and must stay: a released statement must not outlive the evidence of who released it. | **Fixed in Phase 63 + Phase 89.** Phase 63 moved the systematic refusals (self-approval, paused-nowhere) *before* the fail-closed audit, so an ordinary refusal writes no record. Phase 89 closed the residual this line itself predicted: when a decision **is** attempted and the *dispatch* then fails — or a local `DecideBy` loses the race the advisory pre-check cannot — the `session.stepup_decided` was already written and stood for a release that never happened. A compensating **`session.stepup_decision_voided`** (best-effort, attributed to the decider, `reason:` dispatch-failed / self-approval-race / already-resolved) now nets it out. Test: `api.TestStepUpDispatchFailureVoidsTheDecidedRecord`, verified to fail against the pre-fix code. |
| ~~AP~~ | ~~**`session.playback` is best-effort audited.**~~ `playRecording` uses `s.audit`, not `mustAudit`. | **The one read of KEK-protected material that is.** Reveal, checkout, app-secret, MFA enrolment, break-glass, token exchange, viewer connect, WinRM run and both proxies' session start all fail closed (invariant §6.4). Playback decrypts a sealed recording — everything the operator typed and saw — and since Phase 59 `serveSFTPContent` serves the reconstructed bytes of a transferred file, so it can hand over an actual secret. With the audit store down, all of that is readable with no durable record. | **Fixed in Phase 63.** `playRecording` uses `mustAudit`, so playback — and the `serveSFTPContent` reconstruction it gates — fails closed when the durable audit is unavailable, like every other read of KEK-protected material (invariant §6.4). |
| ~~AQ~~ | ~~**`sftpCapture.required` is dead state.**~~ Assigned from `PAM_REQUIRE_RECORDING` in the constructor and never read anywhere. | **Documentation describing a knob that does not exist.** The file header, the constructor doc and two method docs all say an unwritable artifact refuses the transfer *under required mode*; in fact `broken`/`refuseData` refuse in every mode, so the behaviour is stricter than documented rather than weaker. Not a hole — but a reader reasoning about the posture from the comments reasons about a control that is not there. | **Fixed in Phase 63.** The dead field was removed; the SFTP inspector refuses an unwritable artifact's data in every mode, which is the stricter, honest posture the comments now describe. |
| ~~AR~~ | ~~**The per-session SFTP artifact bound stops counting exactly when a client misbehaves.**~~ `bindHandle` inserts into `c.files` **before** the `sftpCaptureMaxOpen` check and returns early without advancing `c.seq` — the counter `trackOpen` enforces the 10 000-artifact bound on. | **A bound that reads as protection and is not, past 128 open artifacts.** Every further OPEN adds a permanent `c.files` entry no bound covers, and `openArtifacts()` rescans the whole map on each one, under the mutex both SFTP legs need for every packet — so the cost is quadratic. Scoped honestly: a real sftp-server self-limits at its file-descriptor ceiling (~1k entries), so this is not a practical DoS from the client side; a **compromised or hostile target** answering every OPEN with a fresh handle is not so limited. The bounds block's stated purpose is that a hostile client cannot grow the proxy's memory or descriptors without limit. | **Fixed in Phase 63.** A real `c.open` counter (incremented on bind, decremented in `finalizeLocked` — the one place a file is closed) replaces the whole-map rescan, and `bindHandle` checks it before admitting data, so a hostile target answering every OPEN with a fresh handle is bounded, not quadratically rescanned under the SFTP mutex. |
| ~~AS~~ | ~~**Audit-vocabulary drift, in both directions.**~~ `breakglass.unseal_failed` (`breakglass_handlers.go`) and `session.relay_start` (`livebus.go`, added by the AF fix) are emitted and absent from §5; `proxy.auth_rate_limited` is listed in §5 **and** classified by the OCSF exporter, while no code path can produce it since Phase 52e made both proxies log-without-append on the throttle branch. | **The vocabulary is the contract SIEM rules are written against.** A prior sweep verified "159 actions, no drift either way", so this is new; a dead action in the OCSF map is a rule that can never fire, and two undocumented ones are events nobody will write a rule for. | **Fixed in Phase 63.** `breakglass.unseal_failed` and `session.relay_start` are in §5; `proxy.auth_rate_limited` is gone from the OCSF classification, with a comment recording why (no path emits it since Phase 52e). |
| AT | **This document was six phases stale and self-contradictory.** Its header claimed phases 0–55, and the 2026-07-30 section said "All of it is now closed" above a paragraph still listing that sweep's findings as "being worked through in severity order". | **The self-audit of record asserting open defects that were closed a week earlier.** A reader — the audience this document exists for — would conclude pamv1 had unfixed reproduced defects in its live buses. | **Partly fixed here**: the header is current and the contradicting paragraph is corrected. **Open**: phases 56–61a still have no entries of their own, including the Phase 59a fifteen-finding review. |
| ~~AU~~ | ~~**Deployment reference drift.** `deploy/docker/.env.example` omits all three Phase 57 variables (`PAM_BROKER_TOKEN_EXCHANGE`, `PAM_BROKER_TOKEN_SIGN_SEED`, `PAM_BROKER_EXCHANGE_TTL_MIN`).~~ | **Finding V recurring, one phase later.** An operator running the shipped compose stack cannot discover a security feature the docs elsewhere claim exists — which is how a feature ships and is never turned on. | **Fixed in Phase 63**: the three variables are in the reference env file, in their own block, stating that they need the SVID block above them. **A second half of this finding was withdrawn, and how it arose is worth more than the finding was.** It was reported that §4 of the low-level doc omitted ~34 variables the code reads, including credential-bearing ones. It does not: §4 documents families in a slash shorthand (`` `PAM_LDAP_BIND_DN` / `_BIND_PASSWORD` ``, `` `PAM_KEK_PKCS11_MODULE` / `_PIN` / `_KEY_LABEL` / `_TOKEN_LABEL` ``), and the check that produced the number matched whole `PAM_*` tokens only, so every suffix-only entry read as absent. Expanding the shorthand before comparing gives **zero** missing of the 158 variables the code reads. A drift check that does not understand the document's own notation manufactures drift — which is the same class of error as a test that cannot fail, arriving from the other direction. |

## The 2026-07-30 sweep — six parallel dimensions

A third read-only sweep, run over the tree as it stood after Phase 55, across six
dimensions in parallel: the authorization surface, the newest code's correctness
(Phase 55 itself), its trust boundaries, audit completeness and secret hygiene,
resource limits and fail-open defaults, and documented-claim-versus-code drift.
Every finding was confirmed by reading the code before being recorded, and the
highest-severity ones were re-verified independently — two of them by
reproduction (a panic, and a viewer token that provably opened a session).

**All of it is now closed**, across ten changes landed on 2026-07-30/31 — the
detail of each is in the [low-level change log](ARCHITECTURE-LOW-LEVEL.md#8-change-log).
Two things are worth keeping from how it went:

1. **Every regression test was run against the original code first.** That is how
   we know the viewer token *opened a session* rather than merely being accepted,
   that the end-marker race was deterministic in the exec-shaped case rather than
   rare, that a forged `NOTIFY` really did terminate a live session, and that the
   recording-cap test was not quietly passing on a read timeout. Three tests
   written this way failed to prove anything on the first attempt and had to be
   rewritten — which is the argument for the practice.
2. **Four of the findings were in code that had shipped the day before**, and one
   of the sweep's own dimensions was aimed at exactly that. New code is where the
   defects are, and reviewing it before it ages is cheaper than finding it later.

| id | Finding | Status | What was done |
|---|---|---|---|
| ~~AD~~ | **A tunnel-scoped viewer token authenticated at all three session proxies.** `Principal.TunnelOnly` was enforced only in `api`'s middleware; the SSH, PostgreSQL and SQL Server proxies resolved the same token through the same resolver and never checked it. A viewer token rides a WebSocket **URL** (so it reaches access logs) and carries **no target binding**, and expiry is checked only at the handshake — so a 60-second copy opened a full JIT session on any target its owner could reach, for as long as that session lived. | **Fixed** | All three listeners refuse it and audit `reason:tunnel-only-token`. Both regression tests provably fail without the fix: the SSH proxy *opened a session*, the DB proxy answered `AuthenticationOk`. |
| ~~AE~~ | **Break-glass through a session proxy raised no signal.** The proxies read `principal.BreakGlass` only to skip the four-eyes approval gate — no `breakglass.access` event, no alert, no `pam_breakglass_access_total` — so the one path that deliberately bypasses approval was the quietest in the system, while the same key against `GET /api/me` produced all three. Finding #7 fixed this class for the HTTP middleware and Phase 52c for the RDP tunnel; the proxies were never covered. | **Fixed** | Shared `proxy.noteBreakGlass` (one implementation, three wrappers) audits it; new `OnBreakGlass` hooks are wired in `main` to `api.Server.NoteBreakGlassSignal`, which owns the alerter and the metric. |

| ~~AG~~ | **The kill bus was unauthenticated and bus-applied kills were unaudited** (Phase 34): `NOTIFY pam_session_kill` terminated every one of an actor's live privileged sessions cluster-wide, and the applying replica recorded nothing. | **Fixed** | `KillSelector.Seal` (AES-256-GCM over a timestamp, bound to the selector's fields, same shared-custody key as the relay); `StartKillBus` fails closed without a key; the applying replica audits `session.kill … via:bus`. A sealless selector provably kills against the old code. |
| ~~AF~~ | **The cross-replica live bus was unauthenticated**, and Postgres `LISTEN`/`NOTIFY` has no privilege model — notifications are visible to every user of the database and `LISTEN` needs no grant. So anything able to open a database session could announce interest and make a hosting replica stream a live privileged session's output to the bus, then read it (full terminal, verbatim SQL, WinRM output), with **no audit event on that path at all**; or inject frames to write fabricated output into a supervisor's pane, or an end marker closing their watch while the session ran on. It narrowed a boundary the project built on purpose: the KEK is outside the database, so database-only access had yielded ciphertext. | **Fixed** | Payloads are **sealed with AES-256-GCM** under a shared-custody key (`internal/session/livecrypto.go`); interest carries a timestamp so it cannot be forged or replayed; `StartCluster` fails closed without a key; the first relay of a session is audited `session.relay_start`; rejected payloads are counted and reported. Both forgeries provably succeed against the old code. |

Also closed in the same pass:

- **Kill cascades now audit unconditionally.** The count is what the LOCAL replica killed, but the kill is broadcast cluster-wide, so `killed == 0` routinely meant "hosted on another replica" rather than "nothing to cut" — and auditing only the non-zero case left the most consequential HA outcome with no evidence on the deciding side. The detail now reads `killed_here:N`, which is what it always meant.
- **WinRM output is capped** at 4 MiB per stream, with a truncation marker, instead of unbounded buffers copied several times into the transcript, the hash and the response — `type C:\big.iso` from a connect-capable operator or a broker agent could take the process to an OOM.
- **The discovery scan is bounded** end to end at two minutes. Hosts were capped at 1024 but the host x port PRODUCT was not, and the scanner dials sequentially: 1024 unreachable hosts across the six default ports is roughly 100 minutes of a wedged handler, long past the write timeout, so the caller saw nothing and retried.

Deliberately left, with reasons:

- **Every proxy connection reads the whole target inventory** (`lookupTargetCred` calls `ListTargets(ctx, 0, 0)` and linear-scans). Cheap to trigger, and the right fix is a `GetTargetByName` store method — a `store.Store` interface change with two implementations and a contract test, which is a phase-sized change rather than a hardening patch.
- **`PAM_MAX_SESSIONS_*` counts SSH connections, not channels**, so one connection can multiplex N shells under a single registry entry. A real OpenSSH upstream's `MaxSessions` caps it in practice, and the per-replica cap semantics are already documented; the channel dimension is not.
- **A recording's digest is audited on a `Close()` that never `fsync`s**, so an unclean host stop can leave the chain attesting to bytes not on disk. Ordinary process exit is safe.
- **Broker `Resume` is not bound to the requesting agent** (`Withdraw` is, via `sameAgent`). Exploitable only by a holder of both another valid agent key and the captured single-use token.

The rest of that sweep's findings **also landed**, on 2026-07-30/31, and are in
the [low-level change log](ARCHITECTURE-LOW-LEVEL.md#8-change-log) under those
dates: the three Phase 55 defects (a reproduced `send on closed channel` panic in
the memstore live bus, an end marker that could overtake queued output so a
remote watcher lost a run's final bytes, and a heartbeat that could resurrect an
ended session's inventory row for ~45s), both unauthenticated LISTEN/NOTIFY
buses, `PAM_MAX_RECORDING_MB` being a silent no-op on both database proxies, the
five paths that acted before or without recording it, the unbounded upstream
legs, and the dozen documented claims the code no longer supported. *(This
paragraph said they were "being worked through in severity order" for a week
after they were all done, contradicting the sentence above it — corrected
2026-08-07 by the sweep that noticed.)*

## The 2026-07-27 post-beta sweep — all 30 findings, now closed

A second full read-only sweep, run immediately after the beta milestone, over
dimensions the earlier passes had not covered as systematically: the
authorization surface re-derived from the route table, concurrency and resource
lifetime, fail-open error handling, cryptography and secret handling, input
validation, and the correctness of the newest code (phases 44–51, the least
reviewed in the tree). Every finding below was **confirmed by reading the code**
before being recorded; nothing here was speculative.

**Every one is now fixed**, across phases 52 through 52e — struck ids below, with
what was actually done in the final column. Two were housekeeping and shipped
with the report itself; the rest were real work.

Three things are worth keeping from how this went:

1. **Two of the thirty were regressions introduced the same day, and both passed
   their tests.** The certificate test used serials `101` and `102` — small
   enough that the defect could not appear — and the audit-paging test used the
   in-memory store, which was the generous implementation. Where practical, each
   fix's test was then **verified to fail against the old code** rather than
   merely to pass against the new.
2. **Not every finding deserved the obvious fix.** Re-wrapping sealed recordings
   during KEK rotation would have destroyed the tamper evidence they exist to
   provide, so that one is resolved as a documented retention rule and a warning
   instead. Recording that reasoning is the point of this document.
3. **One suspected finding turned out not to be one.** The write-timeout problem
   was verified empirically in both directions, which showed that hijacked
   WebSockets — the RDP viewer — do *not* inherit the server deadline. It got no
   speculative change.

The headline is that the earlier sweeps' conclusion still holds — the central
invariant (the operator never receives the vaulted credential), AAD parity, and
`SecretEnc` non-serialization are all intact, and the twenty audited
encrypt/decrypt sites are consistent. What this pass found instead clusters in
three places the previous ones did not look: **the one HTTP handler that
authenticates itself**, **cancellation and deadlines at the edges of the session
path**, and **an offline maintenance command that has not kept up with the
features added around it**.

Severity is stated plainly rather than scored: *outage* means a documented
procedure breaks the deployment, *bypass* means a control does not apply where
its peers do, *exposure* means information reaches somewhere it should not.

| # | Finding | Why it matters | Direction |
|---|---|---|---|
| ~~I~~ | ~~**`-rotate-kek` does not re-wrap the Phase-42 key-custody envelopes, so the documented rotation procedure leaves the server unable to start.** `maint.RotateVaultKEK` re-wraps credentials, MFA enrollments and secret settings; the `key_material` rows are untouched — and *cannot* be re-wrapped, because `Store` exposes only `EnsureKeyMaterial` (insert-if-absent, then read back) with no read or update path.~~ | **Outage, on a default configuration.** The admin guide's procedure is "run `-rotate-kek`, set `PAM_MASTER_KEY` to the new key, restart". On restart, `keycustody.Ensure` runs whenever `PAM_SSH_ADDR != off` (the default), reads back the envelope still wrapped under the **old** KEK, fails to unwrap it, and — deliberately, correctly — treats that as fatal (`cmd/pam-server/main.go` returns the error). `-rotate-kek` itself reports success, so the failure surfaces only at the restart. The obvious recovery, deleting the custody rows, regenerates the SSH host key and the ZSP CA — exactly the MITM-indistinguishable event Phase 42 was built to prevent. | **Fixed in Phase 52a.** `Store` gains `ListKeyMaterial` + `UpdateKeyMaterial`, and `RotateVaultKEK` re-wraps custody alongside the other three kinds — idempotently, like them, so an interrupted rotation is resumable. The function's doc comment now carries the exhaustive four-item list, because the failure mode of this bug was *omission*, not logic. Tests: `maint.TestRotateVaultKEKKeyMaterial` asserts the new KEK unwraps each key **and that the old one no longer does** (proving it moved rather than merely still working), plus a no-op second run; the store contract covers list ordering, re-wrap read-back, and `ErrNotFound` on an unclaimed name, so memstore and pgstore cannot drift. Verified the test fails without the fix. |
| ~~J~~ | **`-rotate-kek` also strands every sealed recording and WinRM transcript.** A sealed recording's header carries its per-recording data key wrapped by the KEK *current at the time of writing* (`recording.NewSealer`); rotation walks store rows only and never touches files. | **Silent, permanent evidence loss.** The guide's provider-migration example (local → AWS KMS) implies retiring the old local key; the moment it is gone, every recording sealed before the rotation fails to open, while its audited SHA-256 still "verifies" the now-unreadable bytes. Nothing in the docs warns that the old KEK must be retained for the whole recording-retention window. | **Resolved as documented-and-warned in Phase 52a, not re-wrapped — deliberately.** Re-wrapping was the obvious fix and is the wrong one: a recording's bytes are what the audit trail and the recording hash chain hold a SHA-256 of, so rewriting the header to swap the wrapping key would make every archived recording read as *never audited* — destroying the tamper evidence the sealing exists to provide, in order to avoid retaining a key. Instead `-rotate-kek` now counts sealed recordings in `PAM_RECORDING_DIR` and prints a warning naming the KEK they still require, and the admin guide states the retention rule explicitly: keep the old KEK for at least as long as you keep sealed recordings. |
| ~~K~~ | **The RDP tunnel is the one HTTP handler that authenticates itself, and it reproduces none of the middleware's failure handling.** `rdpTunnel` calls `resolver.Resolve` on the `?token=` query value and answers a bare `writeError(401)` — where all four other bearer surfaces call `authFailed`. Its two authorization denials likewise write 403 with **no audit event**. | **Bypass + exposure.** `Resolve` accepts *every* credential kind, including the bootstrap `PAM_API_KEY` and the break-glass key. So with RDP enabled, `GET /api/targets/{id}/rdp?token=<guess>` is an online guessing oracle against the admin key with **no rate limit and no `api.auth_failed` record** — invisible to the audit trail, the risk engine and the SIEM forwarder — while the identical guess via `X-API-Key` is throttled and audited (gap #26). Separately, a `user`-role operator enumerating target ids over the tunnel produces zero audit records, where every other connect path emits `authz.denied` or `*_denied … reason:target-policy`. Confirmed as a singular oversight: it is the only self-resolving handler in the tree, and no RDP test asserts on either behavior. | **Fixed in Phase 52c.** `rdpTunnel` now routes a failed token through `authFailed`, exactly as the `authz` middleware does — so it is throttled per source IP and appends `api.auth_failed` — and it audits `authz.denied` for both the enroll-only and the capability refusal, matching the middleware it bypasses. Test: `api.TestRDPTunnelAuthFailureIsThrottledAndAudited` asserts the 401, the audit record, and that repeated guesses reach 429. |
| ~~L~~ | **In-session step-up is the only decision point with no separation-of-duties check.** `decideStepUp` never compares the deciding actor to the paused session's actor, although `StepUp.Pending()` exposes it. | **Bypass.** Every peer enforces it — access requests, vendor grants, broker approvals and (since Phase 46) certification items all refuse self-approval explicitly. An identity holding both `connect` and `approve` — which a directory user in two mapped groups gets by design, since capabilities are unioned, as does a custom profile — can pause its own flagged statement, read its own session id from `GET /api/sessions/stepups` (`read_audit`), and release it. Phase 39 correctly raised this endpoint from `read_audit` to `approve` but left the supervisor self-serviceable. | **Fixed in Phase 52c.** `StepUp.DecideBy` refuses a decision made by the operator whose own session is paused, checked **under the same lock as the claim** so a race cannot slip one through, and reports self-approval distinctly from "nothing pending" so the handler returns 403 rather than a misleading 404. The refused decision leaves the step-up **still pending**, so a supervisor can resolve it — a refusal must not silently consume the gate. Audited as `session.self_stepup_denied`. Test: `session.TestStepUpRefusesSelfApproval` covers both approve and deny by the owner, the still-pending invariant, and resolution by a second person. |
| ~~M~~ | **The agent broker's `reveal_credential` and `rotate_credential` skip the four-eyes/maintenance-window gate that every other credential path enforces.** `authorizeAgentCredential` checks target grants and stops; its sibling `authorizeAgentTarget` (used by `winrm_exec`/`ssh_exec`) additionally runs `enforceApproval`, and the human reveal path runs the full `gateCredentialAccess`. | **Bypass, by the least-trusted actor.** With `require_approval` set on a target, a human holding `reveal_secret` must obtain an approved access request; an agent allowed `reveal_credential` by broker policy gets the plaintext at any hour, outside any window. `rotate_credential` likewise changes a target's password ungated. `reveal_credential` ships default-deny, which limits blast radius, but the omission is silent when an operator enables it. The comment on `authorizeAgentTarget` ("centralizes the checks winrm_exec and ssh_exec share") suggests an oversight rather than a decision. | **Fixed in Phase 52c.** `authorizeAgentCredential` now runs `enforceApproval` unless the call already carries an approval, exactly as its sibling `authorizeAgentTarget` does — so `reveal_credential` and `rotate_credential` obey the four-eyes/maintenance-window requirement that the human reveal path has always enforced. The least-trusted actor no longer has the weakest gate. |
| ~~N~~ | **No pre-authentication deadline on either proxy listener.** There is not one `SetDeadline` call in `internal/proxy`: `ssh.NewServerConn` and the PostgreSQL `ReceiveStartupMessage` both block indefinitely on a client that connects and says nothing. | **Availability.** Each silent connection parks a goroutine and a file descriptor until process exit. Nothing caps *unauthenticated* connections — the session caps apply after authentication, and the auth rate limiter only counts password attempts, which a silent client never makes. Exhausting descriptors makes `Accept` return `EMFILE`, which is `Temporary()`, so the accept loop spins in backoff and no operator can connect. A security appliance's front door should not be trivially wedgeable. | **Fixed in Phase 52d.** Both proxies set a 30-second deadline on the raw connection before the handshake and clear it once authenticated — the SSH proxy around `ssh.NewServerConn`, the PostgreSQL proxy around the startup/TLS/password exchange. Cleared afterwards on purpose: an established session is legitimately idle while an operator reads output, and a deadline that survived authentication would cut working sessions off. The DB proxy clears it on `nConn`, not on the TLS wrapper that may now sit above it, since a deadline set on the socket cannot be undone through the wrapper. |
| ~~O~~ | **A killed `ssh_exec` keeps running on the target.** `rotate.SSHConnector.execGuard` closes the SSH session only when `ctx.Err() == context.DeadlineExceeded`; on `context.Canceled` its goroutine exits without closing anything. | **The kill switch does not kill.** The registry's kill callback *is* `cancel` (`superviseSession`), so a supervisor's kill — and the analytics auto-response, the vendor sweeper and the revoke cascade, which all use the same path — cancels the context, the guard exits silently, and `CombinedOutput` keeps executing the agent's command on the target with the just-in-time credential while the registry reports the session killed. Worse, because the guard goroutine is gone, the 15-second timeout can no longer fire either, so a wedged target parks the caller indefinitely. This contradicts Phase 40's documented guarantee that "a kill cancels the run's context and it returns 503". | **Fixed in Phase 52d.** `execGuard` now watches three signals instead of conflating two: a timer for the connector timeout, the caller's context for a kill, and a `done` channel the stop func closes on normal completion. The old version derived a timeout context and closed the session only on `DeadlineExceeded`, because the stop func itself cancelled that context and treating cancellation as a trigger would have closed the session on every successful run — the exclusion was deliberate but it disabled the case that matters most. Test: `rotate.TestSSHExecStopsWhenContextIsCancelled` asserts both that `Exec` returns promptly **and** that the channel to the target was torn down; verified it fails (hanging the full 5s) against the old code. |
| ~~P~~ | **A global 30-second `WriteTimeout` caps every server-sent-events stream.** `cmd/pam-server/main.go` sets `ReadTimeout`/`WriteTimeout` to 30s on the single `http.Server` that also serves `GET /api/sessions/{id}/stream` (live session monitoring) and `GET /mcp` (the MCP SSE transport). No route extends the deadline — there is no `http.ResponseController` use anywhere. | **A headline feature has probably never worked in a real deployment.** `WriteTimeout` dates from Phase 1; SSE arrived in Phases 16 and 27, so live monitoring has been cut off after ~30 seconds since the day it shipped, and MCP elicitation (which waits up to 30s on that stream) routinely loses its transport mid-flow. Every test uses `httptest`, which sets no timeouts, so the suite cannot see it. The RDP WebSocket is unaffected — hijacking clears the deadlines. | **Fixed in Phase 52d.** The root cause was not the timeout but the access-log `statusWriter`, which wrapped the `ResponseWriter` without an `Unwrap` method — so `http.ResponseController` could not reach the connection to clear the deadline. `Unwrap` is added (generalising the hand-written `Flush` and `Hijack` passthroughs that had each been added after something broke), and a shared `beginStream` helper clears the write deadline for both SSE endpoints. Verified empirically in both directions: an SSE stream under a 1s `WriteTimeout` delivers one frame and dies, and clearing the deadline delivers all of them. **Also verified the WebSocket path is NOT affected** — a hijacked connection does not inherit the server deadline — so the RDP viewer needed no change and did not get a speculative one. Test: `api.TestSessionStreamOutlivesWriteTimeout`. |
| ~~Q~~ | **Expired login sessions are never collected.** The only deletes on `sessions` are explicit logout and per-username revocation; expiry is enforced by filtering reads (`expires_at > now()`), never by removing rows. | **Unbounded growth.** Every portal login, every break-glass activation and every 60-second RDP viewer token inserts a row that lives forever. Contrast the deliberate GC given to broker tokens (swept every 10 minutes) and OIDC states (self-GC on write). In PostgreSQL this is table bloat; in the memstore it is a genuine leak of one permanent map entry per RDP viewer open. | **Fixed in Phase 52d.** New `store.DeleteExpiredSessions(ctx, now)` in both implementations, covered by the contract suite (including that a live session survives the sweep and that a second pass is a no-op). The scheduler's `RunBrokerTokenGC` becomes `RunGC`, sweeps login sessions unconditionally, and — the other half of the bug — is now started unconditionally: it used to run only when a broker policy file was configured, so the common deployment had no garbage collection at all. |
| ~~R~~ | **A certification revoke does not cut the revoked user's live sessions.** `revokeAccess` deletes the grant and stops; the `DELETE /api/targets/{id}/grants/{gid}` route reaching the same state change additionally kills the user's sessions to that target and audits `session.killed`. | **Inconsistency with a fixed gap.** This is precisely the behaviour gap #22 added, applied to one of the two routes that revoke access. An operator revoking access during a certification campaign leaves the in-flight session running. It also emits only `certification.item_revoked`, so a query on `grant.delete` misses grants removed by a campaign. | **Fixed in Phase 52e.** `revokeAccess` resolves the affected target names **before** deleting (afterwards the link is gone) and then cuts the revoked user's sessions to them, exactly as `DELETE /api/targets/{id}/grants/{gid}` does for the same state change. A safe membership resolves to every target scoped to that safe. Role grants remain unmatched — the session registry does not carry each session actor's role set — which is a limit shared with the grant-delete route and now stated in the code. Without this, a campaign whose entire purpose is a reviewer deciding someone should no longer have access removed the grant while leaving the operator connected. |
| ~~S~~ | **MFA recovery codes are offline-crackable from a database backup.** Each code carries 50 bits of entropy (8 random bytes, base32-encoded, then **truncated** to 10 characters) and is stored as a single unsalted SHA-256. | **Exposure to exactly the adversary the vault defends against.** An attacker with database, backup or snapshot read access can brute-force 2^50 unsalted SHA-256 on commodity GPUs in about a day — less with ten valid codes per user — and a recovered code substitutes for the TOTP second factor at login. Every other stored bearer secret is 192-bit and uncrackable; this is the one weak hash in the store. | **Fixed in Phase 52e.** Recovery codes now carry **120 bits** (15 random bytes → 24 base32 characters, grouped `abcdef-ghijkl-mnopqr-stuvwx` for transcription) instead of 50. Plain SHA-256 remains appropriate and that reasoning is recorded in the code: rainbow tables and precomputation need a small or predictable input space, which a random 120-bit value is not — a slow KDF defends a *low*-entropy secret, and the right fix for a generated one is to stop generating it small. The test asserts the entropy, not just the shape. |
| ~~T~~ | **`createVendor` bypasses the privilege-escalation guard its siblings enforce.** It mints a `user`-role login and returns a working token with no `principal.Covers()` check, unlike `createUser`, `updateUser` and `createProfile`. | **Bypass, with bounded impact.** A delegated user-admin holding `manage_users` but not `connect` is refused by `POST /api/users {"role":"user"}` yet can mint the same capability set through `POST /api/vendors`. The vendor gate then keeps the identity contract-gated on every connect path (all fail-closed), so this is a hole in the guard rather than a direct path to access — but it also lets that delegate create a login under an arbitrary name, and mark an arbitrary existing username a vendor, which blocks that user from every target. | **Fixed in Phase 52c.** `createVendor` applies the same `Covers` privilege-escalation guard as `createUser`. The vendor's role is fixed at `user` rather than caller-chosen, which is precisely why the check was missed — but a fixed role is not a safe one: a delegated user-admin lacking the `user` role's capabilities could mint a login that had them, with the token returned in the response. Test: `api.TestVendorCreateRefusesPrivilegeEscalation`, which also asserts the unconstrained admin can still create vendors, so the guard did not simply break the feature. |
| ~~U~~ | **CI ran one of the three live-PostgreSQL tests.** The job's `-run PGStoreContract` filter matched the contract suite alone, leaving `TestPGStoreAuditChainTamperDetection` and `TestPGStoreLeaderLockMutualExclusion` executing **nowhere** — they skip locally without `PAM_TEST_DATABASE_URL` and were filtered out in CI. | **False assurance on two security claims.** One proves the tamper-evident audit chain actually detects a database-level edit; the other proves the advisory leader lock actually excludes concurrent holders, which HA correctness depends on. Both had been dead since they were written. | **Fixed in this change** — the filter is removed so the whole package runs, with a comment recording why a filter must not come back. |
| ~~V~~ | **The deployment reference env file is five phases stale.** `deploy/docker/.env.example` documents every other optional feature but omits `PAM_AUDIT_FORWARD_CA`, `PAM_RECORDING_OPAQUE_NAMES`, `PAM_RETENTION_ARCHIVE_DIR`, `PAM_RDP_CLIPBOARD_AUDIT` and `PAM_SSH_SFTP_DENY_FILE`, and two of its comments are now wrong (the forwarder is described as "syslog or CEF" over "udp \| tcp", and the recording note predates opaque names). | **Discoverability, and a deployment trap.** An operator running the shipped compose stack cannot find five security features the docs claim exist. `PAM_RETENTION_ARCHIVE_DIR` additionally needs guidance: the container is `read_only` with only `/data` writable, so pointing it at a WORM mount requires an explicit volume. | Bring the file up to date and add the archive-mount note. |

| ~~W~~ | ~~**Command injection through credential dependencies, on an operator-chosen host, bypassing every session control.** `dependencyCommand` interpolates the dependency's `Name` straight into a `cmd.exe` command line (`sc.exe config "%s" password= "%s"`, and the `schtasks`/`appcmd` equivalents); `createDependency` validates only that the kind is one of three, that host and name are non-empty, and that the port is in range — **no metacharacter check at all**.~~ | **The most serious finding of the sweep.** A `Name` of `svc" & powershell -enc … & rem ` closes the quote and chains an arbitrary command, executed by `propagateDependencies` on the next rotation (manual, on check-in, or from the scheduled worker) as the vaulted privileged account. Two aggravating factors: `Host` is never checked against the target inventory, so the command lands on **any host reachable from the pamv1 server** — outside target grants, the approval gate and the vendor gate; and `propagateDependencies` calls `winrm.Run` **directly**, so unlike `execWinRM` and `ssh_exec` it never reaches `guardCommand`, never registers with `superviseSession`, and is neither killable, capped, nor recorded. `CapManageCredentials` is meant to manage credentials, not to be arbitrary remote code execution on arbitrary hosts. | **Fixed in Phase 52.** `Name` and `Host` are now allowlisted (`^[A-Za-z0-9 ._\-()\\/]{1,128}$` and a hostname/IP shape) — an allowlist, because a service, task or app-pool name legitimately needs letters, digits, spaces and a few separators and nothing a shell can act on. Enforced at creation **and again in `dependencyCommand`**, so a row written before the rule existed, or straight into the database, still cannot reach a command line; an unusable name is audited and skipped rather than executed. The propagation now also runs through `guardCommand`, so Phase 38's one-policy-everywhere principle finally covers this path. Tests: `api.TestDependencyNameRejectsCommandInjection` (eight break-out shapes and four hostile hosts refused; five real-world names — spaces, dots, a backslash — still accepted). Remaining, documented rather than closed: the host is validated in *shape* but is still not required to be in the target inventory, because a consumer may legitimately run somewhere that is not itself a PAM target. |
| ~~X~~ | ~~**The WinRM rotation username blocklist is incomplete.**~~ `rotate.WinRMConnector.Rotate` rejects only `space`, `"`, `\n` and `\r` before building `net user %s %s /y` — an **unquoted** interpolation — so `&`, `\|`, `^`, `<`, `>`, `(`, `)` and `%` all pass. | **Injection on the same privileged path.** A credential created with username `svc&calc` (only emptiness is validated) yields `net user svc&calc … /y`, and cmd.exe runs the tail as a second command during rotation — with the same `guardCommand`/supervision bypass as W. The SSH rotator is the instructive contrast: it feeds `user:pass` on **stdin** and so needs to reject almost nothing. | **Fixed in Phase 52.** The blocklist is replaced by an allowlist (`^[A-Za-z0-9._@\\$-]{1,104}$`) covering the account shapes Windows actually uses — `DOMAIN\user`, `user@realm`, `gMSA$` — and nothing a shell can act on. Test: `rotate.TestWinRMConnectorRejectsInjectableUsername` proves thirteen hostile names are refused *and never reach the runner*, while six legitimate ones still rotate. |
| ~~Y~~ | **The two newest execution paths run with best-effort auditing only.** `Server.audit` explicitly discards the store error; the RDP viewer decrypts the credential and brokers the desktop with only `s.audit("rdp.connect", …)`, and the REST WinRM endpoint audits `winrm.run` **after** the command has already executed. | **Fail-open on the "every secret use is audited" invariant.** Both SSH and DB proxies refuse the session outright when the audit store is unavailable, and `mustAudit` exists for exactly this. So an audit outage silently permits a full privileged RDP session and an unrecorded WinRM command, while the same failure refuses an SSH session. Note the inversion: the *same* `execWinRM` reached through the agent broker **is** covered, because `ProcessCall` writes into the hash chain and refuses on failure — the least-trusted actor is protected on a path where the human REST caller is not. | **Fixed in Phase 52c.** The RDP session-start audit now fails **closed** — a privileged desktop that leaves no durable record of being opened is precisely what this system exists to prevent — and the WinRM `winrm.run` audit surfaces its error so the handler returns 503 with the result **withheld** rather than handing back output the system of record never accounted for. (The command has already run at that point; withholding the output is the strongest remedy available, and it makes the missing record visible to the operator instead of silent.) |
| ~~Z~~ | **`PAM_REQUIRE_RECORDING` covers two of the four session paths, and this document said otherwise.** The flag is implemented only in `internal/proxy`; `requireRec` appears nowhere in `internal/api`, and `api.Options` has no such field. | **A fail-closed control that silently does not apply.** With the flag set — an operator's explicit "refuse rather than run unrecorded" — an in-portal RDP session and a REST WinRM run both proceed when recording is unavailable. The "Not changed by design" note below claimed the opt-in fail-closed control "already exists", without that qualification. | **Fixed in Phase 52c.** `PAM_REQUIRE_RECORDING` now covers the two paths it never reached. Both checks run **before** anything happens on the target: for RDP before guacd is contacted or the credential is used, and for WinRM before the command executes — the transcript is written from the result, so a post-hoc check would report a failure the command had already caused. Refusals are audited (`rdp.refused`, `winrm.refused`) and return 503. Tests assert not only the status but that guacd was never contacted and the command never ran. |
| ~~AA~~ | **The cluster kill-switch reports success when the broadcast failed.** `Registry.publish` discards the error from `PublishSessionKill`, and `KillDistributed` decides its return value from *whether a bus is configured*, not from whether the publish succeeded. | **The one control whose entire purpose is termination.** If `pg_notify` fails, or the owning replica is inside its LISTEN reconnect window (NOTIFY has no replay, so the message is simply lost), the session keeps running while the API answers `202 Accepted` and audits `session.kill … scope:cluster`. The revoke cascade, vendor offboarding and the analytics auto-response all report success the same way. Not blocking the caller is right; not reporting the failure is separable from that. | **Fixed in Phase 52d.** `publish` reports whether a bus exists **and** whether the broadcast succeeded; `KillDistributed` returns the new `KillDispatchFailed` when the session is elsewhere and the broadcast did not get there, which the handler maps to 503 with a `session.kill_failed` audit rather than 202. An operator cutting off a live privileged session must not be told it worked when it did not. The bulk-kill paths, which return no outcome to a caller, now log the failure loudly — a silent one there means a revoked operator keeps a live session on another replica. |
| ~~AB~~ | **A policy file that yields zero usable patterns disables the control and logs that it is enabled.** `cmdguard.New` returns `(nil, nil)` when nothing survives parsing, and a nil `Guard` never blocks; startup then logs `"… control enabled" patterns=0`. `ParseDeny` compounds it — a `bufio.Scanner` with the default 64 KiB token cap whose `Err()` is never checked, so one over-long line silently truncates the rest of the file. | **Fail-open on three separate controls.** An empty or lost file (an unmounted ConfigMap, a bad path) silently disables `PAM_COMMAND_DENY_FILE`, `PAM_SSH_SFTP_DENY_FILE` or `PAM_DB_STEPUP_FILE` while asserting the opposite in the log. Setting the variable *is* the operator's declaration of intent, and config validation refuses to start for far milder inconsistencies. The code comment introduced with Phase 51 states the exact failure it does not prevent: an operator "would not find out until a file left the building". | **Fixed in Phase 52d.** Two fail-open paths, both closed. `cmdguard.New` returns `ErrNoPatterns` instead of `(nil, nil)`, and every call site treats it as fatal — setting `PAM_COMMAND_DENY_FILE`, `PAM_SSH_SFTP_DENY_FILE` or `PAM_DB_STEPUP_FILE` is a statement of intent, so "I asked for this control and got none" must refuse to start rather than log that it is enabled with zero patterns. `ParseDeny` splits the string directly instead of running a `bufio.Scanner`, removing the 64 KiB token limit that silently discarded every pattern after one over-long line (its `Err()` was never checked), and trims CRLF so a file saved on Windows behaves identically. Tests: `cmdguard.TestParseDenyHandlesLongLines`, `TestParseDenyCRLF`, and the updated `TestGuard`. |
| ~~AC~~ | **The audit trail accepts unauthenticated, unbounded, attacker-shaped input.** Three sites: the proxies audit `proxy.auth_rate_limited` **on the throttled branch** (the API middleware deliberately returns *before* auditing, which is the property gap #26 established) with the raw SSH login as the actor; `api.auth_failed` interpolates the percent-decoded `r.URL.Path` into the detail; and the SFTP inspector interpolates client-supplied paths raw, where the same package's `auditCmd` applies `strconv.Quote` and a length cap. | **Integrity and growth of the system of record.** Anyone who can reach `:2222` can append audit rows without limit — the rate limiter bounds authentication attempts but not audit writes — choosing the `actor` text, and with the HMAC chain enabled the retention worker deliberately refuses to prune them. The path and SFTP sites let newlines and forged `key:value` pairs into details. Every current consumer sanitizes on the way out (the SIEM forwarder, CSV export, the portal), so the exposure is to a raw reader of the column. | **Fixed in Phase 52e.** All three sites. Both proxies now **log without appending** on the throttled branch, matching the API middleware — the failures that preceded the throttle are the signal, and one row per attempt under a flood makes the audit trail the amplifier, which matters more with the HMAC chain on because the retention worker then refuses to prune them. `api.auth_failed` quotes and bounds the percent-decoded path, and the SFTP inspector gives client-supplied paths and patterns the same `auditField` treatment the package already applied to commands. Test: `proxy.TestAuditFieldCannotForgeFields` covers forged `key:value` pairs, embedded newlines and length. |
| ~~AD~~ | **The OIDC JWKS and discovery documents are read unbounded.** Both use `json.NewDecoder(resp.Body)` with no `io.LimitReader`, where every other outbound response in the tree is capped — including the token endpoint eight lines away in the same file. | **Memory exhaustion from a hostile or compromised IdP.** There is no JWKS cache, so every `/api/auth/oidc/callback` triggers a fresh unbounded fetch. | **Fixed in Phase 52e.** Both the JWKS and discovery reads are wrapped in `io.LimitReader` at 1 MiB (`maxMetadataBytes`), matching the token endpoint eight lines away. A provider that is compromised, misconfigured, or simply the wrong URL can no longer stream until the process runs out of memory — a denial of service delivered through the login path. |
| ~~AE~~ | **SSE framing escapes LF but not CR.** `sseEscape` replaces `\n` only, while the data it escapes is deliberately CRLF-bearing — the SSH proxy emits `\r\n` and the DB proxy frames statements as `"psql> " + sql + "\r\n"`. | **Forged live-monitor output for spec-compliant consumers.** A lone CR terminates a line per the SSE specification, so a monitored operator can embed `data:`/`event:` lines and forge or hide content in `GET /api/sessions/{id}/stream`. The bundled portal is immune (it splits on `\n` and strips `\r`), so this bites integrations rather than the shipped UI — which is precisely why it would go unnoticed. | **Fixed in Phase 52e.** `sseEscape` escapes CR as well as LF. Server-Sent Events treats CR, LF and CRLF alike as end-of-line, and the data being escaped is deliberately CRLF-bearing: the SSH proxy emits `\r\n` and the DB proxy frames statements as `"psql> " + sql + "\r\n"`. Every one of those carriage returns could end the `data:` field early, so a supervisor's view of a live session could be split into frames the session never produced. |

| ~~AF~~ | **Phase 48's metadata lookup is broken on PostgreSQL and works only on the demo store.** `recordingOwners` asks for `ListAudit(ctx, 2000)`, but `pgstore.ListAudit` clamps anything above 500 **down to 100**, while `memstore.ListAudit` honours the request. | **A feature that passes its test and does not work in production.** With `PAM_RECORDING_OPAQUE_NAMES` on — the exact configuration Phase 48 exists to serve — the recordings screen resolves target and actor from the newest **100** audit events, which on a busy system is a few minutes; every older recording lists blank. `TestRecordingListingResolvesOwnersFromAudit` runs against memstore and therefore cannot see it. A regression introduced the same day, and the clearest argument in this sweep for the store-contract suite covering limit semantics (finding AI). | **Fixed in Phase 52b.** The root cause was that `ListAudit`'s limit semantics were never part of the contract, so each store invented its own. They are now stated on the interface and shared through `store.ClampAuditLimit`: a non-positive limit means `DefaultAuditPage`, and an oversized one is **capped at `MaxAuditPage`, not reduced to the default** — asking for more must never return less. `recordingOwners` now passes the set of names the listing actually needs and stops as soon as they are all resolved, so the scan is bounded by work rather than by a magic number. The store contract covers it with assertions built to fail against the old implementation (it takes more than 100 events and a mid-sized limit for broken and correct to differ at all) — verified by reproducing the old clamp and watching the contract test fail. |
| ~~AG~~ | **Phase 45 reintroduced a precision hazard the codebase had already identified and fixed elsewhere.** `SSHCert.Serial` is an `int64` serialized as a JSON **number**; serials are seeded from `time.Now().UnixNano()` (≈1.8×10¹⁸), far beyond the 2⁵³ exact-integer range of the IEEE double every JSON parser uses. | **The console's revoke option cannot revoke a real certificate.** The listing renders a rounded serial, and `4=Revoke` posts `String(c.serial)` — the rounded value — so the revocation targets a serial that does not exist, and copying the displayed number by hand fails too. `POST /api/ca/ssh/sign` returns the serial as a **string** for precisely this reason, with a comment saying so; the new listing route did not follow suit. `TestListSSHCertsEndpoint` uses serials 101 and 102, small enough to survive the round trip, so it passes. | **Fixed in Phase 52b.** `SSHCert.Serial` now carries the `,string` struct tag, so it serializes as a JSON string exactly as the `/sign` response already did. The test previously used serials 101 and 102 — small enough that the defect was invisible — and now uses two realistic nanosecond-seeded values differing only in their final digit, asserting both that the serial arrives as a string with every digit intact and that the two remain distinguishable. Verified the test fails without the tag. The console needed no change: its option helpers concatenate the serial into a field name rather than comparing it numerically. |
| ~~AH~~ | **Phase 49 re-archives the entire aged trail on every tick when the audit chain is enabled.** The archive filename is derived from the *cutoff*, which moves with each pass, and `ExportAudit(zero, cutoff)` re-selects everything older than it — but with the chain on the rows are deliberately never pruned. | **Unbounded duplication into storage that is, by the feature's own premise, immutable and usually billed.** Every tick writes a fresh, slightly larger copy of the whole aged trail under a new name; a year of daily ticks leaves hundreds of overlapping, undeletable exports. The single-pass test cannot observe it. Another same-day regression. | **Fixed in Phase 52e.** `archiveAuditBefore` starts from `lastArchivedThrough` — the `older_than:` stamp on the most recent `audit.archived` event — and exports only the delta. The high-water mark lives in the audit trail rather than a new table because the fact is already recorded there, it is visible to an auditor, and a mark stored elsewhere could disagree with the archives that actually exist; an unreadable marker reads as "nothing archived yet", which re-exports rather than skips. Test: `api.TestChainedAuditArchivesOnlyTheDelta` runs three passes, because a single-pass test cannot see this class of bug at all. |
| ~~AI~~ | **A failed source-remove wedges recording archiving permanently.** In the cross-filesystem copy path, if `os.Remove(src)` fails the destination exists and the source survives; the next pass sees the destination, returns `errArchiveExists`, and `archiveRecordingsBefore` **returns at that entry** rather than continuing. | Because `ReadDir` returns names sorted and names begin with a nanosecond timestamp, one stuck file blocks archiving of **every chronologically later recording**, forever, with only a log line to show for it. | **Fixed in Phase 52e.** `archiveRecording` compares contents when the destination already exists: identical means a previous pass copied and failed to remove, so it finishes the interrupted move; **different** is a genuine write-once violation and still an error, because two recordings must never share an archived name. `archiveRecordingsBefore` also continues past a failing file and returns the accumulated errors via `errors.Join`, so the caller still refuses to prune while one stuck file no longer blocks every chronologically later recording — which it did permanently, since `ReadDir` returns names sorted and recording names lead with a nanosecond timestamp. |
| ~~AJ~~ | **Phase 51 turned a latent SSH-channel write race into one that fires in the default mode.** The SFTP inspector's `deny` writes a status packet to the client channel from the inspector goroutine while `io.Copy` writes upstream data to the same channel — and `x/crypto/ssh` documents in-source that concurrent `WriteExtended` calls on the same extended code share a pooled buffer and are unsafe. | Before Phase 51 a deny only fired in `readonly` mode; path denies now fire in `allow` mode too, so an ordinary `mget` over a mixed allowed/denied set is a realistic trigger. The consequence is a data race and a status packet interleaved into a split read response, corrupting the client's SFTP stream. The existing tests are strictly request/response sequential, so they never overlap the two writers. | **Fixed in Phase 52e.** The SFTP inspector's reply path is now an `io.Writer` rather than the channel itself, and the session hands it a shared `syncWriter` that also wraps the target-output copy — so the two goroutines writing to the operator's channel are serialized. Taking a writer is the structural half: the inspector runs on its own goroutine, so if it reached for the channel directly no locking elsewhere could serialize it. Tests: `proxy.TestSyncWriterKeepsPayloadsWhole` asserts the property that matters (every payload arrives **whole**, not merely that nothing crashed) and `TestSFTPRefusalGoesToTheReplyWriter` pins the structure. |
| ~~AK~~ | **Batched Guacamole instructions evade Phase 50's clipboard audit.** `guacd.Decode` parses only the **first** instruction in a buffer and discards the rest, while the bridge forwards the whole WebSocket message to guacd. | A client that packs `clipboard`/`blob`/`end` into a single message has its paste delivered but produces **no `rdp.clipboard` event**. The tunnel authenticates by query token, so any client — not just the bundled viewer, which happens to send one instruction per message — can do this. Gating (Phase 33) remains the backstop, but the auditing this phase added is bypassable by anyone who wants to bypass it. | **Fixed in Phase 52e.** New `guacd.DecodeAll` parses every instruction in a frame (bounded at 256 so inspection cannot become the expensive part of the data path), and `clipWatcher.Observe` iterates them. The protocol is a stream of self-delimiting instructions with no one-per-message rule, and the bridge forwards whole messages — so decoding only the first meant prefixing a batch with a harmless `nop` sent the clipboard and blob instructions to the target completely unexamined. Test: `api.TestClipWatcherSeesBatchedInstructions`, verified to fail against the old single-instruction decode. |
| ~~AL~~ | **The store-contract suite does not cover limit semantics, which is what let AF ship.** `memstore` and `pgstore` disagree on `ListAudit` (memstore honours any limit; pgstore clamps `>500` and `<=0` to 100) and on `ListSSHCerts` (same shape). The Phase 44 `(limit, afterID)` window *is* contract-tested and is consistent; these two older, differently-shaped list methods are not. | Divergence between the store used by tests and the store used in production is the highest-leverage class of bug in this codebase: it makes a green suite meaningless for the affected call. AF is the proof. | **Fixed in Phase 52b.** The contract suite now pins `ListAudit`'s limit semantics for both stores, and the assertions are deliberately built to fail against the old pgstore rather than merely to pass against the new one — which took more than 100 events and a mid-sized explicit limit, since below that threshold the broken and correct implementations are indistinguishable. Phase 52a added the same treatment for the new key-custody methods. |

### What an adversarial review of the fixes then found (2026-07-28)

Fixing thirty findings across six phases is itself a change large enough to
warrant review, so the merged work was re-reviewed against the question "what did
these commits break?" — with an explicit instruction to look for **tests that
cannot fail**. It found six things, all confirmed by reproduction, all now fixed
in Phase 52g. Two are worth reading even if you skip the rest.

| # | What the review found | Fix |
|---|---|---|
| 1 | **The dependency allowlist rejected `$`, which Windows requires.** A named SQL Server instance registers `MSSQL$SQLEXPRESS` and `SQLAgent$PROD` — the textbook credential-dependency case for a PAM. Worse, it was **retroactive and silent**: the same check runs when the command is built, so an *existing* row would be skipped at rotation time, changing the account's password on the target and leaving SQL Server holding a stale one until its next restart failed. The sibling allowlist for `net user`, added in the same commit, accepted `$` for gMSA accounts — the two disagreed about what a legal Windows name is. | `$` admitted (it is inert in cmd.exe, so it bought no safety); the test now asserts the SQL Server shapes explicitly. |
| 2 | **The new handshake deadline cut off human password entry.** 30 seconds covers the whole pre-authentication phase — which in pamv1's documented flow includes an operator typing or pasting the API key at the `ssh` prompt, with OpenSSH re-prompting up to three times inside one connection. Reproduced: a client taking 32s was dropped with no message and no audit event, which looks exactly like a broken server. | Raised to 120s, matching OpenSSH's `LoginGraceTime`. It still prevents an idle unauthenticated peer holding a slot, which is what it was for. |
| 3 | **The clipboard batching fix was incomplete.** `DecodeAll` closed the `nop;clipboard;blob` evasion, but `Observe` still returned one transfer and overwrote on each completion — so two clipboard streams concatenated into one message produced exactly one audit record, and the first transfer left the desktop untraced. | `Observe` returns every completed transfer; the bridge audits each. Same evasion class, narrower hole. |
| 4 | **A new test could not fail.** `TestSyncWriterKeepsPayloadsWhole` was verified to pass with the mutex removed: its destination recorded each `Write` as one block under its own lock, so every block was intact whether or not anything was serialized. The assertion was tautological. | Rewritten against a destination that copies in two halves with a scheduling point between them — the shape of the real hazard — and **verified to fail** without the mutex, reporting the exact splice. |
| 5 | `auditField` was applied to the log line but not to the **actor** on the branch that still appends, leaving an unauthenticated, attacker-chosen login going raw into a column the retention worker refuses to prune with the chain on. | Bounded and quoted at both proxies. |
| 6 | `recordingOwners` asked for `MaxAuditPage` (5000) on every console refresh; the early exit only fires when *every* listed name resolves, so one unattributable recording made it read the full window each time. | An explicit, documented window of 2000 — an order of magnitude above the listing cap, and far below "as much as the store will give me". |

The lesson from #4 is the one that generalises: the previous round's discipline was
"verify the test fails without the fix", and it was applied to the tests written
for *known* bugs but not to a test written for a race. A test asserting that
nothing went wrong is the easiest kind to write and the easiest to get wrong.

### Test coverage, measured honestly (2026-07-28)

CI now measures with `-coverpkg=./...` rather than per-package, and the
difference is not cosmetic. This codebase tests deliberately at the integration
level — `internal/api`'s tests drive most of the other packages — so per-package
accounting attributes none of that work back to them. Measured naively,
`internal/broker` reads as **35%** when it is really **85%**; `internal/ticket`
57% when it is 93%. That gap once sent a review after the wrong problem, and the
right one (three broker controls that were asserted by the threat model and
executed by no test) had nothing to do with the numbers.

Repo-wide the real figure is **72.7% of statements** (68.3% before 2026-07-28).
The honest measurement had made one outlier obvious — **`cmd/pam-server` at
0%**: 1,181 lines with 39 distinct error and validation exit paths, where the
`PAM_OT_AIRGAP` gap was found, and where the air-gap fix's test (placed in
`internal/config`, where the validation lives) never reached. **Closed the same
day** by `cmd/pam-server/main_test.go`: every fail-closed startup path
reachable without external infrastructure is triggered through the environment
the way a real misconfigured deployment would trigger it; the full server is
booted for real (in-memory store, both proxies, audit chain, SSH CA, broker,
workers), health-checked live, and shut down with a real SIGTERM; the utility
flags are proven end to end (`-split-key`'s shares reconstruct the key,
`-hashkey` matches the server's expectation); and `-rotate-kek` is proven
against live PostgreSQL in the pgstore CI job — the secret decrypts under the
new KEK and **stops** decrypting under the old one. The package sits at
**82.8%**; the remainder is `main()`'s flag dispatch and `fatal()`, which call
`os.Exit` and wrap one covered call each.

**Not findings, explicitly checked and clean:** AAD parity across all twenty
credential encrypt/decrypt sites and the `MFAAAD`/`ConfigAAD`/`KeyMaterialAAD`
paths (zero inline constructions); nonce handling in the vault and the chunked
recording sealer; constant-time comparison at every MAC/hash check; no
`math/rand` outside tests; no secret in any log, audit detail or serialized
struct; child-resource scoping on all six child routes; no capability check
comparing a role string; the audit-action vocabulary matches the code in both
directions (159 actions, no drift either way); and the `session`, `ratelimit`,
`broker` and `auditfwd` packages' lifecycle management, which is bounded and
correct throughout.

## Tier 3 — Missing capabilities (deferred; new roadmap phases, not fixes)

> These are severity tiers of *found gaps* — not the same as the market-coverage
> "Tier-3/Tier-4" bands in [EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md), which
> is the canonical list of what needs a real account/host to build and verify
> honestly. Where an item below overlaps that list, EXTERNAL-INFRA-GAPS owns the detail.

These are whole subsystems a commercial PAM has and pamv1 does not — building them
is a phase each, out of scope for a security *fix*:

- ~~**Tamper-evident PRIMARY audit trail.**~~ **Fixed (opt-in).** The keyed-HMAC
  chain now covers the main `audit_events` table (reveal, break-glass, db.query,
  sessions), not just broker events. Set `PAM_AUDIT_HMAC_KEY` (base64 32 bytes) to
  activate chaining; verify with `GET /api/audit/verify`. The migration is additive
  and unset leaves the plain table, so it's non-breaking. This was the top deferred
  item; it is now closed. **Tail-truncation detection** is also covered: set
  `PAM_AUDIT_SIGN_SEED` and archive the ed25519-signed checkpoints from
  `GET /api/audit/head` out-of-band.
- ~~**Session-recording playback**~~ **Shipped (Phase 26).** `GET /api/recordings`
  + `GET /api/recordings/{name}` (`CapReadAudit`) list and replay the stored
  recordings, the served file's SHA-256 verified against the audited value
  (`X-PAM-Recording-Audited`), every replay audited `session.playback`, with a
  5250 player (portal menu 19).
- **JIT ephemeral account provisioning** on targets, **FIDO2/
  WebAuthn**, **CIEM / cloud-IAM brokering**, **Kubernetes secret/SA delivery**,
  **other DB engines** (MySQL/MSSQL/Oracle), **HSM/KMS-backed SSH-CA signing**, and
  **rotation webhooks**.
- ~~**Native audit→SIEM forwarding**~~ **✅ shipped (Phase 35)** — `internal/auditfwd`
  continuously streams every audit event to a syslog/CEF collector (UDP/TCP) from a
  durable cursor with spool-and-retry, leader-locked in HA (`PAM_AUDIT_FORWARD_ADDR`).
  LEEF (QRadar) and the RFC 5425 TLS transport — with always-on, optionally
  CA-pinned certificate verification — shipped in Phase 47 on the same seam.
- **HA correctness** — the periodic-job scheduler runs under a Postgres
  advisory **leader lock** (one replica per tick), the **kill-switch is
  cluster-wide** (Phase 34: a kill is broadcast over Postgres LISTEN/NOTIFY and
  applied on whichever replica hosts the session — kill-switch, revoke cascade,
  vendor offboard, analytics auto-response), and since Phase 55 so are **live
  session *monitoring* and the inventory listing** (a shared heartbeat-refreshed
  inventory, plus an interest-gated relay that forwards a watched session's
  output over the store bus only while a remote supervisor is watching), and
  since Phase 56 so are **in-session step-up decisions** (the pending list is
  cluster-wide over a shared TTL-bounded inventory whose statements rest sealed
  under the bus key, and a decision posted anywhere is dispatched, sealed and
  freshness-bound, to the replica whose memory holds the pause).
- **Roadmap-deferred**: Kerberos/GSSAPI, serial connectors, SPIRE workload
  attestation, automatic broker-chain checkpoint export. (The in-browser RDP viewer
  has since **shipped** — vendored Guacamole client + bundled guacd.)

## New configuration introduced by these fixes

| Env var | Default | Purpose |
|---|---|---|
| 2026-08-25 | **Phase 196 — the non-human credential surface is now a written list.** An agent key, an IdP's SCIM token and an application key pass NO capability check: the middleware authenticates the bearer and hands off, so the set of routes each reaches IS the authorization boundary for it. `nonHumanReach` records all five such schemes route by route with a reason, checked both ways so a stale entry fails too. Also pinned: `server.go`'s claim that browser-extension tokens "reach only this route" was a trailing comment nothing verified — `TestExtensionTokenRefusedEverywhereElse` mints a real token and watches five routes refuse it, but it samples the COMPLEMENT, so a sixth `authzExtOK` route would leave it green and the comment false; verified by wrapping a second route and watching only the new set-assertion fail. And `TestNoMutatingRouteIsPublic` puts a floor under the table: a request that changes state must present something. No defect found — this bounds a surface that had no second gate behind it |
| 2026-08-25 | **Phase 195 — the security map called sixteen authenticated routes `public`.** `docs/ARCHITECTURE-DIAGRAMS.md` §3 is the table a reader consults to see what guards each route, and it is CI-gated for drift — so it was guaranteed current and guaranteed wrong at once. `archgen`'s classifier knew four schemes and **defaulted to "public"** for anything else; three schemes added to the mux later (`agentAuth`, `scimAuth`, `appAuth`) were never taught to it, so the whole AI-agent tool-call surface and the whole SCIM surface — which creates and deletes users — were published as unauthenticated, along with five token-authenticated guest routes. **Not an access-control defect**: `scimAuth` rejects a missing or unmatched bearer token and `agentAuth` verifies the credential then checks quarantine, verified by reading both. It is the document lying about a control, the same class as Phase 190's stale digest. Closed by making the classifier REFUSE to guess — an unrecognised wrapper stops the generator, which CI runs — and by requiring "no credential" to be claimed in an allowlist with a reason rather than inferred from silence |
| 2026-08-25 | **Phase 193 — a review flag pointing the wrong way.** Phase 191 added `blocked` to the reachability review to stop the answer overstating a subject's reach; its `not_enrolled` reason then understated it, marking an unclaimed attested identity as stopped on every deployment that does not set `PAM_BROKER_REQUIRE_ENROLLED_SVID` (the default). The identity in question authenticates and reaches every ungated target, which is the finding the screen exists to show. Not an access-control defect — reach is read-only and no gate consulted the flag — but a review surface that misleads is a control failure of its own kind. Closed, with a test on each side of the flag. Same phase: an unreadable quarantine table rendered as "nothing stops this agent", now `quarantine_unknown` |
| 2026-08-25 | **Phase 192 — supply-chain: the release binary was compiled by an untested toolchain.** A Dependabot bump moved both Dockerfiles to `golang:1.27` and CI went green, because nothing compares the build image against the test pins: every test job and both `release.yml` jobs still ran Go 1.26. A release therefore attested a container built by a compiler no test exercised, with `pam-agent` binaries built by a *different* compiler attached beside it. Closed by moving all seven pins to 1.27 and verifying the full `-race` suite on go1.27.0 locally before pushing, since CI itself was the thing under change. Not exploitable on its own — it is a provenance defect, and provenance is most of what a signed release claims |
| `PAM_TRUSTED_PROXY_HOPS` | `0` | Trusted reverse-proxy hops; picks the client IP from XFF for rate limiting. |
| `PAM_PROXY_AUTH_RATE_LIMIT` | `10` | Failed-auth throttle per IP/min on the SSH & DB proxies (0 disables). |
| `PAM_REQUIRE_HTTPS` | `false` | Refuse to start the API/portal without native TLS. |
| `PAM_REQUIRE_DB_CLIENT_TLS` | `false` | Refuse to start the DB proxy without operator-leg TLS. |
| `PAM_DB_UPSTREAM_CA` | — | PEM CA bundle to VERIFY the upstream PostgreSQL cert (fail-closed). |
| `PAM_DB_UPSTREAM_TLS_VERIFY` | `false` | Verify the upstream PostgreSQL cert against the system roots. |
| `PAM_ALLOW_WEAK_API_KEY` | `false` | Override the 16-char `PAM_API_KEY` floor (demos only). |
| `PAM_NEW_KEK_*` / `PAM_NEW_MASTER_KEY` | — | Target KEK for `-rotate-kek` (any provider; enables migration). |

## New audit actions

`proxy.auth_rate_limited`, `db.session.denied` (enroll-only), `session.revoked`
(admin/reconcile session revocation), `vault.kek_rotated`, and — from the
2026-07-26 pass — `api.auth_failed` (a rejected bearer credential on the REST,
agent-broker or application-secrets surface; `surface:api|agent|app`).
