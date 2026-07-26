# pamv1 — Security Gaps (findings, fixes, and remaining work)

> 🟢 **Living document** — updated in the same change as the code, without a separate ask (see the [docs hub](README.md)).

> **Purpose.** This is a self-audit of pamv1 against the security posture expected
> of a Privileged Access Management system. It records every gap found in a
> read-only review of the codebase, whether each was **fixed**, **mitigated**, or
> **deferred** (a whole subsystem / new roadmap phase), and where the change
> lives. pamv1 is educational ("for learning purposes") — this document is part of
> that: it shows the reasoning, not just the result.
>
> Last updated: 2026-07-26 · Reflects: Phases 0–38 + the 2026-07 hardening passes.

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
| 11 | SCRAM server-signature not verified on the DB upstream (forfeits SCRAM mutual auth). | **Fixed** | `scramAuth` recomputes and constant-time-compares the ServerSignature. |
| 12 | PostgreSQL fast-path (`FunctionCall`) evaded per-statement audit. | **Fixed** | The relay now audits `FunctionCall` frames. |
| 13 | No strength floor on `PAM_API_KEY` (a 1-char admin key started). | **Mitigated** | Rejected below 16 chars on a real (non-`memory`) database, unless `PAM_ALLOW_WEAK_API_KEY=true`; the in-memory demo is exempt so the quickstart still works. Tests in `config`. |
| 14 | `-rotate-kek` only handled local→local master-key rotation; KMS/HSM KEKs had no re-wrap path, and no audit event. | **Fixed** | `-rotate-kek` now builds both KEKs from `PAM_KEK_*` / `PAM_NEW_KEK_*` (any provider — enables local→KMS migration) and writes a `vault.kek_rotated` audit event. |
| 15 | Plaintext HTTP by default; TLS opt-in. | **Mitigated** | `PAM_REQUIRE_HTTPS` refuses to start without native TLS; a loud warning is logged otherwise. (Default kept permissive for the loopback demo.) |
| 16 | DB proxy operator leg cleartext by default. | **Mitigated** | `PAM_REQUIRE_DB_CLIENT_TLS` refuses to start the DB proxy without operator-leg TLS. |
| 17 | No K8s NetworkPolicy in any deploy flavor. | **Fixed** | `deploy/k8s/networkpolicy.yaml` (default-deny) + a gated Helm template (`networkPolicy.enabled`). |
| 18 | `:latest` image tags in the terraform and conjur manifests. | **Fixed** | Pinned to `0.10.0` (matching the raw k8s deployment) with a comment to pin by digest. |
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
  not. (File transfer initiated as `scp` over an interactive shell, or shell
  redirection, still rides the unparsed PTY and is out of scope — use `readonly`
  plus shell restriction for containment.) The **RDP** viewer got the same treatment in Phase 33: `PAM_RDP_CLIPBOARD` gates the Guacamole clipboard bridge (copy-out / paste-in) and drive redirection is always disabled, so the graphical session's side-channels are audited/gatable too.
- **Session recording is fail-open unless `PAM_REQUIRE_RECORDING`** — the opt-in
  fail-closed control already exists; the default is kept permissive for demos.
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
  traded for disk space. With the chain on, retention is an operator step — export
  to WORM (`GET /api/audit/export`, digest-stamped) then re-anchor. Recording-file
  pruning always runs (it preserves the `.chain` head).

## Open findings from the 2026-07-26 sweep

Found by the same pass, **not** fixed in it — each is a phase-sized change or a
deliberate design decision to take, not a one-line correction. They are recorded
here rather than left implicit. Struck-through rows have since shipped.

| # | Finding | Why it matters | Direction |
|---|---|---|---|
| A | **Session recordings are stored unencrypted.** `internal/proxy/record.go` writes `.cast` files at mode `0600` in the clear. | Credentials get AES-256-GCM under a pluggable KEK; the recording — everything the operator typed and saw, including a secret typed by hand and every returned DB row — gets file permissions only. Anyone with volume, backup or snapshot access reads it. CyberArk PSM encrypts recordings into the vault. | Encrypt recordings with the existing envelope (`vault.Encrypt`, AAD binding the session id), decrypting on the audited playback path. Keeps the hash chain, changes the on-disk artifact. |
| B | **Per-pod SSH host key and ZSP CA key.** `proxy.LoadOrCreateHostKey` and `sshca.LoadOrCreate` persist to a local file; the Helm PVC is `ReadWriteOnce` and defaults to `emptyDir`, while `replicaCount` is free. | Scaling replicas gives each pod a different **host key** (operators see host-key-changed warnings that look like a MITM) and a different **CA key**, so a certificate minted on one pod isn't trusted by targets configured with another's `TrustedUserCAKeys`, and the operator-cert challenge — an HMAC keyed off the CA private key, documented as "HA-safe across replicas" — fails across pods. Recordings also scatter per-pod, so `GET /api/recordings` lists only the serving pod's files. | Custody the host key and CA key in the store (vault-encrypted, like MFA secrets and settings) with the file as a fallback; or document RWX/single-replica as a hard requirement. Phase 34 closed the kill-switch half of HA; this is the key-material half. |
| ~~C~~ | ~~**Command control does not cover every path with a discrete command.**~~ | Was: a pattern blocked for a human on the SSH proxy ran freely through the REST WinRM endpoint and the agent broker — the least-trusted actor. | **Fixed in Phase 38** — the guard moved to `internal/cmdguard` and one instance is shared by both proxies and the API server. `Server.guardCommand` enforces it in `execWinRM` (the chokepoint the REST endpoint and the broker's `winrm_exec` share) and in `sshExecTool.Execute`, **before** the JIT decrypt, auditing `command.blocked` with the matched pattern. Tests: `api.TestWinRMRunCommandBlocked`, `api.TestBrokerWinRMCommandBlocked`, `api.TestBrokerSSHExecCommandBlocked`. |
| D | **The REST WinRM endpoint runs outside the live-session registry.** The SSH proxy, DB proxy and RDP tunnel all call `AllowNew` + `Register`; `runWinRM` calls neither. | A WinRM run is absent from `GET /api/sessions`, cannot be killed, is not counted against `PAM_MAX_SESSIONS_*`, and is out of reach of the analytics auto-kill and the vendor session sweeper. It is audited and transcribed, but not *supervisable*. | Register it as a short-lived session for its duration, cancelling the WinRM context on kill. |
| E | **Step-up decisions are gated on `CapReadAudit`.** `POST /api/sessions/{id}/stepup` uses the live-monitoring capability. | The role defined as read-only (`auditor`) can release a statement the step-up policy flagged as sensitive — an execution-authorizing power. `CapApprove` exists for exactly this decision. | Gate the decision on `CapApprove` (keep `CapReadAudit` for *listing* paused statements, so a supervisor can still watch). |
| F | **Certification decisions have no separation of duties.** Campaign create/decide/close require `CapManageUsers`, i.e. admin. | The principal who grants access is the only one who can certify it, and `approver`/`auditor` — the natural reviewers — can read a campaign but not decide one. That undercuts the SOX / ISO 27001 control Phase 19 exists to satisfy. | Let `CapApprove` decide campaign items (management stays `CapManageUsers`), or add a dedicated capability. |
| G | **Console parity has drifted since Phase 25.** Comparing the mux's routes against the endpoints the portal calls: **broker approvals** (`/v1/approvals` — a human approval gate with no screen at all) and **step-ups** (`/api/sessions/stepups`, time-boxed) have no UI, along with vendors, the SSH CA / operator certs / KRL, credential dependencies, blast-radius, `audit/verify`·`head`·`ocsf`, login-session revocation, and agent-key management. | The README still claims full parity; two of the missing screens are *human decision points* with a deadline, which makes a curl-only path operationally fragile. | A console-parity phase in the shape of Phase 25. |
| H | **No update endpoints and no pagination.** The `Store` interface has create/delete but no update for targets, safes, users, vendors or grants; and no list method except the audit reads is bounded. | Fixing a target's port means delete + recreate, cascading away its credentials, grants, dependencies and safe assignment. Unbounded lists are a scale limit and an authenticated memory-exhaustion vector on a large inventory (`listAudit`/`exportAudit` were bounded by gap #9; the rest were not). | Add `Update*` methods + `PUT` routes, and a `limit`/`after` cursor on the list reads. |

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
  LEEF and TLS-syslog transport remain follow-ons on the same seam.
- **HA correctness** — the periodic-job scheduler runs under a Postgres
  advisory **leader lock** (one replica per tick), and the **kill-switch is now
  cluster-wide** (Phase 34: a kill is broadcast over Postgres LISTEN/NOTIFY and
  applied on whichever replica hosts the session — kill-switch, revoke cascade,
  vendor offboard, analytics auto-response). What remains per-replica: **live
  session *monitoring*** (the SSE watch stream is served from the hosting pod) and
  the session **inventory listing**; fanning session *bytes* across replicas is a
  heavier pub/sub than a kill signal and stays a documented follow-on.
- **Roadmap-deferred**: Kerberos/GSSAPI, serial connectors, SPIRE workload
  attestation, automatic broker-chain checkpoint export. (The in-browser RDP viewer
  has since **shipped** — vendored Guacamole client + bundled guacd.)

## New configuration introduced by these fixes

| Env var | Default | Purpose |
|---|---|---|
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
