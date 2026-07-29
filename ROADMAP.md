# pamv1 Roadmap

Guiding principle: **fully functional at every step**. Each phase ships something that runs end-to-end, passes tests, and deploys via IaC. Phases build on each other but stay independently releasable.

Status: ✅ done · 🚧 in progress · ⬜ planned

> 🟢 **Living document** — updated in the same change as the code, without a separate ask (see the [docs hub](docs/README.md)).

**Phases 0–52g are shipped.** The narrative that follows traces the arc through
Phase 43 — the CyberArk/Wallix-style console, the AI-agent
access broker (MCP + SPIFFE), SOPS-encrypted secrets, the four **Tier-1
competitive-coverage gaps** closed (a PostgreSQL session proxy, supervised sessions
with command control, safes, dependent-account propagation), optional CyberArk Conjur
secret sourcing, the three **Tier-2** access-governance gaps closed
(certification campaigns, an ITSM/ticketing gate, richer approval workflows),
the two **Tier-3** market-frontier gaps that can be built and verified honestly in
process — **Zero Standing Privilege** (ephemeral short-lived SSH certificates, Phase 22)
and **privileged threat analytics** (behavioral risk scoring + automated response,
Phase 23) — the first **Tier-4** ecosystem gap: a **Conjur-style
application-secrets API** for non-agent apps (Phase 24), **console parity**
(Phase 25) — 5250 screens for every backend capability that had been API-only
(safes, certification campaigns, risk analytics, a live session viewer, and the
Phase 20/21 request-workflow fields), **session-recording playback +
one-time access** (Phase 26): audited, hash-verified replay of stored session
recordings from the portal, and single-use approvals consumed by the first
connection they admit — and **AI-agent broker completion** (Phase 27): approver-group
separation of duties, periodic ed25519 in-chain audit checkpoints with signing-key
rotation + JWKS and a truncation floor, OCSF SIEM export, and the MCP SSE transport
with elicitation, bringing the broker to parity with the [pam-research](https://github.com/morandeirachema/pam-research)
prototype — **operator SSH certificates** (Phase 28): proof-of-possession issuance of a
short-lived, principal-scoped cert for an operator's own key with KRL revocation — and a
**third-party vendor access gate** (Phase 29): time-boxed, customer-approved contract
grants with live employment attestation, an instant-offboard cascade, and per-vendor
evidence export — and **in-session policy + step-up** (Phase 30): numeric policy
comparators for the agent broker, and a pause-for-supervisor step-up on the
PostgreSQL session proxy that keeps the session open — the **identity blast-radius /
CIEM engine** (Phase 31), **SFTP file-transfer control** (32) and **RDP clipboard
control** (33) closing the two unaudited data-movement paths, the **HA kill-switch**
(34), **audit→SIEM push forwarding** (35), **retention / pruning** (36), and a
**gap-analysis pass** (37): child-resource deletes scoped to their parent, and failed
bearer credentials throttled + audited on every authentication surface — and
**command control on every command path** (38): the deny policy moved to
`internal/cmdguard` and is now enforced on the REST WinRM endpoint and the agent
broker's exec tools, not only inside the session proxies — and **the approver
capability on the two decision points** (39): releasing a paused statement and
certifying access are now `CapApprove`, not a read-only or user-admin gate — and
**every brokered execution is a supervised session** (40): the REST WinRM endpoint
and the agent broker's exec tools join the proxies in the live-session registry, so
they are listable, countable and killable — and **session recordings are encrypted
at rest** (41): the other high-value artifact finally gets the same envelope
encryption and KEK as the credentials themselves — and **shared custody of the host
and CA keys** (42), so a scaled deployment stops handing out a different SSH host key
and a different certificate authority per pod — and the console's **two human
decision points** (43): approving an agent's parked tool call, and releasing or
refusing a paused statement, both of which had been curl-only. The portal is
also **keyboard-first** (mouse optional).

**Phases 44–52g are deliberately not enumerated here** — the sentence above is
already too long, and its length is precisely why it spent nine phases out of
date. In summary: 44–51 hardened the console, the audit trail and the recording
pipeline; **52 through 52g** closed the thirty findings of the
[post-beta security sweep](#the-post-beta-sweep-2026-07-27--all-thirty-findings-closed-)
and the six more that reviewing those fixes uncovered. Each phase has its own
section below, which is the authoritative record.

Beyond those,
a number of items genuinely require external infrastructure or a paid account to build
and verify honestly, so they are left as documented follow-ons rather than faked. The
full catalogue is in **[docs/EXTERNAL-INFRA-GAPS.md](docs/EXTERNAL-INFRA-GAPS.md)**;
the headline deferrals are:

- **Optional Kerberos bind** (Phase 3b) — needs a KDC.
- **Kerberos WinRM auth** (Phase 4) — needs a KDC + an AD-joined host.
- **Serial (RS-232 / terminal-server) connectors** (Phase 8) — needs serial hardware.
- **The remaining three Tier-3 gaps** — connector/plugin breadth, cloud CIEM, and web/SaaS session proxying — each need a real device, cloud account, or browser/SaaS console to build honestly.

---

## Phase 0 — Project foundation ✅

- [x] Public open-source repo ([github.com/morandeirachema/pamv1](https://github.com/morandeirachema/pamv1)), Apache-2.0 license
- [x] Go module, standard layout (`cmd/`, `internal/`), CI on GitHub Actions (fmt, vet, build, race tests, Docker build)

## Phase 1 — Core: vault, inventory, audit, portal ✅

- [x] **Hardened vault**: AES-256-GCM, random nonce per secret, AAD binding to owning target, versioned token format (`v1:`) ready for key rotation
- [x] **Target inventory**: Linux/Windows machines (ssh / winrm / rdp) via REST API
- [x] **Credential store**: secrets encrypted before touching the DB; JSON encoder can never leak them; audited `reveal` as the temporary escape hatch
- [x] **Audit trail**: append-only events for every sensitive action
- [x] **Break-glass v1**: sealed emergency key (only its SHA-256 in config), loud `break-glass` actor, every use audited + logged
- [x] **Portal**: AS/400 / 5250-style terminal UI (Sign On, Work-with screens, F-keys) — deliberately austere so admins feel the gravity of the system
- [x] **Storage**: PostgreSQL (pgx) with embedded idempotent schema; in-memory store for tests/demo
- [x] **Deploy as IaC**: Dockerfile (distroless, non-root), docker-compose with hardened Postgres (scram-sha-256), K8s manifests (restricted PSS), Terraform module

## Phase 2 — Session proxy with JIT credential injection (Linux/SSH) ✅

The flagship: users connect *through* pamv1, never holding the credential.

- [x] SSH gateway (`golang.org/x/crypto/ssh`): user opens `ssh user@target@pam-proxy`, proxy authenticates the user, pulls the credential from the vault and injects it **just-in-time** into the upstream connection
- [x] Session recording (asciicast v2) stored with a SHA-256 written to the audit trail (tamper evidence)
- [x] Per-session audit events (start, record, end, denied, error)
- [x] **Per-target authorization** (`target_grants`): a target with grants only admits matching users/roles (admins always; ungranted targets stay open); enforced in the proxy, WinRM and RDP; managed via `/api/targets/{id}/grants`
- [x] **Live session listing and kill-switch** (`internal/session`): `GET /api/sessions` (auditor+) lists active proxy/RDP sessions; `DELETE /api/sessions/{id}` (admin) terminates one
- [x] **Hash-chain the recordings**: each recording's chain hash = SHA-256(prev-chain-hash ‖ file-hash), head persisted; recorded in the `session.record` audit (`chain:`)
- [x] Disable `reveal` by policy (`PAM_REVEAL_DISABLED`): reveal becomes break-glass-only, forcing the recorded proxy path

## Phase 3 — Identity & access control ✅

### 3a — RBAC with four profiles ✅

- [x] Four roles — **admin**, **user**, **auditor**, **approver** — with an authoritative role→capability matrix (`internal/auth`)
- [x] Per-user access tokens (stored as SHA-256 only), minted by an admin via `POST /api/users`
- [x] Enforcement in the REST API (per-route capability) and the SSH proxy (`CapConnect`); every denial audited (`authz.denied` / `session.denied`)
- [x] Audit now attributes real usernames; portal tolerates per-role 403s
- [x] `approver`'s approval endpoints (access-request workflow) — **shipped in Phase 8** (`/api/access-requests`, 4-eyes)

### 3b — Active Directory connector ✅

- [x] LDAP/LDAPS bind against AD ([go-ldap](https://github.com/go-ldap/ldap)): service-account search + user bind to verify the password
- [x] AD groups → the four pamv1 roles, via `PAM_LDAP_GROUP_*`; a user in several mapped groups carries **all** of them (`Principal.Roles`) and is granted the **union** of their capabilities — not just the single highest role — persisted across a session as `sessions.roles` (same for Entra app-roles/groups)
- [x] Portal Sign On with AD username + password; short-lived **session tokens** (`POST /api/login`, `POST /api/logout`) that work in the portal and the SSH proxy
- [x] **MFA: TOTP** (RFC 6238) enrollment + verification (`internal/mfa`), secret stored vault-encrypted, enforced on `/api/login`; self-service `/api/mfa/*` (NIS2 Art. 21(2)(j))
- [x] **Microsoft Entra ID (Azure AD)** login: OAuth2 (ROPC) against the tenant, Entra app roles / groups → the four roles; composable with LDAP via a chain authenticator; sovereign-cloud authority host
- [x] **Enforce-MFA policy** (`PAM_MFA_REQUIRED`) with enrollment-only sessions, and **single-use recovery codes**
- [x] **OIDC Authorization Code flow + PKCE + JWKS signature validation** (`internal/oidc`): browser SSO (`/api/auth/oidc/{start,callback}`), IdP-side MFA/Conditional Access, ID-token verified (RS256, iss/aud/nonce/exp), discovery
- [ ] Optional Kerberos bind (needs a KDC to test)
- [x] Entra ROPC **id_token JWKS signature validation** — requests `openid`, validates the id_token's RS256 signature against the tenant JWKS (`oidc.VerifyRS256`) + audience + expiry before trusting role/group claims
- [x] OIDC pending-state shared store for multi-replica HA — **shipped in Phase 10** (`store.PutOIDCState`/`TakeOIDCState`, migration `0004`)
- [x] Local emergency admin kept for AD-down scenarios (bootstrap key + break-glass)

## Phase 4 — Windows targets ✅

- [x] **WinRM command execution with JIT credentials** (`internal/winrm`): `POST /api/targets/{id}/winrm` decrypts the target's credential only at run time, executes over WinRM, records the transcript (SHA-256 in the audit), returns stdout/stderr/exit — the caller never sees the secret
- [x] AD-joined target support: uses domain service accounts stored in the vault (the credential username may be `DOMAIN\\user` or UPN)
- [x] **NTLM WinRM auth** (`PAM_WINRM_AUTH=ntlm`) — NTLMv2 transport, which AD-joined hosts usually require
- [x] **RDP brokering via Apache Guacamole `guacd`** (`internal/guacd` + `GET /api/targets/{id}/rdp` WebSocket tunnel): the credential is injected just-in-time into the guacd handshake — it reaches guacd, never the browser (`PAM_GUACD_ADDR`). **guacd itself now ships** in the Docker/K8s/Helm deploys (internal-only)
- [x] **Browser RDP viewer**: the portal vendors guacamole-common-js and renders the desktop on a canvas (*Work with Targets* option 7; `Ctrl+Alt+Q` to disconnect), fronted by a short-lived `POST /api/rdp-token`. Verified by a full WebSocket round-trip test against a fake guacd — only the *rendered pixels* still need a real Windows host (see [docs/RDP-TESTING.md](docs/RDP-TESTING.md))
- [x] guacd server-side session recording for RDP (`PAM_GUACD_RECORDING_PATH`; recording name in the `rdp.connect` audit)
- [ ] Kerberos WinRM auth — **infra-bound**: needs a KDC + an AD-joined Windows host to verify
- [x] **Interactive WinRM shell through the SSH proxy** (`PAM_PROXY_WINRM`): `ssh <cred>@<winrm-target>@pam` opens a command loop — each line runs as a WinRM command (JIT credential), output streams back and is recorded. (A command loop, not a stateful PowerShell — working directory/variables don't persist across lines; a WinRS streaming shell is a follow-on needing a real host to verify.)

## Phase 5 — Hardening: database, vault, transport ✅

- [x] **Envelope encryption** with a pluggable KEK: per-secret data keys wrapped by a Key Encryption Key; `local` KEK (dev/test) + **HashiCorp Vault Transit** KEK (production, KEK never leaves the KMS)
- [x] **Vault key rotation** (`pam-server -rotate-kek`, `internal/maint`): re-encrypts all credentials + MFA secrets from `PAM_MASTER_KEY` to `PAM_NEW_MASTER_KEY`, preserving AAD
- [x] Hardened Postgres guidance: scram-sha-256 enforced (compose), TLS `verify-full` + least-privilege role + [pgAudit](https://www.pgaudit.org/) documented
- [x] **Versioned migrations** (embedded, `schema_migrations` table, ordered `migrations/*.sql` applied in a transaction) replacing the ad-hoc startup schema
- [x] **Native HTTPS** (`PAM_TLS_CERT`/`PAM_TLS_KEY`, TLS 1.2+), **security headers** (nosniff, frame-deny, referrer, HSTS), **rate limiting** on auth endpoints (`PAM_AUTH_RATE_LIMIT`)
- [x] **Backup/restore runbook** with encrypted backups ([docs](docs/BACKUP-AND-RESTORE.md))
- [x] **Upstream SSH host-key pinning** (`PAM_SSH_KNOWN_HOSTS`, [known_hosts](https://pkg.go.dev/golang.org/x/crypto/ssh/knownhosts)): the JIT proxy and the rotation connector verify target host keys instead of trusting any; unconfigured falls back to trust-any with a loud warning
- [x] **AWS KMS KEK** (`aws-kms` provider): the data key is wrapped/unwrapped by KMS (`PAM_KEK_AWS_KEY_ID`/`PAM_KEK_AWS_REGION`); the CMK never leaves KMS
- [x] _(optional extension)_ **PKCS#11 HSM KEK provider** — `vault/pkcs11.go` behind the `pkcs11` build tag (cgo), `deploy/docker/Dockerfile.pkcs11`, `PAM_KEK_PKCS11_*`; the AES wrapping key stays in the HSM. Verified against SoftHSM2 in CI; the default static image is unchanged (a stub returns "not built in")

## Phase 6 — Break-glass v2 ✅

- [x] **M-of-N quorum unseal** ([Shamir secret sharing](internal/shamir), `pam-server -split-key`, `POST /api/breakglass/unseal`): custodians submit shares; when M reconstruct the key (verified against its hash) a session is issued
- [x] **Auto-expiring break-glass sessions** (short-TTL session, `PAM_BREAK_GLASS_TTL_MIN`, scope `breakglass` → admin + loud audit)
- [x] **Real-time alerting** (`internal/alert` webhook, `PAM_ALERT_WEBHOOK`) on every break-glass **access** and **unseal**
- [x] Documented offline procedure (sealed shares, dual control) — see the [Admin Guide](docs/ADMIN-GUIDE.md)
- [x] Forced credential rotation after break-glass use — a break-glass session that connects through the proxy triggers `PAM_ROTATE_AFTER_SESSION` on session end (a reveal-path break-glass rotation is a smaller follow-on)
- [x] **Additional alert channels (email + syslog)** on the same `Notifier` interface (`alert.Syslog`, `alert.Email`, `alert.Multi` fan-out; `PAM_ALERT_SYSLOG` / `PAM_ALERT_EMAIL_*`)

## Phase 7 — Credential lifecycle ✅

- [x] **Rotation connectors** ([`internal/rotate`](internal/rotate)): Linux over SSH (`chpasswd` via stdin — no shell injection), Windows over WinRM (`net user`). Strong password generation from a shell-safe alphabet with guaranteed complexity categories. **`ssh_key` rotation**: generates a fresh ed25519 keypair and replaces the account's `authorized_keys` (old key stops working)
- [x] **On-demand rotation**: `POST /api/credentials/{id}/rotate` generates a fresh secret, sets it on the target, then re-vaults it and stamps `rotated_at` — the new secret is never returned (proxy injects it JIT)
- [x] **Scheduled rotation**: background lifecycle worker (`PAM_ROTATE_INTERVAL_MIN`) rotates password credentials older than `PAM_ROTATE_MAX_AGE_HOURS`
- [x] **Account reconciliation (out-of-sync detection & remediation):**
  - [x] Credential reconciliation — `POST /api/credentials/{id}/reconcile` verifies the vaulted secret still authenticates to the target (SSH handshake / WinRM probe); drift is flagged and, with `?remediate=true`, remediated by rotating to a PAM-managed secret
  - [x] Reconciliation scan — `GET /api/reconcile` reports drift across all credentials (read-only, safe to schedule), fully audited (`credential.reconcile`, `credential.rotate`, `credential.remediate`)
- [x] **Credential checkout/check-in with lease** — `POST /api/credentials/{id}/checkout` grants an exclusive, time-boxed lease (`PAM_CHECKOUT_TTL_MIN`) and returns the secret; `/checkin` ends it and **rotates** the credential so the seen password is invalidated. Enforced single-holder; honors the reveal-disabled policy
- [x] **Discovery** — `POST /api/discovery/scan` probes hosts for reachable management ports (SSH/WinRM/RDP) and can auto-onboard new targets (`internal/discovery`, reachability only — no credentials used)
- [x] **Identity reconciliation**: `POST /api/identity/reconcile[?dry_run=true]` checks every local user against the directory (`auth.DirectorySource.UserStatus`), **revokes disabled directory users** (`user.revoked`) and surfaces absent local-only accounts as `not_in_directory` (never revoked on uncertainty)
- [x] **AD/LDAPS password-change primitive** (`LDAPAuthenticator.ChangePassword` — Modify `unicodePwd`, UTF-16LE/quoted; unit-tested). *(Wiring it into a full AD-account rotation flow and real-DC interop is a follow-on.)*
- [x] **Forced rotation after each proxied SSH session ends** (`PAM_ROTATE_AFTER_SESSION`): the proxy's `OnSessionEnd` hook calls `Server.RotateCredentialByID`, so a secret used in one session can't be reused in the next (covers break-glass proxied sessions too)

## Phase 8 — OT adaptation ✅

Designed for industrial environments ([IEC 62443](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards), Purdue model) — see the [OT Deployment Guide](docs/OT-DEPLOYMENT.md):

- [x] **Session approval workflow (4-eyes)**: `POST /api/access-requests` → approver (a *different* principal, `CapApprove`) approves/denies; `access_requests` table; enforced on **every** connect path (SSH proxy, WinRM, RDP); break-glass bypasses; approvals/denials audited + alerted. Per-target (`require_approval`) or global (`PAM_REQUIRE_APPROVAL`), time-boxed (`PAM_APPROVAL_WINDOW_MIN`)
- [x] **Air-gap/offline mode** (`PAM_OT_AIRGAP`): disables all outbound calls (alert webhooks); alerts still hit the audit trail + local logs
- [x] Deployment pattern for the industrial DMZ (level 3.5) documented (Purdue diagram, firewall guidance, IEC 62443 control mapping)
- [x] **Protocol allowlisting** (`PAM_ALLOWED_PROTOCOLS`): restrict which target protocols may be created/connected (e.g. forbid RDP in an OT zone); enforced at create-target and on every connect path (API + proxy)
- [x] **Read-only observer sessions**: `ssh <cred>@<target>+observe@pam` opens a view-only session — output streams and is recorded, but operator keystrokes are dropped and exec/subsystem requests are refused (`mode:observer` in the audit)
- [x] **Jump-host / bastion connector** (`PAM_SSH_JUMP_*`): reach SSH targets only accessible via an SSH bastion — the proxy tunnels a `direct-tcpip` channel through the jump host (public-key auth, per-dial bastion connection)
- [ ] Serial connectors (RS-232 / terminal servers) for legacy equipment — needs serial hardware (follow-on)

## Phase 9 — NIS2 compliance pack ✅

Mapping to [Directive (EU) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj) — see the [NIS2 Compliance Pack](docs/NIS2-COMPLIANCE.md):

- [x] **Control matrix doc**: full Art. 21(2)(a–j) measure ↔ pamv1 feature mapping
- [x] **Incident reporting export** (Art. 23): `GET /api/audit/export` returns a scoped audit slice (`since`/`until`/`actor`/`action`, JSON or CSV) with a **SHA-256 tamper-evidence digest** (body field + `X-PAM-Export-SHA256` header); the export is itself audited
- [x] **Audit retention + SIEM forwarding** guidance (append-only trail in Postgres; JSON logs + audit events to stdout for a collector; real-time alert webhook)
- [x] **Risk-management documentation template** for essential/important entities

## Phase 10 — Scale & operations ✅

- [x] **Observability**: Prometheus `/metrics` (`internal/metrics`, dependency-free exposition — request counts by status, audit volume, break-glass use, rotations, active-sessions gauge), structured JSON logs, **health/readiness split** (`/healthz` liveness + `/readyz` store-reachability readiness, `store.Ping`)
- [x] **Helm chart** (`deploy/helm/pamv1`): deployment/service/secret/ingress/ServiceMonitor, configurable replicas, PVC or emptyDir, hardened pod security context
- [x] **Signed release pipeline** (`.github/workflows/release.yml`): build + push by digest on a version tag, **SBOM** (SPDX) generation + attestation, **cosign** keyless image signing, GitHub Release. First executed for real on 2026-07-28: **v0.10.0** published, signed and attested end to end
- [x] **HA — OIDC login state shared** via the store (migration `0004`, `store.PutOIDCState`/`TakeOIDCState`), so the auth-code callback can land on any replica. The auth rate-limiter stays best-effort per-replica; break-glass quorum-unseal keeps its shares in memory **by design** (persisting key shares to the DB would weaken the offline-shares guarantee — use a sticky session or a single replica for the unseal flow)
- [x] **Postgres HA** via [CloudNativePG](https://cloudnative-pg.io/): a 3-instance `Cluster` manifest (`deploy/k8s/postgres-cnpg.yaml`, automatic failover, scram-sha-256, optional PITR)
- [x] **Terraform module for cloud-managed Postgres** (`deploy/terraform/cloud-postgres/` — AWS RDS example: multi-AZ, encrypted, `force_ssl`)
- [x] **SLSA build provenance** attested by the release pipeline (not yet exercised — no tags exist) (`actions/attest-build-provenance` in `release.yml`, pushed to the registry alongside the cosign signature + SBOM)

## Phase 11 — Management console ✅

The AS/400 5250 green-terminal portal grows from 3 screens into a full
management console covering every backend capability (CyberArk/Wallix-grade
*coverage*, IBM 5250 *look*). Still one `//go:embed`'d page, vanilla JS,
nonce-CSP, no build step — the retro aesthetic is a deliberate constraint, not a
limitation.

- [x] **Role-aware menu** — `GET /api/me` returns the caller's identity + the stable capability names its role holds; the main menu shows only the options the role may use (panels still tolerate a 403 as a backstop)
- [x] **Targets** — subfile with delete + *work-with-grants*, `require_approval` on add; **target grants** screen (list/add/delete role- or user-scoped access)
- [x] **Credentials** — reveal (audited), **check-out** (leased secret + expiry), rotate, reconcile, delete
- [x] **Check-out / check-in** — active exclusive leases; check-in rotates the secret
- [x] **Active sessions** — live monitor (auto-refresh) of proxied SSH/WinRM/RDP sessions with a kill switch
- [x] **Access requests** — 4-eyes: approvers see pending requests and approve/deny; connect-capable users file requests
- [x] **Users & roles** — mint one-time tokens, delete, run directory reconciliation
- [x] **MFA self-service** — enroll (secret + otpauth), confirm, recovery codes, disable
- [x] **Discovery** — scan hosts for reachable SSH/WinRM/RDP and optionally onboard as targets
- [x] **Reconciliation report** — read-only drift scan across all credentials
- [x] **Audit trail** — client-side filter + tamper-evident CSV export (SHA-256)
- [x] **Break-glass unseal** — submit an M-of-N quorum share; on quorum an audited, auto-expiring admin session is issued

## Phase 12 — Configuration subsystem & custom profiles ✅

Make identity backends, policies, and permission profiles configurable from the
console — the CyberArk/Wallix administration surface — using a **hybrid** model
that respects the project's IaC-first roots.

- [x] **Hybrid config model**: directory bindings (LDAP/AD, **Kerberos**), SSO (Entra/OIDC), and policies become editable settings **persisted in the DB** and applied on save; the authenticator chain is rebuilt from stored config — *shipped*: the DB-persisted, vault-encrypted settings store + `GET/PUT/DELETE /api/config` overlaid onto the env config, **plus hot-swap without a restart** (an atomic `runtimeConf` snapshot rebuilt by a `Reconfigure` closure, with rollback on a rejected change; bootstrap/transport/listeners stay env-only and restart-bound)
- [x] **Networking/TLS stays IaC**: a read-only effective-config + backend-health screen (`GET /api/config/effective`) plus a generator (`GET /api/config/iac?format=env|helm|terraform`) that exports the console-set overrides back to IaC, secrets rendered as secret-store placeholders (never plaintext); listeners/ports/TLS stay env-only
- [x] **Custom permission profiles**: named capability sets assignable to users (a configurable RBAC engine), with the current 4 roles as built-in defaults; assignment surfaced in *Work with users & profiles* — *shipped*: `profiles` table (migration `0009`), `POST/GET /api/profiles` + `DELETE /api/profiles/{id}`, `auth.Principal.Can` resolving a capability set (built-in roles unchanged), `createUser` accepting a profile name, and the console role/profile picker now loading custom profiles live
- [x] Console screens (5250 style) to manage profiles (menu 12), identity/SSO/policy configuration (menu 13), and effective config + backend health with IaC export (menu 14); Kerberos *config* is expressible via the generic `PAM_*` override editor even though live Kerberos auth needs a KDC to exercise (see the infra-bound list above)

## Phase 13 — AI-agent access broker ✅

PAM for AI agents (ports [`morandeirachema/pam-research`](https://github.com/morandeirachema/pam-research)): an agent holds only an identity key; a policy engine decides `allow / require_approval / deny` on a tool call **and its arguments**; approved actions execute **server-side** with a just-in-time credential; the agent receives only the result. "Trust the chokepoint, not the agent." Opt-in via `PAM_BROKER_POLICY_FILE`; brokers pamv1's own operations with JIT vault injection.

- [x] **Policy engine** (`internal/policy`): YAML rules (`eq`/`not`/`in`/`not_in`), first-match-wins, implicit deny, scope templating, fail-loud loader
- [x] **Agent identity** (`internal/agentid`): static bearer keys (`agent_keys`, SHA-256 hash lookup), `RoleAgent` + `CapCallTool`
- [x] **Tool registry + JIT execution**: `winrm_exec` over the refactored `execWinRM` — decrypts just-in-time, returns only the result (proven: the runner gets the vaulted secret, the response leaks nothing)
- [x] **Verifiable audit chain** (`internal/auditchain`): keyed-HMAC per-event hash chain (`broker_audit_events`) + `/v1/audit/verify` + ed25519-signed head checkpoint for truncation detection
- [x] **REST surface**: `POST /v1/tool-calls`, `GET /v1/tool-calls/{id}`, `POST /v1/agents`, `GET /v1/audit[/verify|/head]`; HTTP-200-with-status error model
- [x] **Approval + resume + short-lived single-use tokens + more tools**: the `require_approval` effect parks a call, an approver decides via `GET /v1/approvals` + `POST /v1/approvals/{id}/decision`, execute-on-approve injects JIT (the human decision satisfies the target four-eyes gate), and the agent collects the result once with a single-use `broker_tokens` JTI (`POST /v1/tool-calls/{id}/resume`); per-agent rate limits + argument-size caps. Tools: `winrm_exec`, `ssh_exec`, `list_targets`, `list_credentials`, `rotate_credential`, and `reveal_credential` (default-deny)
- [x] **MCP server** (`internal/mcp`): hand-rolled JSON-RPC 2.0 at `POST /mcp` (`initialize`, `tools/list`, `tools/call`, `ping`, `broker/resume`) behind the same agent auth and sharing the one `broker.ProcessCall`/`Resume` loop — proven at parity with REST (same policy, JIT injection, single-use resume, audit)
- [x] **SPIFFE JWT-SVID + RFC 8693 delegation**: `agentid.SVIDVerifier` validates JWT-SVIDs against a file trust-domain JWKS (RS256/ES256/EdDSA), enforcing SPIFFE subject + audience + expiry (fail-closed), with nested `act` claims capped by `PAM_BROKER_MAX_DELEGATION_DEPTH`; a `MultiVerifier` accepts SVIDs alongside static keys (reuses the `internal/oidc` JWT/JWKS approach, no new dependency)
- [x] **Post-review hardening**: a parked `require_approval` call is **re-validated at decision time** (`broker.WithRevalidator`) — an agent key revoked/disabled, or an SVID expired, since parking is refused rather than executed on approval; broker-audit append is serialized across processes under a **Postgres advisory lock** (`AppendBrokerAuditLinked`, the migration-lock idiom) so a rolling-deploy pod overlap or an HA replica can't fork the keyed-HMAC chain; numeric policy arguments match in plain decimal (no `1e+07` mismatch)
- Deferred (documented): SPIRE workload attestation, RFC 8693 token-**exchange** minting, MCP SSE/elicitation, KEK-wrapping the audit keys

## Phase 14 — SOPS-encrypted secrets ✅

Keep the Kubernetes secret manifest **in the IaC repo** without leaking it: encrypt the
values with [SOPS](https://github.com/getsops/sops) + [age](https://age-encryption.org/) so
`kind`/`metadata`/keys stay reviewable while `PAM_MASTER_KEY`, `PAM_API_KEY` and the database
URL are sealed to a key only operators (or a KMS/HSM) hold.

- [x] **SOPS creation rules** (`deploy/.sops.yaml`): `encrypted_regex` seals only `data`/`stringData` values of any `deploy/k8s/sops/secrets*.yaml`; age recipient (KMS/PGP recipients documented for cloud/multi-custodian setups)
- [x] **Reproducible encrypted example**: `deploy/k8s/sops/secrets.sops.example.yaml` is a real SOPS-sealed Secret decryptable with a committed **throwaway demo key** (`age-example.key`, loudly marked demo-only) so the whole flow can be run and studied
- [x] **Deploy flow**: `apply.sh` streams `sops --decrypt | kubectl apply -f -` (plaintext never touches disk); `.gitignore` blocks real keys and non-example sealed files; docs cover Flux / Argo / helm-secrets GitOps
- [x] **CI gate**: a `sops` job installs sops+age and runs `verify.sh` — proving the example is encrypted (no accidental plaintext commit) and round-trips
- Deferred (documented): cloud-KMS recipients wired into the Helm chart, a Flux `Kustomization` example, and sealing the CloudNativePG app-secret

## Phase 15 — Database session proxy (PostgreSQL) ✅

Extend the JIT chokepoint to **databases** — the first of the [Tier-1 competitive-coverage gaps](README.md#coverage-vs-commercial-pam-cyberark-wallix-) (matching [Teleport](https://goteleport.com/docs/enroll-resources/database-access/) / [StrongDM](https://www.strongdm.com/) / CyberArk DPA). An operator points `psql` at pamv1; the proxy authenticates them, injects the vaulted DB credential just-in-time, and brokers the wire protocol — auditing every SQL statement. The operator never sees the database password. Opt-in via `PAM_DB_ADDR`.

- [x] **PostgreSQL wire-protocol proxy** (`internal/proxy/dbproxy.go`, on `PAM_DB_ADDR`, default off): speaks the frontend/backend protocol via `pgproto3` (already vendored with pgx). Operator connects `psql "host=pam port=5433 user=<dbcred>@<target> dbname=<db>"` with their PAM key as the password; login parsing reuses the SSH proxy's `creduser@target` convention
- [x] **Same authorization gates as the SSH proxy** (decrypt only after every gate): `CapConnect`, per-target grants (`CanConnectTarget`), the protocol allowlist, and the 4-eyes/OT approval gate — then JIT `vault.Decrypt` and injection
- [x] **Upstream authentication with the vaulted secret**: trust, cleartext, MD5, and **SCRAM-SHA-256** (RFC 5802, stdlib `crypto/hmac`·`sha256` + `x/crypto/pbkdf2`), plus best-effort upstream TLS (`sslmode=prefer` style) — so it reaches self-hosted **and** managed/SCRAM Postgres. Optional operator-leg TLS when `PAM_TLS_CERT/KEY` are set
- [x] **Per-statement query audit + recording**: every `Query`/`Parse` becomes a `db.query` audit event and a line in the session recording (asciicast, SHA-256 hash-chained like SSH/WinRM); live in the session registry (list + kill) as protocol `postgres`; post-session rotation honored
- [x] **End-to-end JIT proof**: an in-process fake PostgreSQL upstream that accepts **only** the vaulted secret — a passing test proves the operator's PAM key was swapped for the vault secret and the SQL was audited; a bad-key operator is refused before any upstream contact
- Deferred (documented): MySQL/Oracle connectors (same pattern, new wire protocols) and result-row redaction policies. **MSSQL has since shipped (Phase 53).** **CA-pinned upstream TLS has since shipped** (`PAM_DB_UPSTREAM_CA` / `PAM_DB_UPSTREAM_TLS_VERIFY`, in the 2026-07-22 hardening pass)

## Phase 16 — Live session monitoring + command control ✅

Turn the existing recording + kill-switch into **supervised** sessions — the third [Tier-1 competitive-coverage gap](README.md#coverage-vs-commercial-pam-cyberark-wallix-) (matching CyberArk PSM / Wallix live monitoring + command filtering).

- [x] **Live session monitoring**: a `session.Hub` fans out every recorded output byte, keyed by session id; `GET /api/sessions/{id}/stream` (`CapReadAudit`) streams it as **Server-Sent Events** so a supervisor watches an SSH or PostgreSQL session as it happens. Non-blocking fan-out (a slow watcher drops frames, never stalls the session); the watch is audited (`session.monitor`)
- [x] **Command control**: a `CommandGuard` (regex denylist from `PAM_COMMAND_DENY_FILE`, one pattern per line) blocks a dangerous command **before it reaches the target** on every path where a discrete command is visible — SSH `exec` (the request is refused, never forwarded), each WinRM command-loop line, and each PostgreSQL `Query`/`Parse` (a simple query is refused but the session stays usable; an extended-protocol statement fails closed). Blocks are audited `command.blocked` with the matched pattern
- [x] **Shared writer plumbing**: the proxy tees session output to the hub via `teeLive`; the DB relay serializes all client-facing writes under one mutex (pgproto3 is not concurrency-safe), proven race-free under `-race`
- [x] **Tests**: the guard (match / comment-skip / fail-loud / nil no-op), the hub (pub-sub, cancel, slow-watcher drop), a blocked SSH exec and a blocked SQL statement (neither reaches the upstream), a live SQL frame observed over the hub, and the SSE endpoint (200 + frame for an auditor, 403 without `CapReadAudit`)
- Deferred (documented): interactive-shell command filtering (a raw PTY stream is not parsed — use observer sessions or restrict shell access). *(The in-portal 5250 viewer for the live stream shipped in Phase 25; WinRM live streaming, deferred here, shipped 2026-07-29.)*

## Phase 17 — Safes & dependent-account propagation ✅

The last two [Tier-1 competitive-coverage gaps](README.md#coverage-vs-commercial-pam-cyberark-wallix-): CyberArk's Safe-centric authorization model, and safe rotation of service accounts.

**Safes / vault containers (delegated access):**

- [x] **Safe model** (migration `0012`: `safes`, `safe_members`, `targets.safe_id`): a named container groups targets and delegates who may access them. A **safe member may connect to every target in the safe** — an authorization path alongside per-target grants
- [x] **Effective grants**: `store.EffectiveTargetGrants(targetID)` = direct grants ∪ safe-member-derived grants; every connect gate (SSH proxy, DB proxy, RDP, the two broker-tool checks, `gateCredentialAccess`) now honors it, so placing a target in a safe restricts it to the safe's members. `auth.SubjectMatches` factored out of `CanConnectTarget` and reused
- [x] **Delegated administration**: `POST/GET /api/safes`, `DELETE /api/safes/{id}`, `GET/POST /api/safes/{id}/members`, `DELETE /api/safes/{id}/members/{mid}`, `PUT /api/targets/{id}/safe`. Member management is gated by `canManageSafe` — a global target manager **or** a `can_manage` member of that safe (so safe ownership can be delegated). Audit `safe.create`/`safe.delete`/`safe.member.{add,remove}`/`target.safe_set`
- [x] **Tests**: store contract (CRUD, conflict, `EffectiveTargetGrants`, cascade-unassign on delete), an end-to-end proxy test (a non-member is denied a target in a safe; adding the member's role grants the connection), and delegated-management authz

**Dependent-account propagation (safe service-account rotation):**

- [x] **Declared consumers** (migration `0013`: `credential_dependencies`): a credential lists the **Windows Services / Scheduled Tasks / IIS App Pools** that log on with it (`POST/GET /api/credentials/{id}/dependencies`, `DELETE …/{did}`)
- [x] **Propagation on rotation**: after `rotateCredential` sets and re-vaults the new secret, `propagateDependencies` updates each consumer over WinRM (`sc.exe config` / `schtasks /Change /RP` / `appcmd set apppool …password`) with the new secret — so auto-rotating a service account no longer breaks the services that use it. A propagation failure never fails the (already-persisted) rotation; each consumer is audited `credential.dependency_updated`/`credential.dependency_failed` (the secret is injected into the WinRM command but never audited or recorded)
- [x] **Tests**: store contract (CRUD, default WinRM port, missing-credential `ErrNotFound`, cascade on credential delete) and an end-to-end rotation test (the fake WinRM receives the `sc.exe config` for the service with the new secret; the audit carries the update without the secret)
- Deferred (documented): a per-consumer management/reconcile credential (propagation currently connects as the rotated account) and a Safe-scoped policy/workflow layer (per-safe approval, dual control). *(The in-portal 5250 safe-management screens shipped in Phase 25.)*

## Phase 18 — Conjur secret sourcing (alternative to SOPS) ✅

Let pamv1 source its **own** bootstrap secrets from [CyberArk Conjur](https://www.conjur.org/) at runtime — the runtime-broker counterpart to the SOPS GitOps sealing (Phase 14). **Both ship; SOPS stays the zero-dependency default**, Conjur is opt-in (`PAM_CONJUR_URL`). This is the same philosophy pamv1 already applies to its KEK (Vault-Transit / AWS-KMS / PKCS#11) — externalize the root of trust — now applied to the secret *values*.

- [x] **Hand-rolled Conjur client** (`internal/conjur`, no new dependency — the two REST endpoints pamv1 needs, like the MCP/SPIFFE hand-rolls): authenticate + read secret, over TLS with an optional CA bundle
- [x] **Two authenticators**: `authn-api-key` (host login + API key) and **`authn-jwt`** — the pod presents a Kubernetes projected service-account token, so **no bootstrap secret lives in Git at all** (reuses the JWT posture from `oidc`/`agentid`)
- [x] **Startup sourcing** (`conjur.SourceEnv`, before `config.Load`): fills any **empty** bootstrap `PAM_*` secret (master key, API key, DB URL, break-glass hash, broker keys) from `PAM_CONJUR_POLICY_PREFIX/<name>`. An explicit env value **wins**; a variable missing in Conjur (404) is skipped; a configured-but-unreachable Conjur is **fail-loud** (never starts with empty secrets)
- [x] **IaC**: `deploy/k8s/conjur/` — a Conjur policy (`policy.yaml`), a pam-server Deployment with the authn-jwt projected-token volume (`deployment.yaml`), and a README covering the SOPS-vs-Conjur trade-offs
- [x] **Tests**: an in-process fake Conjur (authenticate → retrieve, 404-as-not-found, auth-failure fail-loud) plus `SourceEnv` behavior (fills empty, env wins, disabled no-op, `PAM_SECRETS_PROVIDER=conjur` without a URL fails loud)
- Deferred (documented): runtime secret **refresh** without a restart (sourcing is one-shot at boot, like SOPS at apply), a per-variable override map, and pushing pamv1's *managed* secrets **out** to Conjur (Secrets-Hub-style sync — a Tier-4 gap)

## Phase 19 — Access certification / attestation campaigns ✅

The first [Tier-2 competitive-coverage gap](README.md#coverage-vs-commercial-pam-cyberark-wallix-) (access-governance depth): the periodic "recertify or revoke who has access to what" review that SOX / ISO 27001 / NIS2 Art. 21(2) expect, and that CyberArk/SailPoint-style IGA provides.

- [x] **Campaign snapshot**: `POST /api/campaigns` captures the *current* access grants — every target grant and every safe member — as reviewable **campaign items** (migration `0014`: `campaigns`, `campaign_items`). A campaign is a point-in-time attestation record
- [x] **Certify or revoke, with teeth**: `POST /api/campaigns/{id}/items/{iid}/decision {certify|revoke}` — a **revoke actually deletes the underlying grant** (`DeleteTargetGrant`/`DeleteSafeMember`; a grant already gone is a no-op, since the goal state is "no access"), certify records the attestation. `POST …/close` closes the campaign (further decisions refused). Every decision is audited
- [x] **Governance-scoped authz**: management (`create`/`decide`/`close`) needs `CapManageUsers`; reading a campaign + its items needs `CapReadAudit` — so an auditor can review the evidence without being able to change access. No new capability added to the matrix
- [x] **Audit vocabulary**: `certification.campaign_created` · `certification.item_certified` · `certification.item_revoked` · `certification.campaign_closed`
- [x] **Tests**: store contract (CRUD, decide, close, missing-campaign `ErrNotFound`) and an end-to-end API test (a campaign snapshots a grant + a safe member; revoke deletes the grant, certify retains the member, a closed campaign returns 409; auditor can read, a plain user cannot manage)
- Deferred (documented): scheduled/recurring campaigns, scoped campaigns (per-safe or per-owner), and reviewer assignment + reminders. *(The 5250 console review screen shipped in Phase 25.)*

## Phase 20 — ITSM / ticketing gate ✅

The second [Tier-2 competitive-coverage gap](README.md#coverage-vs-commercial-pam-cyberark-wallix-): "no privileged access without an approved change ticket" — the ServiceNow/Jira integration compliance teams expect, hung on the existing 4-eyes access-request engine.

- [x] **Ticket validator** (`internal/ticket`, no new dependency): two optional, composable checks — a **regex format** (`PAM_TICKET_PATTERN`, e.g. a ServiceNow/Jira number) and a **webhook** (`PAM_TICKET_VALIDATE_URL`) the ITSM system answers `2xx` for a valid, approved ticket (`POST {"ticket":"<id>"}`). A nil validator accepts any ticket (disabled)
- [x] **Gate on access requests**: `POST /api/access-requests` accepts a `ticket`; when `PAM_REQUIRE_TICKET` is set it is mandatory (422 otherwise), a configured validator must pass (422 + `access.ticket_rejected` audit on failure), and the ticket is **stamped into the request and the audit trail** (`store.AccessRequest.Ticket`, migration `0015`)
- [x] **Tests**: a `ticket` unit test (disabled / bad-pattern / format reject) and an end-to-end API test with a fake ITSM webhook (missing → 422, bad format → 422, webhook-rejected → 422, an approved ticket → 201 and recorded)
- Deferred (documented): a first-class ServiceNow/Jira connector (this ships the generic webhook + regex hook), and gating the connect path directly on a live ticket lookup (today the ticket is validated at request time)

## Phase 21 — Richer approval workflows ✅

The third [Tier-2 competitive-coverage gap](README.md#coverage-vs-commercial-pam-cyberark-wallix-): move past single-level 4-eyes to the approval depth CyberArk/Wallix offer — built on the existing access-request engine (migration `0016`).

- [x] **Multi-tier approval chains (N-of-M)**: an access request needs `RequiredApprovals` **distinct** approvers before it is granted (`PAM_APPROVALS_REQUIRED` default; a request may ask for more via `approvals`). Each approval accumulates into `approved_by`; the request stays `pending` until the count is met, then flips to `approved`. An approver can't approve twice (409); self-approval is still refused (four-eyes). Partial approvals audit `access.approve_partial`
- [x] **Scheduled / time-boxed windows**: a request may carry `not_before` / `not_after`; an approved request is only **active inside that window** (`HasActiveApproval` honors `not_before`), so access can be pre-approved for a future maintenance window
- [x] **Mandatory reason codes**: `PAM_REQUIRE_REASON` rejects an access request with no reason (422)
- [x] **Tests**: store contract (multi-approver accumulation, scheduled-window activation) and end-to-end API tests (a 2-of-N chain — first approval pending, double-approval 409, second distinct approval grants; mandatory reason; a scheduled window round-trips)
- [x] **One-time (single-use) access** — *shipped in Phase 26* (the consume-on-connect hook in every privileged-use gate)

## Phase 22 — Zero Standing Privilege (ephemeral SSH certificates) ✅

The first [Tier-3 competitive-coverage gap](README.md#coverage-vs-commercial-pam-cyberark-wallix-) (where the market is moving): stop storing a standing secret for an account at all. Instead of a vaulted password/key, pamv1 signs a **short-lived SSH user certificate just-in-time** for each proxied session — the target trusts only the pamv1 CA, so the account has **no standing credential** (the Teleport / CyberArk ZSP model), built directly on the existing JIT proxy chokepoint.

- [x] **SSH certificate authority** (`internal/sshca`): a persistent CA key (`PAM_SSH_CA_KEY`, generated on first use, mirrors the host-key handling) that mints short-lived user certificates. Each certificate gets a fresh ephemeral keypair (used for one dial, then discarded), a serial for audit correlation, the standard interactive extensions, and a validity of `PAM_SSH_CERT_TTL_MIN` (default 2m).
- [x] **Zero-standing credential type** (`secret_type: "ssh_ca"`): a credential that stores **no secret** (`SecretEnc` stays empty — nothing to vault, reconcile, or rotate). Only valid on ssh targets; rejected with a secret attached. The proxy, seeing `ssh_ca`, mints a certificate at dial time and authenticates upstream with it — no vault decrypt happens, and a missing CA fails the session closed (`session.error`), never falling back to a non-existent secret.
- [x] **CA public-key publication**: `GET /api/ca/ssh` (`CapReadInventory`) returns the CA public key in authorized_keys form + a `TrustedUserCAKeys` install hint, so an operator can configure their targets; 404 when ZSP is disabled.
- [x] **Audit vocabulary**: `session.cert_issued` (serial · principal · valid-before · key-id — never the private key). Reconciliation reports `ssh_ca` as `unsupported`; post-session rotation and the lifecycle worker skip it (there is no secret to rotate — the cert already expired).
- [x] **Tests**: `internal/sshca` unit tests (a minted cert is a user cert, signed by the CA, principal-scoped, and expires — checked with an `ssh.CertChecker`); an **end-to-end ZSP proxy test** against an in-process upstream that accepts **only** a CA-signed certificate (no password auth exists), proving the account has no standing secret; a without-CA fail-closed test; and API tests for the credential rules + the CA endpoint.
- Deferred (documented): ephemeral **local accounts** (create/destroy the OS account per session — needs a real host), host-certificate issuance, and per-principal certificate options/source-address restrictions.

## Phase 23 — Privileged threat analytics ✅

The second [Tier-3 gap](README.md#coverage-vs-commercial-pam-cyberark-wallix-): behavioral anomaly detection, risk scoring, and automated response over the privileged-session stream (the CyberArk PTA / Wallix analytics capability) — computed from the audit trail pamv1 already produces.

- [x] **Deterministic, explainable risk engine** (`internal/analytics`): a pure scorer over audit events (no clock, no I/O, no opaque model) — every point of an actor's score traces back to a named **signal**: break-glass use, blocked commands, authentication-failure bursts, off-hours activity, credential-decryption failures, and session velocity. Weights, per-signal caps, level thresholds, and business hours are configurable; a single break-glass access alone reaches **high**.
- [x] **Risk API**: `GET /api/analytics/risk` (`CapReadAudit`) scores the recent audit window into per-actor findings (score, level, contributing signals), sorted by score, filterable by `?min_level=` and `?window_min=` — so an auditor reviews risk without changing any access.
- [x] **Background worker + automated response** (`RunAnalyticsWorker`, `PAM_ANALYTICS_INTERVAL_MIN`): each pass scores the window, and for a **newly elevated** high/critical actor appends `analytics.risk_flagged`, fires the alert channel, and — with `PAM_ANALYTICS_AUTO_KILL` on — **terminates a critical actor's live sessions** (`session.Registry.KillByActor`, audited `analytics.auto_response`). A steady state is not re-alerted every pass; a worsening trend is.
- [x] **Tests**: engine unit tests (break-glass → high; clean in-hours work → no finding; off-hours contribution; auth-failure burst + score-descending sort; per-signal cap) and API tests (the risk endpoint scores + enforces `CapReadAudit`; the worker flags, alerts, dedupes, and auto-kills a critical actor's sessions).
- Deferred (documented): peer-baseline / new-target novelty scoring (needs a longer history model) and step-up-MFA response. *(The 5250 console risk dashboard shipped in Phase 25.)*

---

## Phase 24 — Application-secrets API (Tier-4: Conjur-style secret delivery) ✅

The first [Tier-4 ecosystem gap](README.md#coverage-vs-commercial-pam-cyberark-wallix-): a **Conjur-style application-secrets API** so a **non-agent application** (a CI job, a legacy service, a microservice) can retrieve the specific secrets it needs at startup — without an operator, a session proxy, or the AI-agent tool broker. Opt-in via `PAM_APP_SECRETS_ENABLED`; **default-deny** and least-privilege by construction.

- [x] **Application identity** (migration `0017`: `app_keys`): a bearer key whose **SHA-256 hash only** is stored (like agent keys), with an accountable owner recorded in the audit trail. Admin CRUD `POST/GET /v1/apps` + `DELETE /v1/apps/{id}` (`CapManageUsers`).
- [x] **Per-app secret grants** (`app_secret_grants`, default-deny): an app may fetch a credential's secret **only** if it has an explicit grant (`POST/GET /v1/apps/{id}/grants`, `DELETE …/{gid}`). Granting needs **`CapRevealSecret`** — you can only hand an app a secret you could reveal yourself, so a delegated `manage_users` principal can't exfiltrate secrets it couldn't otherwise read. Grants cascade when the app or the credential is deleted.
- [x] **The fetch path** `GET /v1/app-secrets/{credential_id}` (application bearer auth): decrypts the granted credential just-in-time and returns it, audited `app.secret_retrieved` (never the secret itself); a non-granted credential is `app.secret_denied` + 403; a disabled/unknown app is 401; a Zero Standing Privilege (`ssh_ca`) credential has no secret to deliver (422). Independent of `PAM_REVEAL_DISABLED` (apps can't use the session proxy); **front it with TLS** — it delivers plaintext to machines.
- [x] **Audit vocabulary**: `app.create` · `app.revoke` · `app.grant` · `app.grant_revoked` · `app.secret_retrieved` · `app.secret_denied`.
- [x] **5250 console screen** (menu 15, *Work with application secrets*): mint/revoke application identities (the bearer token shown once), and per-app *Work with secret grants* to grant/revoke individual credentials — keyboard-first like the rest of the portal. Tolerates the API being disabled with a hint.
- [x] **Tests**: store contract (app-key CRUD, default-deny + grant, duplicate/missing-FK errors, cascade on credential and app delete) and an end-to-end API test (mint → grant → fetch exactly the granted secret; ungranted 403; bad token 401; the secret never enters the audit trail; a plain user can neither mint apps nor grant secrets; routes absent when disabled).
- Deferred (documented, Tier-4): a **Terraform provider** for pamv1 objects (a separate module + the Terraform Registry), **Secrets-Hub-style sync-out** to AWS Secrets Manager / Azure Key Vault (needs a cloud account), **SSH-key fleet discovery** at scale (needs a real host fleet), and **thick-app connection components** (Windows RemoteApp hosts) — see [docs/EXTERNAL-INFRA-GAPS.md](docs/EXTERNAL-INFRA-GAPS.md).

## Phase 25 — Console parity ✅

Close the gap between the backend and the 5250 console: Phases 16–23 shipped
capabilities whose portal screens were documented follow-ons. This phase brings
the console back to full CyberArk/Wallix-style *coverage* — every capability
reachable keyboard-first, same austere look, still one `//go:embed`'d vanilla-JS
page with no new routes or schema (each screen drives an existing API).

- [x] **Work with safes** (menu 16): list/create/delete safes with per-safe target counts; *Work with safe members* (add/remove, `can_manage` delegated administration); targets now show their safe and *Work with Targets* option 8 assigns/clears a target's safe (`PUT /api/targets/{id}/safe`)
- [x] **Certification campaigns** (menu 17): snapshot a new campaign (name + optional due date), review items with certify/revoke decisions (revoke deletes the underlying grant — labeled as such), close a campaign; read-only for auditors (decisions need `manage_users`), decided items show decision + decider
- [x] **Risk analytics** (menu 18): the per-actor behavioral-risk dashboard over `GET /api/analytics/risk` — score, level (color-coded), named signals with points, event counts; filter by minimum level and scoring window from the screen
- [x] **Live session viewer**: *Work with Active Sessions* option 5 watches a session as it happens — the SSE stream (`GET /api/sessions/{id}/stream`) is read with `fetch` (EventSource cannot send the `X-API-Key` header), ANSI-stripped, and rendered in a bounded scrollback pane; view-only, audited `session.monitor`
- [x] **Access-request workflow fields** (Phases 20–21 catch-up): the file-request form now takes a change **ticket**, a requested **N-of-M approval count**, and a **scheduled window** (`not_before`/`not_after`); the approver list shows ticket, approval progress (`n/m` distinct approvers), window start, and expiry
- [x] Verified end to end against the in-memory server: every screen's exact API calls exercised (safe → member → target assignment; campaign snapshot → certify/revoke-with-teeth → close; risk filters; a ticketed 2-of-N windowed request), plus `node --check` on the embedded script and the full Go test suite

## Phase 26 — Session-recording playback + one-time access ✅

Two follow-ons the backlog had carried since Phases 2 and 21, both fully
buildable and verifiable in process: recordings existed on disk (hash-chained,
audited) but nothing could replay them, and an approval — once granted — kept
admitting connections for its whole window.

**Session-recording playback (the review side of Phase 2's recordings):**

- [x] **Recordings API**: `GET /api/recordings` (`CapReadAudit`) lists the stored recordings newest-first (asciicast `.cast` from the SSH/WinRM/PostgreSQL proxies, `.winrm.log` transcripts from the WinRM run endpoint; dotfiles like the `.chain` head never listed); `GET /api/recordings/{name}` serves one for replay. A strict filename allowlist (the recorder's own `sanitize` alphabet) forecloses path traversal
- [x] **Tamper evidence at replay**: the served file's SHA-256 is recomputed and searched in the audit trail (`store.FindAuditDetail` — the value stamped by `session.record` / `winrm.run` when the recording was written); the verdict rides `X-PAM-Recording-Audited`, so a file tampered on disk is visibly flagged the moment an auditor replays it. Hash and body cover the same byte range, so a still-recording session replays as a consistent prefix
- [x] **Every replay is audited** (`session.playback` — file, bytes, sha256, verdict)
- [x] **5250 replay screen** (menu 19): recordings subfile + a keyboard-first player in the live-viewer pane — Space pause/resume, F5 restart, F6 speed (1x→2x→4x→8x→MAX), long idle gaps capped at 2s (asciinema-style), ANSI-stripped bounded scrollback, and the audit-verification verdict on screen

**One-time (single-use) access (Phase 21's deferred follow-on):**

- [x] **Single-use approvals** (migration `0019`: `one_time`, `consumed_at`): an access request may be filed one-time (`one_time` on `POST /api/access-requests`, or forced globally by `PAM_ACCESS_ONE_TIME`); the first privileged use its approval admits **consumes it** — audited `access.consumed` — and it admits nothing further
- [x] **Consume-on-use in every gate**: the SSH proxy, the PostgreSQL proxy, the RDP tunnel, and the API's approval gate (reveal, checkout, WinRM run, broker tool calls) all burn a single-use approval via `store.ConsumeApproval` — atomic under racing connects (`FOR UPDATE SKIP LOCKED`; exactly one of two simultaneous dials wins), a standing approval is preferred and never burned, and a consumed approval is inactive everywhere (`HasActiveApproval` honors it). Consumption is deliberately fail-closed: an admitted connection that later fails upstream still spends the approval
- [x] **Console**: the file-request form takes a one-time flag; the approver list shows `1x` / `used`
- [x] **Tests**: store contract (round-trip, burn-once, standing-approval preference, an 8-way race admits exactly one consumer), end-to-end SSH and PostgreSQL proxy tests (a single-use approval admits exactly one connection; the second is refused before any upstream contact), API tests (checkout burns the approval; `PAM_ACCESS_ONE_TIME` forces one-time), and playback tests (listing, byte-exact serve, verified/unaudited verdicts, RBAC, name hygiene)

## Phase 27 — AI-agent broker completion (Solution-01 parity) ✅

The AI-agent access broker (Phase 13) ported the [pam-research](https://github.com/morandeirachema/pam-research) control loop; this phase closes the honestly-buildable gaps that remained, so the broker reaches parity with that research prototype's Solution 01 without faking any infra-bound part.

- [x] **Approver-group separation of duties**: a `require_approval` rule's `approvers:` list is now **enforced at decision time** — `broker.Decide` takes an `Approver{Name, Groups, IsAdmin}` (groups = the principal's name + role names, via `auth.Principal.ApproverGroups`) and refuses a decider who is not a member of the rule's group (`broker.approval.refused`, HTTP 403); the parked call stays decidable by someone authorized. Admins are the documented superuser bypass; four-eyes (an agent's owner can't approve its own call) is unchanged
- [x] **Periodic in-chain signed checkpoints**: `PAM_BROKER_AUDIT_CHECKPOINT_EVERY` makes the chain append a `broker.audit.checkpoint` every N events — an ed25519 signature over the running head, itself part of the HMAC chain. This is defense-in-depth over the keyed-HMAC: an attacker who edits history **and** recomputes every HMAC (a leaked HMAC key) still can't forge the checkpoint signature, so `VerifyFloor` flags a `bad_checkpoint`
- [x] **Truncation floor**: `GET /v1/audit/verify?min_entries=N` (driven from a previously archived checkpoint count) reports `truncated` when the chain is now shorter — tail-truncation detection without an out-of-band anchor
- [x] **Signing-key rotation + JWKS**: the checkpoint signer rotates with an overlap window (`PAM_BROKER_AUDIT_SIGN_PREV` trusts rotated-out public keys for verification); current + previous public keys are published as a JWKS at `GET /v1/audit/jwks`, so an external auditor validates an archived checkpoint across a rotation
- [x] **OCSF SIEM export**: `internal/ocsf` maps the audit trail to the [Open Cybersecurity Schema Framework](https://schema.ocsf.io/) — routine actions to **API Activity (6003)**, security-relevant ones (denials, blocked commands, break-glass, flagged risk) to **Detection Finding (2004)** — served at `GET /api/audit/ocsf` (`?format=ndjson` for collectors); the export is audited `audit.ocsf_export`
- [x] **MCP SSE transport + elicitation**: `GET /mcp` implements the MCP 2024-11-05 HTTP+SSE transport (session registry, `endpoint` event, heartbeats); `initialize` advertises `elicitation`/`logging`. An approval-gated `tools/call` from an elicitation-capable client prompts the running user over the stream (`elicitation/create`) — a **decline withdraws the requester's own** parked call (`broker.tool_call.withdrawn`; you may always cancel what you asked for, no approver needed), an **accept** only records intent (`broker.elicit.accepted`) and does **not** satisfy the human approver gate (four-eyes preserved)
- [x] **Threat model doc**: [docs/AGENT-THREAT-MODEL.md](docs/AGENT-THREAT-MODEL.md) maps the OWASP LLM Top 10 (2025) and MITRE ATLAS techniques to the broker's controls, and states the boundaries (admin bypass, in-band truncation limit) honestly
- [x] **Tests**: auditchain (checkpoints emitted + verified, key-compromise edit caught by the signature, rotation overlap, truncation floor), `ocsf` (classification + envelope), and API end-to-end (SoD refuses an out-of-group approver and admits a member; JWKS shape; verify floor; OCSF JSON + NDJSON; a full MCP SSE + elicitation round-trip where a decline withdraws the call and injects no credential)
- Deferred (documented, infra-bound): SPIRE workload attestation and RFC 8693 token-**exchange** minting (need an STS/SPIRE), a real OAuth 2.1 AS behind RFC 9728, and Vault-custodied signing keys — see [EXTERNAL-INFRA-GAPS.md](docs/EXTERNAL-INFRA-GAPS.md)

## Phase 28 — Operator-issued SSH certificates (JIT certs for humans) ✅

Extends the Phase 22 Zero-Standing-Privilege CA from proxy-internal minting to a public **issuance API for an operator's own key** — the [pam-research](https://github.com/morandeirachema/pam-research) Solution-02 model (Teleport `tsh login`-style): an operator authenticates to pamv1, gets a short-lived certificate scoped to a target account, and uses it with their normal SSH client for direct access, revocable early via a KRL. Built entirely in process and verified against real OpenSSH.

- [x] **Proof of possession**: `POST /api/ca/ssh/challenge` (`CapConnect`) mints a stateless, self-authenticating challenge (HMAC keyed off the CA private key — HA-safe across replicas, unforgeable without the CA key); `POST /api/ca/ssh/sign` verifies the operator signed it with the private key of the public key they present, so pamv1 only certifies a key the requester actually holds
- [x] **Scoped issuance**: `sshca.IssueForKey` signs the operator's **public** key (no secret is generated or stored) into a user certificate scoped to a single **principal** with an optional **`source-address`** critical option, capped at `PAM_SSH_OPERATOR_CERT_TTL_MIN` (default 10m). The same connect authorization as the proxy applies (per-target grants + the approval gate — a one-time approval is consumed), and the principal must be a **managed account** on the target, so an operator can't mint a cert for an arbitrary login
- [x] **KRL revocation**: issued certificates are recorded (migration `0020` `ssh_certificates`; the serial is the revocation handle, returned as a JSON **string** so a large uint64 survives float parsing). `POST /api/ca/ssh/revoke` (`CapManageTargets`) revokes a serial; `GET /api/ca/ssh/krl` (`CapReadInventory`) emits a real **OpenSSH Key Revocation List** (`sshca.KRL`, per PROTOCOL.krl) a target installs as sshd `RevokedKeys` to cut a still-valid cert off early
- [x] **Audit vocabulary**: `ssh.cert_issued` (serial · principal · target · valid-before · source-address, never the key) · `ssh.cert_denied` (failed proof of possession) · `ssh.cert_revoked`
- [x] **Tests**: `internal/sshca` (a scoped cert accepted by an `ssh.CertChecker` for its principal only, the proof-of-possession challenge round-trip, and — the honest real-tool check — the generated **KRL verified against `ssh-keygen -Q`**: a revoked serial reports revoked, a different serial does not), store contract (record/revoke/list-revoked, duplicate/already-revoked/unknown errors), and an API end-to-end (challenge → operator signs → sign → the returned cert authenticates for its principal → revoke → KRL served; a bad proof of possession, an unmanaged principal, and a non-connect role are all refused)
- Deferred (documented, infra-bound): ephemeral **local accounts** (create/destroy the OS account per session — needs a real host), host-certificate issuance, and per-principal certificate options beyond source-address — see [EXTERNAL-INFRA-GAPS.md](docs/EXTERNAL-INFRA-GAPS.md)

## Phase 29 — Third-party vendor access gate ✅

The [pam-research](https://github.com/morandeirachema/pam-research) Solution-05 model: give an external vendor **narrow, time-boxed, evidence-backed** access to specific targets, revocable in one action — built by composing pamv1's existing primitives (grants, approval, the session registry, the audit trail) into a vendor-shaped subsystem, entirely in process.

- [x] **Vendor identity + contract grants** (`internal/vendor`, migration `0021`): a vendor is an external `user`-role login linked by username; a **contract grant** (`POST /api/vendors/{id}/grants`) says which target they may reach, as which account, and the window (`not_before`/`not_after`). A grant starts **pending** and grants nothing until approved
- [x] **Customer-controlled approval + live attestation**: `POST /api/vendor-grants/{gid}/approve` (`CapApprove`) is the *customer's* decision — four-eyes refuses a vendor approving their own grant — and runs a **live employment-attestation** webhook (`PAM_VENDOR_ATTEST_URL`; the vendor-management system answers `2xx` for a currently-employed technician), so access is refused the moment the vendor's own employer offboards them
- [x] **Enforced on every connect path**: the SSH proxy, the PostgreSQL proxy, RDP, WinRM runs, and reveal/checkout all call `store.VendorSessionAllowed` — a vendor is admitted **only** while an approved, unrevoked grant is in-window; non-vendor users are unaffected. A vendor reaches nothing outside their contract
- [x] **Time-boxed with mid-session termination**: a background **sweeper** (`PAM_VENDOR_SWEEP_INTERVAL_MIN`) cuts a vendor's live session to a target once that grant's window closes (`vendor.session_expired`), so access ends when the contract does, not just at the next connect
- [x] **Instant offboard cascade**: `POST /api/vendors/{id}/offboard` disables the vendor, **revokes every grant atomically**, and **kills all their live sessions** — persisted, so a revoked technician can't return after a restart
- [x] **Evidence for auditors**: `GET /api/vendors/{id}/evidence` (`CapReadAudit`) bundles the vendor's contract grants + the audit slice attributable to them, with a SHA-256 digest — a SOC 2 / DORA-shaped per-vendor record
- [x] **Audit vocabulary**: `vendor.create` · `vendor.grant_created` · `vendor.grant_approved` · `vendor.grant_revoked` · `vendor.grant_decision_denied` · `vendor.attestation_failed` · `vendor.offboard` · `vendor.session_expired` · `vendor.evidence_export`
- [x] **Tests**: store contract (vendor + grant CRUD, window activation, offboard cascade, `VendorSessionAllowed`), the attestation webhook (`internal/vendor`), an API lifecycle (mint → pending grant refused → customer approves → WinRM admitted → offboard blocks again → evidence export, all audited), and an **SSH-proxy gate test** (a vendor is denied a target with no active grant, admitted once one is approved)
- Deferred (documented): a per-vendor console screen (the API is complete; the 5250 screens are a follow-on like earlier phases) and a first-class connector to a specific vendor-management system (this ships the generic attestation webhook)

## Phase 30 — In-session policy + step-up ✅

The core of the [pam-research](https://github.com/morandeirachema/pam-research) Solution-03 (recorded-session broker): re-evaluate policy **per action inside a session**, gate on **amounts**, and let a supervisor **step up** a risky action **without ending the session**. Applied to pamv1's two policy surfaces — the agent broker and the PostgreSQL session proxy — entirely in process.

- [x] **Numeric policy comparators**: the agent-broker policy engine (`internal/policy`) gains `gte`/`gt`/`lte`/`lt` conditions that compare an argument value **numerically** (fail-closed on an absent or non-numeric value), so a rule can gate on an amount — `when: { args.amount: { gte: 5000 } } → require_approval`, the canonical "refund over $5,000 needs a human" pattern. Load-time validation still enforces exactly one operator per condition and rejects a typo'd operator fail-loud
- [x] **In-session step-up on the PostgreSQL proxy**: a `PAM_DB_STEPUP_FILE` regex list marks sensitive statements; a matched statement **pauses** (audited `db.stepup_required`, surfaced on the live-monitor hub) and waits for a supervisor's decision — an **approval runs it** (`db.stepup_approved`), a **denial or timeout refuses it** (`db.stepup_denied`) — and the **session stays open** either way, unlike the kill-switch. Coordinated by a new `session.StepUp` (shared with the API, like the live `Hub`), bounded by `PAM_DB_STEPUP_TTL_SEC`
- [x] **Supervisor endpoints**: `GET /api/sessions/stepups` lists paused statements and `POST /api/sessions/{id}/stepup` decides one (`CapReadAudit` — the same gate as live monitoring, so the watching supervisor decides); audit `session.stepup_decided`
- [x] **Tests**: policy comparators (amount gating across boundary values + fail-closed on non-numeric, and fail-loud load of a bad/duplicate operator), the `session.StepUp` registry (approve / deny / timeout / one-at-a-time), a DB-proxy **end-to-end** (a matched statement pauses; approval runs it and it reaches the upstream; denial refuses it and it never reaches the upstream; the session survives both), and the API endpoints (listing + decide + 404 when nothing is pending)
- Deferred (documented): per-action step-up on the interactive SSH PTY path (a raw stream isn't parsed — the same boundary as command control) and numeric comparators over raw SQL (statements aren't structured args; step-up covers the DB path instead)

## Phase 31 — Identity blast-radius / CIEM engine ✅

The [pam-research](https://github.com/morandeirachema/pam-research) Solution-04 (identity-blast-radius) — and the third [Tier-3 competitive-coverage gap](README.md#coverage-vs-commercial-pam-cyberark-wallix-) (cloud CIEM), opened **honestly**: the analytical engine is what can be built and verified in process, so it ships complete and tested; only **live cloud ingestion** (boto3 / Okta / GitHub / Workspace API calls) needs an account and stays an external follow-on. pamv1 consumes a **normalized identity graph** an ingester produces and answers "if this identity is compromised, what can it actually reach?"

- [x] **Real AWS IAM effective-permission evaluator** (`internal/blast/iam.go`): implements the true AWS evaluation order — an explicit **Deny** anywhere wins, an **SCP** is a ceiling, a **permission boundary** is a ceiling, then an identity **Allow** grants, else implicit deny — with `*`/`?` wildcard matching (an iterative glob, so a hostile pattern can't cause catastrophic backtracking) and a condition it **cannot evaluate modeled as `uncertain`** rather than guessed. "An edge means a permission that really holds."
- [x] **Normalized identity graph + blast-radius traversal** (`internal/blast/blast.go`): a provider-agnostic graph of principals and directed edges. **Pivot** edges (`can_assume`, `member_of`, `can_escalate_to`, `credential_for`) expand an attacker's reach; **containment** edges (`contains`, `reads`) do not. `BlastRadius` (BFS, shortest path first) computes what a principal can reach; `WhoCanReach` is the reverse query. A conditional edge on a path marks the reach **uncertain**
- [x] **Toxic-combination findings + remediation-as-code**: `Findings` flags a non-admin that can pivot to an **effective admin** (privilege escalation) and any **cross-provider** pivot (lateral movement across trust domains), with **derived severity** (cross-provider + admin = critical). Each finding carries a **remediation** that cuts the **earliest** pivot edge on the path (the least-disruptive break), flagged **needs-review** when the path is uncertain
- [x] **API**: `POST /api/blast/analyze` (`CapReadAudit`) analyzes a submitted graph (4 MiB cap) and returns findings + a summary, plus an optional `source` blast-radius and `target` who-can-reach query; audited `blast.analyze`. Pure read-only analysis — no cloud credentials or persisted state
- [x] **Tests**: the IAM evaluator (explicit-deny precedence, SCP + boundary ceilings, wildcard semantics, conditional → uncertain), traversal + who-can-reach (a read edge must **not** expand reach), findings + earliest-cut remediation over a **canonical cross-provider "Drift"-shaped 4-hop chain** (a low-priv GitHub credential → Okta → an AWS deploy role → AWS admin), malformed-graph rejection (an edge to an unknown principal is fail-loud), and an API test
- Deferred (documented, infra-bound): **live ingestion** from AWS/Okta/GitHub/Workspace (needs accounts + API clients), a persisted snapshot store, and peer-baseline entitlement right-sizing — see [EXTERNAL-INFRA-GAPS.md](docs/EXTERNAL-INFRA-GAPS.md)

## Phase 32 — SFTP file-transfer control + audit ✅

Closes an unaudited file-transfer path in the flagship SSH proxy. SFTP is not a separate protocol: it rides an SSH `subsystem` channel carrying the binary SFTP protocol ([draft-ietf-secsh-filexfer-02](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02), the version-3 dialect OpenSSH speaks). Before this the proxy forwarded that stream **opaque** — an operator could move files with no audit trail, no policy gate, and no deny knob; the bytes merely garbled the session recording, which command control (exec-path only) never covered.

- [x] **SFTP inspector** (`internal/proxy/sftpguard.go`): sits on the operator→target leg (a new `pumpRequests` `onSubsystem` hook plus a per-session `pump` replacing the raw `io.Copy`), frames each SFTP request packet directly (no third-party SFTP dependency — an iterative parser over the wire format), and **fails open on forwarding but loud on auditing** (an unframable stream is passed through and flagged `sftp.parse_error`, never silently dropped)
- [x] **Policy `PAM_SSH_SFTP`** ∈ {`allow`, `readonly`, `deny`} (fail-loud on a typo): **`allow`** (default) forwards but now **audits every operation** (`sftp.session`, `sftp.open` with read/write intent, `sftp.modify` for remove/rename/mkdir/rmdir/setstat/symlink); **`readonly`** refuses any mutating op by **synthesizing an `SSH_FXP_STATUS` permission-denied** to the client (`sftp.blocked`) so the target is never contacted, while reads still flow; **`deny`** refuses the subsystem outright (`sftp.denied`). A non-sftp subsystem is audited `session.subsystem` (refused under `deny`)
- [x] **Tests**: a **real minimal SFTP client + server** exchange genuine v3 packets through the proxy — `allow` forwards an upload to the target and audits it, `readonly` returns permission-denied for both an upload and a delete (neither reaches the target) yet a download still succeeds, `deny` refuses the subsystem — plus the config-enum mapping. New audit vocab `sftp.*` + `session.subsystem`; no schema change
- Deferred (documented): **per-file content recording** of transferred bytes — still open; the **path allow/deny list** has since shipped in Phase 51 (`PAM_SSH_SFTP_DENY_FILE`). **Read-only enforcement for interactive shell file tools** (`scp`/shell redirection) stays inherent to the exec-path-only limit of command control

## Phase 33 — RDP clipboard control ✅

The RDP counterpart to Phase 32. The in-portal RDP viewer relies on [Apache Guacamole](https://guacamole.apache.org/doc/gug/configuring-guacamole.html#rdp), which leaves the **clipboard bridge on in both directions by default** — so an operator could copy data out of (or paste into) a recorded RDP session with no gate and no audit, and Guacamole's drive-redirection could mount a client folder as a file channel. A PAM must be able to restrict the session clipboard (a standard PSM control).

- [x] **`PAM_RDP_CLIPBOARD` policy** (`internal/api/rdp_handlers.go` `rdpClipboardParams`, threaded into the guacd `connect` handshake via `rdpExtra`): **`allow`** (default) leaves copy + paste on; **`readonly`** blocks paste *into* the target (`disable-paste=true` — no clipboard injection) while copy-out stays on, mirroring SFTP read-only; **`deny`** turns the clipboard off both ways (`disable-copy=true`+`disable-paste=true`). Every mode also forces **`enable-drive=false`**, so no file can be exfiltrated through a mounted client drive regardless of guacd's defaults
- [x] **Audited**: the chosen mode rides the `rdp.connect` audit detail (`clipboard:<mode>`); config `PAM_RDP_CLIPBOARD` ∈ {allow, readonly, deny} is validated fail-loud
- [x] **Tests**: the mode→parameter mapping (allow/readonly/deny/unset), that drive redirection is always disabled, and an **end-to-end** assertion that a `deny` policy reaches a fake guacd as `disable-copy=true`/`disable-paste=true`/`enable-drive=false` in the advertised arg order. No new audit vocab, no schema change
- Deferred (documented): **clipboard-content auditing** has since shipped in Phase 50 (`PAM_RDP_CLIPBOARD_AUDIT`, modes `off|meta|full`), and the **per-target** clipboard override shipped 2026-07-29 (`Target.RDPClipboard[Audit]`, strictest-of-global-and-target)

## Phase 34 — HA live-session kill-switch ✅

Closes an HA **correctness** gap. The live-session registry is per-replica — each pod holds the cancel funcs for the sessions it hosts — so a kill issued to one pod could not terminate a session pinned to another. That silently broke the kill-switch, the revoke cascade, vendor offboarding and the analytics auto-response in any multi-replica deployment. (The periodic-job scheduler already had leader election via a Postgres advisory lock; this is the session-registry half.)

- [x] **Cross-replica kill bus** (`internal/session/killbus.go` — `KillBus`, `KillSelector`): a kill published on any replica is delivered to every replica's subscriber, which applies it to its own registry. `Registry.Kill`/`KillByActor`/`KillByActorTarget` broadcast; a private `killLocal*` variant applies an inbound kill **without re-publishing**, so it can't loop
- [x] **Store transport**: Postgres **`LISTEN`/`NOTIFY`** (`pgstore/killbus.go` — a hijacked dedicated connection that reconnects on failure) and an **in-process fan-out hub** for the memory store (`memstore/killbus.go`), so the demo and unit tests drive the same registry code the HA path does. New store methods `PublishSessionKill`/`SubscribeSessionKills`
- [x] **API**: `DELETE /api/sessions/{id}` returns **202 Accepted** when the kill is broadcast to the cluster (the session is not on this replica) vs **204** when killed locally; `main` calls `Registry.StartKillBus(ctx, store)` at startup
- [x] **Tests**: two registries sharing one store prove a kill on "replica B" terminates a session on "replica A" (by id, by actor, by actor+target); a store-contract round-trip exercises pgstore's real `NOTIFY` in CI
- Deferred (documented): **cross-replica live monitoring** — the SSE watch stream is still served from the pod hosting the session (fanning session *bytes* across replicas is a heavier pub/sub than a kill signal). Session **inventory** listing also stays per-replica. The security-critical action — termination — is now cluster-wide

## Phase 35 — Audit→SIEM push forwarding ✅

pamv1 could already *alert* on a specific event (`internal/alert`: webhook/syslog/email) and *export* the trail on demand (OCSF at `GET /api/audit/ocsf`), but it could not **continuously stream the whole audit trail** to a SIEM the way a commercial PAM feeds Splunk/QRadar/Sentinel. This closes that.

- [x] **Continuous forwarder** (`internal/auditfwd`): tails `audit_events` from a **durable cursor** — the last-forwarded id, persisted as a setting — and emits each event as an **RFC 5424 syslog** message (PRI 110 = the log-audit facility) or an **ArcSight CEF** record, to a UDP or TCP collector. New store read `AuditSince(afterID, limit)`
- [x] **Spool-and-retry**: the cursor advances only *after* an event is written to the collector, so a dropped connection re-sends from the last success on the next tick — no silent loss. On first enable it starts from the current head (it does not replay the entire history into the SIEM)
- [x] **HA-safe**: the forward pass runs under the Postgres **leader lock**, so N replicas don't each emit duplicate SIEM records
- [x] **Injection-safe**: actor/action/detail are CR/LF-stripped (and CEF metacharacters escaped), so a directory-supplied name carrying a newline can't forge an extra syslog record
- [x] **Config** `PAM_AUDIT_FORWARD_ADDR` (host:port; empty = off), `PAM_AUDIT_FORWARD_PROTO` (udp/tcp), `PAM_AUDIT_FORWARD_FORMAT` (rfc5424/cef), `PAM_AUDIT_FORWARD_INTERVAL_SEC` — validated fail-loud
- [x] **Tests**: a real in-process UDP syslog sink receives forwarded RFC 5424 and CEF messages; the cursor advances (a second flush sends nothing); a "restarted" forwarder resumes from the persisted cursor without replaying; the store contract covers `AuditSince` (pgstore in CI)
- Deferred (documented): **LEEF** (QRadar) as a third format (trivial to add on the same seam), and **TLS syslog** (RFC 5425) for the transport — both since shipped in Phase 47

## Phase 36 — Retention / pruning ✅

Two data stores grew without bound: **session recordings** on disk and **audit rows** in Postgres. A PAM needs a defined retention policy (NIS2/SOC 2/DORA all expect one) and an operator needs the disk/table not to grow forever. This adds a scheduled, leader-locked sweep — without ever silently weakening the audit trail's tamper-evidence.

- [x] **Recording retention** (`internal/maint.PruneRecordings`): deletes `.cast`/`.winrm.log` files older than `PAM_RECORDING_RETENTION_DAYS`, **preserving dotfiles** — notably the `.chain` head that anchors the recordings' hash chain — and any non-recording file, so a sweep can never corrupt the chain or touch an unrelated file. Audited `recording.pruned`
- [x] **Audit-row retention** (`store.PruneAuditBefore`): deletes audit events older than `PAM_AUDIT_RETENTION_DAYS`, audited `audit.pruned` — **but only when the tamper-evident HMAC chain is off**. Deleting the chain head breaks `VerifyAuditChain` (it requires the first row's `prev_hash` to be nil), so with the chain on the worker **skips audit pruning with a loud warning** rather than trade integrity for space (the correct pattern there is a WORM export + manual re-anchor)
- [x] **Leader-locked worker** (`RunRetentionWorker`, `PAM_RETENTION_INTERVAL_HOURS`, default 24) — one replica sweeps per tick, like the other background jobs. Both windows default to `0` = keep forever, validated fail-loud
- [x] **Tests**: `PruneRecordings` (old removed; the `.chain` head, recent recordings, and non-recording files preserved; a dotfile-`.cast` is never touched); the store contract (`PruneAuditBefore` — a future cutoff prunes all, a past cutoff prunes none); the worker pass (recordings pruned + audited, audit pruned when unchained, and **skipped when chained**)
- Deferred (documented): **archive-to-WORM before delete** has since shipped in Phase 49 (`PAM_RETENTION_ARCHIVE_DIR`), which also resolved the chain-on case by archiving without pruning

## Phase 37 — Gap-analysis pass: child-resource scoping + bearer auth failures ✅

A read-only sweep over the route→capability map, the child-resource handlers and
the four authentication surfaces, comparing them against each other. Two
authorization gaps and one missing control; the same sweep's phase-sized findings
are recorded in [docs/SECURITY-GAPS.md](docs/SECURITY-GAPS.md#open-findings-from-the-2026-07-26-sweep)
rather than half-built here.

- [x] **Child-resource deletes are scoped to their parent**: `deleteSafeMember`
  authorized the safe in the path and then deleted by the member's *global* id, so a
  delegated `can_manage` member of one safe could remove a member of **any** safe —
  delegated administration as a lever to strip access anywhere. It now requires the
  member to belong to that safe. `deleteDependency` ignored its `{id}` credential
  entirely; it is now scoped the same way, and the audit detail names the owning
  credential. Both now follow `deleteTargetGrant`/`deleteAppSecretGrant`, which
  already scoped correctly
- [x] **Failed bearer credentials are throttled and audited on every surface**: only
  the login endpoints and the two session proxies did this, so a wrong `X-API-Key`,
  agent key or **application** key was merely logged — token guessing against
  `/api/*`, `/v1/tool-calls` and `/v1/app-secrets` (the last vends plaintext secrets
  to machines) was an unthrottled online oracle, and invisible to the risk engine and
  the SIEM forwarder because neither sees anything that is not in the audit trail. One
  `Server.authFailed` now covers all three: a per-source-IP **failure** limiter (its own
  window on the existing `PAM_AUTH_RATE_LIMIT` budget — separate from the login
  limiter, since a legitimate API client makes many *successful* calls a minute)
  answers 429 past the budget, and each admitted failure appends `api.auth_failed`
  (`surface:api|agent|app`, method, path, client IP — never the presented credential).
  The append is skipped once throttled, so a flood cannot amplify into the audit trail
- [x] **Tests**: a cross-safe member delete refused with the victim surviving (plus a
  positive control that in-safe deletion still works), a cross-credential dependency
  delete refused, and 401×N-then-429 with exactly N events audited on each of the
  three bearer surfaces. No schema change, no new environment variable
- Deferred (documented in SECURITY-GAPS.md, each phase-sized) — **all seven have
  since shipped, in Phases 38–46**: recording encryption at rest (41), shared
  custody of the SSH host/CA keys in HA (42), command control on the REST WinRM
  and broker exec paths (38), the WinRM endpoint's absence from the session
  registry (40), `CapApprove` for step-up and certification decisions (39), the
  console-parity drift since Phase 25 (43, 45), and update endpoints +
  pagination (44)

## Phase 38 — Command control on every command path ✅

The first of the [open findings](docs/SECURITY-GAPS.md#open-findings-from-the-2026-07-26-sweep)
Phase 37 recorded. Phase 16 described command control as covering "every path
where a discrete command is visible" — but the guard lived inside
`internal/proxy` and was consulted only there. Two paths that *do* see a discrete
command never asked it: `POST /api/targets/{id}/winrm` (any `CapConnect` holder)
and the agent broker's `ssh_exec` / `winrm_exec` tools. A pattern that stopped an
operator's `ssh target "cmd"` did nothing to an AI agent — the least-trusted
actor on the system.

- [x] **One guard, one policy** (`internal/cmdguard`): the denylist moves out of
  `internal/proxy` into its own package (`Guard`, `New`, `ParseDeny`, `Blocked`,
  `Size` — same logic, its tests moved with it). `main` compiles
  `PAM_COMMAND_DENY_FILE` **once** and hands the same guard to the SSH proxy, the
  PostgreSQL proxy and the API server, so the two can't drift apart
- [x] **Enforced on the API's command paths**: `Server.guardCommand` is called from
  `execWinRM` — the single chokepoint the REST endpoint and the broker's
  `winrm_exec` share — and from `sshExecTool.Execute`. Both run **before** the
  just-in-time decrypt, so a refused command never causes a secret to exist in
  memory. A block is audited `command.blocked` with the matched pattern (the same
  vocabulary the proxies use, so one query finds every refusal) and answers HTTP
  403 to a human / a failed tool call to an agent
- [x] **Tests**: a blocked WinRM run is refused with 403, never reaches the fake
  runner, never decrypts the credential, and is audited — while an unmatched
  command still runs; the same for an agent calling `winrm_exec`; and a blocked
  `ssh_exec` against an unroutable host returns the *policy refusal* rather than a
  dial error, which proves the guard runs before the dial
- Unchanged by design: an interactive SSH shell streams a raw PTY that is never
  parsed, so command control still must not be read as a containment boundary —
  use read-only observer sessions or restrict shell access where that guarantee is
  needed. No schema change, no new environment variable

## Phase 39 — Approver capability for the two decision points ✅

Findings **E** and **F** of the [2026-07-26 sweep](docs/SECURITY-GAPS.md#open-findings-from-the-2026-07-26-sweep).
Two endpoints that *authorize* something were gated on the wrong capability — one
too permissive, one too narrow — and `CapApprove` already existed for exactly this
kind of decision.

- [x] **Step-up release needs `CapApprove`** (was `CapReadAudit`): pausing a flagged
  PostgreSQL statement for a supervisor is only meaningful if releasing it is a
  privileged act. As shipped in Phase 30 the role defined as *read-only* — `auditor`
  — could run it. `GET /api/sessions/stepups` **keeps** `CapReadAudit`, the same gate
  as the live stream, so a watching supervisor still sees every paused statement;
  only `POST /api/sessions/{id}/stepup` moved
- [x] **Certification decisions need `CapApprove`** (was `CapManageUsers`): recertifying
  access is a review, not user administration. Requiring the user-management
  capability meant the principal who grants access was the only one who could attest
  to it — the opposite of what a SOX / ISO 27001 review is for. An `approver` can now
  certify or revoke items **without** holding any access-granting capability; creating
  and closing a campaign stay `CapManageUsers`
- [x] **Tests**: an auditor lists paused step-ups but is refused the release (403) while
  an approver's decision resolves the waiting statement; an approver decides a campaign
  item (204) yet still cannot create a campaign, and neither an auditor nor a plain user
  can decide
- Honest limit (documented): this **delegates** the review — it does not by itself stop
  an admin, who also holds `CapApprove`, from certifying a grant they created. Per-item
  four-eyes needs the grant's creator recorded, which is a schema change and stays a
  follow-on. No new capability, no schema change, no new environment variable

## Phase 40 — Every brokered execution is a supervised session ✅

Finding **D** of the [2026-07-26 sweep](docs/SECURITY-GAPS.md#open-findings-from-the-2026-07-26-sweep),
plus the same hole one layer over. The SSH proxy, the PostgreSQL proxy and the RDP
tunnel all registered their sessions; `POST /api/targets/{id}/winrm` did not — and
neither did the agent broker's `winrm_exec` / `ssh_exec` tools. A run on those paths
was invisible to `GET /api/sessions`, could not be killed, was not counted against
`PAM_MAX_SESSIONS_PER_USER` / `_TOTAL`, and was out of reach of the analytics
auto-response and the vendor sweeper — both of which terminate **by actor**. An
agent's long-running command was the least supervisable execution in the system.

- [x] **One helper, every path** (`Server.superviseSession`): enforces the
  concurrent-session caps, registers the session, and returns a context a kill
  cancels plus a release func. The REST WinRM endpoint and both broker exec tools
  now go through it, so an AI agent's run is exactly as listable, countable and
  killable as an operator's
- [x] **Capped before the decrypt**: the cap check runs *before* the just-in-time
  decryption on every path (`ssh_exec`'s decrypt was moved after it), so a run
  refused by the limit never causes a secret to exist in memory
- [x] **A kill is honest about itself**: cancelling the run returns HTTP **503
  session terminated** and audits `session.killed`, rather than blaming the target
  for an upstream failure
- [x] **Tests**: an in-flight WinRM run parks in a blocking runner and is observed
  in `GET /api/sessions` as protocol `winrm`; a second concurrent run is refused
  **429** by the per-actor cap; `DELETE /api/sessions/{id}` terminates the run, which
  returns 503; the registry empties afterwards; and the runner still received the
  vaulted secret, so JIT injection is unchanged
- No schema change, no new environment variable — `PAM_MAX_SESSIONS_*` simply now
  means what it says on every path

## Phase 41 — Session recordings encrypted at rest ✅

Finding **A** of the [2026-07-26 sweep](docs/SECURITY-GAPS.md#open-findings-from-the-2026-07-26-sweep),
and the oldest real asymmetry in the project: pamv1 wrapped every credential in
envelope encryption under a pluggable KEK, then wrote the **recording of the
session** — which holds whatever the operator typed and saw, including a secret
typed by hand, a query result, or a file listed on screen — in the clear, protected
by file permissions alone. Anyone with volume, backup or snapshot access could read
it. This closes that, opt-in via `PAM_RECORDING_ENCRYPT`.

- [x] **A sealed stream, not a sealed blob** (`internal/recording`): a header line
  carrying the vault-wrapped per-recording data key, then AES-256-GCM chunks. It is
  chunked because a session can be killed, hit its size cap or die with the process
  — a partial file must still decrypt up to its last complete chunk rather than be
  lost whole. Each chunk's additional authenticated data binds it to the
  recording's name **and its index**, so chunks cannot be reordered, dropped from
  the middle, or spliced in from another recording
- [x] **Same root of trust as the vault**: the data key is wrapped by the configured
  KEK — local, HashiCorp Vault Transit, AWS KMS or a PKCS#11 HSM — so a deployment
  whose master key never leaves an HSM now protects its recordings that way too
- [x] **Tamper evidence unchanged**: the SHA-256 is deliberately taken over the bytes
  that land **on disk**, so the audited hash, the `X-PAM-Recording-Audited` verdict
  and the recording hash chain keep describing the stored artifact with no change to
  any of them. The WinRM transcript path was hashing its *plaintext* — identical
  while unencrypted, silently wrong once sealed — and now hashes the stored bytes
- [x] **Fails closed, never silently clear**: a KEK that cannot wrap the data key
  returns an error and leaves no file behind, so a session can be refused rather
  than recorded in the open by accident
- [x] **Detected per file, not by config**: playback sniffs the magic prefix, so
  turning encryption on does not orphan the recordings a deployment already had —
  they keep replaying through the same audited path
- [x] **Tests**: the package (round-trip with the plaintext provably absent from the
  file, a flipped bit caught as an authentication failure with the intact prefix
  still recoverable, a chunk refused under another recording's name, a truncated
  file readable up to its last complete chunk, a loud KEK failure); the proxy
  recorder (a session's `.cast` is sealed on disk and `Close` reports the hash of
  the stored bytes); and end to end (a recorded WinRM run leaks neither its command
  nor its output nor the target to disk, yet replays through the API with
  `X-PAM-Recording-Audited: true`, while a pre-encryption recording still replays)
- Honest limit, documented: the **file name** still carries the target and the actor.
  The content is sealed; that metadata is not. Naming recordings by opaque id is a
  follow-on, and would cost the operator the ability to find a session by eye

## Phase 42 — Shared custody of the host and CA keys (HA) ✅

Finding **B** of the 2026-07-26 sweep. `proxy.LoadOrCreateHostKey` and
`sshca.LoadOrCreate` persisted to a **local file**, while the Helm PVC is
`ReadWriteOnce`, defaults to `emptyDir`, and `replicaCount` is freely configurable.
Nothing stopped a second replica starting — and when it did, each pod generated
its own keys, so:

- operators got a **host-key-changed warning** depending on which pod answered,
  which is indistinguishable from a MITM and trains people to click through it;
- a certificate minted on one pod was **not trusted** by targets configured with
  another pod's `TrustedUserCAKeys`, and `GET /api/ca/ssh` returned a different key
  per pod;
- the operator-certificate challenge — an HMAC keyed off the CA private key, and
  documented as "HA-safe across replicas" — **failed across pods**, which was only
  true if that key were shared.

- [x] **Atomic claim in the store** (migration `0022` `key_material`,
  `store.EnsureKeyMaterial`): `INSERT … ON CONFLICT DO NOTHING` followed by a read
  back, so N replicas starting at the same instant all converge on **one** key —
  exactly one wins, the rest adopt. The memory store takes the same lock-guarded
  path, and the contract test races six claimants against live PostgreSQL in CI
- [x] **Sealed, and bound to its name** (`internal/keycustody`): the database holds
  the vault envelope, never usable key material, with
  `store.KeyMaterialAAD(name)` so a host-key envelope cannot be substituted for the
  CA key
- [x] **An existing file seeds custody, it does not lose to it**: a single node that
  upgrades keeps serving the key it already had — that key becomes the shared one —
  and later replicas adopt it and mirror it back to their own path, so tooling that
  reads the file keeps working. Adoption is logged, because it is the moment a
  deployment stops having two host keys
- [x] **A key that cannot be unwrapped is fatal**, never a silent regeneration:
  quietly rotating the host key or the CA would break every target that pinned them,
  so the error names the likely cause (a changed master key) and startup stops
- [x] **Tests**: eight concurrent replicas converge on one key; an existing file
  seeds custody and a second replica adopts + mirrors it; the store holds no usable
  key material and the envelope refuses the other key's AAD; an unwrappable key is
  fatal and returns no key; a failing generator propagates
- Still open (recorded, not closed by this): **recordings remain per-pod**, so
  `GET /api/recordings` lists what the serving replica holds — shared recording
  storage is an operator decision (RWX volume or object storage) rather than a code
  fix, and cross-replica live monitoring stays the Phase 34 follow-on

## Phase 43 — Console: the two human decision points ✅

The first half of finding **G**. Phase 25 brought the 5250 console to full backend
parity and Phases 27–42 drifted away from it again — nine capabilities ended up
with no screen. Two of them are not like the others: **a parked agent tool call**
and **a paused SQL statement** are *human decisions with a deadline*. A step-up is
refused when `PAM_DB_STEPUP_TTL_SEC` runs out; a parked call blocks an agent until
someone answers. Leaving those two on curl-only was the part that actually cost
something, so they ship first rather than waiting for a nine-screen phase.

- [x] **Approve AI-agent tool calls** (menu 20, `approve`): the parked call, the
  agent, who it acts **on behalf of**, the rule that gated it — and its
  **arguments**, because the arguments are what the policy matched on and an
  approver who cannot see them is not really deciding. Option 5 approves (the
  broker then executes server-side with a just-in-time credential the agent never
  sees), option 6 rejects. The screen states the two rules that will refuse a
  decision: four-eyes (you cannot approve a call by an agent you own) and the
  rule's approver groups. With the broker disabled the routes are absent, so a 404
  shows a hint instead of an error — the pattern the application-secrets screen
  already uses
- [x] **In-session step-up decisions** (menu 21, `read_audit` to watch, `approve`
  to decide — the Phase 39 split): the paused statement, its session and actor.
  Option 5 allows it, option 6 refuses it, and the screen says plainly that these
  entries **expire** and that the session survives either way, because that is the
  one thing a supervisor needs to know and cannot infer from a list
- [x] **Verified against a running server**, the way Phase 25 was: a real agent key
  minted, a real `list_targets` call parked by a `require_approval` rule, the exact
  `GET /v1/approvals` the screen issues returning every field it renders, the exact
  decision `POST` returning 200, and the list emptying afterwards — plus the
  step-up list and the broker-disabled 404. `node --check` on the embedded script
- Portal-only: no new routes, no schema, no new environment variable

## Phase 44 — Editable objects and bounded lists ✅

*Finding H*, the last data-shaped gap from the 2026-07-26 sweep. The `Store`
interface had create and delete but **no update** for targets, safes, users or
vendors — fixing a target's port meant delete + recreate, which cascades away
its credentials, grants, dependencies and safe assignment, a data-loss footgun
in ordinary administration — and no top-level list read was bounded, an
authenticated memory-exhaustion vector on a large inventory.

- [x] **Edit in place**: `UpdateTarget` (name/host/port/os/protocol/approval —
  never the safe assignment, which stays `AssignTargetSafe`'s), `UpdateSafe`,
  `UpdateUserRole` and `UpdateVendorOrg` store methods (`ErrNotFound` /
  `ErrConflict` on a name collision), surfaced as `PUT /api/targets/{id}`,
  `/api/safes/{id}` (CapManageTargets), `/api/users/{id}` and
  `/api/vendors/{id}` (CapManageUsers) with **create-equivalent validation and
  authorization** — the user edit re-runs the privilege-escalation guard, so a
  delegated user-admin cannot promote past their own capabilities, and the
  user's token **survives** a role change (no re-mint). Audited
  `target.update` / `safe.update` / `user.update` / `vendor.update`
- [x] **Deliberately not editable**: grants and safe members stay
  create + delete — they have no dependents to lose, and two audited events
  (deleted, created) are a clearer trail than one mutated row. Usernames are
  immutable (the subject key referenced by grants, sessions and vendor rows)
- [x] **Bounded lists**: `ListTargets`, `ListCredentials`, `ListUsers`,
  `ListSafes`, `ListCheckouts`, `ListAccessRequests` and `ListVendors` take a
  shared `(limit, afterID)` window — id-ascending, strictly after the cursor;
  `limit<=0` (uncapped) is reserved for in-process sweeps. Every list endpoint
  parses `?limit=&after=` clamped 1..500, default 100, the way `listAudit`
  already was — a hostile `?limit=0` falls back to the default, never to
  "return everything"
- [x] **Console**: the subfiles drain the cursor page by page (`apiAll`), and
  Work with Targets / Safes / Users gain **2=Change** screens
  (`PAMCHGTGT`/`PAMCHGSAF`/`PAMCHGUSR`); the target forms now offer
  `postgres`, which the console had drifted from
- [x] **Proven in the store contract** (both stores; live PostgreSQL in CI):
  update round-trips, conflict/absence sentinels, safe-assignment preservation
  across an edit, window semantics — plus five API tests (dependents survive a
  target edit; a promoted token immediately carries the new role; pagination
  clamps)
- No schema change, no new environment variable

## Phase 45 — The remaining console screens ✅

The other half of finding **G**, closing it. Seven capabilities had a backend,
tests and docs but no screen — an operator drove them with curl. All seven are
now first-class 5250 screens, keyboard-first, in the single embedded page:

- [x] **Work with vendors & contract grants** (menus 22): register (token shown
  once), 2=Change org, 4=Offboard (shows how many sessions were cut),
  5=contract grants — add a grant (target picker, account, `datetime-local`
  window), 5=Approve (`CapApprove`; the screen states four-eyes: a customer,
  never the vendor) and 6=Revoke — and 6=Evidence export, a real download
  carrying the `X-PAM-Export-SHA256` digest into the message line
- [x] **Work with operator SSH certificates** (menu 23): every issued cert with
  serial, key id, principal, operator, validity and revocation state;
  4=Revoke; F9 downloads the KRL; the CA fingerprint heads the screen, or an
  amber "ZSP not enabled" hint when there is no CA — certs stay revocable
  either way
- [x] **Identity blast radius** (menu 24): paste a normalized graph (the
  placeholder is a valid example; the edge-kind vocabulary is on screen),
  optional source/target focus, and the findings render with severity, path
  (`from ─kind:via→ to`) and the cut-this-edge remediation hint
- [x] **Work with login sessions** (menu 25): active password/SSO logins with
  role(s), scope and expiry; 4=Revoke reports both logins revoked and live
  target sessions cut
- [x] **Work with AI-agent keys** (menu 26): mint (token shown once, owner
  mandatory — the accountable human), revoke; broker-disabled shows the
  configuration hint, the app-secrets pattern
- [x] **Credential dependencies**: option **9=Dependents** on Work with
  Credentials — list, declare (kind/name/host/port) and delete the consumers
  updated on rotation
- [x] **Audit chain + OCSF on the audit screen**: F6=Verify chain (INTACT /
  BROKEN AT id banner), F7=Signed head (a screen rendering the ed25519
  checkpoint: last id, head HMAC, signature, public key, and why to archive
  it), F10=OCSF export (download); F9 CSV stays
- [x] **One deliberate deviation from "no new routes"**: `GET
  /api/ca/ssh/certs` (CapReadInventory, `?limit=` clamped 1..500) — the store
  could list issued certificates but no route exposed them, so the serials a
  revocation needs were invisible outside the audit trail. Metadata only,
  never key material. Test: `api.TestListSSHCertsEndpoint`
- [x] **Verified against a running server** (broker + audit chain + checkpoint
  signing enabled): vendor registered → grant added → approved → evidence
  digest header; agent minted → listed → revoked (204); blast analyze
  returning a real `high` finding with path + remediation; audit verify
  `ok:true`, head with every rendered field, OCSF 200; the CA-disabled hint;
  `node --check` on the embedded script

## Phase 46 — Per-item four-eyes on certification ✅

The Phase 39 follow-on, closing the last separation-of-duties gap (finding
*F*'s honest limit): delegating the review to `CapApprove` did not stop the
principal who **granted** access from **certifying** it themselves — the
reviewer and the grantor could be the same person, which is what an access
review exists to prevent.

- [x] **The grant's creator is recorded**: `target_grants.created_by` and
  `safe_members.created_by` (migration `0023`), stamped from the authenticated
  actor on every create. Rows that predate the migration keep an empty creator
  — four-eyes cannot be enforced retroactively on grants whose creator was
  never recorded, and pretending otherwise would block every legacy review
- [x] **Snapshotted into the campaign item** (`campaign_items.granted_by`), so
  the decision check needs no live lookup and still works after the underlying
  grant is deleted; the item's human-readable detail says *"granted by X"*, so
  the reviewer sees who they are attesting for — in the console too, with no
  screen change
- [x] **Enforced at the decision**: certifying an item whose recorded creator
  is the deciding actor is refused 403 (*"four-eyes: you cannot certify access
  you granted yourself"*) and audited `certification.decision_denied`
  (`reason:four-eyes`). **Self-revoke stays allowed** — removing your own
  grant only reduces access
- [x] Proven in the store contract (creator round-trips through grants, safe
  members and campaign items — live PostgreSQL in CI) and
  `api.TestCertificationFourEyes` (self-certify 403 + audit; another approver
  204; self-revoke 204; legacy item 204), and verified against a running
  server
- One additive migration; no new routes, no new environment variable

## Phase 47 — LEEF format + TLS transport for the SIEM forwarder ✅

The two follow-ons Phase 35 deferred on its own seam, closing them: the audit
trail — the evidence — previously left the building only as cleartext UDP/TCP.

- [x] **LEEF 2.0** (`PAM_AUDIT_FORWARD_FORMAT=leef`): IBM QRadar's native
  format — `LEEF:2.0|pamv1|<tag>|1|<action>|` + tab-separated attributes
  (`devTime` in epoch ms like CEF's `rt`, `usrName`, `msg`). Header fields
  escape `|`; attribute values strip tabs and CR/LF, so an actor name or
  detail carrying the delimiter cannot forge an attribute or a record —
  proven by an injection test
- [x] **Syslog over TLS** (`PAM_AUDIT_FORWARD_PROTO=tls`, RFC 5425):
  certificate verification is **always on** — there is deliberately no
  insecure switch, because the audit trail must never stream to an
  unauthenticated endpoint. `PAM_AUDIT_FORWARD_CA` pins the collector's CA
  (PEM bundle; empty = system roots), rejected fail-loud at startup if
  unreadable or empty, and refused outright on a non-tls proto (a typo must
  not silently drop the pinning). The syslog format uses the
  **octet-counted framing** RFC 5425 §4.3 requires; CEF and LEEF are not
  syslog and stay newline-delimited on every transport
- [x] **Proven against real sockets**: an in-process TLS collector with a
  self-signed certificate — pinned via the CA bundle — receives
  octet-counted syslog; an untrusted collector (different key) is refused,
  **no audit bytes reach it**, and the cursor stays put so the spooled event
  is delivered on the next flush through a trusted collector; plus the LEEF
  wire format and its injection resistance
- One new environment variable (`PAM_AUDIT_FORWARD_CA`); no new routes, no
  schema change

## Phase 48 — Opaque recording file names ✅

Phase 41's documented limit, closed: the recording *content* was sealed, but
the file **name** — `<unixnano>_<target>_<actor>` — still told anyone with
volume, backup or snapshot access who reached which system and when. That is
the metadata half of the same exposure.

- [x] **`PAM_RECORDING_OPAQUE_NAMES`** names a recording
  `<unixnano>_<8 random hex>`. One helper (`recording.Title`) serves all four
  recorders — interactive SSH, SSH exec, PostgreSQL and WinRM transcripts —
  and lives in `internal/recording`, which `proxy` and `api` both already
  import, so this adds no package edge
- [x] **The timestamp prefix survives** in both modes, because retention
  pruning and the newest-first listing key off the name alone; 500 names
  minted in the same nanosecond are all distinct. A `crypto/rand` failure
  falls back to the descriptive name rather than a predictable one — a
  collision would overwrite another session's evidence, which is worse than
  the metadata it hides
- [x] **The metadata moves to where reading it is already gated**:
  `GET /api/recordings` (read_audit, like replay) resolves each file's target
  and actor from the audited `session.record` / `winrm.run` event, matching on
  base name so the SSH proxy's full-path detail and the DB/WinRM bare-name
  detail both work. Best-effort — an audit read failure degrades the listing
  to names only, and an unaudited file lists empty rather than guessed. The
  console gains Target and Actor columns, so the operator experience is
  unchanged
- Opt-in, one new environment variable; no schema change, no new routes

## Phase 49 — Archive to WORM before pruning ✅

Phase 36's follow-on. Retention could *delete* aged audit rows and recordings;
deleting evidence with nowhere for it to go is only acceptable once it has been
written somewhere durable first.

- [x] **`PAM_RETENTION_ARCHIVE_DIR`** turns pruning into **archive-then-prune**.
  Aged audit rows are exported as **JSON Lines** (one complete event per line —
  a truncated array is unparseable, a truncated JSONL file still yields every
  line before the break) and aged recordings are **moved** into the archive
  rather than destroyed, preserving the artifact and its hash-chain membership
- [x] **Fail-closed, which is the point**: the prune runs **only if the archive
  succeeded**. A full, unwritable or misconfigured archive costs disk space,
  never the audit trail — proven by a test that points the archive at a
  non-directory and asserts nothing was pruned and no `audit.pruned` was emitted
- [x] **Write-once by construction**: every archived file is created with
  `O_EXCL` and mode `0400`, so a re-run cannot silently replace an artifact and
  a careless process cannot append to one; a partial write is removed rather
  than left looking complete. pamv1 cannot make storage immutable from inside
  the process — that is the operator's WORM mount — but it never overwrites
- [x] **Verifiable after the fact**: each export appends **`audit.archived`**
  with the file name, event count and the **SHA-256 of the bytes on disk**, so
  an auditor re-hashes the archive and proves it is the trail that was removed.
  Recordings get `recording.archived`
- [x] **The chained trail is now served rather than skipped**: with the HMAC
  chain on, the scheduled WORM export still runs — only the delete stays a
  manual re-anchor (deleting the chain head would break `VerifyAuditChain`), and
  the log says exactly that instead of just refusing
- Opt-in, one new environment variable; no schema change, no new routes

## Phase 50 — Clipboard auditing on the RDP bridge ✅

Phase 33's follow-on. The clipboard bridge could already be **gated** (`allow` /
`readonly` / `deny`) but never **observed**, so an allowed clipboard was an
unwatched channel into and out of a privileged desktop.

- [x] **`PAM_RDP_CLIPBOARD_AUDIT`** = `off` (default) · `meta` · `full`. The
  tunnel already frames the Guacamole stream one instruction at a time, so the
  watcher is an observer on that seam: a transfer is `clipboard` (open, with a
  mimetype) → `blob`* (base64) → `end`, and reassembling those three yields the
  direction (**out** = copied from the target, **in** = pasted into it),
  mimetype, byte count and SHA-256 — audited as **`rdp.clipboard`**
- [x] **Content is NOT recorded by default, deliberately.** A privileged
  desktop's clipboard routinely carries a password the operator just copied out
  of the vault; writing that into a trail every auditor can read would create
  the exposure this system exists to prevent. `meta` proves what moved and
  matches two transfers by digest; `full` adds the content, truncated, and is a
  separate opt-in. A typo in the setting fails startup rather than silently
  choosing either extreme
- [x] **Observation only — never interference.** Every frame is forwarded
  byte-for-byte whatever the watcher decides; a dropped frame would corrupt the
  display, and blocking the clipboard is Phase 33's gate, not this one's.
  Malformed frames are forwarded unread
- [x] **Bounded**: a transfer buffers at most 1 MiB (and a `full` audit records
  at most 4 KiB), flagged `truncated:true` rather than dropped, so a huge or
  hostile clipboard cannot exhaust memory or flood the trail. Newlines in
  recorded content are flattened, so one transfer stays one audit line and
  cannot forge a second
- [x] New `guacd.Decode` (the exact inverse of `Encode`, length-prefix
  authoritative so a value containing `,` or `;` round-trips) with tests
  covering both, plus watcher tests for each mode, non-clipboard streams,
  independent directions, and truncation

## Phase 51 — SFTP path policy ✅

Phase 32's follow-on. SFTP could be `allow` / `readonly` / `deny` — a policy
about the *operation*, never about **which file**. So a read-only session could
still download `/etc/shadow` or a private key, which is the transfer that
actually matters.

- [x] **`PAM_SSH_SFTP_DENY_FILE`** — regular expressions, one per line, `#`
  comments — matched against every SFTP path. It **reuses the `cmdguard`
  engine**, so one regex-denylist semantic (and one file format, and one
  fail-loud-on-a-bad-pattern path) covers commands and file paths alike; no
  second policy engine
- [x] **Denied in every mode, reads included.** A path you deny that an
  operator can still download is not denied at all — so the check runs before
  the read/write distinction, in `allow` mode too, and the target is never
  told the path
- [x] **A rename cannot launder a path**: both the source and destination are
  checked, so neither moving a denied file to an innocuous name nor moving an
  allowed file onto a denied one gets through
- [x] The refusal is a proper SFTP `SSH_FX_PERMISSION_DENIED` (the client sees
  an error instead of hanging) and audits `sftp.blocked` with
  `reason:path-denied` **and the pattern that matched**, so an operator can see
  *why* without guessing which rule fired
- [x] Proven against the Phase 32 harness — a real SFTP conversation, no mocks:
  a denied download refused in `allow` mode, a denied upload, a denied delete,
  both rename directions, an allowed path still working in the same session,
  and nothing bearing a denied path ever reaching the target

## Phase 52 — Close the command-injection findings ✅

The first and most serious pair from the post-beta sweep (findings **W** and
**X**), fixed together because they are the same mistake in two places: a value
an operator supplies being interpolated into a Windows command line that a shell
then parses.

- [x] **Credential dependencies can no longer carry a command.** The dependency
  `Name` and `Host` are checked against an **allowlist** — letters, digits,
  spaces and a few separators for the name, a hostname/IP shape for the host.
  An allowlist rather than a blocklist because the legitimate inputs are
  narrow and knowable, while the set of characters a shell acts on is not:
  the previous code had no check at all, and its sibling in `rotate` had a
  blocklist that missed `&`
- [x] **Checked twice, on purpose.** Validation runs at creation *and* again in
  `dependencyCommand`, the last point before the value reaches a command line —
  so a row written before this rule existed, or inserted straight into the
  database, still cannot execute. An unusable name is audited and skipped, which
  means the consumer silently does not get its password updated: the safe
  failure, and a visible one
- [x] **The path obeys command control now.** `propagateDependencies` calls
  `guardCommand` before executing, so Phase 38's "one policy on every path where
  a discrete command is visible" finally includes this one. It was the last
  WinRM execution path that bypassed it
- [x] **The `net user` username is allowlisted too** (`DOMAIN\user`,
  `user@realm`, `gMSA$` all still work), replacing a blocklist that caught
  space, quote, CR and LF but not `&`, `|`, `^`, `<`, `>`, `(`, `)` or `%` — and
  in `cmd.exe`, `&` needs no surrounding space to chain a second command
- [x] **Proven by tests that assert nothing executes**: eight break-out shapes
  and four hostile hosts refused at the API, thirteen hostile usernames refused
  in the rotator *without reaching the runner*, and eleven legitimate
  real-world names still accepted — because a security fix that breaks
  `My App Pool` or `Contoso.Web` would just be reverted
- Honest remaining limit, recorded rather than quietly closed: the dependency
  host is validated in *shape* but is still not required to be a target in the
  inventory, since a consumer may legitimately run on a host that is not itself
  a PAM target

## Phase 52a — Make `-rotate-kek` whole again ✅

Findings **I** and **J**: the documented key-rotation procedure did not survive
the features built after it. A rotation is the operation you run *because*
something went wrong, so it failing quietly is the worst possible time for it.

- [x] **Key custody is re-wrapped.** `Store` gains `ListKeyMaterial` and
  `UpdateKeyMaterial`, and `RotateVaultKEK` re-wraps the SSH proxy host key and
  the Zero Standing Privilege CA key alongside credentials, MFA secrets and
  settings. Without this the tool reported success and the **next start-up
  failed**, because key custody deliberately treats an unwrappable envelope as
  fatal — and the intuitive recovery, deleting those rows, regenerates the host
  key and the CA, which is indistinguishable from a machine-in-the-middle
- [x] **The omission is now hard to repeat.** The function's doc comment carries
  the exhaustive four-item list of what must be re-wrapped, because this bug was
  omission rather than faulty logic, and a comment that enumerates is the only
  thing that catches the fifth kind when someone adds it
- [x] **Both stores are held to it.** The contract suite covers list ordering,
  re-wrap read-back and `ErrNotFound` on an unclaimed name, so `memstore` and
  `pgstore` cannot drift apart on the new methods the way they did on list
  limits (finding AF, closed in Phase 52b)
- [x] **Verified the test fails without the fix**, rather than assuming it would
- [x] **Sealed recordings: warned, not re-wrapped — and this is the right
  answer.** A recording's data key is wrapped inside the *file*, and the SHA-256
  of those exact bytes is what the audit trail and the hash chain hold.
  Re-wrapping would make every archived recording read as *never audited*,
  destroying the tamper evidence sealing exists to provide, to avoid keeping a
  key. So `-rotate-kek` counts sealed recordings and warns, naming the KEK they
  still need, and the admin guide states the retention rule plainly
- [x] Directory reads use `os.OpenInRoot`, so "this cannot traverse" is enforced
  by the API rather than asserted in a comment

## Phase 52b — Fix the two same-day regressions, and the gap that hid them ✅

Findings **AF**, **AG** and **AL**. Both regressions shipped the same day as the
sweep that found them, and both **passed their tests** — which is the part worth
dwelling on. Neither was caught by review; both were caught by asking what the
tests were actually proving.

- [x] **`ListAudit` limit semantics are now part of the contract.** `pgstore`
  collapsed any limit above 500 back to the 100 default, so asking for *more*
  returned dramatically *fewer*, while `memstore` returned everything it had. A
  caller asking for 2000 got 2000 in tests and 100 in production. The rule now
  lives on the interface and is shared through `store.ClampAuditLimit`: a
  non-positive limit means the default page, and an oversized one is **capped,
  not reduced**
- [x] **The recordings listing no longer depends on a magic number.**
  `recordingOwners` takes the set of names the listing actually needs and stops
  as soon as they are all resolved, so the work is bounded by what is being
  displayed rather than by a constant someone guessed
- [x] **Certificate serials survive the trip to the console.**
  `SSHCert.Serial` carries the `,string` tag, so it serializes as a JSON string
  exactly as `/sign` already did. Seeded from a nanosecond clock, a real serial
  is ~1.7×10¹⁸ — above 2⁵³, where JavaScript stops representing integers
  exactly — so the console received a rounded value, and a rounded serial
  revokes nothing: the published KRL names a certificate that does not exist
  while the real one stays valid until it expires
- [x] **The tests are rebuilt to fail against the old code**, which is the actual
  lesson. The certificate test used serials 101 and 102 — small enough that the
  defect could not appear — and now uses two realistic values differing only in
  their last digit. The audit-limit contract needed more than 100 events and a
  mid-sized limit before broken and correct implementations differ at all. Both
  were verified by reintroducing the bug and watching them fail
- [x] **The root cause is closed, not just the symptoms** (finding AL): an
  interface with two implementations is only as good as the contract test
  holding them together, so limit semantics now live there instead of being
  re-invented on each side

## Phase 52c — Make the authorization gates consistent ✅

Findings **K**, **L**, **M**, **T**, **Y** and **Z**. Every one is the same class
of defect: a gate that all comparable paths enforce, missing on exactly one. That
is how this kind of bug survives review — a reviewer looking at the handler sees
nothing wrong, because the problem is only visible next to its siblings.

- [x] **The RDP tunnel stops being the exception.** It resolves its own principal
  (a browser cannot set headers on a WebSocket handshake), and that is how it
  drifted: a bare 401 instead of `authFailed`. It was the one bearer surface
  where token guessing was neither throttled nor recorded — invisible to the risk
  engine and the SIEM forwarder — while identical guessing against `/api/*` was
  both. Authorization denials are audited now too
- [x] **No self-approval on in-session step-up.** The pause exists to put a
  *second* person in the loop; self-approval turns it into a confirmation prompt
  and leaves an audit entry that reads like independent review — worse than no
  gate, because it manufactures false assurance. Checked under the same lock as
  the claim, reported distinctly from "nothing pending" so the status is honest,
  and a refused attempt leaves the step-up **still pending** for a real
  supervisor
- [x] **The broker's credential tools obey the approval gate.** With
  `require_approval` set, a human needed an approved request while an agent
  permitted `reveal_credential` got the plaintext at any hour, outside every
  window. The least-trusted actor in the system had the weakest gate
- [x] **Vendor creation applies the escalation guard.** Its role is fixed at
  `user` rather than caller-chosen, which is exactly why the check was missed —
  but a fixed role is not a safe one
- [x] **`PAM_REQUIRE_RECORDING` finally means what its name says.** It enforced
  recording for the SSH, WinRM and PostgreSQL proxies but not for the two paths
  that reach a target through the HTTP server — the in-portal RDP viewer and the
  REST WinRM endpoint. An operator who set it believed every session was
  recorded, and the two newest ways to reach a machine were the two it did not
  cover. Both checks run *before* anything happens on the target
- [x] **Audit fails closed where it already did elsewhere**: a privileged desktop
  that leaves no record of being opened is what this system exists to prevent,
  and a WinRM result the audit trail never accounted for is now withheld rather
  than returned
- [x] Tests assert the *consequence*, not just the status code: that guacd was
  never contacted, that the command never ran, that the refusal reached the audit
  trail, and that the legitimate path still works

## Phase 52d — Lifetimes, deadlines and fail-open defaults ✅

Findings **N**, **O**, **P**, **Q**, **AA** and **AB**. This batch is about
things that were *almost* right: a guard that fired on one of its two triggers, a
timeout that applied to the wrong kind of response, a sweep that was never
scheduled, a failure that was reported as success.

- [x] **A killed command actually stops now.** `execGuard` closed the SSH session
  only on a deadline, never on cancellation — so an `ssh_exec` killed from the
  console reported "session terminated" to the operator while the command kept
  running on the target. The exclusion was deliberate (the stop func cancelled
  the same context, so treating cancellation as a trigger would have closed every
  successful run) but it disabled the case that matters most. Now three separate
  signals — a timer, the caller's context, and normal completion
- [x] **Live monitoring is no longer cut off after 30 seconds.** The root cause
  was not the timeout: it was the access-log wrapper having no `Unwrap`, so
  `http.ResponseController` could not reach the connection to clear the deadline.
  Adding `Unwrap` generalises the hand-written `Flush` and `Hijack` passthroughs
  that had each been added after something broke
- [x] **Verified in both directions rather than assumed.** An SSE stream under a
  1s write timeout delivers one frame and dies; clearing the deadline delivers
  all of them. And the WebSocket path — the RDP viewer — turns out **not** to
  inherit the deadline, so it needed no change and did not get a speculative one
- [x] **Neither proxy will hold a slot for an unauthenticated peer.** Both now
  bound the handshake (30 seconds here, raised to 120 in Phase 52g once it was
  measured cutting off a human typing the API key) and clear the deadline once
  authenticated,
  since an established session is legitimately idle while an operator reads
- [x] **Expired login sessions are collected.** Expiry was enforced by filtering
  reads, never by deleting rows, so every login, break-glass activation and
  60-second RDP token left a row behind forever. The GC loop also used to start
  *only* when a broker policy file was configured — so the ordinary deployment
  had no garbage collection at all
- [x] **A failed kill says so.** The cluster broadcast error was discarded and
  the outcome computed from "is a bus configured", so an operator cutting off a
  live privileged session on another replica was told it worked
- [x] **A policy file that yields nothing is fatal, not silently inert.** Setting
  `PAM_COMMAND_DENY_FILE` (or the SFTP/step-up equivalents) is a statement of
  intent; an unmounted ConfigMap used to disable the control while startup logged
  it as enabled. `ParseDeny` also no longer runs a `bufio.Scanner`, whose 64 KiB
  token limit silently discarded every pattern after one long line — with its
  `Err()` unchecked, a half-loaded policy looked exactly like a loaded one

## Phase 52e — Audit-trail integrity, archiving, and two concurrency bugs ✅

The last nine findings from the post-beta sweep (**R**, **S**, **AC**, **AD**,
**AE**, **AH**, **AI**, **AJ**, **AK**).

- [x] **The audit trail stops accepting unauthenticated, unbounded input.** Both
  proxies log without appending on the throttled branch — the failures *before*
  the throttle are the signal, and one row per attempt under a flood makes the
  system of record the amplifier, which bites hardest with the HMAC chain on
  because those rows are then deliberately never pruned. Client-supplied paths,
  patterns and request paths are quoted and bounded, so a filename of
  `x reason:allowed op:read` can no longer read as three legitimate fields
- [x] **SSE framing escapes CR as well as LF.** Server-Sent Events treats both as
  end-of-line, and the data being escaped is deliberately CRLF-bearing — so a
  supervisor's view of a live session could be split into frames the session
  never produced
- [x] **The OIDC JWKS and discovery reads are bounded**, matching the token
  endpoint eight lines away
- [x] **Archiving no longer duplicates the whole trail every tick.** With the
  chain enabled the aged rows are never pruned, so exporting everything older
  than a moving cutoff rewrote all of history under a new name each pass, into
  storage that is immutable and usually billed. It now archives only the delta,
  with the high-water mark read from the audit trail itself — the fact was
  already recorded there, and a mark kept elsewhere could disagree with the
  archives that exist
- [x] **One stuck recording no longer wedges archiving forever.** An interrupted
  move (copy succeeded, remove failed) is now finished rather than treated as a
  collision, a real collision is still refused, and the sweep continues past a
  failure instead of stopping — with names sorted and timestamp-led, stopping
  blocked every later recording permanently
- [x] **A data race on the operator's SSH channel is closed.** Phase 51's path
  denylist made refusals possible in the default mode, so the inspector's status
  packet could interleave with target output mid-response. The test asserts the
  property that matters — every payload arrives *whole* — not just the absence
  of a crash
- [x] **Batched Guacamole instructions can no longer evade clipboard auditing.**
  The protocol has no one-instruction-per-message rule and the bridge forwards
  whole messages, so a leading `nop` used to carry the clipboard and blob
  instructions past inspection unexamined
- [x] **A certification revoke cuts the user's live sessions**, as the equivalent
  grant-delete route already did. A campaign whose purpose is deciding someone
  should no longer have access was removing the grant and leaving them connected
- [x] **MFA recovery codes carry 120 bits instead of 50.** They are a full
  second-factor bypass, valid until used, stored as an unsalted SHA-256 — so they
  are attacked offline from a backup, where rate limiting cannot reach. Plain
  SHA-256 stays, and the reasoning is in the code: precomputation needs a small
  input space, and the fix for a generated secret is to stop generating it small

## Phase 52f — Make the archive high-water mark robust ✅

Reviewing Phase 52e's own change surfaced a weakness in it, which is the more
interesting half of this phase.

- [x] **The archive high-water mark can no longer be lost.** Phase 52e stopped
  the archiver re-exporting the entire aged trail every tick by starting from the
  newest `audit.archived` event — but it *found* that marker by scanning a page
  of recent audit events. On a busy deployment the marker falls off the end of
  any fixed window, and once lost the archiver re-exports history that is already
  archived: the very duplication the delta logic was added to stop, just less
  often and considerably harder to notice
- [x] **`Store.LatestAuditByAction`** — a targeted lookup bounded by `LIMIT 1`
  rather than by a page size that can miss the row, implemented in both backends
  and held by the contract suite, returning `(nil, nil)` when there is no such
  event. It runs from periodic maintenance rather than a request path, so an
  index scan on id descending is an acceptable cost — and a wrong answer here is
  worse than a slow one
- [x] **The guides caught up with Phase 52e's two format changes**: audit details
  now quote client-supplied paths and patterns, and recovery codes are four
  groups of six rather than two of five (codes already issued keep working, since
  only their hashes are stored and the lookup hashes whatever is typed —
  verified, not assumed)
- [x] The admin guide also records that `PAM_REQUIRE_RECORDING` now covers the
  RDP viewer and the REST WinRM endpoint, so a deployment that sets it without a
  recording path will refuse those sessions rather than run them unrecorded, and
  that an unusable deny file is now fatal at startup

## Phase 52g — Fix what the review of the fixes found ✅

Thirty findings across six phases is itself a change large enough to warrant
review, so the merged work was re-reviewed against one question — *what did these
commits break?* — with an explicit instruction to hunt for **tests that cannot
fail**. It found six things, all reproduced, all fixed here. Two are worth
knowing about even in summary:

- [x] **The dependency allowlist rejected `$`, which Windows requires.** A named
  SQL Server instance registers `MSSQL$SQLEXPRESS` — the textbook
  credential-dependency case for a PAM. And it was retroactive and silent: the
  same check runs when the command is built, so an *existing* row would be
  skipped at rotation, changing the account's password on the target and leaving
  SQL Server holding a stale one until its next restart failed. The sibling
  allowlist for `net user`, added in the same commit, accepted `$` for gMSA
  accounts — the two disagreed about what a legal Windows name is
- [x] **The new handshake deadline cut off human password entry.** Thirty seconds
  covers the whole pre-authentication phase, which in the documented flow
  includes an operator typing or pasting the API key. Reproduced: a client taking
  32 seconds was dropped with no message and no audit event, which looks exactly
  like a broken server. Now 120s, matching OpenSSH's `LoginGraceTime`
- [x] **A new test could not fail.** `TestSyncWriterKeepsPayloadsWhole` passed
  with the mutex removed — its destination recorded each write as one block under
  its own lock, so every block was intact whether or not anything was serialized.
  Rewritten against a destination that copies in two halves with a scheduling
  point between them, and verified to fail without the mutex
- [x] The clipboard fix was incomplete (a frame completing several transfers
  audited only the last), the audit **actor** on a failed proxy auth was still
  unbounded, and the recordings listing read 5000 audit rows per console refresh
- [x] Every production function in the tree now carries a doc comment

The lesson from the untestable test generalises: last round's discipline was
"verify the test fails without the fix", and it was applied to tests written for
known bugs but not to one written for a race. A test asserting that nothing went
wrong is the easiest kind to write and the easiest to get wrong.

### The post-beta sweep (2026-07-27) — all thirty findings closed ✅

The second full read-only sweep found **thirty** issues, every one confirmed by
reading the code. All are now fixed, across phases 52–52e — with 52f and 52g
closing what reviewing those fixes then found. The detail of each fix lives in
**[docs/SECURITY-GAPS.md](docs/SECURITY-GAPS.md#the-2026-07-27-post-beta-sweep--all-30-findings-now-closed)**.

| Phase | What it closed |
|---|---|
| **52** | Command injection: credential dependencies (RCE) and the `net user` blocklist |
| **52a** | `-rotate-kek` re-wraps key custody; sealed recordings documented rather than broken |
| **52b** | The two same-day regressions, and the store-contract gap that hid one |
| **52c** | Six authorization gates that did not match their peers |
| **52d** | Lifetimes, deadlines and fail-open defaults |
| **52e** | Audit-trail integrity, archiving, and two concurrency bugs |
| **52f** | The archive high-water mark, made robust — found by reviewing 52e |
| **52g** | Six more, found by reviewing all of the above — including a test that could not fail |

Three things worth carrying forward:

- **Two findings were regressions introduced the same day, and both passed their
  tests.** One test used certificate serials small enough that the defect could
  not appear; the other used the in-memory store, which was the generous
  implementation. Where practical each fix's test was then verified to **fail
  against the old code**, not merely pass against the new
- **The obvious fix was sometimes the wrong one.** Re-wrapping sealed recordings
  during a KEK rotation would have destroyed the tamper evidence they exist to
  provide, so that is resolved as a documented retention rule plus a warning
- **One suspected finding was not one.** Verifying the write-timeout problem in
  both directions showed hijacked WebSockets do not inherit the server deadline,
  so the RDP viewer correctly got no change

## Phase 53 — SQL Server (TDS) session proxy ✅

The second database wire protocol, and the first new one since Phase 15. An
operator points `sqlcmd` (or any TDS client) at pamv1 with
`-U '<dbcred>@<target>'` and their PAM key as the password; the proxy runs the
same authorization gates as every other listener, injects the vaulted SQL login
just-in-time, and brokers the protocol with per-statement audit.

- [x] **`internal/tds`** — the protocol slice a broker needs, hand-rolled with **no new dependency**: packet framing (bounded reassembly; `RESETCONNECTION` preserved through re-framing, or connection pooling breaks silently), PRELOGIN, LOGIN7 parse + re-encode, the keyless password obfuscation, SQLBatch/RPC text extraction, ERROR/DONE refusal tokens, a login-response walker, and a **TLS-inside-TDS-packets handshake shim** (the flush-on-read handoff is where hand-rolled versions hang)
- [x] **`internal/proxy/mssqlproxy.go`** — a line-for-line sibling of `dbproxy.go`, so the two diff cleanly: anything that differs is the transport, never the policy. Same gate order (rate limit → resolve → MFA-enrollment → `CapConnect` → target/protocol → grants → approval consume → vendor window → session cap → **fail-closed audit** → JIT decrypt → dial), same recording, live hub, registry, step-up and post-session rotation
- [x] **JIT injection into the client's own LOGIN7**: username and password replaced, `fIntSecurity` cleared, everything else (hostname, appname, database, language, feature extensions, negotiated version and packet size) forwarded byte-identical — by **re-encoding**, since a credential of a different length shifts every offset and an in-place patch would corrupt the login
- [x] **Command control and audit see through `sp_executesql`** (by name and ProcID, plain and PLP): a procedure-name-only parser would leave every parameterised driver — which is to say every application — unaudited and unfiltered. An unrecoverable RPC degrades to an audited `[rpc <name>]` and is forwarded, the same call the PostgreSQL proxy makes for a fast-path function call
- [x] **Encryption stance**: whole-session TLS on both legs (`ENCRYPT_ON` when `PAM_TLS_CERT/KEY` are set, always requested upstream), `PAM_DB_UPSTREAM_CA`/`_TLS_VERIFY` fail-closed as on the PostgreSQL leg, and TDS's **login-packet-only mode is never selected** — it reverts to plaintext mid-stream, which is where silent-downgrade bugs live. MARS is disabled so requests stay parseable; integrated/Windows auth and TDS 8.0 strict encryption are refused with a clear message instead of a hang
- [x] **No new audit vocabulary**: `db.session.*`, `db.query`, `command.blocked` and `db.stepup_*` disambiguated by `via:mssql`, so OCSF export and threat analytics cover SQL Server sessions without a change
- [x] **Config + surface**: `PAM_MSSQL_ADDR` (default `off`, `off` sentinel case-insensitive like its siblings); protocol `mssql` in the API enum, the 5250 target screens, the session registry and discovery (port 1433); shared database TLS built once in `main` for both listeners
- [x] **Tests**: 15 codec tests pinned to **spec-derived byte literals** — not round-trips, because the fake upstream uses the same codec and a symmetric bug would round-trip happily through every end-to-end test — plus a real TLS-over-TDS handshake; and 13 proxy tests: the JIT proof against an upstream accepting **only** the vaulted secret, wrong-key refused before the upstream is touched, client login fields preserved, a blocked batch **and** a blocked `sp_executesql` (neither reaches the target, session survives), multi-packet reassembly, recording + require-recording, live monitoring, kill, wrong-protocol and enrollment-only refusals
- Deferred (documented): **interop against a real SQL Server is not verified** — no licensed instance in CI, catalogued in [EXTERNAL-INFRA-GAPS.md](docs/EXTERNAL-INFRA-GAPS.md) with the `mcr.microsoft.com/mssql/server` job that would close it. Also deferred: MySQL/Oracle (same pattern, new protocols), result-row redaction, and mid-session packet-size renegotiation

## Phase 54 — VNC connector ✅

The second graphical protocol, and the cheapest one the architecture ever
absorbed: guacd already speaks VNC, so the work was making pamv1's *gates* speak
it — without growing a second copy of them.

- [x] **One tunnel, two protocols.** `rdpTunnel` became `viewerTunnel(proto)` in `internal/api/viewer_handlers.go` (renamed from `rdp_handlers.go`), parameterised by a small `viewerProto` descriptor (name, label, default port, session scope, guacd extras). Every gate — token resolve, break-glass note, MFA-enrollment, `CapConnect`, target lookup, protocol match, protocol allowlist, effective grants, single-use approval consume, vendor contract window, session cap, JIT decrypt, require-recording, fail-closed start audit, registry, clipboard watcher — is executed **once, in one function**, for both. Duplicating them is how two paths that are supposed to be equivalent quietly stop being; Phase 52c was a whole pass fixing exactly that
- [x] **`vnc` is a first-class protocol**: API enum + 422 message, portal add/change `<select>`s, session registry, discovery (port 5900), and the protocol allowlist (`PAM_ALLOWED_PROTOCOLS=ssh,rdp` now excludes VNC as you would expect)
- [x] **In-portal viewer**: `POST /api/vnc-token` + `GET /api/targets/{id}/vnc`, rendered by the same vendored Guacamole client on the same overlay. The portal's option **7** now opens whichever viewer the target's protocol names — one key, two protocols
- [x] **Tunnel-scoped tokens**: `auth.SessionScopeVNC` joins `SessionScopeRDP` behind a new `auth.IsViewerScope`, which is what confers `TunnelOnly`. Routing the check through one function is deliberate — a scope added without it would hand out a **full API token in a query string**, and there is now a test that would catch it
- [x] **The clipboard gate covers VNC** (`disable-copy`/`disable-paste`, the same pair guacd accepts for both), including the per-target override from the Phase 33 follow-on, and **`enable-sftp` is forced off** — VNC's file-transfer channel, the analog of RDP drive redirection
- [x] **Fail closed when the gate cannot be applied.** guacd silently *drops* a parameter it did not advertise, so a guacd that cannot gate the clipboard would render an ungated desktop while the portal showed the policy in force. `guacd.Conn.Supports` exposes the advertised argument list and a non-permissive policy that cannot be applied now **refuses the session** (`vnc.refused … reason:clipboard-unenforceable`). The check protects RDP too
- [x] **Audit vocabulary**: `vnc.token`, `vnc.connect`, `vnc.end`, `vnc.refused`, `vnc.error`, `vnc.clipboard` — mirroring the RDP set, so the SIEM export and threat analytics need no change
- [x] **Tests**: end to end against a fake guacd advertising the **real** VNC argument list (from guacamole-server's `GUAC_VNC_CLIENT_ARGS`) — `select vnc`, the vaulted secret injected into guacd's handshake, `enable-sftp=false` on the wire; the clipboard policy reaching guacd; the fail-closed refusal when it cannot; and the tunnel-scoped-token property. Every existing RDP test passes unchanged, which is the point of the shared implementation
- [x] **A real desktop to look at**: `deploy/docker/docker-compose.vnc-demo.yml` + `vnc-target/` run TigerVNC + XFCE behind guacd, seeded as a `vnc` target — the VNC sibling of the RDP demo
- Deferred (documented): VNC has **no transport security and no server authentication**, and its password is DES-truncated to 8 characters — stated in [PROTOCOLS-AND-CRYPTO.md §3.5](docs/PROTOCOLS-AND-CRYPTO.md) rather than papered over; prefer RDP or SSH where the choice exists. Rendered pixels against every VNC server implementation remain unverified beyond the demo stack

## What is left ⬜

The canonical backlog. Both read-only security sweeps are closed — the
2026-07-26 one by phases 37–46, the 2026-07-27 post-beta one by phases 52–52g —
so nothing here is a known defect. It is the honest remainder, grouped by what it
would take to close, with each item recorded against the phase that deferred it.

#### 1. Blocking the beta claim — ✅ resolved 2026-07-28

The README defines beta as *feature-complete against the roadmap, self-audit
closed, exercised by tests, and deploys as code*. The fourth criterion was the
last to hold, and now does:

- **The release is cut.** `v0.10.0` was tagged on 2026-07-28 and `release.yml`
  ran for real for the first time: its own test job gated the tag, then the
  image was built and pushed as
  `ghcr.io/morandeirachema/pamv1:0.10.0` (digest
  `sha256:ab2a5fa5db27fae805f9096dfdf526497ddff4cc3774b33469ab108b98637b39`),
  cosign-signed keyless, with an SPDX SBOM attestation and SLSA build
  provenance, and a GitHub Release carrying the SBOM. The package is public —
  anonymous pull verified — so `kubectl apply`, `helm install` and the
  Terraform module resolve the pin they always carried. This also closed
  [SECURITY-GAPS finding 18](docs/SECURITY-GAPS.md), which had been
  deliberately reopened until a release existed.

#### 2. Test gaps

- ~~**`cmd/pam-server` is at 0% coverage**~~ — ✅ closed 2026-07-28.
  `cmd/pam-server/main_test.go` now drives the wiring layer the way a
  misconfigured deployment would: every fail-closed startup path reachable
  without external infrastructure (deny files, audit-chain keys, TLS
  requirements, identity backends, listener conflicts) triggered through the
  environment; a full boot of the real server — both proxies, audit chain, SSH
  CA, broker policy, background workers — health-checked live and shut down
  with a real SIGTERM; the utility flags proven end to end (`-split-key` shares
  actually reconstruct the key); and `-rotate-kek` proven against live
  PostgreSQL in the pgstore CI job (old KEK stops decrypting, new one starts).
  82.8% of the package's statements; the remainder is `main()`'s flag dispatch
  and `fatal()`, which call `os.Exit` and are one-line wrappers around what is
  tested.
- ~~**Four small, cheap ones**~~ — ✅ closed 2026-07-28, each against its
  existing fixture: the ITSM gate's unreachable-webhook path **denies** (fail
  closed — proven against a dead endpoint, plus the 2xx/non-2xx legs); the
  broker's 1024 parked-approval cap refuses the 1025th call terminally without
  evicting anyone; `guacd`'s handshake protocol-error branches (wrong opcode,
  EOF, oversized length, garbage, `ready` without a connection id) all surface
  as errors; and `oidc.Discover` resolves endpoints (trailing slash included)
  and errors on unreachable or malformed metadata.

#### 3. Feature follow-ons, in process

Buildable without external infrastructure, each deferred by the phase named.

- **Cross-replica live monitoring** (34) — the SSE watch stream and session
  *listing* are still served by the pod hosting the session. Termination is
  already cluster-wide; fanning session bytes is a heavier pub/sub than a kill
  signal.
- **Per-file SFTP content recording** (32) — operations are audited and paths are
  gatable; the file *bytes* are not captured.
- ~~**WinRM live streaming** (16)~~ — ✅ closed 2026-07-29. Every WinRM path now
  tees to the live-monitoring hub under its session id: the proxy's interactive
  shell (banner, prompt, command echo, output, refusals — the same bytes the
  recording sees), and the REST endpoint + broker `winrm_exec` through their
  shared chokepoint (`winrm>` command echo, output, blocked/error notices). A
  supervisor watches a WinRM session exactly as an SSH or PostgreSQL one.
- ~~**Per-target RDP clipboard override** (33)~~ — ✅ closed 2026-07-29. A
  target's `rdp_clipboard` / `rdp_clipboard_audit` fields (API + 5250 screens)
  tighten the globals for that one target; the **stricter** policy always wins
  (allow < readonly < deny; off < meta < full), so a high-sensitivity target can
  deny what the fleet allows and no target row can loosen a global deny. Proven
  end to end: a target `deny` under a global `allow` reaches guacd as
  `disable-copy`/`disable-paste=true`.
- **Safe-scoped policy** (17) — per-safe approval and dual control, plus a
  per-consumer management credential for dependent-account propagation (which
  currently connects as the rotated account).
- **Campaign depth** (19) — scheduled/recurring campaigns, safe- or owner-scoped
  campaigns, reviewer assignment and reminders.
- **Ticket gate depth** (20) — a first-class ServiceNow/Jira connector (the
  generic webhook ships) and gating the *connect* path on a live ticket lookup
  rather than validating at request time.
- **Vendor console screen** (29) — the API is complete; the 5250 screens are a
  follow-on, as they were for earlier phases.
- **Config depth** (12) — runtime secret refresh without a restart (sourcing is
  one-shot at boot) and a per-variable override map.
- ~~**KEK-wrap the broker audit keys** (13)~~ — ✅ closed 2026-07-28. The two
  variables are now optional: unset, each key is generated once and held under
  shared custody (KEK-sealed in `key_material`, converged on by every replica,
  re-wrapped by `-rotate-kek`), exactly like the SSH host/CA keys. An explicit
  env value still wins — that remains the signer-rotation path.
- **Analytics depth** (23) — peer-baseline and new-target novelty scoring (needs
  a longer history model), and step-up-MFA as an automated response.
- **Deploy examples** (14) — cloud-KMS recipients wired into the Helm chart, a
  Flux `Kustomization` example, and sealing the CloudNativePG app-secret. The
  SOPS README advertises a `helm secrets` flow with no example behind it.

#### 4. Repo furniture — ✅ closed 2026-07-28

- `CHANGELOG.md` (releases; the per-phase history stays here), `CONTRIBUTING.md`,
  `CODEOWNERS`, issue templates (with a private-security-report contact link)
  and a PR template carrying the living-docs checklist.
- `.github/dependabot.yml` — weekly gomod (grouped), github-actions and docker
  updates, so `govulncheck`'s gate has a delivery path for fixes.
- A `manifests` CI job: `helm lint`, a full chart render (defaults **and**
  everything-on, so gated templates are exercised), and `kubeconform` over the
  raw K8s manifests and both renders — a broken chart fails in CI, not at
  `apply` time. CRD instances (CNPG `Cluster`, `ServiceMonitor`) are skipped,
  not failed.
- Housekeeping: the eight remaining stale `phase-*` branches on the remote are
  deleted (each verified against its merged PR first).

#### 5. Infra-bound — not here

Anything needing external infrastructure or a paid account to build and verify
honestly stays in
**[docs/EXTERNAL-INFRA-GAPS.md](docs/EXTERNAL-INFRA-GAPS.md)** rather than being
faked: Kerberos bind and Kerberos WinRM (a KDC), serial connectors (RS-232
hardware), MySQL/Oracle and network-device connectors (SQL Server shipped in Phase 53, though its interop with a real server is unverified), live cloud-CIEM
ingestion and short-lived cloud-credential brokering, web/SaaS session proxying,
SPIRE workload attestation and RFC 8693 token exchange, ephemeral local accounts,
and the Tier-4 ecosystem items (a Terraform provider, Secrets-Hub sync-out,
SSH-key fleet discovery, thick-app components).

#### 6. Deliberate limits, not backlog

Recorded so they are not mistaken for unfinished work:

- **An interactive PTY is never parsed**, so command control and per-action
  step-up cover the exec, WinRM and SQL paths but not a raw shell. Use observer
  sessions or restrict shell access. This is the boundary, not a gap.
- **Numeric policy comparators do not apply to raw SQL** — statements are not
  structured arguments; in-session step-up covers that path instead.
- **Sealed recordings are not re-wrapped by `-rotate-kek`**, because rewriting
  them would invalidate the SHA-256 the audit trail attests to. Retain the old
  KEK for as long as you retain sealed recordings.
- **Operator certificates (28) deliberately bypass the proxy.** Authorization is
  enforced at issuance and certificates are revocable by serial, but the session
  is direct and unrecorded — keep the feature off, or the path off the OT
  firewall, if that is not what you want.

---

## Portal: keyboard-first navigation ✅

The 5250 console is now explicitly **keyboard-first** (the mouse is optional), matching the IBM-terminal heritage: focus lands on each screen's primary field after every render, **Esc** cancels/goes back (the twin of F12), **↑/↓** move between subfile option cells, Tab/Enter/F-keys work throughout, and a persistent hint documents the shortcuts. The look is unchanged — only keyboard affordances were added.

---

**Tier-2 (access-governance depth) is complete** — certification campaigns (19), the ITSM/ticketing gate (20), and richer approval workflows (21), now including one-time access (26). **Tier-3**: Zero Standing Privilege (22), privileged threat analytics (23) and the identity blast-radius / CIEM engine (31) are shipped — three of five; connector/plugin breadth and web/SaaS session proxying remain, along with *live* cloud-CIEM ingestion, all infra-bound. **Tier-4 is under way**: the application-secrets API (24) is shipped; a Terraform provider, Secrets-Hub sync-out, SSH-key fleet discovery, and thick-app components remain, each requiring external infrastructure or an account to build honestly (see [docs/EXTERNAL-INFRA-GAPS.md](docs/EXTERNAL-INFRA-GAPS.md)). The 5250 console has **full parity** with the backend (Phase 25) — every shipped capability is operable from the portal, keyboard-first — and the session-recording loop is closed end to end (Phase 26): record → watch live → replay later, hash-verified. See the [competitive-coverage section](README.md#coverage-vs-commercial-pam-cyberark-wallix-) for the full picture.

**What is next** is consolidated in [What is left](#what-is-left-) above: the
release that would complete the beta claim, the `cmd/pam-server` test gap, a
dozen in-process feature follow-ons, and the repo furniture — with the
infra-bound catalogue kept separately in
[docs/EXTERNAL-INFRA-GAPS.md](docs/EXTERNAL-INFRA-GAPS.md). The console is at
**full parity** — every shipped capability is operable from the portal,
keyboard-first.
