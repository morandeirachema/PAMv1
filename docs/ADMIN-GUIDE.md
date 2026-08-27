# PAMv1 — Administrator Guide

A complete, practical guide for **administrators**: deploy PAMv1, configure it,
onboard targets and credentials, manage users and roles, run the break-glass
procedure, and read the logs and audit trail.

> **Living document.** Kept in step with the product — update it whenever
> admin-facing behavior changes (config, deployment, management, logging). Add a
> row to the [change log](#12-change-log) with each update.
>
> Last updated: 2026-08-27 · Reflects: Phases 0–227 + the 2026-07 hardening passes — through the AI-agent access broker (13, completed in 27), the PostgreSQL database session proxy (15), live monitoring + command control (16), safes + dependent-account propagation (17), optional CyberArk Conjur secret sourcing (18), access certification campaigns (19), the ITSM/ticketing gate (20), richer approval workflows (21), Zero Standing Privilege via ephemeral SSH certificates (22, extended to operator-issued certs in 28), privileged threat analytics (23), the Conjur-style application-secrets API (24), console parity (25: 5250 screens for safes, campaigns, risk analytics, and a live session viewer), recording playback + one-time access (26), the third-party vendor access gate (29, §7), in-session step-up (30, §9.4), the identity blast-radius / CIEM engine (31, §9.8), SFTP and RDP clipboard control (32–33, with per-file SFTP content capture in 59), the cluster-wide kill-switch (34), audit→SIEM forwarding (35), retention (36), the SQL Server and VNC connectors (53–54), cluster-wide live monitoring (55), searchable session recordings (110), mandatory live supervision (112, §9.4b), a live NIS2 compliance report (114, §9.2b), live session-sharing (116, §9.4c), a per-user CIDR source-address allowlist (118, §7), recurring access requests + configurable password policy + checkout extension (120, §7 and §9.6c), suspend/resume for a live session (122, §9.4d) FIDO2/WebAuthn as a second MFA factor (124, alongside the existing TOTP section), selectable console color themes (126, keyboard-first, client-only — **F2** cycles green/amber/slate), authenticated post-login account discovery (128, returning to the original CyberArk/Wallix research backlog now that the Wallix-weighted plan is closed), and Zero Standing Privilege extended to PostgreSQL via ephemeral roles (129 — RDP has no equivalent, a confirmed guacd/FreeRDP protocol limitation; SQL Server deferred, needs a new TDS client-response reader), and an optional command allow-list narrowing every command-control path to a named set (131, §9.4), and device-aware access control — a live EDR-posture webhook plus an optional reverse-proxy client-certificate binding, both re-checked on every connect and every authenticated call (133, §7), and DoubleLock — a second, named-holder password additionally required to reveal or check out a credential, kept deliberately outside the KEK so `-rotate-kek` needs no special case for it (135, §6), and magic-link access-request approval plus session watermarking (137, §9.4e and §9.6d), and personal/private safes — a safe marked personal replaces `CanConnectTarget`'s unconditional admin bypass with a narrow, named `unlimited_vault_access` capability, loudly audited when used (139, §6), and same-target-only raw TCP port-forwarding — a client `ssh -L` request is admitted only to the connected target's own host, any port, closing what would otherwise be an SSRF pivot (141, §9.4), and ICAP-based scanning of SFTP transfers — a finalized upload/download is submitted whole to an AV/DLP gateway, detection only since the file has already reached its destination by the time a whole-object scan can complete (143, §9.4), and generic file-attachment secrets — a `file` secret type for license keys, cert bundles and short documents, size-capped before it is ever vaulted (145, §6), and browser-extension password autofill — a real Manifest V3 extension calling the existing reveal route with a narrowly-scoped token refused everywhere else (147, §6), and SCIM 2.0 push-based user provisioning — `/scim/v2/Users`, authenticated by a new non-human SCIM client key, deactivation that actually cuts the user's own local token, complementing the existing pull-based identity reconcile (149, §7) — and the AI-agent broker's own lifecycle and visibility work — an agent identity that can be suspended, expired or quarantined (159, §7a), and agent behaviour that is finally scored by the risk engine and reconstructible as a run (161, §7a and §9.7) — plus the hardening passes: an HMAC-chained audit trail with signed checkpoints (§9.2), revocation that terminates live sessions (§7), verified upstream-DB TLS, and per-IP auth throttling on every surface (§4). The console is keyboard-first. See the [ROADMAP](../ROADMAP.md).

> ⚠️ **Educational / pre-production.** PAMv1 is a learning project and is
> currently intended for **pre-production** use. It has not been security-audited.
> Do not guard real production credentials with it yet.

New here? If you want the **how-it-works mental model and a script-oriented
runbook** before this reference, start with the
[Sysadmin Guide](SYSADMIN-GUIDE.md). Otherwise read the [concepts](#1-concepts)
first, then jump to [deployment](#3-deployment). Operators/users should read the
[User Guide](USER-GUIDE.md). For the big picture see the
[high-level architecture](ARCHITECTURE-HIGH-LEVEL.md); for firewall rules see the
[ports & flow matrix](PORTS-AND-FLOWS.md); for navigation across all docs see the
[docs hub](README.md).

### Contents

1. [Concepts](#1-concepts) · 2. [Prerequisites](#2-prerequisites) · 3. [Deployment](#3-deployment) · 4. [Configuration reference](#4-configuration-reference) · 5. [Managing targets](#5-managing-targets) · 6. [Managing credentials](#6-managing-credentials) · 7. [Managing users & roles](#7-managing-users--roles) · 8. [Break-glass procedure](#8-break-glass-procedure) · 9. [Logs & audit](#9-logs--audit) · 10. [Security & hardening notes](#10-security--hardening-notes) · 11. [Troubleshooting](#11-troubleshooting) · 12. [Change log](#12-change-log)

---

## 1. Concepts

| Term | Meaning |
|---|---|
| **Vault** | Where privileged secrets are stored, always encrypted ([AES-256-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)). The plaintext is never written to the database. |
| **Target** | A machine or database you grant privileged access to — Linux (SSH), Windows (WinRM/RDP), and PostgreSQL today. |
| **Credential** | A privileged account (username + secret) on a target, stored in the vault. |
| **Session proxy** | A gateway operators connect *through* — SSH (`:2222`) and PostgreSQL (`:5433`) — that injects the credential **just-in-time (JIT)** into the connection to the target, so the operator never sees the secret. |
| **Role** | One of `admin`, `user`, `auditor`, `approver`, or a custom permission profile — determines what an identity may do. |
| **PAM token** | A per-user secret (shown once) that a user presents as `X-API-Key` or the SSH/DB proxy password. (The bootstrap `PAM_API_KEY` is the initial admin equivalent.) |
| **Break-glass** | An emergency key for admin access when the normal path is unavailable; every use is loudly audited. |
| **Audit trail** | An append-only record (in the database) of every sensitive action. Distinct from operational **logs** (stdout). |

```mermaid
flowchart LR
    OP["Operator"] -->|"HTTPS / SSH"| PAM["pam-server<br/>portal · API · proxy"]
    PAM -->|"encrypt / decrypt"| DB[("PostgreSQL<br/>vault + audit")]
    PAM -->|"JIT credential"| T["Target (SSH / WinRM / RDP / PostgreSQL)"]
```

---

## 2. Prerequisites

- [Go 1.26+](https://go.dev/dl/) (to build from source), or [Docker](https://docs.docker.com/) / [Kubernetes](https://kubernetes.io/) to run the image.
- A PostgreSQL 14+ database (16/17 recommended; bundled in docker-compose), or `memory` mode for a throwaway demo.
- `openssl` (to generate keys), an SSH client for operators.

Full run specs — ports, resource requests/limits, Docker/Kubernetes versions,
storage and sizing — are in **[REQUIREMENTS.md](REQUIREMENTS.md)**.

---

## 3. Deployment

### 3.1 Generate the secrets first

Every deployment needs a **master key** (encrypts the vault) and an **API key**
(the bootstrap admin identity). Optionally a **break-glass** hash.

```bash
go build ./cmd/pam-server

# Vault master key (32 bytes, url-safe base64) — losing this makes secrets unrecoverable
./pam-server -genkey                       # → PAM_MASTER_KEY

# Bootstrap admin API key (any strong random string)
openssl rand -hex 24                        # → PAM_API_KEY

# (optional) Break-glass: hash the sealed emergency key; store only the hash
echo -n "the-emergency-key" | ./pam-server -hashkey   # → PAM_BREAK_GLASS_KEY_HASH
```

### 3.2 Local demo (no database)

Fastest way to see it work; data is lost on restart.

```bash
export PAM_MASTER_KEY=$(./pam-server -genkey)
export PAM_API_KEY=$(openssl rand -hex 24)
export PAM_DATABASE_URL=memory
./pam-server
# Portal + API → http://localhost:8080   ·   SSH proxy → localhost:2222
```

### 3.3 docker-compose (recommended for pre-production)

Brings up a hardened PostgreSQL ([`scram-sha-256`](https://www.postgresql.org/docs/current/auth-password.html)) plus pam-server. The Docker/compose files live under `deploy/docker/`:

```bash
cd deploy/docker
cp .env.example .env
# edit .env: set PAM_MASTER_KEY, PAM_API_KEY, POSTGRES_PASSWORD (and optionally the break-glass hash)
docker compose up --build
docker compose logs -f pam        # follow pam-server logs
docker compose logs -f db         # PostgreSQL logs (connections are logged)
```

Host key and session recordings persist in the `pamdata` volume.

### 3.4 Kubernetes

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl -n pamv1 create secret generic pam-secrets \
  --from-literal=PAM_MASTER_KEY=... \
  --from-literal=PAM_API_KEY=... \
  --from-literal=PAM_BREAK_GLASS_KEY_HASH=... \
  --from-literal=PAM_DATABASE_URL='postgres://pam:...@postgres:5432/pam?sslmode=verify-full'
kubectl apply -f deploy/k8s/
kubectl -n pamv1 logs deploy/pam-server -f
```

The `create secret` above keeps the plaintext out of Git but only lives in the
cluster. For **GitOps**, seal the Secret manifest instead: Phase 14 ships a
[SOPS](https://github.com/getsops/sops)+[age](https://age-encryption.org/) flow
under [`deploy/k8s/sops/`](../deploy/k8s/sops/) — `apply.sh` streams
`sops --decrypt | kubectl apply -f -` (plaintext never touches disk) and only the
encrypted manifest is committed. See its [README](../deploy/k8s/sops/README.md)
for Flux/Argo/helm-secrets wiring.

Or, if you run **CyberArk Conjur**, PAMv1 can fetch its own bootstrap secrets
from it at startup instead (Phase 18) — set `PAM_CONJUR_URL` and pam-server pulls
`PAM_MASTER_KEY`/`PAM_API_KEY`/`PAM_DATABASE_URL`/… from Conjur, with a
Kubernetes projected-token (`authn-jwt`) so **no secret lives in Git at all**.
SOPS and Conjur both ship; SOPS stays the zero-dependency default. See
[`deploy/k8s/conjur/`](../deploy/k8s/conjur/).

**Rotating a bootstrap secret without a restart (Phase 78).** Set
`PAM_CONJUR_REFRESH_MIN` (minutes; `0`, the default, is off) and every replica
re-reads the *refreshable* secrets on that interval and adopts a change
immediately — audited `config.secret_refreshed`, which names the keys and never
the values. **Only two can be refreshed**, and this is worth knowing before you
rotate rather than after:

| Secret | Rotating it |
| --- | --- |
| `PAM_API_KEY` | picked up on the next tick — **if Conjur manages it**; see below |
| `PAM_BREAK_GLASS_KEY_HASH` | picked up on the next tick — **if Conjur manages it**; see below |
| `PAM_MASTER_KEY` | **restart, and not just a restart** — it is the KEK, so changing it does not rotate the vault, it makes every stored secret undecryptable. Use `pam-server -rotate-kek` offline, which re-wraps everything |
| `PAM_DATABASE_URL` | restart (it is bound into a live connection pool) |
| `PAM_BROKER_AUDIT_KEY` | restart — it keys the HMAC chain, so swapping it invalidates the history rather than re-keying it |
| `PAM_BROKER_AUDIT_SIGN_SEED` | restart, via `PAM_BROKER_AUDIT_SIGN_PREV`, which keeps the retired public half trusted so old checkpoints still verify |

The pinned secrets are **not read** on the refresh tick at all — pulling the KEK
across the network every few minutes to notice a change nothing can act on is
exposure bought for nothing. The startup log names both lists.

**Two conditions decide whether a rotation actually lands**, and the startup log
tells you both rather than making you find out by watching nothing happen:

1. **Conjur must manage the variable.** At startup the server asks Conjur which
   of the refreshable secrets it holds, and refreshes only those. If
   `pamv1/api-key` does not exist, the log says nothing will be refreshed.
2. **Enabling refresh means Conjur wins.** If a secret is set in the environment
   *and* managed in Conjur, refresh will overwrite the environment value — you
   get a warning naming the variable at startup. (Without refresh enabled, the
   explicit environment value still wins, as it always has.)

**Deleting a variable in Conjur is not a revocation.** Removing or emptying it
keeps the value the server is running with — a policy edit must never disable
break-glass — and logs a warning. To retire a key, set a new one.

A refresh that stops working is not silent: every failed pass logs at `Error`,
increments `pam_secret_refresh_failures_total`, and fires a
`config.secret_refresh_failed` alert.

If your Conjur policy does not follow the `<prefix>/<name>` convention, map each
variable explicitly with
`PAM_CONJUR_VARS=PAM_API_KEY=prod/keys/api,PAM_DATABASE_URL=prod/db/url`. An
unknown name stops the server rather than being ignored, so a typo cannot look
like the feature not working.

The deployment runs non-root, read-only root filesystem, all capabilities
dropped, under the restricted [Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/). Recordings and the host key live on a writable `/data` volume. Readiness is gated on `/readyz` (DB reachable), liveness on `/healthz`.

**Network segmentation.** `deploy/k8s/networkpolicy.yaml` is a default-deny
`NetworkPolicy`: it allows ingress only on the app ports (8080/2222) and egress
only to DNS, the PostgreSQL backend, and your target networks — so no other pod
can reach the vault and the vault can't egress to the public internet. **Scope
the `from`/`ipBlock` rules to your environment before applying** (the defaults use
the RFC-1918 private ranges). In Helm it is a gated template — enable with
`--set networkPolicy.enabled=true` and set `networkPolicy.egressTargetCIDRs`.

Or with **Helm** (`deploy/helm/pamv1`) — configurable replicas, a PVC option, a
Prometheus `ServiceMonitor`, and the same hardened pod security context:

```bash
helm install pamv1 deploy/helm/pamv1 \
  --set secret.data.PAM_MASTER_KEY=... \
  --set secret.data.PAM_API_KEY=... \
  --set secret.data.PAM_DATABASE_URL='postgres://pam:...@postgres:5432/pam?sslmode=verify-full' \
  --set metrics.serviceMonitor.enabled=true
```

For production, set `secret.existingSecret` and manage PAM_* with an external
secret manager (Vault / External Secrets Operator) rather than chart values.

**Highly-available PostgreSQL.** For an in-cluster HA database, install the
[CloudNativePG](https://cloudnative-pg.io/) operator and apply
`deploy/k8s/postgres-cnpg.yaml` (a 3-instance cluster with automatic failover);
point `PAM_DATABASE_URL` at the `pamv1-pg-rw` service. For a cloud-managed
database, `deploy/terraform/cloud-postgres/` is an AWS RDS example (multi-AZ,
encrypted, TLS-forced) to adapt.

### 3.5 Terraform (IaC)

```bash
cd deploy/terraform
terraform init
terraform apply -var master_key=... -var api_key=... -var database_url=postgres://...
```

### 3.6 Put it behind TLS

Operators must reach the portal/API over **HTTPS** and the proxy over SSH only.
Terminate TLS at an ingress/load balancer in front of `:8080`, or set
`PAM_TLS_CERT`/`PAM_TLS_KEY` for native TLS; never expose the plain-HTTP port
off-host. To make plaintext a startup error rather than a footgun, set
`PAM_REQUIRE_HTTPS=true` (refuses to start without native TLS). When TLS is
terminated by a trusted reverse proxy, leave `PAM_REQUIRE_HTTPS` off and set
`PAM_TRUSTED_PROXY_HOPS` so per-IP auth throttling reads the real client IP from
`X-Forwarded-For`. Use `sslmode=verify-full` and, later, LDAPS for AD.

---

## 4. Configuration reference

All configuration is environment variables (12-factor). Full descriptions in
[.env.example](../deploy/docker/.env.example) and the [low-level architecture doc](ARCHITECTURE-LOW-LEVEL.md#4-configuration-env-pam_).

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PAM_KEK_PROVIDER` | | `local` | Vault key backend: `local` (dev/test), `vault-transit`, `aws-kms`, or `pkcs11` (HSM). |
| `PAM_CONJUR_URL` (+ `PAM_CONJUR_*`) | | (off) | Source bootstrap `PAM_*` secrets from CyberArk Conjur at startup (Phase 18); see [deploy/k8s/conjur](../deploy/k8s/conjur/). |
| `PAM_MASTER_KEY` | local only | — | Local KEK key (`-genkey`). **Back it up securely.** Dev/test only. |
| `PAM_KEK_TRANSIT_ADDR` / `_TOKEN` / `_KEY` | transit only | — | HashiCorp Vault Transit KEK (production). |
| `PAM_KEK_AWS_KEY_ID` / `_AWS_REGION` | aws-kms only | — | AWS KMS KEK (production). |
| `PAM_KEK_PKCS11_MODULE` / `_PIN` / `_KEY_LABEL` / `_TOKEN_LABEL` | pkcs11 only | — | On-prem HSM KEK — needs the `pkcs11`-tagged build (`deploy/docker/Dockerfile.pkcs11`). |
| `PAM_API_KEY` | ✅ | — | Bootstrap admin key (X-API-Key / SSH password). **Must be ≥16 chars** on a real database (rejected at startup otherwise). |
| `PAM_ALLOW_WEAK_API_KEY` | | `false` | Override the 16-char `PAM_API_KEY` floor (demos only; the `memory` store is already exempt). |
| `PAM_DATABASE_URL` | ✅ | — | `postgres://…` (use `sslmode=verify-full`) or `memory` for demo. |
| `PAM_BREAK_GLASS_KEY_HASH` | | (off) | Hex SHA-256 of the sealed emergency key. |
| `PAM_LISTEN_ADDR` | | `:8080` | HTTP portal/API bind. |
| `PAM_PORTAL_URL` | | `/` | Where the OIDC callback redirects the browser after a successful login (the session token rides the URL fragment), and — since Phase 116 — the base URL an **external** session-share invite's emailed link and QR code are built from. Must be an absolute `http://`/`https://` URL for external invites to be creatable at all (the default `/` does not qualify); set it whenever the portal is served from another origin than the callback. |
| `PAM_REQUIRE_HTTPS` | | `false` | Refuse to start over plaintext HTTP unless native TLS (`PAM_TLS_CERT/KEY`) is set. Leave off only behind a trusted TLS-terminating proxy. |
| `PAM_TRUSTED_PROXY_HOPS` | | `0` | Number of trusted reverse-proxy hops; makes the auth rate limiter read the real client IP from `X-Forwarded-For` (0 = key on RemoteAddr, spoof-proof). |
| `PAM_SSH_ADDR` | | `:2222` | SSH proxy bind; `off` disables the proxy. |
| `PAM_PROXY_WINRM` | | `false` | Let `ssh <cred>@<winrm-target>@pam` open an interactive **command loop** against a Windows target — each line runs as one WinRM command with a JIT credential, recorded like an SSH session. It is a command loop, not a stateful PowerShell (no working directory or variables across lines). See §5. |
| `PAM_PROXY_AUTH_RATE_LIMIT` | | `10` | Failed-auth attempts per source IP per minute on the SSH (:2222) and DB (:5433) proxies (0 disables). Throttles guessing of `PAM_API_KEY`. |
| `PAM_AUTH_RATE_LIMIT` | | `20` | Attempts per client IP per minute on the login endpoints, and — on its own window — **failed** bearer credentials (`X-API-Key`, agent key, application key) on the REST, broker and application-secrets surfaces (0 disables). Each admitted failure is audited `api.auth_failed`; once throttled the caller gets 429 and nothing further is written to the trail. |
| `PAM_MAX_SESSIONS_PER_USER` / `PAM_MAX_SESSIONS_TOTAL` | | `0` (∞) | Cap concurrent live proxied sessions per user and overall, checked before any secret is decrypted — bounds resource use from one (or a compromised) identity. Per-replica in HA. |
| `PAM_MAX_RECORDING_MB` | | `0` (∞) | Cap a single session recording's output (MB); a session that exceeds it is terminated (`session.record_limit`) rather than run unrecorded, so one runaway session can't fill the recording disk. |
| `PAM_DB_ADDR` | | `off` | PostgreSQL session-proxy bind (Phase 15), e.g. `:5433`; `off` disables it. |
| `PAM_MSSQL_ADDR` | | `off` | **SQL Server (TDS) session-proxy bind** (Phase 53), e.g. `:1433`; `off` disables it. Shares every database knob below — `PAM_REQUIRE_DB_CLIENT_TLS`, `PAM_DB_UPSTREAM_CA`/`_TLS_VERIFY`, command control, step-up, recording. |
| `PAM_DB_UPSTREAM_CA` | | (trust-any + warn) | PEM CA bundle to VERIFY the upstream PostgreSQL server certificate (fail-closed upstream TLS on the credential-bearing leg). |
| `PAM_DB_UPSTREAM_TLS_VERIFY` | | `false` | Verify the upstream PostgreSQL certificate against the system roots (alternative to `PAM_DB_UPSTREAM_CA`). |
| `PAM_REQUIRE_DB_CLIENT_TLS` | | `false` | Refuse to start the DB proxy without operator-leg TLS (so the PAM key is never sent to it in cleartext). |
| `PAM_COMMAND_DENY_FILE` | | (off) | Regex denylist file for command control (Phases 16, 38). One policy blocks matching commands on **every** path where a discrete command is visible: SSH `exec`, the WinRM command loop, PostgreSQL statements, `POST /api/targets/{id}/winrm`, and the agent broker's `ssh_exec`/`winrm_exec` tools. See §9.4. |
| `PAM_COMMAND_ALLOW_FILE` | | (off) | Regex **allow-list** file, same format as `PAM_COMMAND_DENY_FILE` (Phase 131) — once set, narrows every command-control path above to ONLY the listed commands; a deny-pattern match still wins even if the allow-list would also match. See §9.4. |
| `PAM_SSH_SFTP` | | `allow` | SFTP file-transfer policy (Phase 32): `allow` (forward + audit every op), `readonly` (refuse writes/deletes/renames), `deny` (refuse the subsystem). See §9.4. |
| `PAM_SSH_SFTP_DENY_FILE` | | (off) | **Path denylist for SFTP** (Phase 51): regexes, one per line (same format as `PAM_COMMAND_DENY_FILE`). A matching path is refused in **every** mode — downloads too — and on both sides of a rename; audited `sftp.blocked reason:path-denied` with the matched pattern. See §5. |
| `PAM_SSH_SFTP_CAPTURE` | | `off` | **Record the content of SFTP transfers** (Phase 59): `uploads`, `downloads`, or `all`. Every transferred file leaves a `.sftp` chunk-log artifact beside the session recordings — sealed under `PAM_RECORDING_ENCRYPT`, hash-chained, audited `sftp.file_recorded`, replayable from menu 19. While on, an SFTP stream the proxy cannot parse is **refused** (fail closed). See §5. |
| `PAM_SSH_SFTP_CAPTURE_MAX_MB` | | `0` (unlimited) | Per-file cap on captured bytes. Past the cap the transfer is **refused** (permission-denied, audited `sftp.blocked reason:capture-limit`), not merely left unrecorded — so with capture on this doubles as a per-file transfer size limit. |
| `PAM_ICAP_URL` | | (off) | **ICAP AV/DLP scanning of SFTP transfers** (Phase 143): `icap://host[:port]/service`. Requires `PAM_SSH_SFTP_CAPTURE` enabled and `PAM_SSH_SFTP_CAPTURE_MAX_MB` set (> 0). Detection only — the file has already reached its destination by the time a whole-object scan can complete. A flagged file audits `sftp.icap_flagged`; a scan failure audits `sftp.icap_scan_failed` and the transfer still proceeds. Joins the `PAM_OT_AIRGAP` conflict list. See §9.4. |
| `PAM_SSH_PORT_FORWARD` | | `true` | **`ssh -L` port forwarding** (Phase 141): a client-initiated forward is admitted only to the connected target's own host (any port). `false` disables the feature deployment-wide. Always refused in an observer session or while `PAM_REQUIRE_LIVE_SUPERVISION`/`PAM_REQUIRE_RECORDING` are set. See §9.4. |
| `PAM_RDP_CLIPBOARD` | | `allow` | RDP clipboard policy (Phase 33): `allow`, `readonly` (block paste into the target), `deny` (clipboard off both ways); drive redirection always off. A target's `rdp_clipboard` field can tighten this per target — the **stricter** of the two wins. |
| `PAM_RDP_CLIPBOARD_AUDIT` | | `off` | **Audit clipboard transfers** (Phase 50): `meta` records direction, mimetype, size and SHA-256; `full` also records the content (truncated). Content is opt-in because a privileged desktop's clipboard often holds a password the operator just copied. Emits `rdp.clipboard`. A target's `rdp_clipboard_audit` field can raise this per target (whichever records more wins). See §9.4. |
| `PAM_DB_STEPUP_FILE` | | (off) | Regex file marking PostgreSQL statements that **pause for a supervisor's live approval** — in-session step-up (Phase 30). See §9.4. |
| `PAM_DB_STEPUP_TTL_SEC` | | `120` | How long a paused statement waits for a decision before it is denied. |
| `PAM_SESSION_SHARE_INVITE_TTL_SEC` | | `900` | **Session sharing** (Phase 116): how long an approved share invite stays redeemable, **once**, before it expires unused — internal (`join:<token>` over SSH) or external (emailed QR). See §9.4c. |
| `PAM_SESSION_SHARE_GUEST_TTL_MIN` | | `240` | How long an **external** guest's minted viewing key keeps working *after* they redeem it — a separate window from the invite TTL above. See §9.4c. |
| `PAM_ANALYTICS_INTERVAL_MIN` | | `0` (off) | Threat-analytics worker interval (Phase 23); `0` leaves the read-only `GET /api/analytics/risk` endpoint on. See §9.7. |
| `PAM_ANALYTICS_WINDOW_MIN` / `_AUTO_KILL` / `_BUSINESS_START` / `_BUSINESS_END` | | `60` / `false` / `7` / `20` | Risk-scoring window (also the re-alert cooldown), auto-kill of critical actors' sessions, and business hours for the off-hours signal. |
| `PAM_ANALYTICS_TIMEZONE` | | (UTC) | IANA timezone the business hours are interpreted in (audit timestamps are UTC). |
| `PAM_APP_SECRETS_ENABLED` | | `false` | Enable the application-secrets API (Phase 24): Conjur-style secret delivery to non-agent apps. Front it with TLS. See §7. |
| `PAM_SSH_HOST_KEY` | | (ephemeral) | Path to persist the proxy SSH host key. Since Phase 42 the **store** is the authority in a multi-replica deployment: a key already at this path seeds shared custody, otherwise the replica adopts the cluster's key and mirrors it here. |
| `PAM_SSH_CA_KEY` | | (ZSP off) | Path to the Zero Standing Privilege SSH CA key (Phase 22); presence enables `ssh_ca` credentials (mint short-lived certs). Shared across replicas since Phase 42 — every pod publishes and signs with the same CA. See §6. |
| `PAM_SSH_CERT_TTL_MIN` | | `2` | Validity (minutes) of a minted ZSP certificate. |
| `PAM_SSH_OPERATOR_CERT_TTL_MIN` | | `10` | Cap (minutes) on an operator-issued SSH certificate (Phase 28: `POST /api/ca/ssh/sign`). See §6. |
| `PAM_SSH_KNOWN_HOSTS` | | (trust-any + warn) | OpenSSH known_hosts file pinning **upstream target** host keys. |
| `PAM_SESSION_FORENSICS` | | `false` | (Phase 157) After an interactive SSH session ends, pull the TARGET's own kernel audit record of what actually executed during it and store it beside the recording. Off by default: it runs one extra read-only command on the target after every session. See §9.3b. |
| `PAM_SESSION_FORENSICS_MAX_EVENTS` / `PAM_SESSION_FORENSICS_TIMEOUT_SEC` | | `500` / `30` | How many execs one artifact may carry (a cap that bites is reported as truncation, never silently) and how long the whole collection may take. |
| `PAM_K8S_CA_FILE` | | (system roots) | (Phase 155) PEM CA bundle verifying a Kubernetes API server's certificate. Most on-prem clusters use a private CA, so most deployments set this; several clusters' CAs may be concatenated into one file. |
| `PAM_K8S_INSECURE_SKIP_VERIFY` | | `false` | Disable that verification entirely (kind/minikube demos only). The vaulted bearer token would then be handed to whoever answers for the API server; the server logs a warning at startup when it is on. |
| `PAM_K8S_TIMEOUT_SEC` / `PAM_K8S_MAX_RESPONSE_KB` | | `30` / `1024` | Bounds on one brokered Kubernetes operation: how long it may take, and how large a response may be before it fails closed (a truncated object or log is worse than none). |
| `PAM_ENDPOINT_AGENTS_ENABLED` | | `false` | (Phase 153) Accept **outbound-only endpoint agents** on the SSH listener (`endpoint-agent:<name>` login with the agent's own bearer key) and register the `/api/endpoint-agents` routes; a target bound to an agent is then reached only through its reverse tunnel, never dialed. Off = the login is refused and the routes are absent. See "Outbound-only endpoint agents" under §6. |
| `PAM_SSH_JUMP_HOST` / `_USER` / `_KEY` | | (direct) | Reach SSH targets only routable through a **bastion** (Phase 8): the proxy opens a `direct-tcpip` channel through the jump host, authenticating to it with the private key at `_KEY` (public-key only). Set all three; leave unset for a direct dial. |
| `PAM_GUACD_ADDR` | | (RDP off) | `host:port` of the `guacd` daemon that brokers RDP (the Docker/K8s/Helm deploys ship one). See §5 → *RDP*. |
| `PAM_GUACD_RECORDING_PATH` | | (off) | Directory where **guacd** writes its own server-side RDP session recordings; the recording's name lands in the `rdp.connect` audit event. Separate from `PAM_RECORDING_DIR`, which holds the SSH/WinRM/PostgreSQL asciicasts. |
| `PAM_RECORDING_DIR` | | `recordings` | Where session recordings are written. |
| `PAM_RECORDING_OPAQUE_NAMES` | | `false` | Name recording files `<timestamp>_<random hex>` instead of `<timestamp>_<target>_<actor>` (Phase 48), so a backup or snapshot of the recording volume reveals no access metadata. Target and actor then live only in the audit trail — the console's recordings screen (menu 19) still shows both, resolved from it. Pair with `PAM_RECORDING_ENCRYPT` to cover content *and* metadata. See §9.3. |
| `PAM_RECORDING_ENCRYPT` | | `false` | **Seal recordings and WinRM transcripts at rest** (Phase 41): chunked AES-256-GCM under a per-recording data key wrapped by your KEK, so they inherit the same root of trust as credentials. Replay through the portal is unaffected — playback decrypts, and detects the format per file so recordings written before you enabled it still work. The trade: a `.cast` can no longer be fed straight to `asciinema`. See §9.3. |
| `PAM_LOG_LEVEL` | | `info` | `debug` \| `info` \| `warn` \| `error`. |
| `PAM_LOG_FORMAT` | | `json` | `json` (for SIEM) \| `text` (for humans). |
| `PAM_ROTATE_INTERVAL_MIN` | | `0` (off) | Credential-lifecycle worker interval (minutes). |
| `PAM_ROTATE_MAX_AGE_HOURS` | | `0` (report) | Auto-rotate password credentials older than this. |
| `PAM_ROTATE_AFTER_SESSION` | | `false` | Rotate a credential **as soon as the proxied session that used it ends**, so a secret can never be reused in a second session (this is also what forces rotation after a break-glass session). Zero-standing-privilege `ssh_ca` credentials are skipped — there is no stored secret. See §6. |
| `PAM_REQUIRE_APPROVAL` | | `false` | OT: gate every target behind an approved access request (4-eyes). |
| `PAM_APPROVAL_WINDOW_MIN` | | `60` | How long an approved access request stays valid. |
| `PAM_REQUIRE_TICKET` | | `false` | Require an ITSM change/incident ticket on access requests (Phase 20). |
| `PAM_TICKET_PATTERN` / `PAM_TICKET_VALIDATE_URL` | | | Ticket format regex / generic ITSM webhook (`POST {"ticket":…,"actor":…}` → 2xx = valid). |
| `PAM_TICKET_PROVIDER` | | webhook | **First-class ITSM connector** (Phase 84): `webhook`, `servicenow` or `jira`. The connectors check the ticket's **state**, its **change window**, and **whether it names the operator** — none of which a 2xx webhook can express, so before this a valid change number admitted anyone who knew one. Configure with `PAM_TICKET_URL` / `_USER` / `_TOKEN`; tune with `PAM_TICKET_STATES`, `PAM_TICKET_ACTOR_FIELDS`, `PAM_TICKET_REQUIRE_WINDOW` (default on) and `PAM_TICKET_BIND_ACTOR` (default on — turning it off makes a ticket number a shared password). |
| `PAM_TICKET_REVALIDATE` | | `false` | **Re-check the ticket when access is used** (Phase 60), not only when the request was filed — so a change cancelled mid-window stops admitting sessions. Puts your ITSM on the connect path (bounded at 5s) and refuses when it cannot confirm the ticket, including when it is unreachable. See §5. |
| `PAM_APPROVALS_REQUIRED` | | `1` | Default distinct approvers per access request — N-of-M chains (Phase 21). |
| `PAM_REQUIRE_REASON` | | `false` | Reject an access request that carries no reason. |
| `PAM_ACCESS_ONE_TIME` | | `false` | Make **every** access request single-use (Phase 26): the first privileged use its approval admits consumes it. Requests can also opt in individually (`one_time`). |
| `PAM_CHECKOUT_TTL_MIN` | | `30` | Credential checkout lease lifetime (minutes). |
| `PAM_VENDOR_ATTEST_URL` | | (off) | Employment-attestation webhook consulted when a vendor contract grant is approved (Phase 29): PAMv1 `POST`s `{"vendor":…,"org":…}` and the vendor-management system answers `2xx` for a currently-employed technician, so access is refused the moment their own employer offboards them. See §7. |
| `PAM_POSTURE_ATTEST_URL` | | (off) | Live device-posture webhook, checked on every connect and every authenticated call, not just once at approval (Phase 133). See §7. |
| `PAM_DEVICE_HEADER` | | (off) | Name of an HTTP header a trusted reverse proxy injects with a terminated client certificate's fingerprint; once set, a user with an enrolled `device_fingerprint` must present a matching value (Phase 133). See §7. |
| `PAM_VENDOR_SWEEP_INTERVAL_MIN` | | `0` (off) | How often the sweeper cuts a vendor's **live** session once its contract grant's window closes (`vendor.session_expired`), so access ends with the contract rather than at the next connect. |
| `PAM_OT_AIRGAP` | | `false` | Air-gapped sites. Forces the no-op alerter **and refuses to start** alongside anything that would call out of the enclave — the ITSM webhook, vendor attestation, the SIEM forwarder, Conjur, the alert webhook, `PAM_OIDC_ISSUER` and `PAM_SAML_IDP_METADATA_URL` (use `PAM_SAML_IDP_METADATA_FILE` inside the enclave) — and rejects `PAM_KEK_PROVIDER=aws-kms` and `PAM_ENTRA_TENANT_ID` outright. It is a fail-closed startup gate, not a mute switch. |
| `PAM_OT_AIRGAP_ALLOW` | | — | Comma-separated variable names you certify resolve **inside** the enclave, re-permitting them under air-gap. Without this the gate has no escape hatch, which is why an air-gapped site with an internal SIEM could not start. |
| `PAM_ALERT_WEBHOOK` | | (off) | HTTP endpoint POSTed a JSON alert on break-glass access/unseal and newly flagged risk (Slack/PagerDuty/…). Use HTTPS — a plaintext or non-loopback `http://` URL is warned about at startup. |
| `PAM_ALERT_SYSLOG` | | (off) | Syslog collector for the same alerts — `udp://host:port` or `tcp://host:port` (a bare `host:port` is treated as UDP). This is per-*alert*; to stream the whole trail use `PAM_AUDIT_FORWARD_ADDR`. |
| `PAM_ALERT_EMAIL_SMTP` / `_FROM` / `_TO` | | (off) | SMTP server (`host:port`), envelope sender, and comma-separated recipients for email alerts — **all three or none** (validated fail-loud). `PAM_ALERT_EMAIL_USER` / `_PASS` add SMTP auth. |
| `PAM_REVEAL_DISABLED` | | `false` | Make `reveal` break-glass-only (also forces the broker's `reveal_credential` closed). |
| `PAM_AUDIT_HMAC_KEY` | | (off) | base64 32-byte key enabling the **tamper-evident HMAC chain** over the primary audit trail; verify with `GET /api/audit/verify`. See §9.2. |
| `PAM_AUDIT_SIGN_SEED` | | (off) | base64 32-byte ed25519 seed (needs `PAM_AUDIT_HMAC_KEY`) enabling **signed checkpoints** (`GET /api/audit/head`) so an auditor can detect **tail truncation**. See §9.2. |
| `PAM_AUDIT_FORWARD_ADDR` | | (off) | host:port of a SIEM collector; **continuously forwards** every audit event (Phase 35). `PAM_AUDIT_FORWARD_PROTO` (`udp`/`tcp`/`tls` — tls verifies the collector's certificate, always), `PAM_AUDIT_FORWARD_FORMAT` (`rfc5424`/`cef`/`leef`), `PAM_AUDIT_FORWARD_CA` (PEM bundle pinning the collector's CA, tls only), `PAM_AUDIT_FORWARD_INTERVAL_SEC` (`10`) tune it. See §9.2. |
| `PAM_RECORDING_RETENTION_DAYS` / `PAM_AUDIT_RETENTION_DAYS` | | `0` (∞) | **Prune** recordings / audit rows older than N days (Phase 36). Audit pruning is skipped while the HMAC chain is on. `PAM_RETENTION_INTERVAL_HOURS` (`24`) is the sweep cadence. See §9.2. |
| `PAM_RETENTION_ARCHIVE_DIR` | | (delete on expiry) | **Archive before pruning** (Phase 49): aged audit rows are exported as digest-stamped JSON Lines and aged recordings are moved here (write-once, `0400`), and the delete runs **only if the archive succeeded**. Point it at WORM storage. See §9.2. |
| `PAM_BROKER_POLICY_FILE` | | (off) | YAML policy file — **its presence enables the AI-agent access broker** (Phase 13). |
| `PAM_BROKER_AUDIT_KEY` | broker only | (shared custody) | base64 32-byte HMAC key for the verifiable audit chain. **Unset = generated once and held under shared custody** (KEK-sealed in `key_material`, same as the SSH host/CA keys). An explicit value is **written through to custody** (so later unsetting it cannot fork the chain); an explicit value that *disagrees* with custody is a **fatal start** — unset it to adopt the cluster key. |
| `PAM_BROKER_AUDIT_SIGN_SEED` | broker only | (shared custody) | base64 32-byte ed25519 seed signing the audit-chain head (truncation detection). Unset = shared custody; **setting it is how a signing-key rotation is driven** (see §"Rotate the checkpoint signer") — custody converges to the explicit seed, so the replaced signer cannot silently come back. |
| `PAM_BROKER_POSTURE_REQUIRED` | | `false` | Ask the posture webhook about **agent** identities too, not only human operators. **Needs `PAM_POSTURE_ATTEST_URL`** — PAMv1 refuses to start with this on and no webhook to ask. Off by default: a webhook that answers about laptops has never heard of an agent name. |
| `PAM_BROKER_REQUIRE_KNOWN_OWNER` | | `false` | Refuse a broker approval when the calling agent's owner is not a PAMv1 user. Off by default — an unrecognised owner is audited as `broker.approval.four_eyes_unverified` instead. Like every broker refusal, it needs the broker enabled (`PAM_BROKER_POLICY_FILE`) or startup fails. |
| `PAM_BROKER_REQUIRE_ENROLLED_SVID` | | `false` | Refuse a SPIFFE-attested agent whose identity has not been **enrolled** (an owner recorded for it). Off by default. Static agent keys are unaffected. **Needs `PAM_BROKER_TRUST_DOMAIN_JWKS`** — PAMv1 refuses to start with this on and no SVID path to gate. |
| `PAM_BROKER_REQUIRE_POP` | | `false` | Refuse a SPIFFE-attested agent whose token is not **bound to a key** (RFC 7800 `cnf` + RFC 9449 proof of possession). Off by default — turning it on refuses every unbound token already in circulation, so bind first and switch after. **Needs `PAM_BROKER_TRUST_DOMAIN_JWKS`** — PAMv1 refuses to start with this on and no SVID path to gate. Static agent keys carry no claims and are unaffected. |
| `PAM_BROKER_MAX_CALLS_PER_TOKEN` | | `0` (off) | Cap how many brokered calls may be spent with **one token**. A second, independent limit alongside `PAM_BROKER_BUDGET_PER_DAY`: the budget bounds an agent's day, this bounds one credential. When a token hits it, the agent is told so and a **new token starts a new ceiling** — the credential is retired, the agent is not punished. **Static agent keys are unaffected**, because they carry no token id; their ceiling is the per-day budget. Needs the broker enabled. Enforced by a reservation written at the instant of the decision (Phase 219), so a burst of calls arriving together cannot over-run it; a call the policy refuses, or an approver denies, gives its slot back. |
| `PAM_BROKER_PUBLIC_URL` | | *(derived)* | The base origin agents address the broker at, e.g. `https://pam.example.com`. Used to check a proof's `htu` claim. **Set this whenever anything terminates TLS in front of PAMv1** — otherwise the request arrives as plain http on an internal name while the client signed the external URL, and every key-bound agent is refused. Must be a bare origin, no path. |
| `PAM_BROKER_TOKEN_TTL_MIN` | | `15` | Maximum lifetime of a single-use approval resume token, and of the parked call it collects (minutes). A policy rule's `ttl_seconds` may narrow it per call, never extend it. |
| `PAM_BROKER_RATE_PER_MIN` | | `0` (off) | Per-agent tool-call rate limit. |
| `PAM_BROKER_MAX_ARG_BYTES` | | `16384` | Cap on a tool call's serialized arguments (0 = off). |
| `PAM_BROKER_BUDGET_PER_DAY` | | `0` | Default cap on how many brokered tool calls **one agent** may make in a rolling 24 hours (0 = unlimited). A per-agent budget set on the key overrides it. This is the control a rate limit cannot give you: 60 calls/minute is still 86,400 calls a day. Enforced by a reservation written at the instant of the decision (Phase 219), so a burst of calls arriving together cannot over-run it; a call the policy refuses, or an approver denies, gives its slot back. |
| `PAM_BROKER_MAX_RESULT_BYTES` | | `65536` | Cap on how much of a tool's **result** reaches the agent (0 = off). Oversized output is shortened with a visible marker, never refused — the command has already run by then — and a secret-bearing result is never touched. The full output goes to the stored transcript, which is what makes the truncation safe. |
| `PAM_BROKER_AUDIT_CHECKPOINT_EVERY` | | `0` (off) | Emit a signed **in-chain** audit checkpoint every N broker events (Phase 27) — defense-in-depth over the HMAC (catches an edit even under HMAC-key compromise). |
| `PAM_BROKER_AUDIT_SIGN_PREV` | | — | Comma-separated base64 ed25519 **public** keys still trusted after a signing-key rotation (overlap window); published alongside the current key at `GET /v1/audit/jwks`. |
| `PAM_BROKER_TRUST_DOMAIN` / `_TRUST_DOMAIN_JWKS` / `_AUDIENCE` | SVID only | — | SPIFFE JWT-SVID verification: trust-domain host, file JWKS, and required audience. |
| `PAM_BROKER_MAX_DELEGATION_DEPTH` | | `1` | RFC 8693 `act`-chain delegation depth cap — enforced when a chain is presented **and** when a new link is minted. |
| `PAM_BROKER_TOKEN_EXCHANGE` | | `false` | Enable `POST /v1/token`, the RFC 8693 endpoint where an agent delegates its own authority to a sub-agent (Phase 57). Requires the broker and the SVID settings above. |
| `PAM_BROKER_EXCHANGE_TTL_MIN` | | `5` | Lifetime of a minted delegated token, further capped by the delegator's own expiry. |
| `PAM_BROKER_TOKEN_SIGN_SEED` | | *(shared custody)* | Base64 32-byte ed25519 seed for signing delegated SVIDs. Unset is the norm: generated once into KEK-sealed shared custody so every replica issues and accepts under one key. Setting it explicitly is the rotation path. |

The examples below use `-H "X-API-Key: $PAM_API_KEY"`; in production call the
HTTPS endpoint of your ingress instead of `http://localhost:8080`.

### 4.1 Runtime configuration console (Phase 12)

The **identity, SSO, and operational-policy** settings (the `PAM_LDAP_*`,
`PAM_ENTRA_*`, `PAM_OIDC_*`, `PAM_SAML_*` (except the three `_FILE` paths), `PAM_MFA_REQUIRED`, `PAM_REQUIRE_APPROVAL`,
`PAM_REVEAL_DISABLED`, `PAM_ALLOWED_PROTOCOLS`, … keys) can also be set from the
console at runtime and are persisted in the database, overriding the environment.
Secret values (bind password, client secrets) are **vault-encrypted at rest** and
never returned in plaintext. **Bootstrap and transport settings** — database URL,
master key/KEK, listen addresses, TLS, the SSH proxy — stay environment-only and
require a restart; they are deliberately *not* overridable.

- **Menu 13 — System configuration**: list every overridable key, set an override
  (`PUT /api/config`), or clear one back to the env default (`DELETE /api/config/{key}`).
  Changes **hot-swap without a restart**: the identity backends and policy are
  rebuilt atomically on save. A rejected change (e.g. an unreachable directory) is
  rolled back so it can't also break the next restart.
- **Menu 14 — Effective config & backend health**: a read-only view of which
  backends are wired (`GET /api/config/effective`), plus a one-key **IaC export**
  (`GET /api/config/iac?format=env|helm|terraform`, function keys F6/F7/F8) that
  renders your console-set overrides back into env / Helm values / Terraform locals
  so they can be committed to the IaC that owns the deployment. Secrets export as
  secret-store placeholders, never plaintext.

These endpoints require the `manage_users` capability (admin, or a custom profile
that includes it).

---

## 5. Managing targets

> **Naming rule (Phase 77).** Every name the API accepts — targets, users, safes,
> campaigns, profiles, agent keys, vendors, credential usernames, and the
> `subject` of a grant or safe membership — must not contain a **colon** or a
> **control character**, and must be at most **128 bytes**. Anything else is
> allowed: `Prod DB 01`, `sûreté`, `データベース`, `svc@corp` and `a/b` are all
> fine. The reason is that audit details are space-separated `key:value` text, so
> a target named `prod-db action:approved reason:emergency` would put forged
> fields into the record of *every* operator's session on that target — not only
> its creator's. A rejected name comes back as `422` naming the field. **Hosts are
> exempt** (an IPv6 literal legitimately contains colons) and are quoted in the
> audit trail instead. Names created before this rule are **not** rejected
> retroactively; only a create or an update is checked.

```bash
# Create a target
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/targets \
  -d '{"name":"web-01","host":"10.0.0.5","port":22,"os_type":"linux","protocol":"ssh"}'

# List / inspect / edit / delete
curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/targets
curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/targets/1
curl -H "X-API-Key: $PAM_API_KEY" -X PUT http://localhost:8080/api/targets/1 \
  -d '{"name":"web-01","host":"10.0.0.50","port":2222,"os_type":"linux","protocol":"ssh"}'
curl -H "X-API-Key: $PAM_API_KEY" -X DELETE http://localhost:8080/api/targets/1   # cascades to its credentials
```

`os_type` ∈ `linux|windows`; `protocol` ∈ `ssh|winrm|rdp|vnc|postgres|mssql`; optional `rdp_clipboard` ∈ `allow|readonly|deny` and `rdp_clipboard_audit` ∈ `off|meta|full` tighten the global RDP clipboard policy for this target (strictest wins; empty inherits) — they apply to **VNC targets too**, the field names predate it.

**Edit, don't recreate** (Phase 44). `PUT /api/targets/{id}` changes a target in
place with the same validation as create — its credentials, grants, dependencies
and safe assignment survive, where delete + recreate cascades them away. The
safe assignment is deliberately not part of the body (`PUT
/api/targets/{id}/safe` owns it). PUT replaces **every editable field**: a body
that omits `rdp_clipboard`/`rdp_clipboard_audit` **resets those overrides to
inherit** — include the current values when editing something else (the console
change screen always sends them), and note the overrides now ride the
`target.create`/`target.update` audit details (`clipboard:… clip_audit:…`,
`-` = inherit), so setting or clearing one is visible in the trail. Safes (`PUT /api/safes/{id}`), users (`PUT
/api/users/{id}`, role/profile only — the token survives, so a promotion does
not re-mint it, and you cannot assign capabilities you do not hold) and vendors
(`PUT /api/vendors/{id}`, which since Phase 177 edits the org label **and** the
on-file contact address — the one magic-link invites are sent to, previously
fixed at creation; omit `email` to leave it as it is, send `""` to clear it) edit
the same way. In the console,
type **2=Change** next to a row. Grants and safe members are not editable by
design: delete + recreate them (two audited events are a clearer trail).

**Bounded lists.** Every inventory list (`/api/targets`, `/api/credentials`,
`/api/users`, `/api/safes`, `/api/checkouts`, `/api/access-requests`,
`/api/vendors`) serves at most 500 rows per request: `?limit=` (default 100,
clamped 1..500) and `?after=<last id>` page through in ascending id order —
request the next page starting after the last id you received until a short
page comes back. The console does this automatically.

**Per-target access grants** restrict who may connect. A target with no grants is
open to any connect-capable user; add grants to lock it down (admins always have
access):

```bash
# Only members of the "user" role, plus alice specifically, may connect to target 1
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/targets/1/grants -d '{"subject_type":"role","subject":"user"}'
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/targets/1/grants -d '{"subject_type":"user","subject":"alice"}'
curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/targets/1/grants          # list
curl -H "X-API-Key: $PAM_API_KEY" -X DELETE http://localhost:8080/api/targets/1/grants/2
```

Grants are enforced by the SSH proxy, WinRM and RDP alike. To force every access
through the recorded proxy, set `PAM_REVEAL_DISABLED=true` so credential reveal
becomes break-glass-only.

## 6. Managing credentials

```bash
# Vault a credential for a target (secret is encrypted before storage)
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials \
  -d '{"target_id":1,"username":"root","secret":"S3cret-P@ss","secret_type":"password"}'

# List (never returns the secret) · reveal (admin only, audited) · delete
curl -H "X-API-Key: $PAM_API_KEY" "http://localhost:8080/api/credentials?target_id=1"
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/1/reveal
curl -H "X-API-Key: $PAM_API_KEY" -X DELETE http://localhost:8080/api/credentials/1
```

`secret_type` is `password`, `ssh_key` (paste the PEM private key as `secret`),
`ssh_ca`/`db_zsp` (Zero Standing Privilege — no stored secret; see the ZSP
subsections below), or `file` (a license key, cert bundle or short document —
see "File-attachment secrets" below). Once the proxy is your normal path,
**`reveal` should be the exception** — prefer brokered sessions so the secret
is never shown.

### File-attachment secrets (Phase 145)

`secret_type: "file"` vaults arbitrary file content — a license key, a
certificate bundle, a short document — through the exact same encrypt/reveal
pathway as a password, base64-encoded by the client before it is sent:

```bash
b64=$(base64 -w0 license.key)
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials \
  -d "{\"target_id\":1,\"username\":\"license\",\"secret_type\":\"file\",\"secret\":\"$b64\"}"

curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/1/reveal \
  | jq -r .secret | base64 -d > license.key
```

- **`PAM_CREDENTIAL_FILE_MAX_KB`** (default `1024`, range 1–10240) caps the
  content at creation — a file over the cap is **refused outright**, never
  truncated, before it is ever encrypted or a row is ever inserted. Unlike
  the SFTP capture cap, there is no "0 = unlimited" here: a credential is
  not general object storage, so this starts bounded by default rather than
  opening unbounded and needing to be dialed back later.
- **No new REST surface.** This is a new *value* for the existing
  `secret_type` field on the existing `POST /api/credentials` — the same
  route every other secret type already uses, listed, revealed and deleted
  the same way.
- **No way to replace a file's content in place yet.** There is no
  update-secret route for any secret type (only `rotate`, which generates a
  fresh random value — meaningless for an uploaded file); replacing a file
  attachment means deleting the credential and creating a new one.

### Browser-extension password autofill (Phase 147)

A real Manifest V3 extension — `extension/` in the repo root, outside
`internal/`, with its own [setup README](../extension/README.md) — fills a
login form from a credential vaulted in PAMv1. It closes Delinea's Web
Password Filler / BeyondTrust's Workforce Passwords gap by calling the
*existing*, already-audited `POST /api/credentials/{id}/reveal` — the same
route the portal itself uses — rather than opening any new way to get a
secret out of the vault.

**Minting a token.** Anyone holding `reveal_secret` can mint one for
themselves:

```bash
# console menu 30 does this without the curl (Phase 187); the API is here for scripts
curl -H "X-API-Key: $PAM_API_KEY_OR_USER_TOKEN" -X POST http://localhost:8080/api/extension-token
# → {"token":"...", "expires_at":"..."}
```

The token is pasted into the extension's own settings page (toolbar icon →
Settings). It is **not** a general-purpose API key:

- **Refused on every route except reveal.** The token resolves to an
  `ExtensionOnly` principal — structurally similar to an RDP/VNC viewer
  token's `TunnelOnly`, but narrower: where a viewer token is refused
  *everywhere*, an extension token is refused everywhere *except*
  `POST /api/credentials/{id}/reveal`. A copy pulled from the extension's
  local storage cannot list credentials, list targets, connect to
  anything, or mint another token.
- **Inherits the minting user's own access — nothing more.** The token
  carries the same role/capabilities as whoever minted it, so
  `reveal_secret` plus every existing grant, safe membership and approval
  requirement (`gateCredentialAccess`) still applies exactly as it does to
  a normal reveal. Minting one for a user who could never reveal a secret
  is refused up front, not just discovered on first use.
- **`PAM_EXTENSION_TOKEN_TTL_HOURS`** (default `24`, range 1–720) bounds
  how long it stays valid. Unlike an RDP/VNC token (60 seconds, since it
  travels in a WebSocket URL), this one lives in the extension's own
  browser storage across many page loads, so it needs to survive longer —
  but it is still a bearer credential sitting on an endpoint, so it is not
  unbounded either. Once it expires, reveal returns 401 and the user mints
  a new one; there is no renew-in-place.
- **Every reveal is still audited** (`credential.reveal`), with a
  `via:extension` detail marker distinguishing it from a portal/API
  reveal — nothing about the audit trail changes except that one marker.

**What the extension cannot do (v1 scope).** It only reads a vaulted
secret and fills a form — no credential capture, no write-back to PAMv1.
It also has **no way to browse your vault**: there is no route that lists
credentials for an extension-scoped token, so a user manually maps one
hostname to one credential ID in the extension's own settings (which
credential IDs to use come from the portal or `GET /api/credentials`, a
normal admin/reveal-capable action, not something the extension itself
can discover).

> ⚠️ **Not interactively verified against a real browser in this
> environment** — no GUI browser was available to load the unpacked
> extension. Every JS file is syntax-checked and `manifest.json` is
> JSON-validated, and the code follows well-established Manifest V3
> password-manager patterns, but treat this the same way as any
> unverified-infrastructure finding elsewhere in this project (see
> [EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md)): test it against your
> own browser before relying on it.

### Rotation & reconciliation (credential lifecycle)

PAMv1 can change the password **on the target** and re-vault it, so the account's
secret is one only PAMv1 knows — and can prove is current. Rotation and
reconciliation run over the same secure protocols as the proxy: SSH (`chpasswd`,
fed on stdin so the new password never hits a shell command line) and WinRM
(`net user`). The rotating account must be able to set its own password (root /
a sudoer on Linux; a suitably privileged account on Windows).

```bash
# Rotate now: generate a strong secret, set it on the target, re-vault it.
# The new secret is NEVER returned — the proxy injects it just-in-time.
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/1/rotate
# → {"id":1,"target":"web-01","username":"root","rotated":true,"rotated_at":"..."}

# Reconcile one credential: does the vaulted secret still authenticate?
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/1/reconcile
# → {"credential_id":1,...,"status":"in_sync"}   (or "out_of_sync" on drift)

# Reconcile + heal drift by rotating to a fresh PAM-managed secret
curl -H "X-API-Key: $PAM_API_KEY" -X POST "http://localhost:8080/api/credentials/1/reconcile?remediate=true"

# Read-only drift scan across every credential (safe to run on a schedule)
curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/reconcile
# → {"checked":12,"out_of_sync":1,"results":[...]}
```

To automate it, enable the background lifecycle worker: it reconciles every
credential on each pass and rotates password credentials older than a max age.

```bash
PAM_ROTATE_INTERVAL_MIN=60       # run hourly
PAM_ROTATE_MAX_AGE_HOURS=168     # rotate secrets older than 7 days (0 = report only)
```

Every action is audited (`credential.rotate`, `credential.reconcile`,
`credential.remediate`; the worker acts as `system-scheduler`). **Password**
credentials rotate over SSH (`chpasswd`) / WinRM (`net user`); **`ssh_key`**
credentials rotate over SSH by generating a fresh keypair and replacing the
account's `authorized_keys` (the old key stops working). AD/LDAPS account
password-change (`unicodePwd`) and identity reconciliation (revoking users the
directory reports as disabled) shipped in Phase 7.

**Generated-password policy and reuse history (Phase 120).** A generated
password defaults to 24 characters with at least one lowercase, uppercase,
digit and symbol — configurable, and reuse-prevention is opt-in:

```bash
PAM_PASSWORD_MIN_LENGTH=32       # default 24
PAM_PASSWORD_MIN_LOWER=2         # default 1 (each of the four must be >= 1)
PAM_PASSWORD_MIN_UPPER=2
PAM_PASSWORD_MIN_DIGIT=2
PAM_PASSWORD_MIN_SYMBOL=2
PAM_PASSWORD_HISTORY_COUNT=5     # default 0 (off); refuses to reissue one of
                                  # the last 5 rotated secrets per credential
```

History is tracked as SHA-256 hashes only — never the secrets themselves —
and restart-only, like the length/class minimums above (a domain-wide
complexity policy is an infrequent, deliberate change).

**Checkout / check-in (exclusive lease).** For accounts a person or app must use
the password directly, check it out: you get the secret exclusively for a lease
(`PAM_CHECKOUT_TTL_MIN`, default 30 min), and on check-in the credential is
**rotated** so the password you saw is dead. Only one holder at a time.

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/1/checkout \
  -d '{"reason":"deploy hotfix"}'
# → {"checkout_id":7,"username":"root","secret":"...","expires_at":"..."}
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/1/checkin
# → {"returned":true,"rotated":true}          # the seen secret is now invalid
curl -H "X-API-Key: $PAM_API_KEY" "http://localhost:8080/api/checkouts?active=true"
```

**Extending a lease (Phase 120).** Still working when the TTL is about to run
out? Only the holder (or an admin) may extend, and only up to a configured
ceiling on the lease's *total* duration from check-out
(`PAM_CHECKOUT_MAX_EXTEND_MIN`, default 240 minutes) — extension prolongs a
lease already granted, it does not re-grant one, and it cannot turn "leased"
into "standing":

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/1/checkout/extend \
  -d '{"minutes":30}'
# → {"checkout_id":7,"credential_id":1,"expires_at":"..."}
```

**Discovery.** Probe hosts for reachable management ports and optionally onboard
them (reachability only — no credentials are tried):

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/discovery/scan \
  -d '{"hosts":["10.0.0.5","10.0.0.6"],"ports":[22,3389,5986],"create":true}'
# → {"candidates":[{"host":"10.0.0.5","port":22,"protocol":"ssh",...}],"created":[...]}
```

**Authenticated post-login account discovery (Phase 128).** Discovery above only
probes reachability — it never authenticates. This is the authenticated
counterpart: dials an `ssh` or `winrm` target with its *own* first vaulted
credential and runs a fixed, read-only enumeration command (`cat /etc/passwd`
on SSH; `net user` + `net localgroup Administrators` on WinRM), then
cross-references every discovered account name against **every** credential
already vaulted for that target. An account with no matching credential comes
back `"managed":false` — CyberArk DNA-style: a login-capable local or service
account the host has, that PAMv1 is not tracking, rotating or auditing access
to. `manage_targets`, not `connect` — this is a management action, not a
brokered session, so it does not touch the live-session registry or recording
requirements. The command itself still goes through the command-deny policy
(`PAM_COMMAND_DENY_FILE`) like every other discrete command PAMv1 runs:

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/targets/1/discover-accounts
# → {"target":"web-01","protocol":"ssh","scanned_at":"...",
#    "accounts":[{"username":"root","privileged":true},{"username":"deploy","privileged":false}],
#    "managed":{"deploy":true},"unmanaged_count":1,"privileged_unmanaged_count":1}
```

Console: menu 1 (*Work with Targets*), option **9=Discover accounts**
(ssh/winrm targets only) opens a results screen listing every account found,
whether it is privileged, and whether PAMv1 manages it. Scope: SSH and WinRM
only (RDP/VNC/PostgreSQL/SQL Server have no equivalent shell command surface);
Unix privilege detection is UID-based only (root, or a group-membership-aware
follow-on is not attempted in v1); a target needs at least one already-vaulted
credential to authenticate the scan itself.

### DoubleLock: a second password held by someone else (Phase 135)

Any non-ZSP credential can carry an **additional** password, held by a
named person, required — on top of your normal `reveal_secret` capability —
to reveal or check it out. This is the answer to "what stops one admin
account, alone, from reading every secret in the vault": nothing stops
RBAC from being compromised, but a DoubleLocked secret still needs a
*second, different* person's password even then.

```bash
# Enable — requires you can already reveal this credential; you supply the
# new password once, here.
curl -H "X-API-Key: $PAM_API_KEY" -X POST \
  http://localhost:8080/api/credentials/7/doublelock \
  -d '{"holder":"alice (break-glass custodian)","password":"a-second-secret"}'

# Reveal/checkout now additionally require the password, as a header:
curl -H "X-API-Key: $PAM_API_KEY" -H "X-DoubleLock-Password: a-second-secret" \
  -X POST http://localhost:8080/api/credentials/7/reveal

# Without it (or with the wrong one), reveal/checkout are refused with a
# distinct "double-locked" error, not the generic decryption-failed one.

# Disable — ALSO requires the password. An admin who does not know it
# cannot turn DoubleLock off any more than they can read the secret through
# it; that is the whole point.
curl -H "X-API-Key: $PAM_API_KEY" -X DELETE \
  http://localhost:8080/api/credentials/7/doublelock -d '{"password":"a-second-secret"}'
```

**The password must be at least 16 characters** (v0.58.1, the 2026-08-26
audit's H-3), and `PAM_DOUBLELOCK_MIN_LENGTH` can raise that floor — never
lower it. A shorter one is refused with `422` and the reason, which is worth
understanding: this password is the *only* key in front of `DoubleLockEnc`, a
copy of the secret that deliberately lives outside the vault KEK, so a
database-only compromise leaves an attacker an offline guess at it, and
length — entropy — is what defeats that, not iteration count. The derivation
is PBKDF2-HMAC-SHA-256 at **600 000 iterations** (the OWASP figure; it was
100 000), with the count stored per record, so a lock set before v0.58.1
still opens at the count it was sealed with; disable and re-enable it to
reseal at the new count. Locks already in place are otherwise untouched —
only *enabling* is gated.

`holder` is a display label (a name, or a comma-separated set) — never the
password itself, and not tied to a real `store.User` row in v1. Connecting
through the proxy is **completely unaffected**: DoubleLock only gates the
two paths that hand plaintext back to a caller (reveal, checkout), never
the JIT-injection a live session uses, so a DoubleLocked credential still
opens sessions normally. **Rotating the credential's secret clears
DoubleLock** — the password to reseal the new secret isn't available to
the rotation worker, so the holder re-enables it afterward if still wanted.
API/curl-only in v1, not yet on the console screens — matching
`ssh_ca`/`db_zsp`'s own precedent of not adding every new credential
concept to the 5250 UI immediately. See
"Rotating the vault key" in §8 for why a KEK rotation (`-rotate-kek`) never
touches a DoubleLocked credential either way.

### Zero Standing Privilege: ephemeral SSH certificates (Phase 22)

Instead of storing a password or key for an account, PAMv1 can sign a
**short-lived SSH certificate just-in-time** for each session. The account then
has **no standing secret at all** — the target trusts only the PAMv1 CA, and each
certificate is minted fresh and expires in minutes (the Teleport / CyberArk ZSP
model). Enable it by giving PAMv1 a persistent CA key path:

```bash
PAM_SSH_CA_KEY=/data/pamv1_ssh_ca      # created on first use (0600); keep it persistent
PAM_SSH_CERT_TTL_MIN=2                 # minted certificate validity (default 2 minutes)
```

**1. Install the CA on each target.** Fetch the CA public key and trust it:

```bash
curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/ca/ssh
# → {"type":"ssh_ca","public_key":"ssh-ed25519 AAAA... pamv1-ca","fingerprint":"SHA256:...","install_hint":"..."}
```

On the target: write `public_key` to `/etc/ssh/pamv1_ca.pub`, add
`TrustedUserCAKeys /etc/ssh/pamv1_ca.pub` to `sshd_config`, and reload sshd.

**2. Create a Zero Standing Privilege credential** — no secret is stored:

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials \
  -d '{"target_id":1,"username":"root","secret_type":"ssh_ca"}'
# note: an ssh_ca credential must NOT carry a secret, and is only valid on ssh targets
```

That also holds the other direction: `PUT /api/targets/{id}` refuses to change a
target's protocol away from `ssh` while it still holds an `ssh_ca` credential
(Phase 108) — delete the credential first if the target is being repurposed.

**3. Connect as usual** — `ssh root@web-01@pam-host`. The proxy mints a
certificate for `root`, valid for a couple of minutes, and authenticates with it;
nothing is ever stored for the account. Each issuance is audited
`session.cert_issued` (serial, principal, validity, key-id — never the key).
Because there is no stored secret, an `ssh_ca` credential is never rotated or
reconciled (reconcile reports it as `unsupported`).

**Operator certificates for direct access (Phase 28).** The same CA can also sign
an operator's **own** SSH key so they connect **directly** to a target (bypassing
the proxy) with a short-lived, revocable certificate — the Teleport `tsh login`
model. The operator proves they hold the key, then gets a cert scoped to one
principal (capped at `PAM_SSH_OPERATOR_CERT_TTL_MIN`, default 10m):

```bash
# 1. get a proof-of-possession challenge, sign it with your private key
CH=$(curl -s -XPOST -H "X-API-Key: $KEY" $PAM/api/ca/ssh/challenge | jq -r .challenge)
SIG=$(printf %s "$CH" | ssh-keygen -Y sign -n pamv1 -f ~/.ssh/id_ed25519 /dev/stdin ...)  # (client tooling)
# 2. exchange it for a certificate scoped to the "svc" account on web-01
curl -s -XPOST -H "X-API-Key: $KEY" $PAM/api/ca/ssh/sign \
  -d '{"public_key":"ssh-ed25519 AAAA... me","challenge":"'"$CH"'","signature":"<base64>",
       "target":"web-01","principal":"svc","source_address":"10.0.0.0/8","ttl_minutes":10}'
# → {"certificate":"ssh-ed25519-cert-v01@openssh.com AAAA...","serial":"...","valid_before":"..."}
```

The principal must be a **managed account** on the target, and the same connect
authorization as the proxy applies (per-target grants + approval, consuming a
one-time approval). Revoke a cert before it expires by serial, and publish the
KRL for your targets' `RevokedKeys`:

```bash
curl -s -H "X-API-Key: $KEY" $PAM/api/ca/ssh/certs                  # issued certs, newest first — the serials to revoke
curl -s -XPOST -H "X-API-Key: $KEY" $PAM/api/ca/ssh/revoke -d '{"serial":"<serial>"}'
curl -s -H "X-API-Key: $KEY" $PAM/api/ca/ssh/krl -o pamv1-ssh.krl   # install as sshd RevokedKeys
```

Audit: `ssh.cert_issued` / `ssh.cert_denied` (bad proof of possession) /
`ssh.cert_revoked`.

### Kubernetes clusters (Phase 155)

A `kubernetes` target is a cluster's **API server**, not a host: there is no
session to proxy, so PAMv1 brokers **discrete, audited kubectl-shaped
operations** over `POST /api/targets/{id}/kubectl` — the same shape as the WinRM
REST endpoint, and gated the same way. The vaulted credential is a **service-account
bearer token** (`k8s_token`), injected just-in-time as the `Authorization` header
of ONE API call and never handed to the operator.

```bash
# 1. The cluster as a target (port defaults to 6443 for this protocol).
curl -s -XPOST -H "X-API-Key: $KEY" $PAM/api/targets \
  -d '{"name":"prod-cluster","host":"api.k8s.example","port":6443,"os_type":"linux","protocol":"kubernetes"}'

# 2. Its service-account token, vaulted. `username` is the account the token
#    belongs to — it is what the audit trail and the vendor gate record.
curl -s -XPOST -H "X-API-Key: $KEY" $PAM/api/credentials \
  -d '{"target_id":42,"username":"pam-broker","secret_type":"k8s_token","secret":"eyJhbGci..."}'

# 3. One brokered operation.
curl -s -XPOST -H "X-API-Key: $KEY" $PAM/api/targets/42/kubectl \
  -d '{"verb":"get","resource":"pods","namespace":"prod"}'
# → {"target":"prod-cluster","command":"kubectl get pods -n prod","status":200,
#    "method":"GET","path":"/api/v1/namespaces/prod/pods","body":"{\"kind\":\"PodList\",…}"}
```

**The request is a vocabulary, not a passthrough** — every operation has to be
nameable in a command string that command control can match and the audit trail
can carry:

| Field | Verbs | Meaning |
|---|---|---|
| `verb` | — | `get`, `logs`, `apply`, `delete` |
| `api_version` | all | `v1` (default, the core group) or `group/version` — e.g. `apps/v1`, `example.com/v1alpha1` for a CRD |
| `resource` | get/apply/delete | the lowercase plural (`pods`, `deployments`); implied `pods` for `logs` |
| `name` | logs/delete required | the object; blank on `get` lists the collection |
| `namespace` | all | blank means the cluster-scoped path — for a namespaced resource that is Kubernetes' own across-all-namespaces collection |
| `selector` | get | label selector (`app=web,tier!=db`) |
| `container` / `tail_lines` | logs | one container of many; how many lines (default 200, max 10000) |
| `manifest` | apply | the YAML or JSON, sent verbatim as a **server-side apply** patch with `fieldManager=pamv1` |

**What the cluster decides, and what PAMv1 decides.** PAMv1 does not
re-implement Kubernetes RBAC: what the token may do is the cluster's business,
and a cluster-side refusal comes back as its own `403` inside the envelope (with
`status:403` on the audit row) — an answer, not a PAMv1 error, exactly as a
non-zero exit code is on the WinRM endpoint. PAMv1 decides everything else: the
protocol policy (`PAM_ALLOWED_PROTOCOLS`), per-target grants and safes, the
four-eyes approval gate, the vendor contract gate, the concurrent-session cap,
the source-IP allowlist and device/posture checks (they ride the ordinary `authz`
middleware), **command control**, recording and the audit trail.

**Command control covers it.** The canonical `kubectl …` line is what your deny
patterns (`PAM_COMMAND_DENY_FILE`) and, if set, your allow-list
(`PAM_COMMAND_ALLOW_FILE`) match — so `^kubectl delete` can be forbidden
fleet-wide, or a read-only site can permit only `^kubectl (get|logs)`, with the
same file that governs SSH and WinRM. A blocked operation never reaches the
cluster, is audited as `command.blocked … path:kubernetes`, and still leaves a
transcript: the attempt is evidence.

**Recording, monitoring and limits** work as they do for WinRM: every operation
is registered in the live-session registry (listed by `GET /api/sessions`,
killable, watchable — a supervisor sees `kubectl> …` and then the result), the
transcript lands in `PAM_RECORDING_DIR` as a `.k8s.log` whose SHA-256 is on the
audit row, and `PAM_REQUIRE_RECORDING` refuses the operation *before* it runs if
no transcript can be written. If the audit write fails after the call reached the
cluster, the result is **withheld** (503) rather than returned unaccounted for.

**TLS.** The API server's certificate is verified against `PAM_K8S_CA_FILE`, or
the system roots when it is unset — there is no trust-any fallback, because every
request carries a bearer token. `PAM_K8S_INSECURE_SKIP_VERIFY=true` exists for
demos and is logged loudly at startup.

**Console:** *Work with Targets* → option **6** (`Run kubectl`) opens the
operation form and shows the cluster's answer.

**Deliberate boundaries (v1):**

- **`exec`, `attach` and `port-forward` are not brokered.** kubectl upgrades
  those to a multiplexed SPDY/WebSocket stream; auditing what crosses it needs a
  stream parser this codebase has no precedent for, so they are documented as
  out of scope rather than half-built. Use the SSH proxy to reach a node, or a
  cluster-side break-glass procedure, when you need an interactive shell in a pod.
- **Bearer tokens only.** Client-certificate credentials are a keypair, not a
  string, and a cluster cannot revoke one — which conflicts with PAMv1's
  revoke-and-rotate model. Use a service-account token (ideally short-lived and
  re-issued by your own automation into the vault).
- **No discovery.** The API version is explicit (defaulting to `v1`) rather than
  resolved from the cluster's discovery endpoints, so one operation is one
  request, nothing caches staleness, and CRDs work immediately.
- **One `k8s_token` per target** is what the broker uses; a target may still hold
  `file` credentials (a kubeconfig kept for humans, a CA bundle) — they are never
  sent as a bearer token.
- **Not verified against a real cluster** in this environment — the mechanism is
  proven end to end against an in-process API server that accepts only the
  vaulted token; see [EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md).

Audit: `k8s.run` (target, service account, the command, the cluster's status,
the transcript + its hash), `k8s.denied` (target policy / vendor contract),
`k8s.refused` (recording required), `k8s.error` (the call never got an answer),
plus `command.blocked` and the usual `access.denied` from the shared gates.

### Outbound-only endpoint agents — reaching targets PAMv1 cannot dial (Phase 153)

Every session path above has PAMv1 **dialing out** to the target. For a target
that has no reachable listening port at all — a NAT'd branch box, a CGNAT'd
contractor laptop, an unattended host behind a firewall that admits nothing
inbound, a machine on a network where "open 22 from the PAM" is not an option
— that model cannot work, and a jump host (`PAM_SSH_JUMP_*`) does not help
either: the bastion still has to be able to reach the target. Phase 153
inverts the direction for exactly that endpoint (BeyondTrust "Jump
Client"-style): a small **`pam-agent`** binary on the endpoint dials **out** to
PAMv1's existing SSH listener (`:2222`), authenticates as
`endpoint-agent:<name>` with its own bearer key, requests a **reverse tunnel**
(RFC 4254 `tcpip-forward`, the mechanism behind `ssh -R`), and holds it open.
From then on, when an operator connects to that target, the proxy opens a
stream **back through the agent's connection** instead of dialing the target,
and runs its ordinary upstream SSH handshake over it — JIT credential
injection, recording, live monitoring, command control and every admission
gate are exactly as for a directly dialed target. The operator's experience
is unchanged (`ssh -p 2222 root@branch-box@pam-host`).

**Turn it on** with `PAM_ENDPOINT_AGENTS_ENABLED=true` (default off, the same
posture as `PAM_SCIM_ENABLED`: a new bearer-key identity on a public listener
is not accepted by default). Then, per endpoint:

1. Create the target as usual (menu 1 / `POST /api/targets`, protocol `ssh`)
   with the host:port **as seen from the endpoint itself** — normally
   `127.0.0.1:22`, since the agent delivers each tunneled stream to its own
   local sshd. That address is what PAMv1 pins in `PAM_SSH_KNOWN_HOSTS` and
   writes in the audit trail; it is never dialed by PAMv1.
2. Register the agent — menu **28** (*Work with endpoint agents*), F6, or:

   ```bash
   curl -s -XPOST -H "X-API-Key: $KEY" $PAM/api/endpoint-agents \
     -d '{"name":"branch-agent","target_id":42}'
   # → {"id":7,"name":"branch-agent","target_id":42,"key":"<shown once>","login":"endpoint-agent:branch-agent",...}
   ```

   The key is shown **once**; only its SHA-256 hash is stored. **One live agent
   per target**: a second registration is refused (409) until the first is
   revoked, and while an unrevoked agent exists the target is reached **only**
   through it — an offline agent means "target unreachable" (`session.error
   … endpoint agent "branch-agent": endpoint agent is not connected`), never a
   silent fallback to a direct dial. SSH targets only in v1.
3. On the endpoint, run `pam-agent` (a static binary from the GitHub Release
   assets — `pam-agent_linux_amd64` / `_arm64` with `SHA256SUMS` — or `go
   build ./cmd/pam-agent`), configured by environment:

   ```bash
   PAM_AGENT_SERVERS=pam.example.com:2222        # comma-separated; HA: list EVERY replica (one tunnel each)
   PAM_AGENT_NAME=branch-agent
   PAM_AGENT_KEY=<the key shown once>
   PAM_AGENT_LOCAL_ADDR=127.0.0.1:22             # the ONE address tunneled streams are delivered to (default)
   PAM_AGENT_SERVER_HOST_KEY="$(ssh-keyscan -p 2222 pam.example.com 2>/dev/null | cut -d' ' -f2-)"
   ./pam-agent
   ```

   `PAM_AGENT_SERVER_HOST_KEY` is **required**: the agent verifies PAMv1's SSH
   host key (one key cluster-wide, under shared custody, so a single value
   covers every replica) and refuses to run without it — a network attacker
   who could impersonate pam-server would otherwise harvest the agent key.
   `PAM_AGENT_INSECURE_SKIP_HOST_KEY=true` exists for demos only and is
   logged loudly. The agent reconnects with exponential backoff (1 s → 60 s)
   after any failure, sends `keepalive@openssh.com` every 30 s so a silently
   dropped NAT mapping is noticed, and logs to stdout
   (`PAM_AGENT_LOG_LEVEL`/`_FORMAT`, like pam-server).

Menu 28 lists every agent with **this replica's** live view — `connected`
(with remote address and since-when), `offline`, or `revoked` — plus last-seen.
`GET /api/endpoint-agents` returns the same (never a key hash). **Revoke** with
option 4 / `DELETE /api/endpoint-agents/{id}`: the key stops authenticating,
the live tunnel on this replica is dropped at once (not left to linger until
the next reconnect), and the target is free to bind a fresh agent — or, once
no unrevoked agent remains, is dialed directly again. Revocation is a
soft-delete (history is kept); deleting the target cascades to its agents.

What the design guarantees, and what it does not:

- **The agent is the authority on what it exposes.** pam-server never tells it
  where to dial; it can only open a stream that lands on the agent's own
  `PAM_AGENT_LOCAL_ADDR`. A compromised pam-server therefore cannot use an
  agent as a pivot into the endpoint's network.
- **The agent's connection carries nothing toward PAMv1.** It may open no
  channels (a session or `direct-tcpip` attempt is refused), may request only
  one `tcpip-forward` (a second is refused), `cancel-tcpip-forward` and
  keepalives; it holds no capability set and is never an `auth.Principal`.
  Conversely an operator's connection cannot register a forward — its global
  requests are discarded as before.
- **The credential never reaches the agent.** The tunnel carries the proxy's
  own encrypted SSH handshake to the local sshd; the vaulted secret is inside
  it. `PAM_SSH_KNOWN_HOSTS` still pins the target's host key by the address on
  the target row.
- **Per replica.** An agent's TCP connection terminates on one process, so a
  replica the agent is not connected to reports it offline and cannot reach
  it — which is why `PAM_AGENT_SERVERS` takes a list. Point every agent at
  every replica.
- Not an "endpoint privilege management" agent (PAMv1's documented non-goal):
  it elevates nothing, installs nothing, and does nothing on the endpoint but
  pipe bytes to one local port. Not to be confused with the AI-agent broker's
  agent keys (menu 26) either.
- Not verified against a real NAT/CGNAT path in this environment — the whole
  mechanism is proven in-process against a real upstream sshd (see
  [EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md)).

Audit: `endpoint_agent.create` / `endpoint_agent.revoke` (admin actions),
`endpoint_agent.connected` / `endpoint_agent.disconnected` /
`endpoint_agent.auth_failed` (the agent's own connection, actor
`endpoint-agent:<name>`, with `reason:` unknown-key / name-mismatch / revoked /
disabled on a refusal), and the operator's `session.start` row gains
`via:endpoint-agent:<name>` when the session rode a tunnel.

### Windows targets (WinRM)

Create a Windows target (`os_type=windows`, `protocol=winrm`, port `5986` for
HTTPS) with a credential (an AD-joined domain account like `CONTOSO\\svc-admin`
works). Users with the connect capability run commands through PAMv1 — the
credential is injected just-in-time and never shown:

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/targets/1/winrm \
  -d '{"command":"whoami; hostname"}'
# → {"target":"win-01","exit_code":0,"stdout":"contoso\\svc-admin\r\n...","stderr":""}
```

Every run is recorded (a `.winrm.log` transcript with its SHA-256 in the audit as
`winrm.run`). WinRM uses HTTPS by default (`PAM_WINRM_HTTPS`); only set
`PAM_WINRM_INSECURE_SKIP_VERIFY=true` in isolated dev. Most AD-joined hosts
disable basic auth — set `PAM_WINRM_AUTH=ntlm` for NTLMv2.

### RDP (via Apache Guacamole)

PAMv1 brokers RDP through [Apache Guacamole](https://guacamole.apache.org/)'s
`guacd` daemon so the operator sees the desktop but never the password — PAMv1 is
a **client** of guacd, not a Guacamole server.

**guacd now ships with the deploys.** The Docker compose (`deploy/docker/`) runs a
hardened `guacd` service and wires `PAM_GUACD_ADDR=guacd:4822` for you; the raw
Kubernetes manifests include `deploy/k8s/guacd.yaml` (`kubectl apply -f deploy/k8s/`
picks it up); and the Helm chart adds it when you set `guacd.enabled=true`. In all
cases guacd is **internal-only** (no external port) and reached on `:4822`. To use
your own daemon instead, point `PAM_GUACD_ADDR` at it:

```bash
PAM_GUACD_ADDR=guacd:4822       # bundled; or host:port of your own guacd
```

By default guacd **verifies the RDP server certificate** and negotiates the
security mode. For self-signed or legacy hosts, opt out or pin the mode:

```bash
PAM_GUACD_RDP_SECURITY=nla     # force a mode (nla|tls|rdp); empty = negotiate
PAM_GUACD_IGNORE_CERT=true     # dev only — skip RDP server-cert verification
```

**Clipboard control (Phase 33).** Guacamole leaves the RDP clipboard on in both
directions by default — an operator can copy data out of, or paste into, a
recorded session with no gate. `PAM_RDP_CLIPBOARD` restricts it (drive
redirection is *always* disabled, so no file can be exfiltrated via a mounted
client drive):

```bash
PAM_RDP_CLIPBOARD=allow        # copy + paste both on (default)
PAM_RDP_CLIPBOARD=readonly     # block paste INTO the target (no clipboard injection); copy-out stays on
PAM_RDP_CLIPBOARD=deny         # clipboard off in both directions
```

**Per-target tightening** (Phase 33 follow-on): a target's `rdp_clipboard`
field (portal *Change Target*, or the create/update API) overrides the global
for that one target, and the **stricter** policy always wins
(`allow < readonly < deny`) — a high-sensitivity target can deny what the fleet
allows, but no target row can loosen a global `deny`. The same shape applies to
`rdp_clipboard_audit` (whichever records more wins; remember `full` records
clipboard *content*, which is an exposure to choose deliberately).

The active — effective — mode is recorded in the `rdp.connect` audit event
(`clipboard:<mode>`).

**Clipboard auditing (Phase 50).** Gating says what *may* cross; auditing says
what *did*. `PAM_RDP_CLIPBOARD_AUDIT` records each transfer as an
`rdp.clipboard` event:

```bash
PAM_RDP_CLIPBOARD_AUDIT=off    # no clipboard auditing (default)
PAM_RDP_CLIPBOARD_AUDIT=meta   # direction, mimetype, byte count, SHA-256
PAM_RDP_CLIPBOARD_AUDIT=full   # the above plus the content (truncated)
```

`direction:out` is data copied **from** the target to the operator;
`direction:in` is data pasted **into** the target. The SHA-256 lets you match
two transfers (the same secret copied twice, or leaving one host and arriving
on another) without recording either.

**Think before choosing `full`.** A privileged desktop's clipboard routinely
holds a password the operator just copied out of the vault, and the audit trail
is readable by every auditor — recording content can create exactly the exposure
this system exists to prevent. Use `meta` unless a specific regulatory
requirement demands the content, and if you do use `full`, treat the audit trail
as secret material (it is capped at 4 KiB per transfer, and 1 MiB is buffered
for the digest, flagged `truncated:true` past that).

Auditing never blocks or alters a transfer — that is the `PAM_RDP_CLIPBOARD`
gate's job. It observes the same stream the viewer sees.

Create the target with `protocol=rdp`, port `3389`, and a credential. The
WebSocket endpoint `GET /api/targets/{id}/rdp?token=<token>` decrypts the
credential just-in-time, injects it into the guacd handshake, and tunnels the
Guacamole protocol to the browser (`rdp.connect` / `rdp.end` in the audit).

**The in-portal viewer is built in.** The portal vendors the Apache Guacamole
JavaScript client ([guacamole-common-js](https://guacamole.apache.org/), served
same-origin from `/static/guacamole-common.min.js`; see the repo `NOTICE`) and
renders the desktop on a canvas:

- An operator opens *Work with Targets*, types option **7** on an RDP target, and
  the viewer fills the screen; `Ctrl+Alt+Q` disconnects.
- The browser first `POST`s `/api/rdp-token` (requires **connect**) for a
  **60-second** token — browsers can't set headers on a WebSocket handshake, so
  this keeps the operator's long-lived key out of the URL. Minting is audited as
  `rdp.token`.
- The credential still only ever reaches guacd; the browser receives pixels.

The tunnel remains usable by any Guacamole-compatible client too. For the full
verification procedure (automated tests + a manual runbook) see
[RDP-TESTING.md](RDP-TESTING.md).

### Database targets (PostgreSQL)

The database session proxy (Phase 15) extends the same JIT chokepoint to
**PostgreSQL**: an operator connects with `psql` and their PAM token, the proxy
injects the vaulted database credential, and **every SQL statement is audited**
(`db.query`) and recorded. The operator never sees the database password. Enable
the listener:

```bash
PAM_DB_ADDR=:5433     # off by default
```

Create a `postgres` target and a credential for the database login:

```bash
curl -sX POST https://pam.example/api/targets -H "X-API-Key: $PAM_API_KEY" \
  -d '{"name":"appdb","host":"10.0.0.20","port":5432,"os_type":"linux","protocol":"postgres"}'
# then POST /api/targets/{id}/credentials with the DB username + password
```

Operators then connect through the proxy — the username selects the credential
and target, the password is their PAM token (or per-user token):

```bash
psql "host=pam.example port=5433 user=dbuser@appdb dbname=orders"
# Password: <your PAM token>
```

The proxy runs the same authorization gates as the SSH proxy (role capability,
per-target grants, protocol allowlist, the 4-eyes/approval gate, **and the MFA
enrollment gate** — an enroll-only session can't open a DB session either), then
authenticates upstream with the vaulted secret — supporting **SCRAM-SHA-256**
(PostgreSQL 14+ default, with the server signature verified), MD5, and cleartext.

**Harden both legs of the proxy:**

- *Upstream (target) leg* — set `PAM_DB_UPSTREAM_CA` (a pinned CA bundle) or
  `PAM_DB_UPSTREAM_TLS_VERIFY=true` to **verify the database's TLS certificate**,
  so the JIT-injected credential can't be harvested by a MITM. Left unset, the
  upstream connection is trust-any (logged loudly at startup).
- *Operator-facing leg* — set `PAM_TLS_CERT`/`PAM_TLS_KEY` to encrypt it (or
  terminate TLS at the ingress); the PAM key would otherwise travel in cleartext.
  Set `PAM_REQUIRE_DB_CLIENT_TLS=true` to refuse to start without it.

Sessions appear in *Work with active sessions* (protocol `postgres`) and can be
killed like any other. MySQL/MSSQL/Oracle are follow-on connectors on the same
pattern.

### Zero Standing Privilege: ephemeral database roles (Phase 129)

Extends Phase 22's SSH-only ZSP to **PostgreSQL**: instead of a stored,
standing database credential, PAMv1 mints a fresh, randomly-named role with a
random password at connect time, connects the operator's session as that
role, and drops it the instant the session ends — no vaulted secret exists
for the connecting identity at all. This needs two credentials on the
target: one real, vaulted **provisioner** credential with enough privilege to
`CREATE ROLE`/`DROP ROLE` (never itself ZSP), and one `db_zsp` credential —
the connect-time slot operators actually use — which stores nothing:

```bash
# 1. The provisioner: a real password credential, flagged as this target's
#    role-provisioning identity. Exactly one per target — a second is
#    refused at connect time, not silently picked.
curl -sX POST https://pam.example/api/credentials -H "X-API-Key: $PAM_API_KEY" \
  -d '{"target_id":1,"username":"pamv1_provisioner","secret":"...","provisioner":true}'

# 2. The db_zsp credential operators actually connect as — no "secret" field.
curl -sX POST https://pam.example/api/credentials -H "X-API-Key: $PAM_API_KEY" \
  -d '{"target_id":1,"username":"zsp","secret_type":"db_zsp"}'
```

```bash
psql "host=pam.example port=5433 user=zsp@appdb dbname=orders"
# Password: <your PAM token>
# → connects as a freshly minted pamv1_zsp_<random> role, dropped on disconnect
```

Provisioning (`CREATE ROLE ... WITH LOGIN PASSWORD ... VALID UNTIL ...`, a
30-minute hard ceiling independent of teardown succeeding) and teardown
(`DROP ROLE`) both run over their own short-lived connection as the
provisioner — the operator's real session dials the target only as the
ephemeral role, never as the provisioner. New audit actions
`db.zsp_provisioned`/`db.zsp_provision_failed`/`db.zsp_teardown`/
`db.zsp_teardown_failed`. **SQL Server is not supported** — `internal/tds`
has no client-side response-token reader yet (it only ever parses what a
*client* sends), a genuine follow-on tracked in
[ROADMAP.md](../ROADMAP.md#what-is-left-). **RDP has no ZSP path at all**:
Guacamole's RDP implementation has no certificate/smartcard authentication
parameter for the RDP protocol itself (confirmed against its own
documentation) — a permanent limitation of guacd/FreeRDP, not an
infrastructure gap more hardware would resolve.

### Database targets (SQL Server)

Phase 53 adds the TDS sibling of the PostgreSQL proxy. Same gates, same guards,
same recording and live monitoring — a different wire protocol.

```bash
PAM_MSSQL_ADDR=:1433   # off by default
PAM_TLS_CERT=/etc/pamv1/tls.crt   # strongly recommended: modern TDS clients
PAM_TLS_KEY=/etc/pamv1/tls.key    # REQUIRE encryption and refuse a plaintext proxy
```

Create the target with `protocol: "mssql"` (port 1433) and a password credential
holding the SQL login. Operators then connect:

```bash
sqlcmd -S pam.example,1433 -U 'sql_svc@sql-01' -P "$PAM_TOKEN" -d orders -N -C
# URL-style clients must percent-encode the '@':
#   sqlserver://sql_svc%40sql-01:$PAM_TOKEN@pam.example:1433?database=orders
```

- **Every statement is audited** as `db.query … via:mssql`, including statements
  drivers send through `sp_executesql` — command control and step-up see through
  that wrapper, so a denylist is not bypassed by using a parameterised client.
- **Both legs are encrypted** when TLS is configured; `PAM_DB_UPSTREAM_CA` /
  `PAM_DB_UPSTREAM_TLS_VERIFY` make the target leg fail-closed, which matters
  more here than anywhere: TDS password "obfuscation" is a keyless nibble swap.
- **A statement the proxy cannot read is refused** when `PAM_COMMAND_DENY_FILE`
  is set (audited `command.blocked … pattern:unreadable-parameters`). Command
  control that cannot see a statement is not command control, so it fails
  closed; without a deny file configured the call is audited and forwarded.
- **SQL authentication only.** Integrated/Windows auth is refused with a clear
  message — brokering means swapping the operator's PAM key for a vaulted SQL
  login, which SSPI cannot express; federated-auth tokens in the login's feature
  extension are stripped for the same reason. TDS 8.0 *strict* encryption is
  also refused (use `Encrypt=Mandatory`).
- **The target leg must be encrypted.** If the SQL Server declines encryption the
  session is refused rather than sending the vaulted credential under TDS's
  keyless "obfuscation". Every supported SQL Server offers encryption.
- **Interop caveat:** the proxy is proven against a hand-rolled fake upstream and
  a spec-pinned codec, but **has not been tested against a real SQL Server**.
  Treat the first deployment as a pilot — see
  [EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md).

## 7. Managing users & roles

Only `admin` may manage users. Creating a user returns the access token **once** —
store it immediately; it cannot be retrieved again (only its hash is kept).

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/users \
  -d '{"username":"alice","role":"user"}'
# → {"id":1,"username":"alice","role":"user","token":"pamt_…"}

curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/users          # list (no tokens)
curl -H "X-API-Key: $PAM_API_KEY" -X DELETE http://localhost:8080/api/users/1
```

**Revoking active logins.** Deleting a user removes their local token, but
directory (AD/SSO/OIDC) logins create short-lived *login sessions*, not user
rows — so disabling someone upstream leaves their session valid until it expires.
List and force-revoke those (admin / `CapManageUsers`):

```bash
# See who is currently logged in (never shows token hashes)
curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/login-sessions

# Force-invalidate every active login session for a user (e.g. a compromised or
# deprovisioned account) — takes effect immediately, not at TTL expiry
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/login-sessions/revoke \
  -d '{"username":"bob"}'
# → {"username":"bob","revoked":2}
```

`POST /api/identity/reconcile` also revokes the login sessions of any directory
user it finds disabled/absent, so a scheduled reconcile deprovisions logins too.

Revocation now also **terminates in-flight target sessions**, not just login
tokens: revoking a user's login (or disabling them in the directory) kills their
live SSH/DB/RDP sessions, and deleting a *user* grant to a target kills that
user's session to that target (sessions to still-authorized targets keep running).
Deleting a *role* grant only affects new connections. In a multi-replica
deployment the kill is broadcast over the store's kill bus (Phase 34), so it cuts
the session on whichever replica hosts it (see the HA notes in
[SECURITY-GAPS.md](SECURITY-GAPS.md)).

### Roles at a glance

| Role | Manage targets/creds/users | Reveal secret | Connect via proxy | Read audit | Approve requests* |
|---|:--:|:--:|:--:|:--:|:--:|
| `admin` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `user` | — | — | ✅ | — | — |
| `auditor` | — | — | — | ✅ | — |
| `approver` | — | — | — | ✅ | ✅ |

`*` the `approver` role wields the 4-eyes access-request approval workflow (shipped in Phase 8).

Give the user their token; they use it in the portal Sign On or as the SSH proxy
password (see the [User Guide](USER-GUIDE.md)).

### Custom permission profiles (Phase 12)

Beyond the four built-in roles you can define **named capability sets** and assign
them to users exactly like a role. Manage them under **menu 12 — Work with
permission profiles** (or `POST/GET /api/profiles`, `DELETE /api/profiles/{id}`;
`manage_users`). A profile is a name plus any subset of the capability vocabulary
— `read_inventory`, `manage_targets`, `manage_credentials`, `reveal_secret`,
`connect`, `read_audit`, `manage_users`, `approve`, `call_tool`. A profile name may
not collide with a built-in role. When adding a user, the role/profile picker lists
the built-in roles followed by your custom profiles; the built-in roles are
unchanged, so existing users are unaffected.

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/profiles \
  -d '{"name":"ops-readonly","capabilities":["read_inventory","read_audit"]}'
# then assign it:
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/users \
  -d '{"username":"dana","role":"ops-readonly"}'
```

### CIDR/network source-address allowlist (Phase 118)

Restrict a local user (bearer-token) principal to connecting only from chosen
networks — set at creation or update time as a comma-separated list of CIDR
blocks. Empty (the default) means unrestricted. It's enforced everywhere that
principal authenticates: every REST call — including the authenticated-only
routes (`/api/me`, MFA enrollment) and the RDP/VNC viewer tunnel, which ran
no source check until v0.58.2 — every session-proxy connect
(SSH/PostgreSQL/SQL Server), and every **session token** minted for the user
(a browser-extension or viewer token inherits the list; before v0.58.2 it
carried none) — a refusal there fails the *session*, not just the login,
matching the enforcement point CyberArk/Wallix call "network
areas"/`ip_source`.

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/users \
  -d '{"username":"alice","role":"user","ip_allowlist":"10.0.0.0/8, 192.168.1.0/24"}'

# Update later — omit ip_allowlist to leave it untouched (e.g. a role-only
# change); send it explicitly, even as "", to change or clear it:
curl -H "X-API-Key: $PAM_API_KEY" -X PUT http://localhost:8080/api/users/1 \
  -d '{"role":"user","ip_allowlist":""}'   # clears the restriction
```

Break-glass access is exempt, like every other admission gate — an emergency
login is already loudly audited on its own. Directory (AD/SSO/OIDC) logins
have no backing local-user row to hold a list, so they are unaffected in v1.
If you sit behind a reverse proxy, `PAM_TRUSTED_PROXY_HOPS` must already be
set correctly (§3.6) or the resolved source address will be the proxy's, not
the operator's.

### Device-aware access control (Phase 133)

Two independent, opt-in checks close StrongDM's live EDR-posture gate and a
rescoped Teleport device-identity binding — both re-checked on **every**
connect and every authenticated call, not just at login, since either can
change mid-session.

**Live device posture.** Set `PAM_POSTURE_ATTEST_URL` to your EDR/posture
system's webhook (CrowdStrike, Defender, SentinelOne, or anything that
answers HTTP). PAMv1 `POST`s `{"user":"<username>"}` and requires a `2xx` for
the device to be considered healthy; anything else refuses the request. Unset
(the default), no check ever runs. Because this is a live outbound endpoint,
it also joins the `PAM_OT_AIRGAP` conflict list — an air-gapped deployment
that sets it without adding it to `PAM_OT_AIRGAP_ALLOW` is refused at
startup, the same as every other webhook this guide documents.

**Device-identity binding.** Set `PAM_DEVICE_HEADER` to the name of a header
your TLS-terminating reverse proxy injects with the client certificate's
fingerprint (nginx's `$ssl_client_fingerprint`, or your ingress's equivalent)
— **only if that proxy performs real mTLS and strips any client-supplied
copy of the header first**; PAMv1 trusts the value verbatim. Enroll a user's
fingerprint the same way you set their IP allowlist:

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/users \
  -d '{"username":"alice","role":"user","device_fingerprint":"AA:BB:CC:..."}'

# Update later — omit device_fingerprint to leave it untouched; send it
# explicitly, even as "", to change or clear it:
curl -H "X-API-Key: $PAM_API_KEY" -X PUT http://localhost:8080/api/users/1 \
  -d '{"role":"user","device_fingerprint":""}'   # clears the binding
```

A user with no enrolled fingerprint is unaffected even when
`PAM_DEVICE_HEADER` is set deployment-wide. This check reaches every REST
call (RDP/VNC token minting, WinRM exec, account discovery, and every
`authz`-gated route) but **not** a raw `ssh`/`psql`/`sqlcmd` connection —
the session proxies are wire-protocol listeners with no HTTP layer for a
reverse proxy to inject a header into, a permanent limitation of the
approach, not a missing feature. Posture has no such gap: it covers the
session proxies too.

Break-glass is exempt from both, like every other admission gate. Neither
check ever applies to the AI-agent broker's own tool calls (§7's
"AI-agent access broker" below), which authenticate on a separate path.

### SCIM 2.0 user provisioning (Phase 149)

`POST /api/identity/reconcile` is **pull**: PAMv1 asks your directory who's
still enabled, on your schedule. SCIM is the **push** complement — your IdP
tells PAMv1 the moment a user is created, renamed, or deprovisioned, without
waiting for the next reconcile. Both mechanisms can run side by side.

**Turn it on.** Set `PAM_SCIM_ENABLED=true` (default off — this is a new
bearer-key surface most deployments have no IdP to speak it, so it stays
opt-in like `PAM_APP_SECRETS_ENABLED`). Then mint a SCIM client key
(`manage_users`, the token is shown once):

```bash
# console menu 29 mints, lists and revokes these (Phase 187)
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/v1/scim-keys \
  -d '{"name":"okta","owner":"identity-team"}'
# → {"id":1,"name":"okta","owner":"identity-team","token":"pamt_…"}
```

Give the token to your IdP's SCIM connector as an **OAuth Bearer Token**
(the auth scheme `GET /scim/v2/ServiceProviderConfig` advertises), and point
it at `https://your-pamv1-host/scim/v2` as the base URL — most IdPs append
`/Users` themselves. Revoke with `DELETE /v1/scim-keys/{id}`, the same as
revoking an app key.

**What a SCIM key can and cannot do.** It authenticates outside PAMv1's
normal RBAC entirely — it is not an `admin`/`user`/`auditor`/`approver`
principal and holds none of their capabilities, only the ability to
create/read/update/deactivate the user roster over `/scim/v2/Users`. Every
user it provisions gets the fixed, least-privileged built-in `user` role;
there is no way for a SCIM payload to request `admin` or any other role —
promote a SCIM-provisioned user the normal way afterward
(`PUT /api/users/{id}`) if they need more.

**Deactivation actually cuts access.** `PATCH .../active:false` (or
`DELETE`, which does the same thing — see below) immediately blocks that
user's own local PAMv1 token: their next authenticated call gets a plain
401, exactly like an unknown token, not just a cosmetic flag flip — **and,
since v0.58.2, every session that user already held** (a browser-extension
token, a viewer token) is revoked and their live proxied sessions killed,
audited as `session.revoked reason:deactivated`. Until then those sessions
ran on until they expired. `DELETE /api/users/{id}` and a role change do the
same (`reason:user-deleted` / `reason:role-changed`). Directory
(AD/SSO/OIDC) logins are unaffected by this switch — govern those the way
you already do, with `POST /api/identity/reconcile` or upstream directory
disablement. Reactivating (`active:true`) restores access on the **same**
token — nothing is ever re-minted, so there's nothing new to hand back to
the user.

`DELETE /scim/v2/Users/{id}` is a **soft** delete — it sets `active:false`
exactly like a PATCH, never removing the row. This is deliberately
different from `DELETE /api/users/{id}`, which still hard-deletes: SCIM's
whole provisioning model expects a deprovisioned identity to be
reactivatable later, which a hard delete would foreclose.

**A SCIM-provisioned user's local PAMv1 token is never handed back over
SCIM.** One is minted internally (every user row needs one), but SCIM's
schema has no field for a bearer secret, and the realistic expectation is
that this user signs in through the same IdP doing the provisioning
(AD/Entra/OIDC), not a standalone PAMv1 credential. If you specifically need
one, mint it the normal way instead: delete and re-create the user via
`POST /api/users`.

**Idempotent provisioning.** Before creating a user, a well-behaved IdP
checks whether one already exists — `GET /scim/v2/Users?filter=userName eq
"alice"` (or `externalId`) — and PAMv1 answers with an empty result set
(`totalResults:0`), not an error, when there's no match. This is the one
filter shape this server understands; it does not implement SCIM's full
filter grammar.

> ⚠️ **Not interactively verified against a real IdP in this environment**
> (no Okta/Azure AD/OneLogin account available). The wire behavior — both
> RFC 7644's standard `PATCH` shape and Azure AD's documented "no path,
> attributes directly in `value`" variant — is implemented and tested
> against a hand-rolled fake, per [EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md).
> Test your own IdP's connector against a non-production PAMv1 instance
> before relying on it.

### Safes: delegated-access containers (Phase 17)

A **safe** groups targets and delegates who may reach them — the container model
CyberArk builds its authorization around. A member of a safe may connect to
**every target in the safe**, an authorization path alongside per-target grants;
a `can_manage` member is a **delegated safe administrator** who can add/remove
members of that safe without being a global target manager.

```bash
# create a safe, add a role member, and place a target in it
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/safes \
  -d '{"name":"prod-linux","description":"production Linux estate"}'      # → {"id":1,...}
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/safes/1/members \
  -d '{"subject_type":"role","subject":"user","can_manage":false}'
curl -H "X-API-Key: $PAM_API_KEY" -X PUT http://localhost:8080/api/targets/7/safe \
  -d '{"safe_id":1}'      # target 7 is now reachable only by safe members
```

All of this is also operable from the console: **Work with Safes** (menu 16)
lists/creates/deletes safes and manages members, and **Work with Targets**
option **8** assigns a target to (or clears it from) a safe.

Placing a target in a safe **restricts** it to the safe's members (plus any
direct grants) — an empty safe leaves its targets open. Clear a target's safe
with `{"safe_id":null}`. Delegate ownership by adding a `can_manage` member; they
can then manage that safe's membership (`POST`/`DELETE /api/safes/{id}/members`)
even as a non-admin.

**Safe-scoped approval policy (Phase 58).** A safe also carries its own access
policy, binding **every target in it** — so "everything in the production safe
needs two approvers" is one setting rather than a flag on each target that the
next onboarding forgets:

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X PUT http://localhost:8080/api/safes/1 \
  -d '{"name":"prod-linux","require_approval":true,"min_approvers":2}'
```

- `require_approval` — every target in the safe needs an approved access
  request, whatever the target's own flag says.
- `min_approvers` — **dual control**: that many *distinct* approvers must sign
  a request before it is granted (0 = no safe floor; the maximum is 10).
  Setting a floor implies `require_approval`.

Two properties worth knowing:

- **Strictest wins.** A safe can only *tighten* the global `PAM_REQUIRE_APPROVAL`
  and the per-target flag. There is deliberately no way for a safe to exempt a
  target the global policy gates.
- **The floor is re-read as each approval is cast**, not fixed when the request
  was filed. Raising a safe's floor therefore binds requests that are already
  waiting — otherwise anyone could file early and collect the old number of
  approvals afterwards. The floor also applies at request time, so a requester
  cannot ask for fewer approvers than the safe demands.

Both fields are on the console's **Work with Safes** add and change screens, and
the list shows an **Approval** column. Changing them is audited (`safe.update`
records the policy), because it changes who may reach everything inside.

### Personal/private safes (Phase 139)

A safe can be marked **personal** — private even from admins by default,
Delinea's personal-folders model. This changes a real invariant: every
*other* safe still admits any admin unconditionally, exactly as before;
a personal one does not.

```bash
# Creating a personal safe REQUIRES an owner — they are seeded as its
# first can_manage member in the same call, so the safe is never created
# in an unmanageable, memberless state.
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/safes \
  -d '{"name":"alice-personal","personal":true,"owner":"alice"}'

# alice now owns it and manages her own roster like any can_manage member
# — no different capability needed for that part.
curl -H "X-API-Key: $ALICE_TOKEN" -X POST http://localhost:8080/api/safes/9/members \
  -d '{"subject_type":"user","subject":"bob"}'

# A plain admin key, with no membership and no override, is refused —
# both to CONNECT to a target in the safe and to REVEAL/checkout a
# credential in it:
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/42/reveal
# → 403 not authorized for this target
```

- **Writes are bounded too** (v0.58.2): a plain `manage_targets` /
  `manage_credentials` profile can neither add a credential to, delete a
  credential of, nor delete a target that sits in someone else's personal
  safe — the owner, a `can_manage` member, the override, or a built-in admin
  (who provisions personal safes in the first place) can. A write reveals
  nothing, which is why the admin is admitted here and refused at reveal.
- **`personal` is set only at creation and cannot be changed afterward** —
  `PUT /api/safes/{id}` never touches it, at the store layer, regardless
  of what the request body says. A rename or approval-policy edit can
  never accidentally un-personalize a safe.
- **The override is a named, narrow capability, not a role.**
  `unlimited_vault_access` lets its holder reach a personal safe as if
  they were a member — but it is deliberately **not** part of the built-in
  `admin` role. Grant it through a [custom permission
  profile](#custom-permission-profiles-phase-12) to a specific person (a
  security lead, an incident responder), the same way you would grant any
  other narrow capability:
  ```bash
  curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/profiles \
    -d '{"name":"vault-override","capabilities":["read_inventory","connect","reveal_secret","unlimited_vault_access"]}'
  curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/users \
    -d '{"username":"security-lead","role":"vault-override"}'
  ```
  Using it is **audited loudly** — `safe.personal_override_used`, naming
  the target — mirroring how break-glass access is always loudly audited.
  In v1 that extra audit line covers the REST paths (reveal, checkout, the
  RDP/VNC token mint); the raw SSH/PostgreSQL/SQL Server proxy connect
  path enforces the identical denial/admission but does not yet add the
  same audit line — see ROADMAP.md Phase 139 for why.
- **Managing a personal safe's own roster also needs the override** (or
  being an existing `can_manage` member) — `manage_targets` alone, enough
  for any *ordinary* safe, is deliberately not enough here. Otherwise a
  target manager could simply add themselves as a member and connect
  normally, defeating the protection through a side door.
- **What stays unaffected.** Inventory listing (`GET /api/targets`,
  `GET /api/credentials`) is unchanged — a personal safe's target and
  credential *metadata* (name, username, that it exists) is visible to
  any `read_inventory` holder exactly like any other safe's; only the
  paths that actually hand back or use the secret are gated. Deleting or
  renaming the safe itself (`DELETE`/`PUT /api/safes/{id}`) stays a plain
  `manage_targets` action, unchanged from before — a lifecycle action, not
  a confidentiality one.
- API/curl-only in v1, not yet on the **Work with Safes** console screens
  — matching `ssh_ca`/`db_zsp`/DoubleLock's own precedent of not adding
  every new concept to the 5250 UI immediately.

### Dependent accounts: safe service-account rotation (Phase 17)

When a service account's password rotates, the **Windows Services, Scheduled
Tasks and IIS App Pools** that log on with it must be updated too — otherwise
rotation breaks production. Declare those consumers and PAMv1 updates each over
WinRM after the rotation:

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/3/dependencies \
  -d '{"kind":"windows_service","host":"app-01","name":"MyAppSvc","management_credential_id":7}'
# kinds: windows_service | scheduled_task | iis_apppool ; port defaults to 5985 (WinRM)
```

On the next rotation of credential 3, PAMv1 sets the new password on the target,
re-vaults it, then runs the appropriate WinRM command on each consumer's host
(`sc.exe config` / `schtasks /Change /RP` / `appcmd …processModel.password`) with
the new secret. A propagation failure is audited (`credential.dependency_failed`)
but does **not** fail the rotation — the new secret is already vaulted, so the
fix is to update the stale consumer, not to roll back.

**Which account does the updating (Phase 61).** `management_credential_id` names
the credential PAMv1 **logs into that host as** to make the change. Set it.
Without it, PAMv1 connects as the service account it is rotating, which means
that account needs remote-management and local-administrator rights on the
consumer's host — the opposite of what a service account should hold, and
hardened ones usually cannot log on remotely at all, so propagation fails
exactly where you need it. It also leaves nothing to stand on when you are
rotating *because* the account is broken.

- The credential is decrypted just-in-time, like every other use, and the audit
  records which one was used (`managed_via:credential:7`) — never its secret.
- An id that names no credential is refused **when you declare the dependency**
  (422), not silently at 3am during an unattended rotation.
- **Naming a credential here is a use of it (Phase 61a).** PAMv1 will present
  that password to the `host` you give on the same request, so declaring the
  dependency requires the same authorization as revealing the credential:
  the `reveal_secret` capability, a grant on **that credential's own target**,
  an approved access request if that target requires one, and an in-contract
  vendor grant if you are a vendor. A refusal is audited as
  `dependency.create_denied` with the reason. Without this the reference was an
  exfiltration route: `manage_credentials` alone could point any credential in
  the vault at any host.
- The credential must **hold a password** (422 otherwise). An SSH key sent as a
  WinRM password authenticates nothing and hands the whole private key to the
  consumer's host; a zero-standing-privilege (`ssh_ca`) credential holds no
  secret at all. Both are also refused at use time, so a row written straight
  into the database cannot leak one either.
- If you later delete that credential, the update **fails closed**
  (`credential.dependency_failed reason:management-credential-missing`) rather
  than quietly reverting to logging in as the rotated account.
- *Work with Dependent Accounts* in the console shows a **Managed via** column;
  anything reading `this account` in amber is still on the old path.

### Third-party vendor access (Phase 29)

A **vendor** is an external technician who needs narrow, time-boxed access to
specific targets, revocable in one action. They log in like any `user` (local
token or directory), but a vendor's connection is additionally gated by a
**contract grant**: which target, as which account, and for how long. A grant
starts **pending** and grants nothing until the *customer* approves it.

```bash
# 1. Register the vendor (manage_users). This also mints their `user`-role login —
#    the token is returned ONCE, like POST /api/users.
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/vendors \
  -d '{"username":"acme-tech1","org":"ACME Robotics"}'

# 2. File a contract grant: target NAME, the account they may log in as, and the
#    window (manage_targets). not_after is required; not_before defaults to now.
#    $VID is the id returned in step 1.
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/vendors/$VID/grants \
  -d '{"target":"plc-gateway","principal":"svc-maint","not_before":"2026-08-01T08:00:00Z","not_after":"2026-08-01T18:00:00Z"}'

# 3. The customer approves it — $GID is the grant id from step 2 (approve
#    capability; four-eyes, so a vendor can never approve their own grant).
curl -H "X-API-Key: $APPROVER" -X POST http://localhost:8080/api/vendor-grants/$GID/approve
```

Approval runs the **employment attestation** webhook when `PAM_VENDOR_ATTEST_URL`
is set: the vendor-management system answers `2xx` only for a currently-employed
technician, so access is refused the moment their own employer offboards them
(`vendor.attestation_failed`).

The gate is enforced on **every** connect path — SSH proxy, PostgreSQL proxy,
RDP, WinRM runs, and reveal/checkout — so a vendor reaches nothing outside their
contract, and non-vendor users are unaffected. A grant's `principal` binds it to
one login account on the target; omit it for any account.

Ending access:

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/vendor-grants/$GID/revoke
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/vendors/$VID/offboard   # everything, at once
```

**Offboard** disables the vendor, revokes every grant atomically, and kills all
their live sessions — persisted, so a revoked technician can't return after a
restart. Set `PAM_VENDOR_SWEEP_INTERVAL_MIN` so a session is also cut *mid-flight*
when its window closes (`vendor.session_expired`) rather than merely refused at
the next connect.

For an auditor, `GET /api/vendors/{id}/evidence` (`read_audit`) bundles the
vendor's grants with the audit slice attributable to them plus a SHA-256 digest —
a per-vendor SOC 2 / DORA record. Audit vocabulary: `vendor.create` ·
`vendor.grant_created` · `vendor.grant_approved` · `vendor.grant_revoked` ·
`vendor.grant_decision_denied` · `vendor.attestation_failed` · `vendor.offboard` ·
`vendor.session_expired` · `vendor.evidence_export`.

*(The API is complete; a dedicated 5250 console screen is a documented
follow-on — drive it from the REST API for now.)*

### Active Directory login (optional)

Instead of (or alongside) local tokens, users can sign in with their **AD
username + password**. Set `PAM_LDAP_URL` (use **LDAPS**) and map AD groups to
the four roles:

```bash
PAM_LDAP_URL=ldaps://dc.example.com:636
PAM_LDAP_BIND_DN=CN=svc-pam,OU=Service,DC=example,DC=com
PAM_LDAP_BIND_PASSWORD=…            # service account for user search
PAM_LDAP_BASE_DN=DC=example,DC=com
PAM_LDAP_USER_FILTER=(sAMAccountName=%s)
PAM_LDAP_GROUP_ADMIN=CN=PAM-Admins,OU=Groups,DC=example,DC=com
PAM_LDAP_GROUP_USER=CN=PAM-Users,OU=Groups,DC=example,DC=com
PAM_LDAP_GROUP_AUDITOR=CN=PAM-Auditors,OU=Groups,DC=example,DC=com
PAM_LDAP_GROUP_APPROVER=CN=PAM-Approvers,OU=Groups,DC=example,DC=com
```

`PAM_LDAP_INSECURE_SKIP_VERIFY=true` disables LDAPS certificate verification.
It exists for a lab with a self-signed DC certificate and **must never be set in
production** — it would let anything that can answer on port 636 harvest the
credentials PAMv1 binds with. It is deliberately *not* overridable from the
runtime configuration console (§4.1): turning it on requires a restart with a
changed environment, which is auditable at the deployment layer.

How it works: pam-server binds the service account, finds the user, verifies the
password by binding as them, and derives roles from group membership. A user in
several mapped groups keeps **all** of them and is granted the **union** of their
capabilities (not just the single highest role) — e.g. someone in both PAM-Users
and PAM-Auditors can connect *and* read the audit trail. `POST /api/login` then
returns a **session token** (12h) that works in the portal and the SSH proxy
exactly like a per-user token. A user in no mapped group is rejected. Keep the bootstrap `PAM_API_KEY` and break-glass key as
the local emergency path if AD is unreachable.

**Identity reconciliation.** With LDAP configured, revoke PAMv1 access for users
the directory has **disabled** (AD `userAccountControl`), and surface local-only
accounts:

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST "http://localhost:8080/api/identity/reconcile?dry_run=true"
# → {"checked":12,"disabled":1,"dry_run":true,"results":[{"username":"bob","status":"disabled"},…]}
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/identity/reconcile   # actually revoke
```

Disabled directory users are deleted (`user.revoked`); users absent from the
directory are reported `not_in_directory` but **never auto-revoked** (they may be
local service accounts). A directory error never revokes.

### Microsoft Entra ID (Azure AD) login (optional)

For cloud identities, enable Entra ID login alongside or instead of on-prem AD.
PAMv1 uses the OAuth2 **resource-owner-password** grant against your tenant and
reads the user's **app roles** (or group ids) from the token to derive roles —
several matched app-roles/groups grant the **union** of their capabilities, the
same as on-prem AD.

```bash
PAM_ENTRA_TENANT_ID=<tenant-guid>
PAM_ENTRA_CLIENT_ID=<app-registration-client-id>
PAM_ENTRA_CLIENT_SECRET=<client-secret>
# PAM_ENTRA_SCOPE defaults to "<client-id>/.default"
# PAM_ENTRA_AUTHORITY_HOST=login.microsoftonline.com   # sovereign clouds differ
PAM_ENTRA_ROLE_ADMIN=pam.admin      # app role value (or a group object id)
PAM_ENTRA_ROLE_USER=pam.user
PAM_ENTRA_ROLE_AUDITOR=pam.auditor
PAM_ENTRA_ROLE_APPROVER=pam.approver
```

Setup in Azure: create an **app registration**, define **app roles** (e.g.
`pam.admin`) and assign users/groups to them, add a **client secret**, and enable
the ROPC (password) grant for the app. If both LDAP and Entra are configured,
PAMv1 tries each (chain). **Caveats:** ROPC does not trigger Entra Conditional
Access or IdP-side MFA — layer PAMv1's own TOTP MFA on top; the OIDC auth-code
flow is the production-recommended upgrade (roadmap). Always use HTTPS.

### OIDC single sign-on (recommended for Entra)

The **Authorization Code + PKCE** flow is the production-grade alternative to
ROPC: the user authenticates *at the IdP* (so its MFA and Conditional Access
apply) and PAMv1 validates the returned ID token's **RS256 signature** against
the IdP's JWKS. Enable it:

```bash
PAM_OIDC_ISSUER=https://login.microsoftonline.com/<tenant>/v2.0
PAM_OIDC_CLIENT_ID=<app-client-id>
PAM_OIDC_CLIENT_SECRET=<client-secret>
PAM_OIDC_REDIRECT_URL=https://pam.example.com/api/auth/oidc/callback
PAM_OIDC_ROLE_ADMIN=pam.admin   # app role value / group id -> role
PAM_OIDC_ROLE_USER=pam.user
PAM_OIDC_ROLE_AUDITOR=pam.auditor     # optional, same mapping for the other two roles
PAM_OIDC_ROLE_APPROVER=pam.approver
```

Register `PAM_OIDC_REDIRECT_URL` as a redirect URI in the app registration. The
authorize/token/JWKS endpoints are auto-discovered from the issuer — override
them with `PAM_OIDC_AUTH_URL` / `PAM_OIDC_TOKEN_URL` / `PAM_OIDC_JWKS_URL` only
for an IdP without a discovery document. `PAM_OIDC_SCOPES` replaces the requested
scopes (default `openid profile`) when your IdP needs an extra one to emit the
role or group claim. Users click
**Single sign-on** on the portal (or hit `/api/auth/oidc/start`); after the IdP,
the callback issues a PAMv1 session and returns to the portal. Note: PAMv1's own
TOTP is not layered on OIDC (the IdP owns MFA there). The OIDC login state is
held in a shared store (Phase 10), so the callback can land on any replica in HA.

### SAML 2.0 single sign-on (Phase 151 — ADFS, Okta, OneLogin, Entra SAML apps)

For an IdP that speaks **SAML 2.0 but not OIDC** — on-prem **AD FS** being the
canonical case — PAMv1 can act as a SAML **Service Provider** (Web Browser SSO
profile, **SP-initiated** flow). The user authenticates *at the IdP*; the IdP
posts a signed `<Response>` back to PAMv1's Assertion Consumer Service (ACS),
PAMv1 verifies the **XML-DSig signature** against the certificate in the IdP's
metadata, checks the audience, destination, issuer, timing and request binding,
maps the group/role attribute to a PAMv1 role and issues a session — the same
landing the OIDC callback uses, so the console needs nothing SAML-specific.
Enable it:

```bash
PAM_SAML_SP_URL=https://pam.example.com                 # PAMv1's PUBLIC base URL (presence enables SAML)
PAM_SAML_IDP_METADATA_URL=https://adfs.corp.example/FederationMetadata/2007-06/FederationMetadata.xml
#   …or, air-gapped / metadata endpoint unreachable from PAMv1:
# PAM_SAML_IDP_METADATA_FILE=/etc/pamv1/idp-metadata.xml
PAM_SAML_ROLE_ADMIN=PAM-Admins                          # group / role attribute VALUE -> role
PAM_SAML_ROLE_USER=PAM-Users
PAM_SAML_ROLE_AUDITOR=PAM-Auditors                      # optional, same mapping for the other two roles
PAM_SAML_ROLE_APPROVER=PAM-Approvers
```

Then register PAMv1 at the IdP by importing its SP metadata from
**`https://pam.example.com/api/auth/saml/metadata`** (ADFS: *Add Relying Party
Trust → Import data about the relying party published online*; Okta/Entra:
upload the metadata file, or enter the values by hand — entity ID
`https://pam.example.com/api/auth/saml/metadata`, ACS URL
`https://pam.example.com/api/auth/saml/acs`, HTTP-POST binding). Configure the
IdP to emit a **group or role claim**: PAMv1 reads, by default, any attribute
named `groups`, `memberOf`, `role`, ADFS's Token-Groups
(`http://schemas.xmlsoap.org/claims/Group`) or Role
(`http://schemas.microsoft.com/ws/2008/06/identity/claims/role`) claim types,
or Entra's SAML `…/claims/groups`; set `PAM_SAML_GROUP_ATTR` (comma-separated
attribute names, matched by `Name` or `FriendlyName`) to be explicit. The
username defaults to the assertion's **NameID**; `PAM_SAML_NAME_ATTR` names an
attribute to use instead (e.g. ADFS's UPN claim
`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn`). Users open
**Single sign-on (SAML)** on the sign-on screen (or hit `/api/auth/saml/start`).

Options and boundaries:

- **`PAM_SAML_SP_ENTITY_ID`** overrides the SP entity ID (default: the metadata
  URL, the SAML convention). **`PAM_SAML_SP_KEY_FILE` + `PAM_SAML_SP_CERT_FILE`**
  (an RSA key pair, PEM, set together) make PAMv1 **sign its AuthnRequests**
  (RSA-SHA256, for an IdP configured to require signed requests) and **publish
  the certificate for encryption**, so an IdP that encrypts assertions to the SP
  works; without them the SP still verifies every IdP signature — the pair only
  adds those two SP-side operations.
- The IdP metadata is fetched **once** at startup (and again on every hot-swap
  of a `PAM_SAML_*` setting); that fetch is the SP's **only outbound call** —
  the login itself is browser-mediated (HTTP-Redirect out, HTTP-POST back).
  `PAM_OT_AIRGAP` therefore refuses `PAM_SAML_IDP_METADATA_URL` and expects the
  `_FILE` form. Metadata is not auto-refreshed: when the IdP rotates its signing
  certificate, restart (or re-save the SAML config in the console).
- **SP-initiated only.** An unsolicited (IdP-initiated) `<Response>` is refused:
  it carries no `InResponseTo` to bind to the browser that started the login,
  which is exactly the login-CSRF hole the state cookie closes. Single Logout,
  the artifact binding and IdP-initiated SSO are not implemented.
- The ACS is a **cross-site POST** from the IdP's page, so the state cookie is
  `SameSite=None; Secure` — which browsers only honour over **HTTPS**. Over
  plain HTTP (dev only) the attribute is left unset and the browser's default
  handling applies; every real deployment terminates TLS anyway.
- Like OIDC, a SAML identity has **no local user row**: no per-user IP
  allowlist, no local TOTP/WebAuthn (the IdP owns MFA), and a login whose
  attributes map to **no role is refused** (`no_role`) — there is no default.
- The three `_FILE` settings are **env/IaC-only** (not hot-swappable): a stored
  console override must never be able to point the server at a file on its host.
- Verification: the SP is proven against a **real in-process SAML IdP** in the
  test suite (signed and encrypted assertions accepted; tampered attributes,
  swapped subjects, stripped signatures, wrong audience/issuer, expired
  conditions and signature-wrapping decoys refused; replay and cross-browser
  posts refused). **Interop with a live ADFS/Okta/Entra tenant is not
  verified in this environment** — see [EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md).

### Multi-factor authentication (TOTP)

PAMv1 offers two independent second-factor types, TOTP and (Phase 124)
WebAuthn — either one alone satisfies MFA at login; a user is never required
to have both. This section covers TOTP; WebAuthn follows immediately after.

Users can add a second factor ([TOTP](https://en.wikipedia.org/wiki/Time-based_one-time_password),
RFC 6238) that works with Google Authenticator, Microsoft Authenticator, 1Password,
etc. It is **self-service and per-user opt-in**, and applies to the password-login
path. Once enrolled, `POST /api/login` requires the 6-digit code.

```bash
# 1. Enroll (as the signed-in user): returns the secret + otpauth URI, once
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/mfa/enroll
# → {"secret":"…","otpauth_uri":"otpauth://totp/pamv1:alice?…"}
#    add the otpauth URI / secret to your authenticator app

# 2. Confirm with a code from the app
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/mfa/verify -d '{"otp":"123456"}'

# status / disable
curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/mfa
curl -H "X-API-Key: $PAM_API_KEY" -X DELETE http://localhost:8080/api/mfa
```

The TOTP secret is stored **vault-encrypted** and returned only once at enrollment.
The portal Sign On has an *MFA code* field for enrolled users. MFA covers NIS2
Art. 21(2)(j).

**Recovery codes:** `POST /api/mfa/recovery-codes` (as an MFA-enrolled user) issues
10 single-use backup codes, shown once. Enter one in place of your MFA code at
login if you lose your authenticator; each works exactly once.

Since Phase 177 `GET /api/mfa` also reports `recovery_codes_remaining`, and
console `PAMMFA` shows it — none left in red, one or two in amber. Codes are
single-use and the set is only replaced deliberately, so the count is what tells
somebody to generate a new set before the last one is spent. A value of `-1`
means the count could not be read, which is deliberately not `0`.

**Require MFA for everyone:** set `PAM_MFA_REQUIRED=true`. Then a password login by
a user without confirmed MFA returns an **enrollment-only** session — it can *only*
call the `/api/mfa/*` **and** `/api/webauthn/register/*` endpoints (everything
else, including the SSH proxy, is refused) until the user enrolls and
confirms **either** factor, then logs in again.

### Multi-factor authentication (WebAuthn, Phase 124)

FIDO2/WebAuthn is the second second-factor type: a hardware security key
(YubiKey, etc.) or a platform authenticator (Touch ID, Windows Hello). Like
TOTP it is **self-service and per-user opt-in**. It needs one thing TOTP
doesn't — a Relying Party identity — configured once at startup:

```bash
export PAM_WEBAUTHN_RP_ID=pam.example.com        # the effective domain, no scheme/port
export PAM_WEBAUTHN_RP_ORIGIN=https://pam.example.com  # the fully-qualified origin browsers see
```

Presence enables the feature — the same idiom `PAM_OIDC_ISSUER` uses, no
separate boolean flag — and, unlike OIDC's hot-reloadable config, it is
**restart-only**: re-pointing an RP ID at a different domain is a migration
event, not a routine change `PUT /api/config` should ever touch live. Leave
both unset and every `/api/webauthn/*` route refuses with 503.

```bash
# Register a new authenticator (as the signed-in user) — a two-call ceremony:
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/webauthn/register/begin
# → PublicKeyCredentialCreationOptions JSON — the browser's own
#   navigator.credentials.create() consumes this directly; the console does
#   this step for you (menu 9 → WebAuthn: manage keys → F6)
curl -H "X-API-Key: $PAM_API_KEY" -X POST "http://localhost:8080/api/webauthn/register/finish?name=YubiKey" \
  -d '<the browser's PublicKeyCredential response, verbatim>'

# List / delete your own keys:
curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/webauthn/credentials
curl -H "X-API-Key: $PAM_API_KEY" -X DELETE http://localhost:8080/api/webauthn/credentials/3
```

**Login is a different shape than TOTP's, necessarily.** A 6-digit TOTP code
types inline, so `POST /api/login {username, password, otp}` is one request.
WebAuthn cannot work that way — the server has to know *which user* before it
can build a challenge scoped to their credentials, which is an unavoidable
second round trip. So a password-only login for a WebAuthn-enrolled user (with
no confirmed TOTP) returns `{"webauthn_required": true, "token": "..."}`
instead of a full session — that `token` is narrowly scoped
(`MFAPending`, 5-minute TTL) and works for nothing except the two calls below;
using it anywhere else, including `/api/me`, is refused:

```bash
curl -H "X-API-Key: $PENDING_TOKEN" -X POST http://localhost:8080/api/webauthn/login/begin
# → PublicKeyCredentialRequestOptions JSON for navigator.credentials.get()
curl -H "X-API-Key: $PENDING_TOKEN" -X POST http://localhost:8080/api/webauthn/login/finish \
  -d '<the browser's assertion response, verbatim>'
# → {"token": "...", "username": "...", "role": "...", "expires_at": "..."} — a
#   real, full session, same shape POST /api/login's success response has
```

The console drives this automatically: enter your username + password and
leave the MFA code blank, and the browser prompts for your key on its own.

A few things worth knowing:

- **A user with confirmed TOTP is checked first, unaffected by any of this**
  — the WebAuthn branch only applies when there is no confirmed TOTP. A user
  is not expected to juggle both; pick one.
- **Credential public keys are not secret** and are stored in the clear —
  knowing one lets nobody forge an assertion, only the authenticator's own
  private key (which never leaves the device) can.
- **A user may register more than one key** (a YubiKey and a phone, say) —
  unlike TOTP, which is one secret per account.
- **Attestation is accepted but not verified against a trust anchor** in v1
  (no FIDO Metadata Service integration) — any WebAuthn-conformant
  authenticator is accepted, same posture as accepting any TOTP app.
- Recovery codes (above) work identically regardless of which factor type
  they're backing up.

### AI-agent access broker (Phase 13)

The broker extends the "trust the chokepoint, not the agent" model to AI agents:
an agent holds only an identity key, a **policy** decides `allow` / `require_approval`
/ `deny` on each tool call **and its arguments**, approved actions run **server-side
with a just-in-time credential**, and the agent gets back only the result — never
a secret. It is **off** until you point `PAM_BROKER_POLICY_FILE` at a policy file.
The audit-chain keys take care of themselves: left unset, each is generated once
at startup and held under **shared custody** — sealed by the KEK into
`key_material`, converged on by every replica, re-wrapped by `-rotate-kek` —
exactly like the SSH host and CA keys. An explicit env value is **written
through** to that same custody, so a fleet where some replicas carry the
variable and some don't, or a later boot after you unset it, still converges on
one chain key instead of silently forking the chain; an explicit
`PAM_BROKER_AUDIT_KEY` that *disagrees* with what custody already holds is a
fatal startup error (unset it to adopt the cluster key), while a disagreeing
sign seed is taken as a deliberate signer rotation. See the [config
reference](#4-configuration-reference) for the full `PAM_BROKER_*` set.

**Enable it:**

```bash
export PAM_BROKER_POLICY_FILE=/etc/pam/broker-policy.yaml
# optional — hold the audit-chain keys yourself instead of shared custody
# (an explicit value always wins, and is how a signer rotation is driven):
#   export PAM_BROKER_AUDIT_KEY=$(openssl rand -base64 32)        # HMAC chain key
#   export PAM_BROKER_AUDIT_SIGN_SEED=$(openssl rand -base64 32)  # ed25519 head signer
# optional: PAM_BROKER_RATE_PER_MIN=60  PAM_BROKER_TOKEN_TTL_MIN=15
```

**Policy** is ordered, **first-match-wins**, and **implicit-deny** (no match =
denied). Conditions match an argument's value exactly, and since Phase 30 also support `not`, `in`, `not_in` and the numeric comparators `gt`, `gte`, `lt`, `lte` (`in`/`not_in` are a set membership, i.e. an OR); Phase 163 added `present: true|false`. No regex.

**Every condition requires the argument to be supplied.** This changed in Phase
163 and it is the one thing to re-read your policy for after upgrading: `not` and
`not_in` used to be satisfied by an **absent** argument, which quietly inverted
the guard operators are most likely to write. A rule reading

```yaml
- id: not-the-vault
  tool: list_credentials
  effect: allow
  when: { args.target: { not_in: [vault-prod] } }
```

was defeated by *sending less* — `list_credentials` lists **every** credential
when `target` is omitted, and an omitted argument satisfied `not_in`, so the one
call the rule existed to stop was the one call it admitted. Now an omitted
argument matches no condition at all, so that call falls through to the implicit
deny. If you actually want "absent is acceptable", say it: `present: false` is a
condition of its own, and it is also how you write "the unscoped, list-everything
form of this call is not allowed". Note that presence means **supplied**, not
non-empty — though a supplied-but-empty string argument is now refused outright
by the broker, since it is never a meaningful request and was the same bypass
wearing one character.

```yaml
rules:
  - id: allow-read-inventory
    tool: list_targets
    effect: allow
  - id: prod-needs-human
    tool: winrm_exec
    when: { args.target: prod-dc-01 }
    effect: require_approval
    approvers: [platform-team]
    ttl_seconds: 600        # decide within 10 minutes or the call lapses
  - id: never-reveal
    tool: reveal_credential
    effect: deny            # reveal_credential ships default-deny anyway
```

**Who a rule applies to (Phase 173).** A rule can name its principal, which
until this phase it could not: one `allow` for `reveal_credential` enabled that
tool for **every** agent in the deployment.

```yaml
rules:
  - id: only-the-rotator-rotates
    tool: rotate_credential
    agents: [rotation-bot]          # an agent-key name or a full SPIFFE ID
    effect: allow
  - id: no-secrets-through-delegation
    tool: reveal_credential
    when: { caller.delegation_depth: { gte: 1 } }
    effect: deny
    reason: a delegated token may not reveal a secret
```

- **`agents:`** restricts a rule to the listed *presenting* identities; an absent
  list matches everyone, so every policy you already run is unchanged. A call
  delegated **from** a listed agent arrives under the delegate's own identity and
  needs its own rule — the narrowing direction, deliberately.
- **`not_agents:`** excludes, and matches **any** identity the call can be
  attributed to (presenter, delegation chain, accountable party), so an exclusion
  cannot be escaped by delegating one hop.
- **`caller.*` conditions** read the verified identity: `caller.agent`,
  `caller.spiffe_id`, `caller.on_behalf_of`, `caller.delegation_depth` (hops: 0
  is undelegated) and `caller.identity_kind` (`spiffe` or `key`). They cannot be
  forged — an argument named `caller.agent` is a different lookup and never
  reaches the condition — and an unknown `caller.*` attribute is refused when the
  policy loads rather than silently never matching. `caller.spiffe_id:
  { present: false }` is how you write "a static agent key".

**What `ttl_seconds` and `scope` actually do (Phase 171).** Both once read
stronger than they were, and one of them did nothing at all:

- **`ttl_seconds`** bounds how long a `require_approval` call stays decidable and
  its single-use resume token stays spendable. Until Phase 171 it was parsed and
  **read by nothing**: a rule advertising a 60-second grant got the deployment's
  `PAM_BROKER_TOKEN_TTL_MIN` (15 minutes). It now binds — and may only *narrow*
  that deployment-wide bound, never extend it, because a policy file must not
  out-rank the deployment's own limit. After the window lapses the call is swept
  and reported to the agent as failed, so nothing waits forever. **It is refused
  on `allow` and `deny` rules**, where there is no window to bound: such a policy
  now fails to load rather than accepting a setting that does nothing.
- **`scope`** is a template rendered into the **audit record**. It does not
  narrow what a call does — the arguments are fixed before policy runs, and the
  broker executes exactly those. It does assert presence: a template naming
  `{target}` fails to render for a call with no `target` argument, and a render
  failure is a **deny**. Read it as a label with a fail-closed required-argument
  check, not as a grant.

The deadline is visible where the decision is made: `GET /v1/approvals` and
console menu **20** both carry `expires_at` / a **DECIDE BY** column, and the
parking response tells the agent the same instant. Since Phase 183 the same
queue also carries `actor_chain`, shown as a **HOPS** column — `direct` for an
undelegated call, otherwise how many delegations it passed through, with the
chain itself in the cell's hover text. A call that reached you through three
sub-agents used to look exactly like one that came straight from the agent you
know.

**What an inventory tool answers with (Phase 169).** `list_targets` and
`list_credentials` report only the targets the calling agent may reach — the same
direct-grant ∪ safe-membership check every acting tool applies. A target with no
grants and no safe stays visible to everyone, as it is everywhere else in PAMv1,
so the way to narrow an agent's view of the estate is to grant it the targets it
should reach (which gates the rest). Naming an ungranted target explicitly —
`{"target":"prod-dc-01"}` — is refused with `agent not authorized for target`,
not answered with an empty list. Before 169 both tools answered for the whole
estate regardless of grants, so an agent entitled to one host could still
enumerate every hostname, OS, protocol and privileged account name PAMv1 knew.

**Mint an agent identity** (admin, `CapManageUsers`); the token is shown once:

```bash
curl -sX POST https://pam.example/v1/agents -H "X-API-Key: $PAM_API_KEY" \
  -d '{"name":"ci-bot","owner":"alice"}'      # → {"id":1,"token":"agt_…"}
```

The agent then calls tools with `Authorization: Bearer agt_…` at `POST /v1/tool-calls`
(or over MCP JSON-RPC at `POST /mcp`). An `allow` executes and returns the result;
a `require_approval` **parks** the call and returns a `call_id` + single-use resume
token. Revoke/list agents with `DELETE /v1/agents/{id}` / `GET /v1/agents`.

**Approve parked calls** (an `approver`, four-eyes — you can't approve your own
agent's call): `GET /v1/approvals`, then `POST /v1/approvals/{call_id}/decision`
with `{"approve":true}`. On approve the broker executes server-side and the agent
collects the result once via its resume token — and only that agent can: since
v0.60.0 the token is bound to the identity that parked the call, so another agent
presenting it is refused exactly as a bad token is. A call whose agent key was revoked —
or whose SVID expired — since parking is **refused at approval time**, not run.

**Verify the tamper-evident trail:** every tool call is written to a keyed-HMAC
hash chain. `GET /v1/audit/verify` walks it and reports the first broken id (an
edit or mid-history deletion); `GET /v1/audit/head` returns an ed25519-signed
anchor so an auditor can later detect tail truncation. Appends are serialized
across processes by a Postgres advisory lock, so a rolling deploy or HA replica
can't fork the chain.

**Separation of duties (Phase 27):** a `require_approval` rule's `approvers:` list
names the groups (role names or usernames) permitted to decide; an approver
outside every named group is refused (`broker.approval.refused`, 403) and the call
stays parked. Admins are the superuser bypass. **Periodic in-chain checkpoints**
(`PAM_BROKER_AUDIT_CHECKPOINT_EVERY`) add ed25519 signatures over the running head
inside the chain — so even a leaked HMAC key can't forge history undetectably
(`/v1/audit/verify` reports `bad_checkpoint`). Pass `?min_entries=N` (from an
archived checkpoint's count) to detect **tail truncation** without an out-of-band
anchor. Rotate the checkpoint signer with an overlap: set the new
`PAM_BROKER_AUDIT_SIGN_SEED` and list the old **public** key in
`PAM_BROKER_AUDIT_SIGN_PREV`; both are published as a JWKS at `GET /v1/audit/jwks`
for external verification. (If the seed has been under shared custody — i.e. you
never set it — read the outgoing public key from that JWKS **before** rotating.
The explicit env seed takes over **and shared custody converges to it**, so
later unsetting the variable keeps the *rotated* signer rather than silently
resurrecting the replaced one.) **OCSF export:** `GET /api/audit/ocsf` (add
`?format=ndjson` for most collectors) delivers the trail as OCSF events (API
Activity 6003 / Detection Finding 2004) for your SIEM. The full broker threat
model is in [AGENT-THREAT-MODEL.md](AGENT-THREAT-MODEL.md).

**MCP over SSE (Phase 27):** an MCP client can open `GET /mcp` for the
Server-Sent-Events transport (server→client messages + heartbeats) in addition to
`POST /mcp`. When a client advertises `elicitation` support, an approval-gated tool
call prompts the running user to confirm over the stream; **declining withdraws the
call**, while accepting only records intent — a separate human approver is still
required (four-eyes).

The MCP endpoint negotiates the protocol revision with each client (`2024-11-05`,
`2025-03-26` or `2025-06-18` — the client's own when PAMv1 speaks it, else the
latest), accepts JSON-RPC batches, and refuses an `MCP-Protocol-Version` header
naming a revision it does not speak. Its transport is the HTTP+SSE pair (`GET
/mcp` for the stream, `POST /mcp` for messages), which every revision keeps for
backwards compatibility; the newer Streamable HTTP transport is not offered.

For SPIFFE JWT-SVID agents and RFC 8693 delegation, set `PAM_BROKER_TRUST_DOMAIN`,
`PAM_BROKER_TRUST_DOMAIN_JWKS`, and `PAM_BROKER_AUDIENCE`; delegation depth is
capped by `PAM_BROKER_MAX_DELEGATION_DEPTH`. The JWKS file is **re-read when it
changes** (checked every 30 seconds, and at once when a token arrives under a key
PAMv1 does not hold), so a SPIRE key rotation needs no restart; a half-written or
unparsable file keeps the last good bundle in force and is logged
(`service=svid`), never treated as "trust nobody".

**Issuing delegation (Phase 57).** With `PAM_BROKER_TOKEN_EXCHANGE=true`, an
SVID-authenticated agent can delegate **its own** authority to a sub-agent it
spawns:

```bash
curl -s -X POST https://pam.example.com/v1/token \
  -H "Authorization: Bearer $PLANNER_SVID" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d actor_token="$WORKER_SVID"
# → {"access_token":"…","issued_token_type":"urn:ietf:params:oauth:token-type:jwt",
#    "token_type":"N_A","expires_in":300}
```

The sub-agent then calls the broker with that token; its `act` chain names the
planner and, at the end, the accountable human — so the audit trail reads the
same whether a call came from an agent or from something an agent spawned. Three
things worth knowing before you turn it on:

- **The token says who may act, never what they may do.** `scope` is refused;
  every delegated call is still decided by policy over its arguments, so a
  delegated agent is not more privileged than the policy allows it to be.
- **There is no revocation list for a minted token** — the TTL is the
  containment (default 5 minutes, and never longer than the delegator's own
  expiry). Keep `PAM_BROKER_EXCHANGE_TTL_MIN` small.
- **Impersonation is unsupported by design**: an exchange without an
  `actor_token` is refused, because erasing the intermediary defeats the chain
  the audit exists to keep. So is delegating a credential you merely hold — the
  delegator is always the caller you authenticated as.

**Pinning the next hop (Phase 181).** A delegator can name who is allowed to act
for the token it is minting, by adding `may_act` to the request:

```bash
curl -s -X POST https://pam.example.com/v1/token \
  -H "Authorization: Bearer $PLANNER_SVID" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d actor_token="$WORKER_SVID" \
  -d may_act=spiffe://corp.example/ns/prod/sa/helper
```

The issued token carries an RFC 8693 §4.4 `may_act` claim, and the **next**
exchange refuses any actor it does not name. PAMv1 has enforced that claim since
delegation shipped and never issued it, so until now every minted token was
unpinned past the first hop.

- Repeat the parameter, or separate names with spaces or commas; at most **eight**
  parties, all inside your trust domain, and never the token's own subject.
- Omitting it leaves the token unpinned — the behaviour of every token minted
  before this release, and still the default.
- `may_act` is a **PAMv1 extension parameter**. RFC 8693 defines the claim, not a
  request field for it, so no other implementation will accept the same request.
- The pin is on the trail (`broker.token.exchanged … may_act:…`), so an
  investigator can answer "who was this token allowed to be handed to" without
  holding the token.

`GET /v1/token/jwks` (needs `read_audit`) publishes the signing key, so an
auditor holding a delegated token from the trail can confirm which key signed it.

### Agent identity lifecycle and the stop button (Phase 159)

Everything above governs what an agent may *do*. This governs the identity
itself — how long it lives, whether anyone still uses it, and how you stop it at
02:40 when it starts behaving badly.

**Suspend, don't destroy.** `POST /v1/agents/{id}/disable` suspends an agent key:
it stops authenticating immediately, and every parked call awaiting approval
fails re-validation at decision time. `POST /v1/agents/{id}/enable` puts it back.
Before this, the only lever was `DELETE` — which destroys the row an
investigator wants to keep and silently invalidates whatever was parked. Suspend
is reversible and loud (`agent.disable` / `agent.enable`); delete is still there
when you mean it.

**Quarantine covers the identity kind that has no row.** An agent authenticated
by a SPIFFE **SVID** has no `agent_keys` row at all, so disable cannot reach it —
its containment used to be "wait for the SVID to expire". `POST
/v1/agents/quarantine` takes a **subject** and stops it everywhere:

```bash
# a static-key agent: the subject is its agent name
curl -s -XPOST -H "X-API-Key: $KEY" $PAM/v1/agents/quarantine \
  -d '{"subject":"deploy-bot","reason":"anomalous rotate_credential volume, ticket INC-4471"}'

# an SVID agent: the subject is its full SPIFFE ID
curl -s -XPOST -H "X-API-Key: $KEY" $PAM/v1/agents/quarantine \
  -d '{"subject":"spiffe://corp.example/ns/prod/sa/planner","reason":"suspected prompt injection"}'

curl -s -H "X-API-Key: $KEY" $PAM/v1/agents/quarantine            # who is quarantined
curl -s -XDELETE -H "X-API-Key: $KEY" $PAM/v1/agents/quarantine/7 # release
```

One list covers both identity kinds because an SVID agent's canonical name *is*
its SPIFFE ID, and a quarantined subject is refused at the broker's front door
(`agent.quarantine_refused`) **and** at approval time for anything already
parked. A store failure while checking fails **closed** — a stop button that
stops working when the database hiccups is not a stop button. All of this needs
`manage_users`, like every other agent-key route, and appears on console menu
**26** (options `5=Suspend` / `6=Resume`, `F7` for the quarantine list).

**Quarantine follows delegation (Phase 169).** If an agent delegates — exchanging
its token for a sub-agent's via `POST /v1/token` — the sub-agent presents its own
subject, and the delegator appears only inside the token's `act` chain. Until
Phase 169 the check looked at the presenter alone, so quarantining a compromised
root left every token it had already minted working until that token expired.
Now **every actor in the presented token's chain** is checked, at both the front
door and the approval gate: quarantine the root and the sub-agents stop with it,
in the same second. The refusal names which link stopped the call, so the trail
is readable when the agent that went quiet is not the one you named:

```
agent.quarantine_refused  agent:"spiffe://corp.example/ns/prod/sa/worker"
                          path:"/v1/tool-calls"
                          subject:"spiffe://corp.example/ns/prod/sa/planner"
```

One thing this deliberately does not do: a **static** key's owner is a human
username, and quarantining a person's name does not stop the agents they own.
Stopping everything one human is accountable for is offboarding (below), which
suspends each key individually and leaves that trail instead.

**Expiry and dormancy.** `POST /v1/agents` accepts `expires_in_days` (absent or
`0` = never expires, which is what every existing key stays). An expired key
stops authenticating exactly as a suspended one does, and the expiry is carried
on the identity so a parked call whose key expired in the meantime is refused at
approval time too. Every successful authentication records **last use**, so the
agent list answers the question a PAM should always be able to answer about a
standing credential: *is anyone still using this?* An agent that has not called
in months is a finding, not a footnote.

**Offboarding cascades.** Deleting a human user now **suspends** every agent key
they owned, audited per key as `agent.disable … reason:owner-offboarded`. It
suspends rather than deletes for the same reason as above: the accountable human
is gone, so the agent must stop — but the record must not. Since Phase 170 the
cascade also **quarantines every SPIFFE identity** that person owned — an
attested agent has no key to suspend, so quarantine is the stop it has.

### Who owns a SPIFFE agent (Phase 170)

An agent that authenticates with a SPIFFE SVID is admitted by your trust domain,
not minted here, so PAMv1 had nowhere to record the human accountable for it.
Two shipped controls read that owner, and both were silently inert for this
identity kind:

- **Four-eyes approval.** The broker refuses an approval from the human who owns
  the calling agent. For an SVID the owner it compared was a SPIFFE ID, which can
  never equal a username — so the refusal never fired, and the person operating
  an agent could approve their own agent's privileged calls alone.
- **The offboarding cascade** above, which had no key row to reach.

Register the owner once per SPIFFE ID:

```bash
curl -s -XPOST -H "X-API-Key: $KEY" $PAM/v1/agents/identities \
  -d '{"spiffe_id":"spiffe://corp.example/ns/prod/sa/planner",
       "owner":"carol","note":"release planner"}'

curl -s -H "X-API-Key: $KEY" $PAM/v1/agents/identities            # who owns what
curl -s -XPOST -H "X-API-Key: $KEY" $PAM/v1/agents/identities/3/owner \
  -d '{"owner":"dave"}'                                          # handover
curl -s -XDELETE -H "X-API-Key: $KEY" $PAM/v1/agents/identities/3 # de-register
```

Console menu **26**, key **F8** (`PAMAGTOWN`). All four routes need
`manage_users`, like the rest of the agent surface.

**Register every identity in a delegation chain.** The gate resolves owners for
the whole chain, because a call made by a sub-agent was requested, transitively,
by whoever owns the agents it acts for.

**Two fail-closed behaviours to plan for**, both new and both deliberate:

- A SPIFFE identity with **no recorded owner** cannot have its parked calls
  approved by anyone — the decision is refused (`agent-has-no-owner`) and the
  call **stays parked**, so registering the owner unblocks it. If you run agents
  on SVIDs, register owners *before* the first call needs approving.
- If the registry cannot be read at all, the decision is refused too (503). An
  unreadable table is not evidence that nobody owns the agent.

**What this is not.** It is not enrollment and not attestation: recording an
owner admits no workload and proves nothing about one. Any workload in your trust
domain can still authenticate; this records who answers for the ones you named.

**The inventory builds itself (Phase 174).** Recording an owner only helped for
the identities you thought to type in — and any workload your trust domain
vouches for can authenticate. So PAMv1 now records **every** SPIFFE identity
that calls: the first sighting creates a row marked **seen** (no owner, audited
once as `agent.identity_first_seen`), and every call after stamps its last-seen.
The console list (menu 26 → F8) shows both states:

- **seen** — a workload authenticated and nobody has claimed it. Its parked calls
  cannot be approved by anyone, because four-eyes needs an owner.
- **enrolled** — a human has taken responsibility for it. Setting an owner is
  what enrolling *is*, so option **5** on a seen row (or `POST
  /v1/agents/identities` naming the same SPIFFE ID) adopts it, keeping when it
  was first seen.

```bash
curl -s -H "X-API-Key: $KEY" $PAM/v1/agents/identities   # who has called, and who owns them
```

**To require enrollment**, set `PAM_BROKER_REQUIRE_ENROLLED_SVID=true`: an
identity nobody has claimed is refused at the door (`agent.not_enrolled`, the
same 401 a bad bearer gets, so it learns nothing from the reply). The sighting is
still recorded — you enrol *from* that list, so an identity that knocked and was
turned away has to appear in it. Plan the order: enrol first, then turn the flag
on. Static agent keys are unaffected; PAMv1 issued those itself.

**What this is not.** Enrolling is not attestation. It admits no workload — your
trust domain already decided that — and proves nothing about the process holding
the SVID. Cryptographic workload attestation (SPIRE) stays external; see
[EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md).

#### Binding a delegated token to a key (proof of possession)

A token the broker mints is, by default, a **bearer** credential: whoever holds
the string is that sub-agent until it expires. If one leaks — a log line, a
crashed process's environment, an over-broad container mount — the leak is the
compromise. Binding removes that.

Give the sub-agent a key pair (Ed25519, P-256 or RSA), compute the RFC 7638
thumbprint of its **public** key, and pass it when you mint:

```bash
curl -s -X POST "$PAM/v1/token" \
  -H "Authorization: Bearer $DELEGATOR_SVID" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d actor_token="$SUBAGENT_SVID" \
  -d cnf_jkt="$SUBAGENT_JKT"
```

The issued token now carries `cnf: {"jkt": "…"}`, and **every call presenting it
must also send a `DPoP` header** — a short JWT signed by the matching private
key, naming this request's method (`htm`) and URI (`htu`), the SHA-256 of the
token itself (`ath`), a fresh `iat` and a one-use `jti`. Any standard DPoP client
library produces it; the shape is RFC 9449 §4.2. The token may be presented as
`Authorization: DPoP <token>` or `Authorization: Bearer <token>` — PAMv1 reads
the binding from the token, never from the header word.

Three behaviours worth knowing before you turn this on:

- **A bound token cannot delegate to an unbound one.** If the delegator's own
  token carries a `cnf`, `cnf_jkt` is required on the next exchange. Otherwise
  the constraint could be walked off at the next hop.
- **A proof is single-use — per replica.** Headers are not secret, so a captured proof would
  otherwise be replayable; the second use is refused.
- **`PAM_BROKER_PUBLIC_URL` is not optional behind a proxy.** The proof is signed
  over the URL the *client* used. If anything terminates TLS in front of PAMv1,
  set it, or every bound agent is refused with `reason:proof-uri-mismatch`.

**To require binding**, set `PAM_BROKER_REQUIRE_POP=true`: an SVID-authenticated
agent whose token carries no `cnf` is refused (`agent.pop_denied`,
`reason:token-not-key-bound`). Same ordering advice as enrollment — bind the
tokens first, then set the flag. Unbound tokens are completely unaffected until
you do, so upgrading changes nothing on its own.

**What this is not.** The *delegator* names the key, and PAMv1 cannot check that
the key belongs to the sub-agent rather than to the delegator itself. What you
get is that a token lifted off the wire or out of a log is useless without the
private key — theft, contained. Binding a credential to the process holding it is
workload attestation, and stays SPIRE's job.

Audit: `agent.pop_denied`, whose `reason:` names which check failed
(`proof-header-missing`, `proof-replayed`, `proof-not-bound-to-this-token`,
`proof-key-is-not-the-bound-key`, `proof-uri-mismatch`, `token-not-key-bound`, …).
The caller is told only "invalid or missing agent credential" — the reason is for
you, not for whoever is holding the token.

Audit: `agent.identity_register` · `agent.identity_owner_set` ·
`agent.identity_remove` · `agent.identity_first_seen` · `agent.identity_enrolled` ·
`agent.not_enrolled` · `agent.quarantine_failed` (the cascade's failure record,
the quarantine twin of `agent.disable.failed`).

**Why this is its own phase.** Humans in PAMv1 get certification campaigns,
checkout leases and revocation; agent identities held an immortal standing
bearer credential that nothing reviewed, nothing expired and nothing could
pause. Phase 153's endpoint agents — a much newer non-human identity — already
had last-seen and revocation; the oldest one was the weakest. EU AI Act
Art. 14(4)(e) calls the missing control a "stop button"; CyberArk, Microsoft
Entra Agent ID, BeyondTrust and Teleport all ship the lifecycle half.

Audit: `agent.disable` · `agent.enable` · `agent.quarantine` ·
`agent.quarantine_release` · `agent.quarantine_refused` (plus the existing
`agent.create` / `agent.revoke`).

### Watching an agent run (Phase 161)

Phase 159 gave you the stop button. This is how you see whether you need it.

Three things changed in what the broker writes. First, the audit **action** now
says how a tool call went — `broker.tool_call.executed`, `.denied`,
`.pending_approval`, `.failed`, `.resumed` — instead of one flat
`broker.tool_call` with the outcome buried in the detail text. If you have SIEM
rules or saved audit filters keyed on the old flat name, **update them**: it is no
longer written. In exchange, your SIEM finally sees a denied agent tool call as an
OCSF **Detection Finding** rather than routine API activity (it was classified all
along; nothing could emit the classified name, so the rule had never fired).

Second, the risk engine now scores agents — see §9.7 above.

Third, an agent run can be **reconstructed**. Encourage whoever writes your agents
to send the two optional fields on `POST /v1/tool-calls`:

```bash
curl -s https://pam.example/v1/tool-calls -H "Authorization: Bearer $AGENT_TOKEN" \
  -d '{"session_id":"run-2f9c","client":"claude-code/2.1 (some-model)",
       "tool":"ssh_exec","args":{"target":"db-01","command":"systemctl status pg"}}'
```

`session_id` is the agent's own run/conversation id and `client` is what software
and model is driving it. Both appear in the trail as `session:` and `client:`, and
both are **declared by the caller and never verified** — PAMv1 records them so an
investigator can group a run, and never consults them for a decision. Treat them
as provenance, not evidence. Over MCP you do not send them: the protocol session
is the run id and `clientInfo` from `initialize` is the client.

You also get `jti:` on parked calls, which PAMv1 computes itself: it is the resume
token's id, so the "parked for approval", "approved", and "the agent collected the
result" events all name the same ticket. That last event is new to the
hash-chained broker audit — the authoritative record used to end at the human's
decision, which meant the moment a `reveal_credential` result actually left PAMv1
was recorded only in the ordinary trail.

### Application-secrets API (Phase 24, Tier-4)

For a **non-agent application** (a CI job, a legacy service) that just needs to
fetch a secret at startup — not an operator through the proxy, not the AI-agent
tool broker — PAMv1 offers a **Conjur-style** delivery path. It is **opt-in** and
**default-deny**: an app retrieves only the specific credentials it has been
explicitly granted.

```bash
PAM_APP_SECRETS_ENABLED=true          # off by default; front it with TLS
```

```bash
# 1. Mint an application identity (CapManageUsers); the token is shown once.
curl -sX POST https://pam.example/v1/apps -H "X-API-Key: $PAM_API_KEY" \
  -d '{"name":"orders-svc","owner":"payments-team"}'   # → {"id":3,"token":"pamt_…"}

# 2. Grant it one credential (needs CapRevealSecret — you can only hand out a
#    secret you could reveal yourself).
curl -sX POST https://pam.example/v1/apps/3/grants -H "X-API-Key: $PAM_API_KEY" \
  -d '{"credential_id":42}'

# 3. The application fetches exactly that secret with its bearer key.
curl -s https://pam.example/v1/app-secrets/42 -H "Authorization: Bearer pamt_…"
# → {"credential_id":42,"target":"appdb","username":"svc","secret_type":"password","secret":"…"}
```

A credential the app was **not** granted returns 403 (`app.secret_denied`); a
disabled/unknown app returns 401; every successful retrieval is audited
`app.secret_retrieved` (never the secret). Revoke an app (`DELETE /v1/apps/{id}`)
or a single grant (`DELETE /v1/apps/{id}/grants/{gid}`); both cascade. This path
delivers **plaintext** to machines, so run it only over HTTPS and grant narrowly.

In the **portal**, this is menu **15** (*Work with application secrets*): mint or
revoke applications (the bearer token is shown once), and option **5** on an app
opens *Work with secret grants* to grant or revoke individual credentials.

---

## 8. Break-glass procedure

For emergencies when the normal admin path is unavailable.

1. **Prepare** (before you need it):
   ```bash
   openssl rand -base64 30                      # the emergency key
   echo -n "<that-key>" | ./pam-server -hashkey  # → PAM_BREAK_GLASS_KEY_HASH
   ```
   Configure only the hash. Seal the plaintext key in an envelope / physical safe
   (dual control recommended).
2. **Use** in an emergency: present the sealed key as `X-API-Key` (or SSH proxy
   password). It grants `admin` immediately.
3. **It is loud:** every break-glass request is logged (`WARN BREAK-GLASS access`)
   and written to the audit trail as actor `break-glass` (blinking red in the
   portal's audit screen).
4. **After the incident:** rotate the emergency key (new hash), rotate any
   revealed credentials, and review the audit trail.

### Break-glass v2: M-of-N quorum unseal

Instead of a single sealed key, split it among **custodians** so no one person
can invoke break-glass alone. Split the key offline (the server never sees the
shares):

```bash
echo -n "<emergency-key>" | PAM_BREAK_GLASS_SHARES=5 PAM_BREAK_GLASS_THRESHOLD=3 ./pam-server -split-key
# → 5 hex shares; any 3 reconstruct the key. Give one to each custodian.
```

Configure the server with the key's hash and the threshold:
`PAM_BREAK_GLASS_KEY_HASH=<hash>`, `PAM_BREAK_GLASS_THRESHOLD=3`. In an emergency,
custodians each POST their share:

```bash
curl -X POST https://PAM_HOST/api/breakglass/unseal -d '{"share":"<hex-share>"}'
# → {"collected":1,"needed":3} … until the 3rd:
# → {"token":"pamt_…","role":"admin","expires_at":"…"}
```

The reconstructed key is verified against the configured hash; a valid quorum
yields a **short-lived admin session** (`PAM_BREAK_GLASS_TTL_MIN`, default 15 min)
that auto-expires. Every unseal and every subsequent break-glass request is
audited (`breakglass.unseal` / `breakglass.access`) and, if `PAM_ALERT_WEBHOOK`
is set, **alerted in real time**. Keep custodians and their shares under dual
control, and run periodic drills.

### Rotating the vault key

To rotate the local master key (re-encrypt every secret under a new key), run the
maintenance command **offline** (nothing else writing secrets):

```bash
export PAM_MASTER_KEY=<current-key>
export PAM_NEW_MASTER_KEY=$(./pam-server -genkey)
export PAM_DATABASE_URL=postgres://…
./pam-server -rotate-kek   # → "rotated N secrets; set PAM_MASTER_KEY to the new key and restart"
```

Then set `PAM_MASTER_KEY` to the new key and restart. The completed rotation is
recorded in the audit trail (`vault.kek_rotated`, with the old/new KEK ids and the
secret count).

`-rotate-kek` also **migrates between KEK providers** — the current KEK is read
from the usual `PAM_KEK_*` / `PAM_MASTER_KEY`, and the target from the parallel
`PAM_NEW_KEK_*` / `PAM_NEW_MASTER_KEY` set (provider defaults to `local`). For
example, to migrate a local master key to AWS KMS:

```bash
export PAM_MASTER_KEY=<current-local-key>          # current KEK (local)
export PAM_NEW_KEK_PROVIDER=aws-kms                 # target KEK (KMS)
export PAM_NEW_KEK_AWS_KEY_ID=… PAM_NEW_KEK_AWS_REGION=…
export PAM_DATABASE_URL=postgres://…
./pam-server -rotate-kek
# then run the server with PAM_KEK_PROVIDER=aws-kms + PAM_KEK_AWS_* and restart
```

Within a single Vault-Transit / KMS key, day-to-day rotation is handled by the
KMS itself; use `-rotate-kek` to change the *version envelope* or migrate providers.

#### What a rotation covers — and the one thing it cannot

`-rotate-kek` re-wraps **all four** kinds of vaulted secret, and the list is
exhaustive on purpose: anything missed is a secret the server can no longer
decrypt after you switch keys.

| Secret | Bound by | Symptom if it were missed |
|---|---|---|
| Credentials | `CredentialAAD` | Sessions fail at JIT decryption |
| TOTP enrollments | `MFAAAD` | Enrolled users cannot complete MFA |
| Secret config values (LDAP bind password, SSO client secrets) | `ConfigAAD` | Directory login breaks |
| **Key custody** — SSH proxy host key, Zero Standing Privilege CA key, and the broker audit-chain HMAC key + signing seed when custody-held | `KeyMaterialAAD` | **The server refuses to start** (host/CA keys), or the broker's audit chain can no longer be verified |

That last row was a real defect, fixed in Phase 52a: the rotation reported
success and the *next start-up* failed, because `keycustody.Ensure` read back an
envelope still sealed under the old key. If you hit this on a version before the
fix, do **not** delete the `key_material` rows to get past it — that regenerates
the SSH host key and the CA, which is indistinguishable from a
machine-in-the-middle to every operator and every issued certificate. Roll back
to the old key instead, and upgrade.

The rotation is **resumable**: a secret that already decrypts under the new key
is skipped, so an interrupted run can simply be run again rather than leaving a
half-rotated store.

> ⚠️ **Keep the old KEK for as long as you keep sealed recordings.** A sealed
> session recording (`PAM_RECORDING_ENCRYPT*`) carries its own data key wrapped
> **inside the file** by whichever KEK was current when it was written, so a KEK
> rotation does not re-wrap it — and `-rotate-kek` deliberately does not try.
> Rewriting a recording would change its bytes, and the SHA-256 of those exact
> bytes is what the audit trail and the recording hash chain hold; re-wrapping
> would make every archived recording read as *never audited*, destroying the
> tamper evidence the sealing exists to provide, in order to save a key. The
> command counts sealed recordings and warns you by name of the KEK they still
> need. Discard that key and those recordings become permanently unreadable.

**DoubleLocked credentials (Phase 135) need none of this.** A credential's
DoubleLock protection (§6, "DoubleLock") is deliberately never wrapped by
the KEK at all — it is a second, independent encryption keyed directly by
the DoubleLock password, not by anything `-rotate-kek` touches. Run
`-rotate-kek` freely; every DoubleLocked credential comes through unaffected
and you do not need to retain the old key on their account.

### On-prem HSM (PKCS#11 KEK)

For a hardware security module, the AES wrapping key lives *inside* the HSM and
data keys are wrapped/unwrapped there — the KEK never leaves the token. This
provider needs cgo and the vendor PKCS#11 module, so it is **not** in the default
static image; build with the tag (`go build -tags pkcs11`) or use
`deploy/docker/Dockerfile.pkcs11`. There is no published PKCS#11 image — you
build it, so pass the same build arguments the release pipeline passes the
default one, or the container reports `pam-server dev (none)` from `-version`,
from its startup log and from `pam_build_info`, and you lose the ability to tell
which build an HSM-backed deployment is running:

```bash
docker build -f deploy/docker/Dockerfile.pkcs11 \
  --build-arg VERSION="$(git describe --tags --always)" \
  --build-arg COMMIT="$(git rev-parse HEAD)" \
  -t pamv1:pkcs11 .            # from the repo root
```

Example with [SoftHSM2](https://www.opendnssec.org/softhsm/)
(swap in your vendor module for a real HSM):

```bash
softhsm2-util --init-token --free --label pamv1 --pin 1234 --so-pin 5678
# create an AES-256 wrapping key labelled pamv1-kek (pkcs11-tool, or your HSM's tooling)

export PAM_KEK_PROVIDER=pkcs11
export PAM_KEK_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export PAM_KEK_PKCS11_PIN=1234
export PAM_KEK_PKCS11_KEY_LABEL=pamv1-kek
export PAM_KEK_PKCS11_TOKEN_LABEL=pamv1
```

Mount the vendor module read-only into the container. Integrity of the vault token
is still provided by the inner AES-256-GCM layer, so the HSM only handles the
confidentiality of the data keys.

---

## 9. Logs & audit

PAMv1 produces **two** independent streams — keep them both:

### 9.1 Operational logs (stdout)

Structured [slog](https://pkg.go.dev/log/slog) lines, one per event, tagged with
`service=` so you can filter per component. Set `PAM_LOG_FORMAT=json` (default)
for a SIEM, or `text` for humans; set verbosity with `PAM_LOG_LEVEL`.

| `service` | Emits |
|---|---|
| `server` | Startup, listening addresses, shutdown |
| `api` | One line per HTTP request (method, path, status, actor, duration), auth failures, `authz` denials, audit mirror |
| `proxy` | Connection authenticated, session started/ended, denials, upstream errors |
| `store` | Postgres connect; per-query trace at `debug` (SQL + duration + rows, **never** arguments) |

Example (JSON):

```json
{"time":"…","level":"WARN","service":"api","msg":"authorization denied","actor":"bob","role":"auditor","method":"POST","path":"/api/targets"}
{"time":"…","level":"INFO","service":"proxy","msg":"session started","actor":"alice","target":"web-01","cred_user":"root"}
```

Collect them where the platform puts stdout: `docker compose logs pam`,
`kubectl -n pamv1 logs deploy/pam-server`, or your log shipper. **PostgreSQL** logs
connections/disconnections in its own container (`docker compose logs db`).

Secrets are never logged: the vault does not log secret operations, and the store
query tracer logs SQL text only, never argument values.

### 9.2 Audit trail (database)

The security record of *who did what*. Read it via the API or the portal's
**Display Audit Trail** screen:

```bash
curl -H "X-API-Key: $PAM_API_KEY" "http://localhost:8080/api/audit?limit=100"
```

Actions include: `target.create/delete`, `credential.create/reveal/delete/rotate/reconcile`,
`user.create/delete`, `access.request/approve/deny/denied`, `authz.denied`,
`breakglass.access/unseal`, `session.start/record/end/denied/error`. The actor is
the real username (or `bootstrap-admin` / `break-glass` / `system-scheduler`).

**Incident-report export (NIS2 Art. 23).** Produce a scoped, tamper-evident slice
of the audit trail for a regulator. The response carries a SHA-256 over the exact
event list (JSON `sha256` field + `X-PAM-Export-SHA256` header) so the file's
integrity can be re-verified later.

```bash
# JSON, a time window, with the integrity digest
curl -H "X-API-Key: $PAM_API_KEY" \
  "http://localhost:8080/api/audit/export?since=2026-07-19T00:00:00Z&until=2026-07-19T06:00:00Z"
# Scope to an actor/action; CSV for a spreadsheet
curl -H "X-API-Key: $PAM_API_KEY" \
  "http://localhost:8080/api/audit/export?actor=break-glass&format=csv" -o breakglass.csv
```

See the [NIS2 Compliance Pack](NIS2-COMPLIANCE.md) for the full Art. 21 control
matrix and the Art. 23 reporting workflow, and §9.2b below for a live report
against that same matrix rather than a raw event slice.

**Tamper-evident audit trail (optional).** By default the audit table is a plain
log; an attacker with database write access could edit or delete rows. Set a
32-byte HMAC key to chain the whole trail — each event is HMAC-linked to the
previous one, so any edit, reorder, or deletion is detectable:

```bash
export PAM_AUDIT_HMAC_KEY=$(openssl rand -base64 32)   # keep it OUT of the database
# ... (re)start pam-server; every new event is now chained ...
curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/audit/verify
# → {"ok":true,"broke_at_id":0}      (ok:false + the offending id if the chain was broken)
```

Keep the key outside the database (a secret manager / env), so an attacker who
compromises only the database cannot recompute a forged chain. This is the same
keyed-HMAC scheme the AI-agent broker's audit chain uses, extended to the primary
trail. Enabling it is non-breaking — pre-existing rows stay unchained and are
skipped by the verifier; only events appended after you set the key are chained.

The HMAC chain catches edits, reorders, and mid-history deletions, but **not tail
truncation** (deleting the newest events leaves a shorter, still-valid chain). To
catch that, also set an ed25519 signing seed and periodically fetch and archive a
**signed checkpoint**:

```bash
export PAM_AUDIT_SIGN_SEED=$(openssl rand -base64 32)   # keep it OUT of the database
curl -H "X-API-Key: $PAM_API_KEY" http://localhost:8080/api/audit/head > checkpoint-$(date +%F).json
# → {"last_id":12345,"head":"…","ts":"…","signature":"…","public_key":"…"}
```

Store each checkpoint out-of-band (a WORM bucket, a ticket, a signed email). Later,
if the current chain no longer reproduces a stored checkpoint's signed
`(last_id, head)` — verified against the published `public_key` — the tail was
truncated. This is the same signed-head mechanism the broker chain exposes at
`GET /v1/audit/head`.

**Streaming to a SIEM (Phase 35).** To feed a SIEM (Splunk, QRadar, Sentinel, …)
continuously rather than exporting on demand, point PAMv1 at a syslog/CEF
collector:

```bash
export PAM_AUDIT_FORWARD_ADDR=siem.internal:514
export PAM_AUDIT_FORWARD_PROTO=udp          # or tcp, or tls (syslog over TLS, RFC 5425)
export PAM_AUDIT_FORWARD_FORMAT=rfc5424      # or cef (ArcSight), or leef (IBM QRadar)
# For tls: verification is ALWAYS on (there is no insecure switch — this stream
# is your evidence). Optionally pin the collector's CA; empty = system roots.
export PAM_AUDIT_FORWARD_CA=/etc/pam/siem-ca.pem
```

Every audit event is then streamed as it is written, in order. Over `tls` the
syslog format uses the octet-counted framing RFC 5425 requires (rsyslog's
`imtcp` with TLS and syslog-ng accept it natively); `cef` and `leef` records
stay newline-delimited on every transport, which is what ArcSight and QRadar
collectors expect. The forwarder
tracks a **durable cursor** (the last event it delivered, persisted in the
settings table), so a restart resumes exactly where it left off — no gap, no
replay — and a collector outage just means the backlog is delivered once it comes
back (the cursor only advances after a successful send). In a multi-replica
deployment the forwarder runs under the same **leader lock** as the other
background workers, so you get one stream, not one per pod. Enabling it starts
from the current head (it does not flood the SIEM with all prior history).

**Retention (Phase 36).** Recordings and audit rows grow without bound unless you
prune them. A leader-locked worker (one replica per tick) sweeps on a schedule:

```bash
export PAM_RECORDING_RETENTION_DAYS=90    # delete recordings older than 90 days
export PAM_AUDIT_RETENTION_DAYS=365       # delete audit rows older than a year
export PAM_RETENTION_INTERVAL_HOURS=24    # sweep daily (default)
```

Recording pruning preserves the `.chain` head (and any non-recording file), so it
never corrupts the recordings' hash chain. **Audit pruning is refused while the
tamper-evident HMAC chain is enabled** (`PAM_AUDIT_HMAC_KEY`): deleting old rows
would break `GET /api/audit/verify`, so the worker declines the delete and logs a
warning. Both windows default to `0` (keep forever). Each sweep audits what it
removed (`recording.pruned`, `audit.pruned`).

**Archive to WORM before pruning (Phase 49).** Deleting evidence is only
acceptable once it is safely somewhere else. Point the worker at an archive
directory — an S3 Object Lock mount, a WORM appliance, any write-once volume —
and pruning becomes archive-then-prune:

```bash
export PAM_RETENTION_ARCHIVE_DIR=/mnt/worm/pamv1
```

- Aged audit rows are exported as **JSON Lines** (one complete event per line, so
  a truncated file still parses up to the break) and aged recordings are **moved**
  there instead of destroyed — the artifact and its hash-chain membership survive.
- **The prune runs only if the archive succeeded.** A full or unwritable archive
  costs you disk space, never the trail: the worker logs an error and deletes
  nothing.
- Each export appends `audit.archived` / `recording.archived` naming the file and
  stamping the **SHA-256 of the bytes on disk**, so an auditor re-hashes the
  archive and proves it is what was removed.
- Files are written once (`O_EXCL`, mode `0400`) and never overwritten. PAMv1
  can't make your storage immutable — that's the mount — but it will not replace
  an archived artifact.
- **With the HMAC chain on you now still get the scheduled export**; only the
  delete stays manual (re-anchor the chain, then reclaim the space).

### 9.2b A live NIS2 compliance report (Phase 114)

The exports above hand over a raw slice of the audit trail; a regulator or
auditor usually wants it **mapped to the controls it's supposed to evidence**.
`GET /api/compliance/nis2` produces a canned report against the same Art.
21(2) matrix as the [NIS2 Compliance Pack](NIS2-COMPLIANCE.md) §1, scoped to a
time window:

```bash
curl -H "X-API-Key: $PAM_API_KEY" \
  "http://localhost:8080/api/compliance/nis2?since=2026-07-01T00:00:00Z&until=2026-08-01T00:00:00Z"
```

Each control comes back with its **status** — `implemented` or `partial`,
architectural, the same as the doc: whether the capability exists, not
whether it happened to fire in this particular window — and, for controls
with a natural audit signal, an `evidence.families` count of matching events
in the window, bucketed by the action's family prefix (`vendor.*` for (d)
supply-chain security, `certification.*` for (f)/(i), `mfa.*`/`login.*` for
(j), and so on). Control (b) — incident handling — additionally carries the
current `GET /api/audit/verify` result, labeled honestly
`"whole-chain (bounded-range verification is not supported)"`: this report
does not claim to prove the chain was intact *only* during the requested
window, just that it is intact now, end to end. A quiet window on a
window-scoped control is not a finding — it means nothing of that kind
happened, not that the control is broken.

Same conventions as every other evidence export here: `X-PAM-Export-SHA256`
over the exact delivered bytes, deterministic over a fixed window (so
re-running it later for the same dates reproduces the same digest), and the
act of generating it is itself audited (`compliance.nis2_report`). Requires
`CapReadAudit` — the same gate as the raw export and playback. Console:
**F8** from *Display Audit Trail* opens the report screen (since/until
inputs default to the last 90 days; **F9** downloads the JSON).

**Scope, honestly bounded.** Only NIS2 is mapped. PCI-DSS, ISO 27001 and SOX
would each need their own control taxonomy authored by someone who actually
knows that framework — this does not attempt to guess at one, unlike
treating "compliance reporting" as interchangeable across frameworks would
imply. If you need one of those, the building blocks (`ExportAudit`, the
family-prefix bucketing, the digest/audit conventions) are the same ones this
report is built from.

### 9.3 Session recordings

**Encryption at rest (Phase 41).** By default a recording is protected only by its
file permissions — which is a real gap, because the recording holds whatever the
operator typed and saw. Set `PAM_RECORDING_ENCRYPT=true` and each recording is
sealed with its own AES-256-GCM data key, wrapped by the same KEK that protects
your credentials (local, Vault Transit, AWS KMS or a PKCS#11 HSM). Practical notes:

- **Replay is unchanged.** The console player and `GET /api/recordings/{name}`
  decrypt on the way out, and the SHA-256 tamper-evidence check still works because
  the audited hash covers the bytes as stored.
- **Nothing is orphaned.** The format is detected per file, so recordings written
  before you enabled it keep replaying.
- **You lose direct `asciinema` playback** of the raw `.cast`; replay through PAMv1
  (which is the audited path anyway).
- **A KEK outage fails closed** — the session is refused rather than recorded in
  the clear.

**Opaque file names (Phase 48).** Encryption seals the *content*; the file
**name** was still `<timestamp>_<target>_<actor>`, so a backup, a snapshot or
read access to the recording volume told you who reached which system and when
without opening a single file. Set `PAM_RECORDING_OPAQUE_NAMES=true` and
recordings are named `<timestamp>_<random hex>` instead. The mapping does not
disappear — it moves into the audited `session.record` / `winrm.run` event,
where reading it needs `read_audit`, exactly like replaying the recording. The
console's recordings screen (menu 19) resolves it back, so it still lists
Target and Actor per row; `GET /api/recordings` returns the same two fields.
Set both flags together to cover content and metadata. Recordings written under
the old naming keep their names and keep replaying; nothing is migrated. Leave
the flag off and the file name still carries target and actor, so treat the
directory listing itself as metadata worth protecting.

Each proxied session is recorded in [asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/)
under `PAM_RECORDING_DIR`, and its SHA-256 is written to the audit trail (tamper
evidence). Replay with [asciinema](https://asciinema.org/): `asciinema play <file>.cast` —
or straight from the console (Phase 26): **Session recordings**, menu **19**,
lists what's on disk and replays a recording in a keyboard-first player (Space
pause, F5 restart, F6 speed). At replay time the server **recomputes the file's
SHA-256 and checks it against the audit trail** (`session.record` / `winrm.run`):
the response carries `X-PAM-Recording-Audited: true|false`, the player shows the
verdict, and the replay itself is audited `session.playback`. The API twin:

```bash
curl -s https://pam.example/api/recordings -H "X-API-Key: $PAM_API_KEY"          # list
curl -sD- https://pam.example/api/recordings/<name>.cast -H "X-API-Key: $PAM_API_KEY" -o session.cast
```

Both need `read_audit` (auditor+). A recording flagged `false` was tampered with,
truncated, or written outside the audited path — treat it as evidence of a
problem, not as evidence of the session.

**Content search (Phase 110).** `GET /api/recordings/search?q=<text>` finds a
string anywhere in the newest 500 SSH recordings' output, case-insensitively —
even text a slow terminal echoed a few bytes at a time, which grepping the raw
`.cast` file would miss, since the search reconstructs the concatenated output
before matching. Each hit reports a sanitized snippet and the playback time
the match starts at; the console's search screen (**F4** from *Session
Recordings*, menu 19) jumps a replay straight there instead of making you
scrub for it. Works over encrypted-at-rest recordings transparently. Same
`read_audit` gate as playback — search discloses nothing a holder could not
already reach by opening each recording in turn — and is itself audited
(`session.search`) with the query, fail-closed: the query is the sensitive
fact here, independent of whether it matched anything. RDP/VNC recordings
(guacd's binary protocol has no text layer) and WinRM transcripts (plain
text, but out of scope for this pass) are not covered.

```bash
curl -s "https://pam.example/api/recordings/search?q=aws_secret_access_key" -H "X-API-Key: $PAM_API_KEY"
```

### 9.3b What actually RAN: post-session forensic reconstruction (Phase 157)

A session recording shows what was **typed**. That is not the same as what
**ran**: `echo Y3VybCAtcyBodHRwOi8vZXZpbA== | base64 -d | sh` records one
innocuous-looking line, and `stty -echo` records nothing at all. §9.4's command
control has the same blind spot by design — PAMv1 never parses an interactive
PTY, and its own documentation says so.

**Why PAMv1 cannot solve this with a kernel probe.** Teleport closes this gap
with eBPF because its SSH service runs *on the node*: a session's processes are
its own children, in its own kernel. PAMv1 is a **proxy** — your shell runs on
the target, under the target's sshd, in the target's kernel — so an eBPF exec
tracer on the PAMv1 host would see exactly nothing of a brokered session.
Kernel-level in-session tracing would mean putting PAMv1 inside the target,
which is a different product shape. That limitation is permanent and documented
([EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md)), not a to-do.

**What PAMv1 does instead.** The target's own kernel already keeps the record —
the Linux audit subsystem, fed by the same syscall hooks an eBPF probe taps.
When an interactive SSH session ends, PAMv1 runs ONE fixed, read-only command
over that target's own vaulted credential, on a fresh connection (never the live
session), filters the records to the session's window, and stores the result as
a hash-chained artifact beside the recording:

```bash
PAM_SESSION_FORENSICS=true                # off by default
PAM_SESSION_FORENSICS_MAX_EVENTS=500      # per artifact; a cap that bites says so
PAM_SESSION_FORENSICS_TIMEOUT_SEC=30
```

The command is **fixed and not configurable** (a settable remote command run
with a privileged credential is a policy hole):
`ausearch -m EXECVE -ts today | tail -c 1048576`.

**What the target needs.** `auditd` running with exec auditing enabled — most
hardened Linux baselines (CIS, STIG) already have it; if yours does not, the
usual rule is:

```bash
# /etc/audit/rules.d/pamv1.rules
-a always,exit -F arch=b64 -S execve -k pamv1-exec
-a always,exit -F arch=b32 -S execve -k pamv1-exec
```

and the vaulted credential must be able to read the audit log (root, or an
account your `sudo`/file policy permits). If it cannot, PAMv1 says so —
`session.forensics_unavailable` with the reason, and an artifact that reads
`UNAVAILABLE: …`. **"The target could not tell us" never renders as "nothing
ran."** A target whose sessions cannot be reconstructed is itself a finding
worth alerting on.

**Reading the result.** The artifact is a `.forensics.log` beside the
recordings, listed in the console's *Work with Recordings* (menu 19) with kind
`forensics` and replayable there like any transcript; its SHA-256 is on the
`session.forensics` audit row, so playback flags a file tampered on disk exactly
as it does for a recording. Each line names the time, pid/ppid, the login uid
(`auid`, which survives `su`/`sudo` — the field that ties an exec back to a
person on a shared account), the binary, and the command **as executed**, with
auditd's hex and chunked encodings decoded.

**Boundaries, stated plainly:**

- **Audit-only.** It reports after the fact and blocks nothing; it makes no
  containment claim (§9.4's disclaimer is unchanged).
- **Interactive SSH only.** WinRM, Kubernetes and the database proxies already
  audit every discrete command they broker, so they have no equivalent blind
  spot.
- **As trustworthy as the target's own logs.** A root operator on the target can
  tamper with them — exactly as they could unload an eBPF probe. Forward the
  target's audit log to your SIEM if that matters to you.
- **Zero Standing Privilege sessions are not reconstructed**: the session's
  certificate was minted for that session and is gone, and minting another after
  the approval was consumed would be a fresh privileged access. That refusal is
  audited.
- **It runs one extra command per session** — hence off by default.

Audit: `session.forensics` (events, window, artifact + hash),
`session.forensics_unavailable` (the finding above), `session.forensics_failed`
(PAMv1 could not ask: dial/exec/decrypt failure, or a deny pattern that matched
its own literal — also audited as `command.blocked … path:forensics`).

### 9.4 Supervising live sessions & command control (Phase 16)

Beyond after-the-fact recordings, a supervisor can **watch a session as it
happens** and policy can **block a dangerous command mid-stream**.

**Live monitoring.** In the console, **Work with Active Sessions** option **5**
opens a view-only watch pane on a session. The underlying endpoint is
`GET /api/sessions/{id}/stream`, which streams a live session's
output as [Server-Sent Events](https://developer.mozilla.org/docs/Web/API/Server-sent_events)
(requires `CapReadAudit`; the watch is audited `session.monitor`). List the live
sessions first to get an id, then follow one:

```bash
curl -s https://pam.example/api/sessions -H "X-API-Key: $PAM_API_KEY"
curl -N https://pam.example/api/sessions/<id>/stream -H "X-API-Key: $PAM_API_KEY"
```

The stream **ends when the session does** — completed or killed — so the portal
pane reports "session ended" rather than sitting silent; and watching an id
that is not live is refused with 404 instead of subscribing you to a stream
that will never speak. In a multi-replica deployment both calls are
**cluster-wide** (Phase 55): the listing merges a shared inventory in which each
session names its hosting replica (`"replica"` in the JSON), and a watch request
landing on the "wrong" replica still streams — the hosting pod relays the
session's output over the store bus, only while someone is watching, and the
watch is audited with a `via:relay` marker. If the hosting replica crashes
mid-watch, the stream closes within ~45 seconds (its inventory rows age out)
rather than hanging. A session unknown anywhere is refused 404 (with the bus
down, the refusal wording falls back to "not live on this replica"); refused
watches are audited (`session.monitor` with a `refused:` detail), so probing
session ids leaves a trace. Deciding a **paused step-up** crosses replicas too
(Phase 56): `GET /api/sessions/stepups` lists every replica's pauses (each row
naming its hosting `replica`), and a decision posted to the "wrong" replica is
dispatched — sealed, like everything on the bus — to the one whose memory holds
the pause. That path answers **202 Accepted** (dispatched, in the kill-switch's
mold) rather than claiming the statement moved; refresh the pending list to
verify. Nobody may decide their own session's step-up from any replica.

It works for SSH, PostgreSQL and WinRM sessions — the proxy's interactive WinRM
shell streams the same bytes its recording sees, and a REST or agent-broker
WinRM run streams a `winrm>` command echo plus the output — and delivery is
non-blocking (a slow watcher drops frames and never stalls the session being
observed). RDP sessions are not streamed to the watch pane; supervise those
through the clipboard audit and the recording.

**Killing a session (HA).** `DELETE /api/sessions/{id}` terminates a live session.
In a multi-replica deployment the session may be pinned to a different pod than
the one that receives your request: since Phase 34 the kill is **broadcast across
replicas** (Postgres `LISTEN`/`NOTIFY`), so it terminates the session wherever it
is hosted — and the same cluster-wide broadcast backs the revoke cascade, vendor
offboarding and the analytics auto-kill. The response is **204** when the session
was on the replica you hit and **202 Accepted** when the kill was dispatched to
the cluster. (Since Phase 55 live *monitoring* and session *listing* cross
replicas too, over an interest-gated, sealed relay — and since Phase 56 so does
deciding a paused step-up, over a sealed decision bus in the same mold.)

**Command control.** Point `PAM_COMMAND_DENY_FILE` at a file of regular
expressions (one per line, `#` comments). A command matching any pattern is
**refused before it reaches the target** and audited `command.blocked`:

```
# /data/command-deny.txt — deny destructive commands
rm\s+-rf\s+/
(?i)drop\s+(table|database)
(?i)truncate\s+table
:\s*\(\s*\)\s*\{         # shell fork bomb
```

Enforcement covers every path where a discrete command is visible:

| Path | Behavior when a pattern matches |
|---|---|
| SSH `exec` (`ssh target "cmd"`) | The request is refused, never forwarded. |
| Interactive **WinRM** command-loop line | The line is refused; the loop stays usable. |
| **PostgreSQL** statement | A simple query is refused but the session stays usable; an extended/prepared statement fails closed. |
| `POST /api/targets/{id}/winrm` | HTTP **403**; the command never reaches the host and the credential is never decrypted (Phase 38). |
| Agent broker `ssh_exec` / `winrm_exec` | The tool call fails with the policy refusal, before any dial or decrypt (Phase 38). |

The last two matter because the guard is one shared policy: an AI agent calling a
brokered tool is held to exactly the patterns you wrote for your operators. Every
refusal — whichever path — is audited `command.blocked` with the matched pattern.

**Allow-listing (Phase 131).** Point `PAM_COMMAND_ALLOW_FILE` at a second file,
same format, to narrow every path above to ONLY the listed commands —
Delinea's "Command Menus" is the closest commercial-PAM analogue. A deny-file
match still wins even if the allow-file would also match the same command;
anything matching neither file is refused once an allow-list exists at all:

```
# /data/command-allow.txt — the only commands operators may run
^service\s+nginx\s+(status|restart)$
^df\s+-h$
^systemctl\s+status\s+\w+$
```

Setting `PAM_COMMAND_ALLOW_FILE` is optional and independent of
`PAM_COMMAND_DENY_FILE` — leave it unset and every path stays exactly
deny-only, as it always has been. A refusal from the allow-list is audited
`command.blocked` with `pattern:not-allowed`, distinguishing it from a
deny-pattern match in the same audit query.

Interactive SSH **shells** stream a raw terminal and are *not* parsed, so this is
**not a containment boundary**: use read-only observer sessions
(`ssh <cred>@<target>+observe@pam`) or restrict shell access where you need that
guarantee.

**The discrete-command paths above (SSH `exec`, WinRM, both database proxies) are
best-effort too, not a hard boundary.** The guard matches your regexes against
the raw statement text with no normalization, so a determined operator can evade
a pattern by obfuscating the statement: SQL comments (`DROP/**/TABLE users`) and
odd whitespace defeat `(?i)drop\s+table`, and on the simple-query path a pattern
anchored to the start (`^drop`) misses a statement smuggled after a benign one
(`SELECT 1; DROP TABLE users`). Write patterns **unanchored and case-insensitive
(`(?i)`)**, and treat the guard as defense-in-depth plus an audit trail — **the
same caveat applies to the step-up (four-eyes) gate**, so a hard guarantee that a
sensitive statement cannot run without supervisor approval must come from
**database-side roles and permissions**, not from `PAM_DB_STEPUP_FILE` alone. The
proxy deliberately embeds no SQL parser — that is a fixed design decision, and it
is why the gate is regex-over-text rather than statement-aware.

**SFTP file-transfer control (Phase 32).** SFTP is not caught by the command
denylist — it rides its own SSH *subsystem* channel carrying a binary protocol.
`PAM_SSH_SFTP` governs it independently:

| Value | Behavior |
|---|---|
| `allow` (default) | File transfer is forwarded, and **every operation is audited** — `sftp.session` (subsystem opened), `sftp.open` (with `mode:read`/`mode:write`), `sftp.modify` (remove/rename/mkdir/rmdir/setstat/symlink). |
| `readonly` | Downloads work; any **upload, delete, rename, mkdir, chmod, or symlink is refused** with an SFTP permission-denied (`sftp.blocked`) — the target is never contacted for the write. |
| `deny` | The SFTP subsystem is **refused outright** (`sftp.denied`); the operator keeps a shell but cannot transfer files. |

This closes an otherwise **unaudited** file path: before Phase 32 the SFTP stream
passed through opaque. Note it governs SFTP specifically — `scp` run *inside* an
interactive shell rides the unparsed PTY (as above); pair `readonly` with shell
restriction for full containment.

**Path policy (Phase 51).** The three modes govern the *operation*; they say
nothing about *which file*. `readonly` still lets an operator download
`/etc/shadow` or a private key — often the transfer that actually matters. Point
`PAM_SSH_SFTP_DENY_FILE` at a regex file (same format as the command deny file)
to gate by path:

```bash
# /etc/pam/sftp-deny.txt
^/etc/shadow$
^/etc/ssh/ssh_host_.*_key$
\.pem$
```

- A matching path is refused in **every** mode, **downloads included** — a path
  you deny that can still be fetched is not denied at all.
- **Both sides of a rename** are checked, so a denied file cannot be moved to an
  innocuous name (nor an allowed file onto a denied one).
- The operator gets a proper permission-denied error (not a hang), the path is
  never sent to the target, and the audit records
  `sftp.blocked … reason:path-denied pattern:<the rule that matched>` — so you
  can tell *which* rule fired.
- A bad pattern fails startup, like the command deny file.

Patterns are regular expressions, not shell globs: write `\.pem$`, not `*.pem`.

**Content capture (Phase 59).** Operation audit tells you a file moved; capture
keeps **what** moved. With `PAM_SSH_SFTP_CAPTURE` set to `uploads`, `downloads`
or `all`, every file transferred through the SFTP subsystem produces a `.sftp`
artifact in the recording directory — a chunk log of the actual bytes with
their offsets — that behaves exactly like a session recording: sealed at rest
under `PAM_RECORDING_ENCRYPT`, SHA-256 linked into the recording hash chain,
named opaquely under `PAM_RECORDING_OPAQUE_NAMES`, swept by retention, archived
to WORM, and replayable from **menu 19** (a `file` entry downloads the
reconstructed content, hash-verified) or
`GET /api/recordings/<name>` (`?raw=1` for the raw chunk log). The closing
audit event `sftp.file_recorded` ties path, artifact, byte counts, hash and
chain position together.

Three behaviors to know before enabling it:

- **Capture is containment.** While it is on, an SFTP stream the proxy cannot
  parse is **refused** (`sftp.parse_error … fails closed`) instead of passing
  through opaque — otherwise any client could evade capture by being
  unparsable. The same stance covers requests it cannot *account for*: an
  artifact that cannot be written, a request id reused while another is still
  in flight, `copy-data@openssh.com` (which copies inside the server, where no
  bytes cross the proxy), and any `SSH_FXP_EXTENDED` operation PAMv1 does not
  recognize. Each refusal is audited `sftp.blocked` with its reason.
- **The cap refuses, it does not truncate.** `PAM_SSH_SFTP_CAPTURE_MAX_MB`
  (0 = unlimited) refuses data past the cap with a permission-denied — the
  operator's transfer fails there — so it doubles as a per-file size limit. It
  binds downloads as well as uploads: a read claims the bytes it asks for when
  it is admitted, so a client's pipelined reads cannot outrun the limit. **Size
  it above your largest legitimate transfer**, and note that a file of exactly
  the cap size fails on its final end-of-file read.
- **Disk.** Captured content is roughly ⅓ larger than the files themselves
  (base64 + framing, plus the seal). Budget the recording volume and set
  `PAM_RECORDING_RETENTION_DAYS`/`PAM_RETENTION_ARCHIVE_DIR` accordingly.

**ICAP file-transfer scanning (Phase 143).** Content capture (above) keeps
what moved; ICAP scanning **inspects** it. `PAM_ICAP_URL` points at an ICAP
RESPMOD service (`icap://host[:port]/service`) — a real AV/DLP gateway
(c-icap, Symantec, McAfee, Forcepoint/Websense and similar all speak this
protocol) — and every finalized upload or download's captured bytes are
submitted to it whole:

```bash
export PAM_SSH_SFTP_CAPTURE=all
export PAM_SSH_SFTP_CAPTURE_MAX_MB=100   # required: also bounds the in-memory scan buffer
export PAM_ICAP_URL=icap://av-gateway.example:1344/respmod
```

- **Detection, not prevention — read this before relying on it.** A
  whole-object scan needs a *complete* file, which only exists once a
  transfer has finished — by which point an upload has already reached the
  target and a download has already reached the operator. An unreachable or
  malfunctioning ICAP server does not block the transfer; it audits
  `sftp.icap_scan_failed` and the file still moves. True pre-delivery
  blocking would mean buffering and delaying every transfer, a design this
  proxy does not implement. Treat this as a forensic/DLP-visibility control,
  not a gate.
- **A flagged file is audited loudly.** `sftp.icap_flagged` names the
  vendor's own reason (read from whichever threat header the gateway sent —
  `X-Infection-Found`, `X-Virus-ID`, and similar). A clean verdict is **not**
  separately audited — `sftp.file_recorded` already proves the transfer
  happened, and auditing "clean" on every single file would drown the rest
  of the session's trail for no operational gain.
- **Requires capture, and a bounded size.** `PAM_ICAP_URL` refuses to start
  without `PAM_SSH_SFTP_CAPTURE` enabled and `PAM_SSH_SFTP_CAPTURE_MAX_MB`
  set above zero — the same byte cap that bounds the disk artifact also
  bounds how much of the file is held in memory for scanning.
- **A capped or broken capture is skipped, not scanned incomplete** —
  `sftp.icap_skipped … reason:over-capture-limit` or
  `reason:incomplete-capture`. Reporting a partial file as scanned-clean
  would be a false negative wearing a real result's audit trail.
- **Air-gapped deployments**: because this is a live outbound endpoint, it
  also joins the `PAM_OT_AIRGAP` conflict list — an air-gapped deployment
  that sets `PAM_ICAP_URL` without adding it to `PAM_OT_AIRGAP_ALLOW` is
  refused at startup, the same as every other webhook this guide documents
  (see [OT-DEPLOYMENT.md](OT-DEPLOYMENT.md)). An ICAP appliance reachable
  only inside the enclave is the expected shape here, not a cloud service.
- **SFTP only in v1.** RDP clipboard file transfer is not scanned.

**Port forwarding (Phase 141).** An operator's `ssh -L` request is admitted
as a normal SSH proxy feature, scoped tightly: **only to the connected
target's own host**, StrongDM's forwarding closed without the open-ended
version real `ssh -L` gives a direct connection.

```bash
# psql through a forward to a Postgres bound only to loopback on the target
ssh -L 5432:localhost:5432 root@web-01@pam.example
# → in another terminal: psql -h localhost -p 5432 ...
```

- **Same host, any port.** The target's own configured port is its *SSH*
  port — pinning a forward to it would defeat the point, since the whole
  reason to forward is reaching a *different* service (a database, an
  internal admin UI) on the same box. `localhost`/`127.0.0.1`/`::1` count
  as "the target" too: the forward dials out through the already-connected
  upstream, so loopback resolved there **is** the target — the
  `ssh -L X:localhost:Y` form above is the common case, not an edge case.
- **Any other host is refused before it is ever dialed** — `forward.refused
  reason:not-same-host` — closing what would otherwise be an SSRF pivot
  into the target's own network using PAMv1 as the launch point.
- **Three sessions never get it, regardless of `PAM_SSH_PORT_FORWARD`**: an
  **observer** session (`+observe`) — forwarding would be a full read-write
  data path wearing a read-only label; a session while
  **`PAM_REQUIRE_LIVE_SUPERVISION`** is set — a forward has no
  supervisor-wait mechanism to honor; and a session while
  **`PAM_REQUIRE_RECORDING`** is set — forwarded bytes are opaque and were
  never going to be recorded, so "required" means refused, not silently
  unrecorded.
- **`PAM_SSH_PORT_FORWARD`** (default `true`) turns the whole feature off
  deployment-wide if set to `false` — every forward is refused regardless
  of destination.
- **Audit is connection-level, not content**: `forward.start`/`forward.end`
  (destination, byte counts each direction, duration) and `forward.refused`
  (destination rejected, or a policy gate declined). No parser exists for
  arbitrary forwarded application data the way there is for exec/SQL, the
  same honest limit interactive shells already have.

**In-session step-up (Phase 30).** Where command control is a hard block, step-up
is a **pause for a live human decision** — the session stays open. Point
`PAM_DB_STEPUP_FILE` at a regex file (same format as the deny file); a matching
**PostgreSQL** statement pauses (audited `db.stepup_required`, shown on the live
monitor) and waits up to `PAM_DB_STEPUP_TTL_SEC` (default 120) for a supervisor:

From the console: **In-session step-up decisions** (menu 21) lists what is paused
and decides it with option 5 (allow) or 6 (refuse) — the screen a supervisor
should keep open, since these expire. Or over the API:

```bash
curl -s "$PAM/api/sessions/stepups" -H "X-API-Key: $KEY"          # what's paused
curl -s -XPOST "$PAM/api/sessions/<session-id>/stepup" -H "X-API-Key: $KEY" -d '{"approve":true}'
```

An **approval** runs the statement (`db.stepup_approved`); a **denial or timeout**
refuses it (`db.stepup_denied`) but leaves the session usable. **Listing** what is
paused needs `read_audit` — the same gate as the live stream, so anyone who can
watch can see it — but **deciding** needs `approve`: releasing a statement the
policy flagged is an authorization, not an observation, so a read-only `auditor`
is refused (Phase 39). For the agent broker, policy rules can
also gate on an **amount** with the numeric comparators `gte`/`gt`/`lte`/`lt`
(e.g. `when: { args.amount: { gte: 5000 } }` → `require_approval`).

### 9.4b Mandatory live supervision (Phase 112)

Live monitoring (9.4) is opt-in: a supervisor *may* watch. `PAM_REQUIRE_LIVE_SUPERVISION`
makes watching **mandatory** — an interactive SSH session will not proceed until
someone is actually attached to `GET /api/sessions/{id}/stream`, not just
reviewable afterward from the recording.

```bash
export PAM_REQUIRE_LIVE_SUPERVISION=true
export PAM_LIVE_SUPERVISION_TIMEOUT_SEC=120   # default; how long a session waits
```

When set, the proxy holds the channel open — **before it dials the target**, so
nothing is relayed anywhere in the meantime — polling `session.Hub.HasSubscribers`
for up to the timeout. A supervisor attaching the live-monitor stream at any
point during the wait (on any replica, per the cross-replica relay in 9.4)
releases the session immediately; most sessions never notice the check, since a
supervisor who is already watching the queue satisfies it before the channel
even opens. A session that times out unwatched is refused
(`PAMv1: no supervisor attached to watch this session; refused`) and audited
`session.unsupervised` with the target, credential username and configured
timeout — nothing reaches the target.

Two exemptions, both because the requirement would be meaningless against them:

- **Observer sessions** (`ssh <cred>@<target>+observe@pam`) — an observer *is*
  the watching role, not a session that needs one.
- **Break-glass** — the emergency key exists precisely for when no supervisor
  is reachable; gating it on supervision would defeat its purpose.

Scope today is **SSH only** — the PostgreSQL and WinRM proxies register their
live session *after* dialing the target (see `internal/proxy`), so gating
before dial would need a larger rework; they are left for a future phase. There
is no per-target override: the flag is global, like `PAM_REQUIRE_RECORDING`.

### 9.4c Sharing a live session (Phase 116)

Live monitoring (9.4) lets a supervisor watch; **session sharing** lets the
operator **in** the session bring a second party into it — view-only, or
view-**control** where the joiner can type too — through the same four-eyes
shape as an access request: one principal **requests**, a **different**
principal **decides**.

```bash
# 1. Request a share on a live session (needs `connect` — the operator
#    running it). mode: view_only | view_control. kind: internal (a named
#    PAMv1 user, by username) or external (an email address — no account
#    needed).
curl -sX POST https://pam.example/api/sessions/<id>/share -H "X-API-Key: $OPERATOR" \
  -d '{"mode":"view_control","kind":"internal","invitee":"carol"}'
# → {"id":9,"status":"pending",...}

# 2. A DIFFERENT principal decides it (needs `approve`; deciding your own
#    request is refused and audited, same four-eyes as certification).
curl -sX POST https://pam.example/api/share-invites/9/approve -H "X-API-Key: $APPROVER"
# → {"id":9,"status":"approved","token":"..."}   # internal: the token, shown ONCE, right here

# List a session's invites, or see who has actually joined:
curl -s https://pam.example/api/sessions/<id>/share        -H "X-API-Key: $KEY"  # read_audit
curl -s https://pam.example/api/sessions/<id>/share/roster -H "X-API-Key: $KEY"  # read_audit
```

**Internal invite — redeemed over SSH, never the token alone.** Carol connects
with the token as her **entire SSH username**, `join:<token>`, and her **own**
PAM password exactly as any other connection:

```bash
ssh -p 2222 join:7f3a9c...@pam.example
# Password: <Carol's own PAM token — not the invite token>
```

PAMv1 authenticates that password first — the same resolution an ordinary
connection goes through, so an enroll-only or tunnel-only principal is refused
here too — and only then checks the invite: `invitee` must equal Carol
(case-insensitive), and `kind` must be `internal` (an external invite redeemed
this way is refused: *"PAMv1: this invite must be redeemed via its emailed
link"*). `view_control` additionally needs Carol to hold `connect` herself. A
join skips the ordinary connect-admission gates (safe membership, grants,
ticket, approval) by design — it "creates no new access," in the code's own
words, only a seat on a session the primary operator already opened
legitimately.

**External invite — a QR code, redeemed on the web, never SSH.** With
`kind:"external"` and an `email`, approval sends the guest a link **and an
embedded QR code** pointing at `<PAM_PORTAL_URL>/share.html?token=...` — a
page that needs no PAMv1 account at all. It calls
`POST /api/share/redeem/{token}` once, consuming the token, to mint a random
256-bit **guest key**; from then on it authenticates with that key as a query
parameter — `GET /api/share/stream?key=...` for the live output (SSE) and,
for `view_control`, `POST /api/share/input?key=...` for keystrokes. Two
windows govern this, deliberately different:

| Window | Governs | Env var | Default |
|---|---|---|---|
| Invite redemption | How long the emailed link/QR works, **once**, before it expires unused | `PAM_SESSION_SHARE_INVITE_TTL_SEC` | `900` (15 min) |
| Guest viewing session | How long the *minted guest key* keeps working after redemption | `PAM_SESSION_SHARE_GUEST_TTL_MIN` | `240` (4 h) |

An external invite needs real infrastructure to reach the guest at all:
`PAM_ALERT_EMAIL_SMTP`/`_FROM` (§4 — the same SMTP config your alert emails
already use) **and** an absolute `PAM_PORTAL_URL` (`http://` or `https://` —
the default `/` does not qualify). Missing either **refuses invite creation
outright**, loudly (503: *"external session-share invites need
PAM_ALERT_EMAIL_\* and an absolute PAM_PORTAL_URL configured"*) — never a
silently broken link. Internal invites need neither.

**Removing someone.** Revoking an invite
(`POST /api/share-invites/{id}/revoke`, `manage_targets`) stops it being
redeemed again; it does not reach into a session someone has already joined —
that is what **kick** is for:

```bash
curl -sX POST https://pam.example/api/sessions/<id>/share/kick -H "X-API-Key: $ADMIN" \
  -d '{"actor":"carol"}'   # manage_targets
```

In the console: **F6** on a live watch pane opens *Create share invite*; **F7**
opens the invite-decision list for an approver.

Three things worth knowing before you rely on this:

- **`/share.html` is deliberately unauthenticated** — no `X-API-Key`, the same
  posture as the RDP/VNC viewer's tunnel routes. What defends it is the
  invite's single use and short default window, the guest key's 256 bits of
  entropy, and `noindex, nofollow` on the page itself — not a login. Every
  failure on it is still throttled per source IP (`PAM_AUTH_RATE_LIMIT`,
  surface `share-guest`).
- **The guest key lives in memory, not the database, and is per-replica.** In
  a multi-replica deployment a join — internal **or** external — must land on
  whichever replica actually hosts the session; unlike the Phase 55
  live-monitor relay, sharing does not (yet) route across replicas. Behind a
  non-sticky load balancer, a join that lands on the wrong pod should simply
  be retried.
- **Audit vocabulary:** `session.share_requested` · `session.share_approved`
  (fail-closed) · `session.share_denied` (a real decision, or a refused
  self-approval — `reason:self-approval` tells the two apart) ·
  `session.share_revoked` · `session.share_joined` (fail-closed) ·
  `session.share_join_denied` · `session.share_ended` ·
  `session.share_kicked`.

### 9.4d Suspending a live session (Phase 122)

Kill (9.4a) ends a session outright. **Suspend** freezes it instead — the
operator's keystrokes stop reaching the target, the session stays open, and a
later **resume** picks up exactly where it left off. It rides the same input
mux Phase 116 built for session sharing, so it needs no new session-side
plumbing — only a gate on the path from mux to target.

```bash
# Needs `approve` — the same capability that decides a share invite or a
# step-up prompt; freezing someone's live input is that class of decision.
curl -sX POST https://pam.example/api/sessions/<id>/suspend -H "X-API-Key: $APPROVER"
# → {"session":"<id>","suspended":true}

curl -sX POST https://pam.example/api/sessions/<id>/resume  -H "X-API-Key: $APPROVER"
# → {"session":"<id>","suspended":false}

# Check status without changing it — needs only `read_audit`:
curl -s https://pam.example/api/sessions/<id>/suspend -H "X-API-Key: $KEY"
# → {"session":"<id>","suspended":true}   # 404 if the session isn't live here
```

- **The operator is told, not left to think the terminal hung.** The instant
  a session is suspended, its operator gets the same `Stderr`-banner notice
  Phase 116 uses for join announcements — and another on resume. Freezing
  input silently would look indistinguishable from a stuck connection.
- **Idempotent.** Suspending an already-suspended session (or resuming an
  already-live one) is a no-op that still returns `true` — safe to retry, and
  the console's F8 toggle never needs to track state precisely to be correct.
- **Replica-local, like sharing.** The registry behind this has no
  cross-replica bus (unlike the cluster-wide session list or `StepUp`'s
  sealed mirroring); behind a non-sticky load balancer, suspend/resume/status
  must land on whichever replica actually hosts the session. The status
  endpoint 404s rather than guessing when the session isn't live *here* —
  the same honest "not live on this replica" posture `GET /sessions/{id}/stream`
  already uses.
- **Console:** the live-watch pane (**F5**, §9.4) shows an amber *SUSPENDED*
  banner while frozen; **F8** toggles suspend/resume for anyone holding
  `approve`.
- **Audit vocabulary:** `session.suspended` · `session.resumed`.

### 9.4e Session watermarking (Phase 137)

Every session now carries a visible reminder of who is watching it, in the
form the protocol actually supports:

- **RDP/VNC** shows a small overlay in the viewer itself — operator name,
  target, and the time the session started — rendered client-side over the
  Guacamole canvas, `pointer-events: none` so it never intercepts a click
  or keystroke.
- **SSH/PostgreSQL/SQL Server** sessions instead get the same identity as
  a **one-time banner** written into the stream the moment the session
  starts, the same `Hub.Publish` mechanism a WinRM run's own live notices
  already use — so a supervisor watching live (§9.4) or replaying the
  recording later (§9.3) sees exactly who was connected, without PAMv1
  needing to parse or reformat protocol-specific frames to show it.

There is nothing to configure and nothing to enable — every new session
gets its watermark. The text is static identity, not a per-frame dynamic
tracking pattern, and it emits no audit event of its own: it is a display
aid, not a decision.

### 9.5 Metrics & probes

- `GET /metrics` — a Prometheus exposition: `pam_http_requests_total{status}`,
  `pam_audit_events_total`, `pam_breakglass_access_total`,
  `pam_auth_failures_total`, `pam_credential_rotations_total`, and the
  `pam_active_sessions` gauge. It is **unauthenticated** (like `/healthz`) and
  exposes only low-sensitivity counts — restrict it at the ingress/network. The
  Helm chart can render a `ServiceMonitor` (`metrics.serviceMonitor.enabled`).
- `GET /healthz` — liveness (process up). `GET /readyz` — readiness (returns 503
  until the database is reachable); point your load balancer at `/readyz`.
- `pam-server -healthcheck` probes `/healthz` on `PAM_LISTEN_ADDR` and exits
  non-zero when unhealthy. The container images use it as their `HEALTHCHECK`
  because the distroless base has no shell or curl.

### 9.5b Change tickets, checked when access is used (Phase 60)

The ITSM gate (Phase 20) requires a change ticket on an access request and
validates it — by regex format (`PAM_TICKET_PATTERN`) and/or by asking your ITSM
(`PAM_TICKET_VALIDATE_URL`). By default that check happens **once, when the
request is filed**. An approval is then good for `PAM_APPROVAL_WINDOW_MIN`, and
a scheduled request can wait days for its maintenance window, so a change that
is cancelled in the meantime goes on admitting sessions.

Set **`PAM_TICKET_REVALIDATE=true`** and the ticket on the admitting request is
re-checked at the moment access is used — on every path: the SSH, PostgreSQL and
SQL Server proxies, the in-portal RDP/VNC viewer, credential reveal and
check-out, the WinRM run endpoint, and the agent broker's tools.

| What the ITSM says | What happens |
|---|---|
| The ticket is still valid | The use proceeds exactly as before. |
| The ticket is rejected (non-2xx) | The use is **refused** — `access.ticket_revoked` names the ticket and the ITSM's reason, and the denial reads `reason:ticket-not-valid` rather than `reason:approval-required`, so an operator is sent to the right place. |
| The ITSM cannot be reached | Also **refused**. A gate that opens when it cannot do its job is not a gate. |

Three operational points before enabling it:

- **Your ITSM is now on the connect path.** The call is bounded at 5 seconds so a
  slow ITSM cannot hold an SSH handshake open, but an ITSM outage becomes an
  access outage for ticketed requests. That is the trade the control asks for;
  leaving the variable unset keeps the pre-Phase-60 behaviour exactly.
- **A refusal costs the operator nothing but the attempt.** The re-check runs
  *before* the approval is consumed, so a single-use approval is not spent by a
  use the ITSM refused — no going back through four-eyes because your ticketing
  system had a bad minute.
- **One cancelled change does not lock you out (Phase 60a).** If you hold
  several live approvals for the same target, each is checked in turn and the
  one that is admitted is the one whose ticket passed. A cancelled change
  refuses only the approval it belongs to; it neither hides a valid approval
  behind it nor lets a concurrent connection slip in on an unchecked ticket.
  Up to 8 approvals are considered, and the whole walk shares the same
  5-second ITSM budget.
- **Only tickets are re-checked.** An approved request with no ticket is
  unaffected, so turning this on does not silently start requiring tickets; that
  is still `PAM_REQUIRE_TICKET`.

### 9.6 Access certification campaigns (Phase 19)

A **certification campaign** is the periodic "recertify or revoke who has access
to what" review that SOX / ISO 27001 / NIS2 Art. 21(2) expect. Creating a
campaign **snapshots the current access grants** — every target grant, every
safe member, and (since Phase 175) every **AI-agent identity** — into reviewable
items; you then certify (keep) or revoke each, and a **revoke actually removes
the underlying grant**.

**What revoke does depends on the item.** A target grant or safe membership is
deleted, and the holder's live sessions to those targets are cut. An agent
identity is **stopped, not deleted**: a static agent key is suspended, and a
SPIFFE identity is quarantined. Both are reversible and audited under
`reason:certification-revoked`, and both keep the row an investigation would
need — the same stance every other agent control takes.

```bash
# create a campaign (CapManageUsers) — snapshots current access
curl -sX POST https://pam.example/api/campaigns -H "X-API-Key: $PAM_API_KEY" \
  -d '{"name":"Q3 access review"}'      # → {"campaign":{"id":1,...},"items":N}

# review the items, then decide each one
curl -s https://pam.example/api/campaigns/1 -H "X-API-Key: $PAM_API_KEY"
curl -sX POST https://pam.example/api/campaigns/1/items/7/decision \
  -H "X-API-Key: $PAM_API_KEY" -d '{"decision":"revoke"}'   # deletes that grant
curl -sX POST https://pam.example/api/campaigns/1/items/8/decision \
  -H "X-API-Key: $PAM_API_KEY" -d '{"decision":"certify"}'  # attests, keeps it

# close the campaign — the attestation record; further decisions are refused
curl -sX POST https://pam.example/api/campaigns/1/close -H "X-API-Key: $PAM_API_KEY"
```

#### Non-human identities are reviewed too (Phase 175)

Until Phase 175 a campaign covered only what humans hold. AI-agent identities
hold brokered access to the same estate and were reviewed by nobody — and the one
place an agent did appear (a target grant naming it) is stored with subject type
`user`, so it was reviewed as though it were a person.

Each agent identity is now its own item, of kind `agent_key` or
`agent_identity`, with subject type `agent`. The item carries what makes the
question answerable: the owner, the lifecycle state (active / suspended /
expired, or enrolled / seen for an attested identity) and the dormancy signal —
*last used* for a key, *last seen* for an SVID. An agent nobody has called in
four months, owned by somebody who left, is exactly what this review is for.

Safe-scoped campaigns skip agents: an agent is not a member of a safe, and
padding a safe review with unrelated rows is how a review stops being finished.

**Posture now covers agents too (Phase 180).** Device posture has been
re-checked on every human connect and every authenticated REST call since Phase
133; the AI-agent path was not covered, so an agent container reached the broker
on a bearer token alone while an operator's laptop had to prove its health.
Set `PAM_BROKER_POSTURE_REQUIRED=true` (with `PAM_POSTURE_ATTEST_URL` already
configured) and each brokered call attests the calling agent as well.

Three things to know before turning it on:

- **Your webhook will be asked about names it has never seen.** That is why this
  is a separate knob: an existing posture integration answers about laptops, and
  agent identities — an agent-key name, or a full SPIFFE ID — are new subjects to
  it. The request body now carries `{"user": "<name>", "kind": "user"|"agent"}`,
  so a receiver can branch instead of guessing; `user` keeps its name, so an
  existing webhook that ignores unknown fields behaves exactly as before.
- **It costs a webhook call per brokered call.** The check runs last among the
  admission gates, so a quarantined or unenrolled identity is refused locally and
  never reaches your EDR system — but a healthy, busy agent will generate real
  traffic. Size for it, or scope the agents you enable it for by keeping the
  knob off in that deployment.
- **What it proves is narrower than it looks.** For a laptop your EDR system
  knows the device. For a workload, the webhook is answering about a *name*
  PAMv1 verified cryptographically — not about the process holding the
  credential. Binding a credential to its process is workload attestation
  (SPIRE), which stays external. Read an agent posture answer as "the fleet
  manager believes this identity's workload is healthy", never as proof that the
  caller is that workload.

A refusal is audited `agent.posture_denied … reason:posture-check-failed` and
returns the same 401 a bad bearer gets — the agent learns nothing from the reply.

**Four-eyes says when it could not check (Phase 176).** The refusal is
`owner == approver`, so an owner nobody holds — `caro1`, or `platform-team` —
can never match, and the real owner can approve their own agent's call. PAMv1
does not guess: the decision proceeds and the trail records
`broker.approval.four_eyes_unverified` naming the owner. Set
`PAM_BROKER_REQUIRE_KNOWN_OWNER=true` and that decision is refused instead (the
call stays parked, so correcting the owner unblocks it). Turn it on only after
checking the flags below, or approvals for team-owned agents will start failing.

**An owner nobody can offboard is flagged.** An owner is free text on both
identity kinds, and the offboarding cascade matches it as a username *string* —
so `caro1` instead of `carol` means deleting that human will never suspend the
agent, while the row still reads as though somebody were accountable. PAMv1 does
not refuse an owner it does not recognise (a team address or a service account is
a legitimate answer), so it reports one instead: `owner_known` on
`GET /v1/agents` and `GET /v1/agents/identities`, a red owner with a `?` on
console menus 26 and F8, and a WARNING inside the campaign item where a reviewer
is already asking the question. The check is **exact-case**, because every owner
lookup in PAMv1 is: an agent owned by `Carol` while the user is `carol` is
flagged, and it is right to flag it — deleting `carol` would not suspend that
agent.

#### Scope it, or nobody finishes it (Phase 68)

An unscoped campaign snapshots **every** grant and safe member in the estate. On
anything past a demo that is a list of thousands nobody completes, and a review
nobody completes attests to nothing. Two scopes narrow it to a review somebody
actually runs:

```bash
# one safe: its members AND the grants on every target assigned to it —
# covering only the members would leave a target in the safe reachable by a
# direct grant the review never showed
curl -sX POST https://pam.example/api/campaigns -H "X-API-Key: $PAM_API_KEY" \
  -d '{"name":"PCI safe, Q3","scope_kind":"safe","scope_safe_id":4}'

# one subject: everything a person or role holds, anywhere — the leaver review
curl -sX POST https://pam.example/api/campaigns -H "X-API-Key: $PAM_API_KEY" \
  -d '{"name":"leaver: alice","scope_kind":"subject","scope_subject":"alice"}'
```

An unknown `scope_kind`, a `scope_safe_id` that names no safe, or a scope with
its value missing are all **422** — never a silent widening to "everything",
because a typo that quietly reviews the whole estate produces exactly the
unreviewable campaign the scope exists to prevent.

#### Repeat it, so it does not depend on remembering (Phase 68)

`recur_days` makes a campaign the **anchor** of a recurring series: every N days
PAMv1 opens a fresh campaign with the same name and scope, snapshotting access as
it stands then. Recertification is a calendar obligation, and a control that
needs somebody to remember a button lapses the first busy quarter.

```bash
curl -sX POST https://pam.example/api/campaigns -H "X-API-Key: $PAM_API_KEY" \
  -d '{"name":"PCI safe","scope_kind":"safe","scope_safe_id":4,"recur_days":90}'
```

- The schedule lives on the anchor and never moves. Successors are ordinary
  campaigns carrying no schedule, so a series cannot fork.
- **Closing the anchor stops the series.** That is the only stop button, and it
  is the one an operator would reach for first.
- It runs under the HA leader lock, so N replicas open one campaign, not N. The
  worker is always on — there is no interval to configure and nothing to forget.
- `recur_days` is capped at 366.

#### Give each item an owner (Phase 69)

Work that is everyone's is nobody's. A campaign can name a **default reviewer**,
stamped onto every item it snapshots, and any single item can be reassigned:

```bash
curl -sX POST https://pam.example/api/campaigns -H "X-API-Key: $PAM_API_KEY" \
  -d '{"name":"PCI safe, Q3","scope_kind":"safe","scope_safe_id":4,"reviewer":"carol"}'

# reassign one item (CapManageUsers); "" unassigns it
curl -sX PUT https://pam.example/api/campaigns/1/items/7/reviewer \
  -H "X-API-Key: $PAM_API_KEY" -d '{"reviewer":"dave"}'

# a reviewer's own queue: pending items across every OPEN campaign (CapApprove)
curl -s https://pam.example/api/campaigns/mine -H "X-API-Key: $REVIEWER_TOKEN"
```

> **Assignment is advisory, not a gate.** It routes work and makes a queue
> visible. Anyone holding `approve` can still decide any item, and the audit
> trail records who actually decided (`decided_by`) — so accountability comes
> from the trail, not the assignment. Binding it would mean a campaign could not
> be closed once its assigned reviewer left, without adding any evidence, since
> any approver could reassign the item anyway. The **four-eyes** rule is the real
> control here and is unchanged: you may not certify access you granted yourself.

#### Nudge before it lapses (Phase 70)

Recertification lapses quietly: the campaign stays open, the items stay pending,
and nothing happens until an auditor asks. Set a **due date** and PAMv1 nudges.

- The first reminder fires **`PAM_CERT_REMIND_DAYS`** (default `7`, `0` disables, maximum `366` — outside that range the server refuses to start rather than reminding on every campaign at once)
  before the due date, then **daily** while items are pending.
- A campaign created with a due date already inside that window — or past it —
  reminds on the next tick rather than being skipped.
- It goes to the **alert channel** (`PAM_ALERT_WEBHOOK` / `PAM_ALERT_EMAIL_*`,
  §4) and is audited as `certification.reminder`.
- It carries the pending count, how overdue it is, and **which reviewer is
  holding it up** — which is what assignment above is for.
- It **stops** when the campaign is closed, or when nothing is left pending. The
  second cancels the reminder rather than repeating it: nagging about finished
  work is how an alert channel gets muted, and a muted channel is where the next
  lapse hides. Closing the campaign is still a human's call.

A recurring campaign's successors get their own due date and their own reminder,
so a quarterly series nudges every quarter without further setup.

The whole flow is also in the console: **Certification campaigns** (menu 17) —
F6 snapshots a new campaign (due date, scope, reviewer and repeat interval),
**F7** is your own review queue, option **7** on an item reassigns it, option **5**
on a campaign opens the item review (certify / revoke per item), option **8**
closes it. The list names each campaign's scope and marks a repeating one in
amber, since that is the row you must not close by accident — and must close on
purpose to end the series.

Three capabilities, deliberately split (Phase 39):

| Action | Capability | Who |
|---|---|---|
| Create / close a campaign | `manage_users` | admin |
| **Certify or revoke an item** | `approve` | admin, **approver** |
| Read a campaign and its items | `read_audit` | admin, approver, **auditor** |

The middle row is the point: a recertification is a *review*, so a dedicated
**approver** can run it without holding any capability that grants access, and an
**auditor** can read the evidence without being able to change anything. Every
decision is audited (`certification.item_certified` / `certification.item_revoked`),
and the campaign itself is the point-in-time record for your evidence file.

**Per-item four-eyes (Phase 46).** Every access grant records who created it,
the campaign snapshot carries that creator (each item reads *"…, granted by
X"*), and **certifying an item you granted yourself is refused** (403, audited
`certification.decision_denied reason:four-eyes`) — the reviewer and the
grantor cannot be the same person. Revoking your own grant stays allowed (it
only reduces access). Grants created before the upgrade have no recorded
creator and are not blocked retroactively — the guarantee is complete once
every reviewed grant post-dates migration `0023`. Practical consequence: the
bootstrap admin key is one actor (`bootstrap-admin`), so grants it created
cannot be certified with it — mint a dedicated approver user for reviews (you
should anyway).

### 9.6c Recurring access requests (Phase 120)

`recur_days` on an access request works the same way it does on a
certification campaign (§9.6, "Repeat it, so it does not depend on
remembering") — but a request's anchor must first clear the ordinary
four-eyes approval before recurrence ever starts, since a request grants
access rather than merely reviewing it:

```bash
curl -sX POST https://pam.example/api/access-requests -H "X-API-Key: $PAM_API_KEY" \
  -d '{"target_id":1,"reason":"weekly patch window","recur_days":7}'
# → {"id":42,"status":"pending","recur_days":7,...}   # not due yet — still pending

curl -sX POST https://pam.example/api/access-requests/42/approve -H "X-API-Key: $PAM_APPROVER_TOKEN"
# → {"id":42,"status":"approved","next_run_at":"...",...}   # the clock starts NOW, not at filing
```

- Every 7 days a **fresh, still-pending** request is auto-filed with the same
  requester/target/reason — recurrence automates the paperwork, never the
  approval decision, so a periodic access need can never quietly turn into
  standing access nobody re-reviews.
- **Stopping recurrence is the anchor's stop button**, the one an operator
  reaches for first when the periodic need ends:
  ```bash
  curl -sX POST https://pam.example/api/access-requests/42/stop-recurrence -H "X-API-Key: $PAM_APPROVER_TOKEN"
  ```
  It is idempotent (safe to call on an already-stopped or never-recurring
  request) and needs the same `approve`/`deny` capability.
- Runs under its own HA leader lock (`recur_days` is capped at 366, same as
  campaigns), on its own hourly worker — always on, nothing to configure.

### 9.6d Magic-link approval (Phase 137)

An approver can delegate one specific decision — not their whole `approve`
capability — to someone by email, the buildable half of BeyondTrust's
out-of-band approval (no native mobile app in v1). Minting the link needs
no separate approval step of its own: creating it already requires
`approve`, so the invite itself **is** the delegation.

```bash
# Needs `approve` on the request being decided, and you cannot be its own
# requester — see the four-eyes note below.
curl -sX POST https://pam.example/api/access-requests/42/invite -H "X-API-Key: $APPROVER" \
  -d '{"email":"oncall-lead@example.com"}'
# → 201, and an email goes out with a link to /approve.html?token=...

curl -s https://pam.example/api/access-requests/42/invites -H "X-API-Key: $APPROVER"
# → lists every invite for this request: outstanding, consumed, revoked

curl -sX POST https://pam.example/api/approval-invites/7/revoke -H "X-API-Key: $APPROVER"
# → the link stops working even though its TTL hasn't expired
```

- **The recipient never needs a PAMv1 account.** `approve.html` is
  unauthenticated — reached only by knowing the single-use token in the
  link — and shows the requester, target and reason before asking for a
  decision.
- **Loading the link decides nothing.** The page's first call is a safe,
  non-consuming preview; the decision itself only fires when the recipient
  clicks Approve or Deny, deliberately unlike the session-share guest page
  (§9.4c), which redeems automatically on load — approving or denying
  access is a materially higher-stakes action than joining an
  already-approved session, so it needs an explicit act, not just an
  opened email.
- **Four-eyes applies twice, not once.** The obvious defense —
  redemption uses a synthetic `magiclink:<email>` actor that can never
  equal a real requester's own actor string — does not by itself stop a
  requester from addressing an invite to their **own** inbox and
  redeeming it themselves. So the same check also runs at **creation**
  time: you cannot mint an invite for a request you filed yourself,
  regardless of whose email address you name.
- **Single-use, TTL-bound.** `PAM_APPROVAL_INVITE_TTL_MIN` (default 1440 —
  24 hours, deliberately longer than a session-share invite's 15 minutes:
  this is a decision an approver may not open for hours, closer in profile
  to a password-reset link). Revoking works even inside the TTL.
- **Audit vocabulary:** `access.invite_created` · `access.invite_revoked` ·
  the existing `access.decision_denied`, for both the self-approval refusal
  above and an ordinary decision made through the link.

### 9.7 Privileged threat analytics (Phase 23)

PAMv1 scores the audit trail into **behavioral risk** per actor, so a supervisor
can see who is behaving abnormally — and optionally respond automatically. The
scoring is deliberately **explainable**: every point traces to a named signal
(break-glass use, blocked commands, authentication-failure bursts, off-hours
activity, credential-decryption failures, session velocity), not an opaque model.

```bash
# Highest-risk actors over the last hour (CapReadAudit — an auditor may read it)
curl -s https://pam.example/api/analytics/risk -H "X-API-Key: $PAM_API_KEY"
# → {"window_minutes":60,"scored_events":420,"findings":[
#      {"actor":"mallory","score":100,"level":"critical",
#       "signals":[{"name":"break_glass","count":2,"points":100}],"events":5,...}]}

# Only high-and-above, over a 24h window
curl -s "https://pam.example/api/analytics/risk?min_level=high&window_min=1440" \
  -H "X-API-Key: $PAM_API_KEY"
```

The same view is in the console as **Risk analytics** (menu 18), with the
minimum-level and window filters on-screen.

**AI agents are scored too, since Phase 161** — before it they were not, at all.
An executed brokered tool call counts as *activity*, so an agent shows up under
session velocity, peer-outlier comparison and new-target novelty exactly as a
human does; a denied tool call, a refused approval and a quarantined agent that
keeps knocking (`agent.quarantine_refused`) count as *blocked command*, the
signal class that is allowed to drive the automated response, so an agent going
off the rails can be cut off like anyone else.

The peer comparison stays meaningful because it is computed **per class** —
agents are compared against other agents and people against other people. Pooling
them would let a crowd of busy agents raise the bar so far that a person working
ten times their normal volume no longer stands out. A class needs at
least five actors before it is compared at all, so if you run fewer than five
agents (or fewer than five people) that class simply gets no peer comparison,
which is the safer failure: a comparison you did not make can be made
later, while a confident comparison against the wrong population produces a
finding nobody can tell from a real one.

One exemption is deliberate and worth knowing about before you go looking for it:
**an agent is never scored for off-hours activity**. An AI agent working at 03:00
is normal operation. Scoring it would put every agent you run permanently near the
per-signal cap, and a detector that fires on every member of a class every day is
one your team learns to scroll past. Off-hours remains a human signal.

To run it continuously, enable the background worker. Each pass scores the window
and, for a **newly elevated** high/critical actor, appends an
`analytics.risk_flagged` audit event and fires your alert channel
(`PAM_ALERT_WEBHOOK` / syslog / email). With auto-kill on, a **critical** actor's
live sessions are terminated (`analytics.auto_response`):

```bash
PAM_ANALYTICS_INTERVAL_MIN=5      # score every 5 minutes (0 = worker off, endpoint stays on)
PAM_ANALYTICS_WINDOW_MIN=60       # how far back each pass looks
PAM_ANALYTICS_AUTO_KILL=true      # cut off a critical-risk actor's live sessions
PAM_ANALYTICS_BUSINESS_START=7    # business hours for the off-hours signal…
PAM_ANALYTICS_BUSINESS_END=20     # …outside 07:00–20:00 or on a weekend counts as off-hours
PAM_ANALYTICS_TIMEZONE=America/New_York   # interpret business hours in this zone (empty = UTC)
```

Audit timestamps are stored in **UTC**, so set `PAM_ANALYTICS_TIMEZONE` (an IANA
name) if your business hours are local — otherwise the off-hours window is
evaluated in UTC. A high-risk actor is not re-alerted every pass, but a sustained
or recurring incident **is** re-alerted (and, if critical, re-killed) once per
`PAM_ANALYTICS_WINDOW_MIN`, so a repeat incident is never silently suppressed. The
read endpoint's `?window_min=` is capped (at 7 days) so a single request can't be
made to score the entire audit history. Leave auto-kill off until you trust the
scores in your environment.

### 9.8 Identity blast radius / CIEM (Phase 31)

Where §9.7 scores *behavior*, this answers a **structural** question: if this
identity were compromised, what could it actually reach? `POST /api/blast/analyze`
(`read_audit`) runs a read-only analysis over a **normalized identity graph** you
submit — no cloud credentials are involved and nothing is persisted. Producing
the graph (from AWS `GetAccountAuthorizationDetails`, Okta, GitHub, Workspace…)
is an **external ingester's** job; PAMv1 ships the engine, not the collector.

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/blast/analyze -d '{
  "graph": {
    "principals": [
      {"id":"github:deploy-bot","kind":"service","provider":"github"},
      {"id":"aws:role/deploy","kind":"role","provider":"aws"},
      {"id":"aws:role/admin","kind":"role","provider":"aws","admin":true}
    ],
    "edges": [
      {"from":"github:deploy-bot","to":"aws:role/deploy","kind":"can_assume","via":"oidc-trust"},
      {"from":"aws:role/deploy","to":"aws:role/admin","kind":"can_escalate_to","via":"iam:PassRole"}
    ]
  },
  "source": "github:deploy-bot"
}'
```

The response carries **findings** (a non-admin that can pivot to an effective
admin = privilege escalation; a pivot across providers = lateral movement;
severity derived, critical when both), each with a **remediation** naming the
earliest pivot edge to cut — the least-disruptive break — plus the `source`
principal's blast radius. Pass `target` instead to ask *who can reach* it.

Two properties worth knowing when you read the output: an edge exists only where
the permission **really holds** (the AWS evaluator applies the real order —
explicit `Deny` wins, then SCP and permission-boundary ceilings, then an identity
`Allow`), and a condition the engine cannot evaluate is reported as **uncertain**
rather than guessed, which also marks the path's remediation *needs-review*. A
graph whose edge references an unknown principal is rejected fail-loud; requests
are capped at 4 MiB. Every analysis is audited `blast.analyze`.

### 9.9 What can this subject reach? (Phase 189)

§9.8 asks the structural question about a graph you submit; this asks it about
**PAMv1's own grants**, and it is the question an investigator actually starts
with. Every grant lookup inside PAMv1 is target-indexed — "who may reach this
target" — which is what the connect gate needs and the reverse of what a review
needs. Answering the review's question used to mean opening every target in turn
and working it out by hand.

`GET /api/access/reach?subject=<name>&kind=user|agent` (`read_audit`) answers it
directly, and says **why** each target is reachable:

```bash
curl -H "X-API-Key: $PAM_API_KEY" \
  "http://localhost:8080/api/access/reach?subject=alice"

# an AI agent: a key name, or the full SPIFFE ID of an attested workload
curl -H "X-API-Key: $PAM_API_KEY" \
  "http://localhost:8080/api/access/reach?subject=spiffe://example.org/ns/prod/sa/planner&kind=agent"
```

```json
{
  "subject": "alice", "kind": "user", "known": true, "roles": ["user"],
  "blocked": [],
  "total": 3, "counts": {"grant": 1, "safe": 1, "open": 1},
  "targets": [
    {"target": "prod-db-01", "via": "grant", "subject_type": "user", "subject": "alice"},
    {"target": "prod-web-01", "via": "safe", "safe": "prod", "subject_type": "role", "subject": "user"},
    {"target": "lab-01", "via": "open"}
  ]
}
```

The `via` values are the five ways access happens: `grant` (a direct target grant
naming the subject or a role it holds), `safe` (membership of the safe the target
sits in), `admin` (the built-in admin bypass), `unlimited_vault_access` (the
named override for a personal safe, Phase 139) and **`open`** — the target has no
grants at all, so any connect-capable principal reaches it. Read the `counts`
first: "reaches 40 targets, 37 of them open" is a very different finding from 40
grants somebody decided on, and a flat total hides it.

**`blocked` is the other half of the answer** (Phase 191), and on a screen whose
red `open` rows are meant to be read as a finding it is the half that keeps the
total honest. It lists every reason the subject cannot exercise this reach *right
now* — facts about the subject, never about a target, so each applies to the
whole answer at once:

| reason | means |
|---|---|
| `no_usable_capability` | holds none of `connect` / `reveal_secret` / `call_tool`, so no grant it holds can be acted on — an **auditor** is the ordinary case |
| `deactivated` | a local user with `active=false` (SCIM deprovisioning); its token no longer resolves |
| `key_disabled` | a static agent key revoked or suspended — what a certification campaign's revoke does to one |
| `key_expired` | a static agent key past its `expires_at` |
| `quarantined` | the identity is under the agent stop-switch; checked for **every** agent subject, including one no registry lists |
| `not_enrolled` | an attested identity PAMv1 recorded on sight that nobody has claimed — **only when `PAM_BROKER_REQUIRE_ENROLLED_SVID` is on**, because with it off (the default) an unclaimed identity authenticates perfectly well and reaches every ungated target |
| `budget_zero` | an agent key with an explicit per-day budget of **0** — a deliberate hard stop of no brokered calls at all, not an unset budget |
| `quarantine_unknown` | the quarantine table could not be read, so whether this agent is stopped is unknown — reported rather than swallowed, because an empty `blocked` means "nothing stops this subject" |

The targets and the total do not change when `blocked` is non-empty. That is
deliberate: a suspended account's grants are still grants and come back the
moment somebody flips it on, which is exactly why they are worth reviewing. But
"reaches 40 targets" and "would reach 40 targets if it could log in" are
different findings, and an empty `blocked` is what tells them apart.

From the console: menu **31**, or option `5` on a row in the user list (menu 8)
and option `8` on a row in the AI-agent key list (menu 26). Each query is audited
`access.reach_query`, with the blocked reasons in the detail.

Two things it deliberately does **not** do:

- **An agent nobody has enrolled is answered, not refused.** A SPIFFE ID in no
  registry comes back with `"known": false` and the targets nothing gates —
  because "any workload in the trust domain reaches these" is exactly the finding
  worth having. Claim the identity (menu 26 → F8) to make it reviewable, and see
  `PAM_BROKER_REQUIRE_ENROLLED_SVID` to make claiming mandatory.
- **A directory-authenticated identity (AD/LDAP/Entra/OIDC/SAML) returns 404.**
  Its roles are decided by group mapping at login, so PAMv1 has nothing to
  evaluate between logins; answering with the built-in defaults would be
  inventing an identity. Local users and agent identities are reviewable this way.

What you get is **standing** reachability: what the grant model admits. A connect
attempt still passes the gates that can only narrow it — an access request's
approval and its window, a vendor contract, a checkout, step-up, posture,
maintenance windows, quarantine — so the list is an upper bound on what the
subject can reach right now, and the complete list of what it stands to reach at
all. That is the right shape for a review: an entitlement nobody uses is still an
entitlement.

---

## 10. Security & hardening notes

- **Secure protocols only.** Front the portal/API with **HTTPS**; use `sslmode=verify-full`
  to Postgres; prefer **LDAPS** for AD. Plain HTTP/LDAP only in isolated dev.
- **Vault key management (envelope encryption).** Secrets are sealed with per-secret
  data keys that are wrapped by a Key Encryption Key (KEK). In **production use a
  KMS-backed KEK** (`PAM_KEK_PROVIDER=vault-transit`, [HashiCorp Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit))
  so the root key never leaves the KMS. The `local` KEK (`PAM_MASTER_KEY`, base64
  in an env var) is **for development and tests only**.
- **Protect `PAM_MASTER_KEY`** (local KEK). It wraps the entire vault. Back it up out-of-band; a DB dump without it is useless (that's the point). With a KMS KEK there is no local key to protect.
- **Rotate** the bootstrap `PAM_API_KEY` and any per-user tokens periodically; delete users who no longer need access.
- **Least privilege on the network:** see the [ports & flow matrix](PORTS-AND-FLOWS.md) for the firewall/NetworkPolicy baseline. The database must be unreachable from operator and target zones.
- **Upgrades that cross the vault format are breaking (pre-1.0).** The current token format is `v2:` with a per-credential AAD; there is no in-place migration from earlier ciphertext (older AAD, or the pre-GCM PKCS#11 wrap). A deployment that carries vaulted secrets across such a change must re-enter its credentials. Fresh installs are unaffected.
- Transport/data hardening — native HTTPS, security headers, per-IP rate limiting, versioned migrations, and vault key rotation — shipped in [Phase 5](../ROADMAP.md#phase-5--hardening-database-vault-transport-); enforce `sslmode=verify-full` to Postgres at deploy time.
- **Fail-closed controls to enable in production** (each off by default so the demo stays turnkey):
  - `PAM_REQUIRE_HTTPS` / `PAM_REQUIRE_DB_CLIENT_TLS` — refuse to start without TLS on the API and DB-proxy operator legs.
  - `PAM_DB_UPSTREAM_CA` (or `PAM_DB_UPSTREAM_TLS_VERIFY`) — verify the upstream PostgreSQL certificate so the injected DB credential can't be MITM'd; `PAM_SSH_KNOWN_HOSTS` does the same for SSH targets.
  - `PAM_REQUIRE_RECORDING` — refuse a session that cannot be recorded. Since
    Phase 52c this covers **every** path to a target, not only the proxies: the
    SSH proxy, the WinRM proxy, the PostgreSQL proxy, the in-portal RDP viewer
    (needs `PAM_GUACD_RECORDING_PATH`) and the REST WinRM endpoint (needs
    `PAM_RECORDING_DIR`). The check runs *before* anything happens on the target,
    and each refusal is audited (`rdp.refused`, `winrm.refused`). Before that fix
    the flag silently did not cover the two HTTP paths, so an operator who set it
    believed rather more than was true.
  - `PAM_PROXY_AUTH_RATE_LIMIT` (default on, 10/min) — throttles guessing of `PAM_API_KEY` on the SSH/DB proxies; `PAM_AUTH_RATE_LIMIT` (default on, 20/min) does the same for failed `X-API-Key`, agent-key and application-key attempts over HTTP; `PAM_TRUSTED_PROXY_HOPS` keeps both API limiters accurate behind a reverse proxy.
- **A strong `PAM_API_KEY` is enforced** (≥16 chars) on any real database; the bootstrap key is presented as the proxy password, so treat it like a root credential and rotate it.
- **Secret delivery is fail-closed on the audit trail** — a reveal/checkout/app-secret is refused (503) and a proxied session is denied if the action can't be durably audited, so a secret is never handed out unrecorded.
- **Directory deprovisioning** — disabling a user upstream doesn't end their live login until you revoke it; run `POST /api/identity/reconcile` on a schedule (it revokes disabled directory sessions) or `POST /api/login-sessions/revoke` on demand. See §7.
- For the full self-audit — what was hardened, what's a documented trade-off, and what remains a future phase — see **[SECURITY-GAPS.md](SECURITY-GAPS.md)**.

## 11. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `401 invalid or missing API key` | Wrong/expired key or token; check `X-API-Key`. Each failure is audited `api.auth_failed` — check the trail if you didn't expect them. |
| `429 too many failed attempts; try again shortly` | `PAM_AUTH_RATE_LIMIT` throttled repeated bad bearer credentials from one IP (API key, agent key or app key). Fix the credential and wait a minute; a burst you didn't cause is worth investigating in the audit trail. |
| `403 your role does not permit this action` | The identity's role lacks the capability — expected for non-admins. |
| Proxy: `your role may not open sessions` | The token belongs to an `auditor`/`approver`; only `admin`/`user` can connect. |
| Proxy: `upstream connection failed` | Target host/port wrong or unreachable, or the vaulted credential is invalid. |
| Proxy: `too many attempts; try again shortly` | `PAM_PROXY_AUTH_RATE_LIMIT` throttled repeated bad auth from one IP — wait a minute, or raise the limit for a busy bastion IP. |
| `503 audit log unavailable; secret access denied` | The audit store is down; secret delivery fails closed by design. Restore the database, then retry. |
| `PAM_API_KEY must be at least 16 characters` at startup | Strengthen the key (or set `PAM_ALLOW_WEAK_API_KEY=true` for a demo). |
| `PAM_MASTER_KEY is required` at startup | Env var unset — generate with `-genkey`. |
| Portal shows empty panels for a non-admin | Expected: panels the role can't read stay empty (403s are tolerated). |

---

## 12. Change log

| Date | Change |
|---|---|
| 2026-08-27 | **Phase 226 (the MCP revision negotiated, not pinned).** The AI-agent broker section now says which protocol revisions the MCP endpoint negotiates (2024-11-05, 2025-03-26, 2025-06-18), that batches are accepted and an unsupported `MCP-Protocol-Version` header is refused, and that the transport is HTTP+SSE — Streamable HTTP is not offered. Nothing to configure. |
| 2026-08-27 | **Phase 224 (the trust bundle follows the file).** The SPIFFE section now says the trust-domain JWKS is re-read when it changes — every 30 seconds and on an unknown key id — so a SPIRE key rotation no longer needs a restart, and that a broken rewrite keeps the last good bundle and is logged under `service=svid`. Nothing to configure. |
| 2026-08-27 | **Phase 222 (a resume token bound to its collector).** "Approving a parked call" now says that only the agent that parked a call can collect its result: the single-use resume token is bound to that agent's identity (key row id or SPIFFE ID), and any other presenter — even one holding the token and the call id — gets the answer a bad token gets. Nothing to configure; migration `0051` applies on startup, and a token minted before the upgrade keeps spending for its remaining TTL. |
| 2026-08-27 | **Phase 219 (the budget becomes a compare-and-spend).** The `PAM_BROKER_BUDGET_PER_DAY` and `PAM_BROKER_MAX_CALLS_PER_TOKEN` rows now say the limit holds under a burst: the gate writes a reservation at the instant of its decision, so calls arriving together cannot all pass on the same count; a call the policy refuses, or an approver denies, gives its slot back. Also new behaviour to know when running agents near their limits: **a call parked for approval holds a budget slot while it waits** — before v0.59.0 the approval path never re-checked the budget. Nothing to configure; migration `0050` applies on startup. |
| 2026-08-27 | **Phase 215 (the 2026-08-27 audit).** "CIDR/network source-address allowlist" now says where it really applies — including session tokens, `/api/me`, MFA enrollment and the viewer tunnel, none of which honoured it before v0.58.2. "SCIM 2.0 user provisioning": deactivation, deletion and a role change revoke the sessions the user already holds (`session.revoked reason:`), not only the per-user token. "Personal/private safes" gains the write bound (who may add/delete credentials or delete the target). Session-share supervisors: the roster's `join_id` is no longer the guest's key |
| 2026-08-26 | **Phase 212 (the 2026-08-26 audit) — DoubleLock hardened.** "DoubleLock" gains the minimum-length rule (16, raisable with `PAM_DOUBLELOCK_MIN_LENGTH`, never lowerable), the 600 000-iteration PBKDF2 with the count stored per record, and why length rather than iterations is the defence. Also this phase, with no operator-facing knob: personal-safe privacy is one fail-closed guard (reassign, delete, self-grant — a plain target manager could do all three), and a SCIM connector can no longer deactivate or reactivate an admin |
| 2026-08-25 | **Phase 197 — PAMv1 as an External Secrets Operator backend.** An application grant can carry a stable `alias` (`POST /v1/apps/{id}/grants/{gid}/alias`, `reveal_secret`, console option `8`), and `GET /v1/app-secrets/by-alias/{alias}` fetches by that name — because a declarative consumer holds the identifier in a manifest in git, and a credential's row id is not stable across environments or a restore. Status codes are a contract with ESO and one of them is destructive: **404 means "deleted"** and removes the workload's Secret, so a revoked or ungranted credential answers **403, never 404**. Manifests and a cluster-test checklist in `deploy/k8s/eso/` |
| 2026-08-25 | **Phase 191 — `blocked` on the reachability review.** §9.9 gains the reason table: `no_usable_capability`, `deactivated`, `key_disabled`, `key_expired`, `quarantined`, `not_enrolled`. The targets and the total are unchanged when it is non-empty — a suspended account's grants are still grants — but an auditor reaching every ungated target, a deprovisioned user and a revoked agent key all used to read as live entitlement. `access.reach_query`'s audit detail carries the reasons |
| 2026-08-23 | **Phase 189 — "what can this subject reach?"** A new review read, `GET /api/access/reach?subject=&kind=user|agent` (`read_audit`, audited `access.reach_query`), and console menu **31** — plus option `5` on a user row (menu 8) and option `8` on an agent-key row (menu 26). It answers the question PAMv1 could not: every grant lookup was target-indexed, so "what can this agent reach?" meant opening every target in turn. The answer names each reachable target AND why — a direct grant, a role grant, safe membership, the admin bypass, or **open** (nothing gates the target, so anyone connect-capable reaches it), with per-reason counts, because "40 targets, 37 of them open" is a different finding from 40 deliberate grants. An agent in no registry is answered rather than refused (`"known": false` — an unenrolled workload reaching every ungated target is the finding); a directory-authenticated identity returns 404, since its roles are decided at login. Standing access only: the gates a connect still passes can narrow the list, never widen it. New migration `0047` (indexes both grant tables by subject). See §9.9 |
| 2026-08-17 | **Phase 157 — post-session forensic reconstruction (the eBPF finding).** The planned mechanism (eBPF on the pam-server host) turned out to be architecturally impossible for a proxy: an operator's shell runs in the TARGET's kernel, so a probe here would observe zero events — verified, and documented as permanent. Shipped instead: after an interactive SSH session ends, PAMv1 runs ONE fixed, read-only command (`ausearch -m EXECVE -ts today | tail -c 1048576`) over that target's own vaulted credential on a fresh connection, filters the target's kernel audit records to the session's window, and stores them as a hash-chained `.forensics.log` beside the recording — so an obfuscated (`base64 -d | sh`) or unechoed command still leaves a structured record of what actually ran. `PAM_SESSION_FORENSICS` (off by default), `_MAX_EVENTS`, `_TIMEOUT_SEC`. "Unavailable" (no auditd, no permission) is an audited FINDING, never silence; ZSP sessions are refused loudly; PAMv1's own literal still obeys command control. New audit family `session.forensics*`. Also fixes a Phase 155 call site: `.k8s.log` transcripts were invisible to the recordings listing/playback, and both new artifact kinds are now listed and servable. Interactive SSH only, audit-only, no schema change. See §9.3b |
| 2026-08-16 | **Phase 155 — Kubernetes targets (discrete operations).** A new `kubernetes` target protocol (port defaults to 6443) whose credential is a vaulted service-account bearer token (`k8s_token`), and `POST /api/targets/{id}/kubectl` (`connect`) brokering one audited operation at a time: `get`, `logs`, `apply` (server-side apply, `fieldManager=pamv1`) and `delete`. Same gates as the WinRM REST twin (protocol policy, grants/safes, approval, vendor contract, session cap + registry), same command control (the canonical `kubectl …` line is what deny/allow patterns match), same transcript (`.k8s.log`, hash on the audit row), same withheld-result contract when the audit write fails. The cluster's own RBAC decides what the token may do; its refusal comes back as `status:403` in the envelope. New `PAM_K8S_CA_FILE` / `PAM_K8S_INSECURE_SKIP_VERIFY` / `PAM_K8S_TIMEOUT_SEC` / `PAM_K8S_MAX_RESPONSE_KB`. New audit family `k8s.*`. Console: *Work with Targets* option 6. `exec`/`attach`/`port-forward` (streaming), client-certificate credentials and API discovery are deliberate v1 exclusions. No schema change. **Not verified against a real cluster** — proven against an in-process API server that accepts only the vaulted token. See "Kubernetes clusters" under §6 |
| 2026-08-16 | **Phase 153 — outbound-only endpoint agents (Jump Client-style reachability).** For targets PAMv1 cannot dial into: a new `pam-agent` binary (Release assets `pam-agent_linux_{amd64,arm64}` + `SHA256SUMS`) dials OUT to the existing `:2222` listener as `endpoint-agent:<name>` with its own bearer key, holds an RFC 4254 reverse tunnel, and the proxy reaches the bound target through it — never dialing it. `PAM_ENDPOINT_AGENTS_ENABLED` (default off); `POST/GET /api/endpoint-agents`, `DELETE /api/endpoint-agents/{id}` (`manage_targets` to create/revoke, `read_inventory` to list); console menu 28. One live agent per target; revoke kicks the live tunnel; SSH targets only. New migration `0042` (`endpoint_agents`). New audit family `endpoint_agent.*` plus `via:endpoint-agent:<name>` on `session.start`. The agent pins pam-server's host key (`PAM_AGENT_SERVER_HOST_KEY`, required), exposes exactly one local address, may open nothing toward PAMv1, and lists every replica in HA. Proven end to end against a real upstream sshd through the tunnel; not verified across a real NAT. See "Outbound-only endpoint agents" under §6 |
| 2026-08-16 | **Phase 151 — SAML 2.0 single sign-on (Service Provider).** For IdPs with no OIDC endpoint (on-prem AD FS, SAML-only Okta/OneLogin/Entra apps): SP-initiated Web Browser SSO — `GET /api/auth/saml/start` (AuthnRequest, HTTP-Redirect), `POST /api/auth/saml/acs` (the IdP's signed Response, HTTP-POST), `GET /api/auth/saml/metadata` (the SP descriptor an IdP admin imports). `PAM_SAML_SP_URL` enables it (presence, like `PAM_OIDC_ISSUER`); IdP metadata from `PAM_SAML_IDP_METADATA_URL` or `_FILE`; group/role attribute → role via `PAM_SAML_ROLE_*`; optional `PAM_SAML_SP_KEY_FILE`/`_CERT_FILE` sign AuthnRequests and accept encrypted assertions; `PAM_SAML_NAME_ATTR`/`_GROUP_ATTR` pick the attributes. Hot-swappable except the three `_FILE` paths; `PAM_OT_AIRGAP` refuses the metadata URL. XML-DSig verification is delegated to a well-audited library (the WebAuthn precedent — see PROTOCOLS-AND-CRYPTO.md §"SAML"). Login state rides the same single-use store the OIDC flow uses, so the ACS can land on any replica. Login audited as `login … via:saml`. No schema change. **Not verified against a live IdP** — proven against a real in-process SAML IdP instead. See the "SAML 2.0 single sign-on" section above |
| 2026-08-16 | **Phase 149 — SCIM 2.0 user provisioning.** New `/scim/v2/Users` (RFC 7643/7644), authenticated by a new non-human `ScimKey` bearer identity (`POST /v1/scim-keys`, `manage_users` to mint), never a human principal — every SCIM-provisioned user gets the fixed `user` role, no way to request more. `store.User` gains `ExternalID` and `Active`; deactivating (`PATCH active:false` or `DELETE`, which is a soft-delete) now actually blocks that user's local token from authenticating, not just a flag — proven end to end. Reactivation restores the same token, nothing re-minted. Complements the existing pull-based `POST /api/identity/reconcile`. `PAM_SCIM_ENABLED` (default off). **Not interactively verified against a real IdP** — no Okta/Azure AD/OneLogin account in this environment; both RFC 7644's standard `PATCH` shape and Azure AD's documented no-path variant are implemented and tested against a fake. See §7 |
| 2026-08-16 | **Phase 147 — browser-extension password autofill.** New `extension/` (Manifest V3) calls the existing `POST /api/credentials/{id}/reveal` with a new `POST /api/extension-token`-minted bearer token (`CapRevealSecret` required to mint) that inherits the caller's own role/capabilities but is refused on every route except reveal — a new `ExtensionOnly` principal flag, narrower than the RDP/VNC viewer scope's blanket refusal. `PAM_EXTENSION_TOKEN_TTL_HOURS` (default 24, max 720). Reveal audits gain a `via:extension` marker; new audit action `extension.token_issued`. No schema change, no way for the extension to browse the vault (one hostname → one credential ID, configured manually). **Not interactively verified against a real browser** — no GUI browser in this environment; JS syntax-checked, manifest JSON-validated. See §6 |
| 2026-08-15 | **Phase 145 — generic file-attachment secrets.** New `secret_type: "file"` for license keys, cert bundles and short documents — the same `POST /api/credentials` route and `vault.Encrypt`/`Decrypt` pathway every other secret type already uses, base64-encoded by the client. `PAM_CREDENTIAL_FILE_MAX_KB` (default 1024, max 10240, never "0 = unlimited") refuses an over-cap upload before it is ever encrypted or a row inserted. No schema change (`secret_type` is a plain `TEXT` column) and no new REST surface. **A near-miss along the way**: the plan's own stated fix — stop `ListCredentials` from selecting `secret_enc`, since it's `json:"-"` — passed a store-layer contract test and then broke the PostgreSQL session proxy's real JIT credential injection, because `dbproxy.go`'s `lookupTargetCred` deliberately lists first and decrypts from the result afterward, so every gate can run before any plaintext exists; a repo-wide check found nine such internal callers (also `-rotate-kek`, the lifecycle reconciler, the RDP/VNC viewer, REST WinRM, the broker's exec tools). Fixed by leaving `ListCredentials` untouched and adding a separate `ListCredentialsMeta` for the four callers that never touch the secret (the REST list endpoint among them). See §6 |
| 2026-08-15 | **Phase 143 — ICAP-based file-transfer scanning.** `PAM_ICAP_URL` (`icap://host[:port]/service`) submits every finalized SFTP transfer's captured bytes whole to an ICAP RESPMOD service (c-icap, or any commercial AV/DLP gateway that speaks ICAP) for scanning — new `internal/icap` package, a minimal RFC 3507 client (one connection per scan, no OPTIONS/Preview/keep-alive, deliberately no encapsulated req-hdr to avoid embedding an attacker-influenced remote path into a hand-built wire header). **Detection, not prevention**: by the time a whole-object scan can run, an upload has already reached the target and a download has already reached the operator — proven end-to-end by a test where an unreachable ICAP server still lets the transfer through. A flagged file audits `sftp.icap_flagged` (naming the vendor's own reason); a scan failure audits `sftp.icap_scan_failed`; a capped or broken capture is skipped, not scanned incomplete (`sftp.icap_skipped`). Requires `PAM_SSH_SFTP_CAPTURE` enabled and `PAM_SSH_SFTP_CAPTURE_MAX_MB` set — the same cap that bounds the disk artifact also bounds the in-memory scan buffer. Joins the `PAM_OT_AIRGAP` conflict list. No schema change. See §9.4 |
| 2026-08-15 | **Phase 141 — raw TCP port-forwarding, same-target only.** A client-initiated `direct-tcpip` channel (`ssh -L`) is admitted only to the connected target's own host — any port, since the target's own configured port is its SSH port, not the service the operator actually wants to reach — closing what would otherwise be an SSRF pivot into the target's network; a different host is refused (`forward.refused reason:not-same-host`) before the upstream is ever asked to dial it. `localhost`/`127.0.0.1`/`::1` count as the target too, since the forward dials out through the already-authenticated upstream connection. Always refused in an observer session, or while `PAM_REQUIRE_LIVE_SUPERVISION`/`PAM_REQUIRE_RECORDING` are set — none of those mechanisms cover a raw, unrecordable byte stream. `PAM_SSH_PORT_FORWARD` (default true) turns the whole feature off. New audit actions `forward.start`/`forward.end`/`forward.refused`; no schema change. See §9.4 |
| 2026-08-15 | **Phase 139 — personal/private secret folders.** A safe marked `personal` (set only at creation, required to name an `owner` seeded as its first `can_manage` member) replaces `auth.CanConnectTarget`'s unconditional admin bypass with a check for the new, narrow `unlimited_vault_access` capability — deliberately not part of the built-in `admin` role, grantable only via a custom profile. `canManageSafe` closes the matching side door: `manage_targets` alone, enough for any ordinary safe's roster, is no longer enough for a personal one. Using the override to reach a personal safe is loudly audited (`safe.personal_override_used`) on the REST paths (reveal, checkout, RDP/VNC token mint); the raw SSH/PostgreSQL/SQL Server proxy connect path enforces the identical denial/admission, proven end-to-end against a real upstream, but doesn't yet add the same audit line. Inventory listing and safe deletion/rename are unaffected — only the paths that hand back or use the secret are gated. New migration `0040`. See §6 |
| 2026-08-15 | **Phase 137 — magic-link approval + session watermarking.** An `ApprovalInvite` delegates one specific access-request decision by email (`POST /api/access-requests/{id}/invite`, `approve`) — mirrors the Phase 116 session-share invite, but creating it already requires `approve`, so the invite itself is the delegation. Redemption on the new unauthenticated `approve.html` is a safe, non-consuming preview `GET` plus a single-use decision `POST`, fired only on an explicit button click — deliberately unlike `share.html`'s auto-redeem-on-load, since deciding access is higher-stakes than joining a session. A second four-eyes check at invite *creation* (not just redemption) stops a requester self-approving through their own emailed link. `PAM_APPROVAL_INVITE_TTL_MIN` (default 1440). Every RDP/VNC session also now shows a client-side watermark overlay (operator, target, start time); SSH/PostgreSQL/SQL Server sessions get the same identity as a one-time `Hub.Publish` banner. New audit actions `access.invite_created`/`access.invite_revoked`; new migration `0039`; store surface 174 → 181. See §9.4e and §9.6d |
# credential option 10 on console menu 2 toggles this (Phase 187)
| 2026-08-14 | **Phase 135 — DoubleLock.** A named person's password, additionally required (on top of `reveal_secret`) to reveal or check out a credential; disabling it needs the password too, so an admin alone cannot strip the protection. Kept deliberately outside the KEK (`POST`/`DELETE /api/credentials/{id}/doublelock`), so `-rotate-kek` needs no special case for it. See §6 |
| 2026-08-14 | **Phase 133 — device-aware access control.** A live EDR-posture webhook (`PAM_POSTURE_ATTEST_URL`) re-checked on every connect and every authenticated call, and an optional device-identity binding (`PAM_DEVICE_HEADER` + a per-user `device_fingerprint`) trusting a reverse-proxy-injected client-certificate fingerprint on the REST surface only. Both break-glass exempt. See §7 |
| 2026-08-14 | **Phase 131 — command allow-listing.** `PAM_COMMAND_ALLOW_FILE`, same regex-file format as `PAM_COMMAND_DENY_FILE`, once set narrows every command-control path (SSH `exec`, WinRM command loop, PostgreSQL/SQL Server statements, `POST /api/targets/{id}/winrm`, the agent broker's `ssh_exec`/`winrm_exec`) to ONLY the listed commands — Delinea's Command Menus is the closest commercial-PAM analogue. `cmdguard.Guard` gains an `Allowed(cmd)` method reading the exact same compiled pattern set `Blocked` does, so an allow-list is just a second `*cmdguard.Guard` value used the other way round — zero changes to `New`/`ParseDeny`. Deny always wins when both would match; a refusal from the allow-list audits `command.blocked` with `pattern:not-allowed`. Optional and independent of the deny file — unset, every path stays exactly deny-only. Proven end-to-end (real SSH exec, real Postgres wire-protocol session, REST WinRM) including the deny-wins-over-allow edge case. No schema change; no new route. See §9.4 |
| 2026-08-14 | **Phase 129 — Zero Standing Privilege for PostgreSQL.** Extends Phase 22's SSH-only ZSP to databases: a new `db_zsp` credential type stores no secret; at connect time PAMv1 dials the target's separately vaulted `provisioner` credential and runs `CREATE ROLE ... WITH LOGIN PASSWORD ... VALID UNTIL ...` (a 30-minute hard-ceiling safety net independent of teardown), connects the operator's real session as that fresh role, and `DROP ROLE`s it on session end — the operator's real session never touches the provisioner's own credential. Exactly one provisioner per target; zero or more than one refuses the connect (fail-closed, never guessed). Proven end-to-end against a real Postgres wire-protocol fake that authenticates twice with two different, dynamically-generated credentials in one test run. **RDP cut before any code was written**: Guacamole's own documentation confirms no certificate/smartcard RDP auth parameter exists — a permanent protocol limitation, not an infra gap. **SQL Server deferred**: `internal/tds` only ever parses what a client sends; issuing PAMv1's own `CREATE LOGIN` needs a client-side response-token reader that doesn't exist yet. New audit actions `db.zsp_provisioned`/`db.zsp_provision_failed`/`db.zsp_teardown`/`db.zsp_teardown_failed`. New migration `0036` (`credentials.is_provisioner`). See "Zero Standing Privilege: ephemeral database roles" above |
| 2026-08-14 | **Phase 128 — authenticated post-login account discovery.** Returns to the original CyberArk/Wallix competitive-research backlog's remaining item now that the Wallix-weighted plan (116–126) is closed: enumerate local/service accounts on a target PAMv1 already holds a credential for, and flag ones with no matching vaulted credential (CyberArk DNA-style). New `POST /api/targets/{id}/discover-accounts` (`manage_targets`): dials fresh with the target's first credential (SSH: `cat /etc/passwd`; WinRM: `net user` + `net localgroup Administrators`, both through `guardCommand` like every other discrete command PAMv1 runs), parses with the new pure `internal/accountscan` package, and cross-references every found username against **all** the target's vaulted credentials — `"managed":false` is the finding. Deliberately not built on `execWinRM` (which drags in the live-session registry, recording requirements and vendor gating meant for a supervised operator session) — a lean, dedicated path reusing only `guardCommand`/`vault.Decrypt`/`sshConnector.Exec`/`winrm.Run` directly. Console: menu 1, option **9=Discover accounts**. New audit actions `target.accounts_scanned`/`target.accounts_scan_failed`. No schema change; store surface unchanged; route count +1. See "Authenticated post-login account discovery" above |
| 2026-08-14 | **Phase 126 — portal color themes.** Every hardcoded color in the console's inline stylesheet became a CSS custom property on `:root` (exact values preserved); two new `[data-theme="amber"\|"slate"]` blocks redefine only those tokens, so layout/spacing/font/scanlines are identical across all three palettes. **F2** cycles the theme client-side (`localStorage`, no login required) — no new store table, route or audit event, since a color preference isn't an authorization-relevant fact. `TestConsoleThemeTokensAreConsistent` guards token-name consistency between the base palette and every theme override. No schema/route change. |
| 2026-08-14 | **Phase 124 — FIDO2/WebAuthn passwordless MFA.** A second, independent second-factor type alongside TOTP — either alone satisfies MFA. `PAM_WEBAUTHN_RP_ID`/`_RP_ORIGIN` (presence enables it, restart-only) turn it on; self-service `POST /api/webauthn/register/{begin,finish}` (any signed-in identity, and an enrollment-only session too) registers a key, `GET`/`DELETE /api/webauthn/credentials{,/{id}}` manage them. Login for a WebAuthn-enrolled user with no confirmed TOTP is necessarily two calls, not one — password-only `POST /api/login` returns a narrow, 5-minute `MFAPending` token good for nothing but `POST /api/webauthn/login/{begin,finish}`, which the console drives automatically. A user may register more than one key; public keys are stored in the clear (not a secret, unlike the TOTP secret). New migration `0035` (`webauthn_credentials`, `mfa_webauthn_challenges`); store surface 164 → 171. New audit actions `mfa.webauthn_registered`/`_register_failed`/`_deleted`. See the "Multi-factor authentication (WebAuthn, Phase 124)" section above |
| 2026-08-14 | **Phase 122 — suspend vs. terminate a live session.** `POST /api/sessions/{id}/suspend`/`.../resume` (`approve`) freeze and unfreeze an operator's input without ending the session, riding Phase 116's session-sharing input mux rather than new plumbing; `GET .../suspend` (`read_audit`) reports current state, 404ing if the session isn't live on this replica. Both actions are idempotent, and the operator gets a `Stderr` banner the instant either fires — freezing input silently would look like a hang, not a policy action. Replica-local, like sharing: no cross-replica bus yet. Console: live-watch pane shows an amber *SUSPENDED* banner; **F8** toggles for anyone holding `approve`. New audit actions `session.suspended`/`session.resumed`; no new migration (suspend state is in-memory only). See §9.4d |
| 2026-08-14 | **Phase 120 — recurring access requests, password policy, checkout extension.** Recurring access requests: `recur_days` makes an *approved* request an anchor (§9.6c), auto-filing a fresh pending successor every N days on its own hourly worker — the clock starts at approval, not filing; `stop-recurrence` is the anchor's stop button. Password policy: `PAM_PASSWORD_MIN_LENGTH`/`_MIN_LOWER`/`_MIN_UPPER`/`_MIN_DIGIT`/`_MIN_SYMBOL` make generated-password shape configurable (defaults reproduce the old hardcoded 24-char/one-of-each), and `PAM_PASSWORD_HISTORY_COUNT` (default 0) refuses to reissue one of a credential's last N rotated secrets, tracked as SHA-256 hashes only. Checkout extension: `POST /api/credentials/{id}/checkout/extend` (holder-or-admin) pushes an active lease's expiry out, capped at `PAM_CHECKOUT_MAX_EXTEND_MIN` (default 240) total from check-out. New migration `0034`; store surface 157 → 164. See §7 and §9.6c |
| 2026-08-13 | **Phase 118 — CIDR/network source-address allowlist.** A per-user, comma-separated CIDR list (`ip_allowlist` on `POST /api/users` / `PUT /api/users/{id}`, `*string` on update so omitting it leaves an existing list untouched and only an explicit `""` clears it) restricts where that user's bearer token may be used from — enforced on every REST call (`authz` middleware) and every session-proxy connect (SSH/PostgreSQL/SQL Server, the shared `admit()` gate). Empty is unrestricted; break-glass is exempt; directory/OIDC logins are unaffected (no backing local-user row). New migration `0033` (`users.ip_allowlist`). See §7 |
| 2026-08-13 | **Phase 116 — live session-sharing.** A live SSH session can be shared view-only or view-**control** with a second party through a four-eyes request→approve workflow (`POST /api/sessions/{id}/share`, decided by a *different* principal at `POST /api/share-invites/{id}/approve\|deny`). An **internal** invite redeems over SSH as `join:<token>` — the whole username — layered on the joiner's own PAM password, never the token alone; an **external**/vendor invite is emailed with a QR code instead, single-use, `PAM_SESSION_SHARE_INVITE_TTL_SEC` (default 900s), redeemed through a new **unauthenticated** page (`/share.html`) that mints a random 256-bit guest key good for `PAM_SESSION_SHARE_GUEST_TTL_MIN` (default 240 min). A roster + kick (`.../share/roster`, `.../share/kick`) close both. New migration `0032` (`session_share_invites`, plus a `vendors.email` column); new audit actions `session.share_{requested,approved,denied,revoked,joined,join_denied,ended,kicked}`. See §9.4c |
| 2026-08-13 | **Phase 114 — a live NIS2 compliance report.** `GET /api/compliance/nis2?since=&until=` maps window-scoped audit activity onto the existing Art. 21(2) control matrix (docs/NIS2-COMPLIANCE.md §1): each control's status is architectural, and controls with a natural audit signal (supply-chain, policy effectiveness, access control, MFA, incident handling) carry a count of matching events bucketed by action family, plus (for incident handling) the whole-chain integrity result. Same digest/determinism/audit conventions as the raw export. Console: **F8** from *Display Audit Trail*. NIS2 only — PCI-DSS/ISO27001/SOX are not attempted. See §9.2b |
| 2026-08-12 | **Phase 112 — mandatory live supervision.** `PAM_REQUIRE_LIVE_SUPERVISION=true` holds an interactive SSH channel — before it dials the target — until a supervisor is actually watching (`GET /api/sessions/{id}/stream`) or `PAM_LIVE_SUPERVISION_TIMEOUT_SEC` (default 120) elapses; a timeout refuses the session and is audited `session.unsupervised`. Observer sessions and break-glass are exempt. SSH only for now — the database/WinRM proxies register their live session after dialing, so they're left for a future phase. See §9.4b |
| 2026-08-12 | **Phase 110 — SSH session recordings are searchable by content.** `GET /api/recordings/search?q=` finds text anywhere in a recording's output, even split across several writes, and reports each hit's snippet plus the playback time to jump to. Console: **F4** from *Session Recordings* (menu 19). Same `read_audit` gate as playback; the search itself is audited (`session.search`) with the query. RDP/VNC and WinRM are not covered. See §9.3 |
| 2026-08-06 | **Phase 60a — the ticket re-check no longer misfires when you hold more than one approval.** With `PAM_TICKET_REVALIDATE=true`, each live approval for the target is now checked in turn and the one admitted is the one whose ticket passed. Before, a second concurrent connection could be let in on an approval whose change had been cancelled (its ticket was never put to the ITSM at all), and one cancelled change could block a valid approval behind it for the rest of the window. Up to 8 approvals are considered and the whole walk shares the same 5-second ITSM budget. Nothing to configure. See §9.5 |
| 2026-08-06 | **Phase 61a — naming a management credential now takes the same authorization as revealing it.** Declaring a dependent account with `management_credential_id` makes PAMv1 present that password to the host on the same request, so it now requires `reveal_secret`, a grant on that credential's **own** target, an approved access request where that target needs one, and an in-contract vendor grant for a vendor — refusals audited as `dependency.create_denied`. It also must be a **password**: an SSH key or a zero-standing-privilege credential is refused, at declaration and again at use. Nothing changes for an administrator who was already entitled to the credential they name. See §7 |
| 2026-08-02 | **Phase 61 — say which account updates a dependent service.** Declaring a dependent account (a Windows service, scheduled task or app pool) now takes an optional **management credential**: the account PAMv1 logs into that host as in order to reconfigure the consumer. Until now it logged in as the service account it was rotating, which needs administrator rights on the host — and hardened service accounts usually cannot log on remotely at all, so propagation failed there. *Work with Dependent Accounts* shows a **Managed via** column; anything reading `this account` in amber is still on the old path. If the credential you name is later deleted, the update fails closed and says so rather than falling back. See §7 |
| 2026-08-02 | **Phase 60 — change tickets are re-checked when access is used.** Until now a ticket was validated when the access request was filed; if the change was cancelled an hour later, the approval kept working for the rest of its window. Set **`PAM_TICKET_REVALIDATE=true`** and every privileged use — SSH, PostgreSQL, SQL Server, the in-portal viewer, reveal, check-out, WinRM run and agent tools — puts the ticket back to your ITSM first, refusing with `access.ticket_revoked` if it no longer validates. Two things to plan for: your ITSM is now on the connect path (bounded at 5 seconds), and a ticket that cannot be **confirmed** refuses, including when the ITSM is unreachable. Left unset, nothing changes. See §5 |
| 2026-08-02 | **Phase 59a — fifteen fixes to the capture, from its own review.** Nothing to reconfigure. What changed that you can observe: the per-file cap now bounds **downloads** as well as uploads (it counts the bytes reads have asked for, not only what came back), `lsetstat` and unrecognized SFTP extensions are refused under read-only and under capture, `copy-data` is refused under capture because it copies inside the server where the proxy cannot see it, and the console reports the hash verdict when you download captured content instead of staying silent. Several bypasses of capture were closed (a flagless open, a reused request id, an overflowing write offset), and artifact names are now guaranteed to stay inside the recording directory and to be listable. See §5 |
| 2026-08-01 | **Phase 59 — SFTP transfers can now be recorded in full.** `PAM_SSH_SFTP_CAPTURE` (`uploads`/`downloads`/`all`) makes every file moved through the SSH proxy leave a sealed, hash-chained artifact beside the session recordings, attributed in the audit trail (`sftp.file_recorded`) and downloadable hash-verified from menu 19. `PAM_SSH_SFTP_CAPTURE_MAX_MB` caps a file by **refusing** data past the cap (a size limit, not a silent gap), and while capture is on an unparsable SFTP stream is refused rather than forwarded opaque. Also fixed: OpenSSH's `posix-rename`/`hardlink` extension requests now obey readonly mode and the path denylist — a modern client renames via the extension, which previously slid past both. See §5 |
| 2026-07-31 | **Phase 58 — a safe can now carry its own approval policy.** `require_approval` and `min_approvers` (dual control) on a safe bind **every target in it**, so a whole class of systems is governed in one place instead of per target. Strictest-wins: a safe tightens the global and per-target settings and can never loosen them. The dual-control floor is re-read as each approval is cast, so raising it binds requests already waiting, and it applies when a request is filed too. Both fields are on the console's safe screens (new **Approval** column) and in `POST`/`PUT /api/safes`; a floor outside 0–10 is refused. See §"Safes" |
| 2026-07-31 | **Phase 57 — the broker can now issue delegated agent identities.** With `PAM_BROKER_TOKEN_EXCHANGE=true`, `POST /v1/token` (RFC 8693) lets an SVID-authenticated agent delegate **its own** authority to a sub-agent it spawns and receive a short-lived, broker-signed JWT-SVID; the sub-agent's calls carry an `act` chain naming the delegator and the accountable human, so the audit reads the same for a spawned agent as for a direct one. It says who may act, never what they may do — `scope` is refused and policy still decides every call over its arguments — impersonation is unsupported, and the TTL (default 5 min, capped by the delegator's own expiry) is the containment, since a minted token has no revocation list. `GET /v1/token/jwks` publishes the signing key. Also: `POST /api/blast/analyze` with `"terraform": true` returns each finding's remediation as reviewable HCL. See §"AI-agent access broker" |
| 2026-07-31 | **Phase 56 — cross-replica step-up decisions.** In a multi-replica deployment, `GET /api/sessions/stepups` now lists every replica's paused statements (each row naming its hosting `replica` and its `expires_at`) and `POST /api/sessions/{id}/stepup` decides a pause held on any replica — a decision landing on the "wrong" pod is dispatched, sealed, over the store bus and answers **202 Accepted** (dispatched, not proven applied; refresh the list to verify), exactly the kill-switch's honesty. The statement itself rests **encrypted** in the shared inventory (a database observer reads ciphertext; a fabricated row is never shown to a supervisor), decisions cannot be forged or replayed, and nobody may decide their own session's step-up from any replica. Nothing to configure: it activates with the store, best-effort like the kill and live buses, and a failed bus subscription falls back to replica-local with a startup warning. Console screen 21 gained a Replica column and the `DECISION DISPATCHED … VERIFY WITH F5` report |
| 2026-07-29 | **Phase 54 — VNC connector.** `vnc` is a target protocol: create it like any other (default port 5900) and open it from *Work with Targets* → option **7**, the same key as RDP — the portal picks the viewer from the target's protocol. It reuses your guacd deployment and `PAM_GUACD_RECORDING_PATH`, and the clipboard policy (`PAM_RDP_CLIPBOARD` plus any per-target override) applies unchanged; VNC's SFTP file channel is always off. Two things to know: VNC is **plaintext with no server authentication** and its password is DES-truncated to 8 characters, so keep guacd and the targets on a trusted segment (see [PROTOCOLS-AND-CRYPTO §3.5](PROTOCOLS-AND-CRYPTO.md)); and if guacd cannot enforce a non-permissive clipboard policy the session is **refused** (`vnc.refused reason:clipboard-unenforceable`) rather than run ungated. |
| 2026-07-29 | **Phase 53 — SQL Server session proxy.** `PAM_MSSQL_ADDR` (default `off`) brokers `mssql` targets over TDS exactly as `PAM_DB_ADDR` brokers PostgreSQL: same authorization gates, JIT credential injection into the client's own LOGIN7, per-statement `db.query` audit (`via:mssql`), command control that **sees through `sp_executesql`**, in-session step-up, recording, live monitoring and cluster-wide kill. Connect with `sqlcmd -S pam.example,1433 -U '<dbcred>@<target>' -P "$PAM_TOKEN"`. Set `PAM_TLS_CERT/KEY` — modern TDS clients require encryption and will refuse a plaintext proxy. Integrated/Windows auth is not brokered (SQL authentication only). See §5 → *Database targets (SQL Server)*. |
| 2026-07-29 | **Phase 55 — cross-replica live monitoring.** In a multi-replica deployment, `GET /api/sessions` now lists every replica's sessions (each naming its host in a new `"replica"` field) and `GET /api/sessions/{id}/stream` watches a session hosted on any replica — the hosting pod relays the output over the database, only while someone is watching, and the watch is audited `session.monitor … via:relay`. A crashed hosting replica closes the remote stream within ~45s instead of hanging it. Nothing to configure: it activates with the store (Postgres in HA; the demo store behaves as before), and a failed bus subscription falls back to replica-local with a startup warning. Still replica-local by design: deciding a paused step-up (`POST /api/sessions/{id}/stepup` must reach the hosting replica) and the `PAM_MAX_SESSIONS_*` caps. See §5 (monitoring) and the HA notes in REQUIREMENTS.md |
| 2026-07-29 | **Review fixes on #81–#84.** Broker audit keys: an explicit env value is now **written through to shared custody** (mixed fleets and later unsetting can no longer silently fork the chain; a disagreeing explicit HMAC key refuses to start, a disagreeing seed is the signer-rotation path and custody converges to it). WinRM: the recording size cap now **ends** a WinRM session with `session.record_limit` (parity with SSH) instead of letting it continue unrecorded with a frozen live stream; a REST/broker run's output reaches live watchers only **after** the durable `winrm.run` audit (the withheld-result contract now also binds the stream); refused runs (blocked / recording-required / decrypt-failed) publish an explanatory notice and blocked/errored runs leave a transcript (`session.record`). Broker `ssh_exec` now **streams live** like `winrm_exec` (echo + output, output withheld on audit failure). Per-target clipboard: an unrecognizable stored override now enforces as **deny** (fail closed) instead of silently ranking as allow, and the overrides ride the `target.create`/`target.update` audit details. Live watch: the 404 is replica-honest ("not live on this replica") and refused watches are audited. Portal: watch-pane lines no longer end in a literal `\r`. See §5, §9.4 and the broker section. |
| 2026-07-29 | **The watch stream ends with the session.** A supervisor's live watch (`GET /api/sessions/{id}/stream`, portal option 5) now terminates the moment the watched session completes or is killed — the pane reports "session ended" instead of sitting silent forever — and watching an unknown or already-over session id is refused with 404. See §9.4. |
| 2026-07-29 | **Per-target RDP clipboard override (Phase 33 follow-on).** A target's `rdp_clipboard` / `rdp_clipboard_audit` fields (portal *Add/Change Target*, create/update API) tighten the global `PAM_RDP_CLIPBOARD` / `_AUDIT` for that one target — the stricter policy always wins, so a high-sensitivity target can deny what the fleet allows and no target row can loosen a global deny. The effective mode is what `rdp.connect` audits. See §5 and the RDP section. |
| 2026-07-29 | **WinRM sessions stream live (Phase 16 follow-on).** *Work with Active Sessions* option 5 (and `GET /api/sessions/{id}/stream`) now works for WinRM too: the proxy's interactive shell streams exactly what its recording sees, and a REST or agent-broker run streams a `winrm>` command echo plus the output. RDP remains recording-and-clipboard-audit only. See §9.4. |
| 2026-07-28 | **Broker audit keys under shared custody (Phase 13 follow-on).** `PAM_BROKER_AUDIT_KEY` and `PAM_BROKER_AUDIT_SIGN_SEED` are now optional: unset, each is generated once and sealed by the KEK into `key_material` (every replica converges on the same chain key and signer, and `-rotate-kek` re-wraps them like the SSH host/CA keys). An explicit env value still wins — that is how a signer rotation is driven; if the seed was custody-held, read the outgoing public key from `GET /v1/audit/jwks` *before* rotating. See §4 and the broker section. |
| 2026-07-27 | **Phase 51 — SFTP path policy.** `PAM_SSH_SFTP_DENY_FILE` gates file transfer by **path**, not just by operation: a matching path is refused in every mode (downloads included) and on both sides of a rename, audited `sftp.blocked reason:path-denied` with the rule that matched. Same regex-file format as command control, and a bad pattern fails startup. See §9.4. |
| 2026-07-27 | **Phase 50 — clipboard auditing on the RDP bridge.** `PAM_RDP_CLIPBOARD_AUDIT=meta` records every clipboard transfer as `rdp.clipboard` — direction (out = copied from the target, in = pasted into it), mimetype, byte count and SHA-256; `full` also records the content, which is opt-in because a privileged clipboard often holds a just-copied password. Auditing never blocks a transfer; gating stays `PAM_RDP_CLIPBOARD`. See §5 (RDP) and §4. |
| 2026-07-27 | **Phase 49 — archive to WORM before pruning.** `PAM_RETENTION_ARCHIVE_DIR` makes retention archive-then-prune: aged audit rows are exported as digest-stamped JSON Lines and aged recordings are moved into a write-once archive, and **the delete runs only if the archive succeeded** — a broken archive costs disk space, not evidence. New audit actions `audit.archived` / `recording.archived`. With the HMAC chain on you now get the scheduled export too; only the delete stays a manual re-anchor. See §9.2 and §4. |
| 2026-07-27 | **Phase 48 — opaque recording file names.** `PAM_RECORDING_OPAQUE_NAMES=true` names recordings by timestamp + random hex, so the recording volume (and its backups) no longer reveals who accessed which system. Target and actor move to the audit trail; the console's recordings screen and `GET /api/recordings` resolve them back for anyone who may already read audit. Pair with `PAM_RECORDING_ENCRYPT` for content + metadata. See §9.3 and §4. |
| 2026-07-27 | **Phase 47 — LEEF + TLS for the SIEM forwarder.** `PAM_AUDIT_FORWARD_FORMAT=leef` speaks IBM QRadar's LEEF 2.0, and `PAM_AUDIT_FORWARD_PROTO=tls` streams the trail over verified TLS (RFC 5425, octet-counted syslog framing) — pin the collector's CA with `PAM_AUDIT_FORWARD_CA`, or leave it empty for the system roots. Verification cannot be disabled. See §9.2 and §4. |
| 2026-07-27 | **Phase 46 — per-item four-eyes on certification.** Grants record their creator (migration `0023`), campaign items snapshot it ("granted by X"), and certifying a grant you created is refused + audited; self-revoke stays allowed. Legacy rows without a recorded creator are not blocked. See §9.6 |
| 2026-07-27 | **Phase 45 — the remaining console screens.** Everything that was curl-only now has a 5250 screen: vendors & contract grants (menu 22 — register, change org, offboard, add/approve/revoke grants, evidence export with its SHA-256), operator SSH certificates (23 — plus a new `GET /api/ca/ssh/certs` listing so the serials a revocation needs are visible), identity blast radius (24), login sessions (25), AI-agent keys (26), credential dependents (option 9 on a credential), and the audit screen's chain controls (F6=Verify, F7=Signed head, F10=OCSF export). The console is back at **full parity**. See §5–§9 |
| 2026-07-27 | **Phase 44 — editable objects and bounded lists.** Targets, safes, users and vendors now have `PUT` endpoints that edit in place — fixing a target's port no longer means delete + recreate (which cascaded away its credentials, grants, dependencies and safe assignment), a role change keeps the user's token, and the same validation, authorization and privilege-escalation guard as create apply. Grants and safe members stay create + delete by design. Every inventory list serves a clamped `?limit=&after=` window (default 100, max 500, ascending id) — page until a short page returns; the console does it automatically and gains 2=Change. Audit gains `target.update`/`safe.update`/`user.update`/`vendor.update`. See §5 |
| 2026-07-27 | **Phase 43 — the console's two human decision points.** New screens: **Approve AI-agent tool calls** (menu 20) shows each parked call with the agent, who it acts on behalf of, the rule that gated it and its **arguments**, and approves or rejects it; **In-session step-up decisions** (menu 21) lists paused statements and allows or refuses them. Both were previously curl-only, and both are decisions with a deadline — a step-up expires, a parked call blocks its agent. Listing step-ups needs `read_audit`; deciding either needs `approve`. Portal-only: no new routes, schema or settings. See §7 and §9.4 |
| 2026-07-27 | **Phase 42 — shared custody of the SSH host and CA keys.** Both keys were per-pod files, so running more than one replica handed operators a different host key depending on which pod answered (a warning indistinguishable from a MITM) and a different certificate authority, and broke the operator-certificate challenge. They are now claimed atomically in the database, vault-encrypted, so replicas converge on one key. **Upgrading is safe**: a key already on disk seeds the shared custody rather than being replaced, so a single node keeps the host key it has been serving. A key that cannot be decrypted stops startup instead of being silently regenerated — if you see that, check `PAM_MASTER_KEY`. Recordings are still written per pod; put them on shared storage if you scale out. See §3.4 and §4 |
| 2026-07-27 | **Phase 41 — session recordings encrypted at rest.** `PAM_RECORDING_ENCRYPT=true` seals session recordings and WinRM transcripts with a per-recording key wrapped by your KEK (local / Vault Transit / AWS KMS / PKCS#11), so the artifact that holds what the operator typed and saw is protected like a credential rather than by file permissions. Replay from the console is unchanged and the tamper-evidence verdict still works — the hash covers the stored bytes. Existing recordings keep replaying (the format is detected per file). Note the file NAME still carries target and actor. See §4 and §9.3 |
| 2026-07-27 | **Phase 40 — every brokered execution is a supervised session.** A `POST /api/targets/{id}/winrm` run, and an AI agent's `winrm_exec`/`ssh_exec` tool call, now appear in *Active Sessions* while they run, count against `PAM_MAX_SESSIONS_PER_USER`/`_TOTAL` (checked before the credential is decrypted, so a refused run never decrypts one), and can be terminated by the kill switch — including by the analytics auto-response and the vendor sweeper, which terminate by actor. A killed run answers 503. Previously only the SSH, PostgreSQL and RDP paths were registered. See §9.4 |
| 2026-07-26 | **Phase 39 — approver capability on the two decision points.** Releasing a paused step-up statement (`POST /api/sessions/{id}/stepup`) now needs `approve` instead of `read_audit`: a read-only auditor could previously authorize a statement the policy had flagged. Deciding a certification item now needs `approve` instead of `manage_users`, so a dedicated approver can run a recertification without holding any access-granting capability (creating and closing a campaign stay `manage_users`). Listing paused step-ups and reading campaigns are unchanged. See §9.4 and §9.6 |
| 2026-07-26 | **Phase 38 — command control on every command path.** The deny policy (`PAM_COMMAND_DENY_FILE`) moved into its own package and is now compiled once and shared by the session proxies **and** the API server, so it also covers `POST /api/targets/{id}/winrm` (403, before the credential is decrypted) and the agent broker's `ssh_exec`/`winrm_exec` tools (before any dial). Previously a pattern that stopped an operator's `ssh target "cmd"` did nothing to an AI agent. Blocks are audited `command.blocked` with the matched pattern on every path. No new env var, no schema change. See §9.4 |
| 2026-07-26 | **Currency pass over this guide.** Two shipped subsystems had no operator documentation at all and now do: the **third-party vendor access gate** (§7 — contract grants, the attestation webhook, the sweeper, the offboard cascade, evidence export) and the **identity blast radius / CIEM** engine (new §9.8, with a worked example). Every `PAM_*` variable the server reads is now in §4 or its own section — newly documented: `PAM_VENDOR_*`, `PAM_ALERT_WEBHOOK`/`_SYSLOG`/`_EMAIL_*`, `PAM_SSH_JUMP_*`, `PAM_PROXY_WINRM`, `PAM_ROTATE_AFTER_SESSION`, `PAM_GUACD_ADDR`/`_RECORDING_PATH`, `PAM_PORTAL_URL`, `PAM_LDAP_INSECURE_SKIP_VERIFY` (with why it must stay off), and the OIDC endpoint/scope/role overrides. Change-log rows added for Phases 27–31 and the misfiled 32–36 rows sorted back into date order. `.env.example` gained the eight variables it was missing |
| 2026-07-26 | **Phase 37 — gap-analysis pass.** Two authorization scoping fixes: a delegated `can_manage` safe member can no longer remove a member of **another** safe (the member must belong to the safe in the path), and a dependency delete is bound to the credential in its route (the audit now names it). **Failed bearer credentials are throttled and audited on every surface**: a wrong `X-API-Key`, agent key or application key now consumes a per-source-IP failure budget (`PAM_AUTH_RATE_LIMIT`, its own window → 429 past it) and appends `api.auth_failed` (`surface:api\|agent\|app`), so token guessing over HTTP is slowed and visible to the risk engine and the SIEM forwarder — parity with what the SSH/DB proxies already did. No new env var, no schema change. See §4, §11 and [SECURITY-GAPS.md](SECURITY-GAPS.md) |
| 2026-07-25 | Phase 36: **retention / pruning** — a leader-locked worker prunes recordings (`PAM_RECORDING_RETENTION_DAYS`) and audit rows (`PAM_AUDIT_RETENTION_DAYS`); audit pruning is skipped while the HMAC chain is on. See §9.2. |
| 2026-07-25 | Phase 35: **audit→SIEM forwarding** — `PAM_AUDIT_FORWARD_ADDR` streams every audit event to a syslog/CEF collector continuously (durable cursor, spool-and-retry, leader-locked). See §9.2. |
| 2026-07-25 | Phase 34: **HA session kill-switch** — session kills are broadcast across replicas (Postgres LISTEN/NOTIFY), so `DELETE /api/sessions/{id}` (and the revoke cascade / vendor offboard / analytics auto-kill) terminates a session on whichever pod hosts it; 202 when dispatched cluster-wide, 204 when local. See §9.4. |
| 2026-07-25 | Phase 33: **RDP clipboard control** — `PAM_RDP_CLIPBOARD` (`allow`/`readonly`/`deny`) gates the Guacamole clipboard bridge and always disables drive redirection; the mode is audited on `rdp.connect`. See §5 (RDP). |
| 2026-07-25 | Phase 32: **SFTP file-transfer control** — `PAM_SSH_SFTP` (`allow`/`readonly`/`deny`) audits every SFTP operation and can refuse writes or the whole subsystem; closes an unaudited file-transfer path. See §9.4 |
| 2026-07-25 | **Phases 27–31 review fixes.** A vendor grant scoped to one account no longer admits a session on another; DB step-up now also pauses a **prepared** (extended-protocol) statement, so the supervisor gate can't be dodged; broker approver-group membership drops the principal's own name (a delegated `manage_users` can't mint a user named after an approver group to self-approve); an SSH-cert issue refused for an unmanaged principal no longer burns a one-time approval |
| 2026-07-25 | Phase 31: **identity blast radius / CIEM** — `POST /api/blast/analyze` (`read_audit`) answers "if this identity were compromised, what could it reach?" over a normalized identity graph you submit: a real AWS IAM effective-permission evaluator, toxic-combination findings (escalation, cross-provider lateral movement) and an earliest-cut remediation for each. Read-only; the ingester that builds the graph is external. See §9.8 |
| 2026-07-25 | Phase 30: **in-session step-up** — `PAM_DB_STEPUP_FILE` marks PostgreSQL statements that **pause for a supervisor's live decision** (`GET /api/sessions/stepups`, `POST /api/sessions/{id}/stepup`) instead of killing the session; `PAM_DB_STEPUP_TTL_SEC` bounds the wait. Broker policy rules also gained numeric comparators (`gte`/`gt`/`lte`/`lt`) so a rule can gate on an amount. See §9.4 |
| 2026-07-25 | Phase 29: **third-party vendor access gate** — time-boxed, customer-approved contract grants for external technicians, enforced on every connect path, with a live employment-attestation webhook (`PAM_VENDOR_ATTEST_URL`), a mid-session sweeper (`PAM_VENDOR_SWEEP_INTERVAL_MIN`), a one-action offboard cascade, and a per-vendor evidence export. See §7 |
| 2026-07-24 | Phase 28: **operator-issued SSH certificates** — an operator proves possession of their own key (`POST /api/ca/ssh/challenge` → `/sign`) and gets a short-lived cert scoped to one principal (`PAM_SSH_OPERATOR_CERT_TTL_MIN`), usable with their normal SSH client; revoke by serial and publish an OpenSSH **KRL** (`GET /api/ca/ssh/krl`) as your targets' `RevokedKeys`. See §6 |
| 2026-07-24 | Phase 27: **AI-agent broker completion** — a `require_approval` rule's `approvers:` list is enforced at decision time (separation of duties); periodic **signed in-chain checkpoints** (`PAM_BROKER_AUDIT_CHECKPOINT_EVERY`) with signing-key rotation (`PAM_BROKER_AUDIT_SIGN_PREV`) and a JWKS at `GET /v1/audit/jwks`; a truncation floor on `GET /v1/audit/verify?min_entries=N`; **OCSF** SIEM export at `GET /api/audit/ocsf`; and the MCP SSE transport with elicitation. See §7 and §9.2 |
| 2026-07-24 | **Phase 26 — recording playback + one-time access.** `GET /api/recordings[/{name}]` (`read_audit`) lists and replays stored recordings with the SHA-256 re-verified against the audit trail (`X-PAM-Recording-Audited`; replay audited `session.playback`); console menu 19 player. Access requests can be **single-use** (`one_time`, or `PAM_ACCESS_ONE_TIME` globally): every gate — SSH/DB proxies, RDP, reveal, checkout, WinRM run, broker tools — consumes the approval on first use (audited `access.consumed`). §9.3, §5, env table |
| 2026-07-24 | **Phase 25 — console parity.** New 5250 screens: *Work with Safes* (menu 16, incl. member management and target assignment via *Work with Targets* option 8), *Certification campaigns* (menu 17: snapshot / certify / revoke / close), *Risk analytics* (menu 18), and a **live session watch pane** (*Active Sessions* option 5). The file-request form gained the Phase 20/21 fields (ticket, N-of-M approvals, scheduled window). Portal-only — no new routes, schema, or env. §5, §9.4, §9.6, §9.7 |
| 2026-07-23 | **In-portal RDP viewer.** The portal now vendors the Apache Guacamole JS client (`/static/guacamole-common.min.js`, see `NOTICE`) and renders RDP on a canvas — *Work with Targets* → option **7**, `Ctrl+Alt+Q` to disconnect. Adds `POST /api/rdp-token` (short-lived WS token, audited `rdp.token`) and widens the portal CSP for the canvas (`img-src data: blob:`, `script-src 'self'`). Verification: [RDP-TESTING.md](RDP-TESTING.md). See §5 → *RDP*. |
| 2026-07-23 | **Bundled guacd (RDP broker).** The Docker compose runs a hardened `guacd` service (`PAM_GUACD_ADDR=guacd:4822` wired in); the raw K8s manifests add `deploy/k8s/guacd.yaml` (Deployment + ClusterIP + NetworkPolicy); the Helm chart adds it under `guacd.enabled=true`. Internal-only in every case. See §5 → *RDP*. |
| 2026-07-23 | Doc-quality pass: added a contents index; de-staled §1 Concepts (Windows/PostgreSQL targets, DB proxy, custom profiles) and the `protocol`/`secret_type` type-lists; standardized on "PAM token"; fixed undefined `$TOKEN` in examples; header currency |
| 2026-07-23 | **Signed audit checkpoints.** With `PAM_AUDIT_SIGN_SEED` (+ `PAM_AUDIT_HMAC_KEY`), `GET /api/audit/head` returns an ed25519-signed checkpoint so an auditor can detect **tail truncation** the HMAC chain alone can't. Archive checkpoints out-of-band. See §9.2 |
| 2026-07-23 | **Tamper-evident primary audit trail** (opt-in). Set `PAM_AUDIT_HMAC_KEY` (base64 32 bytes) to HMAC-chain the whole `audit_events` table, not just broker events; any edit/reorder/delete is detectable via `GET /api/audit/verify`. Additive, non-breaking (unset = plain table). See §4 and §9.2 |
| 2026-07-22 | **Security gap-analysis hardening pass** ([SECURITY-GAPS.md](SECURITY-GAPS.md)). Safe-scoped targets are now default-deny (a target in an empty safe is no longer open to all); the DB proxy enforces the MFA-enrollment gate; secret delivery and proxied sessions are **fail-closed on the audit trail**. New admin controls: `GET /api/login-sessions` + `POST /api/login-sessions/revoke`, and reconcile revokes disabled directory sessions (§7). New env: `PAM_REQUIRE_HTTPS`, `PAM_REQUIRE_DB_CLIENT_TLS`, `PAM_DB_UPSTREAM_CA`/`_TLS_VERIFY`, `PAM_PROXY_AUTH_RATE_LIMIT`, `PAM_TRUSTED_PROXY_HOPS`, `PAM_ALLOW_WEAK_API_KEY` (§4); `-rotate-kek` migrates between KEK providers via `PAM_NEW_KEK_*` (§8). Deploy: default-deny `NetworkPolicy` (§3.4), pinned image tags. See §10 |
| 2026-07-21 | Phase 24: **application-secrets API** (Tier-4) — a Conjur-style path (`PAM_APP_SECRETS_ENABLED`) where a non-agent app retrieves the secrets it was explicitly granted with a bearer key (`GET /v1/app-secrets/{credential_id}`); default-deny, granting needs `reveal_secret`, every retrieval audited. See §7. The portal is now **keyboard-first** (mouse optional): focus lands on each screen's field, Esc goes back, ↑/↓ move subfile rows. |
| 2026-07-21 | Phase 23: **privileged threat analytics** — explainable behavioral risk scoring over the audit trail (`GET /api/analytics/risk`, `CapReadAudit`); a background worker (`PAM_ANALYTICS_INTERVAL_MIN`) alerts on newly elevated high/critical actors and, with `PAM_ANALYTICS_AUTO_KILL`, terminates a critical actor's live sessions. See §9.7 |
| 2026-07-21 | Phase 22: **Zero Standing Privilege** — an `ssh_ca` credential stores no secret; the proxy mints a short-lived SSH certificate just-in-time per session (`PAM_SSH_CA_KEY`, `PAM_SSH_CERT_TTL_MIN`). Install the CA on targets from `GET /api/ca/ssh`. See §6 → *Zero Standing Privilege* |
| 2026-07-21 | Phase 21: **richer approval workflows** — multi-tier N-of-M approval chains (`PAM_APPROVALS_REQUIRED`, or per-request `approvals`), scheduled maintenance windows (`not_before`/`not_after` on a request), and mandatory reason codes (`PAM_REQUIRE_REASON`) |
| 2026-07-21 | Phase 20: **ITSM / ticketing gate** — an access request can require a change/incident ticket (`PAM_REQUIRE_TICKET`), validated by a format regex (`PAM_TICKET_PATTERN`) and/or an ITSM webhook (`PAM_TICKET_VALIDATE_URL`); the ticket is recorded in the audit trail |
| 2026-07-21 | Phase 19: **access certification campaigns** — `POST /api/campaigns` snapshots current access (target grants + safe members); certify/revoke each item (`revoke` deletes the grant); close to record the attestation. Management `CapManageUsers`, reading `CapReadAudit`. See §9.6 |
| 2026-07-21 | Phase 18: **Conjur secret sourcing** — an alternative to SOPS: set `PAM_CONJUR_URL` and pam-server fetches its own bootstrap secrets from CyberArk Conjur at startup (authn-api-key or Kubernetes authn-jwt). Both ship; SOPS stays the default. See [deploy/k8s/conjur/README.md](../deploy/k8s/conjur/README.md) |
| 2026-07-21 | Phase 17: **safes + dependent-account propagation** — group targets into delegated-access safes (`/api/safes`, a member reaches every target in the safe; `can_manage` delegated administration) and declare a credential's consumers (`/api/credentials/{id}/dependencies`) so rotation updates the Windows Services / Scheduled Tasks / IIS App Pools that use it. See §7 → *Safes* and *Dependent accounts* |
| 2026-07-21 | Phase 16: **live session monitoring + command control** — watch an SSH/PostgreSQL session live over `GET /api/sessions/{id}/stream` (SSE, `CapReadAudit`); block dangerous commands on exec/WinRM/SQL via a regex denylist (`PAM_COMMAND_DENY_FILE`, audited `command.blocked`). See §9.4 |
| 2026-07-20 | Phase 15: **PostgreSQL database session proxy** (`PAM_DB_ADDR`) — brokers `postgres` targets with JIT credential injection and **per-statement query audit** (`db.query`); operators use `psql user=<dbcred>@<target>` with their PAM token. Same authorization gates as the SSH proxy; upstream auth via SCRAM-SHA-256/MD5/cleartext. See §5 → *Database targets (PostgreSQL)* |
| 2026-07-20 | Post-review hardening: directory logins grant the **union** of every mapped group's role (not the single highest); a parked agent approval is **re-validated at decision time** (revoked key / expired SVID refused); broker-audit append serializes under a Postgres advisory lock so a rolling-deploy/HA overlap can't fork the hash chain; numeric policy arguments match in plain decimal |
| 2026-07-20 | Phase 14: **SOPS-encrypted Kubernetes secrets** — seal the Secret manifest with [SOPS](https://github.com/getsops/sops)+[age](https://age-encryption.org/) and keep it in Git; `deploy/k8s/sops/apply.sh` streams decrypt→`kubectl apply` (plaintext never on disk). See [deploy/k8s/sops/README.md](../deploy/k8s/sops/README.md) |
| 2026-07-20 | Phase 13: **AI-agent access broker** — opt-in via `PAM_BROKER_POLICY_FILE`; policy-gated tool calls with JIT server-side execution, approval/resume + single-use tokens, an MCP transport (`POST /mcp`), SPIFFE JWT-SVID identity, and a keyed-HMAC verifiable audit chain (`GET /v1/audit/verify`/`/head`). See §7 → *AI-agent access broker* |
| 2026-07-20 | Phase 12: **configuration subsystem + custom-profile RBAC** — DB-persisted `PAM_*` overrides editable from the 5250 console and **hot-swapped without a restart** (`GET/PUT /api/config`, §4.1), named permission profiles (`/api/profiles`, §7), and effective-config/IaC export (`GET /api/config/iac`) |
| 2026-07-20 | Phase 11: **management console** — the 5250 portal becomes a role-aware console over every API (`GET /api/me`-driven menu) |
| 2026-07-19 | PKCS#11 HSM KEK provider (`pkcs11` build tag, `Dockerfile.pkcs11`, `PAM_KEK_PKCS11_*`); verified against SoftHSM2 |
| 2026-07-19 | Phase 7 follow-ons: credential checkout/check-in leases (auto-rotate on return), discovery scan; system requirements ([REQUIREMENTS.md](REQUIREMENTS.md)) |
| 2026-07-19 | Phase 10: scale & ops — Prometheus `/metrics`, `/readyz` readiness, Helm chart (`deploy/helm/pamv1`), SBOM + cosign-signed release workflow |
| 2026-07-19 | Phase 9: NIS2 pack — tamper-evident audit export (`GET /api/audit/export`, JSON/CSV + SHA-256) for Art. 23; see [NIS2-COMPLIANCE.md](NIS2-COMPLIANCE.md) |
| 2026-07-19 | Phase 8: OT adaptation — 4-eyes access-request approval (`/api/access-requests`), per-target/global gate (`PAM_REQUIRE_APPROVAL`), air-gap mode (`PAM_OT_AIRGAP`); see [OT-DEPLOYMENT.md](OT-DEPLOYMENT.md) |
| 2026-07-19 | Phase 7: credential lifecycle — rotation (`/api/credentials/{id}/rotate`), reconciliation (`/reconcile`, `?remediate`, `GET /api/reconcile`), scheduled worker (`PAM_ROTATE_*`) |
| 2026-07-19 | Phase 6: break-glass v2 (M-of-N quorum unseal, auto-expiring sessions, alerting); AWS KMS KEK |
| 2026-07-18 | Phase 4: NTLM WinRM auth; RDP brokering via Guacamole guacd |
| 2026-07-18 | Phase 3b: OIDC single sign-on (Authorization Code + PKCE, JWKS validation) |
| 2026-07-18 | Phase 4: Windows targets — WinRM command execution with JIT credentials |
| 2026-07-18 | Phase 3b: enforce-MFA policy (`PAM_MFA_REQUIRED`) + single-use recovery codes |
| 2026-07-28 | **Phases 52–52e: the post-beta security sweep, all thirty findings closed.** Operationally relevant: `PAM_REQUIRE_RECORDING` now covers the in-portal RDP viewer and the REST WinRM endpoint as well as the three proxies, so a deployment that sets it without `PAM_GUACD_RECORDING_PATH` / `PAM_RECORDING_DIR` will now **refuse those sessions** rather than run them unrecorded (§4). A deny file that yields no usable patterns (`PAM_COMMAND_DENY_FILE`, `PAM_SSH_SFTP_DENY_FILE`, `PAM_DB_STEPUP_FILE`) is now **fatal at startup** instead of silently disabling the control — an unmounted ConfigMap fails loudly. `-rotate-kek` re-wraps the Phase-42 key custody and warns about sealed recordings (§8). Audit details now quote client-supplied paths and patterns, and MFA recovery codes are longer; both are format changes for anything parsing them |
| 2026-07-18 | Phase 3b: Microsoft Entra ID (Azure AD) login setup (app roles → roles, sovereign host) |
| 2026-07-18 | Phase 3b: TOTP MFA (self-service enroll/verify, enforced on login) |
| 2026-07-18 | Phase 3b: Active Directory login setup (LDAPS, group→role, session tokens); envelope-encryption KEK config |
| 2026-07-18 | Initial admin guide (Phase 3a): deployment, config, target/credential/user management, break-glass, logging & audit, hardening, troubleshooting |

*See also the [User Guide](USER-GUIDE.md) and the [ROADMAP](../ROADMAP.md).*
