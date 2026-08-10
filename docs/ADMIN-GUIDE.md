# pamv1 — Administrator Guide

A complete, practical guide for **administrators**: deploy pamv1, configure it,
onboard targets and credentials, manage users and roles, run the break-glass
procedure, and read the logs and audit trail.

> **Living document.** Kept in step with the product — update it whenever
> admin-facing behavior changes (config, deployment, management, logging). Add a
> row to the [change log](#12-change-log) with each update.
>
> Last updated: 2026-08-10 · Reflects: Phases 0–107 + the 2026-07 hardening passes — through the AI-agent access broker (13, completed in 27), the PostgreSQL database session proxy (15), live monitoring + command control (16), safes + dependent-account propagation (17), optional CyberArk Conjur secret sourcing (18), access certification campaigns (19), the ITSM/ticketing gate (20), richer approval workflows (21), Zero Standing Privilege via ephemeral SSH certificates (22, extended to operator-issued certs in 28), privileged threat analytics (23), the Conjur-style application-secrets API (24), console parity (25: 5250 screens for safes, campaigns, risk analytics, and a live session viewer), recording playback + one-time access (26), the third-party vendor access gate (29, §7), in-session step-up (30, §9.4), the identity blast-radius / CIEM engine (31, §9.8), SFTP and RDP clipboard control (32–33, with per-file SFTP content capture in 59), the cluster-wide kill-switch (34), audit→SIEM forwarding (35), retention (36), the SQL Server and VNC connectors (53–54) and cluster-wide live monitoring (55) — plus the hardening passes: an HMAC-chained audit trail with signed checkpoints (§9.2), revocation that terminates live sessions (§7), verified upstream-DB TLS, and per-IP auth throttling on every surface (§4). The console is keyboard-first. See the [ROADMAP](../ROADMAP.md).

> ⚠️ **Educational / pre-production.** pamv1 is a learning project and is
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

Or, if you run **CyberArk Conjur**, pamv1 can fetch its own bootstrap secrets
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
| `PAM_PORTAL_URL` | | `/` | Where the OIDC callback redirects the browser after a successful login (the session token rides the URL fragment). Set it when the portal is served from another origin than the callback. |
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
| `PAM_SSH_SFTP` | | `allow` | SFTP file-transfer policy (Phase 32): `allow` (forward + audit every op), `readonly` (refuse writes/deletes/renames), `deny` (refuse the subsystem). See §9.4. |
| `PAM_SSH_SFTP_DENY_FILE` | | (off) | **Path denylist for SFTP** (Phase 51): regexes, one per line (same format as `PAM_COMMAND_DENY_FILE`). A matching path is refused in **every** mode — downloads too — and on both sides of a rename; audited `sftp.blocked reason:path-denied` with the matched pattern. See §5. |
| `PAM_SSH_SFTP_CAPTURE` | | `off` | **Record the content of SFTP transfers** (Phase 59): `uploads`, `downloads`, or `all`. Every transferred file leaves a `.sftp` chunk-log artifact beside the session recordings — sealed under `PAM_RECORDING_ENCRYPT`, hash-chained, audited `sftp.file_recorded`, replayable from menu 19. While on, an SFTP stream the proxy cannot parse is **refused** (fail closed). See §5. |
| `PAM_SSH_SFTP_CAPTURE_MAX_MB` | | `0` (unlimited) | Per-file cap on captured bytes. Past the cap the transfer is **refused** (permission-denied, audited `sftp.blocked reason:capture-limit`), not merely left unrecorded — so with capture on this doubles as a per-file transfer size limit. |
| `PAM_RDP_CLIPBOARD` | | `allow` | RDP clipboard policy (Phase 33): `allow`, `readonly` (block paste into the target), `deny` (clipboard off both ways); drive redirection always off. A target's `rdp_clipboard` field can tighten this per target — the **stricter** of the two wins. |
| `PAM_RDP_CLIPBOARD_AUDIT` | | `off` | **Audit clipboard transfers** (Phase 50): `meta` records direction, mimetype, size and SHA-256; `full` also records the content (truncated). Content is opt-in because a privileged desktop's clipboard often holds a password the operator just copied. Emits `rdp.clipboard`. A target's `rdp_clipboard_audit` field can raise this per target (whichever records more wins). See §9.4. |
| `PAM_DB_STEPUP_FILE` | | (off) | Regex file marking PostgreSQL statements that **pause for a supervisor's live approval** — in-session step-up (Phase 30). See §9.4. |
| `PAM_DB_STEPUP_TTL_SEC` | | `120` | How long a paused statement waits for a decision before it is denied. |
| `PAM_ANALYTICS_INTERVAL_MIN` | | `0` (off) | Threat-analytics worker interval (Phase 23); `0` leaves the read-only `GET /api/analytics/risk` endpoint on. See §9.7. |
| `PAM_ANALYTICS_WINDOW_MIN` / `_AUTO_KILL` / `_BUSINESS_START` / `_BUSINESS_END` | | `60` / `false` / `7` / `20` | Risk-scoring window (also the re-alert cooldown), auto-kill of critical actors' sessions, and business hours for the off-hours signal. |
| `PAM_ANALYTICS_TIMEZONE` | | (UTC) | IANA timezone the business hours are interpreted in (audit timestamps are UTC). |
| `PAM_APP_SECRETS_ENABLED` | | `false` | Enable the application-secrets API (Phase 24): Conjur-style secret delivery to non-agent apps. Front it with TLS. See §7. |
| `PAM_SSH_HOST_KEY` | | (ephemeral) | Path to persist the proxy SSH host key. Since Phase 42 the **store** is the authority in a multi-replica deployment: a key already at this path seeds shared custody, otherwise the replica adopts the cluster's key and mirrors it here. |
| `PAM_SSH_CA_KEY` | | (ZSP off) | Path to the Zero Standing Privilege SSH CA key (Phase 22); presence enables `ssh_ca` credentials (mint short-lived certs). Shared across replicas since Phase 42 — every pod publishes and signs with the same CA. See §6. |
| `PAM_SSH_CERT_TTL_MIN` | | `2` | Validity (minutes) of a minted ZSP certificate. |
| `PAM_SSH_OPERATOR_CERT_TTL_MIN` | | `10` | Cap (minutes) on an operator-issued SSH certificate (Phase 28: `POST /api/ca/ssh/sign`). See §6. |
| `PAM_SSH_KNOWN_HOSTS` | | (trust-any + warn) | OpenSSH known_hosts file pinning **upstream target** host keys. |
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
| `PAM_VENDOR_ATTEST_URL` | | (off) | Employment-attestation webhook consulted when a vendor contract grant is approved (Phase 29): pamv1 `POST`s `{"vendor":…,"org":…}` and the vendor-management system answers `2xx` for a currently-employed technician, so access is refused the moment their own employer offboards them. See §7. |
| `PAM_VENDOR_SWEEP_INTERVAL_MIN` | | `0` (off) | How often the sweeper cuts a vendor's **live** session once its contract grant's window closes (`vendor.session_expired`), so access ends with the contract rather than at the next connect. |
| `PAM_OT_AIRGAP` | | `false` | Air-gapped sites. Forces the no-op alerter **and refuses to start** alongside anything that would call out of the enclave — the ITSM webhook, vendor attestation, the SIEM forwarder, Conjur, the alert webhook and `PAM_OIDC_ISSUER` — and rejects `PAM_KEK_PROVIDER=aws-kms` and `PAM_ENTRA_TENANT_ID` outright. It is a fail-closed startup gate, not a mute switch. |
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
| `PAM_BROKER_TOKEN_TTL_MIN` | | `15` | Lifetime of the single-use approval resume token (minutes). |
| `PAM_BROKER_RATE_PER_MIN` | | `0` (off) | Per-agent tool-call rate limit. |
| `PAM_BROKER_MAX_ARG_BYTES` | | `16384` | Cap on a tool call's serialized arguments (0 = off). |
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
`PAM_ENTRA_*`, `PAM_OIDC_*`, `PAM_MFA_REQUIRED`, `PAM_REQUIRE_APPROVAL`,
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
(`PUT /api/vendors/{id}`, org label only) edit the same way. In the console,
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

`secret_type` is `password`, `ssh_key` (paste the PEM private key as `secret`), or `ssh_ca` (Zero Standing Privilege — no stored secret; see the ZSP subsection below).
Once the proxy is your normal path, **`reveal` should be the exception** — prefer
brokered sessions so the secret is never shown.

### Rotation & reconciliation (credential lifecycle)

pamv1 can change the password **on the target** and re-vault it, so the account's
secret is one only pamv1 knows — and can prove is current. Rotation and
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

**Discovery.** Probe hosts for reachable management ports and optionally onboard
them (reachability only — no credentials are tried):

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/discovery/scan \
  -d '{"hosts":["10.0.0.5","10.0.0.6"],"ports":[22,3389,5986],"create":true}'
# → {"candidates":[{"host":"10.0.0.5","port":22,"protocol":"ssh",...}],"created":[...]}
```

### Zero Standing Privilege: ephemeral SSH certificates (Phase 22)

Instead of storing a password or key for an account, pamv1 can sign a
**short-lived SSH certificate just-in-time** for each session. The account then
has **no standing secret at all** — the target trusts only the pamv1 CA, and each
certificate is minted fresh and expires in minutes (the Teleport / CyberArk ZSP
model). Enable it by giving pamv1 a persistent CA key path:

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

### Windows targets (WinRM)

Create a Windows target (`os_type=windows`, `protocol=winrm`, port `5986` for
HTTPS) with a credential (an AD-joined domain account like `CONTOSO\\svc-admin`
works). Users with the connect capability run commands through pamv1 — the
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

pamv1 brokers RDP through [Apache Guacamole](https://guacamole.apache.org/)'s
`guacd` daemon so the operator sees the desktop but never the password — pamv1 is
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

### Dependent accounts: safe service-account rotation (Phase 17)

When a service account's password rotates, the **Windows Services, Scheduled
Tasks and IIS App Pools** that log on with it must be updated too — otherwise
rotation breaks production. Declare those consumers and pamv1 updates each over
WinRM after the rotation:

```bash
curl -H "X-API-Key: $PAM_API_KEY" -X POST http://localhost:8080/api/credentials/3/dependencies \
  -d '{"kind":"windows_service","host":"app-01","name":"MyAppSvc","management_credential_id":7}'
# kinds: windows_service | scheduled_task | iis_apppool ; port defaults to 5985 (WinRM)
```

On the next rotation of credential 3, pamv1 sets the new password on the target,
re-vaults it, then runs the appropriate WinRM command on each consumer's host
(`sc.exe config` / `schtasks /Change /RP` / `appcmd …processModel.password`) with
the new secret. A propagation failure is audited (`credential.dependency_failed`)
but does **not** fail the rotation — the new secret is already vaulted, so the
fix is to update the stale consumer, not to roll back.

**Which account does the updating (Phase 61).** `management_credential_id` names
the credential pamv1 **logs into that host as** to make the change. Set it.
Without it, pamv1 connects as the service account it is rotating, which means
that account needs remote-management and local-administrator rights on the
consumer's host — the opposite of what a service account should hold, and
hardened ones usually cannot log on remotely at all, so propagation fails
exactly where you need it. It also leaves nothing to stand on when you are
rotating *because* the account is broken.

- The credential is decrypted just-in-time, like every other use, and the audit
  records which one was used (`managed_via:credential:7`) — never its secret.
- An id that names no credential is refused **when you declare the dependency**
  (422), not silently at 3am during an unattended rotation.
- **Naming a credential here is a use of it (Phase 61a).** pamv1 will present
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
credentials pamv1 binds with. It is deliberately *not* overridable from the
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

**Identity reconciliation.** With LDAP configured, revoke pamv1 access for users
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
pamv1 uses the OAuth2 **resource-owner-password** grant against your tenant and
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
pamv1 tries each (chain). **Caveats:** ROPC does not trigger Entra Conditional
Access or IdP-side MFA — layer pamv1's own TOTP MFA on top; the OIDC auth-code
flow is the production-recommended upgrade (roadmap). Always use HTTPS.

### OIDC single sign-on (recommended for Entra)

The **Authorization Code + PKCE** flow is the production-grade alternative to
ROPC: the user authenticates *at the IdP* (so its MFA and Conditional Access
apply) and pamv1 validates the returned ID token's **RS256 signature** against
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
the callback issues a pamv1 session and returns to the portal. Note: pamv1's own
TOTP is not layered on OIDC (the IdP owns MFA there). The OIDC login state is
held in a shared store (Phase 10), so the callback can land on any replica in HA.

### Multi-factor authentication (TOTP)

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

**Require MFA for everyone:** set `PAM_MFA_REQUIRED=true`. Then a password login by
a user without confirmed MFA returns an **enrollment-only** session — it can *only*
call the `/api/mfa/*` endpoints (everything else, including the SSH proxy, is
refused) until the user enrolls and confirms, then logs in again with a code.

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
denied). Conditions match an argument's value exactly, and since Phase 30 also support `not`, `in`, `not_in` and the numeric comparators `gt`, `gte`, `lt`, `lte` (`in`/`not_in` are a set membership, i.e. an OR). No regex:

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
  - id: never-reveal
    tool: reveal_credential
    effect: deny            # reveal_credential ships default-deny anyway
```

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
collects the result once via its resume token. A call whose agent key was revoked —
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

For SPIFFE JWT-SVID agents and RFC 8693 delegation, set `PAM_BROKER_TRUST_DOMAIN`,
`PAM_BROKER_TRUST_DOMAIN_JWKS`, and `PAM_BROKER_AUDIENCE`; delegation depth is
capped by `PAM_BROKER_MAX_DELEGATION_DEPTH`.

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

`GET /v1/token/jwks` (needs `read_audit`) publishes the signing key, so an
auditor holding a delegated token from the trail can confirm which key signed it.

### Application-secrets API (Phase 24, Tier-4)

For a **non-agent application** (a CI job, a legacy service) that just needs to
fetch a secret at startup — not an operator through the proxy, not the AI-agent
tool broker — pamv1 offers a **Conjur-style** delivery path. It is **opt-in** and
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

pamv1 produces **two** independent streams — keep them both:

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
matrix and the Art. 23 reporting workflow.

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
continuously rather than exporting on demand, point pamv1 at a syslog/CEF
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
- Files are written once (`O_EXCL`, mode `0400`) and never overwritten. pamv1
  can't make your storage immutable — that's the mount — but it will not replace
  an archived artifact.
- **With the HMAC chain on you now still get the scheduled export**; only the
  delete stays manual (re-anchor the chain, then reclaim the space).

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
- **You lose direct `asciinema` playback** of the raw `.cast`; replay through pamv1
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
  bytes cross the proxy), and any `SSH_FXP_EXTENDED` operation pamv1 does not
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
campaign **snapshots the current access grants** — every target grant and every
safe member — into reviewable items; you then certify (keep) or revoke each, and
a **revoke actually removes the underlying grant**.

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
pamv1 opens a fresh campaign with the same name and scope, snapshotting access as
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
and nothing happens until an auditor asks. Set a **due date** and pamv1 nudges.

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

### 9.7 Privileged threat analytics (Phase 23)

pamv1 scores the audit trail into **behavioral risk** per actor, so a supervisor
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
is an **external ingester's** job; pamv1 ships the engine, not the collector.

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
| 2026-08-06 | **Phase 60a — the ticket re-check no longer misfires when you hold more than one approval.** With `PAM_TICKET_REVALIDATE=true`, each live approval for the target is now checked in turn and the one admitted is the one whose ticket passed. Before, a second concurrent connection could be let in on an approval whose change had been cancelled (its ticket was never put to the ITSM at all), and one cancelled change could block a valid approval behind it for the rest of the window. Up to 8 approvals are considered and the whole walk shares the same 5-second ITSM budget. Nothing to configure. See §9.5 |
| 2026-08-06 | **Phase 61a — naming a management credential now takes the same authorization as revealing it.** Declaring a dependent account with `management_credential_id` makes pamv1 present that password to the host on the same request, so it now requires `reveal_secret`, a grant on that credential's **own** target, an approved access request where that target needs one, and an in-contract vendor grant for a vendor — refusals audited as `dependency.create_denied`. It also must be a **password**: an SSH key or a zero-standing-privilege credential is refused, at declaration and again at use. Nothing changes for an administrator who was already entitled to the credential they name. See §7 |
| 2026-08-02 | **Phase 61 — say which account updates a dependent service.** Declaring a dependent account (a Windows service, scheduled task or app pool) now takes an optional **management credential**: the account pamv1 logs into that host as in order to reconfigure the consumer. Until now it logged in as the service account it was rotating, which needs administrator rights on the host — and hardened service accounts usually cannot log on remotely at all, so propagation failed there. *Work with Dependent Accounts* shows a **Managed via** column; anything reading `this account` in amber is still on the old path. If the credential you name is later deleted, the update fails closed and says so rather than falling back. See §7 |
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
