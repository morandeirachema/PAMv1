# pamv1 — System Requirements & Run Specs

> **Living document.** Update when a version floor, port, or resource spec changes.
>
> Last updated: 2026-08-18 · Reflects: Phases 0–176. Phases 161–173 add no requirement: two additive migrations applied at startup (`0044`, `0045`) on the PostgreSQL instance already required, three optional knobs (`PAM_BROKER_MAX_RESULT_BYTES` from 165, `PAM_BROKER_BUDGET_PER_DAY` from 167, `PAM_BROKER_REQUIRE_ENROLLED_SVID` from 174), and no new dependency, listener or external system. Phases 66–70 add one more
> background worker (the hourly, leader-locked certification scheduler); Phase 78
> adds an optional per-replica Conjur refresh worker (off unless
> `PAM_CONJUR_REFRESH_MIN` is set); 71–94 add no port, resource floor or
> dependency beyond that. Phase 116 adds two env vars
> (`PAM_SESSION_SHARE_INVITE_TTL_SEC`, `PAM_SESSION_SHARE_GUEST_TTL_MIN`) and,
> likewise, no port, resource floor or dependency. Phase 118 adds none of
> those either — the CIDR allowlist is per-user data (`users.ip_allowlist`),
> not configuration; no new env var, port, resource floor or dependency.
> **Phase 120 adds one more background worker** (`RunAccessRequestScheduler`
> — hourly, leader-locked, same shape as the certification scheduler, always
> on) and seven env vars (`PAM_PASSWORD_MIN_LENGTH`/`_MIN_LOWER`/`_MIN_UPPER`/
> `_MIN_DIGIT`/`_MIN_SYMBOL`/`PAM_PASSWORD_HISTORY_COUNT`/
> `PAM_CHECKOUT_MAX_EXTEND_MIN`) — no new port or resource floor. **Phase 122
> adds none of that** — no new worker, no new env var, no new port or
> resource floor; suspend/resume gates an in-memory registry already held by
> the process. **Phase 124 adds two env vars** (`PAM_WEBAUTHN_RP_ID`,
> `PAM_WEBAUTHN_RP_ORIGIN` — presence enables the feature, the same idiom as
> OIDC) and one new dependency (`github.com/go-webauthn/webauthn`); no new
> port, worker or resource floor. **Phase 126 adds none of that
> either** — the color-theme cycle is a client-side `localStorage`
> preference; no new env var, port, worker or resource floor.
> **Phase 128 adds none of that either** — one new route, no new
> worker or resource floor beyond the target dial its own credential
> already makes.
> **Phase 129 adds none of that either** — Zero Standing Privilege for
> PostgreSQL rides the existing `:5433` listener, no new port or worker;
> a db_zsp connect makes one extra short-lived dial to provision/tear
> down its ephemeral role, not a standing resource cost.
> **Phase 131 adds one env var** (`PAM_COMMAND_ALLOW_FILE`, mirroring
> `PAM_COMMAND_DENY_FILE`'s own load-once-at-startup shape) — no new
> port, worker or resource floor.
> **Phase 133 adds two env vars** (`PAM_POSTURE_ATTEST_URL`,
> `PAM_DEVICE_HEADER`) — no new worker or resource floor; a posture
> check is one extra outbound webhook call per connect/authenticated
> call when configured, not a standing cost.
> **Phase 135 adds no env var, worker or resource floor at all** —
> DoubleLock is two new REST routes and a PBKDF2 key derivation on the
> existing `:8080` listener, no new dependency, no new outbound call.
> **Phase 137 adds one env var** (`PAM_APPROVAL_INVITE_TTL_MIN`, default
> 1440) and no new worker, port or resource floor — magic-link approval
> rides the existing `:8080` listener and the email path Phase 116 already
> requires (see [EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md)); session
> watermarking is a client-side overlay plus an in-process `Hub.Publish`
> banner, no new dependency of any kind.
> **Phase 139 adds no env var, worker, port or resource floor at all** —
> the personal-safe check is a capability comparison and one extra `GetSafe`
> read on an already-open store connection, no new dependency, no new
> outbound call.
> **Phase 141 adds one env var** (`PAM_SSH_PORT_FORWARD`, default true) and
> no new worker, port or resource floor — a forward is one more dial on the
> connection the session already holds open, not a standing cost.
> **Phase 143 adds one env var** (`PAM_ICAP_URL`, off by default) and no new
> worker, listening port or memory floor on `pam-server` itself — like the
> ITSM/vendor/posture webhooks before it, turning it on adds a real optional
> external dependency: a genuine ICAP-speaking AV/DLP gateway (c-icap or a
> commercial equivalent), which you must supply and reach on `1344` (default).
> Off, this requirement does not apply.
> **Phase 145 adds one env var** (`PAM_CREDENTIAL_FILE_MAX_KB`, default 1024,
> max 10240) and no new worker, port or external dependency — a file-attachment
> secret is capped in KB, not MB, so its per-request memory footprint stays
> well inside the resource requests already sized for this workload.
> **Phase 147 adds one env var** (`PAM_EXTENSION_TOKEN_TTL_HOURS`, default 24,
> range 1–720) and no new worker, port or resource floor — an extension token
> is one more row in the existing `sessions` table, not a standing cost; the
> only new runtime dependency is the browser extension itself, which is not
> part of `pam-server` and has no server-side resource footprint.
> **Phase 149 adds one env var** (`PAM_SCIM_ENABLED`, default off) and no
> new worker, port or resource floor — SCIM is an inbound REST surface on
> the existing `:8080` listener; the only new runtime dependency, when
> enabled, is a SCIM-speaking IdP to push requests from, which you must
> supply.
> **Phase 151 adds twelve env vars** (`PAM_SAML_SP_URL` enables; `_IDP_METADATA_URL`/`_FILE`,
> `_SP_ENTITY_ID`, `_SP_KEY_FILE`/`_SP_CERT_FILE`, `_NAME_ATTR`, `_GROUP_ATTR`,
> `_ROLE_ADMIN`/`_USER`/`_AUDITOR`/`_APPROVER`) and no new worker, port or
> resource floor — the SAML SP is three routes on the existing `:8080`, and
> the only outbound call is one metadata fetch at startup/hot-swap (none with
> the `_FILE` form). The runtime dependency, when enabled, is a SAML 2.0 IdP
> (AD FS, Okta, OneLogin, an Entra SAML app) that you must supply and
> register pamv1's SP metadata with. Three new Go dependencies
> (`crewjam/saml`, `russellhaering/goxmldsig`, `beevik/etree`) are compiled
> in — no runtime library, no CGO.
> **Phase 153 adds one env var** (`PAM_ENDPOINT_AGENTS_ENABLED`, default off), one
> migration (`0042`, `endpoint_agents`), no new listener or port on pam-server, and
> a **second deployable binary**, `pam-agent` (static, CGO-free, ~10 MB, linux
> amd64/arm64 from the Release assets or `go build ./cmd/pam-agent`) that runs ON
> each unreachable endpoint — configured by `PAM_AGENT_SERVERS`/`_NAME`/`_KEY`/
> `_LOCAL_ADDR`/`_SERVER_HOST_KEY`, needing only outbound TCP to pam-server:2222 and
> a few MB of RAM per tunnel. On pam-server each connected agent is one idle SSH
> connection (goroutine + keepalive every 30 s) — the resource floor is unchanged
> for deployments that leave the flag off, and negligible per agent when on. In HA
> the agent holds one connection per listed replica.
> **Phase 155 adds four env vars** (`PAM_K8S_CA_FILE`, `PAM_K8S_INSECURE_SKIP_VERIFY`,
> `PAM_K8S_TIMEOUT_SEC`, `PAM_K8S_MAX_RESPONSE_KB`), no migration, no new
> listener, no worker and no new Go dependency — the Kubernetes client is
> hand-rolled on the standard library. A brokered operation is one outbound
> HTTPS request whose response is capped (1 MiB by default), so the memory
> floor is unchanged; the runtime dependency, when used, is a reachable
> cluster API server on `:6443` and a service-account token you supply.
> **Phase 157 adds three env vars** (`PAM_SESSION_FORENSICS`, `_MAX_EVENTS`,
> `_TIMEOUT_SEC`), no migration, no listener, no worker and no new Go
> dependency. When enabled it costs ONE extra short SSH connection per
> interactive session (bounded by `_TIMEOUT_SEC`) and one artifact per session
> in `PAM_RECORDING_DIR` — a few KB each, capped by `_MAX_EVENTS`, so budget
> recording storage accordingly. It requires the TARGET to run `auditd` with
> exec auditing and the vaulted credential to be able to read its log; without
> that pamv1 records the finding rather than failing.

> ⚠️ **Beta · for learning purposes. Not production, not externally audited.** These are the
> specs to *run* pamv1 in Docker and Kubernetes, plus rough sizing. Validate
> against your own load.

## At a glance

| Component | Requirement |
|---|---|
| Build toolchain | Go **1.26+** (only to build from source) |
| Container image | `gcr.io/distroless/static-debian12:nonroot` — runs as non-root UID **65532**, read-only root FS, no shell. (HSM/PKCS#11 KEK uses `Dockerfile.pkcs11`: cgo + glibc `distroless/base`, still non-root.) |
| Database | **PostgreSQL 14+** (compose ships **17**); TLS strongly recommended (`sslmode=verify-full`) |
| Ports | **8080** portal + REST API (HTTP or native HTTPS) · **2222** SSH session proxy · **5433** PostgreSQL session proxy (off by default) · **1433** SQL Server session proxy (off by default) |
| Docker | Engine **24+**, Compose **v2** |
| Kubernetes | **1.25+** (restricted Pod Security Standard); optional Prometheus Operator for the ServiceMonitor |
| Architectures | linux/amd64, linux/arm64 |

## Ports & protocols

| Port | Purpose | Notes |
|---|---|---|
| 8080/tcp | Portal + REST API | HTTP, or TLS 1.2+ when `PAM_TLS_CERT`/`PAM_TLS_KEY` are set. Front with an HTTPS ingress otherwise. `/metrics`, `/healthz`, `/readyz` live here. |
| 2222/tcp | SSH session proxy | Operators `ssh -p 2222 <cred>@<target>@host`. Set `PAM_SSH_ADDR=off` to disable. |
| 5433/tcp | PostgreSQL session proxy | Operators `psql "host=... port=5433 user=<cred>@<target> dbname=..."`. Enable with `PAM_DB_ADDR` (off by default). |
| 1433/tcp | SQL Server session proxy | Operators `sqlcmd -S host,1433 -U '<cred>@<target>' -P "$PAM_TOKEN"`. Enable with `PAM_MSSQL_ADDR` (off by default); set `PAM_TLS_CERT/KEY` — TDS clients require encryption. |
| 5900/tcp | Outbound — guacd to VNC targets | **guacd**, not pam-server, makes this connection (plaintext RFB; see [PROTOCOLS-AND-CRYPTO.md](PROTOCOLS-AND-CRYPTO.md) §3.5). |
| 636/5986/4822/5432 | Outbound to targets/IdP | LDAPS to AD, WinRM-HTTPS, **guacd on 4822** (it is *guacd*, not pam-server, that then reaches RDP on 3389), PostgreSQL to `postgres` targets — **egress** from pamv1, not listeners. See [PORTS-AND-FLOWS.md](PORTS-AND-FLOWS.md). |

## Prerequisites (secrets)

Generate before first run (see the [Admin Guide](ADMIN-GUIDE.md#31-generate-the-secrets-first)):

- `PAM_MASTER_KEY` — `./pam-server -genkey` (or use a KMS-backed KEK).
- `PAM_API_KEY` — the bootstrap admin key.
- `PAM_DATABASE_URL` — `postgres://…?sslmode=verify-full` (or `memory` for the demo).
- Optional: `PAM_BREAK_GLASS_KEY_HASH` (`-hashkey`), TLS cert/key, the audit-chain keys `PAM_AUDIT_HMAC_KEY` + `PAM_AUDIT_SIGN_SEED` (base64 32 bytes each, `openssl rand -base64 32`), OIDC/LDAP/Entra config.

## Virtual appliance (OVA)

A single importable VM — Debian 13 (trixie), PostgreSQL, `pam-server` and the full
source tree — built by `deploy/ova/build.sh`. See
[deploy/ova/README.md](../deploy/ova/README.md).

| | Requirement |
|---|---|
| To **build** it | QEMU (`qemu-system-x86_64`, `qemu-img`), `xorriso`, `curl`, `tar`, Go 1.26+. No root, no VirtualBox, no Packer. KVM optional but ~5× faster |
| To **run** it | VirtualBox 7.x, VMware Workstation/Fusion, or ESXi. 2 vCPU, 2048 MiB, ~4 GiB disk (20 GiB sparse) |
| Ports in the guest | 8080 portal/API · 2222 SSH session proxy · 22 appliance administration |
| Not included | guacd (so the RDP/VNC viewers are inactive), a Go toolchain, TLS certificates |

Secrets are **not** baked in: the vault master key, admin API key, PostgreSQL
password, SSH host keys and machine-id are generated on first boot, so cloning the
OVA never clones a root of trust.

## Docker / docker-compose

Minimums: Docker Engine 24+, Compose v2. The bundled `deploy/docker/docker-compose.yml`
runs **four** services: a hardened PostgreSQL 17 (scram-sha-256), a `pam-init`
one-shot that takes ownership of `/data` for UID 65532, an internal-only `guacd`
(so RDP brokering works out of the box), and pam-server. Budget for guacd as well
as pam-server when sizing.

```bash
cd deploy/docker
cp .env.example .env      # fill PAM_MASTER_KEY, PAM_API_KEY, POSTGRES_PASSWORD
docker compose up --build
```

Container resource guidance (per pam-server instance):

| | CPU | Memory |
|---|---|---|
| Request / idle | 50m | 64 MiB |
| Limit / small prod | 500m | 256 MiB |

Volumes:

- pam-server `/data` — session recordings, and an on-disk mirror of the SSH host
  key. Since Phase 42 the host key and the ZSP CA key are held in the database
  under shared custody, so losing `/data` no longer changes the host key
  operators see; recordings are the reason to persist it.
- **`PAM_RETENTION_ARCHIVE_DIR`, if set, needs its own volume** — separate from
  `/data`, and genuinely write-once if the archive is to mean anything. The
  retention sweep moves aged recordings there and writes aged audit rows as
  digest-stamped JSON Lines; a backup scoped only to `/data` loses them.
- PostgreSQL `/var/lib/postgresql/data` — the database (a named volume/PVC).

The image has **no shell** and runs read-only as non-root; write paths are limited
to the mounted `/data` volume.

## Kubernetes

Requires **1.25+** for the restricted [Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
the manifests/chart assume. Two paths:

```bash
# Raw manifests — copy the two *.example.yaml files first and edit them; do NOT
# `kubectl apply -f deploy/k8s/` wholesale, or you apply the CHANGE_ME examples.
cd deploy/k8s
cp secret.example.yaml    secret.yaml       # keys and credentials
cp configmap.example.yaml configmap.yaml    # non-secret PAM_* knobs (optional)
kubectl apply -f namespace.yaml -f postgres-cnpg.yaml
kubectl apply -f secret.yaml -f configmap.yaml
kubectl apply -f deployment.yaml -f service.yaml

# Or Helm (deploy/helm/pamv1)
helm install pamv1 deploy/helm/pamv1 \
  --set secret.data.PAM_MASTER_KEY=... \
  --set secret.data.PAM_API_KEY=... \
  --set secret.data.PAM_DATABASE_URL='postgres://...?sslmode=verify-full'
```

The two example files are the Kubernetes twin of `deploy/docker/.env.example` —
the same variables, split by whether the value is a secret. See
[deploy/k8s/README.md](../deploy/k8s/README.md) for the full file map and the
three ways Kubernetes configuration differs from the Docker path.

Pod spec (defaults in `deploy/k8s/deployment.yaml` and the chart):

- **Security context:** `runAsNonRoot`, `readOnlyRootFilesystem`, all capabilities
  dropped, `seccompProfile: RuntimeDefault`, `automountServiceAccountToken: false`.
- **Resources:** requests `cpu: 50m`, `memory: 64Mi`; limit `memory: 256Mi`.
- **Probes:** liveness `GET /healthz`, readiness `GET /readyz` (returns 503 until
  the database is reachable — gate Service traffic on it).
- **Storage:** `/data` is `emptyDir` by default; set `persistence.enabled=true`
  (chart) or swap in a PVC to retain recordings + host key. **RWO** is sufficient
  for a single writer.
- **Metrics:** scrape `GET /metrics` (pod annotations are set; enable
  `metrics.serviceMonitor.enabled=true` with the Prometheus Operator).
- **TLS:** terminate at the Ingress, or set `PAM_TLS_CERT`/`PAM_TLS_KEY` for native
  HTTPS. Expose 2222 via a `LoadBalancer`/`NodePort` Service if operators need the
  SSH proxy from outside the cluster.

**PostgreSQL:** run 14+ with TLS. For HA use an operator such as
[CloudNativePG](https://cloudnative-pg.io/). Migrations apply automatically on
pam-server startup.

**Scaling / HA:** the server is stateless enough to run multiple replicas —
**OIDC login state is shared via the database**, so the auth-code callback can
land on any replica. Since Phase 42 the **SSH host key and the ZSP CA key** are
held in shared custody in the database rather than generated per pod, so a scaled
deployment no longer hands out a different host key and a different certificate
authority per replica. Session **termination** is cluster-wide over Postgres
`LISTEN/NOTIFY` (Phase 34), and since Phase 55 so are session **listing and live
watching**: `GET /api/sessions` merges a shared, heartbeat-refreshed inventory
(each row naming its hosting replica; a crashed replica's rows age out in ~45s),
and `GET /api/sessions/{id}/stream` reaches a session hosted on any replica —
the hosting pod relays a watched session's output over the store bus, and only
while someone is actually watching. The retention, SIEM-forwarding, analytics
and lifecycle workers each run on exactly one replica behind a Postgres advisory
leader lock.

Three things remain per-replica: the auth **rate-limiter**
(best-effort; slightly looser limits across N replicas, acceptable), the
**break-glass quorum-unseal shares** (kept in memory *by design* — persisting key
shares to the DB would weaken the offline-shares guarantee), and the
`PAM_MAX_SESSIONS_PER_USER` / `_TOTAL` caps (deliberately: a cluster cap derived
from advisory inventory rows could refuse sessions on stale data). In-session
**step-up decisions** cross replicas since Phase 56 (the pending list is
cluster-wide and a decision posted anywhere is dispatched, sealed, to the
replica holding the pause). For the unseal flow,
submit all shares to one replica (a sticky session, or scale to 1 during an
emergency). All other operations (proxy, WinRM, RDP, rotation, reveal, approval,
checkout) are safe across replicas.

## Sizing (rough)

| Scale | pam-server | PostgreSQL |
|---|---|---|
| Demo / lab | 1 replica, 64–128 MiB | `memory` store or 1 small instance |
| Small team | 1–2 replicas, 256 MiB, 250m | 1 vCPU / 1–2 GiB, 10–20 GiB disk |
| Recording-heavy | add disk for `/data` (asciicast files grow with session volume) | — |

Session recordings dominate disk growth; budget storage for `PAM_RECORDING_DIR`
and rotate/archive it per your retention policy (see [NIS2-COMPLIANCE.md](NIS2-COMPLIANCE.md#3-audit-retention--siem-forwarding)).

---

*See also: [ADMIN-GUIDE.md](ADMIN-GUIDE.md), [PORTS-AND-FLOWS.md](PORTS-AND-FLOWS.md), [ARCHITECTURE-HIGH-LEVEL.md](ARCHITECTURE-HIGH-LEVEL.md).*
