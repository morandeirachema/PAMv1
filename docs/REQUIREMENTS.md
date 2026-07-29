# pamv1 — System Requirements & Run Specs

> **Living document.** Update when a version floor, port, or resource spec changes.
>
> Last updated: 2026-07-29 · Reflects: Phases 0–55.

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
# Raw manifests
kubectl apply -f deploy/k8s/

# Or Helm (deploy/helm/pamv1)
helm install pamv1 deploy/helm/pamv1 \
  --set secret.data.PAM_MASTER_KEY=... \
  --set secret.data.PAM_API_KEY=... \
  --set secret.data.PAM_DATABASE_URL='postgres://...?sslmode=verify-full'
```

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
**step-up decisions** are also decided on the replica hosting the session. For the unseal flow,
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
