# Docker / docker-compose

The container build and the local full-stack demo. Kept here (not at the repo
root) to keep the root uncluttered; the build context is still the **repo root**.

| File | What it is |
|---|---|
| `Dockerfile` | The default image — `CGO_ENABLED=0`, static, `distroless/static`, non-root. The read-only root filesystem is applied at *run* time by compose (`read_only: true`), not baked into the image |
| `Dockerfile.pkcs11` | Optional image with the PKCS#11 **HSM KEK** provider (needs cgo + a glibc base) |
| `docker-compose.yml` | Local full stack: hardened PostgreSQL 17 (scram-sha-256), a `pam-init` volume-ownership one-shot, an internal-only `guacd` (so **RDP brokering works here too**) and pam-server |
| `.env.example` | **The env example.** Copy to `.env` and fill the keys before `docker compose up`. Every `PAM_*` variable, grouped and commented; the Kubernetes twin is [`../k8s/configmap.example.yaml`](../k8s/configmap.example.yaml) + [`secret.example.yaml`](../k8s/secret.example.yaml) |
| `docker-compose.rdp-demo.yml` | End-to-end **RDP viewer demo** — a real xrdp desktop + guacd + pam-server, target auto-seeded (see below) |
| `rdp-target/` | The demo's throwaway RDP target image (XFCE over xrdp). Demo only — never deploy |
| `docker-compose.vnc-demo.yml` | End-to-end **VNC viewer demo** — TigerVNC + XFCE behind guacd, target auto-seeded ([docs/VNC-TESTING.md](../../docs/VNC-TESTING.md)) |
| `vnc-target/` | The demo's throwaway VNC target image. Demo only — never deploy |

## Run the full stack

```bash
cd deploy/docker
cp .env.example .env      # fill PAM_MASTER_KEY, PAM_API_KEY, POSTGRES_PASSWORD
docker compose up --build
# → portal + REST API on http://localhost:8080, SSH proxy on :2222
```

Two of those three values have to be generated, not invented — compose fails
fast if they are missing, but it cannot tell you they are *wrong*:

```bash
go run ./cmd/pam-server -genkey      # PAM_MASTER_KEY (32-byte urlsafe base64)
openssl rand -base64 24              # PAM_API_KEY — must be ≥16 chars on a real database
```

The PostgreSQL session proxy (`PAM_DB_ADDR`, `:5433`) is **not** enabled in this
compose file, so nothing listens there even though `.env.example` documents the
variable. Set it and publish the port if you want to try `psql` through pamv1.

> **Two things that will refuse to start, or refuse a session, if you enable them
> here.** Both are deliberate fail-closed behaviour from Phase 52c/52d, and both
> are easy to hit in a demo:
> - `PAM_REQUIRE_RECORDING=true` now also covers the in-portal RDP viewer and the
>   REST WinRM endpoint. Neither compose file sets `PAM_GUACD_RECORDING_PATH`, so
>   enabling it without that will **refuse every RDP session**.
> - A deny file (`PAM_COMMAND_DENY_FILE`, `PAM_SSH_SFTP_DENY_FILE`,
>   `PAM_DB_STEPUP_FILE`) that yields no usable patterns is now a **fatal startup
>   error**, not a silently disabled control. Mounting an empty file stops the
>   server booting.

## Run the RDP viewer demo (see the pixels, no Windows host)

Brings up a real **xrdp Linux desktop** as an RDP target, guacd, and pam-server,
and auto-seeds the pamv1 target + credential — so you can watch a desktop render
through the in-portal viewer end to end.

```bash
cd deploy/docker
docker compose -f docker-compose.rdp-demo.yml up --build
# open http://localhost:8080
#   sign on: leave Password blank, enter the access token  demo-api-key-pamv1
#   Work with Targets → type 7 next to "demo-rdp" → Enter → an XFCE desktop renders
#   Ctrl+Alt+Q disconnects
```

**Demo only** — a throwaway master key, a weak API key, an in-memory store, and an
unhardened **root** xrdp target with a well-known password. Never deploy it. If the
desktop never paints, set `PAM_GUACD_RDP_SECURITY=rdp` on the `pam` service and
re-up. Full verification checklist: [docs/RDP-TESTING.md §4](../../docs/RDP-TESTING.md).

## Build the image directly (context = repo root)

```bash
# from the repo root:
docker build -f deploy/docker/Dockerfile -t pamv1 .
docker build -f deploy/docker/Dockerfile.pkcs11 -t pamv1:pkcs11 .   # HSM variant
```

The compose file sets `build.context: ../..` (the repo root) and
`build.dockerfile: deploy/docker/Dockerfile`, so `COPY . .` still copies the source
and honors the root `.dockerignore`. CI builds with
`docker build -f deploy/docker/Dockerfile .` and the release workflow passes
`file: ./deploy/docker/Dockerfile`.
