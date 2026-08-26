# Kubernetes (raw manifests)

Plain manifests for a namespaced PAMv1 install. For a parameterised install use
the Helm chart in [`../helm/pamv1`](../helm/pamv1) instead — it renders the same
shapes from `values.yaml`.

| File | What it is |
|---|---|
| `namespace.yaml` | The `PAMv1` namespace |
| `configmap.example.yaml` | **The env example.** Every non-secret `PAM_*` knob, grouped and commented. Copy to `configmap.yaml`, edit, apply |
| `secret.example.yaml` | Its secret half: keys, credentials and key-derived hashes. Copy to `secret.yaml` (git-ignored), or encrypt it in-repo with SOPS (`sops/`) |
| `deployment.yaml` | pam-server: non-root, read-only root FS, all capabilities dropped, `/healthz` + `/readyz` probes. Reads both files above via `envFrom` |
| `service.yaml` | ClusterIP for the portal/API (8080) and the SSH proxy (2222) |
| `postgres-cnpg.yaml` | A [CloudNativePG](https://cloudnative-pg.io/) cluster; `pamv1-pg-rw` always resolves to the current primary |
| `guacd.yaml` | The Guacamole proxy daemon behind the in-portal RDP and VNC viewers. Cluster-internal — never expose it |
| `networkpolicy.yaml` | Default-deny with explicit egress. **Scope the target CIDRs to your own networks before applying** |
| `sops/` | SOPS + age encryption of the Secret, so it can live encrypted in the IaC repo (Phase 14) |
| `conjur/` | Optional: source the bootstrap secrets from CyberArk Conjur at startup instead of a Kubernetes Secret (Phase 18) |

## Install

```bash
kubectl apply -f namespace.yaml
kubectl apply -f postgres-cnpg.yaml       # wait for the cluster to be ready

cp secret.example.yaml    secret.yaml     # fill the keys — see below
cp configmap.example.yaml configmap.yaml  # optional; every value has a default
kubectl apply -f secret.yaml -f configmap.yaml

kubectl apply -f guacd.yaml               # only if you want RDP/VNC
kubectl apply -f deployment.yaml -f service.yaml
kubectl -n PAMv1 port-forward svc/pamv1 8080:8080
```

Two of the required values have to be generated, not invented:

```bash
go run ./cmd/pam-server -genkey    # PAM_MASTER_KEY (32-byte urlsafe base64)
openssl rand -base64 24            # PAM_API_KEY — must be ≥16 chars on a real database
```

## Configuration, in two halves

`configmap.example.yaml` and `secret.example.yaml` are the Kubernetes twin of
[`../docker/.env.example`](../docker/.env.example): the same variables, split by
whether the value is a secret. Keep each variable in exactly one of the two — a
ConfigMap is stored and displayed in plaintext.

Three things behave differently here than in Docker, and each has bitten someone:

- **ConfigMap values are strings.** Quote everything, including numbers and
  booleans (`"0"`, `"false"`); an unquoted `true` is a YAML bool and the apply is
  rejected.
- **`deployment.yaml` sets three variables inline** — `PAM_SSH_HOST_KEY`,
  `PAM_RECORDING_DIR` and `PAM_GUACD_ADDR`. A container's `env` beats `envFrom`,
  so the ConfigMap cannot override them; change the Deployment.
- **A path-valued variable needs the file mounted.** The root filesystem is
  read-only and only `/data` is writable, so a deny file, a CA bundle or a JWKS
  has to arrive as its own ConfigMap or Secret volume. `configmap.example.yaml`
  carries a worked example.

The ConfigMap is referenced with `optional: true`, so the pod still starts if you
never create it — every value in it has a working default.

## What stays per-replica

Scaling past one replica is supported: OIDC login state is shared through the
database, the SSH host key and the ZSP CA key are held in shared custody, session
termination and — since Phase 55 — session listing and live watching are
cluster-wide, and the retention, SIEM-forwarding, analytics and lifecycle workers
each run on exactly one replica behind a Postgres advisory lock.

Three things remain per-replica, deliberately: the auth **rate limiter**
(best-effort), the break-glass **quorum-unseal shares** (kept in memory by
design — submit all shares to one replica, or scale to 1 during the emergency),
and the `PAM_MAX_SESSIONS_*` **caps**. **Recordings** are also written per-pod:
use a ReadWriteMany volume if you need one view across replicas. Full HA notes:
[docs/REQUIREMENTS.md](../../docs/REQUIREMENTS.md).

## Before this is anything but a lab

- Set `PAM_DATABASE_URL` to `sslmode=verify-full`. It is not only the database
  password on the wire: the store connection also carries the cross-replica
  live-monitoring relay, so watched-session output crosses it.
- Terminate TLS at an Ingress, or mount a certificate and set `PAM_TLS_CERT`,
  `PAM_TLS_KEY` and `PAM_REQUIRE_HTTPS` so a missing certificate is fatal rather
  than a silent plaintext downgrade.
- Narrow `networkpolicy.yaml`'s egress CIDRs to your real target networks.
- Prefer an external KEK (`PAM_KEK_PROVIDER=vault-transit|aws-kms|pkcs11`) so the
  wrapping key never enters the cluster.
- Enable the audit chain (`PAM_AUDIT_HMAC_KEY` + `PAM_AUDIT_SIGN_SEED`) and back
  those keys up as carefully as the KEK.
