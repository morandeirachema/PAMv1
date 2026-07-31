# Changelog

All notable released changes to pamv1 are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) with 0.x semantics — breaking
changes may land in minor versions until 1.0.

pamv1 is built phase by phase, and the full per-phase history — what shipped in
each phase, in what order, and why — lives in [ROADMAP.md](ROADMAP.md). This
file records **releases**: the tagged, signed points you can actually deploy.

## [Unreleased]

- **Safe-scoped approval policy** (Phase 58) — a safe now carries
  `require_approval` and a dual-control `min_approvers` floor that bind **every
  target in it**, strictest-wins with the global and per-target settings (a safe
  can tighten them, never loosen). The floor is re-read as each approval is cast,
  so raising it binds requests already in flight. The predicate deciding all of
  this moved into one shared fold (`store.EffectiveApprovalPolicy`) consulted by
  the API, all three session proxies and the RDP viewer. Migration `0027`; no new
  environment variable.

- **RFC 8693 token-exchange minting + Terraform remediation** (Phase 57) — the
  agent broker now **issues** the delegated identities it had only ever verified:
  `POST /v1/token` (opt-in, `PAM_BROKER_TOKEN_EXCHANGE`) lets an SVID-authenticated
  agent delegate its own authority to a sub-agent and returns a broker-signed,
  short-lived JWT-SVID whose actor chain grows by exactly one link, capped by the
  delegator's own expiry and the existing delegation-depth limit. Impersonation,
  `scope`, a foreign audience and an actor outside the delegator's `may_act` are
  all refused. `GET /v1/token/jwks` publishes the signing key (shared custody).
  Separately, `POST /api/blast/analyze` with `"terraform": true` renders each
  finding's remediation as reviewable HCL. No schema change.

- **Cross-replica step-up decisions** (Phase 56) — the pending-pause list is
  cluster-wide (`GET /api/sessions/stepups` merges a shared, TTL-bounded
  inventory whose statements rest sealed under the shared-custody bus key) and
  `POST /api/sessions/{id}/stepup` decides a statement paused on any replica: a
  decision landing on the "wrong" pod is dispatched, sealed and freshness-bound,
  over the store bus and answers `202 Accepted`. Self-approval is refused across
  replicas. Migration `0026` (UNLOGGED `stepups`); no new environment variable.

- **Virtual appliance** (`deploy/ova/`) — `build.sh` produces an importable `.ova`
  carrying Debian 13 (trixie), PostgreSQL, `pam-server` and the full source tree.
  It runs an unattended `debian-installer` under QEMU and assembles the OVA by
  hand, so it needs no root, no VirtualBox and no Packer; the build verifies
  itself by booting the finished image on a throwaway overlay and asking pamv1 for
  `/healthz`. No secret is baked into the image — the vault master key, admin API
  key, database password, SSH host keys and machine-id are all generated on first
  boot, so cloning the appliance never clones a root of trust.

- **Kubernetes configuration examples** — `deploy/k8s/configmap.example.yaml`
  (every non-secret `PAM_*` knob) and a `secret.example.yaml` grown to all
  secret-valued variables, giving the Kubernetes path the reference
  `deploy/docker/.env.example` already gave Docker.

- **Cross-replica live monitoring** (Phase 55) — in a multi-replica deployment,
  `GET /api/sessions` now lists every replica's sessions (each naming its host)
  and the SSE watch streams a session hosted on any replica: the hosting pod
  relays a watched session's output over the store's LISTEN/NOTIFY bus, only
  while someone is actually watching. A crashed replica's sessions age out of
  the listing and close their remote watch streams instead of hanging them.
  New `live_sessions` table (migration 0025); no new configuration. Step-up
  decisions remain with the hosting replica (documented).

- **VNC connector** (Phase 54) — `vnc` is a first-class target protocol,
  brokered through guacd and rendered in the portal by the same viewer as RDP
  (`POST /api/vnc-token`, `GET /api/targets/{id}/vnc`). Both viewers now share
  one tunnel implementation, so every authorization gate is executed once for
  both. The clipboard gate covers VNC, VNC's SFTP file channel is forced off,
  and a clipboard policy guacd cannot enforce now refuses the session instead of
  running ungated (this also protects RDP).

- **SQL Server session proxy** (Phase 53) — `PAM_MSSQL_ADDR` brokers `mssql`
  targets over TDS the way `PAM_DB_ADDR` brokers PostgreSQL: the same
  authorization gates, the vaulted SQL login injected just-in-time into the
  client's own LOGIN7, per-statement `db.query` audit (`via:mssql`) that sees
  through `sp_executesql`, command control, step-up, recording, live monitoring
  and cluster-wide kill. New hand-rolled `internal/tds` codec (no new
  dependency) with TLS on both legs. Interop with a real SQL Server is not yet
  verified.

- **Review fixes on the four changes below** — broker audit keys: an explicit
  env value is written through to shared custody and checked against it, so a
  mixed fleet or a later unset can no longer silently fork the audit chain (a
  disagreeing HMAC key refuses to start; a disagreeing sign seed is the signer
  rotation and custody converges to it). WinRM: the recording size cap now ends
  the session with `session.record_limit` (parity with SSH) instead of running
  it unrecorded with a frozen live stream; REST/broker run output reaches live
  watchers only after the durable audit; refusals are visible on the stream and
  leave transcripts. Broker `ssh_exec` streams live like `winrm_exec`. A
  non-canonical per-target clipboard value now enforces as `deny` (fail closed)
  and the overrides are audited on `target.create`/`target.update` (a PUT that
  omits them resets them — now visibly). The live-watch 404 is replica-honest
  and audited; the portal watch pane no longer renders a literal `\r` on every
  line.
- **The watch stream ends with the session** — a supervisor's live SSE watch
  now terminates when the watched session completes or is killed (the portal
  pane reports "session ended" instead of going silent forever), and watching
  an unknown or already-over session id is refused with 404.
- **Per-target RDP clipboard override** (Phase 33 follow-on) — a target's
  `rdp_clipboard` / `rdp_clipboard_audit` fields tighten the global
  `PAM_RDP_CLIPBOARD` / `_AUDIT` for that one target; the stricter policy
  always wins, so a high-sensitivity target can deny what the fleet allows.
  New migration `0024`; editable from the 5250 target screens.
- **WinRM live streaming** (Phase 16 follow-on) — a supervisor can now watch a
  WinRM session live (`GET /api/sessions/{id}/stream`, portal option 5) exactly
  like an SSH or PostgreSQL one: the proxy's interactive shell streams what its
  recording sees, and REST/agent-broker runs stream a `winrm>` command echo
  plus the output.
- **Broker audit keys under shared custody** (Phase 13 follow-on) —
  `PAM_BROKER_AUDIT_KEY` and `PAM_BROKER_AUDIT_SIGN_SEED` are now optional:
  when unset, each is generated once and sealed by the KEK into the store's
  `key_material` (every replica converges on the same chain key and signer;
  `-rotate-kek` re-wraps them). An explicit environment value still wins.

## [0.10.0] — 2026-07-28

The first tagged release, closing the last of the README's four beta criteria
(*deploys as code*): the image every Kubernetes/Helm/Terraform manifest pins now
exists, is public, and is verifiable. Built by the test-gated release pipeline
with an SPDX SBOM attestation, a cosign keyless signature and SLSA build
provenance — see [Verifying a release](README.md#verifying-a-release).

Everything from phases 0–52g is in this release. The short version:

- **Vault** — AES-256-GCM envelope encryption per secret, wrapped by a
  pluggable KEK (local key / Vault Transit / AWS KMS / PKCS#11 HSM), with
  offline KEK rotation (`-rotate-kek`) that doubles as the provider-migration
  path.
- **Session brokering with just-in-time injection** — SSH (with recording,
  live monitoring, command control, SFTP policy), PostgreSQL (per-statement
  audit, in-session step-up), RDP in the portal via Guacamole (clipboard
  control + audit), WinRM; the requester never receives the credential.
- **Zero Standing Privilege** — ephemeral SSH certificates from a built-in CA
  instead of standing credentials.
- **Identity** — four built-in roles plus custom permission profiles; AD
  (LDAPS), Entra ID and OIDC login with group→role mapping; TOTP MFA;
  per-user tokens.
- **Governance** — approval workflows (4-eyes, quorum), safes, access
  certification campaigns, an ITSM ticket gate, vendor access with employment
  attestation, break-glass with M-of-N Shamir unseal.
- **AI-agent access broker** — policy over tool + arguments, JIT server-side
  execution, keyed-HMAC verifiable audit with signed checkpoints, MCP
  transport, SPIFFE SVID identity.
- **Audit** — append-only, optionally HMAC-chained and checkpoint-signed;
  OCSF/CEF/LEEF SIEM export and continuous forwarding; retention with
  archive-before-prune.
- **Operations** — the AS/400 5250 keyboard-first portal, Prometheus metrics,
  Helm chart / raw K8s / Terraform / docker-compose deployments, SOPS and
  Conjur secret sourcing, threat analytics with automated response.

[Unreleased]: https://github.com/morandeirachema/pamv1/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.10.0
