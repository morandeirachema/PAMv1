# Changelog

All notable released changes to pamv1 are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) with 0.x semantics — breaking
changes may land in minor versions until 1.0.

pamv1 is built phase by phase, and the full per-phase history — what shipped in
each phase, in what order, and why — lives in [ROADMAP.md](ROADMAP.md). This
file records **releases**: the tagged, signed points you can actually deploy.

## [Unreleased]

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
