# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

pamv1 is an open-source Privileged Access Management (PAM) system in Go, built **phase by phase with the rule that every phase is fully functional end to end** (it runs, passes tests, and deploys as IaC). `ROADMAP.md` is the source of truth for phase order and status; it is a hard project constraint, not a wishlist. The repo is educational ("for learning purposes" — see `README.md`), not production-hardened.

Stack is fixed by project decision: **Go + PostgreSQL** (no SQLite). The management portal is a deliberately austere **AS/400 / IBM 5250 green-terminal** UI — do not "modernize" it.

## Commands

The `go` toolchain must be on `PATH` (this environment installs it under `~/.local/go/bin`; export it if `go` is not found). There is no Makefile — use raw Go tooling.

```bash
go build ./...                                   # build everything
go test ./...                                    # all tests
go test -race ./...                              # what CI runs
go test ./internal/proxy -run TestJITInjection -v   # a single test
gofmt -l .                                       # must print nothing (CI fails otherwise)
go vet ./...
staticcheck ./...                                # CI gate (go install honnef.co/go/tools/cmd/staticcheck@latest)
govulncheck ./...                                # CI gate (go install golang.org/x/vuln/cmd/govulncheck@latest)
gosec -confidence high -exclude=G104,G115,G306 ./...             # CI gate; deliberate findings carry `#nosec Gxxx -- reason` (G304 file reads + G101 are enforced, annotated per-site)
go run ./cmd/archgen                             # regenerates docs/ARCHITECTURE-DIAGRAMS.md; CI diffs it — run after route/store/schema changes
go mod tidy                                      # after changing imports
```

Run locally with no database (in-memory demo store):

```bash
go build ./cmd/pam-server
export PAM_MASTER_KEY=$(./pam-server -genkey)
export PAM_API_KEY=demo-key
export PAM_DATABASE_URL=memory
./pam-server      # portal+API on :8080, SSH proxy on :2222
```

`pam-server` utility flags (each does one job and exits): `-genkey` prints a new `PAM_MASTER_KEY`; `-hashkey` reads an emergency key on stdin and prints its SHA-256 for `PAM_BREAK_GLASS_KEY_HASH`; `-split-key` reads an emergency key on stdin and prints N Shamir shares; `-rotate-kek` re-encrypts every vaulted secret under a new KEK (any provider via `PAM_KEK_*`/`PAM_NEW_KEK_*`, so it is also the migration path) — run it offline; `-healthcheck` probes the local `/healthz` and exits 0 if healthy, which is what the container HEALTHCHECK uses.

Full stack (hardened Postgres + server): from `deploy/docker/`, `cp .env.example .env` (fill the keys), then `docker compose up --build`. The Docker/compose files live in `deploy/docker/` (`Dockerfile`, `Dockerfile.pkcs11`, `docker-compose.yml`, `.env.example`, plus `docker-compose.rdp-demo.yml` + `rdp-target/` — a throwaway xrdp desktop to demo the in-portal RDP viewer end to end); other deploy manifests live in `deploy/k8s/`, `deploy/helm/` and `deploy/terraform/` (all infra is IaC — do not hand-apply). `deploy/ova/` builds a **virtual appliance** (`build.sh`: an unattended Debian 13 install under QEMU, provisioned from `provision/`, packaged as an importable `.ova`) — it needs no root, VirtualBox or Packer, and bakes in **no secrets**: the vault key, admin key, DB password and SSH host keys are generated on first boot. The SOPS config is `deploy/.sops.yaml` (pass `--config deploy/.sops.yaml` when encrypting; decryption needs no config). The repo root keeps only `go.mod`/`go.sum`, `README*`, `ROADMAP.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`, `NOTICE`, `CLAUDE.md` and the two position-sensitive dotfiles `.dockerignore` and `.gitignore`; community/CI plumbing (CODEOWNERS, issue/PR templates, `dependabot.yml`, workflows) lives under `.github/`.

CI (`.github/workflows/ci.yml`) gates on: `gofmt -l`, `go vet`, `staticcheck`, `govulncheck`, `gosec`, `go build`, the `archgen` diagram drift check, and `go test -race -coverpkg=./...` — plus parallel jobs: the live-Postgres store suite (which also runs `cmd/pam-server`'s Postgres-gated tests), SoftHSM PKCS#11, a Docker image build, Helm lint + kubeconform manifest validation, and SOPS round-trip verification.

## Architecture

Single binary `cmd/pam-server` wires everything (a second, tiny deployable `cmd/pam-agent` — the outbound-only endpoint agent, Phase 153 — runs *on* unreachable targets and only dials in to the SSH proxy; `cmd/archgen` is a doc generator); packages under `internal/`:

- **`vault`** — at-rest secret crypto. `Encrypt(ctx, plaintext, aad)` → `"v2:"+base64(...)` envelope: a per-secret AES-256-GCM data key (random nonce per call) wrapped by a pluggable KEK (`local`/Vault-Transit/AWS-KMS/PKCS#11). The `"v2:"` prefix is a **versioned token format** for key rotation — preserve it.
- **`store`** — `Store` interface + domain types (`Target`, `Credential`, `AuditEvent`, …). Two implementations: `memstore` (tests/demo) and `pgstore` (Postgres via pgx, with embedded versioned migrations in `pgstore/migrations/` applied on startup). Sentinel errors `ErrNotFound`/`ErrConflict` map to HTTP/SSH errors upstream.
- **`api`** — REST (`http.ServeMux` method patterns) + the `auth` middleware, which accepts the `X-API-Key` **or** the break-glass key and sets an actor for audit.
- **`proxy`** — the session gateway and the heart of the system (Phase 2). Operator runs `ssh -p 2222 <creduser>@<target>@pam-host` with the PAM API key as the SSH password. The proxy authenticates, resolves the target's credential, **decrypts the secret just-in-time**, dials the real target injecting that secret, records the session (asciicast v2, SHA-256 into audit), and brokers I/O. The operator never sees the credential. The same package also brokers **PostgreSQL** (`dbproxy.go`, `:5433`, JIT injection + per-statement query audit, Phase 15), enforces **live monitoring** (Phase 16), and — when `PAM_ENDPOINT_AGENTS_ENABLED` — accepts **outbound-only endpoint agents** (`endpointagent.go`, Phase 153: an `endpoint-agent:<name>` login holding an RFC 4254 reverse tunnel that becomes a bound target's "dial"; the agent library is `internal/endpointagent`).
- **`cmdguard`** — the command denylist (`PAM_COMMAND_DENY_FILE`), compiled once in `main` and shared by both proxies *and* the API server, so the same policy covers every path where a discrete command is visible: SSH `exec`, the WinRM command loop, PostgreSQL statements, `POST /api/targets/{id}/winrm`, and the broker's `ssh_exec`/`winrm_exec` tools (Phases 16, 38). It is not a containment boundary — an interactive PTY is never parsed.
- **`web`** — the 5250-style portal, a single `//go:embed`ed `static/index.html` calling the REST API.
- **`config`** — all runtime config comes from `PAM_*` env vars (table in `docs/ARCHITECTURE-LOW-LEVEL.md`).
- **Later subsystems** (full map in the low-level doc): `broker`/`policy`/`agentid`/`auditchain`/`mcp` are the opt-in **AI-agent access broker** (Phase 13 — policy over tool + args, JIT server-side execution, keyed-HMAC verifiable audit, MCP transport, SPIFFE SVID); `conjur` optionally **sources bootstrap secrets** from CyberArk Conjur at startup (Phase 18, alongside SOPS); `session` holds the live-session registry + monitoring hub; `ocsf` maps the audit trail to the Open Cybersecurity Schema Framework for SIEM export (Phase 27); `vendor` gates third-party access behind time-boxed, customer-approved contract grants with employment attestation (Phase 29); `blast` is a read-only identity blast-radius / CIEM engine — an AWS IAM effective-permission evaluator + escalation-path traversal over a normalized identity graph (Phase 31); `rotate`/`discovery`/`maint`, `winrm`/`guacd`, `oidc`/`saml`/`mfa`/`shamir`, `k8s` (a hand-rolled Kubernetes API client — Phase 155 brokers discrete `kubectl`-shaped operations against a `kubernetes` target, never a session), `alert`, `metrics`/`logging` round out the rest (`saml` is pamv1 as a SAML 2.0 Service Provider, Phase 151 — the second place, after WebAuthn, where cryptographic verification is deliberately delegated to a library rather than hand-rolled).

The two most load-bearing cross-package couplings:

1. **Vault AAD parity.** `store.CredentialAAD(targetID, credentialID)` produces the AAD used to encrypt a secret in `api` and to decrypt it in `proxy`. Both sides must call it — if they diverge, decryption silently fails. Because it binds the credential's row ID, a new credential is inserted first (to assign the ID) and its secret encrypted + stored in a second step. Never inline the AAD string.
2. **Secrets never leave as data.** `Credential.SecretEnc` is `json:"-"` and must never be serialized to any client. Plaintext exists only transiently inside `proxy.resolve → dialUpstream` and the audited `api` reveal path; never log it.

## Conventions specific to this repo

- **Living architecture docs.** `docs/ARCHITECTURE-HIGH-LEVEL.md` and `docs/ARCHITECTURE-LOW-LEVEL.md` are kept in step with the code; each ends with a change-log table. When you change structure, packages, schema, wire formats, env vars, or the audit vocabulary, update the relevant doc **in the same change**. Read the low-level doc first — it is the fullest map of the codebase.
- **Security invariants (do not regress)** are listed in the low-level doc §6: constant-time comparisons (`crypto/subtle`), every secret use appends an audit event, break-glass config holds only the SHA-256 hash. Treat them as tests-in-prose.
- **Audit everything sensitive.** Adding an action that touches a target, credential, or session means adding an audit event with an actor; keep the action-name vocabulary (low-level doc §5) consistent.
- **Tests exercise real behavior.** The proxy test proves JIT injection end-to-end against an in-process upstream sshd that accepts *only* the vaulted password (so a pass proves the client never had it). Prefer this style over mocking the security-critical path.

## Access model (RBAC — Phase 3a)

`internal/auth` is the single source of truth for authorization. **Four roles** — `admin`, `user`, `auditor`, `approver` — map to a `Capability` set via the `roleCaps` matrix; check with `Role.Can(cap)`, never inline a role name. Identity is resolved by `auth.Resolver` from a presented key (`X-API-Key` header / SSH proxy password): the bootstrap `PAM_API_KEY` (→ admin), the break-glass key (→ admin, loudly audited), or a per-user token (looked up by SHA-256).

- **admin** — full management + reveal + connect + audit + users.
- **user** — connect through the proxy, read inventory.
- **auditor** — read inventory + audit.
- **approver** — read inventory + audit + `CapApprove` (access-request approval, shipped Phase 8).

Beyond the four built-in roles: **custom permission profiles** (Phase 12) are named capability sets assignable to users (`Principal.Caps`); a non-human **`RoleAgent`** (Phase 13) can only call broker tools; and a directory user in several mapped groups carries **all** of them (`Principal.Roles`) and gets the **union** of their capabilities — so check `principal.Can(cap)`, never a role string.

The API `authz(cap, handler)` middleware and the proxy's post-handshake `CapConnect` check both go through `auth`. **Safe membership** (Phase 17) is an additional connect-authorization path — the connect gates call `store.EffectiveTargetGrants` (direct grants ∪ safe members). Admins mint user tokens via `POST /api/users` (token returned once; only its hash is stored). AD/LDAP + Entra + OIDC login (group→role mapping, MFA) shipped in Phase 3b, SAML 2.0 SSO in Phase 151 — see `ROADMAP.md`.
