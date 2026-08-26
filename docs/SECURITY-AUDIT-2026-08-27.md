# PAMv1 — security audit, 2026-08-27 (redacted)

> **Status: closed.** Every finding below is **fixed** in Phase 215, each with a
> regression test and each pinned by mutation (the check was removed, its test
> watched to fail, the check restored). This is the **redacted** record: the
> class of each finding, where it lived, and how it was closed — enough to
> review the fix, not enough to weaponize against an unpatched checkout. The
> previous pass is [SECURITY-AUDIT-2026-08-26.md](SECURITY-AUDIT-2026-08-26.md).
>
> Scope: **v0.58.1** — the tree as released, one day after the 2026-08-26 audit's
> fixes shipped. Released as **v0.58.2**.

---

## 0. Bottom line

The cryptography, the vault envelope, the JIT gate sequence (`admit()`), the
JWT/DPoP verifiers, the OIDC/SAML callbacks and the token exchange read clean;
no SQL is built from strings, no request body is unbounded, no secret reaches a
log, every unauthenticated route that accepts a bearer value throttles and
audits its failures. Four fuzzers ran ~1.3–2 M executions each without a
crasher; the race-enabled suite, `gofmt`, `vet`, `staticcheck`, `govulncheck`
and `gosec` are clean.

The audit found **two HIGH, one MEDIUM and three LOW** defects — none in the
code the 2026-08-26 audit had just fixed, all in paths beside it. Two patterns,
one of them a repeat:

- **A principal is minted once and never re-read.** A session token is built
  from the user row at login and then lives on its own row. Nothing on any
  write path — delete, SCIM deactivate, role change — revoked those sessions,
  and the resolver never consulted the row again, so a deactivated local user's
  24-hour extension token kept revealing secrets, and the row's IP allowlist
  and device binding never applied to a session at all.
- **A self-resolving door with a shorter checklist** — the 2026-08-26 audit's
  H-1/H-2 shape, found in two more places: the viewer tunnel and the
  `authenticated` middleware both resolve a principal and ran neither the IP
  allowlist nor the posture gate that `authz` and `admit()` run.

## 1. Method

Five read-only passes over the security-critical paths, each finding
re-verified against the code by hand before any fix:

1. **Tooling.** The CI gates, plus `gosec` at medium confidence, `staticcheck
   -checks all`, `golangci-lint` with every linter (style noise discarded;
   `errcheck`/`gosec` hits triaged by hand), the four fuzz targets (SFTP
   inspector, TDS PreLogin/SQLBatch/RPC) for 45–60 s each, and the race suite.
2. **Grep-driven vulnerability classes.** Command execution, weak randomness,
   string-built SQL, unbounded reads, redirects, TLS verification, portal
   template escaping, secrets in log calls, host-key policy on outbound legs.
3. **Authentication and authorization.** `auth.Resolver`, the capability
   matrix, `CanConnectTarget`, the `authz`/`authenticated`/`mfaPendingOnly`
   middlewares, the proxies' `admit()` sequence, the SSH `PasswordCallback`,
   the viewer tunnel, the SCIM scope rule, the personal-safe guards.
4. **Bearer surfaces.** Session-share redeem/stream/input, approval magic
   links, break-glass unseal, the extension and viewer tokens, the broker's
   token exchange and DPoP proof, the rate limiter.
5. **Data paths.** The vault envelope, DoubleLock, the reveal path, the
   recording download's name validation, `pgstore` query construction, the
   Kubernetes path builder.

**Not run here:** the live-Postgres store suite — this machine has no Docker
daemon, podman or PostgreSQL binary. It ran green in CI on the same code
(the `pgstore` job of PRs #350–#352) and runs again on this phase's PR.

## 2. Verified clean (spot-checked)

Fresh DEK and nonce per `vault.Encrypt`, AAD-bound, indistinguishable failure on
`Decrypt`; constant-time comparison on every bootstrap/break-glass/state
value; only SHA-256 of any bearer stored (including, since Phase 212, the
web-guest key); `admit()`'s sixteen gates in order with decryption last; the
exchange refuses a key-bound actor token, self-delegation and an unbound
delegation from a bound delegator; DPoP checks `typ`, private-JWK members,
`htm`/`htu`/`iat`/`ath`/`jkt` and replays; OIDC state is a constant-time cookie
match plus a single-use store row with PKCE and nonce; SAML consumes its
request id once; every self-approval path refuses the requester; all 29 route
groups guarded; `MaxBytesReader`/`LimitReader` on every body; `CSP` with a
nonce and no `unsafe-inline` script; no `exec.Command`, no `math/rand`, no
`Sprintf`-built SQL.

## 3. Findings and resolution

| ID | Sev | Area | Class | Status |
|---|---|---|---|---|
| A-1 | HIGH | `api/users.go`, `api/scim_handlers.go`, `auth.Resolve` | **Sessions outlive the account.** Deleting a user, SCIM-deactivating one, or changing their role revoked nothing: a browser-extension token (hours) or any session minted before the change kept resolving until it expired, and the resolver never re-read the user row for a session | **Fixed** — one `cutUserAccess` (login sessions + live proxied sessions, audited `session.revoked reason:`) on all three write paths, AND `Resolve` refuses a session whose local row is inactive (fail-closed on a lookup error). Three end-to-end tests + one resolver test; mutation-pinned |
| A-2 | HIGH | `api/sessionshare_handlers.go`, `session/share.go` | **The guest's bearer key was the roster id.** A web guest was tracked under its raw key, so `GET /api/sessions/{id}/share/roster` handed every `read_audit` reader the guest's live credential as `join_id`, and the kick audit wrote it into the trail — a supervisor could watch as the guest or, for `view_control`, type as the guest | **Fixed** — tracked under `session.GuestJoinID` (the SHA-256 the registry already keys on); `Kick` revokes by that id; the roster id resolves to nothing as a key. Registry + API tests; mutation-pinned |
| A-3 | MED | `auth.Resolve` | **A session principal carried no IP allowlist or device binding.** Only the per-user-token path copied `store.User.IPAllowlist`/`DeviceFingerprint`, so an extension or viewer token of a local user was never restricted — the ADMIN-GUIDE's "enforced everywhere that principal authenticates" was false for sessions | **Fixed** — the same row lookup A-1 adds carries both fields onto session principals; end-to-end test |
| A-4 | LOW-MED | `api/server.go` (`authenticated`) | **The authenticated-only middleware ran no source gates.** `/me`, `/logout` and the MFA enrollment/WebAuthn registration routes skipped the IP allowlist, device and posture checks `authz` runs — a token used from outside its allowlist could still enroll a second factor | **Fixed** — `sourceGates`, one function shared by `authz`, `authenticated` and the viewer tunnel |
| A-5 | LOW | `api/viewer_handlers.go` | **The viewer tunnel ran no source gates** (the 2026-08-26 H-1/H-2 shape again): approval, vendor and session cap yes; IP allowlist, device, posture no. The 60-second token was minted by a request that did enforce them, which bounds it | **Fixed** — `sourceGates`; end-to-end test with a 502 control; mutation-pinned |
| A-6 | LOW | `api/credentials.go`, `api/targets.go` | **Personal-safe integrity.** Phase 212's M-5 closed the privacy bypasses; a plain `manage_targets`/`manage_credentials` profile could still plant a credential on, delete a credential of, or delete a target in someone else's personal safe | **Fixed** — `guardPersonalTargetWrite` (owner, `can_manage` member, override or built-in admin) on all three; test; mutation-pinned |
| — | INFO | `internal/alert` | `gosec` G118: a fire-and-forget alert goroutine uses `context.Background()` | Deliberate — the request's context would cancel the delivery when the handler returns; the goroutine carries its own 10 s timeout. Not changed |
| — | INFO | `golangci-lint` `errcheck` | ~780 unchecked returns, almost all `Close`/`Reply`/`Fprint`, plus unchecked *denial* audits on the app-secrets and MCP paths | The success-side audits on those paths are fail-closed (`mustAuditAs` / the broker's own HMAC chain); an ignored denial audit cannot admit anything. Not changed |

## 4. The pattern worth keeping

Three of the six share one shape the 2026-08-26 audit named and this one met
again: **an entry point that resolves its own principal runs a shorter
checklist than the middleware.** The structural fix this time was, as then,
one function called everywhere — `sourceGates` — so a gate added to the
middleware cannot miss the tunnel or the authenticated-only routes. The other
three share a shape that audit had not named: **state derived once from a row
and never re-derived.** A session principal now re-reads its row on every
resolve, and every write that changes a row's authority cuts the sessions
that were derived from the old one.

## 5. Change log

| Date | Change |
|---|---|
| 2026-08-27 | First version: six findings, all fixed in Phase 215; released as v0.58.2 |
