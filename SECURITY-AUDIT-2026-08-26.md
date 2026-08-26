# PAMv1 — security audit, 2026-08-26 (redacted)

> **Status: closed.** Every finding below is either **fixed** (with a regression
> test, most pinned by mutation) or **deferred** with a stated reason. This is
> the **redacted** record: because the issues are resolved and this repository is
> public, the concrete exploitation steps have been removed. What remains is the
> class of each finding, where it lived, and how it was closed — enough to review
> the fix, not enough to weaponize against an unpatched checkout.
>
> Fixes shipped on the `phase-212-*` branch. The full gate suite (build, gofmt,
> vet, staticcheck, gosec, govulncheck, archgen) and the race-enabled test suite
> pass, and the fixed binary was re-verified booting and serving end to end.

---

## 0. Bottom line

The application is functional and its documented claims are accurate: all gates
pass, the credential loop works end to end, no secret leaks to any read path, and
the store/route/migration counts and released digests are all independently true.

The audit nonetheless found real defects — one CRITICAL, five HIGH, several
MEDIUM. The dominant theme was **not** broken cryptography or missing
authorization (both are in good shape) but two recurring shapes: **entry points
that re-implement a check and drift from the canonical one**, and **comments that
claimed a security property the code did not deliver**. Four defects were
introduced by this session's own Phases 206/209 — the strongest argument for the
audit having happened.

## 1. Verified clean (spot-checked)

No SQL injection (every pgstore query parameterised); no inlined role-name checks;
every route guarded; all siblings of the historical IDOR bug carry ownership
checks; no `math/rand` in a security role; AAD parity with zero inline
construction; no non-constant-time secret comparison; the operator cannot observe
an injected credential on any JIT leg; migrations gap-free with no destructive
statements.

## 2. Findings and resolution

Severities as originally assessed. Locations are kept because the fix commits
reference them; exploitation detail is intentionally omitted.

| ID | Sev | Area | Class | Status |
|---|---|---|---|---|
| C-1 | CRITICAL | PostgreSQL proxy (`dbproxy.go`) | Unauthenticated memory-exhaustion via an unbounded wire-message body; rate limiter ran after the read | **Fixed** — bounded pre-auth and session message bodies; limiter moved ahead of the first read; regression pinned by mutation |
| H-1 | HIGH | proxy `admit()` + viewer tunnel | A narrow-scope token was accepted by an entry point that re-implemented the scope check with fewer fields than the middleware | **Fixed** — one shared `Principal.MayOpenSession`; deleting a scope from it fails every entry point's test together |
| H-2 | HIGH | RDP/VNC viewer tunnel | A partially-authenticated (second-factor-pending) token reached a live desktop | **Fixed** — same shared predicate; regression at the tunnel |
| H-3 | HIGH | DoubleLock (`doublelock.go`) | A KEK-independent copy of a secret protected only by an unvalidated password at a low KDF cost | **Fixed** — minimum length enforced, iterations raised to the OWASP figure, count stored per record for backward-compatible open |
| H-4 | HIGH | TDS broker (`internal/tds`) | A crafted parameter name desynchronised the per-statement audit while the statement still executed | **Fixed** — protocol-correct disambiguation; verified by mutation |
| H-5 | HIGH | TDS broker (`internal/tds`) | Per-statement audit recorded the wrong parameter for the common driver shape | **Fixed** — statement selected per procedure; the full parameter list is recorded for the shapes where it is not first |
| T-1 | MED-HIGH | Per-token ceiling (Phase 209) | Approval-path work was never counted against a token's ceiling | **Fixed** — both transports write the correlating field through one helper; end-to-end regression |
| T-2 | MED | Token exchange (`exchange.go`) | A key-bound token could be re-delegated by a third party | **Fixed** — a bound actor token is refused at the exchange |
| T-3 | MED | Proof replay cache (`pop.go`) | Replay protection is per-replica; this scope was undocumented | **Fixed (docs)** — scope stated wherever the guarantee appears |
| T-4 | LOW | config validation | A knob was documented as failing closed without its prerequisite but did not | **Fixed** — added to the startup prerequisite group |
| M-1 | MED | audit details (proxies) | Untrusted values could forge `key:value` fields the trail is parsed by | **Fixed** — shared `auditfmt.Value` at every sink; unit-guarded |
| M-2 | MED | login audit actor | An unauthenticated username reached the audit actor unbounded/unquoted | **Fixed** — bounded and quoted, matching the proxy |
| M-3 | MED | agent keys / budgets | Two active keys could share a name and pool one budget | **Fixed (name half)** — partial unique index (migration 0049). Reservation half **deferred** (see below) |
| M-4 | MED | approval decision | A racing approve could overwrite a final deny | **Fixed** — compare-and-set on `pending`, both backends |
| M-5 | MED | personal safes | A plain target manager could reach a private target three ways | **Fixed** — one fail-closed guard on all three |
| M-7 | MED | SFTP guard | Link operations could launder a denied path | **Fixed** — both paths of both link ops checked, every mode; mutation-pinned |
| M-8 | MED | SSH proxy | Unbounded channels per connection | **Fixed** — per-connection cap |
| F-5 | (LOW→) | SCIM | A connector could act on a privileged user | **Fixed** — refused by effective capability, not role string; the deprovisioning error now surfaces |
| F-8 | INFO | middleware | Scope refusals were unaudited | **Fixed** — now audited with the shared reason slug |
| — | LOW | DB proxy SCRAM; JWK member check; guest key | Bound an upstream-supplied iteration count; case-fold the private-member check; store the guest bearer key by hash like every other token | **Fixed** |

## 3. Deferred, with rationale

- **M-6** — 20 store methods absent from the pgstore contract suite. Test-coverage
  debt, not a live defect: the methods work and are exercised through handler
  tests. Adding them to the contract suite is a sizable, purely-additive task.
- **M-3 reservation half** — the concurrent-burst budget over-run needs a new
  atomic compare-and-spend store primitive (a design change). The per-minute rate
  limit already bounds burst volume, so the residual is small.
- **F-7** — binding a broker resume token to its collector needs a schema column;
  the token is single-use bearer by explicit design and call ids are 96-bit
  random, so this is defence-in-depth rather than a live hole.
- Remaining informational items were assessed non-exploitable or already
  documented.

## 4. The pattern worth keeping

Three of the most serious findings shared one shape: **a component that resolves
its own principal, or re-implements a check, and drifts from the canonical one.**
The structural fix was a single predicate every self-resolving entry point calls,
so the next scope added cannot miss a surface.

The second pattern was **comments asserting a property the code did not deliver.**
Several were found. This project already treats that as a defect class; these were
the ones no gate could catch — which is also why a fix passing its test is not
proof it works, only proof the test agreed with it.
