# pamv1 — security audit, 2026-08-26

> Audit of `main` at `f3fc356`, release **v0.57.1**. Five parallel read-only
> passes (crypto/secrets · authn/authz · proxies & parsers · store/data ·
> documentation fact-check), plus an independent runtime verification.
>
> **Nothing in the repository was modified.** Every finding below marked
> CONFIRMED was re-verified by reading the code path directly, not accepted from
> a summary.

---

## 0. Bottom line

**The application is functional and its factual claims are accurate.** All eight
CI gates pass, the binary boots and serves, the credential loop works end to end,
and every number the documentation states (218 store methods, migration `0048`,
193 routes, the published digests) is independently true.

**The audit nonetheless found real defects**, including one CRITICAL and five
HIGH. The dominant theme is not broken cryptography or missing authorization —
both are in good shape — but **entry points that re-implement a check and drift
from it**, and **comments that claim a security property the code does not
deliver**.

Four defects were introduced by this session's own work (Phases 206 and 209).

---

## 1. Verified working

| Check | Result |
|---|---|
| `go build` · `gofmt` · `vet` · `staticcheck` · `gosec` | clean |
| `govulncheck` | **0 vulnerabilities** |
| `go test -race ./...` | full suite passes |
| archgen drift | none |
| Live boot: `/healthz` `/readyz` `/metrics` | 200 / 200 / 200 |
| Portal, SSH proxy | 245 KB served; `SSH-2.0-Go` on :2222 |
| API auth: no key / bad key / good key | **401 / 401 / 200** |
| Vault round-trip (create → reveal) | plaintext matches; **no leak** in any read path, metrics, portal or log |
| Store methods / migrations / routes | **218 / 0048 / 193** — each verified independently |
| `v0.57.1` "no functional change" | **true**: zero `.go` changes vs `v0.57.0` |
| Registry digest vs recorded digest | identical |

Substantial areas came back genuinely clean: **no SQL injection** (all 111 pgstore
query sites parameterised); **no inlined role-name authorization checks**; **every
one of 150+ routes guarded**; **all five siblings of the historical IDOR bug carry
ownership checks**; **no `math/rand` anywhere**; **AAD parity with zero inline
construction**; **no non-constant-time secret comparison**; **the operator cannot
observe an injected credential** on any of the four JIT legs; migrations 0001–0048
with no gaps, no duplicates, no destructive statements.

---

## 2. CRITICAL

### C-1 · Unauthenticated ~2 GiB allocation on the PostgreSQL proxy

`internal/proxy/dbproxy.go:304` — **CONFIRMED** (demonstrated empirically by the
audit pass; the code path re-verified by hand).

`pgproto3.Backend.SetMaxBodyLen` is **never called anywhere in the repository**, so
the default "no maximum" applies. `ReceiveStartupMessage` is bounded at 10 000
bytes, but the *next* read — the password message, still fully unauthenticated —
is not.

An attacker sends a valid StartupMessage, then five bytes declaring a ~2 GiB body.
The proxy allocates it and blocks until the 120 s handshake timeout. **The auth
rate limiter is at line 314 — downstream of the read at line 304 — so it cannot
fire.** A handful of connections OOM-kills `pam-server`, terminating every live
SSH and database session.

**Triage:** `PAM_DB_ADDR` defaults to `off`, so this is reachable only where the
PostgreSQL proxy is deliberately enabled — but that is the documented Phase 15
feature, and the port is by design operator-reachable.

**Fix:** call `SetMaxBodyLen` on every `pgproto3.Backend`/`Frontend`, and move the
rate-limiter check ahead of the first unauthenticated body read.

---

## 3. HIGH

### H-1 · A leaked browser-extension token opens full privileged sessions

`internal/proxy/gates.go` (no check) and `internal/api/viewer_handlers.go:120` —
**CONFIRMED**.

`ExtensionOnly` is enforced in exactly four places: the two API middlewares, the
reveal handler, and its own definition. It is **not** checked by the SSH proxy's
`admit()`, the PostgreSQL proxy, the SQL Server proxy, or the RDP/VNC viewer
tunnel. An extension token carries the minting user's full role with a 24-hour
default TTL.

`internal/auth/auth.go:380-382` states: *"Every OTHER authenticated route refuses
it exactly like TunnelOnly, so a token that leaked from an endpoint's local
storage cannot do anything but reveal."* **This is false**, and the threat it
names — a token lifted from browser storage — is precisely what becomes an
interactive session on every reachable target.

### H-2 · An `mfa_pending` token opens an RDP/VNC desktop

`internal/api/viewer_handlers.go:120` — **CONFIRMED**.

The tunnel checks only `EnrollOnly` and `Can(CapConnect)`. The proxy correctly
refuses `MFAPending` at `gates.go:223`; the tunnel never looks. A password-verified
but **not** WebAuthn-verified session opens a live desktop, bypassing the second
factor. Preconditions: WebAuthn and guacd both configured, victim without a
confirmed TOTP. `auth.go:322` claims it is *"refused everywhere except the WebAuthn
login-ceremony routes"*.

### H-3 · DoubleLock stores a KEK-independent copy of the secret behind an unvalidated password

`internal/api/doublelock.go:49,60-61,212` — **CONFIRMED**; the file's own comment
describes the mechanism.

`DoubleLockEnc` is *a second ciphertext of the same secret*, keyed by
PBKDF2-HMAC-SHA256 at 100 000 iterations over a password validated only for being
non-empty. `SecretEnc` remains alongside it. A database-only compromise — the exact
scenario the KEK-outside-the-database design defeats — yields an offline-crackable
copy of every double-locked secret, with the same-row verifier as a cheap oracle.

The comment reasoning that *"this is a defense-in-depth check … so it does not need
to match the OWASP guidance"* is wrong: this password is the sole key protecting a
copy of a privileged secret at rest.

### H-4 · TDS parameter-name ambiguity defeats per-statement audit and step-up

`internal/tds/tds.go:892` — **CONFIRMED** (executed against the real package).

A 128-character T-SQL parameter name produces a name-length byte of `0x80`, which
`walkParams` treats as a batch separator. The walk desynchronises and the statement
text is never recovered. With no `CommandGuard` configured (the default), the
original bytes are still forwarded and executed while the audit trail and the
session recording record `[rpc #10]`. A configured `StepUpGuard` is silently
bypassed. With a `CommandGuard` present it does fail closed.

### H-5 · `sp_executesql` audits the wrong parameter

`internal/tds/tds.go:876` — **CONFIRMED** (executed).

`req.SQL = texts[len(texts)-1]`, commented *"the statement is the last character
parameter in every shape we know"*. For `sp_executesql` the statement is **first**.
Every parameterised call from ADO.NET / JDBC / pyodbc — the majority of real
traffic — records an operator-chosen parameter *value* in `db.query`, in the
recording and on the live monitor, instead of the executed statement. `cmdguard` is
**not** bypassed (it checks all parameters); this is audit forgery, not policy
evasion.

---

## 4. Introduced by this session (Phases 206 / 209)

### T-1 · The per-token ceiling never counts approval-path work — MEDIUM-HIGH

`internal/api/agenttokenceiling.go` + `broker_handlers.go:543` +
`mcp_handlers.go:235` — **CONFIRMED**.

`brokerCallDetail` — the only writer of `svid_jti` — is called from the two initial
call paths. Both **resume** handlers build their detail inline and omit the field.
`CountAgentCallsForTokenSince` requires `strpos(detail, ' svid_jti:"…"') > 0`, so it
can never match a `resumed` row.

An agent whose calls require approval does all its work through the approval path
and **charges nothing** against its token ceiling — precisely the loophole the daily
budget's own interface doc says must not exist. The claim that it "counts the same
two spending actions … the difference is only what it groups by" is false.

The contract fixture compounds it: it builds a `resumed` row **with** `svid_jti`,
under a comment asserting "Every row below is written with the field the API
actually writes". Production never writes that shape — the test validates a case
that cannot occur.

### T-2 · The token exchange never checks the actor token's `cnf` — MEDIUM

`internal/agentid/exchange.go` — **CONFIRMED**: `actor.ConfirmationKey` appears
nowhere in the repository. An SVID agent holding a captured key-bound token for Y
can post it as `actor_token` with its own key as `cnf_jkt` and receive a token whose
`sub` is Y, bound to its key. `pop.go`'s *"A captured token without the private key
proves nothing and is refused"* is true at the ingress and false at the exchange.

### T-3 · Proof replay protection is per-replica and undocumented — MEDIUM

`internal/agentid/pop.go` — **CONFIRMED**. The replay cache is an in-process map
created per `api.Server`. In the HA deployment this codebase explicitly supports, a
captured token + proof pair replays once per replica inside the ±60 s window. The
claim "a proof is single-use" is stated unqualified in `pop.go`, ADMIN-GUIDE,
PROTOCOLS-AND-CRYPTO and the ROADMAP. This repo documents exactly this scope
elsewhere as a matter of habit, which makes the silence a gap rather than a style
choice.

### T-4 · `PAM_BROKER_PUBLIC_URL` has no prerequisite check — LOW

`internal/config/config.go` — **CONFIRMED**. It is absent from the broker-gated
group, so only its URL *shape* is validated. The claim that "both knobs fail the
startup loudly when their prerequisite is absent" is repeated in CHANGELOG 0.56.0,
ROADMAP Phase 206, ARCHITECTURE-LOW-LEVEL and SYSADMIN-GUIDE.

*(An earlier runtime check of mine exercised the shape cases and I mistakenly read
that as confirming the prerequisite claim. It did not.)*

---

## 5. MEDIUM — the rest

- **M-1 · Audit-detail `key:value` injection via `cmd:`** — `auditfmt.Field` quotes
  but does not escape `:` or spaces. The repo **already fixed this once**:
  `sftpguard.go:176` wraps it in a `":" → "\x3a"` replacer, with a comment naming
  the recording tamper-check as the reason. The `cmd:` sites, the raw SSH subsystem
  name (`proxy.go:1199`), the client-supplied database name (`dbproxy.go:359`,
  `mssqlproxy.go:353`) and `res.reason` (`proxy.go:903`) did not get the same
  treatment. Consequences: forging `sha256:` into the playback tamper check, and
  relabelling a recording's target in the console.
- **M-2 · Unauthenticated caller controls the audit `actor` verbatim** —
  `authn.go:49` passes the raw client username, unbounded and unsanitised, while the
  SSH proxy uses `auditField(c.User(), 64)` on the identical input. Downstream,
  `auditfwd` renders `actor=%s` unquoted, so a crafted username injects a competing
  field into every RFC 5424 record. (Analytics is correctly defended — `auth_failure`
  is excluded from the auto-response score.)
- **M-3 · Budgets and the token ceiling are check-then-act** with no reservation or
  compare-and-set; K concurrent calls all observe the same count. Compounded by
  `agent_keys.name` not being unique, so two keys can pool one usage count under two
  different limits.
- **M-4 · Approval state machine has no compare-and-set** — a deny can be silently
  overwritten by a racing approve. Several sibling paths (`ConsumeApproval`,
  `ConsumeBrokerToken`) are genuine single-winner CAS; this one is not.
- **M-5 · Personal-safe privacy bypassable three ways** by any `CapManageTargets`
  holder: unassign the safe, delete the safe, or self-grant a direct target grant.
  All audited, which is the only mitigation.
- **M-6 · 20 store methods absent from the contract suite**, including magic-link
  approval redemption, session-share redemption, vendor-grant revocation and session
  revocation on offboarding — their pgstore SQL has no test coverage at all.
- **M-7 · SFTP native `SSH_FXP_LINK` unchecked in allow mode**, and
  `SSH_FXP_SYMLINK` checks only one of its two paths — while the admin guide states
  a matching path is refused in *every* mode.
- **M-8 · Unbounded channels per authenticated SSH connection** — the session cap is
  consulted once per connection; each accepted channel creates a recording file and
  goroutines.

---

## 6. The pattern worth acting on

Three of the five most serious findings share one shape: **a component that
resolves its own principal, or re-implements a check, and drifts from the
canonical one.** The viewer tunnel, the proxy `admit()` chain and the API
middleware each enforce a different subset of the same scope rules.

The structural fix is a single predicate on `*auth.Principal` — "is this a
narrow-scope token?" — that every self-resolving entry point must call, so the
next scope added cannot miss a surface. Tests belong at the tunnel and the proxy,
not only at `/api/me`.

The second pattern is **comments asserting properties the code does not deliver**.
Eight were found. This project already treats that as a defect class in its own
right; these are simply the ones no gate can catch.

---

## 7. Suggested order

1. **C-1** — bound the pgproto3 body length and move the limiter ahead of the read.
2. **H-1 / H-2** — the shared narrow-scope predicate, plus tests at every
   self-resolving entry point.
3. **T-1** — write `svid_jti` on the resume paths (or count by a field that exists
   there), and fix the fixture that validates a shape production never emits.
4. **H-4 / H-5** — the TDS parameter walk and the `sp_executesql` ordering; both are
   audit-integrity defects in a feature whose entire purpose is per-statement audit.
5. **H-3** — raise the PBKDF2 cost and enforce a password policy, or restate what
   DoubleLock protects.
6. **M-1 / M-2** — apply the existing `auditPath` colon-escaping pattern at the
   remaining sinks; sanitise the login actor.
7. **T-2 / T-3 / T-4** and the remaining doc corrections.

Items 1–4 change behaviour and warrant a phase plus a patch release. Items under
§4 are regressions from today and should not wait.
