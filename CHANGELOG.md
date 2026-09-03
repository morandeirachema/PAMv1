# Changelog

All notable released changes to PAMv1 are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) with 0.x semantics — breaking
changes may land in minor versions until 1.0.

PAMv1 is built phase by phase, and the full per-phase history — what shipped in
each phase, in what order, and why — lives in [ROADMAP.md](ROADMAP.md). This
file records **releases**: the tagged, signed points you can actually deploy.

## [0.65.0] — 2026-09-02

A minor that ships **Phase 236** — the review of Phases 232–235, and what it
found. **Schema and store surface moved** (`0052`, two `UserStore` methods)
and one audit action is new, which is why it is a minor and not a patch; no
route or env var was added.

**What was found, and fixed.** Two Medium authorization findings in the
Slack chat-ops approval shipped in 0.64.0 shared one root cause: a button
click was recorded as a synthetic `slack:<handle>` actor, and the four-eyes
check and the distinct-approver count both compare PAMv1 usernames — so a
linked requester could approve their own request from the channel, and one
approver could satisfy a two-person floor once via the API and once via
Slack. A click is now resolved through a **Slack identity mapping** — the
new `slack_user_id` on a user (`POST`/`PUT /api/users`, console Add/Change
User) — to an **active PAMv1 user holding `approve`**, and decided **as that
identity**; an unlinked member, a deactivated user or a role without the
capability is refused and audited (`access.decision_denied` with
`slack-unlinked`/`slack-not-approver`), and every Slack decision is audited
as `access.slack_decision`. Also: the Slack ack is now flushed before any
follow-up (it was held until an up-to-8-second `response_url` call
finished, against Slack's 3-second budget), every refusal reaches the
clicker as an ephemeral message (Slack ignores the ack body the old code
wrote it to), a partial approval on a multi-approver chain keeps the buttons
live, mrkdwn escaping no longer turns `'` into `&#39;`, and the button
token's MAC is domain-separated from Slack's own request signature.

**What an operator must do to keep using Slack approval.** Link each
approver's Slack member ID to their PAMv1 user — until then, every click is
refused with an in-channel note. And re-run `slack-notify` for any request
whose buttons were posted **before** this upgrade: the button token's MAC
is now domain-separated, so buttons minted by 0.64.0 no longer verify and
answer every click with "expired" (noted by Phase 238's review — this
paragraph did not say so at release). Deployments without Slack configured
are unaffected.

**Security.** `golang.org/x/crypto` 0.55.0 → 0.56.0 for
[GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354) and
[GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355) (SSH channel-deadlock
denial of service, reached from the SSH proxy, the rotator and the endpoint
agent).

### Added

- `users.slack_user_id` (migration `0052`); `slack_user_id` on
  `POST`/`PUT /api/users`; audit action `access.slack_decision`.

### Changed

- `POST /api/slack/interactivity` decides as the linked PAMv1 user, or
  refuses; acks before its `response_url` follow-up; refusals are ephemeral.

### Fixed

- Four-eyes and dual-control bypass via Slack (see above).
- Slack message escaping, target-name fallback, and the never-rendered
  "expired" reply.

Helm chart `0.55.0` → `0.56.0`, a minor alongside an app minor. Image digest
`sha256:292045eb…` (the full value is in the README and on the release page).

## [0.64.0] — 2026-09-01

A minor that ships **Phase 234** — Slack chat-ops access-request approval,
the second finding from the research pass Phase 232 opened, against
Britive. **No schema change**, but two new routes, a new env-var pair and
observable behaviour when they're set, which is why it is not a patch.

**What an operator can now configure.** Set `PAM_SLACK_WEBHOOK_URL` and
`PAM_SLACK_SIGNING_SECRET` (required together) and a `CapApprove` holder
can post an interactive Approve/Deny message to Slack for a pending access
request (`POST /api/access-requests/{id}/slack-notify`, or console menu
Work with Access Requests option 8). Clicking either button in Slack
decides the request through the same path an authenticated approve/deny
call uses — no PAMv1 login needed to click, but Slack's own request
signature is verified on every callback.

**What has not changed.** Unset (the default), no routes behave
differently and nothing about an existing deployment changes. The
underlying approval workflow (multi-tier chains, tickets, magic-link
invites) is untouched — Slack is one more way to reach the same decision.

### Added

- `internal/slack` package: Slack v0 request-signature verification, and a
  compact signed token per Approve/Deny button.
- `POST /api/access-requests/{id}/slack-notify`, `POST /api/slack/interactivity`.
- `PAM_SLACK_WEBHOOK_URL`, `PAM_SLACK_SIGNING_SECRET` (join the
  `PAM_OT_AIRGAP` conflict list).

Helm chart `0.54.0` → `0.55.0`, a minor alongside an app minor. Image digest
`sha256:76701645…` (the full value is in the README and on the release page).

## [0.63.0] — 2026-08-31

A minor that ships **Phase 232** — on-call/schedule-aware access gating,
from a fresh competitive-research pass against HashiCorp Boundary. **No
schema or route change**, but a new env var and observable behaviour when
it's set, which is why it is not a patch.

**What an operator can now configure.** Set `PAM_ONCALL_ATTEST_URL` to an
on-call scheduler's webhook (PagerDuty, Opsgenie, an internal roster) and
PAMv1 checks it on every connect and every authenticated call, the same
shape as the existing `PAM_POSTURE_ATTEST_URL` device-posture check — a
2xx means the user is currently on call, anything else refuses. Break-glass
is exempt, like every other admission gate. Human operators only: it is
never asked about the AI-agent broker's own calls, since "on call"
describes a shift a non-human identity doesn't have.

**What has not changed.** Unset (the default), no check ever runs and
nothing about an existing deployment's behaviour is different.

### Added

- `internal/oncall.Attestor`, checked in the session-proxy `admit()`
  sequence and the REST `authz`/viewer-tunnel `sourceGates`.
- `PAM_ONCALL_ATTEST_URL` (joins the `PAM_OT_AIRGAP` conflict list).

Helm chart `0.53.1` → `0.54.0`, a minor alongside an app minor. Image digest
`sha256:5ecdd799…` (the full value is in the README and on the release page).

## [0.62.1] — 2026-08-31

A patch that ships **Phase 229** — a gap-analysis pass. **No schema, route or
env-var change**, no upgrade note that needs an action, and nothing an
operator does changes: the fixes are doc-currency, dead code, and this
project's own bookkeeping. They ship anyway because the rule since Phase 200
is that a differing binary does not bank on `main`.

### Fixed

- **`cmd/pam-server` now parses `PAM_SSH_SFTP` through `proxy.ParseSFTPMode`**
  instead of casting the raw string, matching the shape
  `PAM_SSH_SFTP_CAPTURE` already used — closes a latent duplicate-validation
  risk between `internal/config` and `internal/proxy`, not a live bug.

### Removed

- **`store.EffectiveMFAFactors`** (Phase 124) had zero production callers;
  its own doc comment overclaimed that it centralized four call sites which
  in fact each need the concrete `MFAEnrollment`, not a collapsed boolean.
  Deleted rather than force-fit.

### Docs

- `docs/ARCHITECTURE-LOW-LEVEL.md`'s §4 config table gained rows for eleven
  live env vars that were previously documented only in phase-history prose.
- `ROADMAP.md`'s own top banner, corrected: Phase 228 had bumped it to claim
  a code-free flake investigation was "shipped."

Helm chart `0.53.0` → `0.53.1`, a patch alongside an app patch. Image digest
`sha256:38ad4e2b…` (the full value is in the README and on the release page).

## [0.62.0] — 2026-08-27

A minor that ships **Phase 226** — the MCP endpoint negotiates the protocol
revision with each client instead of answering every `initialize` with
`2024-11-05`. No schema, env var, route or audit-action change; a minor
because the wire behaviour is visible to every MCP client.

**What an MCP client sees now.** `initialize` answers with the client's own
revision when PAMv1 speaks it — `2024-11-05`, `2025-03-26` or `2025-06-18` —
and with `2025-06-18` otherwise, after which the client decides. JSON-RPC
batches are accepted (the 2025-03-26 revision requires it) and answered
element by element. A request carrying an `MCP-Protocol-Version` header that
names a revision PAMv1 does not speak is refused with `400`; a request without
the header is served as before. The advertised server capabilities are now the
ones that exist — `tools` — where `logging` (never implemented) and
`elicitation` (a client capability) had been listed too.

**What has not changed.** The transport: `GET /mcp` for the SSE stream, `POST
/mcp` for messages — the HTTP+SSE pair every revision keeps for backwards
compatibility. The Streamable HTTP transport is not offered.

### Changed

- `initialize` negotiates `protocolVersion`; server capabilities list only
  `tools`.
- `POST /mcp` accepts JSON-RPC batches and validates `MCP-Protocol-Version`.

Helm chart `0.52.0` → `0.53.0`, a minor alongside an app minor. Image digest
`sha256:8145ca1b…` (the full value is in the README and on the release page).

## [0.61.0] — 2026-08-27

A minor that ships **Phase 224** — the SPIFFE trust bundle is re-read when the
file changes, so an issuer key rotation no longer needs a restart. No schema,
env var, route or audit-action change; a minor rather than a patch because the
behaviour is observable and was, until now, an operational step.

**A SPIRE key rotation no longer needs a restart.** The trust-domain JWKS
(`PAM_BROKER_TRUST_DOMAIN_JWKS`) was read once at startup, so every SVID under a
newly published key was refused — indistinguishably from any other bad token —
until PAMv1 was restarted. The file's modification time and size are now
checked at most every 30 seconds, and the bundle is re-read at once when a token
arrives under a key id PAMv1 does not hold (rate-limited to one re-read per
second). A half-written, unparsable, empty or missing file keeps the **last good
bundle** in force and is logged under `service=svid` — a rotation in progress is
never treated as "trust nobody". A key the issuer removes stops verifying on the
next successful read. The broker's own token-exchange key survives every
reload, and a bundle that tries to shadow its key id is refused whole.

### Changed

- `agentid.SVIDVerifier` re-reads its bundle on change (`Reload`,
  `SetBundleRecheck`, `WithLogger` — Go API only). Nothing to configure.

Helm chart `0.51.0` → `0.52.0`, a minor alongside an app minor. Image digest
`sha256:50be5f7c…` (the full value is in the README and on the release page).

## [0.60.0] — 2026-08-27

A minor that ships **Phase 222** — a broker resume token is bound to the agent
that parked the call — and **Phase 221**, a documentation resync. A minor
rather than a patch because the schema moves: migration `0051` adds a
`subject` column to `broker_tokens`, applied automatically on startup. **No
env var, route or audit-action change**, and nothing an operator configures
changes.

**A leaked resume token is now worth nothing to another agent.** The token was
already single-use and its call id 96-bit random (the 2026-08-26 audit rated
the gap LOW for that reason), so a token that reached another agent was worth
one collection at most. It is now bound to the identity that parked the call —
a static key's row id, or an attested workload's SPIFFE ID — and any other
presenter, even one holding both the token and the call id, gets the same
answer a bad token gets, at the peek and inside the atomic spend. Its attempt
spends nothing; the owner still collects exactly once. With this, **every
finding of the 2026-08-26 security audit is closed.**

### Added

- `broker_tokens.subject` (migration `0051`), written when a call parks and
  required to collect its result. `ConsumeBrokerToken`/`PeekBrokerToken` take
  the presenter's subject (Go API only; `store.Store` stays at 220 methods).

### Operational notes

- A token minted before the upgrade carries no subject and keeps spending for
  any presenter until it expires — at most one `PAM_BROKER_TOKEN_TTL_MIN`
  window, for calls parked across a rolling deploy.
- Phase 221 corrected two long-stale "latest migration" marks in the
  architecture and code guides and brought several change logs up to date;
  documentation only.

Helm chart `0.50.0` → `0.51.0`, a minor alongside an app minor. Image digest
`sha256:55f70935…` (the full value is in the README and on the release page).

## [0.59.0] — 2026-08-27

A minor that ships **Phase 219** — the agent budget and the per-token ceiling
become a **compare-and-spend**. A minor rather than a patch because the schema
moves: migration `0050` adds `agent_call_reservations`, applied automatically
on startup like every migration before it. **No env var, route or audit-action
change**, and nothing an operator configures changes; what changes is that a
limit now holds under load.

**A burst of calls can no longer over-run a budget.** Both limits were counted
from the audit trail and then the call ran — so calls arriving together all
read the same count, all passed, and the limit over-ran by the width of the
burst (twelve calls against a budget of two: twelve executed). The gate now
also writes a reservation at the instant of its decision, under the store's
own serialisation, and exactly the allowed number get through. The audit trail
is still what the console and `GET /v1/agents` report, and it still refuses
first with its own numbers; the reservation sits behind it and can only refuse,
never admit. Refusals are audited under the same `agent.budget_exhausted` /
`agent.token_budget_exhausted` actions with the same fields as before.

**A call parked for approval now holds a budget slot from the moment it is
requested.** Until now the trail counted approval-path work only once the
agent collected it and the approval path never re-checked, so an agent could
park any number of calls under a budget of one and have every one approved.
The slot is returned if the approver denies, the requester withdraws, or the
approval expires — a refused or failed call never consumes budget, as before.

### Added

- `agent_call_reservations` (migration `0050`) and
  `BrokerStore.ReserveAgentCall` / `ReleaseAgentCallReservation` — the
  compare-and-spend ledger. It holds at most one rolling window per agent and
  purges itself on write; nothing is written for an agent nothing limits.

### Changed

- A parked call holds its budget slot while it waits (see above).
- `Broker.SweepExpiredParked` returns the ids it evicted rather than a count
  (Go API only; the scheduler uses it to settle the reservations of expired
  approvals).

### Operational notes

- Fail-closed in every direction that matters: if the ledger cannot be read
  the call is refused (the rule the trail counts already followed); if a
  release fails, or a parked call is lost to a restart, its reservation stands
  until it ages out of the 24-hour window — the agent is under-served for a
  day, never over-served.

Helm chart `0.49.3` → `0.50.0`, a minor alongside an app minor. Image digest
`sha256:cc5ae871…` (the full value is in the README and on the release page).

## [0.58.3] — 2026-08-27

A patch that ships **Phase 217** — the 2026-08-26 audit's last deferred
test-coverage finding (M-6) closed, and the four backend divergences that
closing it exposed. **No schema, route or env-var change**, no upgrade note
that needs an action, and nothing an operator does changes: every fix is at
the store's own edges, on paths no API handler as written reaches. They ship
anyway, because a store used by the tests and a store used in production that
disagree is the highest-leverage class of bug this codebase has (the AF/AL
findings of 2026-07-30), and the rule since Phase 200 is that a differing
binary does not bank on `main`.

### Fixed

- **A denied session-share invite no longer keeps a token on PostgreSQL.**
  `DecideSessionShareInvite` stores `token_hash` and `expires_at` only on
  approval — as its contract always said and as the in-memory store always
  did. The API passes empty values on a denial, so no denial was ever
  redeemable; the stored row now matches the contract on both backends.
- **`CreateApprovalInvite` reports its constraints the same way on both
  backends**: `ErrNotFound` for an access request that does not exist,
  `ErrConflict` for a duplicate token hash — previously a raw SQLSTATE on
  PostgreSQL and no check at all in memory.
- **Deleting a target removes the approval invites of its access requests in
  the in-memory store**, matching PostgreSQL's `ON DELETE CASCADE` chain.
- **Session-share and approval-invite listings order deterministically** —
  `created_at` descending with an `id` tie-break on both backends (the
  in-memory sort was unstable and PostgreSQL had no tie-break).

### Changed

- The store contract suite (`internal/store/storetest`) covers every one of
  `store.Store`'s 218 methods: the twenty the 2026-08-26 audit found absent
  are in, and `Close` has its own `RunCloseContract`. Test-only; the CI job
  against live PostgreSQL runs it.

Helm chart `0.49.2` → `0.49.3`, a patch alongside an app patch. Image digest
`sha256:7367417a…` (the full value is in the README and on the release page).

## [0.58.2] — 2026-08-27

A patch that ships **the second security audit's fixes** — two HIGH, one
MEDIUM, three LOW, found by a fresh five-pass read of v0.58.1 one day after the
first audit's fixes shipped; the redacted record is
`docs/SECURITY-AUDIT-2026-08-27.md`. **No schema, route or env-var change**,
no upgrade note that needs an action — but two behaviours an operator will
notice, stated first.

**An account change now ends the sessions the account holds.** Deleting a user
(`DELETE /api/users/{id}`), deactivating one over SCIM (`active:false`), or
changing a user's role revokes every login session minted for that user — a
browser-extension token that lives for `PAM_EXTENSION_TOKEN_TTL_HOURS`, a
viewer token, a directory login — and kills their live proxied sessions,
audited as `session.revoked reason:user-deleted|deactivated|role-changed`.
Until now none of those paths did, so a deleted user's extension token kept
revealing secrets until it expired. Independently, the resolver refuses any
session whose local user row is inactive, so a deactivated user is cut off even
by a path that forgets to revoke.

**A session token now carries its user's IP allowlist and device binding.**
Only the per-user-token path ever copied them, so an extension or viewer token
of a local user was never network-restricted — the ADMIN-GUIDE's "enforced
everywhere that principal authenticates" was false for every session. It is
true now, and true on two doors that had run no source check at all: the
authenticated-only routes (`/api/me`, MFA enrollment) and the RDP/VNC viewer
tunnel.

### Fixed

- **A-1 — sessions outlived the account** (HIGH): see above. New
  `session.revoke_failed` audit action for the case the revoke itself fails
  (logged, audited, never reverses the account change).
- **A-2 — the web guest's bearer key was its roster id** (HIGH). A session-share
  guest was tracked under its raw key, so `GET /api/sessions/{id}/share/roster`
  served every `read_audit` reader the guest's live credential as `join_id`,
  and `session.share_kicked` wrote it into the audit trail — a supervisor could
  watch as the guest or, for `view_control`, type as the guest. **`join_id` is
  now the SHA-256 of the key**; it still targets `POST .../share/kick`, and it
  resolves to nothing when presented as a key. A client that had used `join_id`
  as a guest key was doing something it never should have been able to.
- **A-3 — session principals carried no allowlist or device binding** (MED):
  see above.
- **A-4/A-5 — two doors with a shorter checklist**: the `authenticated`
  middleware and the viewer tunnel now run the same source gates (IP allowlist,
  device fingerprint, posture) as `authz` and the proxies, through one shared
  function, so a gate added to one cannot miss the others — the shape the
  2026-08-26 audit's H-1/H-2 had, found in two more places.
- **A-6 — personal-safe integrity** (LOW). A plain `manage_targets` /
  `manage_credentials` profile could add a credential to, delete a credential
  of, or delete a target in someone else's personal safe. Refused now unless
  the caller is the safe's owner, a `can_manage` member, holds
  `unlimited_vault_access`, or is a built-in admin (a write reveals nothing,
  and provisioning a personal safe is an admin's job).

### Changed

- **Documentation.** The 2026-08-26 audit report moved to
  `docs/SECURITY-AUDIT-2026-08-26.md` (the repository root keeps its fixed
  file set); both reports are indexed in `docs/README.md` and linked from
  `SECURITY.md`. Three claims the audit found false are corrected in place.
  The README's verification commands gain a one-line tip for a Docker config
  that names a credential helper you do not have.

### Upgrade notes

None that require an action. Two to know: an existing browser-extension token
belonging to a user who is later deleted, deactivated or re-roled stops working
at that moment rather than at its expiry; and a session-share supervisor's
console reads the same roster — only the value of `join_id` changed.

Helm chart `0.49.1` → `0.49.2`, a patch alongside an app patch. Image digest
`sha256:89cfc84e…` (the full value is in the README and on the release page).

## [0.58.1] — 2026-08-26

**The artifacts for 0.58.0.** That tag exists and stays where it is — the Go
module proxy had already cached it (checked before deciding, as Phase 65c
taught), so re-pointing it would leave a permanent checksum mismatch for anyone
running `go get …@v0.58.0` — but its release pipeline failed *after the push*:
an image was pushed under `0.58.0` (and, until this release, `latest`) and then
the SBOM, the signature, both attestations and the GitHub Release never happened.
**An image exists under `0.58.0` that nothing verifies. Do not deploy it.**
0.58.1 is the same source plus the one pipeline fix, and it is what every
manifest pins. Everything the `[0.58.0]` entry below describes ships here.

- **The release workflow no longer builds the image reference from
  `github.repository`.** The repository was renamed `PAMv1` alongside the
  display-name change below, and `github.repository` followed — but an OCI
  reference must be lowercase. `docker/metadata-action` lowercases the tags it
  emits, so the build and push succeeded; `Generate SBOM`, `cosign sign` and
  both attestations assemble their reference from the raw variable, and the
  first of them refused `ghcr.io/morandeirachema/PAMv1@sha256:…`. The name is
  now lowercased once, in a step that also *refuses* an uppercase result, and
  that step runs in the `workflow_dispatch` rehearsal too.
- **The README's verification commands** accept the repository's case in the
  signing identity (`(?i)` on `--certificate-identity-regexp`; the repository's
  real name on `gh attestation verify --repo`). The image name stays lowercase.
- **The release checklist gained the clause it was missing.** "`.github/`
  untouched since the last tag, so no rehearsal" had been the rule since v0.11.2
  and was applied correctly here — the diff was empty. A workflow reads its
  environment as well as its file, and the environment changed under an
  unchanged file. A rehearsal is now due when anything the workflow *reads* has
  changed, and the repository's name is on that list.

Helm chart `0.49.0` → `0.49.1`, a patch alongside an app patch. No Go source,
schema, route or env var changed between `v0.58.0` and this tag.

**Digests.** 0.58.1 is `sha256:67e9ee72…` (the full value is in the README and on the
release page); the unsigned image under 0.58.0 is `sha256:77c8dba0…`. They differ,
as the v0.57.1 note explains any two builds here will, and the second one is how
to recognise the image not to run: `docker inspect --format '{{index .RepoDigests 0}}'`
on what you have deployed.

## [0.58.0] — 2026-08-26 · unsigned image only, superseded by 0.58.1

> **Do not deploy `0.58.0`.** Its pipeline failed after the image push and before
> the SBOM, signature, attestations and GitHub Release — see `[0.58.1]` above,
> which ships exactly the content described here, verified. The unsigned image's
> digest is `sha256:77c8dba0633738545af269508dd37188bfafb8aee0a1c1608efa5975916b252b`.

A minor that ships a **security audit's fixes**: one CRITICAL, five HIGH and every
MEDIUM but one, from a five-pass read-only audit of v0.57.1 whose redacted record
is `docs/SECURITY-AUDIT-2026-08-26.md`. Migration high-water `0048` → **`0049`**,
**one new env var**, no new route — and **four upgrade notes, the first of which
can refuse a startup**. Read those before pulling the image.

The CRITICAL is the one to understand. The PostgreSQL proxy reads its wire
protocol through `pgproto3`, whose default message-body bound is *none*, and the
proxy never set one — so an unauthenticated peer could declare a ~2 GiB password
body, and the connection rate limiter, which ran *after* that read, never saw it.
Nothing was wrong in the cryptography or the authorization model; the audit's
dominant theme was **entry points that re-implemented a check and drifted from
the canonical one**, and four of the defects were introduced by v0.56.0 and
v0.57.0 themselves — which is the strongest argument for the audit having
happened. The fixes are mostly one function called everywhere rather than new
machinery, and each carries a regression test, most pinned by mutation.

### Fixed

- **C-1 — unauthenticated ~2 GiB allocation on the PostgreSQL proxy.** The
  `pgproto3` backend is now built by a constructor that cannot forget the bound:
  64 KiB before authentication (a password is the only message an unauthenticated
  peer may send), 64 MiB in session (query text, bind parameters, COPY data). The
  rate limiter runs before the first read.
- **H-1/H-2 — narrow-scope tokens opened the sessions they existed to prevent.**
  A leaked browser-extension token opened SSH, database and desktop sessions, and
  an `mfa_pending` token opened a desktop, because four entry points each
  re-implemented "is this token narrow?" over a different subset of the scope
  fields. One `auth.Principal.MayOpenSession`, called by both proxies, the desktop
  and the viewer tunnel — a whitelist of two (a full session, or exactly the scope
  that door is for), so a scope added later is refused by construction.
- **H-3 — DoubleLock.** The second password guards `DoubleLockEnc`, a copy of the
  secret deliberately outside the vault KEK — and it was checked only for being
  non-empty, at 100 000 PBKDF2 iterations. Now: a **minimum length of 16**
  (`PAM_DOUBLELOCK_MIN_LENGTH` raises it; nothing lowers it), **600 000
  iterations** (the OWASP figure), and the count stored per record so every
  existing lock still opens at the count it was sealed with.
- **H-4/H-5 — the SQL Server broker's per-statement audit could be forged.** A
  128-character parameter name was read as a batch separator (the statement was
  never recovered, and still executed), and `sp_executesql` audited the wrong
  parameter. Both fixed and mutation-pinned.
- **The four defects v0.56.0 and v0.57.0 introduced** (T-1..T-4): the per-token
  ceiling never counted calls routed through approval — the resume handlers never
  wrote the field the count searches for, so an agent routing calls through
  approval was charged nothing (one shared `resumeDetail` on both transports now);
  the token exchange never checked the actor token's `cnf`, so a captured bound
  token could buy its victim's identity; the replay cache's per-replica scope was
  undocumented; and `PAM_BROKER_PUBLIC_URL` did not actually refuse startup
  without its prerequisite, though four documents said it did.
- **M-1/M-2 — audit-detail injection.** `auditfmt.Field` quotes but does not
  escape colons, so five wire-sourced values (the SSH subsystem name, both DB
  proxies' database name, the resolve reason, the login actor) could forge
  `key:value` pairs into the trail that the playback tamper check and the SIEM
  forwarder parse. New `auditfmt.Value` generalises the fix the SFTP path handler
  already used.
- **M-4** — a racing approve could overwrite a final deny; decisions are now
  compare-and-set on `pending` in both backends. **M-5** — personal-safe privacy
  was bypassable three ways by a plain target manager (reassign the safe, delete
  it, self-grant); one fail-closed guard covers all three. **M-7** — SFTP
  `SSH_FXP_LINK` checked neither path and `SSH_FXP_SYMLINK` only one, so a link
  laundered a denied path; both paths of both ops are checked in every mode.
  **M-8** — channels per authenticated SSH connection capped at 64. **F-5** — a
  SCIM connector could deactivate or reactivate an admin; admin lifecycle is not
  delegated to an IdP, and the swallowed activation error now surfaces. **F-8** —
  scope refusals in the authenticated middleware now audit as `authz.denied`.
  Plus a bound on the upstream SCRAM iteration count (600 000) and a case-folded
  private-JWK check.

### Added

- **`PAM_DOUBLELOCK_MIN_LENGTH`** (default `0` = the built-in floor of 16,
  maximum `1024`): minimum length of a DoubleLock password at enable time. It can
  raise the floor and never lower it — a misconfiguration cannot weaken the
  control below what the audit set.
- **Migration `0049`** — a partial unique index, `agent_keys_active_name_unique`:
  at most one *active* agent key per name. The per-agent budget and the audit
  actor key on the name, and only the token hash was unique, so two keys could
  share a name and pool one usage count under two different `budget_per_day`
  limits with indistinguishable audit rows. Revoking a key and minting a fresh
  one under the same name still works; the revoked row is outside the index.

### Changed

- **The product's display name is `PAMv1`.** Prose, portal and extension text,
  doc comments, error and log display strings, transcript and IaC-export headers,
  the alert e-mail subject, the syslog tag default, the CEF/LEEF vendor field, the
  OCSF `product` and the TOTP issuer. Every machine identifier stays `pamv1` —
  module path, image name, Kubernetes/Helm names and labels, env-var values, the
  SSH-certificate KeyID, the SAML EntityID, hostnames — because those must.
- **Documentation currency.** The audit phase had bumped every `Reflects:` header
  without documenting itself: `PAM_DOUBLELOCK_MIN_LENGTH` was in no document,
  migration `0049` was attributed to the wrong phase in one doc and absent from
  another, and the DoubleLock hardening was recorded nowhere an operator reads.
  All closed in this release.

### Upgrade notes

1. **Migration `0049` refuses to apply — and the server refuses to start — if
   two *active* agent keys share a name.** Before upgrading, check
   `SELECT name, count(*) FROM agent_keys WHERE disabled = FALSE GROUP BY name
   HAVING count(*) > 1;` and disable (revoke) all but one of each set. A
   deployment that never minted two keys under one name is unaffected, and a
   fresh install has nothing to check.
2. **A new DoubleLock password must be at least 16 characters.** Locks already
   set keep working unchanged — they open at the iteration count they were
   sealed with; only *enabling* DoubleLock is gated. To reseal an existing lock
   at 600 000 iterations, disable and re-enable it.
3. **SIEM rules keyed on the vendor field.** CEF and LEEF lines now carry
   `PAMv1` where they carried `pamv1`, the syslog tag default follows, and the
   OCSF `product.name` / `vendor_name` likewise; a rule that matches the old
   literal case-sensitively needs the new one.
4. A TOTP factor enrolled from now on is labelled `PAMv1` in the authenticator
   app. Existing enrollments are unaffected — the issuer is a label in the
   provisioning URI, not part of the secret.

## [0.57.1] — 2026-08-26

**A version bump with no functional change.** Cut deliberately, on request, and
recorded as such rather than dressed up: the only commits between `v0.57.0` and
this tag are the two that wrote v0.57.0's own image digest into `ROADMAP.md` and
`README.md`. No Go source, no schema, no route, no env var, no dependency.

**What that means for you: nothing.** The binary in `0.57.1` behaves exactly as
the one in `0.57.0`. If you are running v0.57.0 there is no reason to move, and
if you pin by digest you may ignore this release entirely. Every manifest in the
repository has been repointed at `0.57.1` so the shipped examples stay
self-consistent, which is the only practical effect.

**Why it is a patch and not a minor.** Nothing was added. Semantic versioning
asks what changed in the artifact, and the honest answer here is "the build
metadata", so the patch component is the one that moves. The Helm chart follows
with a patch of its own (`0.48.0` → `0.48.1`) rather than a minor, matching how
v0.54.1 was handled.

**Note for anyone comparing digests — and this happened.** v0.57.1 published
`sha256:279a5d8b…` where v0.57.0 published `sha256:75a2a43d…`. The image here
does NOT have the same digest as v0.57.0 despite being built from equivalent sources — this build
is not bit-reproducible across runs, which v0.55.0 demonstrated when a pipeline
re-run produced a different digest from the same commit. A differing digest
between these two tags is expected and is not evidence that something changed.

### Changed

- Deployment pins, the Helm chart, both READMEs and the documentation set moved
  from `0.57.0` to `0.57.1`.

### Upgrade notes

None, and none needed. This release exists to move a version number.

## [0.57.0] — 2026-08-26

A minor that bounds **one credential** rather than one agent. The per-minute rate
limit bounds a burst and the daily budget bounds a total; neither bounds the case
an operator actually worries about when handing a sub-agent a delegated token —
that the token quietly does two hundred things. **No schema change** (migration
high-water stays `0048`), no new route, **one new env var**, **no upgrade note**.

### Added

- **`PAM_BROKER_MAX_CALLS_PER_TOKEN`** (default `0`, off): cap how many brokered
  calls may be spent while presenting **one token**.

  When a token reaches its ceiling the agent is told so plainly — a denial with a
  reason, not a 401, because the credential is valid and has simply spent its
  allowance — and **a new token starts a new ceiling**. The control retires a
  credential; it does not punish an agent.

  **It is keyed on the token's `jti`, not on the caller's declared `session:`.**
  That distinction is the feature. `session:` is chosen by the party being
  limited, so a ceiling built on it is escaped by sending a different string; a
  `jti` is chosen by the issuer — PAMv1 itself for a delegated token — so a fresh
  allowance costs a trip back through the exchange, which is audited,
  depth-capped, `may_act`-gated and, since v0.56.0, able to require proof of
  possession.

  **Two identity kinds are deliberately not covered**, and are left to the
  per-day budget instead: a static agent key carries no token id at all, and
  neither does an SVID whose issuer stamped no `jti`. "Unlimited" is the correct
  answer for an identity this control cannot see, and an operator should not have
  to discover that by experiment.

- **`agent.token_budget_exhausted`** and **`agent.token_budget_check_failed`**
  join the audit vocabulary. The first is a fact worth alerting on directly — it
  reads as a runaway sub-agent as often as it reads as a ceiling set too low —
  and carries the `svid_jti:` of the token in question, so the refusal joins to
  the calls that spent it and to the `broker.token.exchanged` row that minted it.
  The second is the fail-closed record: an unevaluable ceiling refuses the call
  rather than reading as no ceiling.

### Changed

- **Documentation currency.** Eight documents had stalled at `Phases 0–205`,
  because the two preceding releases each bumped only the headers that were
  already current — a sweep keyed on the newest range cannot see a document that
  never reached it. Both READMEs had also gone on defining beta as "every phase
  through 52g has shipped", true when beta was declared and quietly wrong for 150
  phases since.

- **Three refusal actions reached the documented audit vocabulary**, two of which
  appear as a literal nowhere in the source: `gateCredentialAccess` audits its
  action argument *plus* `_denied`, so `credential.doublelock_enable_denied` and
  `credential.doublelock_disable_denied` had been emitted since v0.35.0-era work
  while being invisible to every audit that grepped for literals.
  `credential.checkout_extend_denied` was simply missed. A guard test now
  reconstructs these names the way the code assembles them.

### Upgrade notes

None. `PAM_BROKER_MAX_CALLS_PER_TOKEN` defaults to `0`, which is the behaviour
every existing deployment already has. Set it per deployment once you know what a
normal task costs — and note that it is a *second* limit rather than a
replacement: the daily budget still applies, and whichever refuses first wins.

## [0.56.0] — 2026-08-26

A minor that makes a delegated AI-agent token **stop being a bearer credential**.
Until now, anything that captured one — a log line, a crashed process's
environment, an over-broad container mount — *was* that sub-agent until the token
expired. It can now be bound to a key, so holding the token is no longer enough.
**No schema change** (migration high-water stays `0048`), no new route, **two new
env vars**, **no upgrade note**.

### Added

- **Proof of possession for delegated agent tokens** —
  [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) (DPoP) over
  [RFC 7800](https://datatracker.ietf.org/doc/html/rfc7800)'s `cnf` claim and
  [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638)'s JWK thumbprint.

  `POST /v1/token` accepts a new `cnf_jkt` parameter naming the thumbprint of the
  key the sub-agent holds, and stamps `cnf: {"jkt": …}` into the issued token.
  Every call presenting that token must then carry a `DPoP` header — a short JWT
  signed by the matching private key and scoped to this request's method and URI,
  this token, and one use. `Authorization: DPoP <token>` is accepted alongside
  `Bearer`; which scheme was used is never consulted, because the `cnf` claim
  inside the token decides whether a proof is demanded, not a header word the
  caller chose.

  **`cnf_jkt` is a PAMv1 extension and is documented as one.** RFC 8693 defines no
  such request parameter, and RFC 9449's own binding flow has the *client* prove
  its key at the token endpoint — which cannot apply here, since the party calling
  the exchange is the delegator, not the sub-agent that will hold what it mints.

  **What this establishes, precisely:** the delegator names the key, so PAMv1
  cannot verify that the key belongs to the sub-agent rather than to the delegator
  itself. What is gained is that a token lifted off the wire or out of a log is
  useless without the private key. That bounds the blast radius of token *theft*;
  binding a credential to the process holding it is workload attestation, and
  stays SPIRE's job.

- **`PAM_BROKER_REQUIRE_POP`** (default `false`): refuse an SVID-authenticated
  agent whose token carries no binding, turning sender-constrained tokens from
  available into mandatory. **Bind your tokens first, then set the flag** — with
  it on, every unbound token already in circulation is refused. Static agent keys
  carry no claims and so are exempt by construction; the way to stop accepting
  bearer agent keys is to stop configuring them.

- **`PAM_BROKER_PUBLIC_URL`**: the base origin agents address the broker at, which
  a proof's `htu` claim is compared against. **Set it whenever anything terminates
  TLS in front of PAMv1** — otherwise the request arrives as plain HTTP on an
  internal name while the client signed the external URL, and every key-bound
  agent is refused. `X-Forwarded-*` is deliberately never consulted: letting a
  caller choose what its own proof is checked against would remove the check.

  Both variables fail the startup loudly when their prerequisite is absent — a
  sentence that was true of `PAM_BROKER_REQUIRE_POP` and, until Phase 212, false
  of `PAM_BROKER_PUBLIC_URL`, which checked only its URL shape — the
  same idiom the other broker refusals already use.

- **`agent.pop_denied`** joins the audit vocabulary, carrying a `reason:` naming
  which check failed (`proof-header-missing`, `proof-replayed`,
  `proof-not-bound-to-this-token`, `proof-key-is-not-the-bound-key`,
  `token-not-key-bound`, …) behind the same opaque 401 a bad bearer credential
  gets. It also scores as a blocked command in the risk engine: to be refused
  here, a caller had to present a token whose signature, audience, expiry and
  trust domain all verified and merely fail to prove key possession — which is the
  signature of a stolen token being spent.

### Upgrade notes

None. An unbound token behaves exactly as it did before, pinned by its own test,
and both new variables default to off. Adoption is per token, at the mint: pass
`cnf_jkt` for the agents you want bound, and set `PAM_BROKER_REQUIRE_POP` only
once they all are.

Two behaviours to know before enabling it. A **bound delegator cannot mint an
unbound token** — if the delegating token carries a `cnf`, `cnf_jkt` is required
on the next exchange, so the constraint cannot be walked off one hop down. And a
confirmation PAMv1 cannot enforce (RFC 7800 also defines `jwk` and `kid` forms)
**refuses the token** rather than reading as "unbound", since treating an
unreadable binding as no binding would downgrade a token its issuer deliberately
constrained.

## [0.55.0] — 2026-08-25

A minor that closes **two estate-wide defaults** — the kind of thing that is not
a bug in any single place, and is therefore easy to leave alone indefinitely.
Both are narrowing, and one is opt-in because turning it on is a real change for
a running estate. **No schema change** (migration high-water stays `0048`), no
new route, **one new env var**, **no upgrade note**.

### Added

- **`PAM_REQUIRE_TARGET_GRANT`** (default `false`): refuse a connection to a
  target that has **no grants at all** — no direct grant, and not in a safe with
  members.

  Until now such a target was reachable by *every* connect-capable principal,
  human or agent. That is an estate-wide default rather than a decision anyone
  made about a particular system, which is why the reachability review has
  rendered those targets in red since it shipped. **False stays the default**, so
  upgrading changes nothing: this is a decision an operator makes, not one taken
  underneath them.

  **The migration path is the review itself.** Open console menu **31** (or
  `GET /api/access/reach`), see how many targets are reachable for reason `open`,
  grant those deliberately, then set the flag. The answer now also reports which
  policy is in force, because an `open` row means opposite things under each and
  an empty open-count is otherwise indistinguishable from a policy that makes one
  impossible.

  Admins still bypass, deliberately: that is an explicit decision about a role,
  where "nobody got round to restricting this target" is not a decision at all. A
  safe-scoped target with no members was already default-deny and is unaffected.

### Changed

- **An AI agent is no longer handed the whole toolset.** MCP `tools/list`
  returned the entire registry to every agent, so one permitted only `ssh_exec`
  was still told that `winrm_exec` and `reveal_credential` exist. Policy refused
  the call — the listing had already described the surface. It is now filtered to
  what policy could *ever* allow that identity.

  **This narrows a listing, never a call.** `tools/call` is unchanged and still
  evaluates policy in full, so a tool that survives the filter can still be
  refused, and a tool removed by it can still be invoked by name — an agent that
  already knows the name loses nothing. What is removed is a map, not a door, and
  the code says so rather than implying a boundary it does not provide.

### Upgrade notes

None. `PAM_REQUIRE_TARGET_GRANT` defaults to `false`, which is the behaviour
every existing deployment already has. The `tools/list` change is visible to
agents immediately but cannot refuse anything `tools/call` would have allowed —
if a deployment runs no policy engine, every tool is still listed.

## [0.54.1] — 2026-08-25

A patch, cut because v0.54.0 is the only release that carries the External
Secrets Operator backend and it carried a defect in it. **No schema change, no
new route, no new env var, no upgrade note** — upgrade in place.

### Fixed

- **An alias could be planted on another application's grant.**
  `POST /v1/apps/{id}/grants/{gid}/alias` parsed only the grant id and ignored the
  application in the route, so naming grant 14 under application 7 renamed
  **application 12's** grant and answered `200`. A mistyped or stale grant id
  therefore handed a different application a stable, git-committable name for a
  credential nobody meant to expose, while the operator read success.

  **Not an escalation** — the route requires `reveal_secret`, so the caller is
  already privileged, and no access was created that did not already exist. What
  was wrong is that a privileged operator's mistake landed silently on the wrong
  object and reported success. The handler now resolves the grant within the named
  application and answers `404` otherwise, exactly as revoking a grant already did.
- **`archgen` published two authenticated routes as unauthenticated again.** Its
  wrapper scan returns on first match and `rateLimit(` was one of the entries, so
  it absorbed whatever it wrapped: `POST /api/webauthn/login/{begin,finish}` are
  `rateLimit(mfaPendingOnly(…))`, and `mfaPendingOnly` resolves the presented key
  and refuses an invalid one, yet the generated API-surface table called them
  `public (rate-limited)`. Rate limiting is now treated as a modifier and the
  wrapper inside it is classified on its own. No route's actual authorization
  changed — this is the security map describing a control it does not have, the
  same class v0.54.0's own Phase 195 entry fixed.
- **Revocation semantics on the ESO path are now described accurately.** Revoking
  an application's grant removes its alias, so the by-alias route answers `404`
  and an External Secrets Operator **deletes the Kubernetes Secret it manages**.
  That is the intended behaviour — revocation should propagate — but the code
  comment, a test name and the operator checklist in `deploy/k8s/eso/README.md`
  all claimed the opposite. What must never delete is a *transient* refusal, such
  as the reveal kill switch, which answers `403`; that case now has its own test
  on the route it applies to.
- **A 3.7 MB compiled binary is no longer committed at the repo root.** `archgen`
  had been tracked since the v0.54.0 development cycle; `go build ./cmd/archgen`
  writes exactly that path, so any contributor following the build instructions
  got a dirty tree and could re-commit a stale executable. Removed and gitignored.

### Changed

- The alias audit detail records the application id alongside the grant.
- `deploy/k8s/eso/secretstore.yaml` now states plainly that the reference
  Kubernetes deployment serves **plain HTTP** on `8080` while the manifest is
  `https://`, and what to do about it. The URL stays `https://` deliberately: the
  endpoint hands out plaintext secrets, and defaulting the example to `http://`
  would make the insecure path the easy one.

## [0.54.0] — 2026-08-25

A minor whose one user-facing feature answers a question this project could not:
**how does a workload running in Kubernetes get a secret out of PAMv1?** It could
already seal its *own* secrets into a cluster, and already brokered privileged
*access to* Kubernetes Secrets as discrete audited operations — but it was not a
**source** of secrets for the workloads there. Now it is, through External
Secrets Operator. **Schema change** — migration `0048`, one additive nullable
column; applied on startup, no backfill, **no upgrade note**. Two new routes, one
new console screen, no new env var.

The rest is the review that preceded it, and a flaky test that finally said why.

### Added

- **PAMv1 as an External Secrets Operator backend** (Phase 197). An application
  grant can carry a stable **alias**, and `GET /v1/app-secrets/by-alias/{alias}`
  fetches by that name — so an ESO `SecretStore` can reference a secret from a
  manifest held in git. Set one with `POST /v1/apps/{id}/grants/{gid}/alias`
  (`reveal_secret`), or console option `8` on a grant row (`PAMAPPALS`).

  The alias lives on the **grant**, not the credential: the grant must exist for
  access anyway, so naming it adds no authorization surface; it is scoped per
  application, so two apps may call the same credential different things; and
  `credentials` has no uniqueness on `(target_id, username)` to name against.
  Resolution runs inside the calling app's own grants, which makes the lookup the
  authorization check as well.

  **The status codes are a contract, and one of them is destructive**: ESO reads
  `404` as "this secret was deleted" and removes the Kubernetes Secret it
  manages. An undefined alias is `404` — correct, it is gone — while a revoked or
  never-granted credential is **`403`, never `404`**.
- **Working manifests and a cluster checklist** in `deploy/k8s/eso/` — a
  `SecretStore` and `ExternalSecret` pair carrying no secret material, and a
  README ending in what to verify against a real cluster.
- **Migration `0048`** — `alias` on `app_secret_grants`, unique per application
  where set. Nullable, so every existing grant keeps working unchanged and stays
  addressable by credential id.
- `app.grant_alias_set` and `app.grant_alias_cleared` join the audit vocabulary;
  the alias also rides in `app.secret_retrieved`'s detail.

### Fixed

- **The generated API-surface map called sixteen authenticated routes `public`**
  (Phase 195). `docs/ARCHITECTURE-DIAGRAMS.md` §3 is what a reader consults to
  see what guards each route, and it is CI-gated for drift — so it was guaranteed
  current and guaranteed wrong at once. The generator classified routes by
  pattern and **fell back to `"public"`** for anything it did not recognise, and
  three authentication schemes added later were never taught to it: the whole
  AI-agent tool-call surface, the whole SCIM surface (which creates and deletes
  users), the application-secrets route, and five token-authenticated guest
  routes. **No route was ever unprotected** — this was the document misdescribing
  a control. Nineteen rows corrected, and the classifier now **refuses to guess**:
  an unrecognised wrapper stops the generator, which CI runs.
- **A test that failed about once in a hundred runs, now understood** (Phase 199).
  `TestSessionForensicsEndToEnd`'s audit fixture stamped its records to a whole
  second while the forensic window filter allows one second of clock slack, so
  the record survived only when the rounding loss plus the setup delay stayed
  under that second. Reproduced deterministically before being changed. The
  fixture now carries the millisecond component auditd actually emits, and the
  slack itself is pinned at its edges rather than leaned on by accident. No
  production code was involved.

### Changed

- **What each non-human credential reaches is now a written list** (Phase 196).
  An agent key, an IdP's SCIM token and an application key pass **no capability
  check** — the middleware authenticates the bearer and hands off — so the set of
  routes each reaches *is* the authorization boundary for it. That set is now
  recorded route by route with a reason, and checked in both directions so a
  stale entry fails too. Also pinned: browser-extension tokens reach exactly one
  route, a scoping that had lived only in a code comment; and no state-changing
  route may be reachable with no credential at all.

### Upgrade notes

None. Migration `0048` is additive and nullable and applies on startup; existing
application grants keep working and stay addressable by credential id, with the
alias purely opt-in.

## [0.53.0] — 2026-08-25

Three phases, and two of them exist because the release before them was
reviewed rather than trusted. **No schema change** (migration high-water stays
`0047`), no new route, no new env var, **no upgrade note** — but the Go toolchain
that builds the published image moved to **1.27**, and the reachability review
shipped in v0.52.0 gained the half it was missing and then had that half
corrected.

### Added

- **The reachability review says whether the subject could actually use what it
  reaches** (Phase 191). `GET /api/access/reach` gains **`blocked`** — every
  reason the subject cannot exercise its standing reach right now, drawn from the
  subject and never from a target: `no_usable_capability`, `deactivated`,
  `key_disabled`, `key_expired`, `quarantined`, `not_enrolled`, and (Phase 193)
  `budget_zero` and `quarantine_unknown`. Console menu **31** prints them in red
  above the target list.

  The targets and the total do **not** change when it is non-empty. That is
  deliberate: a suspended account's grants are still grants and come back the
  moment somebody flips it on, which is exactly why they are worth reviewing. But
  "reaches 40 targets" and "would reach 40 targets if it could log in" are
  different findings, and until now they looked identical.
- **`auth.CanUseAnyTarget`** supplies the half `CanConnectTarget` structurally
  cannot: that function does not consider capabilities at all — every call site
  checks them separately, at the door — so the review reported an **auditor**
  reaching every ungated target, for a role that can never open a session, reveal
  a secret or call a tool.
- **`GrantStore.ReachGrantSnapshot`** (Phase 193) returns the subject's grants and
  the gated-target set from **one consistent view** — a read-only `REPEATABLE
  READ` transaction in PostgreSQL, one lock hold in the in-memory store.

### Fixed

- **A review flag that pointed the wrong way** (Phase 193). `not_enrolled` was
  reported for every unclaimed attested identity, while being unenrolled only
  *blocks* when `PAM_BROKER_REQUIRE_ENROLLED_SVID` is on — and that defaults to
  off. On a default deployment the identity in question authenticates and reaches
  every ungated target, yet the console painted it red as already stopped. A
  review surface that misleads is a control failure of its own kind. Now
  conditional on the flag, with a test on each side of it.
- **A grant race that could name a just-revoked target** (Phase 193). The two
  grant reads behind the answer are only meaningful against each other, so
  ordering them cannot make them correct — it only moves the window. Reading the
  gated set first reported a newly restricted target as `open`, reachable by
  anyone; reading grants first reported a revoked grant as still admitting a
  target, and the AI-agent broker's own inventory listing runs on that path. Both
  are closed by taking the pair from one snapshot, pinned by a concurrent-writer
  test rather than by argument.
- **An unreadable quarantine table read as "nothing stops this agent"** (Phase
  193): a store error was swallowed and rendered as an empty `blocked`,
  indistinguishable from a clean bill of health. It now reports
  `quarantine_unknown`.
- **An expiry comparison that disagreed with the authoritative one** (Phase 193)
  at exactly the boundary instant — a hand-written second copy of a security
  predicate, now decomposed from `store.AgentKey.Active` instead of re-derived.
- **An agent key with a per-day budget of `0` was not reported as stopped**
  (Phase 193). Zero is a deliberate administrative hard stop, distinct from an
  unset budget, and it stops the subject exactly as a disabled key does.

### Changed

- **The published image is built with Go 1.27** (Phase 192), and so are the tests
  that gate it. A dependency bump had moved both Dockerfiles to `golang:1.27`
  while every CI job and both release jobs still ran Go 1.26 — so the release
  would have attested a container compiled by a toolchain no test exercised, with
  `pam-agent` binaries built by a *different* compiler attached beside it. Nothing
  in CI compares those two halves, so it went green. Not exploitable on its own;
  provenance is most of what a signed release claims.
- **The Terraform module and the README's digest no longer lag the release**
  (shipped in v0.52.0, restated because both were long-lived): the module's
  default image had been 23 releases behind, and the README's Status block quoted
  an image digest from nine releases earlier. The digest is now recorded in the
  README alongside `ROADMAP.md` in the same pass, so the two move together.

## [0.52.0] — 2026-08-25

A minor that ships one phase, closing a question PAMv1 could not answer about
itself: **every grant lookup it had was target-indexed**. `EffectiveTargetGrants`
is exactly what a connect gate needs and exactly the reverse of what a reviewer
needs, so "what can this agent reach?" could only be answered by walking the
whole estate and re-deriving each decision by hand. Now it is one query, one
route and one console screen — and it reports not just *which* targets but
**why** each one is reachable. **Schema change** — migration `0047` (two plain
indexes; applied on startup, no backfill, no downtime). One new route, one new
console screen, no new env var, **no upgrade note**.

### Added

- **"What can this subject reach?"** (Phase 189).
  `GET /api/access/reach?subject=&kind=user|agent` answers for a local user or
  either AI-agent identity kind, gated on `CapReadAudit` — the same gate as the
  audit trail it complements — and audited `access.reach_query`. Each target
  comes back with the **reason** it is reachable: `admin`,
  `unlimited_vault_access`, `open`, `grant` or `safe`. The reason is the point: a
  yes/no gate can say a subject reaches 40 targets, only this can say 37 of them
  are reachable because nobody decided anything.
- **The grant relation, readable backwards.** `GrantsForSubjects` returns every
  grant naming any of a principal's identifiers — its username plus each role it
  holds — each row carrying the target it reaches and the path it came from
  (`grant` / `safe`); `GatedTargetIDs` returns the targets anything gates at all,
  which is what separates an **open** target from an unreachable one, a
  distinction the subject-side rows alone can never make because an open target
  has no row. `auth.ReachableTargets` composes them into the whole answer in
  **four reads regardless of estate size**.
- **An agent in no registry is answered, not refused** — `known:false` plus the
  targets nothing gates, because "any workload in the trust domain reaches these"
  is precisely the question an identity inventory leaves open, and refusing it
  would hide the finding. A directory-authenticated identity returns `404`
  instead: its roles are decided by group mapping at login, and answering with
  the built-in defaults would be inventing an identity.
- **Console menu 31 (`PAMSUBRCH`)**, plus option `5` on a user row (menu 8) and
  option `8` on an agent-key row (menu 26) — the two places somebody is already
  looking at the subject. `open` renders red, because it is the finding rather
  than the happy path.
- **Migration `0047`** indexes `target_grants` and `safe_members` on
  `(subject_type, subject)`. A subject-indexed query with no subject index is a
  sequential scan of both tables on exactly the estate size where the question
  starts to matter.

### Changed

- **The broker's own inventory listing stops paying per-target reads.**
  `agentVisibleTargets` re-derived the decision with **two store reads per
  target** on every `list_targets` call, a cost accepted in writing because no
  subject-indexed query existed. It now goes through the same path as the new
  route — the payoff rather than a side-effect: the query exists *and* the hot
  path that needed it uses it.

### Fixed

- **The Terraform module deployed a 23-release-old image.**
  `deploy/terraform/variables.tf` defaulted `image` to
  `ghcr.io/morandeirachema/pamv1:0.28.0` and had not moved since v0.28.0, so
  `terraform apply` with the module's own default installed a version from
  2026-08-14 while every other manifest pinned the current one. Now `0.52.0`,
  like the rest. The release checklist's sweep — one `grep` over `deploy/`
  requiring exactly one release to appear — is what found it, which is the
  argument for keeping a check that cannot go stale over a list of places that
  can.
- **The README quoted the wrong image digest for nine releases.** Its Status
  block — the one a reader follows to verify a release's provenance — carried
  `sha256:0562b828...`, which is **v0.42.0's** digest, while the version label
  beside it moved from v0.43.0 all the way to v0.51.0. The cause is structural:
  the digest-recording pass that runs after each tag only ever updated
  `ROADMAP.md`, and the README's copy cannot be correct when the release PR is
  written because the digest does not exist until the tag is pushed. The README
  now says the digest is recorded once the workflow has run, and it is part of
  the recording step, so it moves with the release instead of behind it.
- **Four releases were unlinkable from the CHANGELOG.** The reference-link block
  at the bottom stopped at `0.47.0`, so the `[0.48.0]`–`[0.51.0]` headings above
  it rendered as literal brackets, and `[Unreleased]` compared against `v0.47.0`.
  All five links restored and the compare re-pointed.

## [0.51.0] — 2026-08-21

A small minor with one theme: **three capabilities that had shipped with an API
and no way to use them from the portal**. No schema change, no new env var, no
new route, no upgrade note — only screens that should have existed and a test
that will notice next time.

### Added

- **DoubleLock is operable from the console** (option `10` on the credentials
  screen). Turning it off is immediate; turning it on collects the holder and
  password on a new `PAMDBLLCK` screen, and the credential listing gains a
  DoubleLock column so the state is visible before somebody wonders why a reveal
  is asking for a second password. Shipped in v0.30-era Phase 135 with routes and
  a curl command.
- **SCIM client keys are operable from the console** (menu **29**): mint, list
  and revoke the bearer identity an IdP presents to `/scim/v2/Users`, with the
  token shown once exactly as an agent key is. Shipped in Phase 149 the same way.
- **A browser-extension token can be minted from the console** (menu **30**),
  rather than from a curl command in the admin guide — a strange thing to have
  asked of the person whose browser it is for. Shipped in Phase 147.

### Fixed

- **The parity claim is now enforced, not asserted.** PAMv1's README and roadmap
  say every shipped capability is operable from the portal; that was last checked
  by hand in Phase 45, and three phases had shipped past it.
  `web.TestConsoleCanReachEveryOperatorRoute` diffs the generated route table
  against the console's own calls, and a route behind an operator capability must
  either be reachable or carry a written reason why a person is not expected to
  use it.

## [0.50.0] — 2026-08-21

A minor that finishes the AI-agent-broker batch's research backlog — posture on
the agent path, `may_act` actually issued, the approver's view of a delegation —
and then spends three phases auditing the batch itself, which is where most of
this release's value is. **No schema change.** One new env var. **Three upgrade
notes**, one of which can stop a deployment from starting.

### Added

- **Device posture reaches AI agents** (Phase 180). `PAM_BROKER_POSTURE_REQUIRED`
  (default `false`) asks the posture webhook already configured for human
  operators about agent identities too. A human's laptop had to prove its health
  on every authenticated call while an agent container passed on a bearer token
  alone. The check runs **last** among the admission gates, so a quarantined or
  unenrolled identity is refused locally and never becomes traffic your EDR
  system absorbs; the webhook body gains a `kind` field (`user`/`agent`) so a
  receiver can branch instead of guessing. What it proves is narrower than for a
  laptop, and the docs say so: the webhook answers about a *name*, not about the
  process holding the credential.
- **A delegated token can pin its next hop** (Phase 181). `POST /v1/token`
  accepts `may_act` — a PAMv1 extension parameter, since RFC 8693 defines the
  claim and no request field for it — and writes it into the issued token, which
  the next exchange enforces. PAMv1 had enforced that claim since delegation
  shipped and never issued it, so beyond the first hop the check had nothing to
  read.
- **The approver sees the delegation** (Phase 183). `GET /v1/approvals` carries
  `actor_chain`, and console menu 20 shows a **HOPS** column — a direct call and
  one that arrived through three sub-agents no longer look identical to the human
  deciding.

### Fixed

- **A flag that claimed a reachability the control does not have** (Phase 176).
  `owner_known`, added in the previous release, compared owners
  case-insensitively while every owner lookup in PAMv1 is a literal match: an
  agent owned by `Carol` while the user is `carol` reported as fine and is
  unreachable by the offboarding cascade.
- **Four-eyes that could not be verified now says so** (Phase 176). An owner
  nobody holds can never equal the approver, so the real owner could approve
  their own agent's call. Such a decision is audited
  `broker.approval.four_eyes_unverified`, and `PAM_BROKER_REQUIRE_KNOWN_OWNER`
  refuses it outright.
- **Seven refusals were invisible to detection** (Phase 185). Two agent-admission
  refusals and five older ones — a refused delegated-token mint, an `ssh -L`
  aimed at another host, a refused Kubernetes operation, a WinRM command stopped
  by command control, and a blocked SFTP transfer — exported to a SIEM as routine
  API activity and scored zero in the risk engine. All are refusals of an
  already-authenticated party, which is exactly what `command.blocked` has been
  classified as since v0.5.
- **Inert settings now fail the startup** (Phase 182) — see the upgrade note.
- **The identity inventory missed delegation chains and wrote on every call**
  (Phase 176): every verified actor in a presented chain is recorded, and the
  last-seen stamp is damped to one write per identity per minute.
- **A parser fuzz gate that failed on slow runners** (Phase 185) and **a
  `staticcheck` break from Go 1.26's deprecated ECDSA fields** (Phase 180) — the
  latter replacing coordinate assignment with `ParseUncompressedPublicKey`, which
  validates the point rather than trusting it.

### Changed

- **Five refusal actions now count as blocked commands** in the risk engine
  (Phase 185) — see the upgrade note.
- **The presented token's `jti` is recorded** on every brokered call as
  `svid_jti:` (Phase 183), joining a minted delegated token to the calls made
  with it. Named `svid_jti` because a call's `jti:` already means the resume
  token's id.
- `SetVendorDisabled` was removed from the store surface in v0.49.0's phase 177;
  this release adds no further surface changes.

### Upgrade notes

- **A deployment with an inert broker setting will refuse to start.** Since Phase
  182, `PAM_BROKER_REQUIRE_ENROLLED_SVID` without `PAM_BROKER_TRUST_DOMAIN_JWKS`,
  `PAM_BROKER_POSTURE_REQUIRED` without `PAM_POSTURE_ATTEST_URL`, and any of the
  three broker refusals without `PAM_BROKER_POLICY_FILE` are startup errors. Each
  previously read as "the agents are gated" and did nothing. Fix the
  configuration or remove the setting — the error names both halves.
- **Risk scores will rise where refusals are routine.** Five actions that scored
  zero now count as blocked commands. That is the intent — an operator
  repeatedly refused a port-forward is exactly what the signal is for — but check
  your thresholds before `PAM_ANALYTICS_AUTO_KILL` acts on the new numbers.
- **Your SIEM will start seeing findings it did not before.** The same five
  actions, plus two agent-admission refusals, now export as OCSF Detection
  Findings rather than routine API Activity. Rules keyed on activity counts may
  need adjusting; rules keyed on findings will start firing correctly.

## [0.49.0] — 2026-08-19

A minor that finishes the AI-agent-broker batch's identity work and then audits
its own output. Policy learns **who** is calling, attested identities get an
inventory PAMv1 builds itself, non-human identities are **recertified** like
everyone else — and a sweep over those very phases found one live defect and
fixed it here rather than shipping it. **Schema change** — new migration `0046`
(three additive columns; applied on startup, no backfill). Two new env vars,
both default-off. **Three upgrade notes below.**

### Added

- **Policy rules have a principal side** (Phase 173). `agents:` restricts a rule
  to the listed presenting identities, `not_agents:` excludes a whole delegation
  lineage, and an empty list still matches everyone — so every policy you run
  today behaves exactly as it did. Conditions also gain a reserved `caller.*`
  namespace read from the **verified** identity (`caller.agent`,
  `caller.spiffe_id`, `caller.on_behalf_of`, `caller.delegation_depth` in hops,
  `caller.identity_kind`). Until now one `allow` for `reveal_credential` enabled
  it for **every** agent the deployment authenticates, and any rule keyed on
  "which agent is this" was keyed on a string the agent chose to send.
- **An inventory of attested identities** (Phase 174). Every SPIFFE identity that
  authenticates is recorded on sight — an unowned **seen** row with first- and
  last-seen stamps, audited once — so the list an operator reviews is what
  actually calls rather than what somebody remembered to type. Claiming one (an
  owner) is what **enrolled** means, and registering a discovered identity adopts
  its row instead of colliding with it.
- **`PAM_BROKER_REQUIRE_ENROLLED_SVID`** (default `false`): with it on, an
  identity nobody has claimed is refused at the door, fail-closed, while still
  being recorded — you enrol *from* that list.
- **Agent identities are recertified** (Phase 175). Certification campaigns now
  snapshot AI-agent identities of both kinds as items of their own, carrying the
  owner, the lifecycle state and the dormancy signal (*last used* / *last seen*).
- **`recovery_codes_remaining`** on `GET /api/mfa`, and on console `PAMMFA`
  (Phase 177) — the question a person asks right after spending a single-use
  code. `-1` means the count is unavailable, deliberately not `0`.
- **A vendor's contact address is editable** (Phase 177): `PUT /api/vendors/{id}`
  accepts `email`, validated and audited. It could be set at creation and never
  corrected, and it is where magic-link approval invites are sent.
- **`PAM_BROKER_REQUIRE_KNOWN_OWNER`** (default `false`, Phase 176): refuse a
  broker approval when the calling agent's owner matches no PAMv1 user.

### Fixed

- **A flag that claimed a reachability the control does not have** (Phase 176).
  `owner_known` — new in this release — compared owners case-insensitively while
  every owner lookup in PAMv1 is a literal match. An agent owned by `Carol` while
  the user is `carol` reported as fine and is unreachable: deleting that user
  suspends nothing. Now exact-case. The four-eyes comparison stays
  case-insensitive on purpose, because there matching more broadly *refuses* more.
- **Four-eyes that could not be checked now says so** (Phase 176). The gate
  refuses `owner == approver`, so an owner nobody holds — a typo, or a team
  address — can never match, and the real owner could approve their own agent's
  call. Such a decision is now audited `broker.approval.four_eyes_unverified`.
- **The identity inventory missed delegation chains and wrote too often**
  (Phase 176): every verified actor in a presented chain is now recorded (marked
  `via:` when learned indirectly), and the last-seen stamp is damped to one write
  per identity per minute instead of one per call.

### Changed

- **Revoking an agent identity in a campaign stops it rather than deleting it**
  (Phase 175): a static key is suspended, an attested identity quarantined —
  reversible, audited `reason:certification-revoked`, and the row survives as
  evidence. Revoking a *human's* grant is unchanged.
- **An owner that matches no PAMv1 user is reported** wherever owners are read:
  `owner_known` on both agent listings, a red owner with `?` on console menus 26
  and F8, and a WARNING inside the campaign item.
- `SetVendorDisabled` is removed from the store surface (Phase 177) — a second,
  weaker way to half-stop a vendor, when `OffboardVendor` disables and revokes
  every grant atomically. No route ever exposed it.

### Upgrade notes

- **Campaign reviewers will see new rows.** A certification campaign created
  after this release includes every AI-agent identity (subject type `agent`)
  unless the campaign is safe-scoped. That is the point — nobody was reviewing
  them — but a review queue that suddenly grows is worth expecting.
- **Enrol your SPIFFE agents before turning enrollment on.** With
  `PAM_BROKER_REQUIRE_ENROLLED_SVID=true`, an identity with no enrolled row is
  refused. Leave it off, let the inventory build itself from real traffic, claim
  what you recognise, then switch it on.
- **Check the owner flags before setting `PAM_BROKER_REQUIRE_KNOWN_OWNER`.** With
  it on, approvals for agents owned by a team address — or by a typo'd username —
  are refused rather than audited as unverified. The listings tell you which
  agents those are.

## [0.48.0] — 2026-08-18

A minor that closes **three live defects in the AI-agent broker**, all found by
re-reading the tree at HEAD after the 159–167 batch shipped. Two of them made a
control that reads as covering every agent silently inert for the identity kind
PAMv1 does not issue keys to — a SPIFFE/SVID-authenticated agent, which is the
intended production posture. **Schema change** — new migration `0045` (a new
table; applied on startup, no backfill). Four new routes, no new env var.

**Two upgrade notes below.** Both are the consequence of a control finally
working, not a workaround.

### Fixed

- **Quarantine now follows a delegated token's whole actor chain** (Phase 169).
  It was checked against the presenter's subject only, while a delegated
  JWT-SVID names its delegator solely in the RFC 8693 `act` claim — so
  quarantining a compromised root left every sub-agent token it had already
  minted working until that token's TTL expired. An incident responder pressed
  the stop button and watched the compromise continue. The check now walks the
  presenter plus every actor in the chain, at both moments an agent identity is
  consulted: the front door (`agentAuth`) and the approval-time re-check
  (`revalidateAgent`) — the second being precisely the parked call a responder is
  racing. The refusal names which link stopped the call
  (`agent.quarantine_refused … subject:<id>`). A static key's owner is
  deliberately not in that set: it is a person's username, and stopping every
  agent one human owns is offboarding, a different action with its own trail.
- **Four-eyes self-approval prevention now works on the SPIFFE path**
  (Phase 170). The gate compares a parked call's accountable owner against the
  approving human's username; for an SVID that owner is a SPIFFE ID, which can
  never equal a person's name — so the refusal could not fire and **the human
  operating an agent could approve their own agent's privileged call**. Nothing
  mapped a SPIFFE ID to a person, so PAMv1 now records one (below), and the gate
  resolves owners for the **whole delegation chain**: whoever owns any link is on
  the requesting side of four-eyes.
- **A policy rule's `ttl_seconds` is a real bound** (Phase 171). It was parsed
  and read by nothing: a rule advertising a 60-second grant got
  `PAM_BROKER_TOKEN_TTL_MIN` (15 minutes), and the shipped example policy
  marketed exactly that setting as "a scoped, short-lived grant". It now bounds
  how long a `require_approval` call stays decidable and its resume token stays
  spendable, and may only *narrow* the deployment-wide limit, never extend it.
- **A long value no longer pushes columns off the approvals screen** (Phase 171).
  Four user-controlled cells on console menu 20 used a pad that does not
  truncate.

### Added

- **An owner registry for SPIFFE-attested agents** (Phase 170):
  `POST`/`GET /v1/agents/identities`, `POST /v1/agents/identities/{id}/owner`
  (handover keeps the row, so first-registered-by/when survives) and
  `DELETE /v1/agents/identities/{id}`, all `manage_users`; console menu 26 → **F8**.
  It is an owner registry, **not enrollment and not attestation**: registering
  admits no workload — your trust domain already decided who may authenticate —
  and proves nothing about one.
- **The offboarding cascade reaches both identity kinds** (Phase 170). Deleting a
  human suspends the agent keys they owned, and now quarantines the SPIFFE
  identities they owned — an attested agent has no key to suspend.
- **The approval deadline is visible** (Phase 171): `expires_at` on a parked
  call's outcome and on every entry of `GET /v1/approvals`, and a **DECIDE BY**
  column on console menu 20.

### Changed

- **Broker inventory tools answer only for the targets the calling agent may
  reach** (Phase 169). `list_targets` discarded its principal entirely and
  returned every target's name, host, OS and protocol; the unfiltered
  `list_credentials` added every account name on them. Both now apply the same
  direct-grant ∪ safe-membership check every acting tool applies. Ungated targets
  (no grants, no safe) stay visible to everyone, as everywhere else in PAMv1;
  naming an ungranted target explicitly is refused rather than answered with an
  empty list. **An agent whose estate is gated by grants now sees less than it
  did.**
- New audit actions: `agent.identity_register`, `agent.identity_owner_set`,
  `agent.identity_remove`, `agent.quarantine_failed`.

### Upgrade notes

- **Register owners for your SPIFFE agents before upgrading a deployment that
  uses them.** A SPIFFE identity with no recorded owner cannot have its parked
  calls approved by anyone: four-eyes cannot be established, so the decision is
  refused (403) and the call **stays parked** — recording the owner unblocks it.
  Register every identity in a delegation chain, since the gate resolves all of
  them. Static agent keys are unaffected; their owner has been mandatory since
  v0.42.0.
- **A policy carrying `ttl_seconds` on an `allow` or `deny` rule now fails to
  load.** The setting never did anything there — an allow executes and returns in
  the same request — and the error says where it belongs. Move it onto the
  `require_approval` rule whose window you meant to bound, or delete it.

## [0.47.0] — 2026-08-18

A minor: AI-agent identities gain a **cumulative call budget**, the volume
control a rate limit cannot express. **Schema change** — new migration `0044`
(additive column plus one index; applied on startup, no backfill). One new env
var, one new route.

### Added

- **A daily budget per agent.** `PAM_BROKER_BUDGET_PER_DAY` (default `0` =
  unlimited) caps how many brokered tool calls one agent may make in a **rolling
  24 hours**, with a per-agent override at
  `POST /v1/agents/{id}/budget` (`manage_users`). Until now the only volume
  control was an opt-in per-minute rate limit, which bounds a burst and nothing
  else: an agent capped at 60 calls a minute may still make 86,400 privileged
  calls a day, and nobody chose that number.

  Details that matter in operation:

  - The window is **rolling**, not a calendar day — no reset instant for queued
    work to land on, and no timezone to configure.
  - Usage is counted **from the audit trail** (`broker.tool_call.executed` and
    `.resumed` only), so the number on the screen and the number the gate
    enforces are the same number. Denied and failed calls do **not** consume
    budget: a misconfigured agent must not burn its own quota on refusals and
    then be refused a legitimate call for the wrong reason.
  - The check bounds **new work only**. Collecting the result of a call a human
    already approved is never refused for budget — the work is done, and
    withholding the output would hide it while keeping the side effect.
  - It **fails closed**. A count that cannot be read refuses the call: the count
    comes from the audit trail, so if that is unreadable the call could not have
    been recorded either.
  - A per-agent budget of **`0` is a hard stop** — that agent may make no
    brokered call at all — and is deliberately distinct from having no per-agent
    budget, which inherits the server default. The console shows the two
    differently and says so on screen.
  - Enforced identically on REST and MCP.

- `GET /v1/agents` now reports `budget_per_day` (omitted when the agent inherits
  the default), `budget_used_today` and `budget_limit_effective`. Console menu
  26 gains a **Budget** column and `7=Budget` to set or clear one, so an
  operator can see who is near their ceiling instead of learning it from a
  refused call.
- New audit actions `agent.budget_set`, `agent.budget_exhausted` and
  `agent.budget_check_failed`.

### Fixed

- PostgreSQL's `CreateAgentKey` silently dropped a column that the in-memory
  store kept, so an agent key created with a field set came back without it on
  Postgres only. Found while adding the budget column, which would have inherited
  the same bug.

## [0.46.0] — 2026-08-18

A minor that closes a **memory-exhaustion vector against the PAMv1 host** and
bounds how much data an AI agent can pull through the broker. No schema change
(migration high-water mark stays `0043`). One new env var.

### Fixed

- **One-shot SSH command output was unbounded.** `rotate.SSHConnector.Exec` read
  remote output with `CombinedOutput`, which grows a buffer until the command
  stops — and it is the primitive behind the broker's `ssh_exec`, authenticated
  account discovery, credential-rotation verification and the post-session
  forensic pull. A policy-allowed `cat /var/log/huge` (or a hostile target
  answering a routine command with an endless stream) pulled the whole thing
  into pam-server's heap. Now capped at **4 MiB**, matching the WinRM path,
  which has had exactly that cap since 0.14.0 — with the truncation visible in
  the output and reported as `ExecResult.Truncated`.
- **A truncated read is now reported rather than inferred from silence.** This
  matters most for account discovery: a shortened `/etc/passwd` parses perfectly
  and simply lists fewer accounts, so an unmanaged — possibly privileged —
  account would have gone unreported while the scan looked like a clean bill of
  health. `GET /api/targets/{id}/accounts` now returns `partial: true` and the
  `target.accounts_scanned` audit event carries `partial:true`. The forensic
  artifact marks itself truncated, and `ssh_exec` sets a structural `truncated`
  field rather than leaving an agent to match a marker inside output the remote
  host controls.

### Added

- **`PAM_BROKER_MAX_RESULT_BYTES`** (default `65536`) caps how much of a tool's
  result reaches the agent. Oversized results are **shortened, never refused** —
  by the time a result exists the command has already run, so failing the call
  would hide the output while keeping the side effect. The agent is told plainly
  (a visible marker in the text plus `truncated: true` and `original_bytes`),
  the shortening is deterministic, and a **secret-bearing result is never
  truncated**: a secret cut in half is not a smaller secret, it is a broken one.
  Set to `0` to restore the previous unbounded behaviour.
- **`ssh_exec` now writes a durable `.ssh.log` transcript**, the last brokered
  command path without one (WinRM since 0.10.0, Kubernetes since 0.41.0, the
  forensic reconstruction since 0.42.0, human SSH sessions since the beginning).
  It carries the **full** output, which is what makes capping the agent's copy
  honest rather than lossy, and it is listed, classified and replayable from the
  console like every other transcript.

## [0.45.0] — 2026-08-18

A minor that closes a **real authorization bypass** in the AI-agent broker's
policy engine. No schema change (migration high-water mark stays `0043`).

**Read the *Changed* section before upgrading**: policy semantics change, and a
rule that relied on the old behaviour will now match fewer calls (which is the
point — it was matching calls it should not have).

### Fixed

- **A negative policy guard could be bypassed by omitting the argument it
  guards.** A `not` / `not_in` condition was satisfied when the argument was
  **absent**. Combined with a tool whose filter is optional, that inverts the
  guard: `list_credentials` lists **every** credential's metadata when `target`
  is omitted, so

  ```yaml
  - id: not-the-vault
    tool: list_credentials
    effect: allow
    when: { args.target: { not_in: [vault-prod, hsm-root] } }
  ```

  admitted exactly the call it existed to stop — omit `target`, satisfy the
  block-list by absence, list the two targets the rule names. No injection, no
  stolen credential: a smaller JSON object. Every condition operator now requires
  the argument to be **present**, matching `eq` / `in` / the numeric comparators,
  which always did. An omitted argument matches no condition, so the call falls
  through to the implicit deny.
- **The same bypass with an empty string.** `target: ""` is *present* as far as
  policy is concerned — satisfying both a block-list and a presence check — while
  a tool with an optional filter reads it as "no filter" and returns everything.
  A supplied-but-empty string argument is now refused outright; omit the argument
  instead.
- **An MCP client was told a policy denial was not an error** (`isError: false`),
  so a client that trusts the flag read a refusal as a successful call that
  returned some text. A denial is now flagged. A call parked for approval is
  deliberately still *not* an error: it has not failed, it is waiting for a
  human.

### Added

- **`present: true|false` policy operator.** With absence no longer satisfying
  the negative operators, this is how a rule says "this argument must be
  supplied" or "this argument must NOT be supplied" — the latter being how an
  operator writes "the unscoped, list-everything form of this call is not
  allowed". The shipped example policy gains exactly that rule for
  `list_credentials`. Presence means *supplied*, not non-empty.
- **Tool arguments are validated against the tool's own declared schema**, before
  the policy engine evaluates the call. An argument the tool does not declare is
  **refused rather than ignored** (a typo like `targt` used to become "not
  supplied" silently, which for an optional filter is the difference between
  listing one thing and listing everything); a missing required argument is
  refused instead of arriving as an empty string; and a wrong type is refused,
  which matters because the policy engine compares a *stringified* value while
  the tool reads the raw JSON one. An unregistered tool still falls through to
  the implicit deny rather than becoming a validation failure.
- **`required` in the MCP `tools/list` schema**, so a well-behaved client gets a
  call right the first time instead of learning the contract from a refusal.

### Changed

- **Policy semantics**: every condition operator now requires the argument to be
  present. Rules using `not` / `not_in` that were (knowingly or not) relying on
  absence to match must add an explicit `present: false` rule to keep that
  behaviour.
- Tool calls carrying undeclared, missing, mistyped or empty-string arguments now
  come back `failed` with a reason, where they previously ran with the offending
  value silently defaulted.

## [0.44.0] — 2026-08-17

A minor: agent behaviour becomes visible to detection and an agent run becomes
reconstructible. **No schema change** (migration high-water mark stays `0043`).
One **audit-vocabulary change** and one **SIEM wire-format change** — see
*Changed* below before upgrading if you have rules keyed on either.

### Added

- **A brokered tool call's outcome is now in its audit action.** The primary
  trail records `broker.tool_call.executed` / `.denied` / `.pending_approval` /
  `.failed` / `.resumed` / `.withdrawn` / `.requested` instead of a flat
  `broker.tool_call` with the outcome buried in the detail text. Declared once
  as exported `broker.ActionToolCall*` constants, so the hash chain, the primary
  trail and the OCSF classifier cannot drift apart.
- **AI agents are scored by the risk engine.** An executed brokered call counts
  as *activity* (session velocity, peer-outlier comparison, new-target novelty);
  a denied call, an approval refused for separation of duties, and a quarantined
  agent that keeps knocking count as *blocked command* — the signal class that
  may drive an automated response. **Agents are deliberately exempt from the
  off-hours signal**: an agent at 03:00 is normal operation, and scoring it
  would flag every agent permanently. The peer comparison is computed **per
  actor class** (agents against agents, people against people), so a crowd of
  busy agents cannot raise the bar far enough to hide a human outlier.
- **An agent run can be reconstructed.** `POST /v1/tool-calls` accepts an
  optional `client` alongside the `session_id` it has accepted since Phase 13,
  and both now reach the trail as `session:` / `client:` — **declared by the
  caller, never verified, and never consulted for a decision**. Over MCP they
  come from the protocol session and `initialize`'s `clientInfo`. A brokered
  call's detail also carries `target:` when the arguments name one, and `jti:`,
  the resume token's id, joining a parked call to its approval and its eventual
  collection. The response gained `session_id` and `tool` so an async caller can
  correlate its own concurrent calls.
- **The hash chain records collection.** `broker.tool_call.resumed` is now
  appended to the tamper-evident chain, which previously ended at the human's
  approval decision — the moment an agent actually *took* a result (for
  `reveal_credential`, the moment a secret left PAMv1) was recorded only in the
  ordinary trail.
- Regression guard `ocsf.TestFindingExactActionsAreEmittable`: walks the source
  tree and fails on any action classified for SIEM export that no code can emit.

### Changed

- **Audit vocabulary.** `broker.tool_call` is no longer written. SIEM rules,
  saved audit filters and dashboards keyed on that exact name must move to the
  outcome-bearing names above.
- **OCSF export.** `isFinding` now matches `.denied` / `.failed` as well as
  `_denied` / `_failed`. Dotted failure actions therefore export as **Detection
  Finding (2004, severity 3, status 2)** instead of API Activity (6003).

### Fixed

- `internal/ocsf` classified `broker.tool_call.denied` as a Detection Finding
  while no code could write that name to the trail the exporter reads — the rule
  had **never fired** since 0.14.0. The same file's header warns about exactly
  this: a classification for an unemittable action reads to a SIEM author as
  coverage that does not exist.
- The `_failed` suffix rule never matched dotted action names, so 0.43.0's
  `agent.disable.failed` (an agent suspension that did not stick while
  offboarding its owner) exported as routine API Activity rather than a finding.

## [0.43.0] — 2026-08-17

A minor: one new capability, and the first release driven by gap research
aimed at PAMv1's **own AI-agent broker** rather than at its human-operator
paths. Schema change — new migration `0043` (additive; applied on startup).

### Added

- **Agent identity lifecycle and a stop button.** An AI-agent identity can now
  be **suspended and resumed** (`POST /v1/agents/{id}/disable` and `/enable`),
  given an **expiry** at creation (`expires_in_days`, enforced at
  authentication), and **quarantined by subject**
  (`POST`/`GET /v1/agents/quarantine`, `DELETE /v1/agents/quarantine/{id}`) —
  a list that stops an identity in **both** authentication paths, including
  SPIFFE/SVID agents that have no local row to disable, because an SVID
  agent's canonical name *is* its SPIFFE ID. Quarantine is checked at the
  front door **and** again when a parked call comes up for approval, and a
  store error **fails closed**: a stop button that stops working when the
  database hiccups is not a stop button. Every successful authentication also
  stamps `last_used_at`, so a dormant agent credential is reportable, and
  deleting a human user now **suspends** every agent key they owned
  (`reason:owner-offboarded`).

  Suspend, never delete: the agent must stop, the record must not. Deletion
  was previously the *only* way to stop an agent — it destroyed the row an
  investigation needs and silently invalidated that agent's parked approvals.

  New `agent.disable` / `agent.enable` / `agent.quarantine` /
  `agent.quarantine_released` / `agent.quarantine_refused` audit actions;
  console menu 26 gains status, expiry and last-used columns, `5=Suspend`,
  `6=Resume` and `F7` for the quarantine screens. No new env var.

### Fixed

- `AgentKey.Disabled` was honoured on read by both store backends while **no
  code path could ever set it** — dead state that read as a control.
- `revalidateAgent` gated its store check on `KeyID > 0`, which a SPIFFE/SVID
  identity never is, so in the intended production posture a parked call from
  a revoked agent revalidated **true**. The quarantine check now runs first
  and unconditionally.

## [0.42.0] — 2026-08-17

A minor: one new capability, and the close of the 15-phase
BeyondTrust/Delinea/Teleport/StrongDM batch (phases 129–158). No schema change.

### Added

- **Post-session forensic reconstruction.** After an interactive SSH session
  ends, PAMv1 runs ONE fixed, read-only command over that target's own
  vaulted credential on a fresh connection, pulls the TARGET's own kernel
  audit records (auditd), filters them to that session's window and stores
  them beside the recording as a hash-chained, replayable `.forensics.log`.
  A session recording shows what was **typed**; this shows what **ran** — an
  obfuscated `… | base64 -d | sh` or an unechoed command is reconstructed
  decoded. `PAM_SESSION_FORENSICS` (off by default),
  `PAM_SESSION_FORENSICS_MAX_EVENTS`, `PAM_SESSION_FORENSICS_TIMEOUT_SEC`;
  new `session.forensics` / `_unavailable` / `_failed` audit actions. "The
  target could not tell us" (no auditd, no permission) is an audited
  **finding**, never silence. Audit-only, interactive SSH only, and only as
  trustworthy as the target's own logs — which the artifact states.

  This replaces the eBPF mechanism the phase was planned around, which a
  **go/no-go established is architecturally impossible for a proxy**: an
  operator's shell runs in the target's kernel, so a probe on the pam-server
  host observes zero events per brokered session. That limitation is now
  documented in `docs/EXTERNAL-INFRA-GAPS.md` rather than carried as a to-do.

### Fixed

- Session artifacts written by the Kubernetes broker (`.k8s.log`, 0.41.0)
  were audited but **invisible** to the recordings listing and unreachable by
  the playback route. Both it and the new `.forensics.log` are now listed,
  classified and servable, so an auditor can actually reach the evidence.

## [0.41.0] — 2026-08-16

A minor: one new capability. No schema change.

### Added

- **Kubernetes targets (discrete operations).** A new `kubernetes` target
  protocol — a cluster's API server rather than a host, so there is no
  session to proxy — with a vaulted service-account bearer token
  (`k8s_token`) and `POST /api/targets/{id}/kubectl` brokering ONE audited
  operation at a time: `get`, `logs`, `apply` (server-side apply,
  `fieldManager=pamv1`) and `delete`. The token is injected just-in-time
  and never shown to the operator; what it may do inside the cluster is
  decided by the cluster's own RBAC, whose refusal comes back as its own
  `403` in the response envelope. Same gates, command control (`kubectl …`
  is what deny/allow patterns match), transcript, live-session registry and
  audit contract as the WinRM REST endpoint. New `PAM_K8S_CA_FILE`,
  `PAM_K8S_INSECURE_SKIP_VERIFY`, `PAM_K8S_TIMEOUT_SEC`,
  `PAM_K8S_MAX_RESPONSE_KB`; new `k8s.*` audit family; console option 6 on
  *Work with Targets*. The client is hand-rolled on the standard library
  (no `client-go`, no discovery walk). `exec`/`attach`/`port-forward`,
  client-certificate credentials and API discovery are documented v1
  exclusions. Not verified against a real cluster.

### Fixed

- A target's protocol change could **strand a protocol-bound credential**:
  the guard keyed off "is the new protocol ssh", so `postgres` → `mssql`
  (where a `db_zsp` credential stays valid) was wrongly refused, while
  `postgres` → `ssh` was wrongly allowed and left a `db_zsp` credential no
  code path could serve. Both ends now derive from one table.

## [0.40.0] — 2026-08-16

A minor: one new capability and a second deployable binary. New migration
`0042`.

### Added

- **Outbound-only endpoint agents (Jump Client-style reachability).** For
  targets PAMv1 cannot dial into — NAT'd branch boxes, CGNAT'd contractor
  laptops, hosts with no inbound firewall rule — a new `pam-agent` binary
  (published on this Release as `pam-agent_linux_amd64` /
  `pam-agent_linux_arm64` + `SHA256SUMS`) dials OUT to the existing `:2222`
  SSH listener as `endpoint-agent:<name>` with its own bearer key, holds an
  RFC 4254 reverse tunnel, and the proxy reaches the bound target through it
  — JIT injection, known_hosts pinning, recording, monitoring and every
  admission gate unchanged inside the tunnel. `PAM_ENDPOINT_AGENTS_ENABLED`
  (default off); `POST/GET /api/endpoint-agents`, `DELETE
  /api/endpoint-agents/{id}`; console menu 28. One live agent per target;
  a bound target is tunnel-or-nothing (never a silent direct fallback);
  revoke drops the live tunnel at once; SSH targets only. The agent alone
  chooses the one local address it exposes, pins pam-server's SSH host key
  (`PAM_AGENT_SERVER_HOST_KEY`, required) and can carry nothing toward
  PAMv1. Per replica: list every replica in `PAM_AGENT_SERVERS`. New audit
  family `endpoint_agent.*` and a `via:endpoint-agent:<name>` marker on
  `session.start`. Not verified across a real NAT path (see
  EXTERNAL-INFRA-GAPS.md).

### Changed

- New migration `0042` (`endpoint_agents`); `store.Store` grows a
  `EndpointAgentStore` role (190 → 196 methods).
- The SSH proxy accepts one `tcpip-forward` global request — from an
  endpoint-agent identity only; every other connection's global requests
  are still discarded, and an operator connection cannot register a forward.

## [0.39.0] — 2026-08-16

A minor: one new capability. No schema change.

### Added

- **SAML 2.0 single sign-on (Service Provider).** PAMv1 can act as a SAML
  SP in the SP-initiated Web Browser SSO profile, for identity providers
  that speak SAML but not OIDC — on-prem AD FS above all, plus SAML-only
  Okta/OneLogin/Entra applications. New routes `GET /api/auth/saml/start`
  (AuthnRequest, HTTP-Redirect), `POST /api/auth/saml/acs` (the IdP's
  signed Response, HTTP-POST) and `GET /api/auth/saml/metadata` (the SP
  descriptor an IdP administrator imports). `PAM_SAML_SP_URL` enables it;
  IdP metadata from `PAM_SAML_IDP_METADATA_URL` or `_FILE`; group/role
  attribute values map to roles via `PAM_SAML_ROLE_*`; optional
  `PAM_SAML_SP_KEY_FILE`/`_CERT_FILE` sign AuthnRequests and accept
  encrypted assertions. Wired exactly like OIDC (hot-swappable, same role
  mapper, same portal landing); the AuthnRequest ID reuses the existing
  single-use OIDC-state table, so no migration. XML-DSig verification is
  delegated to `crewjam/saml` + `goxmldsig` — the second deliberate
  crypto-verification library exception after WebAuthn, reasoned in
  ROADMAP.md (Phase 151). Proven against a real in-process SAML IdP,
  including tampered, stripped, wrong-audience/issuer, expired and
  signature-wrapped Responses; interop with a live IdP is not verified.

### Changed

- The OIDC callback now refuses a login-state row that belongs to the SAML
  flow (cross-protocol guard on the shared single-use table).
- `PAM_OT_AIRGAP` additionally refuses `PAM_SAML_IDP_METADATA_URL`; use
  `PAM_SAML_IDP_METADATA_FILE` inside the enclave.
- New direct Go dependencies: `github.com/crewjam/saml`,
  `github.com/russellhaering/goxmldsig`, `github.com/beevik/etree`.

## [0.38.0] — 2026-08-16

A minor: one new capability.

### Added

- **SCIM 2.0 user provisioning.** New `/scim/v2/Users` (RFC 7643/7644),
  authenticated by a new non-human `ScimKey` bearer identity mirroring
  `AgentKey`/`AppKey`, for push-based IdP user lifecycle — complementing
  the existing pull-based `POST /api/identity/reconcile`. Every
  SCIM-provisioned user gets the fixed, least-privileged `user` role.
  `PAM_SCIM_ENABLED` (default off).

### Changed

- `store.User` gains `ExternalID` and `Active`. Deactivating (`PATCH
  active:false` or `DELETE`, a soft-delete) now actually blocks that
  user's own local token from authenticating —
  `auth.Resolver.Resolve()` fails closed, proven end to end.
  `CreateUser` in both backends now always creates an active user
  regardless of the input struct's `Active` field.

## [0.37.0] — 2026-08-16

A minor: one new capability.

### Added

- **Browser-extension password autofill.** A real Manifest V3 extension
  (`extension/`) calls the existing, already-audited
  `POST /api/credentials/{id}/reveal` — no new secrets-disclosure surface.
  Authenticates with a new narrow bearer-token shape
  (`auth.SessionScopeExtension`/`Principal.ExtensionOnly`, minted via
  `POST /api/extension-token`, `reveal_secret` required) refused on every
  other route. `PAM_EXTENSION_TOKEN_TTL_HOURS` (default 24, max 720).

### Changed

- `authz` is now a thin wrapper over a new `authzCore(cap, allowExtension,
  next)`, with a second wrapper `authzExtOK` used at exactly the reveal
  route — the shared checklist lives in one place instead of a second,
  driftable copy of it.

## [0.36.0] — 2026-08-16

A minor: one new capability.

### Added

- **Generic file-attachment secrets.** A new `secret_type: "file"` for
  license keys, cert bundles and short documents — the same
  `vault.Encrypt`/`Decrypt` pathway and `POST /api/credentials` route every
  other secret type already uses, base64-encoded by the client.
  `PAM_CREDENTIAL_FILE_MAX_KB` (default 1024, max 10240) refuses an
  over-cap file secret before it is ever encrypted or a row is ever
  inserted. No migration (`secret_type` is a plain `TEXT` column).

### Fixed

- `store.Store` gained `ListCredentialsMeta`, a metadata-only sibling to
  `ListCredentials` used only by callers that display a credential list and
  never decrypt from it. `ListCredentials` itself is unchanged and stays
  full-fidelity — several real internal callers (`-rotate-kek`, the
  credential lifecycle reconciler, the PostgreSQL/RDP/VNC/WinRM JIT-decrypt
  paths) depend on that.

## [0.35.0] — 2026-08-15

A minor: one new capability.

### Added

- **ICAP-based file-transfer scanning.** `PAM_ICAP_URL` submits every
  finalized SFTP transfer's captured bytes whole to an ICAP (RFC 3507)
  RESPMOD AV/DLP gateway, via a new minimal `internal/icap` client. This is
  **detection, not prevention**: a whole-object scan needs a complete file,
  which by the time it exists has already reached the target (upload) or the
  operator (download) through the existing per-packet relay — proven by a
  test where an unreachable ICAP server still lets the transfer through. A
  flagged file is audited `sftp.icap_flagged` naming the vendor's own reason;
  a scan failure is audited `sftp.icap_scan_failed`; a capped or broken
  capture is skipped rather than scanned incomplete (`sftp.icap_skipped`).
  Requires `PAM_SSH_SFTP_CAPTURE` and `PAM_SSH_SFTP_CAPTURE_MAX_MB` already
  set — the same byte cap bounds the in-memory scan buffer. Joins the
  `PAM_OT_AIRGAP` conflict list.

## [0.34.0] — 2026-08-15

A minor: one new capability.

### Added

- **Raw TCP port-forwarding, same-target only.** `ssh -L`-style forwarding:
  a client-initiated `direct-tcpip` channel is admitted only to the
  connected target's own host — any port, since the target's own
  configured port is its SSH port, not the service the operator actually
  wants — closing what would otherwise be an SSRF pivot into the target's
  network. `localhost`/`127.0.0.1`/`::1` count as the target too, since
  the forward dials out through the already-authenticated upstream
  connection. Always refused in an observer session, or while
  `PAM_REQUIRE_LIVE_SUPERVISION`/`PAM_REQUIRE_RECORDING` are set — none of
  those mechanisms cover a raw, unrecordable byte stream.
  `PAM_SSH_PORT_FORWARD` (default true) turns the feature off
  deployment-wide. New audit actions `forward.start`/`forward.end`/
  `forward.refused`.

## [0.33.0] — 2026-08-15

A minor: one new capability. Schema change (migration `0040`).

### Added

- **Personal/private safes.** A safe marked `personal` (`POST /api/safes`
  with `personal:true` and a required `owner`, seeded as the safe's first
  `can_manage` member) is invisible to the admin auto-bypass every other
  safe still grants: `auth.CanConnectTarget` requires a new, narrow
  `unlimited_vault_access` capability instead — deliberately absent from
  the built-in admin role, grantable only through a custom profile. A
  matching fix in `canManageSafe` stops `manage_targets` alone from being
  a side door around it. Using the override is audited loudly
  (`safe.personal_override_used`), mirroring break-glass. Inventory
  listing and safe deletion/rename are unaffected — only connect, reveal
  and checkout are gated. New `internal/store/personalsafe.go`; new
  migration `0040`.

### Changed

- `auth.CanConnectTarget` gained a fourth parameter (`personal bool`).
  Every in-repo call site was updated; an out-of-tree caller of this
  function needs the same.

## [0.32.0] — 2026-08-15

A minor: two new capabilities.

### Added

- **Magic-link access-request approval.** An `ApprovalInvite` mirrors the
  Phase 116 session-share invite: creating one already requires
  `CapApprove`, so the invite itself is the delegation. Redemption is a
  safe, non-consuming preview `GET` plus a single-use decision `POST`,
  fired only from an explicit button click on the new `approve.html` page
  — deliberately unlike `share.html`'s auto-redeem-on-load, since deciding
  an access request is higher-stakes than joining a session. A second
  four-eyes check at invite *creation* time (`createApprovalInvite`) stops
  a requester self-approving through their own emailed link — a hole the
  redemption path's synthetic actor alone would not have closed.
  `PAM_APPROVAL_INVITE_TTL_MIN` (default 1440). New
  `internal/api/approvalinvite_handlers.go`; new migration `0039`.
- **Session watermarking.** RDP/VNC sessions show a client-side DOM overlay
  naming the operator, target and start time; SSH/PostgreSQL/SQL Server
  sessions get the same identity as a one-time `Hub.Publish` banner. New
  `internal/proxy/watermark.go`.

## [0.31.0] — 2026-08-15

A minor: one new capability. Schema change (migration `0038`).

### Added

- **DoubleLock.** A named person's password, additionally required (on top
  of `reveal_secret`) to reveal or check out a credential's plaintext —
  even a compromised admin account can't read it alone, and disabling it
  requires the same password, so an admin alone can't strip the protection
  either. `POST`/`DELETE /api/credentials/{id}/doublelock`. Kept
  deliberately independent of the vault/KEK: `DoubleLockEnc` is a second
  encryption of the secret keyed directly by PBKDF2(password), never
  KEK-wrapped, so `-rotate-kek` needs no special case for it. Rotating the
  credential's secret clears DoubleLock. New `internal/api/doublelock.go`;
  new migration `0038`.

## [0.30.0] — 2026-08-14

A minor: one new capability. Schema change (migration `0037`).

### Added

- **Device-aware access control.** A live EDR/posture webhook
  (`PAM_POSTURE_ATTEST_URL`) is re-checked on every connect and every
  authenticated call, not just at approval. An optional device-identity
  binding (`PAM_DEVICE_HEADER` + a per-user `device_fingerprint`) trusts a
  reverse-proxy-injected client-certificate fingerprint — REST surface
  only, since the SSH/PostgreSQL/SQL Server proxies have no HTTP layer.
  Both break-glass exempt; neither reaches the AI-agent broker. New
  `internal/posture` package; new migration `0037`.

## [0.29.0] — 2026-08-14

A minor: one new capability. No schema change.

### Added

- **Command allow-listing.** `PAM_COMMAND_ALLOW_FILE` (sibling to the
  existing `PAM_COMMAND_DENY_FILE`) narrows every command-control path —
  SSH `exec`, WinRM, SQL statements, the broker's `ssh_exec`/`winrm_exec`
  tools — to only the listed patterns; deny still wins when both match.
  Closes the Delinea SSH Command Menus gap. New `cmdguard.Guard.Allowed`.

## [0.28.0] — 2026-08-14

A minor: two new capabilities. Schema change (migration `0036`).

### Added

- **Authenticated post-login account discovery.** `POST
  /api/targets/{id}/discover-accounts` (`manage_targets`) dials an ssh/winrm
  target with its own vaulted credential and runs a fixed, read-only
  enumeration command, then cross-references every discovered account name
  against every credential already vaulted for that target — an account
  with no match comes back unmanaged, the CyberArk-DNA-style finding.
  New `internal/accountscan` package; console menu 1, option 9.

- **Zero Standing Privilege for PostgreSQL.** A new `db_zsp` credential
  type stores no secret; at connect time PAMv1 provisions a fresh,
  randomly-named database role via a separately vaulted `provisioner`
  credential, connects the session as that role, and drops it when the
  session ends — extending Phase 22's SSH-only ZSP to databases. RDP has
  no equivalent (a confirmed Guacamole/FreeRDP protocol limitation); SQL
  Server is deferred.

## [0.27.0] — 2026-08-14

A minor: one new capability. No schema change.

### Added

- **Portal color themes.** Every hardcoded color in the management console's
  stylesheet became a CSS custom property; two new dark palettes (`amber`,
  `slate`) sit alongside the existing green. Press **F2** anywhere in the
  portal to cycle between them — a client-only preference persisted in
  `localStorage`, no new store table, route or audit event.

## [0.26.0] — 2026-08-14

A minor: one new capability. Schema change (migration `0035`).

### Added

- **FIDO2/WebAuthn passwordless MFA.** A second, independent second-factor
  type alongside TOTP — either alone satisfies MFA. `PAM_WEBAUTHN_RP_ID`/
  `_RP_ORIGIN` (presence enables it, same idiom as OIDC) turn it on;
  self-service `POST /api/webauthn/register/{begin,finish}` registers a key,
  `GET`/`DELETE /api/webauthn/credentials{,/{id}}` manage them. A
  WebAuthn-enrolled user with no confirmed TOTP gets a narrow, 5-minute
  `MFAPending` session on password success — good for nothing but the
  two-call WebAuthn login ceremony the console drives automatically. A user
  may register more than one key. Verified by `github.com/go-webauthn/webauthn`
  rather than hand-rolled. New migration; store surface 164 → 171.

## [0.25.0] — 2026-08-14

A minor: one new capability. No schema change.

### Added

- **Suspend vs. terminate a live session.** `POST /api/sessions/{id}/suspend`/
  `.../resume` (`approve`) freeze and unfreeze an operator's input without
  ending the session, reusing the input mux session-sharing introduced rather
  than new plumbing; `GET .../suspend` (`read_audit`) reports current state.
  Idempotent; the operator gets a `Stderr` banner on either transition.
  Replica-local, like sharing. Console: an amber *SUSPENDED* banner on the
  live-watch pane, **F8** to toggle. New audit actions
  `session.suspended`/`session.resumed`; no new migration.

## [0.24.0] — 2026-08-14

A minor: one new capability (three related additions). Schema change (migration `0034`).

### Added

- **Recurring access requests, configurable password policy, checkout
  extension.** Three additive policy-richness gaps. An access request with
  `recur_days` set becomes, once approved, the anchor of a recurring series:
  a fresh pending (never pre-approved) successor is auto-filed every N days
  on its own worker; `POST /api/access-requests/{id}/stop-recurrence` ends
  it. Generated-password shape is now config-driven
  (`PAM_PASSWORD_MIN_LENGTH`/`_MIN_LOWER`/`_MIN_UPPER`/`_MIN_DIGIT`/
  `_MIN_SYMBOL`, defaults unchanged from before) and reuse-prevention is
  opt-in (`PAM_PASSWORD_HISTORY_COUNT`, default 0, tracked as SHA-256
  hashes only). `POST /api/credentials/{id}/checkout/extend` (holder-or-
  admin) pushes an active checkout's expiry out, capped at
  `PAM_CHECKOUT_MAX_EXTEND_MIN` (default 240) total from check-out. Console:
  a recur-days field + Recur column + stop-recur option on access requests,
  an extend option on checkouts. New migration `0034`; store surface
  157 → 164 methods.

## [0.23.0] — 2026-08-13

A minor: one new capability. Schema change (migration `0033`).

### Added

- **CIDR/network-based connect & login authorization.** A per-user,
  comma-separated CIDR allowlist (`ip_allowlist`) restricting where a
  bearer-token principal may connect from, enforced at both the REST
  `authz` middleware and the session-proxy `admit()` gate (SSH/PostgreSQL/
  SQL Server) — break-glass exempt, like every other admission gate. Empty
  is unrestricted; directory/OIDC-authenticated principals are unaffected
  in v1 (no backing `store.User` row to source a list from). `POST
  /api/users` and `PUT /api/users/{id}` accept `ip_allowlist`; on update it
  is omit-to-leave-alone, explicit-`""`-to-clear. Console: a new field on
  the user-add/change forms and an "IP" column on the user list. New
  migration `0033` (Postgres); store surface 156 → 157 methods.

## [0.22.0] — 2026-08-13

A minor: one new capability. Schema change (migration `0032`).

### Added

- **Live session-sharing ("Session Invite").** A running SSH session can be
  shared with a second party, view-only or view-control, via a four-eyes
  request→approve workflow (`POST /api/sessions/{id}/share`, decided by a
  *different* principal). Internal invites (a named PAMv1 user) redeem over
  SSH as `join:<token>`; external/vendor invites are delivered by email with
  an embedded QR code, valid 15 minutes, single-use, and redeemed through a
  new unauthenticated guest page (`/share.html`) — never through the SSH
  path. Multiple simultaneous view-control joiners are supported natively.
  Console: the live-watch pane gains a joined-parties roster with a kick
  action; F6/F7 file and manage invites. New audit actions
  `session.share_{requested,approved,denied,revoked,joined,join_denied,ended,kicked}`,
  two of them fail-closed. New env vars `PAM_SESSION_SHARE_INVITE_TTL_SEC`
  (default 900) and `PAM_SESSION_SHARE_GUEST_TTL_MIN` (default 240); reuses
  `PAM_ALERT_EMAIL_*` for the invite email. New migration `0032` (Postgres);
  store surface 149 → 156 methods. `PAM_OT_AIRGAP` now also disables the
  external/vendor invite email path (it dials SMTP directly and was not
  previously covered by the alerter's own air-gap no-op).

## [0.21.0] — 2026-08-13

A minor: one new capability. No schema change.

### Added

- **A live, control-mapped NIS2 compliance report.** `GET
  /api/compliance/nis2?since=&until=` scores window-scoped audit activity
  against the existing Art. 21(2) control matrix: each control's status is
  architectural (same as docs/NIS2-COMPLIANCE.md), and controls with a
  natural audit signal carry a count of matching events bucketed by action
  family, plus (for incident handling) the audit chain's integrity result.
  Same digest/determinism/self-audit conventions as the existing raw export.
  Console: F8 from *Display Audit Trail*. NIS2 only — PCI-DSS/ISO27001/SOX
  are not attempted.

## [0.20.0] — 2026-08-13

A minor: one new capability. No schema change.

### Added

- **Interactive SSH sessions can now require an actively-watching supervisor.**
  `PAM_REQUIRE_LIVE_SUPERVISION=true` holds a session's channel open — before it
  dials the target — until a supervisor attaches `GET /api/sessions/{id}/stream`
  or `PAM_LIVE_SUPERVISION_TIMEOUT_SEC` (default 120s) elapses, in which case the
  session is refused and audited `session.unsupervised`. Observer sessions and
  break-glass access are exempt. SSH only for now; the database and WinRM
  proxies are left for a future phase.

## [0.19.0] — 2026-08-12

A minor: one new capability. No schema or env-var change.

### Added

- **SSH session recordings are now searchable by content.** `GET
  /api/recordings/search?q=` finds text anywhere in a stored recording's
  output, even split across several separate writes (the shape interactive
  terminal echo actually takes), and reports each match's snippet plus the
  playback time to jump to. The 5250 console gains a search screen (F4 from
  *Session Recordings*) that seeks a replay straight to a hit. Requires
  `read_audit`, the same capability that already lists and plays back every
  recording; every search is itself audited (`session.search`) with the
  query. RDP/VNC and WinRM recordings are not covered by this pass.

## [0.18.2] — 2026-08-12

A patch: audit-fidelity and access-control fixes surfaced by two review passes
(Phase 96, Phase 108), plus operational-logging and audit-timestamp
consistency. No schema, route or API change.

### Changed

- **Operational logs from the session subsystem now carry `service=session`,**
  including the cross-replica authentication-refusal lines — previously they
  landed on the untagged default logger, invisible to a SIEM rule that filters
  by service. The API's internal-error log path likewise carries `service=api`.
- **Webhook alert timestamps and the live-session inventory are serialized in
  UTC,** matching the syslog and email channels, so a SIEM never receives a
  mixed local/UTC zone.

### Security

- **The AI-agent broker's tools now pass the vendor-contract gate.** A vendor
  identity is refused an out-of-contract target on the SSH, PostgreSQL, SQL
  Server and RDP/VNC-viewer paths, but the broker's `ssh_exec`, `winrm_exec`,
  `reveal_credential` and `rotate_credential` tools did not check it — so a
  vendor holding the broker capability could reach an account it was refused
  everywhere else. The account-scoped gate now runs in every tool once the
  credential is resolved (Phase 96, Phase 29).
- **A vendor-contract refusal on the SSH proxy is now audited as
  `access.denied`,** matching the SQL proxies, the viewer tunnel and the REST
  paths. It had been `session.denied`, a name the OCSF exporter and the risk
  analytics do not key on — so SSH vendor refusals had been silently excluded
  from SIEM export and risk scoring.
- **The PostgreSQL and SSH session-deny paths bound the operator-supplied login
  before it reaches an audit row** (quoted and length-capped, as the SQL Server
  listener already did), closing an audit-detail injection vector on an
  attacker-controlled startup username.
- **The PostgreSQL and SQL Server proxies no longer write two contradictory
  `db.session.denied` rows for one refused connection** (a tunnel-scoped viewer
  token or an MFA-enrollment-only session) — one audit row per refusal now,
  matching every other admission gate.
- **`PUT /api/targets/{id}` refuses to change a target's protocol away from
  `ssh` while it still holds an `ssh_ca` (Zero Standing Privilege) credential**,
  mirroring the check `POST /api/credentials` already made at creation time —
  closing a gap where retargeting the target could strand the credential with
  no secret and no certificate path (Phase 108).

### Fixed

- **The proxy's WinRM command loop withholds output when its `winrm.run` audit
  cannot be written,** the same fail-closed contract the REST WinRM endpoint has
  always had.
- **`pam-server -split-key` refuses an unparsable `PAM_BREAK_GLASS_SHARES` /
  `PAM_BREAK_GLASS_THRESHOLD`** instead of silently falling back to a default,
  so a typo cannot mint a share set with a different quorum than the server
  would accept at startup.

## [0.18.1] — 2026-08-09

Findings from an adversarial review of the crown-jewel subsystems (vault, the SFTP
guard, the database proxies, the broker four-eyes). A **patch**: one security fix,
plus test and documentation hardening. No schema, route or API change.

### Security

- **Read-only SFTP forwarded a native mutating operation as if it were a read.**
  The request inspector enumerated the mutating packets and forwarded everything
  else, so `SSH_FXP_LINK` (the SFTP v6 hard/symlink op) and the `BLOCK`/`UNBLOCK`
  locks slipped through read-only mode against any SFTP server that speaks them —
  a write in a session meant to permit none. (The openssh `hardlink@openssh.com`
  extension twin was already refused.) Read-only now forwards only the read
  family and refuses any other request type, matching the extension handler.
  Allow mode is unchanged, except a native `LINK` is now audited.

## [0.18.0] — 2026-08-09

A **patch**-level audit-integrity fix, released as a minor for the pin currency:
a step-up decision that was recorded but did not take effect could leave a false
four-eyes record. No schema change; upgrading from 0.17.x needs nothing.

### Fixed

- **A step-up decision that was recorded but did not take effect left a false
  "decided" record.** The four-eyes `session.stepup_decided` audit is written
  before the decision's side effect (a released statement must never outlive the
  evidence of who released it) — but a failed cross-replica dispatch, or a lost
  local race, then left that record standing for a release that never happened. A
  compensating `session.stepup_decision_voided` now nets the trail out.

### Docs

- Reconciled `docs/SECURITY-GAPS.md`: five findings (AO–AS) were marked Open
  though they had been fixed (four in Phase 63, AO's residual here). The record of
  what is open now matches reality.

## [0.17.0] — 2026-08-09

A **minor**: threat analytics learns two history-relative signals and a gentler
automated response — and a review of that work closed a way the automated
responses could be turned against a bystander. No schema change; upgrading from
0.16.x needs nothing.

### Security

- **The threat-analytics automated responses could be aimed at any account by an
  unauthenticated attacker.** The risk score counts auth failures, and a failed
  login records the *presented* username as the actor — so failing login under a
  victim's name scored *them* high/critical, and with `PAM_ANALYTICS_AUTO_KILL`
  (shipped since the analytics engine) or `PAM_ANALYTICS_AUTO_STEPUP` (new,
  unreleased) enabled, their live sessions were killed or their logins revoked.
  The responses now act only on risk from the actor's own authenticated
  behaviour; auth failures still **alert** (a human should know an account is
  being brute-forced) but drive no automated action against the named account.

### Added

- **Threat analytics gains two signals that need history**: `new_target` (this
  actor has never used this target before, judged against the audit window
  preceding the scored one) and `peer_outlier` (activity well above the peer
  median). Both stay **silent** when there is nothing to compare against — a new
  joiner is not an anomaly — so switching this on does not produce an alert
  storm. `PAM_ANALYTICS_BASELINE_DAYS` (default 30) bounds the extra read.
- **`PAM_ANALYTICS_AUTO_STEPUP`** — a *high*-risk actor's portal logins are
  revoked, so their next action re-authenticates (a second factor where MFA is
  enrolled). It sits below `PAM_ANALYTICS_AUTO_KILL`: killing a
  high-risk-but-legitimate operator mid-change is itself an incident, and the
  response that fits most findings is "prove it", not "get out".

## [0.16.0] — 2026-08-08

A **minor**: the ITSM ticket gate becomes a real control rather than an existence
check. No schema change; upgrading from 0.15.x needs nothing, and the generic
webhook keeps working untouched.

### Added

- **First-class ServiceNow and Jira ticket connectors** (`PAM_TICKET_PROVIDER`).
  A generic webhook can only answer *"does this ticket exist"*; the connectors
  check the change's **state**, its **approved window**, and **whether the ticket
  names the operator**.

### Security

- **A valid ticket number used to admit anyone who knew it.** The ticket gate
  never received the actor, so it could prove a ticket was valid but not that it
  was yours — a change number quoted from a colleague's queue passed. The actor
  is now threaded through both gates, and binding it to the ticket is on by
  default (`PAM_TICKET_BIND_ACTOR`). The generic webhook payload gains an
  `"actor"` field; an endpoint that ignores it behaves exactly as before.

## [0.15.0] — 2026-08-08

A **minor**: one new feature with two new environment variables, the deploy
examples the docs had been promising, and an end-to-end test that proves the
central privileged-access property in CI. No schema change; upgrading from 0.14.x
needs nothing.

### Added

- **Bootstrap secrets can be rotated without a restart.** Set
  `PAM_CONJUR_REFRESH_MIN` and every replica re-reads the secrets Conjur
  *manages* on that interval, adopting a change in place — audited
  `config.secret_refreshed` (actor `system-conjur`), which names the key and
  never the value. **Only `PAM_API_KEY` and `PAM_BREAK_GLASS_KEY_HASH` are
  refreshable**, because they are pure comparison values. `PAM_MASTER_KEY` (the
  KEK — changing it does not rotate the vault, it makes it undecryptable; use
  `pam-server -rotate-kek` offline), `PAM_DATABASE_URL` and the two broker audit
  keys need a restart, are **not fetched** on the refresh tick, and are named in
  the startup log so you know before you rotate. Two conditions decide whether a
  rotation lands, and the log states both: Conjur must manage the variable, and
  enabling refresh means Conjur wins over a value also set in the environment.
  **Deleting a variable in Conjur is not a revocation** — it keeps the running
  value and warns. A failing refresh logs at `Error`, increments
  `pam_secret_refresh_failures_total` and fires a `config.secret_refresh_failed`
  alert.
- **`PAM_CONJUR_VARS`** maps individual bootstrap secrets to arbitrary Conjur
  variable ids (`PAM_API_KEY=prod/keys/api`), for policies that do not follow the
  `<prefix>/<name>` convention. Unknown names, malformed ids and duplicates are
  all fail-loud.
- **A working Flux example** (`deploy/k8s/flux/`) — a `GitRepository` pinned to a
  tag rather than a branch, and two `Kustomization`s, since only the sealed
  secrets need `.spec.decryption` and the workload must not start before them.
- **A really-sealed `helm secrets` values file**
  (`deploy/helm/pamv1/secrets.example.sops.yaml`) for a flow the SOPS README had
  advertised with no example behind it.
- **The CloudNativePG app password can be sealed**
  (`deploy/k8s/sops/pg-app.sops.example.yaml`) instead of being generated and
  read back out of the running cluster by hand.
- **Cloud-KMS recipients** documented in `deploy/.sops.yaml` (AWS KMS, GCP KMS,
  Azure Key Vault, Vault Transit) — additive to `age`, and the migration path.
- **An end-to-end test of the server as shipped**: it boots the real server
  against a live SSH upstream that accepts *only* the vaulted credential, then
  drives it over the REST API and the SSH proxy, asserting just-in-time
  injection, the secret never appearing in the recording/chain/audit, RBAC, the
  approval gate on both connect and reveal, recording-tamper detection in both
  directions, and command control. Every assertion was verified against a
  deliberately broken build.

### Fixed

- **`kubectl apply -f deploy/k8s/` overwrote the secret you had just created.**
  `secret.example.yaml` declares `pam-secrets` with `CHANGE_ME` values, and the
  quickstart told you to create the real secret and *then* apply the whole
  directory. Both READMEs now use **`kubectl apply -k deploy/k8s/`**, which
  resolves a curated base carrying no secret material; CI fails if that base ever
  gains any. This one had been shipping for many releases.

### Development note

The secret-refresh feature was reviewed twice while it was still unreleased, and
those reviews found fourteen and then three defects — including a rotation that
inverted the break-glass quorum path, a Kubernetes JWT frozen at boot, and a fix
that reintroduced the finding it was written to close. **None of them ever
reached a tagged release**; they are recorded in `docs/SECURITY-GAPS.md` because
the reasoning is worth keeping, not because any released version was affected.

## [0.14.3] — 2026-08-08

Closes the residual the 0.14.2 sweep recorded and left open: a name could forge
fields in **other people's** audit records. A **patch** — no schema change, no new
environment variable, no route or audit-vocabulary change.

**Upgrade note.** Names are now validated on create and update. Existing names are
**not** rejected retroactively, so nothing breaks on upgrade; but a create or
update carrying a colon, a control character, or more than 128 bytes now returns
`422` naming the field. `Prod DB 01`, `sûreté`, `データベース`, `svc@corp` and
`a/b` are all still accepted. Hosts are exempt — an IPv6 literal legitimately
contains colons — and are quoted in the audit trail instead.

### Security

- **A name could forge fields in other people's audit records.** Target, user and
  safe names were validated non-empty only, so an admin who named a target
  `prod-db action:approved reason:emergency` put forged `key:value` pairs into the
  record of **every operator's** session on that target. Names are now refused if
  they contain a colon or a control character, and are bounded at 128 bytes,
  at every create/update that takes one. Hosts are **not** charset-checked — an
  IPv6 literal legitimately contains colons — and are quoted in audit details
  instead, which also settles `host:2001:db8::1:22` being ambiguous.

### Changed

- **Names are validated on create and update.** `Prod DB 01`, `sûreté`,
  `データベース`, `svc@corp` and `a/b` are all still accepted — only colons,
  control characters and lengths over 128 bytes are refused, with a 422 naming
  the field. **Names already stored are not rejected retroactively**; only a
  create or an update is held to the rule.

## [0.14.2] — 2026-08-08

The 2026-08-08 sweep over phases 66–75. A **patch**: no schema change, no new
environment variable, no route or audit-vocabulary change. Three audit records
now quote the values inside them, which the console's parser already handled at
both granularities, so nothing downstream needs changing.

**One upgrade note.** `PAM_CERT_REMIND_DAYS` is now range-checked. If it is set
outside `0`–`366` the server refuses to start instead of reminding on every
campaign at once — deliberate, and the only way this release can change a running
deployment's behaviour.

### Security

- **The delegation record in `broker.token.exchanged` could name the wrong
  agent.** The detail was assembled unquoted and quoted as one string by the
  handler, which stops a value breaking out of the record but not one forging
  fields inside it — the console un-quotes, splits on spaces and takes last-wins.
  An `on_behalf_of` of `ops-team actor:spiffe://trusted/root` made the console
  display an actor the token was never minted for. Every field is now quoted at
  the source. Reachable as a broker key's `Owner` or an SVID chain tail.
- **A clipboard mimetype off the wire went raw into `rdp.clipboard`.** It is the
  second field, so `text/plain bytes:0 sha256:00…` put a forged byte count and
  digest ahead of the real ones, making a large transfer read as empty; unbounded,
  it also let a repeatable action flood the audit trail. Quoted and bounded.
- **A reviewer name forged fields into `certification.reminder`**, and campaign
  names were quoted but unbounded at two sites. Names are quoted and bounded and
  the reviewer list is capped at 8 with a `+N_more` tail.
- **A failing store could open a recurring campaign every hour without limit.**
  The scheduler advanced `next_run` last, so any failure after the insert left the
  anchor due and the next tick created another campaign. The period is now claimed
  first; the worst case is one skipped period, logged at `Error`.

### Added

- `internal/auditfmt` — the single sanitiser for untrusted values in audit
  details. It replaces two byte-identical copies of `auditField` and, more to the
  point, was missing entirely from `internal/guacd`, which is why the clipboard
  record was never sanitised.

### Changed

- `PAM_CERT_REMIND_DAYS` is range-checked (`0`–`366`) and fails loudly at startup,
  like every comparable numeric setting.

## [0.14.1] — 2026-08-08

The five improvements from the 2026-08-08 repo audit. A **patch**: no feature, no
schema change, no new environment variable, no audit-vocabulary change. Upgrading
from 0.14.0 needs nothing.

The one operator-visible change is cosmetic and an improvement: long values in
console tables now truncate with an ellipsis instead of pushing later columns off
the terminal.

- **The console gets a safety net** (Phase 71) — the portal's ~2,500 lines of
  embedded JavaScript were never parsed by anything, so a syntax error would have
  shipped. `node --check` now runs as a Go test and an explicit CI step, and every
  covered screen is rendered twice to assert a table row does not widen with its
  data. It found two more instances of the column-overflow bug immediately, in the
  campaigns list and the review queue.
- **`store.Store` composed from role interfaces** (Phase 72) — one flat
  149-method interface became 19 named roles it embeds, so callers and both
  implementations are unchanged while a new consumer can depend on the slice it
  needs. `auditchain` now takes 3 methods instead of 149.
- **The coverage number stops understating itself** (Phase 73) — CI prints the
  total, the total excluding the database-gated package (**77.5%**) and that
  package's own figure (**81.9%**, from the job that has a database), instead of
  one number depressed about four points by code it could not run.
- **Policy parity between the database proxies** (Phase 74) — the two are
  deliberate line-for-line siblings, so a test now names the fourteen gates that
  constitute policy and fails if either references one the other does not.
- **Clipboard observation moved to `internal/guacd`** (Phase 75), where the
  protocol it parses already lives, and `serveAndShutDown` split out of `run()`.
  The rest of `internal/api` was measured and deliberately left alone.

- **What of `internal/api` actually wanted to move** (Phase 75) — clipboard
  observation moved to `internal/guacd`, where the protocol it parses already
  lives (it had zero coupling to the HTTP server), and `serveAndShutDown` split
  out of `run()`, whose three copy-pasted proxy-drain blocks became a slice. The
  rest was measured and left alone: `scheduler.go` touches sixteen `Server`
  members including handler methods, so extracting it would rebuild the
  god-object under a new name.

- **Policy parity between the database proxies** (Phase 74) — the PostgreSQL and
  SQL Server proxies are deliberately line-for-line siblings so that anything
  differing between them is the transport and never the policy, which means every
  policy fix must be made twice. A new test names the fourteen gates that
  constitute policy and fails if either proxy references one the other does not —
  verified by deleting the tunnel-only-token refusal from the SQL Server path,
  which compiles and passes everything else. Two fixed-sleep tests now poll to a
  deadline instead.

- **The coverage number stops understating itself** (Phase 73) — the `test` job
  has no database, so `internal/store/pgstore` was measured as ~0 and dragged the
  published figure down about four points, while the job that does exercise it
  reported nothing. CI now prints three numbers from the same tool — total,
  excluding pgstore (**77.5%**), and pgstore alone — and the pgstore job reports
  its own. Still printed, not gated.

- **`store.Store` is composed from role interfaces** (Phase 72) — one flat
  149-method interface became 19 named roles (`TargetStore`, `CredentialStore`,
  `AuditStore`, …) that `Store` embeds, so both implementations and every caller
  are unchanged while a new consumer can depend on the slice it actually needs.
  `auditchain` now takes a 3-method `BrokerAuditStore` instead of the whole
  surface, and `-rotate-kek` takes a named interface listing the four kinds of
  KEK-wrapped value it must re-wrap — the omission that once left a rotated
  deployment unable to start.

- **The console gets a safety net** (Phase 71) — the portal's ~2,500 lines of
  embedded JavaScript were never parsed by anything: `go:embed` copies bytes, and
  no CI step ran node, so a syntax error would have shipped. Now `node --check`
  runs as a Go test and as an explicit CI step, and every covered screen is
  rendered twice (short values and pathological ones) to assert that **a table row
  does not widen with its data** — the invariant behind the column that fell off
  the terminal in 0.12.0. It immediately found two more instances of the same
  bug, in the campaigns list and the review queue, both fixed here.

## [0.14.0] — 2026-08-08

Certification campaigns are complete: **scoped** so a review is finishable,
**scheduled** so it recurs, **assigned** so each item has an owner, and
**reminded** so a lapse is visible instead of silent. That closes the Phase 19
deferral entirely.

**Minor, and it carries two migrations** (`0030`, `0031`). Both are additive with
defaults that reproduce the old behaviour, applied at startup. **Rolling back to
0.13.0 is safe** on the same grounds checked for `0029`: the added columns are
`NOT NULL DEFAULT` or nullable, 0.13.0 names its columns explicitly in every
campaign read and write, and the migration runner applies only what it is missing
and never objects to a database ahead of it.

- **An item has an owner** (Phase 69) — a campaign names a default reviewer
  stamped onto every item it snapshots; a single item can be reassigned; and
  `GET /api/campaigns/mine` is a reviewer's queue (pending items in open
  campaigns). **Assignment is advisory**: it routes work and makes a queue
  visible, it is not an authorization gate — anyone with `approve` can still
  decide any item, and the trail records who did. Console: a reviewer column,
  `7=Assign reviewer`, and a My Review Queue screen (F7 from menu 17).
  **Also fixes a pre-existing console bug**: the item screen gated deciding on
  `manage_users` while the API has gated it on `approve` since Phase 39, so the
  dedicated approver role saw a read-only screen.

- **A campaign nudges before it lapses** (Phase 70) — the first reminder fires
  `PAM_CERT_REMIND_DAYS` (default 7, `0` disables) before the due date and repeats
  daily while items are pending, through the same alert channel as break-glass,
  carrying the pending count, how overdue it is, and **which reviewer is holding
  it up**. It stops when the campaign is closed, or when nothing is left pending —
  the second cancels rather than repeats, because nagging about finished work is
  how an alert channel gets muted.

- **A documentation currency pass** (Phase 70a) — all 18 doc status markers
  brought to 0–70, saying explicitly where a phase changed nothing; the §4 config
  table completed; and `SECURITY-GAPS.md` finally recording the Phase 66 review
  (findings AV–AX).

**New audit actions**: `certification.item_assigned`, `certification.reminder`.
**New environment variable**: `PAM_CERT_REMIND_DAYS`.

- **A campaign nudges before it lapses** (Phase 70) — the last item of the
  Phase 19 deferral. The first reminder fires `PAM_CERT_REMIND_DAYS` (default 7)
  before a campaign's due date and repeats daily while items are pending, through
  the same alert channel as break-glass, carrying the pending count, how overdue
  it is, and **which reviewer is holding it up**. It stops on the two conditions
  that mean the work is over: a closed campaign, or nothing left pending — the
  second cancels rather than repeats, because nagging about finished work is how
  an alert channel gets muted. Migration `0031` is additive; new audit action
  `certification.reminder`.

- **An item has an owner** (Phase 69) — a campaign can name a default reviewer,
  stamped onto every item it snapshots; a single item can be reassigned; and
  `GET /api/campaigns/mine` is a reviewer's queue (pending items in open
  campaigns). **Assignment is advisory**: it routes work and makes a queue
  visible, it is not an authorization gate — anyone with `approve` can still
  decide any item, and the trail records who did. Console: a reviewer column,
  `7=Assign reviewer`, and a My Review Queue screen (F7 from menu 17). Migration
  `0030` is additive; new audit action `certification.item_assigned`.
  **Also fixes a pre-existing console bug**: the item screen gated deciding on
  `manage_users` while the API has gated it on `approve` since Phase 39, so the
  dedicated approver role saw a read-only screen.

## [0.13.0] — 2026-08-08

Certification campaigns become something an organisation can actually run: scoped
so a review is finishable, and scheduled so it does not depend on somebody
remembering.

**Minor, and it carries a migration** (`0029`). It is additive with defaults that
reproduce the old behaviour, applied automatically at startup, and every existing
campaign keeps meaning exactly what it meant. **Rolling back to 0.12.0 is safe**,
and checked rather than assumed: the added columns are `NOT NULL DEFAULT` or
nullable, 0.12.0 names its columns explicitly in every campaign read and write,
and the migration runner applies only what it is missing — it never objects to a
database ahead of it. A 0.12.0 binary therefore starts unchanged against the
migrated schema and simply ignores the scope and the schedule.

- **Campaigns you can scope and schedule** (Phase 68) — a campaign snapshotted
  *every* grant and safe member, which past a demo is a list nobody completes. It
  can now be scoped to **one safe** (its members *and* the grants on every target
  assigned to it) or **one subject** (everything a person or role holds, anywhere
  — the leaver review), and `recur_days` makes it the anchor of a recurring
  series that opens the next campaign on schedule with the same scope. **Closing
  the anchor stops the series.** An unknown scope is refused with 422 rather than
  silently widened to "everything". The scheduler is leader-locked and always on,
  and advances the anchor *after* a successful spawn, so a crash repeats a review
  rather than skipping a period. Console menu 17 gains both, and names a
  campaign's scope by safe name.

- **The token-exchange screen fits its terminal** (Phase 67b) — Phase 67's table
  put a full SPIFFE ID in every cell, so a row overflowed the 980px terminal and
  pushed the last column off screen; on a refused row that column is the *reason*.

**Audit-detail change**: `certification.campaign_created` gains `scope:`,
`safe:`, `subject:`, `recur_days:` and `recurring_from:`. No vocabulary change and
no new environment variable.

- **Campaigns you can scope and schedule** (Phase 68) — a certification campaign
  snapshotted *every* grant and safe member, which past a demo is a list nobody
  completes. It can now be scoped to **one safe** (its members and the grants on
  every target in it) or **one subject** (everything a person or role holds — the
  leaver review), and `recur_days` makes it the anchor of a recurring series that
  opens the next campaign on schedule with the same scope. Closing the anchor
  stops the series. An unknown scope is refused rather than silently widened to
  "everything". Migration `0029` is additive; existing campaigns are unchanged.
  **Audit-detail change**: `certification.campaign_created` gains `scope:`,
  `safe:`, `subject:`, `recur_days:` and `recurring_from:`.

- **The token-exchange screen fits its terminal** (Phase 67b) — Phase 67's table
  put a full SPIFFE ID in every cell, so a row overflowed `#term`'s 980px and
  pushed the last column off the screen: on a refused row that column is the
  *reason*, which is the whole point of the row. Identities now show as paths
  within a trust domain stated once above the table, cells truncate before they
  pad, and the column header no longer says "Actor" on rows that name a delegator.

## [0.12.0] — 2026-08-07

A **minor** rather than a patch: Phase 67 adds a capability, not a fix. It is the
last curl-only one, so the console-parity claim the README has made since Phase 25
is finally true — every shipped capability is operable from the 5250 portal.

- **Console screen for the token exchange** (Phase 67) — menu **27, Delegated
  agent tokens (RFC 8693)** (`read_audit`): the broker's signing key (`kid`, key
  type, curve, algorithm) and the delegation chains it has issued, with refusals
  beside them. The chains come from the audit trail because a minted SVID is
  stateless — the broker signs it and forgets it — so `broker.token.exchanged` is
  the only record one ever existed. Read-only by nature: minting is an agent
  presenting its *own* credential to `POST /v1/token`, which a human at a
  terminal cannot do on its behalf and should not be able to.

- **The review of phases 62–65** (Phase 66) — three findings, none a bypass. The
  SFTP capture handle table admitted pipelined opens past its cap (a real ceiling
  of 1152 against a documented 128 — bounded either way, so nothing grew without
  limit); the release workflow's `dry_run` input had become dead and is removed,
  so the manual trigger is unambiguously a rehearsal and a signed release can no
  longer be published by hand from an arbitrary ref; and the path-derived session
  id reached three audit details unquoted.

No schema, environment-variable, audit-vocabulary or wire-format change.
Upgrading from 0.11.2 needs nothing.

- **Console screen for the token exchange** (Phase 67) — menu **27, Delegated
  agent tokens (RFC 8693)** (`read_audit`): the broker's signing key (`kid`,
  type, curve, algorithm) and the delegation chains it has issued, read from the
  audit trail because a minted SVID is stateless and that event is the only
  record it existed. Refusals are shown beside them. Read-only by nature —
  minting is an agent presenting its own credential. This was the last curl-only
  capability, and the one place the "full console parity" claim was false.

- **The review of phases 62–65** (Phase 66) — reading the phases that closed the
  2026-08-07 sweep the way the sweep read everything else. Three findings, none a
  bypass: the SFTP handle-table bound admitted pipelined opens past its cap
  (1152 rather than the 128 its comment claimed — bounded either way); the
  release workflow's `dry_run` input had become dead, controlling nothing, and is
  removed so the manual trigger is unambiguously a rehearsal; and the
  path-derived session id reached three audit details unquoted.

## [0.11.2] — 2026-08-07

**The artifacts for 0.11.1.** That tag exists and stays where it is — the Go
module proxy had already cached it, so re-pointing it would leave a permanent
checksum mismatch for anyone running `go get …@v0.11.1` — but its release
pipeline failed *before the push*, so no image, no signature, no attestations and
no GitHub Release were ever produced under it. 0.11.2 is the same content plus
the two fixes for that failure, and it is what every manifest pins.

- **The release build takes no cache** (Phase 65b) — Phase 64 had added
  `cache-from`/`cache-to: type=gha`, which requires the docker-container driver
  while the job uses buildx's default `docker` driver. Removed rather than
  repaired: a release is the one build whose speed matters least and whose
  provenance matters most. The Dockerfile's cache mounts stay and still serve
  everyday `docker build`.
- **The release dry run actually rehearses** (Phase 65b) — it used to skip the
  entire release job, so it proved only that `go test` runs and would have sailed
  past the failure above. It now BUILDS the image, while the push, signature,
  attestations and GitHub Release stay gated on a real tag.

## [0.11.1] — 2026-08-07 · source tag only, superseded by 0.11.2

Phases 63–65: the rest of the 2026-08-07 sweep, the container build, and the
self-audit catching up with itself. Cut immediately rather than banked, because
the gap v0.11.0 existed to close was precisely a pinned image drifting behind the
fixes — banking these would have started that over.

**Audit-vocabulary change.** `proxy.auth_rate_limited` is removed from the
documented vocabulary **and from the OCSF exporter's Detection Finding
classification**; no code path has emitted it since Phase 52e, so any SIEM rule
built on it was one that could never fire. `breakglass.unseal_failed` and
`session.relay_start` are now documented, the first also classified.

**Operator-visible fixes.** A refused in-session step-up decision no longer
leaves an audit record saying it *was* decided — a refused self-approval had
recorded the paused operator as having decided their own statement. Recording
playback now fails closed on its audit like every other path that hands over
KEK-protected material. And a step-up decision that resolves between the check
and the claim answers **409** rather than a misleading 404.

**Build.** `Dockerfile.pkcs11` accepts `VERSION`/`COMMIT`, so an HSM-backed
deployment stops reporting `pam-server dev (none)`; base images are pinned by
digest; BuildKit cache mounts mean an everyday `docker build` no longer
recompiles the standard library from cold. The release build itself deliberately
takes no cache — a signed, attested artifact is a stronger claim when nothing
outside the commit fed the compiler.

- **The self-audit absorbs the phases it had not read** (Phase 65) —
  documentation only. `docs/SECURITY-GAPS.md` recorded every read-only sweep and
  none of the per-phase reviews, so the seventeen defects found by reviewing
  phases 59a, 60a and 61a the day each merged lived only in the roadmap. Closes
  the last item of the 2026-08-07 sweep; every sweep is now closed.

- **The container build** (Phase 64) — no runtime change. Both Dockerfiles gain
  BuildKit cache mounts for the Go module and build caches (and `release.yml`
  a GitHub Actions cache), so a build no longer recompiles the standard library
  and every dependency from cold. `Dockerfile.pkcs11` finally accepts
  `VERSION`/`COMMIT`, so an HSM-backed deployment stops reporting
  `pam-server dev (none)`. Base images are pinned **by digest** as well as by
  tag, dependabot keeps them current, `EXPOSE` names the database-proxy ports it
  had omitted, and CI builds **both** images instead of one.

- **Close the rest of the 2026-08-07 sweep** (Phase 63) — six findings, none a
  bypass. A refused step-up decision no longer leaves an audit record saying it
  was decided (a refused self-approval had recorded the *paused operator* as
  deciding their own statement); `session.playback` fails closed on its audit
  like every other path that hands over KEK-protected material; the SFTP capture
  handle table is bounded on the request leg instead of growing past the
  open-artifact cap; the dead `required` field is gone; and the audit vocabulary
  matches the code again (`proxy.auth_rate_limited` removed from the docs and the
  OCSF classifier, where it was a rule that could never fire).
  `deploy/docker/.env.example` documents the Phase 57 token-exchange variables.
  **Audit-vocabulary change**: one removal, two additions.

## [0.11.0] — 2026-08-07

The release that makes the deployable artifact current again. `v0.10.0` was
tagged on 2026-07-28 and every Kubernetes, Helm and Terraform manifest has
pinned it since — but the read-only sweep of 2026-07-30 landed **ten fixes over
the following two days**, so the pinned image did not contain them. Among them:
a tunnel-scoped viewer token that authenticated at all three session proxies
(reproduced *opening a session*), the unauthenticated cross-replica live and
kill buses, three paths to a credential that skipped their siblings' gates, and
five paths that acted before — or without — recording it. A pin is only as good
as what it points at, and this one pointed at a build the project itself
documents as fixed.

Everything from phases 53–62 is in this release. Beyond the fixes above:

- **In-session step-up decisions are bound to the pause they were made about**
  (Phase 62) — a sealed cross-replica decision named only the session, while a
  session pauses once per flagged statement, so a decision captured off the
  NOTIFY channel released the operator's *next* statement for as long as its
  timestamp stayed fresh. Decisions now name the pause and the applying replica
  refuses one it has already resolved. **Wire-format change** on the step-up
  decision bus (see below).
- **A dependent account names the credential that manages it** (Phases 61/61a),
  the ITSM ticket gate holds at connect time (60/60a), safe-scoped approval
  policy (58), RFC 8693 token-exchange minting (57), cross-replica step-up
  decisions (56), SFTP per-file content recording (59/59a), the SQL Server (TDS)
  proxy (53), the VNC connector (54) and cross-replica live monitoring (55).

**Upgrade note (HA only).** The step-up decision seal now binds the pause, so a
replica running 0.11.0 and one running 0.10.0 cannot authenticate each other's
cross-replica step-up decisions. The failure is closed — a decision is refused,
never misapplied — and a supervisor can still decide on the replica hosting the
session. Roll all replicas to finish the upgrade. Nothing else on the bus, in
the store or in the API changes.

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
  itself by booting the finished image on a throwaway overlay and asking PAMv1 for
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

[Unreleased]: https://github.com/morandeirachema/pamv1/compare/v0.58.2...HEAD
[0.65.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.65.0
[0.64.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.64.0
[0.63.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.63.0
[0.62.1]: https://github.com/morandeirachema/pamv1/releases/tag/v0.62.1
[0.62.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.62.0
[0.61.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.61.0
[0.60.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.60.0
[0.59.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.59.0
[0.58.3]: https://github.com/morandeirachema/pamv1/releases/tag/v0.58.3
[0.58.2]: https://github.com/morandeirachema/pamv1/releases/tag/v0.58.2
[0.58.1]: https://github.com/morandeirachema/pamv1/releases/tag/v0.58.1
[0.58.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.58.0
[0.57.1]: https://github.com/morandeirachema/pamv1/releases/tag/v0.57.1
[0.57.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.57.0
[0.56.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.56.0
[0.55.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.55.0
[0.54.1]: https://github.com/morandeirachema/pamv1/releases/tag/v0.54.1
[0.54.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.54.0
[0.53.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.53.0
[0.52.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.52.0
[0.51.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.51.0
[0.50.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.50.0
[0.49.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.49.0
[0.48.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.48.0
[0.47.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.47.0
[0.46.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.46.0
[0.45.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.45.0
[0.44.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.44.0
[0.43.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.43.0
[0.42.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.42.0
[0.41.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.41.0
[0.40.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.40.0
[0.39.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.39.0
[0.38.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.38.0
[0.37.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.37.0
[0.36.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.36.0
[0.35.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.35.0
[0.34.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.34.0
[0.33.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.33.0
[0.32.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.32.0
[0.31.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.31.0
[0.30.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.30.0
[0.29.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.29.0
[0.28.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.28.0
[0.27.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.27.0
[0.26.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.26.0
[0.25.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.25.0
[0.24.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.24.0
[0.23.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.23.0
[0.22.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.22.0
[0.21.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.21.0
[0.20.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.20.0
[0.19.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.19.0
[0.18.2]: https://github.com/morandeirachema/pamv1/releases/tag/v0.18.2
[0.18.1]: https://github.com/morandeirachema/pamv1/releases/tag/v0.18.1
[0.18.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.18.0
[0.17.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.17.0
[0.16.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.16.0
[0.15.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.15.0
[0.14.3]: https://github.com/morandeirachema/pamv1/releases/tag/v0.14.3
[0.14.2]: https://github.com/morandeirachema/pamv1/releases/tag/v0.14.2
[0.14.1]: https://github.com/morandeirachema/pamv1/releases/tag/v0.14.1
[0.14.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.14.0
[0.13.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.13.0
[0.12.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.12.0
[0.11.2]: https://github.com/morandeirachema/pamv1/releases/tag/v0.11.2
[0.11.1]: https://github.com/morandeirachema/pamv1/releases/tag/v0.11.1
[0.11.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.11.0
[0.10.0]: https://github.com/morandeirachema/pamv1/releases/tag/v0.10.0
