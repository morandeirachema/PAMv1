# Changelog

All notable released changes to pamv1 are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) with 0.x semantics — breaking
changes may land in minor versions until 1.0.

pamv1 is built phase by phase, and the full per-phase history — what shipped in
each phase, in what order, and why — lives in [ROADMAP.md](ROADMAP.md). This
file records **releases**: the tagged, signed points you can actually deploy.

## [Unreleased]

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

[Unreleased]: https://github.com/morandeirachema/pamv1/compare/v0.15.0...HEAD
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
