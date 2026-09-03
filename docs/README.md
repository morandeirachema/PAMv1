# PAMv1 — documentation

> Last updated: 2026-09-03 · Reflects: Phases 0–227 and 229–238, and release v0.65.0 (see [CHANGELOG.md](../CHANGELOG.md)).

> **Living docs, kept in step with the code.** Nearly every doc here carries a
> `Last updated · Reflects Phases 0–N` line and, where it tracks change, a
> change-log table at the foot. Two are exempt by nature:
> [ARCHITECTURE-DIAGRAMS.md](ARCHITECTURE-DIAGRAMS.md) is code-generated, and
> [RELATED-PROJECTS.md](RELATED-PROJECTS.md) tracks the outside world rather than
> this repo. New to the project? Read the
> [main README](../README.md) first, then follow your audience path below.
>
> 🟢 **These are living documents — updated in the same change as the code, automatically.**
> Whenever a change touches structure, packages, schema, wire formats, env vars, the
> audit vocabulary, deploy manifests, ports/flows, or user-visible behavior, the affected
> living documents (and the two shareable overview artifacts, below) are updated in the
> **same** change — no separate approval step, no waiting to be asked. The full set is
> **every file listed under [Every document](#every-document)** plus `ROADMAP.md`, the root
> `README.md` / `README.es.md`, and the living overview artifacts
> ([English](https://claude.ai/code/artifact/a1b34e5b-cd84-4fc7-8389-ebb1897495f7) ·
> [Español](https://claude.ai/code/artifact/b9f19443-5ad1-42d2-955f-e43ca17ac542)).
> `ARCHITECTURE-DIAGRAMS.md` is **code-generated** (`go run ./cmd/archgen`, CI-enforced) — never hand-edited.

> ⚠️ **Beta · for learning purposes.** PAMv1 is feature-complete against its
> [roadmap](../ROADMAP.md) and has closed every finding of its own security
> self-audit, but it has not been audited by anyone outside the project and is not
> production-ready.

## Pick your path

| You are… | Read, in order |
|---|---|
| **New / evaluating** | [Sysadmin Guide](SYSADMIN-GUIDE.md) → [High-Level Architecture](ARCHITECTURE-HIGH-LEVEL.md) → [Requirements](REQUIREMENTS.md) |
| **Day-to-day operator** (connect, approve, audit) | [User Guide](USER-GUIDE.md) → [Sysadmin Guide (runbook)](SYSADMIN-GUIDE.md#6-day-to-day-operations-the-runbook) |
| **Administrator / deployer** | [Admin Guide](ADMIN-GUIDE.md) → [Requirements](REQUIREMENTS.md) → [Ports & Flows](PORTS-AND-FLOWS.md) → [Backup & Restore](BACKUP-AND-RESTORE.md) → [External-Infra Gaps](EXTERNAL-INFRA-GAPS.md) |
| **Developer / contributor** | [Low-Level Architecture](ARCHITECTURE-LOW-LEVEL.md) → [Code Guide](CODE-GUIDE.md) → [Architecture Diagrams](ARCHITECTURE-DIAGRAMS.md) → [ROADMAP](../ROADMAP.md) → [Security Gaps](SECURITY-GAPS.md) |
| **Auditor / compliance** | [NIS2 Compliance](NIS2-COMPLIANCE.md) → [Protocols & Crypto](PROTOCOLS-AND-CRYPTO.md) → [Security Gaps](SECURITY-GAPS.md) → [User Guide (auditor)](USER-GUIDE.md) → [Admin Guide (audit)](ADMIN-GUIDE.md#92-audit-trail-database) |
| **OT / industrial operator** | [OT Deployment](OT-DEPLOYMENT.md) → [NIS2 Compliance](NIS2-COMPLIANCE.md) → [Ports & Flows](PORTS-AND-FLOWS.md) → [Admin Guide](ADMIN-GUIDE.md) |

## Every document

### Guides (task-oriented)
- **[SYSADMIN-GUIDE.md](SYSADMIN-GUIDE.md)** — the mental model + a `curl`/`ssh` runbook; the best first read for a shell-native admin.
- **[USER-GUIDE.md](USER-GUIDE.md)** — for operators, auditors and approvers: sign in, connect through the proxy, per-role abilities.
- **[ADMIN-GUIDE.md](ADMIN-GUIDE.md)** — the full reference: deploy, every `PAM_*` flag, manage targets/credentials/users/roles, break-glass, logging & audit.

### Architecture & code
- **[ARCHITECTURE-HIGH-LEVEL.md](ARCHITECTURE-HIGH-LEVEL.md)** — conceptual view: components, trust zones, data flows.
- **[ARCHITECTURE-LOW-LEVEL.md](ARCHITECTURE-LOW-LEVEL.md)** — the engineer's map: packages, schema, wire formats, the full `PAM_*` table, audit vocabulary, invariants. Read it first as a contributor.
- **[ARCHITECTURE-DIAGRAMS.md](ARCHITECTURE-DIAGRAMS.md)** — code-generated package graph, data model and REST-surface map (CI-enforced current; do not hand-edit).
- **[CODE-GUIDE.md](CODE-GUIDE.md)** — a narrative walkthrough of how the code actually runs, package by package and flow by flow — opens with a *Reading Go when you write Python* primer (§0.1), so you can follow it without writing Go.

### Deploy & operate
- **[REQUIREMENTS.md](REQUIREMENTS.md)** — run specs: ports, resource requests/limits, versions, rough sizing.
- **[PORTS-AND-FLOWS.md](PORTS-AND-FLOWS.md)** — the listener/egress matrix for firewalls, security groups, NetworkPolicies and OT segmentation.
- **[VNC-TESTING.md](VNC-TESTING.md)** — run the in-portal VNC viewer end to end against a real TigerVNC desktop with the bundled demo stack.
- **[PROTOCOLS-AND-CRYPTO.md](PROTOCOLS-AND-CRYPTO.md)** — every protocol PAMv1 speaks or brokers and every cryptographic mechanism it relies on, with where each is implemented and where verification is opt-in.
- **[BACKUP-AND-RESTORE.md](BACKUP-AND-RESTORE.md)** — runbook for backing up the database and the vault KEK *separately*.
- **[EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md)** — what needs a real host/account to verify honestly before you rely on it.
- **[RDP-TESTING.md](RDP-TESTING.md)** — the procedure to verify the RDP path end to end: automated tests, a local runbook, and troubleshooting.

### Security, compliance & OT
- **[PROTOCOLS-AND-CRYPTO.md](PROTOCOLS-AND-CRYPTO.md)** — every protocol PAMv1 speaks or brokers and every cryptographic mechanism it relies on: the vault envelope and its KEK providers, the audit chains, key custody, per-protocol TLS posture, and a single table of where verification is opt-in.
- **[SECURITY-GAPS.md](SECURITY-GAPS.md)** — a security self-audit: every gap found, and whether it was fixed, mitigated or deferred.
- **[SECURITY-AUDIT-2026-08-26.md](SECURITY-AUDIT-2026-08-26.md)** and **[SECURITY-AUDIT-2026-08-27.md](SECURITY-AUDIT-2026-08-27.md)** — the two dated, redacted audit reports (five read-only passes each, every finding re-verified by hand): what was found, where, and how it was closed.
- **[AGENT-THREAT-MODEL.md](AGENT-THREAT-MODEL.md)** — the AI-agent access broker's threat model: OWASP LLM Top 10 & MITRE ATLAS mapped to broker controls.
- **[NIS2-COMPLIANCE.md](NIS2-COMPLIANCE.md)** — maps PAMv1 features to Directive (EU) 2022/2555 (NIS2) Art. 21/23.
- **[OT-DEPLOYMENT.md](OT-DEPLOYMENT.md)** — the IEC 62443 / Purdue-model deployment pattern and OT-specific controls.

### Landscape
- **[RELATED-PROJECTS.md](RELATED-PROJECTS.md)** — where PAMv1 sits among open-source projects and commercial PAM vendors.

## House style (for doc authors)

Keep the set reading as one product:

1. **H1** is `# PAMv1 — <Title>` (project name first, em-dash separator, one per file).
2. **Status header**, a blockquote right under the H1: `> Last updated: YYYY-MM-DD · Reflects: Phases 0–N …` (use `Last updated`, ISO dates).
3. **Living-document note** (a blockquote) for any doc that tracks code — either `> **Living document.** Update when <trigger> changes.` or the newer `> 🟢 **Living document** — updated in the same change as the code`. Generated docs say `> **Do not edit by hand.**` instead.
4. **Maturity banner** (`> ⚠️ **Beta · for learning purposes.** …`) on any doc a newcomer might land on first — the guides, the compliance and deployment docs, this hub. Reference docs read in context (the architecture pair, CODE-GUIDE, SECURITY-GAPS) do not repeat it. Keep the wording in step with the [README](../README.md); the two disagreeing is worse than neither carrying it.
5. **Change-log table** at the foot of any doc that evolves — `| Date | Change |`, newest first, ISO dates. Bump the `Last updated` line to the newest change-log date.
6. **Diagrams are [Mermaid](https://mermaid.js.org/), never ASCII** (repo hard rule); wrap wide diagrams so they scroll, not the page.
7. **Cross-links are relative paths**: bare `FILE.md` for siblings here, `../ROADMAP.md` / `../README.md` / `../deploy/…` for repo-root and code; deep-link a section with `#anchor`. No absolute GitHub URLs for in-repo files.
8. **Fixed vocabulary**: *target* (an onboarded machine/database), *credential* (the vaulted object) vs *secret* (its plaintext), *operator* (a human using the proxy) vs *user* (the RBAC role), *portal* (the web app) vs *console* (its 5250 UI), **PAM token** (a per-user/session token) vs **bootstrap API key** (`PAM_API_KEY`).
9. **No doc is a dead end** — every reader-facing doc links onward, back to this hub or the [README](../README.md), or to the next doc in its path. Reference docs that are always reached *from* somewhere may rely on their inbound links instead.
10. **Update the doc in the same commit as the code it describes** — that is what keeps this set trustworthy.

## Deploy references

The deployment directories carry their own READMEs, and nothing in this hub
linked to them until now:

- **[../deploy/docker/README.md](../deploy/docker/README.md)** — the local full
  stack (hardened PostgreSQL, guacd, pam-server) and the throwaway RDP demo.
- **[../deploy/ova/README.md](../deploy/ova/README.md)** — the **virtual
  appliance**: one importable VM (Debian 13 + PostgreSQL + the binary + the full
  source), built with QEMU and no root, generating its own keys on first boot.
- **[../deploy/k8s/README.md](../deploy/k8s/README.md)** — the raw Kubernetes
  manifests, and the ConfigMap/Secret pair that is the Kubernetes twin of
  `.env.example`.
- **[../deploy/k8s/sops/README.md](../deploy/k8s/sops/README.md)** — SOPS + age
  encrypted secrets, and the CI check that proves the committed example really is
  encrypted.
- **[../deploy/k8s/conjur/README.md](../deploy/k8s/conjur/README.md)** — sourcing
  bootstrap secrets from CyberArk Conjur instead of env vars.

## Change log

| Date | Change |
|---|---|
| 2026-09-03 | Phase 238 (the review of 236/237) documented: ARCHITECTURE-LOW-LEVEL, ARCHITECTURE-HIGH-LEVEL, CODE-GUIDE and ADMIN-GUIDE change logs (the ack is now complete on the wire, Slack decisions are audited as the linked user, a `PUT /api/users` conflict no longer half-applies); v0.65.0's digest — owed by Phase 237 and never recorded — written into ROADMAP, README and CHANGELOG. No table, vocabulary or env change. |
| 2026-09-02 | Phase 236 (the review of 232–235) documented: ARCHITECTURE-LOW-LEVEL's table list (`users.slack_user_id`), migration mark (`0052`), user-administration bullet, audit vocabulary (`access.slack_decision`) and change log; ARCHITECTURE-HIGH-LEVEL, CODE-GUIDE (§3.3 migration mark) and ADMIN-GUIDE (the Slack section's new *link each approver* step) change logs. |
| 2026-08-27 | Phase 226 (the MCP revision negotiated, not pinned) documented: ARCHITECTURE-LOW-LEVEL's change log, CODE-GUIDE's MCP bullet and change log, ADMIN-GUIDE's broker section (revisions, batches, the header, the transport that stays HTTP+SSE), both READMEs' MCP line. |
| 2026-08-27 | Phase 224 (the trust bundle follows the file) documented: ARCHITECTURE-LOW-LEVEL's `PAM_BROKER_TRUST_DOMAIN_JWKS` row and change log, ADMIN-GUIDE's SPIFFE paragraph, EXTERNAL-INFRA-GAPS's SVID row, AGENT-THREAT-MODEL's evidence table, CODE-GUIDE's change log. |
| 2026-08-27 | Phase 222 (a resume token bound to its collector — the 2026-08-26 audit's F-7, its last finding) documented: ARCHITECTURE-LOW-LEVEL's table list, migration mark (`0051`) and change log; CODE-GUIDE §3.3's atomic-spend statement and §3.5's park/mint sentence; AGENT-THREAT-MODEL's `jti:` paragraph and evidence table; ADMIN-GUIDE's approval walkthrough; PROTOCOLS-AND-CRYPTO's credential table; BACKUP-AND-RESTORE, REQUIREMENTS and SYSADMIN-GUIDE headers; the audit report's F-7 row and §3 (every finding of that audit now closed) and SECURITY-GAPS's register. |
| 2026-08-27 | Phase 221 (documentation resync after 217–220): two stale "latest migration" marks corrected (`0025` → `0050` in ARCHITECTURE-LOW-LEVEL §2.2, `0018` → `0050` in CODE-GUIDE §3.3), CODE-GUIDE's atomic-operation and advisory-lock bullets taught the reservation, the 2026-08-26 audit report's M-3/M-6 rows marked closed, change-log rows for 217/219 added to ADMIN-GUIDE, ARCHITECTURE-HIGH-LEVEL, CODE-GUIDE and BACKUP-AND-RESTORE (whose high-water narrative now reaches `0050`), REQUIREMENTS and SYSADMIN-GUIDE headers state that 217–220 add no requirement and no worker, and SECURITY-GAPS's register records the two closures with F-7 as the one finding still open. |
| 2026-08-27 | Phase 219 (the budget becomes a compare-and-spend — the 2026-08-26 audit's M-3, reservation half) documented: ARCHITECTURE-LOW-LEVEL's table list gains `agent_call_reservations` (`0050`) and its change log the design; AGENT-THREAT-MODEL's budget section states that the trail count is now the reported number and the reservation the enforced one, why the two never disagree in the permissive direction, and that a parked call holds its slot — with the burst test in its evidence table; ADMIN-GUIDE's `PAM_BROKER_BUDGET_PER_DAY` and `PAM_BROKER_MAX_CALLS_PER_TOKEN` rows say the limit holds under a burst. |
| 2026-08-27 | Phase 217 (the twenty store methods the contract suite never called — the 2026-08-26 audit's M-6) documented: ARCHITECTURE-LOW-LEVEL's test-strategy bullet now states that `storetest` covers every `Store` method and that its assertions are written from the interface's doc comments, and its change log records the four backend divergences that writing them exposed. The `store.Store` interface comments gain the constraints the suite now pins (`CreateApprovalInvite`'s sentinels, the invite listings' tie-break, a denial's empty token). |
| 2026-08-27 | **Phase 215 — the 2026-08-27 audit.** New [SECURITY-AUDIT-2026-08-27.md](SECURITY-AUDIT-2026-08-27.md) (six findings, all fixed) and the 2026-08-26 report moved under `docs/` (the repo root keeps its fixed file set), both indexed above and linked from `SECURITY.md`. Three claims corrected where they were false: ADMIN-GUIDE's allowlist "enforced everywhere that principal authenticates" (it was not, for sessions) and "deactivation actually cuts access" (not the sessions the user already held), and ARCHITECTURE-LOW-LEVEL's "`join_id` and guest key are the same string" (they are not any more, and must not be). §5 gains `session.revoke_failed`; PROTOCOLS §2.5's guest-key row says hashed, as it has been since Phase 212 |
| 2026-08-26 | **Release v0.58.1** (Phase 214 — v0.58.0's pipeline failed *after* the image push because the repository's new mixed-case name reached an OCI reference, so that tag stays as an unsigned-image-only release the CHANGELOG says not to deploy, and v0.58.1 is the same source plus the pipeline fix): every `Reflects:` header states 0–214, both READMEs restated, `NIS2-COMPLIANCE.md`'s evidence row and every `deploy/` pin at 0.58.0. The pre-release currency check found that **Phase 212 had bumped every header without documenting itself** — the mirror image of the drift Phase 208 found: there, headers stalled behind the code; here they moved while the content did not. `PAM_DOUBLELOCK_MIN_LENGTH` was in no document; migration `0049` was attributed to Phase 197 in BACKUP-AND-RESTORE and absent from REQUIREMENTS; DoubleLock's new iteration count and minimum length were in neither the ADMIN-GUIDE nor PROTOCOLS-AND-CRYPTO §2.5 — which had never carried the DoubleLock row its own Phase 135 change-log entry says it did; and neither architecture doc nor CODE-GUIDE had a change-log row for 212 or 213. All closed here, and Phase 213's rename recorded across the set |
| 2026-08-26 | Phase 209 (a ceiling on one token) documented: ARCHITECTURE-LOW-LEVEL §4 gains `PAM_BROKER_MAX_CALLS_PER_TOKEN` and §5 gains `agent.token_budget_exhausted`/`_check_failed`; AGENT-THREAT-MODEL gains the control row; ADMIN-GUIDE gains the knob with the two identity kinds it does not cover. The roadmap's own wording for this item was **wrong and is corrected in place**: it described a ceiling keyed on `session:`, which the party being limited chooses for itself |
| 2026-08-26 | Phase 208 (doc-currency audit against v0.56.0). Eight documents had **stalled at `Phases 0–205`** — 206 and 207 each bumped only the headers that were already current, so a sweep keyed on "0–206" could not see a document that never reached 206; all eighteen now state 0–208 **with what the new phases do or do not change for each**. Both READMEs claimed the wrong roadmap range and still defined beta as "every phase through 52g has shipped", true when beta was declared and wrong for 150 phases since. And §5 was missing three refusal actions, two of which **appear as a literal nowhere in the source**: `gateCredentialAccess` audits its argument plus `_denied`, so the emitted name is assembled at runtime and every literal-grep audit was blind to it. `api.TestGateDenialNamesAreDocumented` now reconstructs the names the way the helper does and requires each inside §5, not merely somewhere in the file |
| 2026-08-26 | Release-currency check alongside v0.56.0 found a **four-release drift**: `NIS2-COMPLIANCE.md`'s Art. 21(2)(e) evidence row still named v0.51.0 as the current release, stale since v0.52.0 — in a row whose entire purpose is to be what an auditor reads. It is named in the release checklist by name and was missed anyway, which is the same lesson the `deploy/` pin sweep already encodes: a list of places is only as good as its last update, so the durable check is a grep that enumerates every version string rather than a checklist that remembers them |
| 2026-08-25 | Documentation currency audit alongside v0.55.0. Verified rather than assumed, in both directions: **zero** documented env vars the code never reads (the Phase 182 defect class), **zero** server env vars absent from every operator-facing doc, and **zero** audit actions the code emits that §5 omits. One real defect found and fixed — BACKUP-AND-RESTORE, SYSADMIN-GUIDE and REQUIREMENTS all stated the migration high-water as `0047` while carrying `Reflects:` headers claiming currency through 205, when Phase 197 moved it to `0048`. A header asserting currency over a body that stopped being true is the same shape as the stale release digest Phase 190 closed |
| 2026-08-26 | Phase 206 (proof of possession) documented across the set: PROTOCOLS-AND-CRYPTO §2.8 gains a **fifth** JWT verification path and corrects the sentence that said a minted delegated token is a bearer token — it need not be any more; ARCHITECTURE-LOW-LEVEL adds `PAM_BROKER_REQUIRE_POP` and `PAM_BROKER_PUBLIC_URL` to §4 and `agent.pop_denied` to the §5 vocabulary; AGENT-THREAT-MODEL gains the control row and states its limit (the delegator names the key, so this bounds token THEFT, not workload attestation); ADMIN-GUIDE §on agent identity gains a how-to with the exchange call, the three behaviours to know before enabling, and the reason codes |
| 2026-08-25 | Phase 195 (fail-closed route map): SECURITY-GAPS records that the generated API-surface table had labelled sixteen authenticated routes `public` — the whole AI-agent tool-call surface and the whole SCIM surface among them — because `archgen`'s classifier defaulted to "public" for schemes added after it was written; ARCHITECTURE-LOW-LEVEL and CODE-GUIDE record the fail-closed classifier that replaces it |
| 2026-08-25 | Phase 193 (the flags that were wrong) documented across the set: ADMIN-GUIDE §9.9's reason table gains `budget_zero` and `quarantine_unknown` and marks `not_enrolled` as conditional on `PAM_BROKER_REQUIRE_ENROLLED_SVID`, both architecture docs and CODE-GUIDE record `ReachGrantSnapshot` and why ordering two grant reads cannot be made correct, and SECURITY-GAPS carries the finding that a review flag pointing the wrong way is a control failure of its own kind. Phase 192 (Go 1.27 toolchain parity) is in the same sweep |
| 2026-08-25 | Phase 191 (the subject's own state) documented across the set: ADMIN-GUIDE §9.9 gains the `blocked` reason table and the note that the total deliberately does not change when it is non-empty, both architecture docs and CODE-GUIDE record the capability half `CanConnectTarget` cannot give and the fail-closed read reorder, USER-GUIDE describes the new red line on menu 31, and every `Reflects:` header moved to 0–191. Phase 190 (v0.52.0) is in the same sweep: its own entry records that the README's Status block had quoted v0.42.0's image digest for nine releases, and that the digest-recording pass now covers the README as well as ROADMAP.md |
| 2026-08-23 | Phase 189 (subject-indexed reachability) documented across the set: a new ADMIN-GUIDE §9.9 (the route, the five `via` reasons, why an unenrolled agent is answered and a directory identity is not, and the standing-vs-effective distinction), console menu 31 in USER-GUIDE's menu table, `access.reach_query` in the audit vocabulary, the new store reads and `auth.ReachableTargets` in both architecture docs, and BACKUP-AND-RESTORE's migration high-water mark moved to `0047` — an index-only migration, so a restore has nothing extra to carry |
| 2026-08-21 | **Phase 184 — documentation sync across the set.** Every doc's `Reflects:` header was current while five bodies still said "161–173": PORTS-AND-FLOWS, OT-DEPLOYMENT, RDP/VNC-TESTING, REQUIREMENTS and SYSADMIN-GUIDE now read through 183, with the knob count corrected from three to five and the migration count from two to three. Both READMEs said the roadmap runs 0–178. SECURITY-GAPS gained the **2026-08-19/21 self-sweeps** (findings CN–CP, one of them a defect a single phase old) and says what that implies about per-phase review; NIS2's control-mapping note absorbed 179–183; CODE-GUIDE gained the agent-admission order and what a verified `Identity` now carries. |
| 2026-08-21 | Phase 182 (inert knobs): the three broker refusals that could never fire now fail startup, and all three reached `deploy/docker/.env.example` and `deploy/k8s/configmap.example.yaml`, which had never mentioned them. |
| 2026-08-21 | Phase 183 (the approver's view): ADMIN-GUIDE's approval section gains the HOPS column and what it means, the threat model gains both controls and their test, and the low-level doc records why the new audit field is `svid_jti` and not `jti`. |
| 2026-08-21 | Phase 181 (`may_act` issued): the delegation section of ADMIN-GUIDE gains the extension parameter and its narrowing rules, PROTOCOLS-AND-CRYPTO's honest note that the claim was enforced but never issued is replaced by what now happens, and the threat model gains the control and its round-trip test. |
| 2026-08-21 | Phase 180 (posture on the agent path): a new env var in both configuration tables, `agent.posture_denied` in the audit vocabulary, the webhook's additive `kind` field in the admin guide, and the honest limit — a webhook attests a NAME, not the process — stated in the posture package doc, ADMIN-GUIDE and EXTERNAL-INFRA-GAPS alike. |
| 2026-08-19 | Phase 175 (recertifying non-human identities): the campaign section of ADMIN-GUIDE gains what a review now covers and what revoking an agent actually does, the threat model gains the two controls and their tests, and USER-GUIDE tells a reviewer why agent rows appear in their queue. |
| 2026-08-18 | Phase 174 (SVID enrollment and inventory) documented across the set: a new env var in both configuration tables, the audit vocabulary's three new actions, the migration high-water mark at `0046`, and the threat model's "still open" note on SVID inventory closed rather than left standing. |
| 2026-08-18 | Documentation currency pass over the AI-agent-broker batch (159–173). `ARCHITECTURE-HIGH-LEVEL.md`'s change log had stopped at Phase 157 and gained the nine missing rows; `SECURITY-GAPS.md` gained the **2026-08-17/18 research** section (five findings, all closed by 169–173, with the two live authorization defects called out as the shape Phase 159 had already found once); `PROTOCOLS-AND-CRYPTO.md` records that the verified `act` chain is now load-bearing for containment, plus the two honest edges (`may_act` enforced but never issued, no proof-of-possession); `PORTS-AND-FLOWS.md`'s "adds no flow" note extends to 173; `USER-GUIDE.md` gains the approver-visible DECIDE BY deadline. Every `Reflects:` header is at 0–173 / v0.48.0 |
| 2026-08-09 | Phase 95 — documentation currency pass across the whole set: every `Reflects:` header brought to 0–94 / v0.18.1 (they ranged from 0–70 to 0–93; this entry point still said v0.13.0), the READMEs' phase story extended past 61 (both languages), PORTS-AND-FLOWS gained the omitted ITSM egress (E14), EXTERNAL-INFRA-GAPS' ITSM row caught up with the Phase 84 connectors, and the CODE-GUIDE package map gained its ten missing packages |
| 2026-07-28 | Maturity banner corrected to **Beta** (it still said Alpha while the README said Beta — the entry point contradicting the doc that links to it). Added this file's own status header and change log, which house rules 2 and 5 require of every other doc. Rules 3, 4 and 9 rewritten to describe what the doc set actually does rather than a state it never reached. Linked the three deploy READMEs, which nothing in the repo referenced. Noted CODE-GUIDE §0.1 for readers who do not write Go |
