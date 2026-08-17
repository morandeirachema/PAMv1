# pamv1 — documentation

> Last updated: 2026-08-17 · Reflects: Phases 0–159 and release v0.42.0 (see [CHANGELOG.md](../CHANGELOG.md)).

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

> ⚠️ **Beta · for learning purposes.** pamv1 is feature-complete against its
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
- **[PROTOCOLS-AND-CRYPTO.md](PROTOCOLS-AND-CRYPTO.md)** — every protocol pamv1 speaks or brokers and every cryptographic mechanism it relies on, with where each is implemented and where verification is opt-in.
- **[BACKUP-AND-RESTORE.md](BACKUP-AND-RESTORE.md)** — runbook for backing up the database and the vault KEK *separately*.
- **[EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md)** — what needs a real host/account to verify honestly before you rely on it.
- **[RDP-TESTING.md](RDP-TESTING.md)** — the procedure to verify the RDP path end to end: automated tests, a local runbook, and troubleshooting.

### Security, compliance & OT
- **[PROTOCOLS-AND-CRYPTO.md](PROTOCOLS-AND-CRYPTO.md)** — every protocol pamv1 speaks or brokers and every cryptographic mechanism it relies on: the vault envelope and its KEK providers, the audit chains, key custody, per-protocol TLS posture, and a single table of where verification is opt-in.
- **[SECURITY-GAPS.md](SECURITY-GAPS.md)** — a security self-audit: every gap found, and whether it was fixed, mitigated or deferred.
- **[AGENT-THREAT-MODEL.md](AGENT-THREAT-MODEL.md)** — the AI-agent access broker's threat model: OWASP LLM Top 10 & MITRE ATLAS mapped to broker controls.
- **[NIS2-COMPLIANCE.md](NIS2-COMPLIANCE.md)** — maps pamv1 features to Directive (EU) 2022/2555 (NIS2) Art. 21/23.
- **[OT-DEPLOYMENT.md](OT-DEPLOYMENT.md)** — the IEC 62443 / Purdue-model deployment pattern and OT-specific controls.

### Landscape
- **[RELATED-PROJECTS.md](RELATED-PROJECTS.md)** — where pamv1 sits among open-source projects and commercial PAM vendors.

## House style (for doc authors)

Keep the set reading as one product:

1. **H1** is `# pamv1 — <Title>` (project name first, em-dash separator, one per file).
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
| 2026-08-09 | Phase 95 — documentation currency pass across the whole set: every `Reflects:` header brought to 0–94 / v0.18.1 (they ranged from 0–70 to 0–93; this entry point still said v0.13.0), the READMEs' phase story extended past 61 (both languages), PORTS-AND-FLOWS gained the omitted ITSM egress (E14), EXTERNAL-INFRA-GAPS' ITSM row caught up with the Phase 84 connectors, and the CODE-GUIDE package map gained its ten missing packages |
| 2026-07-28 | Maturity banner corrected to **Beta** (it still said Alpha while the README said Beta — the entry point contradicting the doc that links to it). Added this file's own status header and change log, which house rules 2 and 5 require of every other doc. Rules 3, 4 and 9 rewritten to describe what the doc set actually does rather than a state it never reached. Linked the three deploy READMEs, which nothing in the repo referenced. Noted CODE-GUIDE §0.1 for readers who do not write Go |
