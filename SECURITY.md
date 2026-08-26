# Security Policy

## What this project is, and what that means for you

PAMv1 is an **educational** Privileged Access Management system. It is
feature-complete against its [roadmap](ROADMAP.md) and has closed every finding
of its own [security self-audit](docs/SECURITY-GAPS.md) and of its two dated
audit passes ([2026-08-26](docs/SECURITY-AUDIT-2026-08-26.md),
[2026-08-27](docs/SECURITY-AUDIT-2026-08-27.md)), but it **has not been
audited by anyone outside the project** and is **not production-ready**.

Please do not use it to guard real privileged credentials. If you have, treat
that as the finding and rotate them.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting on this repository — the
**Security** tab → **Report a vulnerability**. That opens a channel visible only
to the maintainer, and it is the preferred route because it keeps the report,
the discussion and the eventual advisory in one place.

Please include, as far as you can:

- what the flaw is, and which component it lives in (a file path or package name
  is ideal);
- how to reproduce it — a failing test, a `curl`, or a sequence of console
  actions is worth more than a description;
- what an attacker gains, and what they need to start with (an operator token? a
  database backup? network access to `:2222`?);
- the version or commit you were looking at.

You will get an acknowledgement. Because this is a single-maintainer educational
project, please expect **best-effort** timelines rather than a commercial SLA —
if that does not suit your disclosure needs, say so in the report and we will
agree something workable rather than leave you guessing.

## What is in scope

Anything that breaks one of the invariants this project is built around:

- **The operator never receives the vaulted credential.** The secret is decrypted
  just-in-time inside PAMv1 and injected into the upstream connection.
- **Every use of a secret is audited**, and the security-critical paths fail
  closed when the audit trail is unavailable.
- **Authorization is enforced at the chokepoint**, not delegated to the client.
- **Secrets at rest are useless without the KEK**, and `SecretEnc` never
  serialises to any client.
- **The audit trail is tamper-evident** when the HMAC chain is enabled.

Also in scope: privilege escalation between roles, authentication bypass on any
of the bearer surfaces, injection into a brokered session, and anything that lets
an AI-agent broker call escape the policy or approval gates described in
[the agent threat model](docs/AGENT-THREAT-MODEL.md).

## What is out of scope

- **The absence of an external audit.** This is stated plainly above and in the
  README; it is a known limitation, not a vulnerability.
- **Deliberate, documented deferrals.** Items in
  [EXTERNAL-INFRA-GAPS.md](docs/EXTERNAL-INFRA-GAPS.md) need infrastructure or a
  paid account to build honestly and are recorded rather than faked.
- **Demo material.** `deploy/docker/docker-compose.rdp-demo.yml`, its throwaway
  xrdp target and the committed SOPS example key are all deliberately weak and
  labelled as such. The SOPS demo key is public on purpose.
- **Configuration choices the documentation warns against**, such as running
  without `PAM_SSH_KNOWN_HOSTS` — where PAMv1 logs a warning at startup. If you
  think a warning should be a refusal, that is a good issue, but file it as one.

## How this project already looks for its own problems

Reports are welcome regardless, but you may find it useful to know what has
already been swept:

- [docs/SECURITY-GAPS.md](docs/SECURITY-GAPS.md) — a living self-audit: every gap
  found, whether it was fixed, mitigated or deferred, and the reasoning. It
  includes a post-beta sweep of 30 findings and the six more that reviewing those
  fixes uncovered.
- CI gates every change on `gofmt`, `go vet`, `staticcheck`, `govulncheck`,
  `gosec`, `go test -race`, a live-PostgreSQL store contract, a PKCS#11 build
  against SoftHSM2, and a check that the committed SOPS example really is
  encrypted.
- [docs/AGENT-THREAT-MODEL.md](docs/AGENT-THREAT-MODEL.md) maps the AI-agent
  broker against the OWASP LLM Top 10, and records which test proves each control.

## Supported versions

There are no published releases yet, so **`main` is the only supported ref**.
Fixes land there. Once releases begin, this section will name the versions that
receive them.
