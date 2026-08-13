# pamv1 — External Infrastructure & Accounts Checklist

> 🟢 **Living document** — updated in the same change as the code, without a separate ask (see the [docs hub](README.md)).

> **Purpose.** pamv1 follows a hard rule: *every phase is fully functional and
> tested end-to-end without faking the security-critical path.* Where a feature
> can only be **verified honestly against a real external system or a paid
> account**, we build the code, test it against an in-process fake or mock, and
> record the real-world dependency here rather than pretend it was validated
> live. This is the operator's checklist of what you must stand up (and what to
> re-verify) before relying on each capability in production.
>
> Last updated: 2026-08-13 · Reflects: Phases 0–120 (58–94 needed no external infrastructure, so nothing here was added or closed by them; Phase 84 moved the ITSM gate's *depth* in-process with first-class ServiceNow/Jira connectors, leaving only live-instance interop verification external — see the ITSM row; **Phase 116** reuses the *existing* email-alerts requirement for its external session-share invites — see that row — so it adds nothing new here either; **Phase 118** needs nothing external either — CIDR matching is pure `net.ParseCIDR` against an already-resolved local address; **Phase 120** needs nothing external either — the recurring-request scheduler and password-history checks are pure PostgreSQL reads/writes on the connection already open).
> (Phases 25–28, 30 and 31 — console parity, recording playback + one-time
> access, broker completion, operator SSH certificates, in-session step-up and the
> CIEM blast-radius engine — are fully in-process and add no
> external-infrastructure requirements; the operator-cert KRL is even verified
> against a real `ssh-keygen` in CI. **Phase 29 is the exception**: the vendor
> access gate calls an external employment-attestation webhook, catalogued
> below. **Phase 57 removed an entry from this catalogue** rather than adding
> one: RFC 8693 token-exchange minting was listed as needing an external STS,
> and did not — see §6.)

## Legend

- **CI proof** — how the code is exercised in the automated test suite today.
  - `fake/mock` — an in-process fake or mock stands in for the external system
    (the protocol/logic is tested; the third party is not contacted).
  - `SoftHSM2` / `mock server` — a real software implementation is run in CI.
  - `— none` — no automated test; the code path needs live infra even to smoke-test.
- **You must provide** — the external infrastructure or account to run it for real.
- **Verify** — what to check once the real system is wired up.

---

## 1. Identity providers & directories (accounts)

| Capability | Env / code | CI proof | You must provide | Verify |
|---|---|---|---|---|
| **Active Directory / LDAP login** | `PAM_LDAP_*`, `internal/auth/ldap.go` | fake `ldapConn` | An AD/LDAPS directory + a service (bind) account | User bind verifies the password; `memberOf` groups map to roles; LDAPS cert validates |
| **Microsoft Entra ID (Azure AD)** | `PAM_ENTRA_*`, `internal/auth/entra.go` | mock token endpoint + RS256 JWKS | An Entra tenant + app registration (client id/secret) | ROPC returns an id_token; its signature validates against the tenant JWKS; app roles/groups map |
| **OIDC Authorization Code + PKCE** | `PAM_OIDC_*`, `internal/oidc` | RSA-signed token, mock IdP | An OIDC IdP (Okta/Keycloak/Entra/Google) | Auth-code round-trip; ID-token signature/iss/aud/nonce/exp verified; IdP-side MFA/Conditional Access applies |
| **Kerberos bind (LDAP)** — *deferred* | Phase 3b | — none | A **KDC** (AD domain) | GSSAPI bind against the KDC. Not implemented — needs a KDC to build and test honestly |
| **Directory-driven identity reconciliation** | `POST /api/identity/reconcile` | fake directory | A live directory (LDAP) reporting disabled users | Disabled directory users are revoked; local-only accounts are surfaced, not revoked |

MFA (TOTP, RFC 6238) and recovery codes are **self-contained** — no external
dependency — and fully unit-tested.

---

## 2. Secret & key management backends (accounts / appliances)

The vault KEK is pluggable; the **local** KEK (dev/test) needs nothing. The
production backends externalize the root of trust and need the real service to
verify end-to-end:

| Capability | Env / code | CI proof | You must provide | Verify |
|---|---|---|---|---|
| **HashiCorp Vault Transit KEK** | `PAM_KEK_TRANSIT_*`, `vault/transit.go` | mock Transit server | A Vault server with a Transit key | Wrap/unwrap round-trips; the KEK never leaves Vault |
| **AWS KMS KEK** | `PAM_KEK_AWS_*`, `vault/awskms.go` | mock `kmsAPI` | An AWS account + a KMS CMK + IAM | Data key wrap/unwrap via KMS with the `app=pamv1` encryption context |
| **PKCS#11 HSM KEK** | `PAM_KEK_PKCS11_*`, `vault/pkcs11.go` (`pkcs11` build tag) | **SoftHSM2 in CI** | A real HSM/token (or SoftHSM2) | AES wrap/unwrap inside the token; the key never leaves the HSM |
| **CyberArk Conjur secret sourcing** | `PAM_CONJUR_*`, `internal/conjur` | in-process fake Conjur | A Conjur appliance (+ authn-api-key host or Kubernetes authn-jwt) | Bootstrap `PAM_*` secrets are sourced at startup; fail-loud if unreachable |
| **SOPS + age sealed secrets** | `deploy/k8s/sops/`, `deploy/.sops.yaml` | round-trip with a committed demo key | Real age/PGP/cloud-KMS recipients for operators | `sops -d \| kubectl apply` decrypts only for held keys; cloud-KMS recipients wired into the chart is a follow-on |

---

## 3. Target connectors (real machines / services)

The SSH proxy's JIT path is proven against an in-process sshd. Everything that
touches a **real Windows host, database, bastion, or device** needs that system
to exercise fully:

| Capability | Env / code | CI proof | You must provide | Verify |
|---|---|---|---|---|
| **WinRM command execution (JIT)** | `POST /api/targets/{id}/winrm`, `internal/winrm` | fake `Runner` | A Windows host with WinRM (basic or NTLM) | Command runs with the vaulted credential; caller never sees the secret |
| **NTLM / Kerberos WinRM auth** | `PAM_WINRM_AUTH` | client-construction test | An AD-joined Windows host (+ a KDC for Kerberos) | NTLMv2 auth to a domain host. **Kerberos WinRM is deferred** — needs a KDC + AD-joined host |
| **RDP via Apache Guacamole** | `PAM_GUACD_ADDR`, `internal/guacd` | mock guacd handshake | An RDP host (a `guacd` daemon now **ships** with the Docker/K8s/Helm deploys; bring your own or use the bundled one) | JIT credential reaches guacd, never the browser; server-side recording |
| **Browser RDP viewer** — *shipped* | portal option 7, `web` (vendored guacamole-common-js), `POST /api/rdp-token` | full WebSocket round-trip vs a fake guacd (`TestRDPTunnelEndToEnd`) | Just a **Docker host** — a bundled demo (`deploy/docker/docker-compose.rdp-demo.yml`) ships a real xrdp desktop as the target, so even the pixels need no external host | In-portal canvas display. The renderer is vendored and the whole path is tested; the demo compose renders a live XFCE desktop end to end. See [RDP-TESTING.md §4a](RDP-TESTING.md) |
| **SSH jump host / bastion** | `PAM_SSH_JUMP_*` | in-process (via proxy tests) | A real bastion for production topology | `direct-tcpip` tunnel to targets only reachable via the bastion |
| **Credential rotation (SSH/WinRM)** | `internal/rotate` | in-process sshd; fake WinRM | Real Linux/Windows hosts | Password/`ssh_key` actually changes on the target; the old secret stops working |
| **Account & identity reconciliation** | `/api/reconcile`, `/reconcile` | in-process | Real hosts to detect out-of-band drift | Drift is detected and (opt-in) remediated |
| **Discovery scan** | `POST /api/discovery/scan` | injected dialer | A network with reachable SSH/WinRM/RDP hosts | Reachable management ports are found and (opt-in) onboarded |
| **Dependent-account propagation** | `/api/credentials/{id}/dependencies` | fake WinRM | A Windows host running Services / Scheduled Tasks / IIS App Pools | The consumer's stored password is updated on rotation so the service keeps running |
| **PostgreSQL session proxy** | `PAM_DB_ADDR`, `dbproxy.go` | in-process fake upstream | (optional) a real Postgres for interop breadth | JIT injection + per-statement `db.query` audit against a managed/SCRAM Postgres; the SCRAM server signature is verified |
| **Upstream DB TLS verification** | `PAM_DB_UPSTREAM_CA` / `_TLS_VERIFY` | in-process fake upstream | A Postgres with a CA-issued (or pinned) server cert | With a CA set, the proxy verifies the target's certificate fail-closed (no MITM of the injected credential); unset = trust-any + startup warning |
| **Zero Standing Privilege (SSH certs)** | `PAM_SSH_CA_KEY`, `internal/sshca` (Phases 22, 28) | in-process cert-only sshd; **KRL verified vs real `ssh-keygen`** | A target sshd trusting the pamv1 CA (`TrustedUserCAKeys`); for operator certs, its `RevokedKeys` pointed at the published KRL | A minted short-lived cert authenticates; no standing secret exists; a revoked serial is refused once the target reloads the KRL |
| **Serial (RS-232) connectors** — *deferred* | Phase 8 | — none | Serial hardware / a terminal server | Legacy OT equipment reached over serial. Not implemented — needs the hardware |

---

## 4. Cloud & Kubernetes deployment (accounts / clusters)

| Capability | Code | You must provide | Verify |
|---|---|---|---|
| **Helm deploy** | `deploy/helm/pamv1` | A Kubernetes cluster | Pod runs with the hardened security context; ServiceMonitor scrapes `/metrics` |
| **Postgres HA (CloudNativePG)** | `deploy/k8s/postgres-cnpg.yaml` | K8s + the CNPG operator | 3-instance cluster, automatic failover, scram-sha-256, optional PITR |
| **Cloud-managed Postgres (Terraform)** | `deploy/terraform/cloud-postgres` | An AWS account (RDS) | Multi-AZ, encrypted, `force_ssl` instance provisioned |
| **Signed releases (cosign + SLSA)** | `.github/workflows/release.yml` | GitHub Actions OIDC + registry | Keyless image signature, SBOM attestation, build provenance on a version tag |
| **Conjur authn-jwt (K8s-native)** | `deploy/k8s/conjur/` | A Conjur appliance reachable from the cluster | Pod presents its projected SA token; no bootstrap secret in Git |

---

## 5. Alerting & SIEM (endpoints)

| Channel | Env | You must provide | Verify |
|---|---|---|---|
| **Webhook alerts** | `PAM_ALERT_WEBHOOK` | An HTTP endpoint (Slack/PagerDuty/etc.) | Break-glass and analytics events POST as JSON |
| **Syslog alerts** | `PAM_ALERT_SYSLOG` | A syslog collector (udp/tcp) | Events arrive at the collector |
| **Email alerts** | `PAM_ALERT_EMAIL_*` | An SMTP server + credentials | Alert email is delivered to the recipient list — since Phase 116 the same config also delivers external session-share invite emails (`alert.SendDirect`); same requirement, same CI-proof shape (an in-process fake SMTP server), nothing new to verify |
| **Audit → SIEM push forwarding** | `PAM_AUDIT_FORWARD_ADDR`/`_PROTO`/`_FORMAT`/`_CA`, `internal/auditfwd` (Phases 35, 47); in-process fake collector in CI | A syslog/SIEM collector on udp, tcp or **TLS** (`:514`/`:6514`) speaking RFC 5424, ArcSight **CEF** or QRadar **LEEF 2.0** | Events arrive in order from a durable cursor, resume after a restart with no gap or replay, one forwarder per cluster under the Postgres leader lock; with `proto=tls`, `PAM_AUDIT_FORWARD_CA` verifies fail-closed |
| **Audit / log collection** | JSON logs on stdout (Phase 9); OCSF at `GET /api/audit/ocsf` (Phase 27) | A log collector / SIEM | The append-only audit trail and JSON logs are ingested for detection |
| **Vendor employment attestation** | `PAM_VENDOR_ATTEST_URL`, `internal/vendor` (Phase 29); CI proves it against an `httptest` fake | A vendor-management or HR system that answers 2xx for a currently-employed technician | An offboarded technician's contract grant is refused at approval, audited `vendor.attestation_failed` |
| **ITSM ticket gate** | `PAM_TICKET_VALIDATE_URL` + `PAM_TICKET_PATTERN` (Phase 20 webhook); **first-class ServiceNow/Jira connectors** via `PAM_TICKET_PROVIDER`/`_URL`/`_USER`/`_TOKEN` (Phase 84: ticket state, change window, ticket names the operator); use-time re-check with `PAM_TICKET_REVALIDATE` (Phase 60) — all in `internal/ticket`, proven in CI against in-process fakes speaking the documented REST shapes | A **real** ServiceNow or Jira instance — like SQL Server, the connector ships tested against the documented protocol but its interop with a live instance is unverified | An access request without a valid change ticket — or one whose ticket is in the wrong state, outside its window or not naming the requester — is refused, audited `access.ticket_rejected` |
| **WORM archive storage** | `PAM_RETENTION_ARCHIVE_DIR`, `internal/api/archive.go` (Phase 49) | Genuinely write-once storage mounted at that path (S3 Object Lock, a WORM NAS) — the code writes digest-stamped exports and moves recordings, it cannot itself enforce immutability | The `audit.archived` SHA-256 matches a re-hash of the file, and a failed archive leaves the rows unpruned |

`PAM_OT_AIRGAP` disables the alert channels **and refuses to start** alongside
any integration in this catalogue that would reach the network — the ITSM ticket
webhook, the vendor-attestation webhook, the SIEM forwarder, Conjur sourcing, an
OIDC issuer, the alert webhook. Each may be re-permitted individually by naming
it in `PAM_OT_AIRGAP_ALLOW`, which certifies that it resolves inside the enclave;
`PAM_KEK_PROVIDER=aws-kms` and `PAM_ENTRA_TENANT_ID` have no such hatch, because
there is no in-enclave version of somebody else's cloud.

---

## 6. Zero-trust agent identity (SPIFFE / SPIRE)

| Capability | Env / code | CI proof | You must provide | Verify |
|---|---|---|---|---|
| **SPIFFE JWT-SVID verification** | `PAM_BROKER_TRUST_DOMAIN_JWKS`, `internal/agentid/svid.go` | file JWKS + signed SVIDs | A trust-domain JWKS (from SPIRE or another issuer) | SVIDs validate (subject/audience/exp); RFC 8693 `act` delegation depth is capped |
| **Live SPIRE workload attestation** — *deferred* | Phase 13 | — none | A SPIRE deployment | Workloads receive SVIDs via the SPIRE agent, attested by the node/workload |
| **RFC 8693 token-exchange minting** — **shipped** (Phase 57) | `PAM_BROKER_TOKEN_EXCHANGE`, `internal/agentid/exchange.go`, `POST /v1/token` | in-process: a minted token is verified at the ingress that minted it, re-delegated, depth-capped, `may_act`-pinned and expiry-capped | **Nothing external.** This entry previously read "needs an STS / token-exchange endpoint" — that was wrong, and a research-parity audit caught it: the broker already holds an accountable identity for the delegator and already decides every call, so it is the only party that can honestly issue "X may act for Y here". No third-party STS is involved | A delegated token authenticates a real tool call; its `act` chain names the delegator and the original accountable party; `GET /v1/token/jwks` publishes the signing key |

---

## 7. Tier-3 market-frontier gaps not yet built (need infra to build honestly)

Three Tier-3 gaps **shipped** and are tested in-process — **Zero Standing
Privilege** (Phase 22, §3), **privileged threat analytics** (Phase 23), and the
**identity blast-radius / CIEM engine** (Phase 31; `internal/blast` — a real AWS
IAM effective-permission evaluator + escalation-path analysis over a normalized
graph). The remaining pieces cannot be *built and verified honestly* without
external systems, so they are scoped here rather than stubbed:

| Gap | What it needs to build honestly | Fit in pamv1 |
|---|---|---|
| **SQL Server interop verification** (Phase 53) — the TDS proxy is proven end to end against a hand-rolled fake upstream and its codec is pinned to spec-derived byte literals, but it has never spoken to a real Microsoft SQL Server | A licensed SQL Server instance (a `mcr.microsoft.com/mssql/server` container in CI would close it) | A `PAM_TEST_MSSQL_URL`-gated interop test brokering a real batch, on the live-Postgres job pattern |
| **Connector / plugin breadth** — network devices (Cisco/Juniper/F5/Palo Alto), MySQL/Oracle, VMware/SAP/mainframe | The real devices/databases (network gear speaks SSH and already rides the existing proxy; new DB wire protocols each need a real server to prove interop) | New `Rotator`/`Verifier` connectors and new DB wire-protocol proxies on the Phase 15 pattern |
| **Cloud CIEM — live ingestion + credential brokering** (the analytical **engine shipped** in Phase 31) | A cloud account + API clients (boto3 `GetAccountAuthorizationDetails`, Okta, GitHub, Workspace) to **ingest** the identity graph the engine consumes, and AWS STS `AssumeRole` (or Azure/GCP) to **mint** short-lived cloud creds | An ingester that produces `blast.Graph`, and a broker tool that mints short-lived cloud creds JIT (mirrors ZSP for cloud IAM) |
| **Third-party credential backends for the broker** — dynamic database credentials (Vault's database secrets engine), **GitHub App** installation tokens, **AWS STS** session credentials | Each needs the real service and an account to verify honestly: a Vault server with a configured database role, a GitHub App installation, an AWS account + role. The [pam-research](https://github.com/morandeirachema/pam-research) prototype implements all three behind one seam, which is the shape to follow | New backends behind the broker's existing credential seam, each minting a short-lived credential server-side that the agent never sees — the invariant `reveal_credential` and the ZSP certificate path already hold |
| **Vault SSH secrets engine as the certificate authority** | A Vault server with the SSH engine enabled and its CA key generated *inside* Vault, so the pamv1 process never holds the CA private key at all (today it holds it under shared custody, KEK-sealed — strong, but the key does exist in the process). Mockable in CI the way the Transit KEK already is | A `PAM_SSH_CA_PROVIDER=vault-ssh` alternative in `internal/sshca` that signs certificates over the Vault API instead of locally |
| **Web / SaaS session proxying** — record + inject into web admin consoles | A headless browser + a real SaaS console to drive and record | The heaviest lift; a reverse-proxy/browser-isolation layer alongside SSH/RDP. The [pam-research](https://github.com/morandeirachema/pam-research) `saas-session-broker` prototype covers the *policy* half — per-action re-evaluation over arguments and in-session step-up — both of which pamv1 already has (Phases 16, 30, 38); what stays out of reach is driving and recording a real browser session |

---

## 8. Tier-4 ecosystem (external systems / registries)

The **application-secrets API** (Conjur-style secret delivery for non-agent apps)
**shipped in Phase 24** — it is fully in-process and tested (`PAM_APP_SECRETS_ENABLED`,
`GET /v1/app-secrets/{credential_id}`). The rest of Tier 4 needs an external system,
account, or a separate module/registry:

| Item | Needs |
|---|---|
| **Terraform provider** for pamv1 objects | A separate Go module (terraform-plugin-framework) + the Terraform Registry; acceptance tests need a running pamv1 to target |
| **Secrets-Hub-style sync-out** | AWS Secrets Manager / Azure Key Vault accounts to push managed secrets to (and a deliberate decision to export secrets outward) |
| **SSH-key fleet discovery** at scale | A fleet of hosts with existing authorized_keys to inventory (the read mechanism is unit-testable in-process, like the rotation connectors) |
| **Thick-app connection components** (SSMS / Toad / vSphere via RDP RemoteApp) | Windows RemoteApp hosts + the thick clients |

---

## 9. Parity with the research prototypes (`pam-research`)

pamv1's sibling repository, **[pam-research](https://github.com/morandeirachema/pam-research)**,
is the market investigation that preceded this codebase plus five runnable
proof-of-concept prototypes (Python/FastAPI) for its five candidate products.
pamv1 is the production-shaped answer to the same questions in Go, and the two
repos are audited against each other so a mechanism proven there does not
quietly go missing here. This is that audit, re-run on **2026-07-31**.

**Applied** — every control-plane mechanism the five prototypes demonstrate now
exists in pamv1, in most cases more completely:

| Research prototype | The mechanism it proves | Where it lives in pamv1 |
|---|---|---|
| **01 · agent-access-broker** | policy decided over a tool call's **arguments**, human-in-the-loop approval, server-side execution the agent never sees, MCP transport (+ SSE, elicitation), SPIFFE agent identity, keyed-HMAC hash-chained audit with ed25519 checkpoints, OCSF export | `internal/policy`, `internal/broker`, `internal/mcp` + `api/mcp_sse.go`, `internal/agentid`, `internal/auditchain`, `internal/ocsf` (Phases 13, 27) |
| | RFC 8693 **token-exchange minting** | `internal/agentid/exchange.go`, `POST /v1/token` (**Phase 57** — the gap this audit found) |
| **02 · jit-smb-access** | zero standing privilege: a CA signs a short-lived OpenSSH certificate after approval; hosts trust only the CA | `internal/sshca` (Phases 22, 28) — plus proof-of-possession operator certs and a real KRL, which the prototype does not have |
| **03 · saas-session-broker** | policy re-evaluated on **every action**, **in-session step-up** that pauses without ending the session, per-session recording as its own tamper-evident hash chain | `internal/cmdguard` + `session.StepUp` (Phases 16, 30, 38, 56), `internal/recording` (Phases 2, 41) |
| **04 · identity-blast-radius** | real AWS IAM effective-permission evaluation (an edge only where the permission actually holds), escalation-path traversal, toxic-combination findings, **remediation as Terraform** | `internal/blast` (Phase 31); the Terraform rendering is **Phase 57** |
| **05 · vendor-access-gate** | customer-approved, time-boxed contract grants; credential injected per action; **instant offboard** that revokes everything and survives a restart | `internal/vendor` (Phase 29) — plus a window-close session sweeper and evidence export |
| *engineering spine* | fail-closed startup preflight, structured JSON logs with correlation ids, security headers, graceful shutdown, SBOM + signed releases, dependency vulnerability gating | `cmd/pam-server`, `internal/logging`, `.github/workflows/{ci,release}.yml` |

**Not applied, with the reason** — each is catalogued above rather than
half-built: the three third-party **credential backends** (Vault dynamic-DB,
GitHub App, AWS STS) and the **Vault SSH engine CA** need the real service to
verify honestly (§7); **live IAM ingestion** needs cloud accounts (§7);
**browser/SaaS session proxying** needs a headless browser and a real SaaS
console (§7). The prototypes' **Ansible multi-PoC stack** and **aggregate
console** have no pamv1 equivalent by design — pamv1 is one binary with one
5250 console, so there is nothing to aggregate.

**Deliberately not carried over**: the prototypes' documented shortcuts — HMAC
where production wants real STS/OAuth, fixture data instead of live cloud
clients, single-writer stores, no HA. pamv1 took the opposite trade on each
(real Postgres, shared custody, cross-replica buses), which is the point of
having two repos.

## Deliberate non-goal

**Endpoint Privilege Management** (removing local admin / elevating sudo via an
endpoint agent) is a different product category that does not fit a vault + proxy
chokepoint, and is **out of scope** by design — it is not an infra gap, it is not
planned.
