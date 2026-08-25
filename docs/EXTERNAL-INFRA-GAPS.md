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
> Last updated: 2026-08-25 · Reflects: Phases 0–201 (**161–183, the rest of the AI-agent-broker batch, need nothing external either** — every one of them decides, records or bounds something inside the process pamv1 already runs: outcome-bearing audit actions and risk signals (161), argument-presence semantics (163), an output cap and a local transcript (165), a budget counted from pamv1's own audit trail (167), a quarantine check that walks a chain already inside a verified token (169), an owner registry that is a table in pamv1's own database (170 — see §6's row on why recording an owner is **not** attestation), a TTL narrowed against the deployment's own setting (171), policy conditions read from an identity pamv1 already verified (173), an inventory row per attested identity (174), a campaign item per non-human identity (175), a `may_act` claim written into a token pamv1 already signs (181), and a delegation chain shown to an approver (183). **Phase 180 is the one that dials out at all** — and it dials the posture webhook this deployment may already run for its human operators, asking about a second kind of subject rather than needing a second system; the row in §5 covers it, and §6's SPIRE row is still what would be needed to attest the workload rather than its name. Nothing else here is left unverified against a real third party. Earlier: 58–94 needed no external infrastructure, so nothing here was added or closed by them; Phase 84 moved the ITSM gate's *depth* in-process with first-class ServiceNow/Jira connectors, leaving only live-instance interop verification external — see the ITSM row; **Phase 116** reuses the *existing* email-alerts requirement for its external session-share invites — see that row — so it adds nothing new here either; **Phase 118** needs nothing external either — CIDR matching is pure `net.ParseCIDR` against an already-resolved local address; **Phase 120** needs nothing external either — the recurring-request scheduler and password-history checks are pure PostgreSQL reads/writes on the connection already open; **Phase 122** needs nothing external either — suspend/resume is an in-memory flag and broadcast channel on a registry the process already holds; **Phase 124** needs nothing external either — the WebAuthn relying-party verification is pure in-process cryptography against the browser's own response, no IdP, no FIDO Metadata Service call; **Phase 126** needs nothing external either — a color-theme toggle never leaves the browser; **Phase 128** needs nothing external either — the ssh/winrm connection it dials is the exact same kind of connection pamv1 already makes to that target for a real session, no new infrastructure; **Phase 129** needs nothing external either for the PostgreSQL half it ships — the provisioning/teardown dials ride the same kind of connection the real session makes. Its two cut/deferred halves are NOT infrastructure gaps, so they are deliberately not catalogued here: RDP ZSP is a confirmed, permanent Guacamole/FreeRDP protocol limitation (more infrastructure would not resolve it), and SQL Server ZSP is deferred pending a new `internal/tds` client-response reader — genuine unbuilt code, not an unverified external dependency; both are tracked in ROADMAP.md instead; **Phase 131** needs nothing external either — command allow-listing is a regex match against a local file, no new dependency of any kind. **Phase 133** is split: the live device-posture webhook is a genuine new external-infra gap, catalogued in §5's table below, the same shape as vendor attestation and the ITSM gate; its device-identity half is deliberately NOT catalogued here, for the same reason RDP/SQL-Server ZSP weren't in Phase 129 — it's an honest v1 scope decision (REST surface only, no client-side mTLS story to build), not something more infrastructure would resolve). **Phase 135** needs nothing external either — DoubleLock's second encryption is raw AES-256-GCM keyed by PBKDF2(password), entirely in-process, no webhook, no external system to verify against. **Phase 137** reuses the *existing* email-alerts requirement too, for the same reason 116 does — see that row — so magic-link approval adds nothing new here either; session watermarking needs nothing external at all. **Phase 139** needs nothing external either — the personal-safe check is a plain boolean read and a capability comparison, entirely in-process, no webhook, no external system to verify against. **Phase 141** needs nothing external either — a forwarded connection dials out through the already-authenticated `upstream` SSH client the real session uses, the same kind of connection pamv1 already makes to that target, no new dependency. **Phase 143** is a genuine new external-infra gap, catalogued in §5's table above, the same shape as vendor/posture attestation and the ITSM gate: a real ICAP AV/DLP appliance to verify interop against, unavailable in this environment. **Phase 145** needs nothing external either — a file-attachment secret's content flows entirely in-process through the existing `vault.Encrypt`/`Decrypt` pathway, no webhook, no external system to verify against. **Phase 147** is a genuine new external-infra gap, but a different shape than 133/143's webhooks — catalogued in §7's table below, alongside the SQL Server interop row, since both are "built and proven against a fake, never exercised against the real thing": a real Chromium/Firefox browser to load the unpacked extension into and drive a login form end to end, unavailable in this environment. **Phase 149** is also a genuine new external-infra gap, catalogued in §1's table above alongside directory-driven reconciliation: a real SCIM-speaking IdP (Okta/Azure AD/OneLogin) to verify interop against — the mechanism itself is built and proven against a hand-rolled fake covering both documented `PATCH` wire shapes, unavailable in this environment.
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
| **SCIM 2.0 provisioning interop** (Phase 149) | `PAM_SCIM_ENABLED`, `internal/api/scim_handlers.go`, `/scim/v2/Users` | hand-rolled fake IdP requests, including both RFC 7644's path-based `PATCH` shape and Azure AD's documented no-path variant | A real SCIM-speaking IdP (Okta, Azure AD, OneLogin) | Push-provisioned/deactivated users behave correctly against a live IdP's actual request shapes, not just the documented ones — same caveat as the ITSM/SQL Server rows |
| **SAML 2.0 SSO interop with a live IdP** (Phase 151) | `PAM_SAML_*`, `internal/saml`, `/api/auth/saml/{start,acs,metadata}` | a **real in-process SAML IdP** (`crewjam/saml`'s `IdentityProvider`, `internal/saml/samltest`) that signs — and, when the SP publishes a certificate, encrypts — genuine Responses; tampered/stripped/wrong-audience/wrong-issuer/expired/signature-wrapped variants refused | A live **AD FS** farm, or an Okta/OneLogin/Entra SAML application, to register pamv1's SP metadata with | The IdP accepts the SP metadata import, sends its group/role claim under the attribute name pamv1 expects (`PAM_SAML_GROUP_ATTR`), and its Response validates end to end — in particular ADFS's default RSA-SHA256 signing and, if enabled, its assertion encryption to the SP certificate. The mechanism is proven; vendor-specific claim-rule quirks are what a live tenant would surface |
| **Outbound-only endpoint agent across a real NAT / CGNAT path** (Phase 153) | `PAM_ENDPOINT_AGENTS_ENABLED`, `cmd/pam-agent`, `internal/endpointagent`, `internal/proxy/endpointagent.go` | the REAL agent library dialing the REAL proxy in-process, tunneling to a real upstream sshd that accepts only the vaulted password; revoke/kick/refused-reconnect; every refusal path | An endpoint behind an actual NAT/CGNAT or deny-all-inbound firewall, plus a pam-server reachable on :2222 from it | The tunnel comes up from behind the NAT with no inbound rule, survives the NAT's idle timeout (the 30 s keepalive is sized for common CGNAT/UDP-style timeouts but was not measured against a real one), and reconnects after a mapping change. The mechanism is proven; what a real path would surface is timing/keepalive tuning and any middlebox that mangles long-lived SSH connections |
| **Kubernetes brokering against a real cluster** (Phase 155) | `internal/k8s`, `POST /api/targets/{id}/kubectl`, `PAM_K8S_*` | a fake TLS API server that accepts ONLY the vaulted service-account token: every verb's method/path/query, server-side apply carrying the manifest verbatim, a cluster 403 surfaced as a result, path-injection refusals, and the end-to-end JIT-injection proof through the REST handler | A real cluster (a free `kind`/k3s is enough) plus a service account and RBAC bindings | The paths and the apply patch are accepted by a real API server exactly as the fake models them (in particular server-side apply with `fieldManager=pamv1&force=true`), a real cluster's RBAC refusal shape matches, and a private cluster CA verifies through `PAM_K8S_CA_FILE`. The mechanism is proven; what a live cluster would surface is version-specific API shapes and the ergonomics of naming `api_version` explicitly |
| **Post-session forensic reconstruction against a real auditd target** (Phase 157) | `PAM_SESSION_FORENSICS`, `internal/sessionforensics`, `api.CollectSessionForensics` | a fake target answering the fixed `ausearch` command with fixture records covering all three auditd argv encodings, plus the proxy hook and artifact/audit plumbing end to end | A Linux target running `auditd` with exec auditing (`-S execve`) and a credential permitted to read its log | Real `ausearch` output parses as the fixtures model it across auditd versions and locales, and the credential can actually read the log on your baseline. The mechanism is proven; what a live fleet surfaces is auditd rule coverage and log-permission policy |

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
| **Live device-posture attestation** | `PAM_POSTURE_ATTEST_URL`, `internal/posture` (Phase 133; extended to AGENT identities by Phase 180 behind `PAM_BROKER_POSTURE_REQUIRED`, which asks the same webhook about a workload's name and says plainly that this is weaker than attesting the process — see §6's SPIRE row); CI proves the gate mechanism against an `httptest` fake, plus a real in-process sshd end-to-end (`TestPostureGateProxy`) | A **real** EDR/posture system (CrowdStrike, Defender, SentinelOne, or anything answering the same webhook shape) — the gate ships proven against the documented contract, but interop with a live vendor account is unverified, same caveat as the ITSM row below | An unhealthy device is refused on every connect and every authenticated call, audited `authz.denied`/`session.denied`/`db.session.denied` with `reason:posture-check-failed` |
| **ICAP file-transfer scanning** | `PAM_ICAP_URL`, `internal/icap` (Phase 143); CI proves the wire protocol against a fake RESPMOD responder, and the proxy integration end-to-end (real SFTP uploads through the proxy, including an unreachable-scanner case) | A **real** ICAP AV/DLP gateway (c-icap, Symantec, McAfee, Forcepoint/Websense, or anything speaking RFC 3507 RESPMOD) — the client ships proven against the documented wire protocol, but interop with a live commercial gateway is unverified, same caveat as the posture/ITSM rows | A flagged file is audited `sftp.icap_flagged` naming the vendor's own reason; a scan failure is audited `sftp.icap_scan_failed` — **detection only**, the transfer is never blocked on either outcome |
| **ITSM ticket gate** | `PAM_TICKET_VALIDATE_URL` + `PAM_TICKET_PATTERN` (Phase 20 webhook); **first-class ServiceNow/Jira connectors** via `PAM_TICKET_PROVIDER`/`_URL`/`_USER`/`_TOKEN` (Phase 84: ticket state, change window, ticket names the operator); use-time re-check with `PAM_TICKET_REVALIDATE` (Phase 60) — all in `internal/ticket`, proven in CI against in-process fakes speaking the documented REST shapes | A **real** ServiceNow or Jira instance — like SQL Server, the connector ships tested against the documented protocol but its interop with a live instance is unverified | An access request without a valid change ticket — or one whose ticket is in the wrong state, outside its window or not naming the requester — is refused, audited `access.ticket_rejected` |
| **WORM archive storage** | `PAM_RETENTION_ARCHIVE_DIR`, `internal/api/archive.go` (Phase 49) | Genuinely write-once storage mounted at that path (S3 Object Lock, a WORM NAS) — the code writes digest-stamped exports and moves recordings, it cannot itself enforce immutability | The `audit.archived` SHA-256 matches a re-hash of the file, and a failed archive leaves the rows unpruned |

`PAM_OT_AIRGAP` disables the alert channels **and refuses to start** alongside
any integration in this catalogue that would reach the network — the ITSM ticket
webhook, the vendor-attestation webhook, the posture-attestation webhook
(Phase 133), the ICAP AV/DLP gateway (Phase 143), the SIEM forwarder, Conjur
sourcing, an OIDC issuer, the alert webhook. Each may be re-permitted individually by naming
it in `PAM_OT_AIRGAP_ALLOW`, which certifies that it resolves inside the enclave;
`PAM_KEK_PROVIDER=aws-kms` and `PAM_ENTRA_TENANT_ID` have no such hatch, because
there is no in-enclave version of somebody else's cloud.

---

## 6. Zero-trust agent identity (SPIFFE / SPIRE)

| Capability | Env / code | CI proof | You must provide | Verify |
|---|---|---|---|---|
| **SPIFFE JWT-SVID verification** | `PAM_BROKER_TRUST_DOMAIN_JWKS`, `internal/agentid/svid.go` | file JWKS + signed SVIDs | A trust-domain JWKS (from SPIRE or another issuer) | SVIDs validate (subject/audience/exp); RFC 8693 `act` delegation depth is capped |
| **Live SPIRE workload attestation** — *deferred* | Phase 13 | — none | A SPIRE deployment | Workloads receive SVIDs via the SPIRE agent, attested by the node/workload |

**Recording an owner is not attestation (Phase 170).** The `agent_identities`
registry maps a SPIFFE ID to the human pamv1 holds accountable for it, which is
what makes four-eyes and the offboarding cascade work on the attested path — and
it needs no external infrastructure, because it is a table in pamv1's own
database. It admits nothing: the trust domain already decided which workloads may
authenticate, and a name in a table proves nothing about the workload that
presented the SVID. The row above is still the gap, and it is the one that would
be closed by infrastructure rather than code. The related in-process item — enrolling SVID identities so that only claimed
ones may call, with first-seen/last-seen — shipped in **Phase 174** without any
external dependency, which is precisely the distinction: knowing *which* workloads
call and who answers for them is pamv1's own bookkeeping, while proving *what* a
workload is remains the row above.
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
| **Browser-extension live verification** (Phase 147) — the `extension/` Manifest V3 autofill extension is written, its JS syntax-checked (`node --check`) and its manifest JSON-validated, and it closely follows well-documented MV3 patterns, but it has never been loaded into a real Chromium/Firefox instance and driven against a real login form | A GUI browser environment (headless Chrome via `chromedp`/Puppeteer would close it in CI) | A `PAM_TEST_BROWSER`-gated interop test loading the unpacked extension and exercising a real autofill click, on the live-Postgres job pattern |
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
| **External Secrets Operator end-to-end** | A Kubernetes cluster running ESO | The contract is implemented and pinned by tests against an in-process server (`TestESOStatusContract`); what needs a cluster is the round trip — `ExternalSecret` reaching `SecretSynced`, the value landing in a `Secret`, a rotation propagating after `refreshInterval`, and above all that **revoking a grant leaves the Kubernetes Secret in place** (a 403 read as 404 would delete it). Checklist in `deploy/k8s/eso/README.md` |
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

## Permanent limitation, not an infra gap (Phase 157)

**Kernel-level IN-session tracing (eBPF Enhanced Session Recording) is not
available to a proxy, and no amount of infrastructure changes that.** Teleport
attaches eBPF probes to a session's processes because its SSH service *is* the
sshd on the node: the shell is its own child, in its own kernel. pamv1 brokers —
an operator's shell runs on the TARGET, under the target's sshd, in the target's
kernel — so a probe attached on the pam-server host would observe **zero** events
for every brokered session. This was verified before any code was written: there
is no `os/exec` anywhere in pamv1's production paths, the SSH proxy bridges
channels to the target's own sshd, and WinRM/Kubernetes/database work is remote
by construction.

The only pamv1 code that ever runs on a target is the Phase 153 **endpoint
agent**, on opt-in endpoints only. Even there, kernel tracing would need
system-wide probes plus a socket → sshd-child → process-tree correlation to know
which execs belong to which brokered session, *and* a reporting path from agent
to server that Phase 153 deliberately refused to open ("an agent may open NO
channels toward pamv1"). That is a different product shape — an agent-based PAM —
rather than a missing feature, so it is recorded here rather than as a to-do.

What pamv1 does instead is **Phase 157's post-session reconstruction** (the row
in §3 above): the target's own kernel audit records, pulled after the session
over the same vaulted credential, which closes the same forensic gap
(obfuscated and unechoed commands) with the target's own subsystem as the
witness. Its trust boundary is stated plainly in the artifact itself: a root
operator on the target can tamper with those logs — as they could unload an
eBPF probe.

## Deliberate non-goal

**Endpoint Privilege Management** (removing local admin / elevating sudo via an
endpoint agent) is a different product category that does not fit a vault + proxy
chokepoint, and is **out of scope** by design — it is not an infra gap, it is not
planned.
