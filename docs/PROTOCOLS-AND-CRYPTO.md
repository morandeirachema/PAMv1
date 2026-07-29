# pamv1 — Protocols & Cryptography

> Every protocol pamv1 speaks or brokers, and every cryptographic mechanism it
> relies on — with the file that implements each one.
>
> Last updated: 2026-07-29 · Reflects: Phases 0–53.

> 🟢 **Living document** — updated in the same change as the code. Whenever a
> protocol, cipher, key, TLS posture or transport-security env var changes, this
> file changes with it.

> ⚠️ **Beta · for learning purposes.** pamv1 is feature-complete against its
> [roadmap](../ROADMAP.md) and has closed every finding of its own security
> self-audit, but it has **not** been audited by anyone outside the project and
> is not production-ready. Nothing here is a certification claim.

Two audiences: an **auditor** asking "what protects this secret, and how", and a
**network engineer** asking "what will this process speak, and to whom". Ports
and firewall rules live in [PORTS-AND-FLOWS.md](PORTS-AND-FLOWS.md); known gaps
live in [SECURITY-GAPS.md](SECURITY-GAPS.md). This file is the *what and why*.

---

## 1. The short version

- **At rest**, every secret is AES-256-GCM with a per-secret data key, wrapped by
  a pluggable KEK (local key, HashiCorp Vault Transit, AWS KMS, or a PKCS#11
  HSM). The database only ever holds the envelope.
- **In transit**, every leg that can carry a credential is TLS — and the two
  places where the protocol itself offers no protection (TDS's keyless password
  transform, PostgreSQL's cleartext operator auth) are exactly where TLS is
  hardest to opt out of.
- **The audit trail** is hash-chained with HMAC-SHA-256 and periodically signed
  with Ed25519, so tampering is detectable and truncation is detectable
  separately.
- **Nothing is trusted because it is on the inside.** Every brokered session
  re-runs authorization, and the durable audit write happens *before* the secret
  is decrypted.

---

## 2. Cryptography

### 2.1 Secrets at rest — the vault envelope

`internal/vault/vault.go` produces a versioned token: `"v2:" + base64url(...)`.
The `v2:` prefix is a **wire format**, kept stable so keys can rotate without
re-reading every row.

| Property | Choice | Where |
|---|---|---|
| Data-key cipher | **AES-256-GCM**, fresh 32-byte key **per secret**, random 12-byte nonce per call | `internal/vault/vault.go` (`Encrypt`) |
| Envelope layout | `uint16(len(wrappedDEK)) ‖ wrappedDEK ‖ nonce ‖ ciphertext` | same |
| Binding | GCM **AAD** ties each ciphertext to its logical slot, so a valid envelope cannot be moved between rows | `internal/store/store.go` |
| Failure mode | every decrypt error collapses to one `ErrInvalidToken` — no padding/oracle distinction | `internal/vault/vault.go` (`Decrypt`) |

The AAD strings are the load-bearing detail. `CredentialAAD(targetID, credID)`
means a credential envelope copied onto another target simply fails to decrypt;
`KeyMaterialAAD(name)` means a stored SSH host key cannot be swapped in for the
CA key. **Never inline these strings** — both the encrypting and decrypting side
must call the same helper, or decryption silently fails.

**KEK providers** (`PAM_KEK_PROVIDER`, `internal/vault/kek.go`):

| Provider | Mechanism | Notes |
|---|---|---|
| `local` (default) | AES-256-GCM under `PAM_MASTER_KEY` (32 bytes, urlsafe-base64) | The key is in the environment — fine for dev, a real KEK for production. |
| `vault-transit` | HashiCorp Vault Transit encrypt/decrypt | `https://` **required** unless loopback (`internal/vault/transit.go`) — the request carries plaintext data keys and the Vault token. |
| `aws-kms` | KMS Encrypt/Decrypt with encryption context `{"app":"pamv1"}` | `internal/vault/awskms.go` |
| `pkcs11` | AES key inside an HSM, **CKM_AES_GCM** wrap | Build tag `pkcs11` only; the default build is a stub that errors (`internal/vault/pkcs11_stub.go`). |

Vault Transit and KMS both **reject a wrong-size unwrapped data key**, so a
provider misconfiguration cannot silently downgrade AES-256 to AES-128.

Rotation: `pam-server -rotate-kek` re-encrypts every secret under a new KEK read
from `PAM_NEW_KEK_*`. It is also the migration path *between* providers. Run it
offline; see [BACKUP-AND-RESTORE.md](BACKUP-AND-RESTORE.md).

### 2.2 Session recordings

Recordings are evidence, so they get both confidentiality and integrity.

- **Sealed at rest** (`PAM_RECORDING_ENCRYPT`): header `#pamrec1 <wrapped key>`
  then AES-256-GCM chunks. The per-recording key is wrapped by the KEK, and each
  chunk's AAD binds the recording name **and its chunk index** — so chunks cannot
  be reordered, duplicated or spliced between files (`internal/recording/recording.go`).
- **Hashed**: the SHA-256 of the bytes *as they land on disk* (sealed or not) is
  written into the `session.record` audit event, and recordings are **hash-chained**
  (`chain = SHA-256(prev ‖ fileHash)`, head in `<dir>/.chain`) so removing one
  recording breaks the chain (`internal/proxy/record.go`).
- **Verified on replay**: the portal re-hashes the stored file and reports whether
  that hash appears in the audit trail (`internal/api/recordings_handlers.go`).
- **Opaque names** (`PAM_RECORDING_OPAQUE_NAMES`): `<unixnano>_<8 random hex>`,
  because `<timestamp>_<target>_<actor>` told anyone with volume or backup access
  who reached which system and when. A random-source failure falls back to the
  descriptive name rather than minting a predictable one.

### 2.3 The audit trail

| Mechanism | Algorithm | Protects against | Where |
|---|---|---|---|
| Primary audit chain | **HMAC-SHA-256** over `prev ‖ canonical(actor, action, detail)` | Editing or deleting a row (`PAM_AUDIT_HMAC_KEY`) | `internal/store/store.go`, `pgstore`, `memstore` |
| Signed head | **Ed25519** over the running head | **Truncating the tail** — which a hash chain alone cannot detect (`PAM_AUDIT_SIGN_SEED`) | `internal/auditchain`, `internal/api/handlers.go` |
| Broker chain (agents) | HMAC-SHA-256 + **in-chain Ed25519 checkpoints** every N events | Same, for the separate AI-agent trail; forging a checkpoint needs the signing key too | `internal/auditchain/auditchain.go` |
| Truncation floor | `?min_entries=N` against an archived checkpoint's count | Truncation with no out-of-band anchor | `internal/auditchain` (`VerifyFloor`) |
| Signer publication | **JWKS** (`OKP`/Ed25519, `EdDSA`) at `GET /v1/audit/jwks` | Lets an external verifier check checkpoints, including across a signer rotation | `internal/api/broker_handlers.go` |

Timestamps are deliberately **excluded** from the canonical form: a chain that
covered them would break on any legitimate clock correction, and the ordering is
already pinned by the chain itself.

Verify with `GET /api/audit/verify` and `GET /api/audit/head`.

### 2.4 Keys that outlive a process — shared custody

A second replica that invents its own SSH host key looks exactly like a
man-in-the-middle to an operator, and a replica with its own audit chain key makes
honest events read as tampering. So the long-lived keys are held in **shared
custody** (`internal/keycustody/keycustody.go`): the candidate is sealed under the
KEK, offered to the store, and whichever replica wins the claim is adopted by the
rest. The database holds only the envelope.

Under custody: the **SSH proxy host key**, the **ZSP SSH-CA key**, and (when not
set in the environment) the **broker audit-chain HMAC key and Ed25519 signing
seed**. An explicit environment value wins *and is written through to custody*, so
a mixed fleet — or a later boot without the variable — cannot fork the chain.

### 2.5 Authentication secrets

| Secret | Storage | Comparison |
|---|---|---|
| `PAM_API_KEY` (bootstrap) | env only | SHA-256 digests compared in **constant time** (`crypto/subtle`) |
| Break-glass key | **only its SHA-256** (`PAM_BREAK_GLASS_KEY_HASH`) | constant time |
| Per-user PAM tokens | `pamt_` + 24 random bytes; **only the SHA-256 is stored** | hash lookup |
| Login sessions, agent keys, app keys, broker resume tokens | high-entropy random; only the SHA-256 stored; resume tokens single-use | hash lookup |

Hashing before comparison is not decoration: comparing raw keys leaks length, and
a fixed-size digest comparison does not.

**MFA** (`internal/mfa/totp.go`): TOTP per RFC 6238 — HMAC-SHA-1 (mandated by the
RFC for authenticator-app compatibility, annotated `#nosec G505`), 6 digits, 30-second
period, ±1 step of skew, constant-time compare. The matched time step is
**consumed server-side**, so a captured code cannot be replayed inside its window.
Recovery codes carry 120 bits of entropy and are stored as unsalted SHA-256 — at
that entropy an offline search is infeasible, which is why no KDF is used.

**Break-glass quorum** (`internal/shamir/shamir.go`): Shamir secret sharing over
GF(2^8) with the AES polynomial, using **branch-free constant-time** multiply and
inverse, because the shares are secret at reconstruction time. `-split-key`
produces the shares; `POST /api/breakglass/unseal` reassembles M of N.

### 2.6 SSH

- **Host key**: Ed25519, generated with `crypto/rand`, persisted as OpenSSH PEM
  `0600`, held in shared custody (`internal/proxy/hostkey.go`).
- **KEX and ciphers**: the `golang.org/x/crypto/ssh` defaults — deliberately not
  overridden, since hand-picking a suite list is how you end up pinned to
  yesterday's algorithms.
- **Zero Standing Privilege** (`internal/sshca/sshca.go`): an Ed25519 CA signs a
  **short-lived user certificate** (default 2-minute TTL, 1-minute clock skew) over
  a per-session ephemeral keypair, minted at dial time. Nothing durable is stored
  on the target.
- **Operator certificates**: pamv1 signs the operator's *own* public key after a
  proof-of-possession challenge — 8-byte expiry + 16 random bytes authenticated
  with HMAC-SHA-256 truncated to 16 bytes, keyed from a value derived from the CA
  key. It is **stateless**, so it works across replicas without shared session
  state. Certificates-as-keys are rejected; `source-address` and `force-command`
  critical options are supported; revocation is published as an OpenSSH **KRL**.
- **Upstream host keys**: verified against `PAM_SSH_KNOWN_HOSTS` when set. Unset,
  the proxy trusts any upstream key and says so loudly at startup — a documented
  gap, annotated `#nosec G106`, not an accident.

### 2.7 Database authentication

**PostgreSQL upstream** (`internal/proxy/dbproxy.go`) speaks
**SCRAM-SHA-256** (RFC 5802): 18-byte random nonce, `PBKDF2-HMAC-SHA-256` for the
salted password, and — importantly — it **verifies the server signature**. Skipping
that check, as an earlier version did, forfeits mutual authentication. MD5 auth is
supported because the wire protocol mandates it (`#nosec G501/G401`), as is
cleartext for servers configured that way.

The **operator-facing** PostgreSQL leg authenticates with a cleartext password
message carrying the PAM key. That is the protocol's own design, and it is why
`PAM_REQUIRE_DB_CLIENT_TLS` exists.

**SQL Server / TDS** (`internal/tds`) has no upstream authentication crypto at
all: TDS "password obfuscation" is a **nibble swap XOR 0xA5** — a fixed transform
with no key. It protects nothing. That single fact drives the whole TDS TLS
posture in §3.4.

### 2.8 Token verification (three independent verifiers)

| Path | Algorithms | Hard rules |
|---|---|---|
| **OIDC** (`internal/oidc`) | **RS256 only** (alg pinned), `rsa.VerifyPKCS1v15` + SHA-256 against the JWKS key by `kid` | Authorization Code + **PKCE S256**; issuer, audience, nonce and expiry all checked (60 s leeway); metadata reads capped at 1 MiB |
| **Entra ROPC** (`internal/auth/entra.go`) | RS256 via the same verifier | Expiry **required** (fail closed); tenant (`tid`) checked against config |
| **SPIFFE JWT-SVID** (`internal/agentid/svid.go`) | RS256, **ES256** (P-256), **EdDSA** | Expiry and audience mandatory; subject must be inside the configured trust domain; RFC 8693 `act` delegation chains bounded by `PAM_BROKER_MAX_DELEGATION_DEPTH`, every delegate in-domain |

All three make failures **indistinguishable** to the caller — no oracle telling an
attacker which check failed.

### 2.9 Supply chain and deploy

- **Images are signed keyless with cosign** (OIDC identity, no long-lived key),
  with an **SPDX SBOM attestation** and **SLSA build provenance**
  (`.github/workflows/release.yml`).
- **Secrets in manifests** are encrypted with **SOPS + age**, scoped by creation
  rule to `data`/`stringData` and `PAM_*` keys (`deploy/.sops.yaml`). The
  committed example age key is explicitly a throwaway.
- The bundled PostgreSQL runs `scram-sha-256` for host and local auth
  (`deploy/docker/docker-compose.yml`).

---

## 3. Protocols

### 3.1 Inbound — what connects to pamv1

| Protocol | Port / env | Encrypted | Notes |
|---|---|---|---|
| **HTTP/HTTPS** REST + 5250 portal | `PAM_LISTEN_ADDR`, `:8080` | HTTPS with `PAM_TLS_CERT/KEY`; `PAM_REQUIRE_HTTPS` fails closed | Auth: `X-API-Key`, or `Bearer` for broker/MCP and the app-secrets API |
| **Server-Sent Events** | same port | follows the server | Live session monitoring (`/api/sessions/{id}/stream`) and the MCP stream |
| **WebSocket** | same port | follows the server | In-portal RDP viewer; subprotocol `guacamole`. The token rides the URL because browsers cannot set headers on a WS handshake — so it is short-lived and **tunnel-scoped**: leaked from an access log it cannot call the API |
| **SSH** | `PAM_SSH_ADDR`, `:2222` | yes | Operators authenticate with their PAM key as the SSH password; only session channels are proxied; 120-second pre-auth deadline |
| **PostgreSQL wire** | `PAM_DB_ADDR`, off (`:5433` by convention) | only with a cert | `SSLRequest` answered `S`/`N`; **GSSEnc always refused** |
| **TDS (SQL Server)** | `PAM_MSSQL_ADDR`, off (`:1433` by convention) | `ENCRYPT_ON` with a cert, else `NOT_SUP` | See §3.4 |
| **Prometheus metrics**, **healthz** | same port | follows the server | Hand-rolled text exposition; no client libraries |

### 3.2 Outbound — what pamv1 connects to

| Protocol | Where | Encrypted by default |
|---|---|---|
| **SSH** to targets, and to a **jump host** (`direct-tcpip`) | `internal/proxy` | Yes; host keys verified only with `PAM_SSH_KNOWN_HOSTS` |
| **PostgreSQL** to database targets | `internal/proxy/dbproxy.go` | TLS if the server accepts; **verified** only with `PAM_DB_UPSTREAM_CA`/`_TLS_VERIFY` |
| **TDS** to SQL Server targets | `internal/proxy/mssqlproxy.go` | **TLS mandatory** — a plaintext upstream is refused outright |
| **WinRM** (WS-Management SOAP) | `internal/winrm` | **HTTPS by default** (`PAM_WINRM_HTTPS=true`); Basic or **NTLM** |
| **guacd** (Guacamole protocol) for RDP | `internal/guacd` | **Plain TCP on this hop** — keep guacd on a private network; guacd→RDP is cert-verified unless `PAM_GUACD_IGNORE_CERT` |
| **LDAP/LDAPS** (Active Directory) | `internal/auth/ldap.go` | **`ldaps://` enforced** — the scheme is rejected otherwise, because bind passwords travel on it |
| **Entra ID / OIDC** | `internal/auth/entra.go`, `internal/oidc` | Yes (HTTPS endpoints) |
| **Syslog RFC 5424 / CEF / LEEF** (SIEM) | `internal/auditfwd` | Only with `PAM_AUDIT_FORWARD_PROTO=tls` — and then certificate verification is **always on**, with no skip knob. RFC 5425 octet framing over TLS |
| **Alerts**: webhook, syslog, SMTP | `internal/alert` | Webhook per URL scheme; syslog no; SMTP **opportunistic** StartTLS |
| **CyberArk Conjur** | `internal/conjur` | TLS 1.2, optional pinned CA. Sources `PAM_MASTER_KEY`/`PAM_API_KEY` at boot, fail-loud |
| **AWS KMS** | `internal/vault/awskms.go` | Yes (SDK) |
| **PostgreSQL LISTEN/NOTIFY** | `internal/store/pgstore/killbus.go` | Per connection string — the cross-replica kill bus |
| **TCP reachability probes** | `internal/discovery` | n/a — connect-only, ports 22/1433/3389/5985/5986 |

The **identity blast-radius engine** (`internal/blast`) is worth calling out for
what it does *not* do: it evaluates AWS IAM **offline**, over an ingested JSON
snapshot. It makes no AWS API calls.

### 3.3 Brokered application protocols

These are protocols pamv1 *parses* rather than merely carries — that is what makes
per-statement audit and command control possible.

- **SFTP** (`internal/proxy/sftpguard.go`) — the SSH subsystem stream is parsed so
  every file operation is audited, `readonly` refuses writes/deletes/renames with a
  synthesized `SSH_FX_PERMISSION_DENIED` (the target is never contacted), and a
  regex **path** denylist applies in **every** mode including downloads. A path you
  deny that can still be fetched is not denied.
- **PostgreSQL** — each `Query`/`Parse` is audited and recorded. The deprecated
  fast-path `FunctionCall` carries no SQL text, so it cannot be filtered; it is
  audited instead of being allowed to escape the trail silently.
- **TDS** — see below.
- **Guacamole** — the instruction stream is decoded so clipboard transfers can be
  gated and audited, and drive redirection is forced off in every mode.

### 3.4 TDS in detail, and why it is strict

The SQL Server proxy (Phase 53) is the newest and least conventional, so its
decisions are recorded explicitly.

- **The upstream leg must be encrypted.** TDS's password transform is keyless, so
  the credential would otherwise be effectively in the clear. A server that
  declines encryption is **refused**, not downgraded.
- **The "encrypt the login packet only" mode is never selected.** That mode
  reverts to plaintext mid-stream, which is precisely where silent-downgrade bugs
  live. The proxy offers whole-session encryption or none.
- **MARS is disabled.** Multiplexed sessions would carry SMP headers the request
  parser never sees, so per-statement audit and command control would silently go
  blind rather than fail loudly.
- **Integrated/Windows (SSPI) authentication is refused**, and **federated-auth
  tokens are stripped** from the forwarded login. Brokering means swapping the
  operator's PAM key for a vaulted SQL login; a federated token would authenticate
  the *operator's own* identity upstream while the session was audited as the
  vaulted account. The specification forbids the integrated-auth flag alongside
  such a token, so stripping it is the only way to catch it.
- **TDS 8.0 strict encryption** (raw TLS before any TDS byte) is unsupported, and
  says so instead of hanging.
- **A statement the proxy cannot parse is refused** when a command guard is
  configured. Command control that cannot see a statement is not command control.
- **The TLS handshake is framed inside TDS packets** and split at 4096 bytes,
  because a TDS client sizes its read buffer from the packet size *during* the
  handshake and rejects anything larger.

**Not verified:** interop against a real Microsoft SQL Server. The codec is pinned
to specification-derived byte literals and the brokering is proven end to end
against an in-process fake upstream, but no licensed instance exists in CI. See
[EXTERNAL-INFRA-GAPS.md](EXTERNAL-INFRA-GAPS.md).

---

## 4. Where verification is opt-in (read this before deploying)

Being explicit is better than being reassuring. Each of these defaults to the
permissive setting, warns at startup, and is annotated in the source:

| Leg | Default | Make it strict |
|---|---|---|
| SSH → target host key | trust any (warned) | `PAM_SSH_KNOWN_HOSTS` |
| PostgreSQL → target TLS | TLS if offered, **not verified** | `PAM_DB_UPSTREAM_CA` or `PAM_DB_UPSTREAM_TLS_VERIFY` |
| SQL Server → target TLS | TLS **required**, not verified | same two variables |
| Operator → DB proxies | plaintext unless a cert is configured | `PAM_TLS_CERT/KEY` + `PAM_REQUIRE_DB_CLIENT_TLS` |
| Portal/API | plaintext HTTP | `PAM_TLS_CERT/KEY` + `PAM_REQUIRE_HTTPS` |
| pamv1 → guacd | plain TCP, no TLS option | Keep it on a private network / same pod |
| LDAP | `ldaps://` enforced | (already strict; `PAM_LDAP_INSECURE_SKIP_VERIFY` is dev-only) |
| SMTP alerts | opportunistic StartTLS | Use a webhook or TLS syslog for sensitive alerting |

Every `InsecureSkipVerify` in the non-test code is one of: the loopback
healthcheck probe, the LDAP dev toggle, or the two documented database
trust-any fallbacks above. Every one carries a `#nosec` annotation with its
reason — that is the convention, so an unexplained one is a review finding.

**Air-gapped deployments** (`PAM_OT_AIRGAP`) default-deny every egressing
integration, including the AWS-KMS KEK and Entra. Name a variable in
`PAM_OT_AIRGAP_ALLOW` to assert it resolves inside the enclave. See
[OT-DEPLOYMENT.md](OT-DEPLOYMENT.md).

---

## 5. Cryptographic inventory (one table)

For an auditor who wants the whole list on one screen.

| Primitive | Used for |
|---|---|
| AES-256-GCM | Secrets at rest, recording chunks, local/PKCS#11 KEK wrap |
| HMAC-SHA-256 | Audit chains, SCRAM, operator-cert challenge, SSH-CA challenge key derivation |
| SHA-256 | Key/token hashing, recording and export digests, recording hash chain, PKCE challenge |
| HMAC-SHA-1 | TOTP only (RFC 6238 compatibility) |
| MD5 | PostgreSQL MD5 auth only (wire-protocol mandated) |
| Ed25519 | SSH host key, SSH CA, rotated SSH keys, audit checkpoints, JWKS |
| RSA (PKCS#1 v1.5 + SHA-256) | OIDC/Entra/SVID token verification |
| ECDSA P-256 | SVID `ES256` verification |
| PBKDF2-HMAC-SHA-256 | SCRAM salted password |
| Shamir over GF(2^8) | Break-glass M-of-N quorum |
| TLS 1.2+ | Every configured TLS surface (explicit `MinVersion`) |
| `crypto/rand` | Every key, nonce, token, session id and CSP nonce |
| `crypto/subtle` | Every secret comparison |

---

## 6. Related reading

- [PORTS-AND-FLOWS.md](PORTS-AND-FLOWS.md) — the listener/egress matrix for
  firewalls and NetworkPolicies.
- [ARCHITECTURE-LOW-LEVEL.md](ARCHITECTURE-LOW-LEVEL.md) — the full `PAM_*`
  table, wire formats, audit vocabulary and security invariants.
- [SECURITY-GAPS.md](SECURITY-GAPS.md) — the self-audit: every gap found, and
  whether it was fixed, mitigated or deferred.
- [AGENT-THREAT-MODEL.md](AGENT-THREAT-MODEL.md) — the AI-agent broker's threat
  model, including its separate audit chain.
- [BACKUP-AND-RESTORE.md](BACKUP-AND-RESTORE.md) — backing up the database and
  the KEK *separately*, and what each key's loss costs.
- Back to the [documentation hub](README.md).

---

## 7. Change log

| Date | Change |
|---|---|
| 2026-07-29 | First version, written from a file-by-file audit of the code: the vault envelope and its four KEK providers, recording sealing + hash chain, the two audit chains and their Ed25519 checkpoints, shared key custody, authentication-secret handling, SSH/ZSP/operator-certificate crypto, PostgreSQL SCRAM and TDS's keyless transform, the three token verifiers, supply-chain signing — plus the full inbound/outbound protocol matrix, the brokered (parsed) protocols, the TDS strictness rationale, and a single table of every place verification is opt-in. |
