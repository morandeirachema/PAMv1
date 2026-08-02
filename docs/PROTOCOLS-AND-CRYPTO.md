# pamv1 — Protocols & Cryptography

> Every protocol pamv1 speaks or brokers, and every cryptographic mechanism it
> relies on — with the file that implements each one.
>
> Last updated: 2026-08-02 · Reflects: Phases 0–59a.

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
- **In transit**, every credential-bearing leg *can* be TLS — with one exception:
  the **pamv1 → guacd hop is always plain TCP** and carries the vaulted RDP or
  VNC credential, so guacd belongs on a private network or in the same pod.
  Classic VNC adds a second exception of its own — it has no transport security
  at all, and its authentication is DES over an 8-character password (§3.5). The
  TDS
  **upstream** leg is the one place TLS cannot be opted out of; the
  operator-facing legs (portal/API, both database proxies) run plaintext until
  you configure a certificate. §4 is the honest table.
- **The audit trail** can be hash-chained with HMAC-SHA-256 and its head signed
  with Ed25519 — tamper-evidence and truncation-evidence respectively. For the
  **primary** trail both are **opt-in and off by default**
  (`PAM_AUDIT_HMAC_KEY`, `PAM_AUDIT_SIGN_SEED`); the AI-agent broker's separate
  chain provisions its own keys and is always on when the broker is.
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
  written into the audit trail — `session.record` for proxied sessions,
  `winrm.run` for WinRM transcripts. The **proxy** recordings (SSH, PostgreSQL,
  SQL Server `.cast` files) are additionally **hash-chained**
  (`chain = SHA-256(prev ‖ fileHash)`, head in `<dir>/.chain`), so removing one
  breaks the chain (`internal/proxy/record.go`). Two artifacts are **not** in
  that chain: WinRM run transcripts (hashed and audited, but unchained) and
  guacd's server-side RDP recordings (`PAM_GUACD_RECORDING_PATH`), which guacd
  writes itself — neither hashed, chained, nor sealed by pamv1.
- **Verified on replay**: the portal re-hashes the stored file and reports whether
  that hash appears in the audit trail (`internal/api/recordings_handlers.go`).
- **Opaque names** (`PAM_RECORDING_OPAQUE_NAMES`): `<unixnano>_<8 random hex>`,
  because `<timestamp>_<target>_<actor>` told anyone with volume or backup access
  who reached which system and when. A random-source failure falls back to the
  descriptive name rather than minting a predictable one.

### 2.3 The audit trail

The primary chain is **opt-in**: with no `PAM_AUDIT_HMAC_KEY` the trail is an
ordinary append-only table, and `GET /api/audit/head` answers `501` until
`PAM_AUDIT_SIGN_SEED` is set too. The broker chain is different — it generates
and holds its own keys under custody, so it is always on when the broker is.

| Mechanism | Algorithm | Protects against | Where |
|---|---|---|---|
| Primary audit chain (opt-in) | **HMAC-SHA-256** over `prev ‖ canonical(actor, action, detail)` | Editing or deleting a row — **only when `PAM_AUDIT_HMAC_KEY` is set** | `internal/store/store.go`, `pgstore`, `memstore` |
| Signed head (opt-in) | **Ed25519** over the running head | **Truncating the tail** — which a hash chain alone cannot detect. Needs `PAM_AUDIT_SIGN_SEED` **and** the HMAC key | `internal/auditchain`, `internal/api/handlers.go` |
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
| **WebSocket** | same port | follows the server | In-portal RDP **and VNC** viewers; subprotocol `guacamole`. The token rides the URL because browsers cannot set headers on a WS handshake — so it is short-lived and **tunnel-scoped**: leaked from an access log it cannot call the API |
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
| **guacd** (Guacamole protocol) for RDP **and VNC** | `internal/guacd` | **Plain TCP on this hop** — keep guacd on a private network; guacd→RDP is cert-verified unless `PAM_GUACD_IGNORE_CERT`; guacd→VNC has nothing to verify (§3.5) |
| **LDAP/LDAPS** (Active Directory) | `internal/auth/ldap.go` | **`ldaps://` enforced** — the scheme is rejected otherwise, because bind passwords travel on it |
| **Entra ID / OIDC** | `internal/auth/entra.go`, `internal/oidc` | Entra URLs are constructed `https://`. For a **generic OIDC provider the scheme is not enforced** — an `http://` issuer would be accepted, unlike Vault Transit, which rejects one. Configure HTTPS endpoints |
| **Syslog RFC 5424 / CEF / LEEF** (SIEM) | `internal/auditfwd` | Only with `PAM_AUDIT_FORWARD_PROTO=tls` — and then certificate verification is **always on**, with no skip knob. RFC 5425 octet-counted framing applies to the `rfc5424` format; CEF and LEEF stay newline-delimited on every transport |
| **Alerts**: webhook, syslog, SMTP | `internal/alert` | Webhook per URL scheme; syslog no; SMTP **opportunistic** StartTLS |
| **CyberArk Conjur** | `internal/conjur` | TLS 1.2, optional pinned CA. Sources `PAM_MASTER_KEY`/`PAM_API_KEY` at boot, fail-loud |
| **AWS KMS** | `internal/vault/awskms.go` | Yes (SDK) |
| **PostgreSQL LISTEN/NOTIFY** | `internal/store/pgstore/killbus.go`, `livebus.go`, `stepupbus.go` | Per connection string. The live-monitor relay's payloads are additionally **sealed with AES-256-GCM** under a shared-custody key (`internal/session/livecrypto.go`) — necessary because NOTIFY channels have no privilege model, so `sslmode` protects the hop but not the *readers* of the channel. The kill bus is sealed by the same key: its selectors carry an AES-256-GCM seal over a timestamp bound to the target fields, so a kill can be neither forged nor replayed. The step-up decision bus (Phase 56) is sealed the same way — session/verdict/decider as AAD, ±2 min freshness — and the shared `stepups` inventory stores each paused **statement** as an AES-256-GCM envelope under that key (AAD: session/actor/replica), so a database observer reads ciphertext and a fabricated pending row fails to open and is never listed |
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
  deny that can still be fetched is not denied. The `SSH_FXP_EXTENDED` family is
  governed from an **explicit list** rather than by familiarity, because a modern
  client's ordinary operations live there: `posix-rename@openssh.com` (what
  `rename` actually sends), `hardlink@openssh.com` (a second name for a denied
  path) and `lsetstat@openssh.com` (attribute mutation *by path*) obey the same
  policy as their classic packets; `copy-data@openssh.com` is refused under
  capture, since it copies inside the server where no `WRITE` or `DATA` crosses
  the proxy; the benign ones (statvfs, fsync, limits, path lookups) pass; and
  anything unrecognized is refused under read-only or capture rather than
  forwarded because it is unfamiliar.
  **Without content capture this inspector is fail-open**, and deliberately
  differs from the TDS proxy: a stream it cannot frame is audited once
  (`sftp.parse_error`) and then forwarded **un-inspected** — after that point
  neither the audit, the path denylist nor the read-only refusals apply. The TDS
  path takes the opposite choice (refuses what it cannot parse).
  **With content capture on (`PAM_SSH_SFTP_CAPTURE`, Phase 59) the posture
  inverts to fail-closed**: capture is containment, so an unframable stream on
  either leg, an unparsable OPEN/READ/WRITE/CLOSE, or an overflowing tracking
  bound fails the transfer rather than let bytes move unobserved. Capture parses
  **both legs** — OPEN/WRITE/READ/CLOSE on the request side; HANDLE (which binds
  the server's handle to the opened path), DATA and STATUS on the response side,
  forwarded byte-identical — and writes each transferred file as a **chunk-log
  artifact**: a JSON header (remote path, open mode), then one line per data
  movement `["w"|"r", offset, base64]` in arrival order. A log rather than a
  reassembled file, because random-access writes cannot stream through the
  at-rest Sealer and reassembly would merge overlapping rewrites the wire
  actually carried. The artifact rides the **same cryptography as a session
  recording**: sealed with a per-artifact data key wrapped by the vault KEK when
  `PAM_RECORDING_ENCRYPT` is on (`#pamrec1` chunked AES-256-GCM, AAD-bound to
  the artifact name and chunk index), SHA-256 hashed **as stored**, linked into
  the recordings' hash chain, and attested by `sftp.file_recorded`. The
  per-file cap refuses data past it (permission-denied), so it doubles as a
  transfer size limit. If you need no file transfer at all, `PAM_SSH_SFTP=deny`
  still refuses the subsystem outright.
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

### 3.5 VNC in detail, and why it is brokered rather than exposed

VNC (Phase 54) is rendered in the portal through guacd exactly as RDP is, and it
runs the same authorization gates in the same function. What differs is that VNC
brings **no security of its own**:

- **The wire is plaintext.** Classic RFB has no TLS. There is no certificate to
  verify on the guacd→target hop and no `ignore-cert` decision to make — the
  bytes, including the framebuffer of a privileged desktop, are in the clear.
  Keep guacd and its targets on a private network.
- **Authentication is DES with an 8-character key.** RFB security type 2 hands
  the server a challenge, and the client replies with it encrypted under the
  password — a 56-bit DES key. Every implementation therefore **truncates the
  password to 8 characters**; a longer one is not stronger, its tail is
  discarded. This is why the vaulted secret must never reach the operator: it is
  short, offline-crackable from a captured handshake, and usually shared.
- **There is no server authentication at all.** The client proves knowledge of
  the password to the server; nothing proves the server is the right host. A
  machine-in-the-middle on that hop is not detectable by the protocol.
- **The file-transfer channel is forced off.** guacd can layer SFTP onto a VNC
  session (`enable-sftp`); pamv1 always sends it disabled, the same stance it
  takes on RDP drive redirection — file movement belongs on the audited SFTP
  path, not on a channel that leaves no record.
- **A clipboard policy that guacd cannot enforce refuses the session.** The gate
  is applied through guacd's `disable-copy`/`disable-paste` parameters, and guacd
  silently *drops* a parameter it did not advertise. So the tunnel checks the
  handshake's advertised argument list and, if a non-permissive policy cannot be
  applied, refuses with `vnc.refused … reason:clipboard-unenforceable` instead of
  rendering an ungated desktop while the portal reports the policy as in force.
  The same check protects RDP.

**Not verified:** rendered pixels against every VNC server implementation. The
brokering, credential injection and clipboard gating are proven end to end
against an in-process fake guacd, and `deploy/docker/docker-compose.vnc-demo.yml`
runs a real TigerVNC desktop for a by-hand check.

---

## 4. Where verification is opt-in (read this before deploying)

Being explicit is better than being reassuring. Most of these default to the
permissive setting and are annotated in the source. **Startup warnings exist for
the SSH host-key, both database upstream legs, both database operator legs and
the plaintext portal — but not for the guacd hop or SMTP StartTLS**, so their
absence in the log is not evidence of safety. The LDAP row is strict by default:

| Leg | Default | Make it strict |
|---|---|---|
| SSH → target host key | trust any (warned) | `PAM_SSH_KNOWN_HOSTS` |
| PostgreSQL → target TLS | TLS if offered, **not verified** | `PAM_DB_UPSTREAM_CA` or `PAM_DB_UPSTREAM_TLS_VERIFY` |
| SQL Server → target TLS | TLS **required**, not verified | same two variables |
| Operator → DB proxies | plaintext unless a cert is configured | `PAM_TLS_CERT/KEY` + `PAM_REQUIRE_DB_CLIENT_TLS` |
| Portal/API | plaintext HTTP | `PAM_TLS_CERT/KEY` + `PAM_REQUIRE_HTTPS` |
| pamv1 → guacd | plain TCP, no TLS option | Keep it on a private network / same pod |
| guacd → VNC target | plaintext, **no server authentication** (the protocol offers none) | Nothing to configure — isolate the segment; prefer RDP/SSH where you can choose |
| LDAP | `ldaps://` enforced | (already strict; `PAM_LDAP_INSECURE_SKIP_VERIFY` is dev-only) |
| SMTP alerts | opportunistic StartTLS | Use a webhook or TLS syslog for sensitive alerting |

There are **four** verification-skip knobs. Three appear as a literal
`InsecureSkipVerify` in this repo — the loopback healthcheck probe, the LDAP dev
toggle, and the two documented database trust-any fallbacks above — each carrying
a `#nosec G402` or `//nolint:gosec` annotation with its reason. The fourth,
`PAM_WINRM_INSECURE_SKIP_VERIFY`, will **not** show up in such a grep: the skip
happens inside the `masterzen/winrm` dependency, which pamv1 hands the flag to.
An unexplained skip in pamv1's own code is a review finding; this list is the
whole set.

**Air-gapped deployments** (`PAM_OT_AIRGAP`) refuse to start alongside the
egressing integrations they gate — the ITSM webhook, the vendor-attestation
webhook, the SIEM forwarder, Conjur and the webhook alerter — and **hard-refuse**
the AWS-KMS KEK and Entra outright. Name a variable in `PAM_OT_AIRGAP_ALLOW` to
assert it resolves inside the enclave. Three caveats an auditor should know:
**alerting is disabled entirely** under air-gap regardless of the allow-list (the
alerter is replaced with a no-op, so allow-listing the webhook does not bring it
back); the syslog and SMTP alert channels are not in the gate list at all; and
`PAM_LDAP_URL` and `PAM_KEK_TRANSIT_ADDR` are **assumed in-enclave** — they are
neither denied nor allow-listable. See [OT-DEPLOYMENT.md](OT-DEPLOYMENT.md).

---

## 5. Cryptographic inventory (one table)

For an auditor who wants the whole list on one screen.

| Primitive | Used for |
|---|---|
| AES-256-GCM | Secrets at rest, recording chunks, local/PKCS#11 KEK wrap |
| HMAC-SHA-256 | Audit chains, SCRAM, the operator-certificate challenge MAC (its key is derived by plain SHA-256 over a CA signature) |
| SHA-256 | Key/token hashing, recording and export digests, recording hash chain, PKCE challenge |
| HMAC-SHA-1 | TOTP only (RFC 6238 compatibility) |
| MD5 | PostgreSQL MD5 auth (wire-protocol mandated) |
| DES (56-bit, 8-char key) | Classic VNC authentication only — performed by **guacd**, not by pamv1, and mandated by RFB security type 2. Listed because it bounds how much a vaulted VNC password can protect (§3.5) |
| NTLMv2 (MD4 NT hash, HMAC-MD5) | Optional WinRM auth (`PAM_WINRM_AUTH=ntlm`) — implemented by the `go-ntlmssp`/`bodgit` dependencies, not by pamv1. Legacy by nature; prefer HTTPS + Basic, or Kerberos at the target |
| Ed25519 | SSH host key, SSH CA, rotated SSH keys, audit checkpoints, JWKS, and `EdDSA` SPIFFE-SVID token verification |
| RSA (PKCS#1 v1.5 + SHA-256) | OIDC/Entra/SVID token verification |
| ECDSA P-256 | SVID `ES256` verification |
| PBKDF2-HMAC-SHA-256 | SCRAM salted password |
| Shamir over GF(2^8) | Break-glass M-of-N quorum |
| TLS 1.2+ | Every configured TLS surface sets an explicit `MinVersion`, except two client-side fallbacks that inherit Go's own 1.2 floor: the PostgreSQL upstream trust-any config and the SMTP StartTLS config |
| `crypto/rand` | Every key, nonce, token, session id and CSP nonce |
| `crypto/subtle` | Every **direct** comparison of a secret-derived value (API/break-glass keys, TOTP, SSH-CA challenge, break-glass unseal). Per-user tokens, agent keys and app keys are verified by **hashed-index lookup** instead — the digest is the database key, so there is no value to compare in constant time |

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
| 2026-08-02 | **Phase 59a — the review of the capture.** No cryptography changed; what changed is where it is applied and what it attests. An artifact's name is now `sanitize`d before it reaches `filepath.Join` (an unsanitized target name escaped the recording directory with `O_CREATE|O_TRUNC`), and `sanitize` also refuses to produce a leading `.`, since a dotfile artifact is one the archiver skips and the pruner preserves. The **audited path is colon-escaped**: `strconv.Quote` keeps colons inside the quotes, and a detail is matched as text, so a path named `evade sha256:<hash>` planted the exact substring playback's tamper check looks for — an operator could vouch for a recording they had altered. Each artifact's attestation is written through the session-teardown auditor, so a drained session cannot leave sealed files whose hash appears nowhere. The per-artifact KEK wrap is bounded and cancellable (`artifactWrapTimeout`), and it no longer runs the audit store under the mutex both SFTP legs share. Wire-level: whole packets only are forwarded on the response leg (a synthesized refusal could otherwise land inside a half-written `DATA`), request ids are single-use while outstanding, `pflags=0` counts as a read, and the `SSH_FXP_EXTENDED` family is governed from an explicit list — see §3.3 |
| 2026-08-01 | **Phase 59 — SFTP content capture, and the inspector's posture split.** No new primitive: a captured file artifact (`internal/recording/sftpfile.go`, a JSON chunk log of every data movement) is sealed by the **same** `#pamrec1` scheme as a session recording — per-artifact data key wrapped by the vault KEK, chunked AES-256-GCM with the artifact name + chunk index as AAD — hashed as stored, and linked into the recordings' SHA-256 chain. Wire-protocol coverage grew on both legs: the request inspector now parses `SSH_FXP_CLOSE`/`READ`/`WRITE` bodies and a response watcher frames `HANDLE`/`DATA`/`STATUS` (forwarded byte-identical) to bind server handles to paths and downloads to offsets. **Posture**: the inspector stays fail-open *without* capture (§3.3), but with `PAM_SSH_SFTP_CAPTURE` on it is fail-closed — an unframable stream on either leg refuses the transfer, because a containment control that can be evaded by being unparsable is not one. Also closed while parsing the wire: OpenSSH's `posix-rename@openssh.com`/`hardlink@openssh.com` EXTENDED requests now obey rename policy (they previously bypassed the readonly refusal and the path denylist, which parsed only the classic packet) |
| 2026-07-31 | **Phase 57 — the broker signs delegated identities.** A third ed25519 signing key joins the primary-audit and broker-checkpoint signers: `PAM_BROKER_TOKEN_SIGN_SEED` (shared custody by default, KEK-sealed, one per cluster) signs the delegated JWT-SVIDs minted at `POST /v1/token`. **EdDSA over the JWS signing input**, `kid` derived from SHA-256 of the public key so a rotation cannot be mistaken for the key it replaced, published as a JWK at `GET /v1/token/jwks`. The minted token is a bearer credential for THIS broker only (`aud` fixed, refused otherwise) and its lifetime is `min(PAM_BROKER_EXCHANGE_TTL_MIN, the delegator's own exp)`. Verification reuses the existing SVID path — the broker's public key is added to the same kid→key map as the trust-domain bundle, refusing a colliding kid — so there is no second, more-trusted verification path. No new dependency and no new primitive: the same `crypto/ed25519` and JWT machinery `internal/oidc` and `internal/auditchain` already use |
| 2026-07-31 | **Phase 56 — cross-replica step-up decisions.** Two new payload kinds under the existing shared-custody live-bus key (`internal/session/livecrypto.go`), no new key and no new transport: (1) a **decision** (`pam_stepup_decision` NOTIFY channel, `pgstore/stepupbus.go`) carries an AES-256-GCM seal over a timestamp, AAD-bound to session id + verdict + decider, refused outside a ±2 min window — so a release can be neither forged, flipped, re-attributed nor replayed (a replay inside the window finds the pause already claimed); (2) a pending pause's **statement** rests in the shared UNLOGGED `stepups` table as an AES-256-GCM envelope, AAD-bound to session id + actor + replica — session content never touches the database in the clear, and a fabricated or tampered row fails authentication and is skipped from every listing, making the seal double as row authentication. Store TLS (`sslmode`) still protects the hop; the seals protect against the channel's and table's *readers and writers* |
| 2026-07-29 | **Phase 55 — cross-replica live monitoring.** No new protocol on the wire and no new cryptography: the live-monitor relay is two more `LISTEN/NOTIFY` channels beside the Phase 34 kill bus, riding the store connection and therefore its TLS (`sslmode` in `PAM_DATABASE_URL`) — which is now also what protects **watched-session output in transit between replicas**, a fact worth knowing when choosing `sslmode`. Frames are JSON with base64 data, chunked under NOTIFY's ~8000-byte limit; NOTIFY payloads are not persisted, and the new `live_sessions` inventory table holds session *metadata* only (actor, target, protocol, replica, timestamps — never output bytes or credentials). Outbound table updated |
| 2026-07-29 | **Phase 54 — the VNC connector.** New §3.5: VNC is brokered through guacd like RDP but brings no security of its own — plaintext RFB, DES authentication over an 8-character-truncated password, and no server authentication — which is the whole argument for keeping the credential server-side and guacd private. `enable-sftp` is forced off (VNC's analog of RDP drive redirection), and a clipboard policy guacd does not advertise the parameters to enforce now **refuses the session** rather than running ungated (this check covers RDP too). Summary, inbound/outbound tables, the opt-in-verification table and the cryptographic inventory (DES) updated with it |
| 2026-07-29 | First version, written from a file-by-file audit of the code: the vault envelope and its four KEK providers, recording sealing + hash chain, the two audit chains and their Ed25519 checkpoints, shared key custody, authentication-secret handling, SSH/ZSP/operator-certificate crypto, PostgreSQL SCRAM and TDS's keyless transform, the three token verifiers, supply-chain signing — plus the full inbound/outbound protocol matrix, the brokered (parsed) protocols, the TDS strictness rationale, and a single table of every place verification is opt-in. |
