# PAMv1 — Backup & Restore Runbook

> **Living document.** Update when the data model or deployment changes. See the
> [change log](#change-log).
>
> Last updated: 2026-08-27 · Reflects: Phases 0–225. **Phases 206–207 change nothing here**: proof of possession adds no table, no migration and no artifact to back up — a `cnf` thumbprint is a claim inside an already short-lived token, and the key it names is held by the agent, never by PAMv1. The procedure is unchanged, and the migration high-water mark is now **`0051`**: Phase 222 added it (one additive `subject` column on `broker_tokens` — the identity a resume token is bound to; a restore carries it like any other column, and a token restored without one — a pre-migration row — merely spends for anyone for its remaining minutes, so there is nothing extra to back up). Before it, `0050`: Phase 219 added it (`agent_call_reservations`, the compare-and-spend ledger behind the agent budget — a transient table holding at most one rolling 24-hour window per agent and purging itself on write; a restore carries it like any other table, and restoring an older dump only means an agent is under-served for at most a day, never over-served, so there is nothing extra to back up). Before it, `0049`: Phase 212 added it (one partial unique index, `agent_keys_active_name_unique` — at most one ACTIVE agent key per name, the 2026-08-26 audit's M-3; an index carries no data, so a restore rebuilds it and there is nothing extra to back up — **but a dump taken before v0.58.1 that holds two active agent keys with the same name will not start under v0.58.1 until one of them is disabled**, see the CHANGELOG's upgrade note). Before it, `0048`: Phase 197 added it (one additive nullable
> `alias` column on `app_secret_grants` plus a partial unique index — a name for a
> grant, never a secret, so a restore carries it like any other column and there
> is nothing extra to back up). Before it, `0047`: Phase 189 added it (two plain indexes — `target_grants` and `safe_members` by `(subject_type, subject)` — so the subject-indexed grant query is not a sequential scan; indexes carry no data, so a restore simply rebuilds them and there is nothing extra to back up). Before it, `0046`: Phase 174 added that one (three additive columns on `agent_identities` — `enrolled`, defaulting TRUE so every row an operator created stays truthful, plus `first_seen`/`last_seen`, which a restore carries like any other column); Phase 167 added `0044` (one additive nullable `budget_per_day` column on `agent_keys` — NULL means "use the server default", which is what every existing row already meant — plus an `(actor, action, ts)` index on `audit_events`, so a restored database rebuilds it like any other index) and Phase 170 added `0045` (a new `agent_identities` table mapping a SPIFFE ID to the human accountable for it; nothing secret in it either — an identity NAME, an owner name and a note). Both are additive and applied at startup, so a restore of an older dump migrates forward on first boot with nothing to do by hand. Earlier: `0043` (Phase 159 added it — two additive nullable columns on `agent_keys` (`expires_at`, `last_used_at`, both NULL for every existing row, which is exactly today's behaviour) and a new `agent_quarantine` table keyed by subject; nothing to migrate by hand and nothing secret in either — a quarantine row holds an identity NAME and a reason, never a credential; Phase 153 added `0042` (Phase 157 added none either — a forensic artifact is a file in `PAM_RECORDING_DIR`, backed up with the recordings it sits beside, and its hash lives in the audit trail like every other artifact's; Phase 155 added none — a `kubernetes` target is an ordinary `targets` row and its service-account token an ordinary `credentials` row, vaulted under the KEK like every other secret, so a restore needs nothing new; Phase 153 added `0042` (Phase 153 added it — `endpoint_agents`: id, name, target_id (FK, cascade), key_hash (unique), created_by, created_at, last_seen, revoked_at, plus a partial unique index enforcing one live agent per target; only key HASHES, so a restored backup restores agent identities without ever holding a key — an agent whose key you have lost is simply revoked and re-registered; Phase 151 added none — the SAML AuthnRequest ID reuses the existing `oidc_states` single-use table, and the SP key pair, when configured, is operator-supplied file material like `PAM_TLS_KEY`, backed up with the deployment's own secrets, not by PAMv1; Phase 149 added `0041` — `users.external_id` (with a partial unique index excluding the empty default) and `users.active`, two additive columns, plus a new `scim_keys` table mirroring `agent_keys`/`app_keys`; every existing user row defaults `active` to `true`, so nothing already-working changes; Phase 147 added none — an extension token is a row in the original `sessions` table (migration `0001`), the same one every RDP/VNC viewer token and MFA-pending token already uses; `auth.SessionScopeExtension` is a new value for the existing `scope` column, not a new column or table; Phase 145 added none — `secret_type: "file"` is a new value on an existing plain-`TEXT` column, not a schema change; Phase 143 added none — ICAP scanning holds captured bytes in memory only, long enough to submit one scan, then discards them; no new table or column; Phase 141 added none — port-forwarding is a new SSH channel-type handler in the proxy, no schema touched; Phase 139 added migration `0040` (`safes.personal`, a boolean column — no new table, additive, defaults false); Phase 137 added migration `0039` (a new `approval_invites` table, mirroring `session_share_invites`'s own shape); Phase 135 added migration `0038` (`credentials.double_lock_holder`/`double_lock_verifier`/`double_lock_enc`, three TEXT columns — no new table, additive, defaults empty); Phase 133 added migration `0037` (`users.device_fingerprint`, a text column — no new table, additive, defaults empty); Phase 131 added none — command allow-listing is a regex file read at startup, no schema touched; Phase 129 added migration `0036` (`credentials.is_provisioner`, a boolean column — no new table, additive, defaults false); Phase 128 added none — account discovery reads existing credentials, it vaults nothing new; Phase 126 added none — portal color themes are a client-side `localStorage` preference, no schema touched; Phase 124 added `webauthn_credentials` and `mfa_webauthn_challenges`; Phase 122 added none — suspend/resume state is in-memory only; Phase 120 added `access_requests.recur_days`/`next_run_at` plus a new `password_history` table; Phase 118 added a `users.ip_allowlist` column; Phase 116 added `session_share_invites` plus a `vendors.email` column; phases 71–115 otherwise added none beyond `0031`), migrations `0025`–`0041` are additive and applied at startup, and the new columns/tables live in tables this runbook already covers.

> ⚠️ **Beta · for learning purposes.** PAMv1 is feature-complete against its
> [roadmap](../ROADMAP.md) and has closed every finding of its own security
> self-audit, but it has **not** been audited by anyone outside the project and is
> **not** production-ready.

PAMv1 has **two** things to protect, and they must be backed up **separately** —
backing them up together defeats the encryption:

1. **The database** — targets, encrypted credentials, users, sessions, MFA
   enrollments, audit trail. Secrets here are ciphertext.
2. **The vault key** — `PAM_MASTER_KEY` (local KEK) or the KMS key material
   (`vault-transit`). Without it, a database backup is unrecoverable *by design*.

> ⚠️ Keep the key backup in a **different** location/custodian from the database
> backup (e.g. the DB backup in object storage, the key in a secrets manager /
> sealed envelope). Anyone holding both can decrypt every secret.

Also back up, if used (these are **keys** → hold them under separate-custodian
handling like the vault key):

- the **audit-chain keys** `PAM_AUDIT_HMAC_KEY` and `PAM_AUDIT_SIGN_SEED` —
  without the HMAC key you cannot verify the audit chain after a restore, and the
  archived `GET /api/audit/head` ed25519 checkpoints are your only tail-truncation
  anchor;
- the **broker audit keys** `PAM_BROKER_AUDIT_KEY` and
  `PAM_BROKER_AUDIT_SIGN_SEED` back a second, independent HMAC + ed25519 chain,
  and losing them costs the agent trail exactly what losing
  `PAM_AUDIT_HMAC_KEY` costs the main one. Whether you set them explicitly or
  not, they end up **custody-held** (an explicit value is written through to
  `key_material` at startup), so a database backup plus the KEK already
  restores them; keeping explicitly-set values out of band as well is the same
  belt-and-braces as the host/CA PEMs — the only recovery from a lost KEK;
- the **SSH proxy host key**, the **ZSP SSH-CA key**, and the custody-held
  **broker audit keys** — these live in the database (`key_material`) sealed
  under the KEK (host/CA since Phase 42; broker keys since the Phase 13
  follow-on), so a database backup plus the KEK already restores them; the files
  at `PAM_SSH_HOST_KEY` / `PAM_SSH_CA_KEY` are on-disk *mirrors*, not the system
  of record (the broker keys have no mirror). Keeping the host/CA PEMs out of
  band is still worthwhile: it is the only recovery from a lost KEK that does
  not rotate the host key and the CA;
- session recordings (`PAM_RECORDING_DIR`, including the `.chain` head that anchors
  the [recording hash chain](ARCHITECTURE-LOW-LEVEL.md));
- **the retention archive** (`PAM_RETENTION_ARCHIVE_DIR`), if set — the retention
  sweep *moves* aged recordings out of `PAM_RECORDING_DIR` and writes aged audit
  rows there as digest-stamped JSON Lines. A backup scoped only to the recording
  directory silently loses everything past the retention cutoff, which is also
  where the *oldest* sealed recordings live — the ones most likely to outlast a
  KEK rotation.

> **Two rules for restoring recordings, both easy to get wrong:**
>
> 1. **Never rename them.** A sealed recording's file name is the AAD for both
>    its key envelope and every chunk, so a restore that renames, re-cases or
>    flattens file names produces recordings that cannot be decrypted at all.
> 2. **A sealed recording is not a file you can open.** It does not replay with
>    `asciinema`; it must be served by a running pam-server holding the KEK that
>    wrote it. A disaster-recovery plan that assumes "the recordings are just
>    files" is wrong.
>
> If `PAM_RECORDING_OPAQUE_NAMES` is on, the file name identifies neither target
> nor actor — that mapping exists **only** in the `session.record` / `winrm.run`
> audit rows. Restoring recordings while having pruned audit leaves you with
> unattributable files.

## Back up the database

```bash
# Consistent logical backup, compressed (custom format)
pg_dump --format=custom --no-owner "$PAM_DATABASE_URL" > pamv1-$(date +%F).dump

# Encrypt the dump before it leaves the host (age, gpg, or your KMS)
age -r <recipient> pamv1-*.dump > pamv1-*.dump.age && rm pamv1-*.dump
```

Store the dump in your backup system with retention that satisfies your audit
requirements (NIS2 retention — see [audit retention & SIEM forwarding](NIS2-COMPLIANCE.md#3-audit-retention--siem-forwarding)).

## Back up the vault key

- **Local KEK:** copy `PAM_MASTER_KEY` into your secrets manager (Vault, AWS
  Secrets Manager, 1Password) or a sealed envelope under dual control. Record the
  key version/date. Test recovery periodically.
- **vault-transit KEK:** nothing to export — Vault holds the key. Ensure **Vault
  itself** is backed up (its storage + unseal keys / recovery keys).

## Restore

```bash
# 1. Provision an empty PostgreSQL database and restore the dump
age -d -i <identity> pamv1-*.dump.age | pg_restore --no-owner --dbname "$PAM_DATABASE_URL"

# 2. Provide the SAME vault key the backup was encrypted under
export PAM_MASTER_KEY=<the-backed-up-key>          # or point vault-transit at the same key

# 3. Start pam-server; the schema is applied idempotently on boot
./pam-server
```

Verify by revealing/decrypting one credential (or opening a proxy session) — if
the key matches, it works; if not, the vault key is wrong.

## Key-loss scenarios

- **Lost the vault key, have the DB:** you have lost considerably more than the
  credentials, and "re-onboard and carry on" is **not** a recovery path.
  - Every **vaulted secret** — credentials, TOTP enrollments, secret config
    values — is unrecoverable. This part is the intended failure mode: the
    database alone is useless.
  - Every **sealed session recording** (`PAM_RECORDING_ENCRYPT=true`) is
    permanently unreadable. Each recording carries its own AES-256-GCM data key
    wrapped by the KEK **inside the file**, not in the database, so a recording
    backup without its KEK is inert. Recordings written before sealing was turned
    on are unaffected — the format is detected per file.
  - **pam-server will not start.** Since Phase 42 the SSH proxy host key and the
    Zero Standing Privilege CA key live in the `key_material` table sealed under
    the KEK, and an envelope that cannot be unwrapped is treated as fatal by
    design — silently regenerating a host key or a CA is the
    machine-in-the-middle-shaped event that shared custody exists to prevent.
    Getting past it means deleting those rows so a fresh pair is claimed, which
    **does** rotate the proxy host key (every pinned client warns) and the SSH CA
    (every target trusting the old CA must be re-pointed, and every issued ZSP or
    operator certificate becomes void).

  Practically: **treat the KEK as no more losable than the database itself.**
- **Lost the DB, have the key:** restore from the last DB backup; secrets decrypt
  normally.
- **Compromise suspected:** rotate the vault key (`pam-server -rotate-kek`, see the
  [Admin Guide](ADMIN-GUIDE.md#rotating-the-vault-key)), rotate exposed target
  credentials, and review the audit trail (including any `break-glass` rows).

  > ⚠️ `-rotate-kek` re-wraps the four kinds of envelope held in the **store** —
  > credentials, TOTP enrollments, secret config values, and the Phase-42 SSH
  > host/CA key custody. It does **not** re-wrap sealed recordings, and it cannot:
  > rewriting a recording's bytes would invalidate the SHA-256 that the audit
  > trail and the recording hash chain attest to, destroying the tamper evidence
  > the sealing exists to provide. **Keep the old KEK for at least as long as you
  > retain sealed recordings**, including any already moved to
  > `PAM_RETENTION_ARCHIVE_DIR`. The command counts them and names the KEK they
  > still need.

## Hardened PostgreSQL (production)

- Require TLS: `sslmode=verify-full` in `PAM_DATABASE_URL` with a pinned CA.
- Enforce `scram-sha-256` (the bundled compose already does).
- Use a **least-privilege** DB role for pam-server (DML on its tables; not a
  superuser).
- Enable **[pgAudit](https://www.pgaudit.org/)** for database-side audit logging
  (needs an image that bundles the extension; the demo `postgres:17-alpine` does not).
- Managed HA with point-in-time recovery **ships** in `deploy/k8s/postgres-cnpg.yaml`
  (a 3-instance [CloudNativePG](https://cloudnative-pg.io/) cluster with automatic
  failover). Uncomment the `backup.barmanObjectStore` block and point it at object
  storage to enable continuous backup + PITR.

## Change log

| Date | Change |
|---|---|
| 2026-08-27 | Phase 222 (resume token bound to its collector): migration high-water mark `0050` → `0051` (`broker_tokens.subject`, an additive column naming the parking agent — never a secret). A plain dump covers it; no new key-inventory bullet. |
| 2026-08-27 | Phase 219 (the budget as a compare-and-spend): migration high-water mark `0049` → `0050` (`agent_call_reservations`). A transient ledger — one rolling window per agent, self-purging — that carries no secret and no key material: a plain dump covers it, and an older dump restored merely under-serves agents for at most 24 hours. No new key-inventory bullet. |
| 2026-08-13 | Phase 116 (live session-sharing): migration high-water mark `0031` → `0032` (`session_share_invites`, plus a `vendors.email` column). Its `token_hash` column follows the existing hash-only pattern (like PAM tokens), never KEK-vaulted, so no new key-inventory bullet is needed — a plain database dump already covers it. The share invite's separate in-memory **guest key** is never persisted at all, so there is nothing there to back up or lose |
| 2026-07-23 | Aligned with the doc set (standard header, change log); added the audit-chain keys and ZSP SSH-CA key to the backup inventory; corrected the CloudNativePG PITR note (ships in `deploy/k8s/postgres-cnpg.yaml`); fixed the NIS2 retention cross-link |
| 2026-07-19 | Initial backup & restore runbook (Phase 5): separate DB and vault-key backup, restore procedure, key-loss scenarios, hardened Postgres |
