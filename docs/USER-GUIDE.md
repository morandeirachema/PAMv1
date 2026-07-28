# pamv1 — User Guide

For **operators, auditors and approvers** who use pamv1 to reach systems or to
review activity. If you deploy or administer pamv1, see the
[Administrator Guide](ADMIN-GUIDE.md) instead.

> **Living document.** Kept in step with the product — update it whenever
> user-facing behavior changes (portal, connecting, roles). Add a row to the
> [change log](#8-change-log) with each update.
>
> Last updated: 2026-07-28 · Reflects: Phases 0–52g — the 5250 console (11, now keyboard-first and with full backend parity: safes, campaigns, risk analytics, live watch — Phase 25), custom permission profiles (12), the database session proxy you connect to with `psql` (15), supervised sessions (16: a supervisor may watch live, and a command can be blocked by policy), and Zero Standing Privilege on some targets (22: no stored password — pamv1 signs a short-lived certificate for your session). Since then, the things you are most likely to *notice*: a SQL statement can **pause mid-session** for a supervisor's decision (30) instead of the session dying; your session can be **refused outright** if recording is required but not configured (52c); certification and step-up decisions need the **approver** capability (39) and nobody may decide their own (46, 52c); and recovery codes are now four groups of six (52e). An admin revoking your access still ends your live sessions immediately. See the [ROADMAP](../ROADMAP.md).

> ⚠️ Educational / pre-production project — see the [README](../README.md).

---

## 1. What pamv1 does for you

pamv1 lets you connect to a server **without ever holding its password**. You
authenticate to pamv1 with your own access token; pamv1 fetches the target's
credential from its encrypted vault and injects it into the connection for you.
Your session is recorded and logged. This is *just-in-time (JIT)* credential
injection.

```mermaid
flowchart LR
    YOU["You<br/>(your token)"] -->|"ssh"| PAM["pamv1 proxy"]
    PAM -->|"injects the vaulted password"| TARGET["Target server"]
```

You never see the target's password — and that's by design.

## 2. Your role decides what you can do

An administrator assigns you one of four built-in roles (or a **custom permission
profile** — a named set of the same capabilities, tailored by your admin):

| Your role | You can | You cannot |
|---|---|---|
| **user** | Connect to targets through the proxy; see the list of targets | Manage anything, reveal secrets, read the audit trail |
| **auditor** | Read the inventory and the full audit trail | Connect to targets, change anything |
| **approver** | Read inventory + audit, approve/deny access requests¹ | Connect to targets, change anything |
| **admin** | Everything (see the Admin Guide) | — |

¹ The 4-eyes access-request approval workflow (shipped in Phase 8); approvers review requests in the portal's "Work with access requests" screen.

## 3. How you sign in

There are a few ways, depending on how your organization set things up:

- **Single sign-on (SSO)** — click **Single sign-on** on the Sign On screen (or
  open `/api/auth/oidc/start`). You authenticate with your identity provider
  (Entra ID, Okta, etc., including its MFA), then land back in the portal already
  signed in. This is the smoothest option when your org enabled it.


- **Active Directory (AD) login** — you sign in with your **AD username and
  password**. On the portal Sign On screen, fill *User* and *Password*. pamv1
  gives you a **session token** valid for 12 hours; the portal keeps it for you.
  For the SSH proxy, first get a token from the login endpoint (your admin can
  script this) and use it as the SSH password. Your role comes from your AD groups.
- **Access token** — your administrator creates your user and gives you a
  **token** like `pamt_1a2b3c…`, shown only once (store it in your password
  manager). Use it as the *access token* on the Sign On screen (leave Password
  blank), or as the **SSH password** when connecting through the proxy.

If your session expires, just sign in again. If you lose a token, an admin issues
a new one.

### Adding a second factor (MFA)

You can protect your sign-in with a 6-digit code from an authenticator app
(Google Authenticator, Microsoft Authenticator, 1Password…). Once signed in:

1. **Enroll:** `POST /api/mfa/enroll` returns a `secret` and an `otpauth://` URI
   — add either to your authenticator app (scan the URI as a QR or type the secret).
2. **Confirm:** `POST /api/mfa/verify` with `{"otp":"123456"}` from the app.

From then on, when you sign in with User + Password the portal also asks for your
**MFA code** — enter the current 6-digit code. (Bearer access tokens aren't
protected by MFA; MFA covers the username/password login.)

**Recovery codes:** `POST /api/mfa/recovery-codes` gives you 10 single-use backup
codes, each shaped like `abcdef-ghijkl-mnopqr-stuvwx`. Save them somewhere safe —
this is the only time they are shown. If you lose your phone, enter one in the
MFA code field to sign in; each works only once, and generating a new set
replaces the old one.

Treat a recovery code exactly as you would your password: it bypasses your second
factor completely and stays valid until it is used. The hyphens are only there to
make the code readable when you copy it onto paper; type it however your client
accepts it.

If your organization **requires MFA**, your first sign-in gives you a limited
session that can *only* set up MFA — enroll and confirm, then sign in again
normally with your code. That limited session can't open any target session
(SSH, WinRM, RDP **or** database) until you've completed enrollment.

## 4. Using the portal

The portal is an intentionally old-school [IBM 5250 / AS-400](https://en.wikipedia.org/wiki/IBM_5250)
green-screen terminal — the austerity is deliberate, to remind you that you're
touching privileged systems.

1. Open the portal URL your admin gave you (over **HTTPS**).
2. On the **Sign On** screen, either fill *User* + *Password* (AD login) or put your
   token in *access token* (leave Password blank), then press **Enter**.
3. Use the numbered menu to move around; the function keys work like a real 5250:

| Key | Action |
|---|---|
| **Enter** | Confirm / submit the screen |
| **Esc** | Cancel / go back (the twin of F12) |
| **↑ / ↓** | Move between the option cells in a list |
| **Tab** | Move to the next field |
| **F3** | Exit to the main menu / sign off |
| **F5** | Refresh |
| **F6** | Add (target, credential, grant, user, access request, safe, member, campaign) |
| **F9** | Context action (export the audit CSV; reconcile the directory) |
| **F12** | Cancel / go back |

The portal is **keyboard-first**: the mouse is **optional**. The cursor lands on
each screen's main field automatically, so you can just start typing — no clicking
required.

The **main menu** is your whole management surface. This is the complete menu;
**the portal hides the rows your role may not use**, so you may see fewer:

| # | Screen | |
|---|---|---|
| 1 | Work with targets (+ access grants, require-approval) | any inventory-reading role sees it; changing needs `manage_targets`, option 7 (RDP) needs `connect` |
| 2 | Work with vaulted credentials (reveal, check-out, rotate, reconcile) | any inventory-reading role sees it; `5=Display secret` / `6=Check-out` need `reveal_secret`, the rest need `manage_credentials` |
| 3 | Credential check-out / check-in (exclusive leases) | admin |
| 4 | Work with active sessions (live monitor + kill; option 5 watches one live) | `read_audit` — a plain `user` does not see it; `4=End session` needs `manage_targets` |
| 5 | Work with access requests (4-eyes approve / deny / file) | |
| 6 | Rotation & reconciliation report | admin |
| 7 | Discovery scan (find and onboard hosts) | admin |
| 8 | Work with users & profiles (mint tokens, directory reconcile) | admin |
| 9 | Multi-factor authentication (enroll / recovery / disable — yourself) | |
| 10 | Display audit trail (filter + CSV export) | |
| 11 | Break-glass unseal (M-of-N quorum) | |
| 12 | Work with permission profiles | admin |
| 13 | System configuration | admin |
| 14 | Effective config & IaC export | admin |
| 15 | Work with application secrets | admin |
| 16 | Work with safes (members, delegated administration) | |
| 17 | Certification campaigns (review access, certify / revoke) | |
| 18 | Risk analytics (behavioral risk per actor) | |
| 19 | Session recordings (replay stored sessions, hash-verified) | |
| 20 | Approve AI-agent tool calls (parked calls, with the arguments policy matched on) | approver |
| 21 | In-session step-up decisions (paused SQL statements — these expire) | |
| 22 | Work with vendors & contract grants (register, approve, offboard, evidence) | |
| 23 | Work with operator SSH certificates (issued certs, revoke, KRL download) | |
| 24 | Identity blast radius (paste a graph, see escalation paths + remediation) | |
| 25 | Work with login sessions (see and revoke active password/SSO logins) | admin |
| 26 | Work with AI-agent keys (mint / revoke broker identities) | admin |
| 90 | Sign off | |

The audit screen (10) also carries the tamper-evidence controls: **F6** verifies
the HMAC chain, **F7** shows the signed head checkpoint, **F9** exports CSV and
**F10** exports OCSF for a SIEM. On a credential row, option **9** opens its
dependent accounts (the services updated on rotation).

On list screens you type an **option number** next to a row (e.g. `5` to display,
`4` to delete, and on targets, safes and users `2` to **change** — edit in
place; the object keeps its credentials, grants and memberships) and press
Enter. Long lists load completely: the portal pages through the API's bounded
result windows for you.

Options your role can't use simply don't appear on the menu — that's normal for
your role, not an error.

## 5. Connecting to a target (the main event)

You connect with a normal SSH client. The **SSH username selects the target**, and
your **PAM token is the SSH password**.

```bash
# Connect to target "web-01" (uses that target's first credential)
ssh -p 2222 web-01@PAM_HOST

# Choose a specific credential (account "root") on that target
ssh -p 2222 root@web-01@PAM_HOST

# Read-only / observer session: watch the output but cannot type or run commands
ssh -p 2222 root@web-01+observe@PAM_HOST

# Windows target (if the admin enabled it): an interactive WinRM command loop —
# each line you type runs as a separate command (not a stateful PowerShell)
ssh -p 2222 Administrator@win-01@PAM_HOST
```

- `PAM_HOST` is the pamv1 proxy host; `2222` is the proxy port (ask your admin).
- When prompted for a password, paste your **PAM token**.
- You'll land on the target as the vaulted account. You never typed — and never
  learn — that account's real password.

What happens behind the scenes: pamv1 checks your token and role, pulls the
credential from the vault, decrypts it just for this connection, logs you in to
the target, and records the session. For some targets there is **no stored
password at all** — pamv1 signs a short-lived certificate just for your session
(Zero Standing Privilege). You connect exactly the same way; nothing changes for
you.

> **Your session is recorded.** Everything on screen is captured (asciicast) and a
> tamper-evident hash is stored. Connect only for authorized work. A supervisor
> may also **watch your session live**, and a dangerous command can be **blocked
> by policy** — if you see `command blocked by policy`, that command was refused
> before it reached the target (the rest of your session continues).

> **File transfers (SFTP) are audited too.** You can use `sftp`/`scp` over the
> proxy as normal, but each file operation is logged. Depending on policy your
> access may be **read-only** (uploads, deletes and renames are refused with
> "permission denied" — downloads still work) or SFTP may be **disabled** (the
> subsystem is refused; you still get a shell). Ask your admin if you need to
> upload and can't.

### Connecting to a database (PostgreSQL)

If your admin enabled the database proxy, you reach `postgres` targets with
**`psql`** the same way: the **username selects the credential and target**, and
your **PAM token is the password**.

```bash
# user "dbuser" on target "appdb", connecting to database "orders"
psql "host=PAM_HOST port=5433 user=dbuser@appdb dbname=orders"
# Password: <your PAM token>
```

You run SQL as the vaulted database account without ever learning its password;
**every statement you run is audited**. `5433` is the database-proxy port (ask
your admin; it's off unless enabled).

### Connecting to a Windows desktop (RDP)

For a `windows` target with the **RDP** protocol you don't need any client — the
desktop opens **inside the portal**. In *Work with Targets*, type option **`7`**
next to the target and press Enter. The green title bar shows which host you're
on; the Windows desktop renders in the browser. Press **`Ctrl+Alt+Q`** to
disconnect and return to the list.

As everywhere in pamv1, the password is injected for you — it reaches the RDP
broker, never your browser — and the session is audited (and may be watched live
by a supervisor). This needs your admin to have enabled RDP (a `guacd` broker);
if option 7 does nothing, the target isn't RDP or RDP isn't enabled.

### Automating the password prompt

For scripts, an SSH client can read the password non-interactively (e.g. with
`sshpass -e` and `SSHPASS=$PAM_TOKEN`, or an `SSH_ASKPASS` helper). Prefer your
platform's secret store over hard-coding the token.

## 6. Reviewing activity (auditor / approver)

Auditors and approvers can read the audit trail — in the portal's
**Display Audit Trail** screen, or via the API:

```bash
curl -H "X-API-Key: $YOUR_TOKEN" "https://PAM_HOST/api/audit?limit=100"
```

Each entry shows the timestamp, the **actor** (a real username, or `break-glass`),
the **action**, and details. Break-glass entries are highlighted — they mark
emergency access and always deserve a look.

You can also **watch an in-progress session live**: on **Work with Active
Sessions**, type option **5** next to a session and its output streams into a
view-only pane as it happens (F12 stops watching). The same stream is available
via the API — `GET /api/sessions/{id}/stream` (Server-Sent Events). The watch
itself is audited (`session.monitor`).

Two more review screens (both need audit-read):

- **Certification campaigns** (menu 17) — the periodic access review: each item
  is one grant; you (or an admin) certify it (keep) or revoke it (**the grant is
  deleted**). Auditors can read every campaign and its decisions as evidence;
  deciding an item needs the **approver** capability (`approve`) since Phase 39 — creating and closing a campaign is what needs a user-management role. You cannot certify a grant **you** created (four-eyes, Phase 46; revoking your own is still allowed), and a revoke now also terminates that user's live sessions to the affected targets.
- **Risk analytics** (menu 18) — per-actor behavioral risk over the recent audit
  window. Every score is explainable: the screen lists the named signals
  (break-glass, blocked commands, auth-failure bursts, off-hours, velocity) and
  the points each contributed. Filter by minimum level or widen the window and
  press Enter to rescore.
- **Session recordings** (menu 19, Phase 26) — replay any stored recording:
  option `5` on a row opens a player in the same pane as the live viewer.
  **Space** pauses/resumes, **F5** restarts, **F6** cycles the speed
  (1x→2x→4x→8x→MAX; long silences are compressed to 2s). The header shows
  whether the recording's SHA-256 **matches the value in the audit trail** — a
  file tampered on disk is flagged in amber. Every replay is itself audited
  (`session.playback`).

When you **file an access request** (menu 5, F6) you can now also provide a
change **ticket** (if your organization gates access on ITSM tickets), ask for a
stricter **N-of-M approval chain**, set an **active window** (`Active from` /
`Active until`) to pre-approve a future maintenance slot, and mark it
**one-time** (Phase 26): a single-use approval is consumed by the first
connection (or reveal/checkout/WinRM run) it admits and grants nothing further —
file a new request for the next session. Approvers see the ticket, the approval
progress (e.g. `1/2`), the window, and a `1x`/`used` marker for single-use
requests on their list.

## 7. Troubleshooting

| What you see | What it means / what to do |
|---|---|
| `invalid or missing API key` (401) | Your token is wrong or was deleted. Check it, or ask an admin for a new one. |
| `your role does not permit this action` (403) | Your role can't do that — expected. Ask an admin if you need more access. |
| SSH: `your role may not open sessions` | You're an auditor/approver; only `user`/`admin` can connect. |
| SSH: `unknown target "x"` | The target name in your SSH username doesn't exist — check spelling with your admin. |
| SSH: `upstream connection failed` | pamv1 reached your token fine, but couldn't reach the target (down, or bad vaulted credential). Tell your admin. |
| `too many attempts; try again shortly` | Repeated failed sign-ins from your address were rate-limited. Wait a minute and retry with the correct token. |
| `command blocked by policy` (SSH exec / WinRM / SQL) | That specific command matched a command-control deny rule and was refused before reaching the target. The session continues; run something else or ask your admin. |
| SSH/psql: `connection requires an approved access request` right after a session that worked | Your approval was **one-time** and the previous connection consumed it. File a new access request. |
| `psql`: `pamv1: authentication failed` | Your PAM token (the psql password) is wrong or deleted — check it, or ask for a new one. |
| Portal panels are empty | Normal — your role can't read those panels. |
| Your session ended abruptly / `connection closed` mid-session | An admin may have revoked your login or your grant to that target — revocation now ends live sessions. Confirm your access. |

---

### Things that are not your fault

Four refusals landed in recent phases that look like breakage but are policy
working as configured. If you hit one, quote it to your administrator.

| What you see | What it means |
|---|---|
| `pamv1: session recording is unavailable; session refused` (SSH), `pamv1: session recording unavailable` (psql), or **503 recording is required but not configured** in the portal | Your site requires every session to be recorded and recording is not configured for that path. Nothing to do at your end |
| `pamv1: statement requires supervisor approval (denied or timed out)` | Your statement matched the step-up policy and paused for a second person. Nobody decided in time, or they refused. **A simple query leaves the session open**; one sent over the extended protocol ends it |
| `session limit reached` (or HTTP 429) | You are at your concurrent-session cap. Close one and retry |
| `vendor access requires an approved, in-window contract grant for this account` | You are a third-party user and your contract grant has not been approved, or its window has closed |

Also: leaving the SSH or `psql` password prompt idle now drops the connection
after **120 seconds** with no message. Reconnect and type promptly — it is a
guard against connections that open and never authenticate, not a fault.

## 8. Change log

| Date | Change |
|---|---|
| 2026-07-27 | Phase 45: **console parity restored** — menus **22–26** (vendors & contract grants, operator SSH certificates, identity blast radius, login sessions, AI-agent keys), option **9=Dependents** on a credential, and the audit screen's tamper-evidence keys (F6=Verify chain, F7=Signed head, F10=OCSF export). The menu table above now lists 20/21 too (shipped in Phase 43). §4 |
| 2026-07-27 | Phase 44: **2=Change** on Work with Targets, Safes and Users — edit a target's host/port, rename a safe, or change a user's role in place; nothing attached to the object is lost, and a changed user keeps their token. The target form now also offers the `postgres` protocol. §4 |
| 2026-07-25 | Phase 32: **SFTP file transfers are audited**, and may be **read-only** (uploads/deletes refused) or **disabled** by policy. §3 |
| 2026-07-24 | Phase 26: **Session recordings** (menu 19) — replay stored recordings with a keyboard-first player and an on-screen audit-hash verdict; **one-time access requests** (a single-use approval is consumed by the first connection it admits) with a `1x`/`used` marker on the approver list. §4, §6, §7 |
| 2026-07-24 | Phase 25 (console parity): menu items **16–18** (safes, certification campaigns, risk analytics), **watching a session live from the portal** (Active Sessions option 5), and the richer access-request form (ticket, N-of-M approvals, active window). §4, §6 |
| 2026-07-23 | **RDP in the portal:** documented option **7** on an RDP target — the Windows desktop now renders in the browser (`Ctrl+Alt+Q` disconnects), no client needed. §5 |
| 2026-07-23 | Completed the main-menu table (items 12–15); noted that revoking access now ends live sessions (troubleshooting + header); aligned with the doc set |
| 2026-07-21 | Portal is now **keyboard-first** (mouse optional): the cursor lands on each screen's field, **Esc** goes back, **↑/↓** move between list rows |
| 2026-07-21 | Phase 22: some targets now use **Zero Standing Privilege** — there is no stored password; pamv1 signs a short-lived certificate just for your session. You connect exactly as before |
| 2026-07-21 | Phases 15–16: connect to **`postgres` targets with `psql`** through the proxy (`:5433`; every SQL statement audited); sessions can be **watched live** by a supervisor and a command can be **blocked by policy** (`command blocked by policy`). Custom permission profiles (Phase 12) can be assigned in place of the four built-in roles |
| 2026-07-20 | Phase 11: the portal is now a full role-aware management console — menu options for sessions, check-out, access requests, users, MFA, discovery, reconciliation, audit export and break-glass, in the same 5250 style |
| 2026-07-18 | Phase 3b: OIDC single sign-on option on Sign On |
| 2026-07-18 | Phase 3b: recovery codes + enforce-MFA (enrollment-only first sign-in) |
| 2026-07-28 | Phase 52e: recovery codes are longer — four groups of six (`abcdef-ghijkl-mnopqr-stuvwx`) instead of two groups of five. Codes you already hold keep working; generate a new set to get the longer ones |
| 2026-07-18 | Phase 3b: TOTP MFA (enroll/confirm, MFA code on Sign On) |
| 2026-07-18 | Phase 3b: Active Directory login (username + password → session token) added to Sign On |
| 2026-07-18 | Initial user guide (Phase 3a): roles, tokens, portal Sign On, connecting via the SSH proxy, audit review |

*Questions an admin should answer live in the [Administrator Guide](ADMIN-GUIDE.md).*
