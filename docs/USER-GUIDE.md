# pamv1 — User Guide

For **operators, auditors and approvers** who use pamv1 to reach systems or to
review activity. If you deploy or administer pamv1, see the
[Administrator Guide](ADMIN-GUIDE.md) instead.

> **Living document.** Kept in step with the product — update it whenever
> user-facing behavior changes (portal, connecting, roles). Add a row to the
> [change log](#8-change-log) with each update.
>
> Last updated: 2026-08-25 · Reflects: Phases 0–190 — the 5250 console (11, now keyboard-first and with full backend parity: safes, campaigns, risk analytics, live watch — Phase 25), custom permission profiles (12), the database session proxy you connect to with `psql` (15), supervised sessions (16: a supervisor may watch live, and a command can be blocked by policy), and Zero Standing Privilege on some targets (22: no stored password — pamv1 signs a short-lived certificate for your session). Since then, the things you are most likely to *notice*: a SQL statement can **pause mid-session** for a supervisor's decision (30) instead of the session dying; your session can be **refused outright** if recording is required but not configured (52c); certification and step-up decisions need the **approver** capability (39) and nobody may decide their own (46, 52c); recovery codes are now four groups of six (52e); and the **content of SFTP transfers may be recorded**, with a per-file size cap that refuses what crosses it (59). Newer still: where a first-class ITSM connector is configured, your change ticket must be in an accepted state, inside its change window, **and name you** (84); and a high risk score can **sign you out**, so your next action asks you to authenticate again (86). **Newest**: a live session can be **shared** with a second party — view-only or view-control — through the same two-person approval shape as an access request; join with a one-time token as your SSH username, or by an emailed QR link if you're outside the organization (116); and an admin can restrict your account to specific source networks — connecting from outside that range refuses the session (or the API call) with a clear reason rather than a silent hang (118); a periodic access request can now **recur** — set "recur every N days" when you file it, and once it's approved a fresh request is auto-filed each period, so you don't have to remember to re-ask, though each occurrence still needs its own approval (120); if you're still working when a credential checkout is about to expire, you (or an admin) can **extend** it up to a configured maximum instead of losing access mid-task (120); and a supervisor can now **pause** your live input without ending your session — you'll see a clear on-screen notice the moment it happens and again the moment it's lifted, so it never just looks like a hang (122); and you can now register a **hardware security key or your device's built-in authenticator** (Touch ID, Windows Hello, a YubiKey) as an alternative to a TOTP app — enter your username and password and leave the code blank, and your browser prompts you for your key (124); and the console now offers two extra dark color themes besides the original green — press **F2** to cycle green → amber → slate and back, a purely personal, on-this-browser choice (126). (Phase 128, authenticated account discovery, is an admin-only inventory tool — nothing changes in what you see or do.) And some PostgreSQL targets now use **Zero Standing Privilege** too (129, extending 22 beyond SSH): there is no stored database password either — pamv1 creates a fresh, one-time database login just for your session and removes it the moment you disconnect. You connect exactly as before. And if your site configures a command **allow-list** (131), a refused command means it wasn't on the approved list at all, not just that it matched a deny pattern — same "command blocked by policy" message either way. If your site enables **device-aware access** (133), a refusal reads as "your device failed its posture check" or "this device is not enrolled for your account" — the latter only applies if an admin has bound your account to a specific device; most operators never see either message. And if a credential you use is **DoubleLocked** (135), that changes nothing about connecting through the proxy — you still just connect; DoubleLock only affects someone directly revealing or checking out that credential's raw password, a separate admin-facing action. If you approve access requests, you can now delegate a single decision by **emailing someone a link** instead of them needing a pamv1 account — they see the request's details and click Approve or Deny, nothing happens just from opening the email (137). And every session now shows a small **watermark** naming who's connected and to what — an on-screen overlay for RDP/VNC, a one-time banner at the top of the output for SSH/database sessions — a passive reminder, not something you can turn off or that changes how you connect (137). If a target or credential you use lives in someone's **personal safe** (139), only that safe's own members can connect to or reveal it — an admin who isn't a member is refused too, unless specifically granted the override; if you own a personal safe, nothing changes about how you use it. You can now use **`ssh -L`** through your SSH session to reach another service on the same box you're connected to — a database, an internal web UI — without a second login; forwarding to any *other* host is refused (141). If your site enables **ICAP file-transfer scanning** (143), a file you upload or download over SFTP may be checked by an antivirus/DLP system after the transfer completes — you are not blocked or slowed down waiting for a verdict, but a flagged file is recorded in the audit trail for your admin to see; this is a detection tool, not something that stops a transfer from reaching you or the target. (Phase 145, file-attachment secrets, is mostly an admin-facing storage option — a license key or cert bundle vaulted the same way a password is; if you have `reveal_secret` and reveal one, you'll get its raw content back instead of a password, nothing else about revealing changes.) And if you have `reveal_secret`, you can now install a **browser extension** that fills a login form for you: ask an admin (or mint one yourself) for an extension token, paste it into the extension's settings along with your pamv1 server address, then map a site's address to a credential ID once — after that, a small key button appears next to that site's password field (147). The token the extension holds can only ever call the one reveal action; it cannot browse your vault, list targets, or do anything else in pamv1, and it expires on its own (ask your admin how long). (Phase 149, SCIM 2.0 provisioning, is an admin/IdP-integration concern — if your account was created or deprovisioned this way, it looks exactly like any other account being enabled or disabled; nothing changes in how you sign in or what you see.) (Phases 159–183 concern **AI-agent identities**, not yours: an agent can be suspended, expired or quarantined — and since 169 quarantining one also stops the sub-agents it delegated to — what an agent does is recorded and risk-scored the way your own activity always has been, an agent now sees only the targets it has a grant on, and a policy rule can finally name *which* agent it applies to. Nothing changes in how you sign in, connect, or what you see. **If you approve agent calls** (menu 20) there is one visible change: each parked call now shows a **DECIDE BY** deadline, after which it lapses and the agent is told the call failed — so an entry close to its deadline is the one to look at first. **If you approve agent calls**, each parked call also shows how many delegations it passed through — `direct`, or a hop count you can hover for the chain — so a call that reached you through three sub-agents no longer looks like one that came straight from the agent you know (183). **And if you review certification campaigns**, your queue now includes AI-agent identities alongside people (subject type `agent`): the question is whether that non-human identity should still exist and whether the human named beside it is really accountable for it. Revoking one stops the agent — it does not delete it — and an owner shown in red with a `?` matches no pamv1 account, which usually means a typo nobody has noticed.) An admin revoking your access still ends your live sessions immediately. See the [ROADMAP](../ROADMAP.md).

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
  signed in. This is the smoothest option when your org enabled it. If your
  organization uses **AD FS or another SAML identity provider** instead, the
  Sign On screen shows a second link, **Single sign-on (SAML)**
  (`/api/auth/saml/start`) — same experience, same landing (Phase 151).


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

**Or use a hardware key or your device's authenticator instead (Phase 124).**
If your organization has WebAuthn turned on, from the portal's MFA menu choose
*WebAuthn: manage keys*, then **F6** to register — your browser will prompt
you to touch your security key or unlock with Touch ID / Windows Hello /
similar. From then on, at sign-in, enter your username and password and
**leave the MFA code field blank**: your browser prompts you for your key on
its own, no code to type. You can register more than one key (say, a YubiKey
and your phone). You only ever need ONE second factor — TOTP or WebAuthn, not
both — so pick whichever fits how you work.

If your organization **requires MFA**, your first sign-in gives you a limited
session that can *only* set up a second factor — enroll and confirm **either**
TOTP or WebAuthn, then sign in again normally. That limited session can't open
any target session (SSH, WinRM, RDP **or** database) until you've completed
enrollment.

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
| **F2** | Cycle color theme (green / amber / slate) |
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
| 20 | Approve AI-agent tool calls (parked calls, with the arguments policy matched on, and the **DECIDE BY** deadline each one lapses at) | approver |
| 21 | In-session step-up decisions (paused SQL statements — these expire) | |
| 22 | Work with vendors & contract grants (register, approve, offboard, evidence) | |
| 23 | Work with operator SSH certificates (issued certs, revoke, KRL download) | |
| 24 | Identity blast radius (paste a graph, see escalation paths + remediation) | |
| 25 | Work with login sessions (see and revoke active password/SSO logins) | admin |
| 26 | Work with AI-agent keys (mint / revoke broker identities) | admin |
| 29 | Work with SCIM client keys (the token an IdP provisions users with) | admin |
| 30 | Browser-extension token (mint one for your own autofill extension) | reveal_secret |
| 31 | What can this subject reach? — every target a user or an AI agent stands to reach, and **why** each one (a grant, a role, a safe, an admin bypass, or nothing gating it at all) | read_audit |
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

# Join a session someone shared with you (an invite naming you, already
# approved) — the token IS your whole username; your own PAM token is still
# the password
ssh -p 2222 join:<token>@PAM_HOST

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
> subsystem is refused; you still get a shell). Your site may also **record the
> content** of transferred files (Phase 59) — the bytes you move are kept as
> evidence, encrypted, exactly like your session recording — and may enforce a
> **per-file size limit**: a transfer that hits it fails mid-file with
> "permission denied". Ask your admin if you need to upload and can't, or if a
> large transfer keeps failing at the same point. If your site also enables
> **ICAP AV/DLP scanning** (Phase 143), a completed transfer is separately
> submitted to an antivirus/DLP system — this never delays or blocks the
> transfer itself (the file is already where it's going by the time a verdict
> exists), it only adds to the audit trail if something is flagged.

> **A live session can be shared with someone else.** Request it from your
> session — view-only, or view-**control** if you want them typing too — and
> a *different* person has to approve it before it goes live, the same
> two-person shape as an access request. Another pamv1 user joins over SSH
> with a one-time token as their username (above); someone outside your
> organization is invited by email instead, with a QR code good for a short
> window and no account of their own needed.

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

### Connecting to a database (SQL Server)

`mssql` targets work the same way with **`sqlcmd`** (or any TDS client): the
username selects the credential and target, and your PAM token is the password.

```bash
# credential "sql_svc" on target "sql-01", database "orders"
sqlcmd -S PAM_HOST,1433 -U 'sql_svc@sql-01' -P "$PAM_TOKEN" -d orders -N -C
```

`-N` asks for an encrypted connection and `-C` trusts the proxy's certificate
(drop `-C` when it is signed by a CA your machine trusts). If your admin has
not configured TLS on the proxy, modern clients refuse to connect at all — that
is the client protecting your token, not a pamv1 fault; ask them to set it up.

A URL-style client needs the `@` percent-encoded as `%40`:

```
sqlserver://sql_svc%40sql-01:$PAM_TOKEN@PAM_HOST:1433?database=orders
```

Every statement is audited, including the ones your driver sends through
`sp_executesql`. **Windows/integrated authentication is not brokered** — use
SQL authentication.

### Connecting to a remote desktop (RDP or VNC)

For a target with the **RDP** or **VNC** protocol you don't need any client — the
desktop opens **inside the portal**. In *Work with Targets*, type option **`7`**
next to the target and press Enter. The green title bar shows which host you're
on; the Windows desktop renders in the browser. Press **`Ctrl+Alt+Q`** to
disconnect and return to the list.

As everywhere in pamv1, the password is injected for you — it reaches the RDP
broker, never your browser — and the session is audited (and may be watched live
by a supervisor). This needs your admin to have enabled RDP (a `guacd` broker);
if option 7 does nothing, the target isn't RDP or RDP isn't enabled.

Copy and paste through the session clipboard follow policy, and the policy can
be **stricter on some targets than others** — if paste (or the clipboard
entirely) doesn't work on one machine while it works elsewhere, that target is
deliberately locked down, not broken. What crosses the clipboard may also be
audited.

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
view-only pane as it happens (F12 stops watching). When the session ends —
finished or killed — the pane says **SESSION ENDED**; a quiet pane means a
quiet session, not a dead one. In a multi-replica deployment the list shows
**every** replica's sessions and the watch works wherever the session is
hosted (Phase 55 — the hosting server relays the output through the
database), so a 404 now honestly means the session is unknown or already
over. The same stream is available via the API —
`GET /api/sessions/{id}/stream` (Server-Sent Events). The watch — and a
refused watch — is audited (`session.monitor`; a cross-replica watch is
marked `via:relay`).

From that same live-watch pane, **F6** requests to share the session you're
watching — view-only or view-control — with someone else, and **F7** opens
the list of pending share requests for you to approve or deny (you can't
decide one you filed yourself — the same four-eyes rule as everywhere else).
Once approved, the pane's roster shows who has actually joined, with an
option to kick anyone who shouldn't be there anymore.

Two more review screens (both need audit-read):

- **Certification campaigns** (menu 17) — the periodic access review: each item
  is one grant; you (or an admin) certify it (keep) or revoke it (**the grant is
  deleted**). Auditors can read every campaign and its decisions as evidence;
  deciding an item needs the **approver** capability (`approve`) since Phase 39 — creating and closing a campaign is what needs a user-management role. You cannot certify a grant **you** created (four-eyes, Phase 46; revoking your own is still allowed), and a revoke now also terminates that user's live sessions to the affected targets.

  Three things you are likely to notice (Phases 68–70). A campaign is usually
  **scoped** — to one safe, or to everything one person holds — so what you are
  asked to review is finishable rather than the whole estate. Items may be
  **assigned to you**: press **F7** on menu 17 for *My Review Queue*, your
  pending items across every open campaign. And if the campaign has a due date
  you will be **reminded** through whatever alert channel your deployment uses,
  with the nudge naming who is still holding it up. Assignment routes the work; it
  is not a permission — anyone with `approve` can decide any item, and the trail
  records who actually did.
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
  (`session.playback`). A row of kind **`file`** is captured SFTP content
  (Phase 59): option `5` **downloads the transferred bytes** instead of
  replaying — reconstructed from the capture, with the same hash verdict.

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
| SSH: `pamv1: this invite was not issued to you` / `pamv1: this invite must be redeemed via its emailed link` | The `join:<token>` you used names someone else, or is an **external** invite — those redeem only through the emailed web link, never SSH. |
| SSH: `upstream connection failed` | pamv1 reached your token fine, but couldn't reach the target (down, or bad vaulted credential). Tell your admin. |
| `too many attempts; try again shortly` | Repeated failed sign-ins from your address were rate-limited. Wait a minute and retry with the correct token. |
| `command blocked by policy` (SSH exec / WinRM / SQL) | That specific command matched a command-control deny rule and was refused before reaching the target. The session continues; run something else or ask your admin. |
| SSH/psql: `connection requires an approved access request` right after a session that worked | Your approval was **one-time** and the previous connection consumed it. File a new access request. |
| The same message on a request that is still approved and in-window, at a site that uses change tickets | The **change ticket** on your request is no longer accepted by the ITSM — usually the change was closed or cancelled, drifted outside its change window, or (with a ServiceNow/Jira connector) **does not name you**. Get it fixed or re-opened, or file a new request with a current ticket. Your approval was not spent by the refusal. |
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
| An SFTP transfer fails with "permission denied" **partway through a large file** | Your site records transfer content with a per-file size cap, and the file crossed it. The bytes up to the cap moved; the rest were refused. Split the file or ask your admin about the limit |
| `session limit reached` (or HTTP 429) | You are at your concurrent-session cap. Close one and retry |
| `vendor access requires an approved, in-window contract grant for this account` | You are a third-party user and your contract grant has not been approved, or its window has closed |

Also: leaving the SSH or `psql` password prompt idle now drops the connection
after **120 seconds** with no message. Reconnect and type promptly — it is a
guard against connections that open and never authenticate, not a fault.

## 8. Change log

| Date | Change |
|---|---|
| 2026-08-15 | **Phase 143 — SFTP transfers may now be scanned by an antivirus/DLP system.** If your site enables it, a file you upload or download is checked after the transfer completes — this never slows down or blocks the transfer itself, it only adds a flagged-file entry to the audit trail if something is found. §7 |
| 2026-08-14 | **Phase 131 — some sites now restrict you to an approved list of commands.** If your site configures a command allow-list, an SSH/WinRM/database command not on that list is refused the same way a denylisted one is — "command blocked by policy." Ask your admin what's on the list if a command you expect to work doesn't. §9.4 (ADMIN-GUIDE) |
| 2026-08-14 | **Phase 129 — some database connections now use Zero Standing Privilege.** If your site enables it on a PostgreSQL target, there's no stored database password for that account at all — pamv1 creates a brand-new, one-time login the instant you connect and removes it the instant you disconnect. You connect exactly the same way (`psql ... user=<cred>@<target>`, your PAM token as the password); nothing in your workflow changes. §"Connecting to a database (PostgreSQL)" |
| 2026-08-14 | **Phase 126 — pick a color theme.** Press **F2** anywhere in the portal (even on the Sign On screen) to cycle the console between the original green, an amber-phosphor look, and a cooler low-glare slate. It's remembered on this browser only — nothing is sent to the server, and it doesn't affect anyone else. §4 |
| 2026-08-13 | **Phase 116 — share a live session with someone else.** Request it from your session (view-only or view-control); a *different* person approves it before it goes live — same two-person shape as an access request. Another pamv1 user joins over SSH as `join:<token>` (their own PAM token is still the password); someone outside your organization gets emailed a QR code instead, good for a short window, no account needed. **F6**/**F7** on the live-watch pane request/decide; its roster shows who's actually joined. §5, §6, §7 |
| 2026-08-09 | **Phase 95 — documentation currency pass** (nothing changed in the product today; this row catches the guide up on what already had). Since Phase 84, a site using a ServiceNow/Jira connector accepts your ticket only if it is in an accepted state, inside its change window and **names you**. Since Phase 86, a high risk score can **sign you out** so your next action re-authenticates — less drastic than losing your live sessions. Since Phase 92, a read-only SFTP session also refuses link/lock operations. §7 |
| 2026-08-02 | **Phase 60 — your change ticket is checked again when you connect.** If your site gates access on ITSM tickets, the ticket on your approved request is re-checked at the moment you use it, not only when you filed it. A change that has since been cancelled or closed means the connection is refused — ask for the change to be re-opened, or file a new request. Your approval is **not** used up by such a refusal. §7 |
| 2026-08-01 | **Phase 59 — file transfers may be recorded in full, and may hit a size limit.** If your site enables content capture, the bytes of every file you move over SFTP are kept as encrypted evidence alongside your session recording, and auditors can download them from menu 19 (kind `file`). A per-file cap, when set, makes a transfer fail with "permission denied" partway — see §7. §3, §4 |
| 2026-07-31 | **Some targets now need more than one approver.** If a target belongs to a safe with dual control, your access request stays *pending* until the required number of **different** people have approved it — the screen shows the progress (`n/m`). Nothing changes in how you file the request. |
| 2026-07-31 | **Phase 56 — a paused statement can be decided from any replica.** Nothing changes in what you see: your statement pauses, then runs or is refused. What changed is behind the curtain — the supervisor no longer has to reach the exact replica running your session to decide it, so decisions should land faster on multi-replica deployments. Nobody may approve their own paused statement, from anywhere. |
| 2026-07-29 | **Option 7 now opens VNC desktops too.** On *Work with Targets*, type **7** next to a `vnc` target and it renders in the portal exactly like an RDP one — same key, same `Ctrl+Alt+Q` to disconnect, same rule that the password is injected for you and never reaches your browser. If copy/paste does not work, the clipboard policy for that target says so. |
| 2026-07-29 | **SQL Server databases can now be reached through pamv1** (Phase 53): `sqlcmd -S pam,1433 -U '<cred>@<target>' -P "$PAM_TOKEN"`, same rules as PostgreSQL — your token is the password, you never learn the database one, and every statement is audited. §"Connecting to a database (SQL Server)" |
| 2026-07-29 | **Phase 55 — the session list and live watch now cover the whole cluster.** On a multi-replica deployment, *Work with Active Sessions* shows every replica's sessions and option 5 watches a session wherever it is hosted, so a 404 honestly means "unknown or already ended" — the "hosted elsewhere" caveat below is history. §"Watching a session" |
| 2026-07-29 | **Watch-pane fixes**: lines no longer end in a stray `\r`; a refused command watched live now says *why* it was refused instead of looking like it ran silently; and the 404 for a non-live session is replica-honest — on a multi-replica deployment it can mean "hosted elsewhere", not "ended". §"Watching a session" |
| 2026-07-29 | **The live watch pane now reports SESSION ENDED** the moment the watched session finishes or is killed — a quiet pane means a quiet session, not a dead one. Watching a session that is already over says so (404) instead of showing an empty stream. §"Watching a session" |
| 2026-07-29 | **RDP clipboard can differ per target** (Phase 33 follow-on): if copy/paste is blocked on one machine while it works elsewhere, that target is deliberately locked down — the per-target policy is always at least as strict as the global one. Admins set it on *Add/Change Target*. §"Connecting to a Windows desktop" |
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
| 2026-08-17 | Phase 157: if your administrator enabled it, a short **forensics** artifact is stored after each of your interactive SSH sessions — the target's own record of what actually ran, visible in *Work with Recordings* (menu 19) beside the session recording. Nothing changes about how you connect; it is an after-the-fact record, and it exists because a recording shows what was typed, which is not always what ran |
| 2026-08-16 | Phase 155: **Kubernetes clusters** — if your administrator added one as a target, *Work with Targets* → option **6** runs one operation against it (`get`, `logs`, `apply`, `delete`) and shows the cluster's answer. You never hold the cluster credential, the operation is recorded like any other, and what you are allowed to do inside the cluster is decided by the cluster's own RBAC — a refusal there comes back as its own `403`. Interactive `kubectl exec` is not offered |
| 2026-08-16 | Phase 153: nothing changes for you — a target your administrator reaches through an outbound-only endpoint agent (a NAT'd or firewalled machine) is opened exactly like any other (`ssh -p 2222 root@<target>@pam-host`); if the agent is offline the connect fails with "upstream connection failed" and your administrator sees why on menu 28 |
| 2026-08-16 | Phase 151: a second **Single sign-on (SAML)** link on Sign On, for AD FS / SAML identity providers — same experience as the OIDC one |
| 2026-07-18 | Phase 3b: OIDC single sign-on option on Sign On |
| 2026-07-18 | Phase 3b: recovery codes + enforce-MFA (enrollment-only first sign-in) |
| 2026-07-28 | Phase 52e: recovery codes are longer — four groups of six (`abcdef-ghijkl-mnopqr-stuvwx`) instead of two groups of five. Codes you already hold keep working; generate a new set to get the longer ones |
| 2026-07-18 | Phase 3b: TOTP MFA (enroll/confirm, MFA code on Sign On) |
| 2026-07-18 | Phase 3b: Active Directory login (username + password → session token) added to Sign On |
| 2026-07-18 | Initial user guide (Phase 3a): roles, tokens, portal Sign On, connecting via the SSH proxy, audit review |

*Questions an admin should answer live in the [Administrator Guide](ADMIN-GUIDE.md).*
