# pamv1 Autofill (browser extension)

A Manifest V3 extension (Chrome, Edge, and other Chromium-based browsers;
Firefox works unmodified since it also supports MV3) that fills a login
form from a credential vaulted in pamv1 — Delinea's Web Password Filler /
BeyondTrust's Workforce Passwords equivalent (Phase 147).

## What it does, and does not do

- Calls the *existing*, already-audited `POST /api/credentials/{id}/reveal`
  — the exact same route the portal itself uses. No new secrets-disclosure
  surface is introduced anywhere in pamv1 to support this.
- Authenticates with a narrowly-scoped **extension token**
  (`POST /api/extension-token`, minted from an already-signed-in session)
  that the server refuses on every route except that one reveal endpoint —
  see [ADMIN-GUIDE.md §6](../docs/ADMIN-GUIDE.md) and
  [ROADMAP.md Phase 147](../ROADMAP.md). A copy of this token pulled from
  the extension's local storage is useless anywhere else against the API.
- **V1 scope is autofill only**: it reads a vaulted secret and fills a
  form. It never captures a password you type, never writes anything back
  to pamv1, and never sends page content anywhere.
- It has **no way to browse your vault** — it can only reveal a specific
  credential ID you give it, one hostname at a time, in Settings. There is
  no "discover the right credential for this site" feature in v1.

## Setup

1. **Load the extension.** In Chrome/Edge: `chrome://extensions` → enable
   *Developer mode* → *Load unpacked* → select this `extension/` directory.
2. **Mint a token.** While signed in to pamv1 with an identity that holds
   `reveal_secret`, call:
   ```bash
   curl -H "X-API-Key: $PAM_API_KEY_OR_USER_TOKEN" -X POST https://pam.example.com/api/extension-token
   # → {"token":"...", "expires_at":"..."}
   ```
   (A future release may add a portal button for this; today it is one API
   call, the same way an RDP/VNC viewer token is minted.)
3. **Configure the extension.** Click the toolbar icon → it opens the
   settings page. Enter your pamv1 server URL and paste the token from
   step 2.
4. **Map a site to a credential.** Still in settings, add the hostname you
   want autofill on (e.g. `intranet.example.com`) and the numeric
   credential ID (visible in the portal's credential list, or via
   `GET /api/credentials?target_id=...`).
5. Visit the mapped site. A small **🔑 pamv1** button appears next to any
   password field found on the page; click it to fill the username and
   password.

## Token lifetime

An extension token expires on its own
(`PAM_EXTENSION_TOKEN_TTL_HOURS`, default 24h — ask your pamv1
administrator what your site has configured) and is not renewable in
place; mint a new one and paste it into settings when the old one stops
working (reveal will return 401).

## Files

| File | Purpose |
|---|---|
| `manifest.json` | MV3 manifest — permissions, content script registration |
| `background.js` | Service worker; the only file that calls the pamv1 API |
| `content.js` | Detects password fields on a mapped site and offers the fill button |
| `options.html` / `options.js` | Settings page: server URL, token, site→credential mappings |

All state (server URL, token, site mappings) lives in the browser's own
`chrome.storage.local` for this extension — nothing is written to disk
outside the browser's own extension-storage sandbox, and nothing syncs
anywhere pamv1 does not control.
