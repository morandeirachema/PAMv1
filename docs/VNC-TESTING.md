# pamv1 — VNC viewer: testing procedure

> 🟢 **Living document** — updated in the same change as the code. Update
> whenever the VNC path (the guacd handshake, the tunnel prelude, the token
> endpoint, or the in-portal viewer) changes.
>
> Last updated: 2026-08-25 · Reflects: Phases 0–204 (161–183 are AI-agent-broker phases and change nothing a viewer renders or a test procedure touches; **Phase 137 is the first phase since 55 to change the rendered viewer**: a small `.rdpwatermark` overlay — operator, target, start time — is appended as a sibling of the Guacamole canvas, client-side, `pointer-events: none`; see §3, check 9. Nothing else since 55 changes the VNC path or how it is exercised — Phase 116's session-sharing is SSH-only and does not touch guacd or the viewer. Phase 118's CIDR allowlist reaches this path indirectly, same as RDP — `POST /api/vnc-token` goes through the same `authz` middleware — but doesn't change this testing procedure. Phase 120 doesn't touch this path at all. Phase 122's suspend/resume is SSH-only too and doesn't touch this path either. Phase 124's WebAuthn is a login-time change only and likewise doesn't touch this path. Phase 126's theme toggle doesn't touch this path either — it's a global console preference, not per-protocol. Phase 128's account discovery is SSH/WinRM only and doesn't touch VNC either. Phase 129's Zero Standing Privilege is PostgreSQL-only and doesn't touch VNC either. Phase 131's command allow-listing doesn't touch this path either — VNC is GUI-only pixel streaming, no discrete command surface for cmdguard to see. Phase 133's device-aware access control reaches this path indirectly, same as Phase 118 — `POST /api/vnc-token` goes through the same `authz` middleware every other route does — but doesn't change this testing procedure, since the demo setup configures neither `PAM_POSTURE_ATTEST_URL` nor `PAM_DEVICE_HEADER`. Phase 135's DoubleLock doesn't touch this path either — it gates the credential-management reveal/checkout endpoints, not a connect path. Phase 139's personal-safe check reaches this path more directly than 118/133 did — `viewer_handlers.go` computes `EffectiveSafePersonal` and passes it to the exact same `auth.CanConnectTarget` call the connect gates use — but still doesn't change this testing procedure, since the demo setup places `demo-vnc` in no safe at all. Phase 141's port-forwarding doesn't touch this path either — it's a new SSH channel type on the `:2222` proxy; VNC has no SSH channels of any kind. Phase 143's ICAP scanning doesn't touch this path either — it hooks the SFTP subsystem's file-finalization step; VNC has no file-transfer mechanism of any kind, SFTP or otherwise. Phase 145's file-attachment secrets doesn't touch this path either — it's a `secret_type` value on `POST /api/credentials`; how a credential's secret is stored has nothing to do with how the VNC viewer connects with it. Phase 147's browser-extension autofill doesn't touch this path either — it calls only `POST /api/credentials/{id}/reveal`, never `POST /api/vnc-token` or the VNC tunnel, and its `ExtensionOnly` token is refused on both. Phase 149's SCIM provisioning doesn't touch this path either — it manages `store.User` rows over `/scim/v2/Users`; a SCIM key cannot mint a VNC token or open the tunnel, and how an operator's account was provisioned has nothing to do with how the VNC viewer connects). (VNC shipped in 54).

This is the procedure to verify pamv1's **VNC function** end to end: an operator
opens a VNC target from the 5250 portal, the credential is injected server-side
at the guacd handshake, and the browser only ever receives the rendered screen.

It is the sibling of [RDP-TESTING.md](RDP-TESTING.md), and deliberately so: both
viewers run the **same** tunnel code (`internal/api/viewer_handlers.go`), so a
difference in behaviour between them is a bug, not a feature.

## 1. What the VNC path is

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser (portal)
    participant S as pam-server
    participant V as Vault
    participant G as guacd
    participant T as VNC target (:5900)

    B->>S: POST /api/vnc-token (X-API-Key)
    S-->>B: short-lived token (TTL 60s)
    B->>S: WS /api/targets/{id}/vnc?token=…
    S->>S: authz — CapConnect + grants + approval + session cap
    S->>V: decrypt credential (JIT)
    S->>G: handshake select vnc / size / connect (secret injected)
    G->>T: VNC connect :5900 (RFB, plaintext)
    G-->>S: ready + render stream
    S-->>B: rendered pixels only
```

The operator never receives the VNC password, and the browser never sends it.

## 2. The fastest check: the bundled demo stack

A real TigerVNC desktop, guacd and pam-server, with the target seeded for you:

```bash
cd deploy/docker
docker compose -f docker-compose.vnc-demo.yml up --build
# → http://localhost:8080
#   Sign On: leave Password blank, enter the access token (demo-api-key-pamv1)
#   Work with Targets → type 7 next to "demo-vnc" → Enter
#   → an XFCE desktop renders in the portal. Ctrl+Alt+Q disconnects.
```

**Demo only** — throwaway keys and a well-known VNC password. Never deploy it.

Note the demo password is eight characters (`DemoVnc1`). That is not a
coincidence: classic VNC authentication uses the password as a **56-bit DES
key**, so every implementation truncates it to 8 characters. See
[PROTOCOLS-AND-CRYPTO.md §3.5](PROTOCOLS-AND-CRYPTO.md).

## 3. What to verify

| # | Check | How | Expected |
|---|---|---|---|
| 1 | The desktop renders | Option **7** on the `demo-vnc` target | XFCE paints in the portal; `Ctrl+Alt+Q` closes it |
| 2 | The credential never reaches the browser | Browser devtools → WS frames | Only Guacamole render instructions; no password anywhere |
| 3 | The session is audited | *Work with Audit* (or `GET /api/audit`) | `vnc.token`, then `vnc.connect` with `target:`, `cred_user:` and `clipboard:`, then `vnc.end` |
| 4 | It is a live session | *Work with Active Sessions* | One entry, protocol `vnc`, killable — a kill closes the viewer |
| 5 | The clipboard gate works | Restart with `PAM_RDP_CLIPBOARD=deny` (it gates VNC too) | Copy/paste between browser and desktop does nothing |
| 6 | The gate is auditable | With `PAM_RDP_CLIPBOARD_AUDIT=meta` and the policy back to `allow` | Copying text produces an `rdp.clipboard`-style `vnc.clipboard` event with direction, size and SHA-256 |
| 7 | Recording is enforced | Restart with `PAM_REQUIRE_RECORDING=true` and no `PAM_GUACD_RECORDING_PATH` | Option 7 refuses; `vnc.refused reason:recording-required` |
| 8 | An unenforceable policy refuses | A guacd too old to advertise `disable-copy`, with a non-`allow` policy | Session refused; `vnc.refused reason:clipboard-unenforceable` naming the missing parameter |
| 9 | A watermark overlay appears (Phase 137) | Option **7** on any VNC target | A small translucent label over the desktop names the operator, target and start time; `pointer-events: none`, nothing to configure |

## 4. What the automated tests already cover

`internal/api/vnc_ws_test.go` proves, against a fake guacd advertising the real
VNC argument list (from guacamole-server's `GUAC_VNC_CLIENT_ARGS`):

- guacd is asked to `select vnc`, with the target's host and port;
- the **vaulted secret is injected** into guacd's handshake and never sent by the
  browser;
- `enable-sftp=false` reaches the wire — VNC's file-transfer channel is off;
- a `deny` clipboard policy arrives as `disable-copy`/`disable-paste`;
- a policy guacd **cannot** enforce refuses the session and audits why;
- a VNC viewer token is refused by every non-tunnel endpoint and cannot re-mint.

What tests cannot cover is the rendered pixels against every VNC server
implementation — hence §2.

## 5. Related reading

- [RDP-TESTING.md](RDP-TESTING.md) — the same procedure for RDP.
- [PROTOCOLS-AND-CRYPTO.md](PROTOCOLS-AND-CRYPTO.md) — §3.5 on why VNC is
  brokered rather than exposed (plaintext RFB, DES-truncated password, no server
  authentication).
- [PORTS-AND-FLOWS.md](PORTS-AND-FLOWS.md) — flow **E4c**, guacd → VNC target on
  5900.

## 6. Change log

| Date | Change |
|---|---|
| 2026-08-15 | Phase 137: check 9 — a watermark overlay now renders over every VNC session. |
| 2026-07-29 | First version, with Phase 54: the demo stack, the eight checks, and what the automated tests already prove. |
