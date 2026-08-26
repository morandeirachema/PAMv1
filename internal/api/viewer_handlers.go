package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/guacd"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// rdpTokenTTL bounds the lifetime of a browser viewer WebSocket token. It is
// short because the token travels in the WS URL (browsers cannot set request
// headers on a WebSocket handshake), where it can leak via proxy/access logs.
const rdpTokenTTL = 60 * time.Second

// viewerProto describes one guacd-brokered graphical protocol. RDP and VNC reach
// a target through the same chokepoint and the same authorization gates, so they
// share one tunnel implementation and differ only in these few values. Keeping
// the gates in ONE function is deliberate: duplicating them is how two paths that
// are supposed to be equivalent quietly stop being (Phase 52c was a whole pass
// fixing gates that had drifted apart).
type viewerProto struct {
	name        string // target protocol, audit prefix and session-registry kind
	label       string // human-facing name for error messages
	defaultPort int
	scope       string // session scope minted for this viewer's tunnel token
	// extra builds the guacd parameters this protocol needs beyond the common
	// ones, given the effective clipboard policy.
	extra func(s *Server, clipboard string) map[string]string
	// gateArgs are the guacd parameters this protocol enforces the clipboard
	// policy through. If guacd does not advertise them, the policy cannot be
	// applied and a non-permissive one must refuse rather than run ungated.
	gateArgs []string
}

var (
	protoRDP = viewerProto{
		name: "rdp", label: "RDP", defaultPort: 3389, scope: auth.SessionScopeRDP,
		extra: func(s *Server, clipboard string) map[string]string {
			return rdpExtra(s.guacdRDPSecurity, s.guacdIgnoreCert, clipboard)
		},
		gateArgs: []string{"disable-copy", "disable-paste"},
	}
	protoVNC = viewerProto{
		name: "vnc", label: "VNC", defaultPort: 5900, scope: auth.SessionScopeVNC,
		extra: func(_ *Server, clipboard string) map[string]string {
			return vncExtra(clipboard)
		},
		gateArgs: []string{"disable-copy", "disable-paste"},
	}
)

// rdpToken mints a short-lived session token for the in-portal RDP viewer.
func (s *Server) rdpToken(w http.ResponseWriter, r *http.Request) {
	s.viewerToken(w, r, protoRDP)
}

// vncToken mints a short-lived session token for the in-portal VNC viewer.
func (s *Server) vncToken(w http.ResponseWriter, r *http.Request) {
	s.viewerToken(w, r, protoVNC)
}

// viewerToken mints a short-lived session token for an in-portal graphical
// viewer. The caller is already authenticated (X-API-Key) and holds CapConnect;
// the minted token inherits their identity but expires within rdpTokenTTL, and
// the tunnel re-checks every authorization when the WebSocket connects. This
// keeps the operator's long-lived token out of the WS URL. Requires CapConnect.
func (s *Server) viewerToken(w http.ResponseWriter, r *http.Request, proto viewerProto) {
	if s.guacdAddr == "" {
		writeError(w, http.StatusNotFound, proto.label+" is not configured")
		return
	}
	p := principalFrom(r.Context())
	// Mint a tunnel-scoped token: it resolves to a TunnelOnly principal the API
	// middleware refuses, so a copy leaked from the WS URL is useless elsewhere and
	// cannot re-mint. A break-glass caller keeps the break-glass scope so the tunnel
	// still fires the loud audit and bypasses the approval gate as break-glass must
	// (break-glass is already full-admin, so this adds no exposure).
	scope := proto.scope
	if p.BreakGlass {
		scope = auth.SessionScopeBreakGlass
	}
	token, sess, err := s.issueSessionTTL(r.Context(), p, scope, rdpTokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not mint "+proto.label+" token")
		return
	}
	s.audit(r.Context(), proto.name+".token", "ttl:"+rdpTokenTTL.String())
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expires_at": sess.ExpiresAt})
}

// rdpTunnel bridges a browser WebSocket to a guacd RDP session.
func (s *Server) rdpTunnel(w http.ResponseWriter, r *http.Request) {
	s.viewerTunnel(w, r, protoRDP)
}

// vncTunnel bridges a browser WebSocket to a guacd VNC session.
func (s *Server) vncTunnel(w http.ResponseWriter, r *http.Request) {
	s.viewerTunnel(w, r, protoVNC)
}

// viewerTunnel bridges a browser WebSocket to a guacd session for a graphical
// target (RDP or VNC). The credential is decrypted just-in-time and injected into
// the guacd handshake — it reaches guacd (which drives the remote protocol) but
// never the browser, which only receives the rendered display. Requires
// CapConnect.
//
// The token is read from the query string because browsers cannot set custom
// headers on a WebSocket handshake; prefer a short-lived session token.
func (s *Server) viewerTunnel(w http.ResponseWriter, r *http.Request, proto viewerProto) {
	if s.guacdAddr == "" {
		writeError(w, http.StatusNotFound, proto.label+" is not configured")
		return
	}
	principal, err := s.resolver.Resolve(r.Context(), r.URL.Query().Get("token"))
	if err != nil {
		// Route the failure through authFailed, exactly as the authz middleware
		// does. This handler resolves its own principal, and for a while that
		// meant it was the ONE bearer surface with neither per-IP throttling nor
		// an api.auth_failed record — so guessing tunnel tokens here was
		// unthrottled and invisible to the risk engine and the SIEM forwarder,
		// while the same guessing against /api/* was both slowed and recorded.
		s.authFailed(w, r, proto.name, "invalid or missing token")
		return
	}
	// Resolving its own principal also means this handler must reproduce the rest
	// of what the middleware does: the loud break-glass audit/alert, and an
	// authz.denied record for every refusal. A denial that leaves no trace is
	// worse here than elsewhere, because this path ends in a live desktop.
	setActor(r.Context(), principal.Name)
	r = r.WithContext(withPrincipal(r.Context(), principal))
	s.noteBreakGlass(r.Context(), principal, r)
	// One shared scope test, not a hand-rolled subset. Until the 2026-08-26
	// audit this handler checked EnrollOnly and nothing else, so an mfa_pending
	// token (password verified, WebAuthn NOT yet verified) and a browser-extension
	// token — both refused by every proxy and by the API middleware — opened a live
	// desktop here. This path ends in a decrypted credential inside a Windows
	// session; it cannot be the one door with a shorter checklist than the rest.
	// The tunnel legitimately serves TunnelOnly tokens, so that is the one narrow
	// scope MayOpenSession is told to allow through.
	if !principal.MayOpenSession(auth.ScopeTunnelOnly) {
		reason, msg := "narrow-scoped-token", "this token cannot open a "+proto.label+" session"
		switch principal.NarrowScope() {
		case auth.ScopeEnrollOnly:
			reason, msg = "mfa-enrollment-incomplete", "complete MFA enrollment to continue"
		case auth.ScopeMFAPending:
			reason, msg = "mfa-webauthn-pending", "complete WebAuthn sign-in first"
		case auth.ScopeExtensionOnly:
			reason, msg = "extension-scoped-token", "a browser-extension token cannot open a "+proto.label+" session"
		}
		s.audit(r.Context(), "authz.denied", r.Method+" "+r.URL.Path+" reason:"+reason)
		writeError(w, http.StatusForbidden, msg)
		return
	}
	// The same three gates the authz middleware runs between the scope test
	// and the capability test (IP allowlist, device, posture) — absent here
	// until the 2026-08-27 audit; see sourceGates.
	if reason, msg := s.sourceGates(r.Context(), principal, r); reason != "" {
		s.audit(r.Context(), "authz.denied", r.Method+" "+r.URL.Path+" reason:"+reason)
		writeError(w, http.StatusForbidden, msg)
		return
	}
	if !principal.Can(auth.CapConnect) {
		s.log.Warn("authorization denied", "actor", principal.Name, "role", string(principal.Role),
			"method", r.Method, "path", r.URL.Path)
		s.audit(r.Context(), "authz.denied", r.Method+" "+r.URL.Path+" role:"+string(principal.Role))
		writeError(w, http.StatusForbidden, "your role does not permit "+proto.label+" access")
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	target, err := s.store.GetTarget(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	if target.Protocol != proto.name {
		writeError(w, http.StatusUnprocessableEntity, "target protocol is not "+proto.name)
		return
	}
	if !s.protocolAllowed(proto.name) {
		writeError(w, http.StatusForbidden, proto.name+" is not allowed by policy")
		return
	}
	grants, err := s.store.EffectiveTargetGrants(r.Context(), target.ID)
	if err != nil {
		storeError(w, err)
		return
	}
	personal, err := store.EffectiveSafePersonal(r.Context(), s.store, target)
	if err != nil {
		storeError(w, err)
		return
	}
	if !auth.CanConnectTarget(principal, grants, target.SafeID != nil, personal, s.rt().ungated) {
		writeError(w, http.StatusForbidden, "not authorized for this target")
		return
	}
	// Loud, mirroring authorizedForTarget's own audit (Phase 139).
	if principal.PersonalOverrideUsed(personal) {
		s.audit(r.Context(), "safe.personal_override_used", "target:"+target.Name)
	}
	needsApproval, aperr := s.requireApprovalFor(r.Context(), target)
	if aperr != nil {
		storeError(w, aperr)
		return
	}
	if needsApproval && !principal.BreakGlass {
		// Connect-time approval gate: a single-use approval is consumed by this
		// very connection (Phase 26), so it cannot admit a second viewer
		// session, and the admitting request's ITSM ticket is re-checked here
		// rather than trusted from when the request was filed (Phase 60).
		actx := withPrincipal(r.Context(), principal)
		claim, aerr := s.claimApproval(actx, principal.Name, target)
		if aerr != nil {
			storeError(w, aerr)
			return
		}
		if !claim.OK {
			reason := "approval-required"
			if claim.TicketErr != nil {
				reason = "ticket-not-valid"
			}
			s.audit(actx, "access.denied", "target:"+target.Name+" reason:"+reason)
			writeError(w, http.StatusForbidden, "connection requires an approved access request")
			return
		}
	}
	creds, err := s.store.ListCredentials(r.Context(), target.ID, 0, 0)
	if err != nil {
		storeError(w, err)
		return
	}
	if len(creds) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "target has no credential")
		return
	}
	cred := creds[0]
	// Vendor contract gate (Phase 29): a vendor reaches the target only within an
	// active contract grant authorizing the login account (the credential username).
	if isVendor, allowed, verr := s.store.VendorSessionAllowed(r.Context(), principal.Name, target.Name, cred.Username, time.Now()); verr != nil {
		storeError(w, verr)
		return
	} else if isVendor && !allowed {
		s.audit(withPrincipal(r.Context(), principal), "access.denied", "target:"+target.Name+" reason:vendor-contract")
		writeError(w, http.StatusForbidden, "vendor access requires an approved, in-window contract grant for this account")
		return
	}
	// Enforce the concurrent-session caps before decrypting a secret, as the SSH and
	// PostgreSQL proxies do — otherwise a connect-capable user could open unbounded
	// memory-heavy RDP sessions past PAM_MAX_SESSIONS_PER_USER / _TOTAL.
	if s.sessions != nil && !s.sessions.AllowNew(principal.Name) {
		s.audit(withPrincipal(r.Context(), principal), "session.denied", "target:"+target.Name+" reason:session-limit")
		writeError(w, http.StatusTooManyRequests, "session limit reached")
		return
	}
	secret, err := s.vault.Decrypt(r.Context(), cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		s.audit(withPrincipal(r.Context(), principal), "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%s op:%s", cred.ID, target.Name, proto.name))
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}

	// Cancelable so a kill (or the handler returning) unblocks both bridge pumps:
	// they read/write the WebSocket with this ctx, and closing gconn alone does not
	// unblock a pump parked in ws.Read/ws.Write on a stalled browser.
	ctx, cancel := context.WithCancel(withPrincipal(r.Context(), principal))
	defer cancel()
	port := target.Port
	if port == 0 {
		port = proto.defaultPort
	}
	// PAM_REQUIRE_RECORDING covers this path too now. guacd writes the recording,
	// so "can we record?" here means "is a recording path configured?" — checked
	// before the credential is used and before a desktop exists to watch.
	if s.recordingRequired(s.guacdRecordingPath) {
		s.audit(ctx, proto.name+".refused", "target:"+target.Name+" reason:recording-required")
		writeError(w, http.StatusServiceUnavailable, "recording is required but not configured for "+proto.label)
		return
	}
	var recName string
	if s.guacdRecordingPath != "" {
		recName = fmt.Sprintf("%d_%s_%s", time.Now().UnixNano(), sanitizeName(target.Name), sanitizeName(principal.Name))
	}
	// Per-target clipboard tightening (Phase 33 follow-on): the effective policy
	// is the stricter of the global and this target's override, computed once
	// and used identically by the guacd gate, the connect audit and the
	// transfer watcher — three views of one decision.
	clipMode := strictestClipboard(s.rdpClipboard, target.RDPClipboard)
	clipAudit := strictestClipAudit(s.rdpClipAudit, target.RDPClipboardAudit)

	gconn, err := guacd.Connect(ctx, s.guacdAddr, guacd.Params{
		Protocol: proto.name, Hostname: target.Host, Port: strconv.Itoa(port),
		Username: cred.Username, Password: secret,
		Width:         clampDim(atoiOr(r.URL.Query().Get("width"), 1024)),
		Height:        clampDim(atoiOr(r.URL.Query().Get("height"), 768)),
		RecordingPath: s.guacdRecordingPath,
		RecordingName: recName,
		Extra:         proto.extra(s, clipMode),
	})
	if err != nil {
		s.log.Error("viewer connect failed", "protocol", proto.name, "target", target.Name, "err", err)
		s.audit(ctx, proto.name+".error", "target:"+target.Name+" error:"+err.Error())
		writeError(w, http.StatusBadGateway, proto.name+" connection failed")
		return
	}
	defer gconn.Close()

	// A clipboard policy is enforced by guacd, through parameters guacd only
	// applies if it advertised them — an unadvertised parameter is dropped, not
	// refused. So a guacd that cannot gate the clipboard would render an ungated
	// desktop while the portal showed the policy as in force. Refuse instead: a
	// control that silently does nothing is worse than one that is off.
	if clipMode != "allow" {
		for _, arg := range proto.gateArgs {
			if gconn.Supports(arg) {
				continue
			}
			s.log.Error("viewer session refused: guacd cannot enforce the clipboard policy",
				"protocol", proto.name, "target", target.Name, "missing_param", arg, "policy", clipMode)
			s.audit(ctx, proto.name+".refused",
				"target:"+target.Name+" reason:clipboard-unenforceable clipboard:"+clipMode+" missing:"+arg)
			writeError(w, http.StatusBadGateway,
				"guacd cannot enforce the configured clipboard policy for "+proto.label)
			return
		}
	}

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		return // Accept already wrote the response
	}
	defer ws.Close(websocket.StatusNormalClosure, "")

	// Fail CLOSED on the session-start audit, as both session proxies do: a
	// privileged desktop that leaves no durable record of having been opened is
	// exactly what this system exists to prevent. Best-effort was the odd one out
	// here, not the norm.
	if err := s.auditAs(ctx, actorFrom(ctx), proto.name+".connect",
		"target:"+target.Name+" cred_user:"+cred.Username+" recording:"+recName+" clipboard:"+clipMode); err != nil {
		s.log.Error("viewer session refused: audit unavailable", "protocol", proto.name, "target", target.Name, "err", err)
		ws.Close(websocket.StatusInternalError, "audit log unavailable")
		return
	}
	defer s.audit(ctx, proto.name+".end", "target:"+target.Name)
	s.log.Info("viewer session", "protocol", proto.name, "actor", principal.Name, "target", target.Name)

	if s.sessions != nil {
		sid := s.sessions.Register(session.Info{
			Actor: principal.Name, Target: target.Name, Protocol: proto.name, Remote: r.RemoteAddr, Started: time.Now(),
		}, func() { cancel(); gconn.Close() })
		defer s.sessions.Remove(sid)
	}

	// guacamole-common-js's tunnel needs an internal UUID instruction to consider
	// the tunnel open, then the client waits for `ready` to reach the CONNECTED
	// state. The server-side handshake already consumed guacd's own `ready` to
	// learn gconn.ID, so synthesize both here — matching what a real Guacamole
	// servlet relays — before piping guacd's render stream to the browser.
	uuid := tunnelUUID()
	if uuid == "" {
		uuid = gconn.ID // RNG failed; any non-empty tunnel id will do
	}
	for _, inst := range guacamolePrelude(uuid, gconn.ID) {
		if err := ws.Write(ctx, websocket.MessageText, inst); err != nil {
			return
		}
	}

	// Clipboard auditing (Phase 50): observe what crosses the bridge Phase 33
	// gates. The audit is written on a cancel-detached context so a transfer
	// completed as the session tears down is still recorded.
	clip := guacd.NewClipWatcher(clipAudit)
	auditCtx := context.WithoutCancel(ctx)
	bridgeGuacd(ctx, ws, gconn, clip, func(t guacd.ClipTransfer) {
		s.audit(auditCtx, proto.name+".clipboard", "target:"+target.Name+" "+t.Detail())
	})
}

// tunnelUUID returns a random identifier for the Guacamole tunnel handshake. The
// value is opaque to the WebSocket transport (guacamole-common-js only stores
// it), so a random hex string suffices; "" signals the system RNG failed.
func tunnelUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// guacamolePrelude builds the two instructions guacamole-common-js expects before
// the render stream: the internal (empty-opcode) tunnel-UUID instruction that
// marks the tunnel open, then a `ready` carrying the guacd connection id that
// advances Guacamole.Client to CONNECTED. Encoded in the Guacamole wire format,
// they read "0.,<len>.<uuid>;" and "5.ready,<len>.<connID>;".
func guacamolePrelude(uuid, connID string) [][]byte {
	return [][]byte{
		[]byte(guacd.Instruction{Args: []string{uuid}}.Encode()),
		[]byte(guacd.Instruction{Opcode: "ready", Args: []string{connID}}.Encode()),
	}
}

// bridgeGuacd pipes Guacamole protocol text between the browser WebSocket and
// the guacd connection until either side closes. When clip is non-nil it also
// observes clipboard transfers in both directions (Phase 50) — observation
// only: every frame is forwarded byte-for-byte regardless, because dropping one
// would corrupt the display, and blocking the clipboard is Phase 33's gate.
func bridgeGuacd(ctx context.Context, ws *websocket.Conn, gconn *guacd.Conn, clip *guacd.ClipWatcher, onClip func(guacd.ClipTransfer)) {
	done := make(chan struct{}, 2)
	note := func(direction string, frame []byte) {
		if onClip == nil {
			return
		}
		// Every transfer the frame completed, not just the last: one message can
		// finish several, and an unreported one is a clipboard transfer that
		// happened with no audit record of it.
		for _, t := range clip.Observe(direction, frame) {
			onClip(t)
		}
	}
	go func() { // guacd → browser
		// Forward one whole Guacamole instruction per WebSocket message: the browser
		// tunnel parses each message independently and closes on a partial instruction,
		// so a raw byte-stream copy (which splits large img/blob paints at the read
		// boundary) corrupts or kills the viewer on the first real screen update.
		for {
			inst, err := gconn.NextInstruction()
			if len(inst) > 0 {
				if werr := ws.Write(ctx, websocket.MessageText, inst); werr != nil {
					break
				}
				note("out", inst) // copied FROM the target to the operator
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() { // browser → guacd
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				break
			}
			if _, werr := gconn.Write(data); werr != nil {
				break
			}
			note("in", data) // pasted INTO the target by the operator
		}
		done <- struct{}{}
	}()
	<-done
}

// atoiOr parses s as a positive int, returning def when s is empty, non-numeric,
// or non-positive.
func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return def
}

// clampDim caps a client-supplied RDP display dimension so a connect-capable user
// can't ask guacd to allocate an enormous framebuffer.
func clampDim(n int) int {
	const max = 4096
	if n > max {
		return max
	}
	return n
}

// rdpExtra builds the guacd RDP security parameters. By default (security == ""
// and ignoreCert == false) it sets neither, so guacd negotiates the security mode
// and verifies the RDP server certificate. A security mode is passed through when
// set; ignore-cert is only sent (disabling cert verification) when explicitly
// enabled for dev/self-signed hosts.
func rdpExtra(security string, ignoreCert bool, clipboard string) map[string]string {
	extra := rdpClipboardParams(clipboard)
	if security != "" {
		extra["security"] = security
	}
	if ignoreCert {
		extra["ignore-cert"] = "true"
	}
	return extra
}

// rdpClipboardParams maps the clipboard policy (PAM_RDP_CLIPBOARD) to Guacamole
// RDP parameters. Guacamole leaves both clipboard directions ON by default, so an
// operator can copy data out of (or paste into) a recorded RDP session with no
// gate and no audit — the RDP analog of unrestricted SFTP. This closes that:
//   - allow (default): copy (target→browser) and paste (browser→target) both on;
//   - readonly: paste INTO the target is blocked (no clipboard injection), copy
//     out stays on — the "target is read-only" stance, mirroring SFTP read-only;
//   - deny: the clipboard bridge is off in both directions.
//
// It also always disables drive redirection (`enable-drive=false`) so no file can
// be exfiltrated through a mounted client drive regardless of guacd's defaults.
// rdpClipboardMode normalizes a clipboard policy: "" inherits the default
// ("allow" — for the global value, config validation already rejects anything
// else), and an unknown non-empty value folds to "deny". Unknown values can
// only arrive from outside the API — a direct SQL write, a restore, an importer
// (the handlers 422 anything outside the enum) — and a row that says something
// unrecognizable on a security gate must fail closed: ranking it as allow would
// silently ignore an override the row visibly asks for, while the target list
// displays it as if enforced.
func rdpClipboardMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return "allow"
	}
	if _, ok := clipboardRank[mode]; !ok {
		return "deny"
	}
	return mode
}

// clipboardRank orders the clipboard-gate modes by strictness, for the
// per-target override merge.
var clipboardRank = map[string]int{"allow": 0, "readonly": 1, "deny": 2}

// clipAuditRank orders the clipboard-audit modes by how much they record.
var clipAuditRank = map[string]int{guacd.ClipAuditOff: 0, guacd.ClipAuditMeta: 1, guacd.ClipAuditFull: 2}

// strictestClipboard merges the global clipboard policy with a target's
// override, returning the STRICTER of the two (allow < readonly < deny); an
// empty target value inherits the global. Tighten-only on purpose: an override
// that could loosen a global deny would let one mislabeled target row undo a
// fleet-wide decision, and the codebase's one existing per-target override
// (Target.RequireApproval) composes the same way — by OR, never by replacement.
func strictestClipboard(global, target string) string {
	g, t := rdpClipboardMode(global), rdpClipboardMode(target)
	if clipboardRank[t] > clipboardRank[g] {
		return t
	}
	return g
}

// strictestClipAudit merges the global clipboard-audit mode with a target's
// override, keeping whichever records MORE (off < meta < full); an empty target
// value inherits the global. Note the exposure trade this can make deliberate:
// "full" records clipboard CONTENT, which often includes a just-copied
// password — setting it per target is an explicit admin decision on that
// target, carrying the same warning as the global flag.
func strictestClipAudit(global, target string) string {
	g, t := guacd.NormalizeClipAudit(global), guacd.NormalizeClipAudit(target)
	if clipAuditRank[t] > clipAuditRank[g] {
		return t
	}
	return g
}

// rdpClipboardParams translates the clipboard policy into the guacd parameters
// that enforce it. Enforcement happens in guacd, not in the browser, because
// anything the browser decides is advice: the operator controls that side.
//
// "deny" blocks both directions, "readonly" allows copy OUT of the target but
// blocks paste IN, and anything else allows both. Drive redirection is off in
// every mode — file transfer belongs on the audited SFTP path, not on a channel
// that leaves no record.
func rdpClipboardParams(mode string) map[string]string {
	m := clipboardParams(mode)
	m["enable-drive"] = "false"
	return m
}

// clipboardParams translates the clipboard policy into the two guacd parameters
// that enforce it. guacd accepts the same pair for RDP and VNC, so both viewers
// gate the clipboard through this one mapping.
func clipboardParams(mode string) map[string]string {
	m := map[string]string{}
	switch mode {
	case "deny":
		m["disable-copy"], m["disable-paste"] = "true", "true"
	case "readonly":
		m["disable-copy"], m["disable-paste"] = "false", "true"
	default: // allow (and any unset value — validated at config load)
		m["disable-copy"], m["disable-paste"] = "false", "false"
	}
	return m
}

// vncExtra builds the guacd VNC parameters. VNC has no transport security of its
// own to configure (classic RFB is plaintext and its authentication is a DES
// challenge over a password truncated to 8 characters), so unlike RDP there is no
// security mode or certificate here — which is exactly why the credential stays
// server-side and guacd belongs on a private network.
//
// enable-sftp is forced off: it is VNC's file-transfer channel and therefore the
// analog of RDP's drive redirection, an unaudited way to move files that this
// system exists to prevent. guacd defaults it off; sending it explicitly means a
// changed default cannot open the channel behind us.
func vncExtra(clipboard string) map[string]string {
	extra := clipboardParams(clipboard)
	extra["enable-sftp"] = "false"
	return extra
}
