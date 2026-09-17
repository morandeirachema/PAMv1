package api

// terminal_handlers.go is the in-portal SSH terminal (Phase 254): the browser
// draws an xterm.js surface over a WebSocket, and this server is an SSH
// CLIENT of the session proxy on the operator's behalf. That is the whole
// design: the session it opens is a proxy session in every respect — every
// admit() gate, just-in-time injection, the recording, the live registry,
// sharing, suspend, supervision, command control, the idle clock — because
// it IS one. Nothing here decides access; the proxy does, exactly as it does
// for `ssh -p 2222 creduser@target pam-host`.
//
// What this file adds is the door. A terminal token is minted for ONE target,
// lives 60 seconds, is spent on first use, is refused by every API route (it
// travels in a WebSocket URL, as a viewer token does), and is accepted by the
// SSH proxy only over loopback — so the only party that can ever present one
// to the proxy is this server, which has already run the same source gates
// the middleware runs (IP allowlist, device, posture) against the browser's
// real address, twice: when the token was minted and when the WebSocket
// opened. The browser's address rides the SSH client-version string so the
// registry and the audit trail name the operator's machine, not 127.0.0.1.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// terminalTokenTTL bounds a terminal token: long enough for the console to
// mint it, ask for a session-MFA ticket if the target needs one, and open the
// WebSocket; short enough that a copy left in an access log is dead before
// anyone reads it. It is single-use besides.
const terminalTokenTTL = 60 * time.Second

// SetSSHProxy tells the server where the session proxy listens on loopback and
// which host key to expect — wired by main once the proxy exists, because the
// proxy's host key is loaded after the API server is built.
func (s *Server) SetSSHProxy(addr string, hostKey ssh.PublicKey) {
	s.sshProxyAddr, s.sshProxyHostKey = addr, hostKey
}

// sshTerminalToken (POST /api/ssh-token, {"target_id", "credential_id"?})
// mints a terminal token for one target. It answers, before any WebSocket
// exists, the refusals a browser could otherwise only see as an opaque close:
// no proxy on loopback, not an SSH target, no credential, a credential the
// caller may not use (Phase 252) — and it says whether the target needs a
// session-MFA ticket, which the console then mints and sends beside the token
// as the SSH password, exactly as an operator would paste it into ssh.
func (s *Server) sshTerminalToken(w http.ResponseWriter, r *http.Request) {
	if s.sshProxyAddr == "" || s.sshProxyHostKey == nil {
		writeError(w, http.StatusNotFound, "the in-portal terminal is not available (the SSH proxy is off or not on loopback)")
		return
	}
	p := principalFrom(r.Context())
	var in struct {
		TargetID     int64  `json:"target_id"`
		CredentialID *int64 `json:"credential_id"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	target, err := s.store.GetTarget(r.Context(), in.TargetID)
	if err != nil {
		storeError(w, err)
		return
	}
	if target.Protocol != "ssh" {
		writeError(w, http.StatusUnprocessableEntity, "the in-portal terminal opens SSH targets only")
		return
	}
	cred, ok := s.terminalCredential(w, r, target, in.CredentialID)
	if !ok {
		return
	}
	// The proxy will decide again; deciding here too makes the refusal
	// answerable. The same credential-scoped reading admit() makes.
	if allowed, err := s.authorizedForCredential(r.Context(), target, &cred.ID, auth.ActionUse); err != nil {
		storeError(w, err)
		return
	} else if !allowed {
		s.audit(r.Context(), "terminal.denied", "target:"+target.Name+" cred_user:"+cred.Username+" reason:target-policy")
		writeError(w, http.StatusForbidden, "not authorized for this target")
		return
	}
	mfaRequired := false
	if !p.BreakGlass {
		mfaRequired, err = store.EffectiveSessionMFA(r.Context(), s.store, target, s.sessionMFA)
		if err != nil {
			storeError(w, err)
			return
		}
	}
	token, sess, err := s.issueSessionBound(r.Context(), p, auth.SessionScopeTerminal, terminalTokenTTL, &target.ID)
	if err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "ssh.terminal_token", fmt.Sprintf("target:%s cred_user:%s ttl:%s", target.Name, cred.Username, terminalTokenTTL))
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token, "expires_at": sess.ExpiresAt, "target": target.Name, "cred_user": cred.Username,
		"session_mfa_required": mfaRequired,
	})
}

// terminalCredential resolves the credential a terminal will log in as: the
// one named, which must be on this target, or the target's first. It writes
// the 4xx itself.
func (s *Server) terminalCredential(w http.ResponseWriter, r *http.Request, target *store.Target, credID *int64) (*store.Credential, bool) {
	if credID != nil {
		c, err := s.store.GetCredential(r.Context(), *credID)
		if err != nil || c.TargetID != target.ID {
			writeError(w, http.StatusUnprocessableEntity, "credential_id must name a credential on this target")
			return nil, false
		}
		return c, true
	}
	creds, err := s.store.ListCredentials(r.Context(), target.ID, 0, 0)
	if err != nil {
		storeError(w, err)
		return nil, false
	}
	if len(creds) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "target has no credential")
		return nil, false
	}
	return &creds[0], true
}

// terminalResize is the one control message the browser sends as a TEXT
// frame; everything else is keystrokes, sent as BINARY frames.
type terminalResize struct {
	Resize *struct {
		Cols int `json:"cols"`
		Rows int `json:"rows"`
	} `json:"resize"`
}

// sshTerminal (GET /api/targets/{id}/ssh/terminal?token=&ticket=&cols=&rows=)
// bridges a browser WebSocket to an SSH session THROUGH the session proxy.
// The token is read from the query because browsers cannot set headers on a
// WebSocket handshake; it is terminal-scoped, bound to this target, spent on
// the first successful dial, and refused as an API key everywhere else.
func (s *Server) sshTerminal(w http.ResponseWriter, r *http.Request) {
	if s.sshProxyAddr == "" || s.sshProxyHostKey == nil {
		writeError(w, http.StatusNotFound, "the in-portal terminal is not available")
		return
	}
	token := r.URL.Query().Get("token")
	principal, err := s.resolver.Resolve(r.Context(), token)
	if err != nil {
		s.authFailed(w, r, "terminal", "invalid or missing token")
		return
	}
	setActor(r.Context(), principal.Name)
	r = r.WithContext(withPrincipal(r.Context(), principal))
	// Only a terminal token opens this door: not a full API key (which must
	// never sit in a URL), not a viewer token, not a ticket.
	if principal.NarrowScope() != auth.ScopeTerminal {
		s.audit(r.Context(), "authz.denied", r.Method+" "+r.URL.Path+" reason:not-a-terminal-token")
		writeError(w, http.StatusForbidden, "this endpoint takes a terminal token (POST /api/ssh-token)")
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if principal.TerminalTarget != id {
		s.audit(r.Context(), "authz.denied", r.Method+" "+r.URL.Path+" reason:terminal-token-target")
		writeError(w, http.StatusForbidden, "this terminal token was minted for a different target")
		return
	}
	// The same source gates the middleware runs, against the BROWSER's address
	// — this is the second time (the first was at mint); the proxy will see a
	// loopback dial and trusts this server to have done exactly this.
	if reason, msg := s.sourceGates(r.Context(), principal, r); reason != "" {
		s.audit(r.Context(), "authz.denied", r.Method+" "+r.URL.Path+" reason:"+reason)
		writeError(w, http.StatusForbidden, msg)
		return
	}
	if !principal.Can(auth.CapConnect) {
		s.audit(r.Context(), "authz.denied", r.Method+" "+r.URL.Path+" role:"+string(principal.Role))
		writeError(w, http.StatusForbidden, "your role does not permit terminal access")
		return
	}
	target, err := s.store.GetTarget(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	credUser := r.URL.Query().Get("cred_user")
	if credUser == "" {
		cred, ok := s.terminalCredential(w, r, target, nil)
		if !ok {
			return
		}
		credUser = cred.Username
	}
	cols, rows := atoiOr(r.URL.Query().Get("cols"), 120), atoiOr(r.URL.Query().Get("rows"), 40)
	if cols > 500 {
		cols = 500
	}
	if rows > 200 {
		rows = 200
	}
	// The SSH password: a session-MFA ticket when the target demands a fresh
	// factor (the proxy spends it at its gate 12, as it would from ssh), else
	// the terminal token itself, which the proxy accepts only over loopback.
	password := auth.TerminalPassword(token, r.URL.Query().Get("ticket"))
	clientIP := s.clientIP(r)

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"pamv1-terminal"}})
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	client, err := ssh.Dial("tcp", s.sshProxyAddr, &ssh.ClientConfig{
		User:            credUser + "@" + target.Name,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.FixedHostKey(s.sshProxyHostKey),
		ClientVersion:   auth.TerminalClientVersion(clientIP),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		// The proxy has already audited the precise gate; this records that
		// the browser door saw it, with the browser's address.
		s.audit(r.Context(), "terminal.refused", fmt.Sprintf("target:%s cred_user:%s remote:%s error:%s", target.Name, credUser, clientIP, auditField(err.Error(), 160)))
		ws.Close(websocket.StatusPolicyViolation, terminalCloseReason(err))
		return
	}
	defer client.Close()
	// Spend the terminal token: it opened exactly one session. Done after the
	// dial so a refused dial leaves the token usable for its remaining
	// seconds — over loopback only, by this server only.
	_ = s.store.DeleteSession(context.WithoutCancel(r.Context()), auth.TokenHash(token))

	sess, err := client.NewSession()
	if err != nil {
		ws.Close(websocket.StatusInternalError, "could not open a session")
		return
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		ws.Close(websocket.StatusInternalError, "could not open a session")
		return
	}
	stdout, _ := sess.StdoutPipe()
	stderr, _ := sess.StderrPipe()
	if err := sess.RequestPty("xterm-256color", rows, cols, ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}); err != nil {
		ws.Close(websocket.StatusInternalError, "pty refused")
		return
	}
	if err := sess.Shell(); err != nil {
		ws.Close(websocket.StatusPolicyViolation, terminalCloseReason(err))
		return
	}
	s.audit(r.Context(), "terminal.open", fmt.Sprintf("target:%s cred_user:%s remote:%s cols:%d rows:%d", target.Name, credUser, clientIP, cols, rows))
	defer s.audit(context.WithoutCancel(r.Context()), "terminal.end", fmt.Sprintf("target:%s cred_user:%s remote:%s", target.Name, credUser, clientIP))

	done := make(chan struct{}, 4) // four senders: stdout, stderr, the browser reader, Wait
	pump := func(rd io.Reader) {   // proxy → browser
		buf := make([]byte, 32*1024)
		for {
			n, err := rd.Read(buf)
			if n > 0 {
				if werr := ws.Write(ctx, websocket.MessageBinary, buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go pump(stdout)
	go pump(stderr)
	go func() { // browser → proxy
		for {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				break
			}
			if typ == websocket.MessageText {
				var m terminalResize
				if json.Unmarshal(data, &m) == nil && m.Resize != nil && m.Resize.Cols > 0 && m.Resize.Rows > 0 {
					_ = sess.WindowChange(m.Resize.Rows, m.Resize.Cols)
				}
				continue
			}
			if _, werr := stdin.Write(data); werr != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() { _ = sess.Wait(); done <- struct{}{} }()
	<-done
	ws.Close(websocket.StatusNormalClosure, "session ended")
}

// terminalCloseReason turns an SSH dial/shell error into the short reason a
// browser can show, without leaking anything the proxy did not already say
// to the operator on the wire.
func terminalCloseReason(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "PAMv1:"); i >= 0 {
		msg = msg[i:]
	}
	if len(msg) > 120 {
		msg = msg[:120]
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "the session proxy did not answer"
	}
	return msg
}

// loopbackDialAddr derives the address to dial the proxy on from its listen
// address (PAM_SSH_ADDR): an unspecified or empty host means loopback; a
// loopback host is used as-is; any other host is not dialable as "the proxy
// on this machine" and yields "", which disables the terminal.
func LoopbackDialAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return ""
	}
	if _, perr := strconv.Atoi(port); perr != nil {
		return ""
	}
	switch {
	case host == "", host == "0.0.0.0", host == "::":
		return net.JoinHostPort("127.0.0.1", port)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return net.JoinHostPort(host, port)
	}
	if host == "localhost" {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return ""
}
