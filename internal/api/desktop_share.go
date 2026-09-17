package api

// desktop_share.go shares a live RDP/VNC session with another person
// (Phase 260 — Access Manager's session invite): view only, or view and
// control. It is Phase 116's invite workflow unchanged — filed by one
// principal, approved by a DIFFERENT one, a single-use token, an email + QR
// for an outsider — with a desktop at the end of it instead of a terminal.
//
// The join is Phase 258's: the sharer is added to the operator's guacd
// connection as another user, so they see the current screen at once. What
// differs is control. A view_only sharer is joined read-only and forwards
// nothing but keep-alive, exactly as a watcher. A view_control sharer is
// joined with input, but only keyboard, mouse and touch pass the bridge:
// clipboard, file and pipe streams do not, in either direction, so sharing a
// desktop never becomes a way to move data into or out of it.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/guacd"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// shareControlForwardable is what a view_control sharer's browser may send
// guacd: input devices and the protocol's keep-alive — never a clipboard,
// file or pipe stream.
var shareControlForwardable = map[string]bool{
	"sync": true, "nop": true, "disconnect": true,
	"key": true, "mouse": true, "touch": true,
}

// operatorInputOpcodes are the forwarded instructions that are a person
// acting, for the session's idle clock.
var operatorInputOpcodes = map[string]bool{"key": true, "mouse": true, "touch": true}

// shareControlInput filters one browser message down to what a
// view_control sharer may send, re-encoded, and reports whether any of it
// was input a person made.
func shareControlInput(data []byte) (out []byte, active bool) {
	for _, inst := range guacd.DecodeAll(data) {
		if shareControlForwardable[inst.Opcode] {
			out = append(out, inst.Encode()...)
			active = active || operatorInputOpcodes[inst.Opcode]
		}
	}
	return out, active
}

// memberStanding re-checks the PAMv1 user a member key was issued to, as
// they are now: active and unlocked, still holding connect for a control
// share, and inside the source gates (IP allowlist, device, posture) from
// THIS connection's address. It returns a refusal reason and message, or "".
// A directory identity has no local row to re-read; its key is bounded by
// PAM_SESSION_SHARE_GUEST_TTL_MIN, a kick, and the session's end.
func (s *Server) memberStanding(r *http.Request, username string, control bool) (reason, msg string) {
	u, err := s.store.GetUserByUsername(r.Context(), username)
	if errors.Is(err, store.ErrNotFound) {
		return "", ""
	}
	if err != nil {
		return "identity-lookup-failed", "could not verify your account"
	}
	if !u.Active || u.LockedAt(time.Now()) {
		return "identity-inactive-or-locked", "your account is inactive or locked"
	}
	p, err := s.resolver.PrincipalForRole(r.Context(), u.Username, u.Role)
	if err != nil {
		return "identity-lookup-failed", "could not verify your account"
	}
	p.IPAllowlist, p.DeviceFingerprint = u.IPAllowlist, u.DeviceFingerprint
	if control && !p.Can(auth.CapConnect) {
		return "no-connect-capability", "view-control requires connect capability"
	}
	return s.sourceGates(r.Context(), p, r)
}

// isDesktopSession reports whether sid is a live RDP/VNC session on this
// replica — one joined through guacd, not through the text stream.
func (s *Server) isDesktopSession(sid string) bool {
	_, ok := s.viewerJoins.Load(sid)
	return ok
}

// sessionProtocol names a live session's protocol from this replica's
// registry, or "" when it is not known here.
func (s *Server) sessionProtocol(sid string) string {
	if s.sessions == nil {
		return ""
	}
	if info, ok := s.sessions.Get(sid); ok {
		return info.Protocol
	}
	return ""
}

// desktopRedeemIn is the body of POST /api/share/desktop/redeem.
type desktopRedeemIn struct {
	Token string `json:"token"`
}

// redeemDesktopInvite (POST /api/share/desktop/redeem) is where an INTERNAL
// invite to a desktop is redeemed — the portal's counterpart of the SSH
// proxy's `join:<token>` login, which a desktop cannot use. The caller is
// authenticated with their own key, and the checks are the proxy's, in the
// proxy's order: the token is consumed FIRST (a failed redemption still burns
// it), then it must be internal, issued to this caller, carry connect for
// view_control, and name a desktop live on this replica. It answers with a
// guest key bound to this caller, which the desktop WebSocket takes.
func (s *Server) redeemDesktopInvite(w http.ResponseWriter, r *http.Request) {
	if s.shares == nil || s.guacdAddr == "" {
		writeError(w, http.StatusNotFound, "desktop sharing is not enabled")
		return
	}
	var in desktopRedeemIn
	if !readJSON(w, r, &in) {
		return
	}
	p := principalFrom(r.Context())
	deny := func(detail string, code int, msg string) {
		s.audit(r.Context(), "session.share_join_denied", detail)
		writeError(w, code, msg)
	}
	if p.BreakGlass {
		deny("reason:break-glass", http.StatusForbidden, "a break-glass session cannot join a shared session")
		return
	}
	inv, err := s.store.ConsumeSessionShareInviteByTokenHash(r.Context(), auth.TokenHash(strings.TrimSpace(in.Token)), time.Now())
	if err != nil {
		deny("reason:invalid-expired-or-used-token", http.StatusForbidden, "this invite is invalid, expired or already used")
		return
	}
	if inv.Kind != "internal" {
		deny(fmt.Sprintf("invite:%d reason:wrong-redemption-path", inv.ID), http.StatusForbidden, "this invite must be redeemed via its emailed link")
		return
	}
	if !strings.EqualFold(inv.Invitee, p.Name) {
		deny(fmt.Sprintf("invite:%d reason:invitee-mismatch", inv.ID), http.StatusForbidden, "this invite was not issued to you")
		return
	}
	if inv.Mode == "view_control" && !p.Can(auth.CapConnect) {
		deny(fmt.Sprintf("invite:%d reason:no-connect-capability", inv.ID), http.StatusForbidden, "view-control requires connect capability")
		return
	}
	if !s.isDesktopSession(inv.SessionID) {
		reason, msg := "not-live", "this session is no longer live on this replica"
		if s.sessions != nil && s.sessions.Exists(inv.SessionID) {
			reason, msg = "not-a-desktop", "this is not a desktop session; redeem it over SSH as join:<token>"
		}
		deny(fmt.Sprintf("invite:%d session:%s reason:%s", inv.ID, inv.SessionID, reason), http.StatusConflict, msg)
		return
	}
	if !s.mustAudit(w, r.Context(), "session.share_joined", fmt.Sprintf("invite:%d session:%s mode:%s remote:%s via:portal",
		inv.ID, inv.SessionID, inv.Mode, auditField(s.clientIP(r), 64))) {
		return
	}
	key, err := s.shares.IssueMemberKey(inv.SessionID, p.Name, inv.Mode, s.shareGuestTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issuing a join key failed")
		return
	}
	writeJSON(w, http.StatusOK, shareRedeemOut{Key: key, SessionID: inv.SessionID, Mode: inv.Mode, Protocol: s.sessionProtocol(inv.SessionID)})
}

// shareDesktop (GET /api/share/desktop?key=&width=&height=) is the shared
// desktop's WebSocket, for an internal invitee and an external guest alike:
// both hold a guest key (browsers cannot set WebSocket headers). The join is
// tracked on the session's roster under GuestJoinID — so the console lists
// it and a kick ends it — and ends with the session.
func (s *Server) shareDesktop(w http.ResponseWriter, r *http.Request) {
	if s.shares == nil || s.guacdAddr == "" {
		writeError(w, http.StatusNotFound, "desktop sharing is not enabled")
		return
	}
	key := r.URL.Query().Get("key")
	sid, actor, mode, ok := s.shares.ResolveGuestKey(key)
	if !ok {
		s.authFailed(w, r, "share-guest", "invalid or expired guest key")
		return
	}
	setActor(r.Context(), actor)
	control := mode == "view_control"
	// An internal invitee's key is only as good as the user behind it (the
	// review of 250–262). The SSH join re-authenticates on every connection;
	// this key was checked at redemption and then trusted for its whole TTL, so
	// a user locked, deactivated, stripped of connect or outside their IP
	// allowlist kept the keyboard of a privileged desktop.
	if s.shares.GuestKeyIsMember(key) {
		if reason, msg := s.memberStanding(r, actor, control); reason != "" {
			_ = s.auditAs(r.Context(), actor, "session.share_join_denied", "session:"+sid+" reason:"+reason)
			writeError(w, http.StatusForbidden, msg)
			return
		}
	}
	v, ok := s.viewerJoins.Load(sid)
	if !ok {
		writeError(w, http.StatusConflict, "this is not a desktop session live on this replica")
		return
	}
	j := v.(viewerJoin)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	gconn, err := guacd.Connect(ctx, s.guacdAddr, guacd.Params{
		Protocol: j.protocol, Join: j.conn, ReadOnly: !control,
		Width:  clampDim(atoiOr(r.URL.Query().Get("width"), 1024)),
		Height: clampDim(atoiOr(r.URL.Query().Get("height"), 768)),
	})
	if err != nil {
		_ = s.auditAs(r.Context(), actor, "session.share_join_denied", "session:"+sid+" reason:guacd-join-failed")
		writeError(w, http.StatusBadGateway, "could not join the session")
		return
	}
	defer gconn.Close()
	if !control && !gconn.Supports("read-only") {
		_ = s.auditAs(r.Context(), actor, "session.share_join_denied", "session:"+sid+" reason:read-only-unenforceable")
		writeError(w, http.StatusBadGateway, "guacd cannot make a view-only sharer read-only")
		return
	}
	if !s.mustAuditAs(w, r.Context(), actor, "session.monitor", fmt.Sprintf("session:%s protocol:%s target:%s actor:%s via:share mode:%s",
		sid, j.protocol, j.target, j.actor, mode)) {
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		return
	}
	defer ws.Close(websocket.StatusNormalClosure, "")

	joined := time.Now()
	joinID := session.GuestJoinID(key)
	kicked := s.shares.Track(sid, joinID, actor, mode)
	defer func() {
		s.shares.Untrack(sid, joinID)
		_ = s.auditAs(context.WithoutCancel(r.Context()), actor, "session.share_ended",
			fmt.Sprintf("session:%s duration:%s", sid, time.Since(joined).Round(time.Second)))
	}()
	// The session ending, or a kick, ends the join — whatever guacd does.
	go func() {
		select {
		case <-j.done:
		case <-kicked:
			ws.Close(websocket.StatusPolicyViolation, "removed from this session")
		case <-ctx.Done():
			return
		}
		cancel()
		gconn.Close()
	}()
	uuid := tunnelUUID()
	if uuid == "" {
		uuid = gconn.ID
	}
	for _, inst := range guacamolePrelude(uuid, gconn.ID) {
		if err := ws.Write(ctx, websocket.MessageText, inst); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() { // guacd → sharer, less the owner's clipboard
		var out watchOutput
		for {
			inst, err := gconn.NextInstruction()
			if len(inst) > 0 && out.forward(inst) {
				if werr := ws.Write(ctx, websocket.MessageText, inst); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() { // sharer → guacd
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				break
			}
			var out []byte
			if control && !s.shares.Suspended(sid) { // a suspended session takes nobody's input
				var active bool
				if out, active = shareControlInput(data); active && j.touch != nil {
					j.touch()
				}
			} else {
				out = watchInput(data)
			}
			if out != nil {
				if _, werr := gconn.Write(out); werr != nil {
					break
				}
			}
		}
		done <- struct{}{}
	}()
	<-done
}
