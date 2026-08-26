package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// --- session-share invite workflow (Phase 116, four-eyes) ---
//
// A share invite goes through the same request-then-approve shape as an
// AccessRequest/VendorGrant: creating one (createShareInvite) only records
// intent — nothing is redeemable and no email is sent until a DIFFERENT
// principal approves it (decideShareInvite). Two independent redemption
// surfaces consume an approved invite's token exactly once:
//   - internal: internal/proxy's `join:<token>` SSH login (see proxy.go).
//   - external: the three guest handlers below (redeemShareInvite +
//     streamShareGuest + inputShareGuest), reached from the emailed
//     link/QR's guest page (internal/web's Share handler).

// shareInviteIn is the body of POST /api/sessions/{id}/share.
type shareInviteIn struct {
	Mode    string `json:"mode"`              // view_only | view_control
	Kind    string `json:"kind"`              // internal | external
	Invitee string `json:"invitee,omitempty"` // internal: a PAMv1 username
	Email   string `json:"email,omitempty"`   // external: recipient address
}

// createShareInvite files a request to share the live session named in the
// {id} path value. Nothing is sent and no token is minted yet — see
// decideShareInvite.
func (s *Server) createShareInvite(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("id")
	if s.sessions == nil || !s.sessions.Exists(sid) {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	var in shareInviteIn
	if !readJSON(w, r, &in) {
		return
	}
	switch in.Mode {
	case "view_only", "view_control":
	default:
		writeError(w, http.StatusUnprocessableEntity, "mode must be view_only or view_control")
		return
	}
	switch in.Kind {
	case "internal":
		if in.Invitee == "" {
			writeError(w, http.StatusUnprocessableEntity, "invitee is required for an internal invite")
			return
		}
	case "external":
		if in.Email == "" {
			writeError(w, http.StatusUnprocessableEntity, "email is required for an external invite")
			return
		}
		if !s.shareEmailEnabled() {
			writeError(w, http.StatusServiceUnavailable, "external session-share invites need PAM_ALERT_EMAIL_* and an absolute PAM_PORTAL_URL configured")
			return
		}
	default:
		writeError(w, http.StatusUnprocessableEntity, "kind must be internal or external")
		return
	}
	inv := store.SessionShareInvite{
		SessionID: sid,
		Mode:      in.Mode,
		Kind:      in.Kind,
		Invitee:   in.Invitee,
		Email:     in.Email,
		Status:    "pending",
		Requester: actorFrom(r.Context()),
	}
	if err := s.store.CreateSessionShareInvite(r.Context(), &inv); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "session.share_requested", fmt.Sprintf("invite:%d session:%s mode:%s kind:%s", inv.ID, sid, inv.Mode, inv.Kind))
	writeJSON(w, http.StatusCreated, inv)
}

// listShareInvites lists the session named in the {id} path value's share
// invites (outstanding, active and ended), newest first.
func (s *Server) listShareInvites(w http.ResponseWriter, r *http.Request) {
	invs, err := s.store.ListSessionShareInvites(r.Context(), r.PathValue("id"))
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, invs)
}

// approveShareInvite approves the share invite named in the {id} path value.
func (s *Server) approveShareInvite(w http.ResponseWriter, r *http.Request) {
	s.decideShareInvite(w, r, "approved")
}

// denyShareInvite denies the share invite named in the {id} path value.
func (s *Server) denyShareInvite(w http.ResponseWriter, r *http.Request) {
	s.decideShareInvite(w, r, "denied")
}

// shareInviteOut is what a decision returns: the invite, plus — internal
// approvals only — the raw single-use token, present in this ONE response and
// never stored or logged anywhere (the same "returned once" handling
// POST /api/users gives a new user's bearer token).
type shareInviteOut struct {
	store.SessionShareInvite
	Token string `json:"token,omitempty"`
}

// decideShareInvite records an approver's decision, enforcing the four-eyes
// rule (the approver must differ from the requester) and that only a pending
// invite can be decided. Approving mints a single-use token valid for
// shareInviteTTL (15 minutes by default — see config.Config.ShareInviteTTL)
// and, for an external invite, sends the email+QR. session.share_approved is
// audited fail-closed (mustAudit): an approval is about to grant live access
// to a running session, exactly the class of event audited-before-disclosure
// exists for. It fires AFTER the store write but BEFORE any actual
// disclosure (the email send / the token leaving this handler) — so a failed
// audit write still leaves the row "approved" in the store (a benign
// inconsistency: nothing has been disclosed to anyone) but blocks the
// disclosure itself.
func (s *Server) decideShareInvite(w http.ResponseWriter, r *http.Request, decision string) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	inv, err := s.store.GetSessionShareInvite(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	approver := actorFrom(r.Context())
	if inv.Requester == approver {
		s.audit(r.Context(), "session.share_denied", fmt.Sprintf("invite:%d reason:self-approval", inv.ID))
		writeError(w, http.StatusForbidden, "four-eyes: you cannot decide your own share invite")
		return
	}
	if inv.Status != "pending" {
		writeError(w, http.StatusConflict, "invite already "+inv.Status)
		return
	}

	if decision == "denied" {
		if err := s.store.DecideSessionShareInvite(r.Context(), inv.ID, "denied", approver, time.Now(), "", nil); err != nil {
			storeError(w, err)
			return
		}
		s.audit(r.Context(), "session.share_denied", fmt.Sprintf("invite:%d requester:%s session:%s", inv.ID, inv.Requester, inv.SessionID))
		inv.Status, inv.Approver = "denied", approver
		writeJSON(w, http.StatusOK, inv)
		return
	}

	token, tokenHash, err := newShareToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generating the invite token failed")
		return
	}
	expires := time.Now().Add(s.shareInviteTTL).UTC()
	if err := s.store.DecideSessionShareInvite(r.Context(), inv.ID, "approved", approver, time.Now(), tokenHash, &expires); err != nil {
		storeError(w, err)
		return
	}
	inv.Status, inv.Approver, inv.ExpiresAt = "approved", approver, &expires

	if !s.mustAudit(w, r.Context(), "session.share_approved", fmt.Sprintf(
		"invite:%d requester:%s session:%s mode:%s kind:%s expires:%s",
		inv.ID, inv.Requester, inv.SessionID, inv.Mode, inv.Kind, expires.Format(time.RFC3339))) {
		return
	}

	if inv.Kind == "external" {
		if err := s.sendShareInviteEmail(r.Context(), *inv, token); err != nil {
			writeError(w, http.StatusBadGateway, "approved, but sending the invite email failed: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, shareInviteOut{SessionShareInvite: *inv})
		return
	}
	writeJSON(w, http.StatusOK, shareInviteOut{SessionShareInvite: *inv, Token: token})
}

// rosterShareInvite lists who is currently attached to the session named in
// the {id} path value — the primary operator's own live view of who is
// watching/typing, backing the console's joined-parties roster. Works even
// with session-sharing disabled (nil s.shares): ShareRegistry.Roster is
// nil-safe and returns an empty (never nil) slice.
func (s *Server) rosterShareInvite(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.shares.Roster(r.PathValue("id")))
}

type kickIn struct {
	JoinID string `json:"join_id"`
}

// kickShareJoin force-disconnects one attached join (internal/SSH or
// external/web, either kind) from the session named in the {id} path value —
// ShareRegistry.Kick closes the channel that join's own I/O loop is
// selecting on, so it disconnects promptly rather than merely being removed
// from the roster's bookkeeping.
func (s *Server) kickShareJoin(w http.ResponseWriter, r *http.Request) {
	if s.shares == nil {
		writeError(w, http.StatusNotFound, "session sharing is not enabled")
		return
	}
	var in kickIn
	if !readJSON(w, r, &in) {
		return
	}
	sid := r.PathValue("id")
	if !s.shares.Kick(sid, in.JoinID) {
		writeError(w, http.StatusNotFound, "no such joined party")
		return
	}
	s.audit(r.Context(), "session.share_kicked", fmt.Sprintf("session:%s join:%s", sid, auditField(in.JoinID, 128)))
	writeJSON(w, http.StatusOK, map[string]any{"kicked": true})
}

// revokeShareInvite revokes an approved-but-not-yet-consumed (or already
// active) share invite, so a later redemption attempt fails even though the
// token and TTL would otherwise still be valid.
func (s *Server) revokeShareInvite(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.RevokeSessionShareInvite(r.Context(), id, time.Now()); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "session.share_revoked", fmt.Sprintf("invite:%d", id))
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

// newShareToken returns a fresh random bearer token and its SHA-256 hash —
// the token is handed to the redeemer (or emailed) once; only the hash is
// ever stored, matching how every other bearer secret in this codebase is
// handled.
func newShareToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(b)
	return token, auth.TokenHash(token), nil
}

// shareEmailEnabled reports whether this server can send session-share
// invite email: not air-gapped (PAM_OT_AIRGAP — an external invite email is
// exactly the outbound call an air-gapped deployment must never make; unlike
// the security-alert channel, which buildAlerter already neuters to a no-op
// under air-gap, alert.SendDirect dials SMTP directly and has no such
// built-in guard, so this check is what actually closes that path), the same
// PAM_ALERT_EMAIL_* SMTP settings the security-alert channel uses (so
// enabling alert email also enables external session-share invites, no
// second config surface — see main.go), AND an ABSOLUTE portal URL, since
// the emailed link has to resolve for a recipient with no other browser
// context (unlike the portal's own relative-path default).
func (s *Server) shareEmailEnabled() bool {
	return !s.airGap && s.shareSMTPAddr != "" && s.shareSMTPFrom != "" &&
		(strings.HasPrefix(s.portalURL, "http://") || strings.HasPrefix(s.portalURL, "https://"))
}

// sendShareInviteEmail sends the email+QR for a just-approved external
// invite. The link and the QR code both encode the same URL, carrying the
// raw single-use token — https, 15-minutes-by-default TTL, single
// redemption (see ShareInviteTTL / ConsumeSessionShareInviteByTokenHash).
func (s *Server) sendShareInviteEmail(ctx context.Context, inv store.SessionShareInvite, token string) error {
	link := strings.TrimRight(s.portalURL, "/") + "/share.html?token=" + token
	png, err := qrcode.Encode(link, qrcode.Medium, 256)
	if err != nil {
		return err
	}
	verb := "watch"
	if inv.Mode == "view_control" {
		verb = "watch and interact with"
	}
	subject := "You've been invited to a live PAMv1 session"
	body := fmt.Sprintf(`<html><body style="font-family:sans-serif;background:#050705;color:#eaffea;padding:24px">
<p>You have been invited to %s a live PAMv1 session.</p>
<p><a href="%s" style="color:#4be0e0">%s</a></p>
<p>Or scan this code:</p>
<img src="cid:qr" alt="QR code" width="256" height="256">
<p>This link expires in %d minutes and can only be used once.</p>
</body></html>`, html.EscapeString(verb), html.EscapeString(link), html.EscapeString(link), int(s.shareInviteTTL/time.Minute))
	return alert.SendDirect(s.shareSMTPAddr, s.shareSMTPFrom, inv.Email, s.shareSMTPUser, s.shareSMTPPass, subject, body, png, "qr")
}

// --- external/vendor guest redemption (unauthenticated until a token is
// presented) — reached from the emailed link/QR's guest page, NOT from the
// authenticated portal. Registered without the s.authz(...) wrapper (see
// server.go), the same way the RDP/VNC viewer's query-token-authed WebSocket
// routes are — see viewer_handlers.go. ---

type shareRedeemOut struct {
	Key       string `json:"key"`
	SessionID string `json:"session_id"`
	Mode      string `json:"mode"`
}

// redeemShareInvite is POST /api/share/redeem/{token}: the guest page's very
// first call. It atomically consumes the invite's one-time token (refusing
// anything but an external-kind, approved, unexpired, unrevoked,
// not-yet-consumed invite — internal invites are SSH-only, symmetric with
// the proxy's own join: path refusing anything but Kind=="internal") and, on
// success, mints a SEPARATE guest key: the one-time token proves the
// redemption; the guest key is what the browser's subsequent SSE stream and
// (for view_control) input POSTs authenticate with; those happen many times
// over the course of the viewing, which a single-use token cannot back.
// session.share_joined is audited fail-closed — the class of event
// audited-before-disclosure exists for — BEFORE the guest key is minted, so
// a failed audit write hands back no usable credential at all.
func (s *Server) redeemShareInvite(w http.ResponseWriter, r *http.Request) {
	if s.shares == nil || s.live == nil {
		writeError(w, http.StatusNotFound, "session sharing is not enabled")
		return
	}
	token := r.PathValue("token")
	inv, err := s.store.ConsumeSessionShareInviteByTokenHash(r.Context(), auth.TokenHash(token), time.Now())
	if err != nil {
		s.authFailed(w, r, "share-guest", "invalid, expired, revoked, or already-used invite token")
		return
	}
	if inv.Kind != "external" {
		// An internal invite's token was somehow presented on the web path —
		// refuse and audit the same as any other wrong-surface redemption
		// attempt, distinct from a merely-invalid token.
		s.audit(r.Context(), "session.share_join_denied", fmt.Sprintf("invite:%d reason:wrong-surface remote:%s", inv.ID, r.RemoteAddr))
		writeError(w, http.StatusForbidden, "this invite is not redeemable on the web")
		return
	}
	actor := "guest:" + inv.Email
	detail := fmt.Sprintf("invite:%d session:%s mode:%s remote:%s ua:%s email:%s",
		inv.ID, inv.SessionID, inv.Mode, auditField(s.clientIP(r), 64), auditField(r.UserAgent(), 128), auditField(inv.Email, 128))
	if !s.mustAuditAs(w, r.Context(), actor, "session.share_joined", detail) {
		return
	}
	key, err := s.shares.IssueGuestKey(inv.SessionID, actor, inv.Mode, s.shareGuestTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issuing a guest session failed")
		return
	}
	writeJSON(w, http.StatusOK, shareRedeemOut{Key: key, SessionID: inv.SessionID, Mode: inv.Mode})
}

// streamShareGuest is GET /api/share/stream?key=... — the guest page's
// EventSource. It is streamSession's shape (see handlers.go), reused for a
// guest key instead of a PAMv1 principal's CapReadAudit, since a browser
// EventSource cannot set the X-API-Key header the normal stream requires.
func (s *Server) streamShareGuest(w http.ResponseWriter, r *http.Request) {
	if s.shares == nil || s.live == nil {
		writeError(w, http.StatusNotFound, "session sharing is not enabled")
		return
	}
	key := r.URL.Query().Get("key")
	sid, actor, mode, ok := s.shares.ResolveGuestKey(key)
	if !ok {
		s.authFailed(w, r, "share-guest", "invalid or expired guest key")
		return
	}
	frames, cancel := s.live.Subscribe(sid)
	defer cancel()
	if s.sessions != nil && !s.sessions.Exists(sid) {
		writeError(w, http.StatusNotFound, "session has ended")
		return
	}
	rc, ok := s.beginStream(w)
	if !ok {
		return
	}
	// Track/Untrack bracket the stream's own lifetime (not the one-shot
	// redeem call above it) — this handler's loop runs for as long as the
	// guest's browser tab stays open, exactly like the SSH-side join's own
	// long-lived goroutine (proxy.go's handleJoinSession); tracking at
	// redeem time would leave a roster entry stuck "joined" forever if the
	// guest closed their tab without the underlying session ever ending.
	joined := time.Now()
	// Tracked under GuestJoinID, never the key: the roster is served to every
	// CapReadAudit reader and the kick is audited, so the id that reaches them
	// must identify this join without BEING the guest's credential (2026-08-27
	// audit).
	joinID := session.GuestJoinID(key)
	kicked := s.shares.Track(sid, joinID, actor, mode)
	s.shares.Notify(sid, fmt.Sprintf("PAMv1: %s joined this session (%s)", actor, mode))
	defer func() {
		s.shares.Untrack(sid, joinID)
		s.shares.Notify(sid, fmt.Sprintf("PAMv1: %s left this session", actor))
		_ = s.auditAs(r.Context(), actor, "session.share_ended", fmt.Sprintf("session:%s duration:%s", sid, time.Since(joined).Round(time.Second)))
	}()
	_ = s.auditAs(r.Context(), actor, "session.monitor", "session:"+sid+" via:share-guest")
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-kicked:
			fmt.Fprintf(w, "event: kicked\ndata: removed from this session\n\n")
			_ = rc.Flush()
			return
		case b, open := <-frames:
			if !open {
				return
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", sseEscape(b)); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}
}

// inputShareGuest is POST /api/share/input?key=... — the guest page's
// keystroke path, view_control only. The request body (read whole, capped)
// is written verbatim into the session's input mux, the same mux the
// primary operator's own keystrokes and any internal (SSH join:) joiners
// feed — see internal/session/share.go.
func (s *Server) inputShareGuest(w http.ResponseWriter, r *http.Request) {
	if s.shares == nil {
		writeError(w, http.StatusNotFound, "session sharing is not enabled")
		return
	}
	sid, _, mode, ok := s.shares.ResolveGuestKey(r.URL.Query().Get("key"))
	if !ok {
		s.authFailed(w, r, "share-guest", "invalid or expired guest key")
		return
	}
	if mode != "view_control" {
		writeError(w, http.StatusForbidden, "this invite is view-only")
		return
	}
	// One keystroke (or a small paste) at a time — bounded well above any
	// realistic single input event so a misbehaving client cannot use this
	// as an unbounded upload.
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		writeError(w, http.StatusBadRequest, "reading the request body failed")
		return
	}
	if _, err := s.shares.Writer(sid).Write(body); err != nil {
		writeError(w, http.StatusGone, "the session has ended")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
