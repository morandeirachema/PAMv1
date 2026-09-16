package api

// sessionmfa_handlers.go is per-session MFA (Phase 244) on the HTTP side: the
// three routes that mint a session-MFA ticket after a FRESH second factor, and
// the gate the REST access paths — reveal, checkout, operator certificates,
// the WinRM and kubectl endpoints — run with it. The session proxies run the
// same decision inside admit(), and the RDP/VNC viewer tunnel runs it inline;
// all of them go through auth.CheckSessionMFA, so a ticket means the same
// thing at every door.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// sessionMFATicketTTL bounds a ticket: long enough to paste into an SSH or
// database client once the factor is proven, short enough that a copy left in
// a scrollback is dead before anyone finds it. It is single-use besides.
const sessionMFATicketTTL = 2 * time.Minute

// sessionMFAHeader carries a ticket on the REST access paths, BESIDE the
// caller's own X-API-Key: the key still says who is asking, so every other
// gate reads the caller's identity, and the ticket only proves the factor.
const sessionMFAHeader = "X-PAM-Session-MFA"

type sessionMFAIn struct {
	Target string `json:"target"`
	OTP    string `json:"otp"`
}

// sessionMFACaller refuses the one principal `authenticated` admits that must
// not mint a ticket: an enrollment-only session. A ticket resolves to the
// user's full role, so minting one would widen a scope built to allow nothing
// but finishing enrollment.
func (s *Server) sessionMFACaller(w http.ResponseWriter, r *http.Request) (*auth.Principal, bool) {
	p := principalFrom(r.Context())
	if p.EnrollOnly {
		s.audit(r.Context(), "authz.denied", r.Method+" "+r.URL.Path+" reason:mfa-enrollment-incomplete")
		writeError(w, http.StatusForbidden, "complete MFA enrollment to continue")
		return nil, false
	}
	return p, true
}

// sessionMFATarget resolves the one target a ticket is bound to.
func (s *Server) sessionMFATarget(w http.ResponseWriter, r *http.Request, name string) (*store.Target, bool) {
	if strings.TrimSpace(name) == "" {
		writeError(w, http.StatusUnprocessableEntity, "target is required")
		return nil, false
	}
	t, err := s.targetByName(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown target")
		return nil, false
	}
	return t, true
}

// mintSessionMFATicket (POST /api/session-mfa) proves a one-time code — a TOTP
// code or a single-use recovery code — and returns a ticket for ONE target.
func (s *Server) mintSessionMFATicket(w http.ResponseWriter, r *http.Request) {
	p, ok := s.sessionMFACaller(w, r)
	if !ok {
		return
	}
	var in sessionMFAIn
	if !readJSON(w, r, &in) {
		return
	}
	target, ok := s.sessionMFATarget(w, r, in.Target)
	if !ok {
		return
	}
	enr, err := s.store.GetMFAEnrollment(r.Context(), p.Name)
	switch {
	case errors.Is(err, store.ErrNotFound), err == nil && !enr.Confirmed:
		writeError(w, http.StatusUnprocessableEntity,
			"no confirmed one-time-code factor is enrolled — use POST /api/session-mfa/webauthn/begin with a security key")
		return
	case err != nil:
		storeError(w, err)
		return
	}
	code := strings.TrimSpace(in.OTP)
	if code == "" {
		writeError(w, http.StatusUnprocessableEntity, "otp is required")
		return
	}
	factor, verr := auth.VerifySecondFactor(r.Context(), s.store, s.vault, enr, p.Name, code, time.Now())
	if verr != nil {
		s.log.Warn("totp replay check failed; rejecting code", "user", p.Name, "err", verr)
	}
	if factor == "" {
		s.log.Warn("session mfa failed", "user", p.Name, "target", target.Name, "remote", r.RemoteAddr)
		s.audit(r.Context(), "session.mfa_failed", "target:"+target.Name+" factor:otp remote:"+r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "invalid multi-factor code")
		return
	}
	if factor == auth.FactorRecovery {
		s.audit(r.Context(), "mfa.recovery_used", "user:"+p.Name)
	}
	s.issueSessionMFATicket(w, r, p, target, factor)
}

// sessionMFAChallengePurpose keys a ticket ceremony's stored challenge by the
// target it will bind, so a finish can only mint for the target its begin
// named.
func sessionMFAChallengePurpose(targetID int64) string {
	return "session-mfa:" + strconv.FormatInt(targetID, 10)
}

// sessionMFAWebAuthnBegin (POST /api/session-mfa/webauthn/begin, {"target"})
// starts an assertion ceremony for a ticket — the factor a user whose second
// factor is a security key presents, since a key cannot type a code.
func (s *Server) sessionMFAWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	if s.webAuthn == nil {
		writeError(w, http.StatusServiceUnavailable, "WebAuthn is not configured")
		return
	}
	p, ok := s.sessionMFACaller(w, r)
	if !ok {
		return
	}
	var in sessionMFAIn
	if !readJSON(w, r, &in) {
		return
	}
	target, ok := s.sessionMFATarget(w, r, in.Target)
	if !ok {
		return
	}
	creds, err := s.store.ListWebAuthnCredentials(r.Context(), p.Name)
	if err != nil {
		storeError(w, err)
		return
	}
	if len(creds) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "no WebAuthn credentials registered")
		return
	}
	assertion, sess, err := s.webAuthn.BeginLogin(webauthnUser{username: p.Name, creds: creds})
	if err != nil {
		s.log.Warn("webauthn: begin session-mfa failed", "user", p.Name, "err", err)
		writeError(w, http.StatusInternalServerError, "could not begin the ceremony")
		return
	}
	sessJSON, err := json.Marshal(sess)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.store.PutWebAuthnChallenge(r.Context(), p.Name, sessionMFAChallengePurpose(target.ID), sessJSON, time.Now().Add(webauthnChallengeTTL)); err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

// sessionMFAWebAuthnFinish (POST /api/session-mfa/webauthn/finish?target=)
// verifies the assertion and mints the ticket.
func (s *Server) sessionMFAWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	if s.webAuthn == nil {
		writeError(w, http.StatusServiceUnavailable, "WebAuthn is not configured")
		return
	}
	p, ok := s.sessionMFACaller(w, r)
	if !ok {
		return
	}
	target, ok := s.sessionMFATarget(w, r, r.URL.Query().Get("target"))
	if !ok {
		return
	}
	raw, ok, err := s.store.TakeWebAuthnChallenge(r.Context(), p.Name, sessionMFAChallengePurpose(target.ID), time.Now())
	if err != nil {
		storeError(w, err)
		return
	}
	if !ok {
		s.audit(r.Context(), "session.mfa_failed", "target:"+target.Name+" factor:webauthn reason:challenge-expired")
		writeError(w, http.StatusUnauthorized, "no ceremony is pending for this target — begin again")
		return
	}
	var sess webauthn.SessionData
	if err := json.Unmarshal(raw, &sess); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	creds, err := s.store.ListWebAuthnCredentials(r.Context(), p.Name)
	if err != nil {
		storeError(w, err)
		return
	}
	cred, err := s.webAuthn.FinishLogin(webauthnUser{username: p.Name, creds: creds}, sess, r)
	if err != nil {
		s.log.Warn("webauthn session-mfa failed", "user", p.Name, "target", target.Name, "err", err)
		s.audit(r.Context(), "session.mfa_failed", "target:"+target.Name+" factor:webauthn remote:"+r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "webauthn verification failed")
		return
	}
	s.webauthnWriteBack(r.Context(), p.Name, cred)
	s.issueSessionMFATicket(w, r, p, target, auth.FactorWebAuthn)
}

// issueSessionMFATicket mints the ticket row — a session with the ticket scope
// and the target binding — and returns it once.
func (s *Server) issueSessionMFATicket(w http.ResponseWriter, r *http.Request, p *auth.Principal, target *store.Target, factor string) {
	token, sess, err := s.issueSessionBound(r.Context(), p, auth.SessionScopeSessionMFA, sessionMFATicketTTL, &target.ID)
	if err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "session.mfa_ticket", fmt.Sprintf("target:%s factor:%s ttl:%s", target.Name, factor, sessionMFATicketTTL))
	writeJSON(w, http.StatusCreated, map[string]any{
		"ticket":     token,
		"target":     target.Name,
		"target_id":  target.ID,
		"factor":     factor,
		"expires_at": sess.ExpiresAt,
	})
}

// sessionMFAGate is the per-session MFA gate for a REST path that opens
// access to target. The caller's identity is the X-API-Key principal; a ticket,
// if any, rides in sessionMFAHeader and must be the SAME identity's. It writes
// the refusal itself and reports whether the path may continue. deniedAction is
// the path's own denial vocabulary (credential.reveal_denied, winrm.denied, …)
// and path names it on session.mfa_verified.
func (s *Server) sessionMFAGate(w http.ResponseWriter, r *http.Request, target *store.Target, deniedAction, path string) bool {
	ctx := r.Context()
	required, err := store.EffectiveSessionMFA(ctx, s.store, target, s.sessionMFA)
	if err != nil {
		storeError(w, err)
		return false
	}
	subject := principalFrom(ctx)
	if raw := r.Header.Get(sessionMFAHeader); raw != "" {
		tp, rerr := s.resolver.Resolve(ctx, raw)
		if rerr != nil || !tp.SessionMFATicket || tp.Name != subject.Name {
			return s.refuseSessionMFA(ctx, w, target, deniedAction, auth.ReasonSessionMFATicketInvalid, true)
		}
		subject = tp
	}
	factor, why, err := auth.CheckSessionMFA(ctx, s.store, subject, target.ID, required)
	if err != nil {
		storeError(w, err)
		return false
	}
	if why != "" {
		// A browser-extension token reaches exactly one route (authzExtOK) and
		// so can never mint a ticket — Phase 244 stated that limit, but the
		// refusal still told the caller to call a route its token is refused
		// at. Say what is actually true instead (Phase 248).
		if why == auth.ReasonSessionMFARequired && subject.NarrowScope() == auth.ScopeExtensionOnly {
			return s.refuseSessionMFA(ctx, w, target, deniedAction, auth.ReasonSessionMFAExtension, true)
		}
		return s.refuseSessionMFA(ctx, w, target, deniedAction, why, true)
	}
	if factor != "" {
		s.audit(ctx, "session.mfa_verified", "target:"+target.Name+" factor:"+factor+" path:"+path)
	}
	return true
}

// refuseSessionMFA audits a per-session MFA refusal under the path's own
// action and answers 403 with session_mfa_required, the flag the console reads
// to ask for the factor and retry — the shape login's mfa_required already has.
func (s *Server) refuseSessionMFA(ctx context.Context, w http.ResponseWriter, target *store.Target, action, reason string, viaHeader bool) bool {
	s.audit(ctx, action, "target:"+target.Name+" reason:"+reason)
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":                sessionMFAMessage(reason, viaHeader),
		"reason":               reason,
		"session_mfa_required": true,
	})
	return false
}

// sessionMFAMessage is the client-facing text for a refusal reason. viaHeader
// distinguishes the REST paths (ticket in a header) from the viewer (ticket as
// the tunnel token).
func sessionMFAMessage(reason string, viaHeader bool) string {
	switch reason {
	case auth.ReasonSessionMFATicketTarget:
		return "this session-MFA ticket was issued for a different target"
	case auth.ReasonSessionMFATicketUsed:
		return "this session-MFA ticket has already been used"
	case auth.ReasonSessionMFATicketInvalid:
		return "the session-MFA ticket is invalid, expired, or not yours"
	case auth.ReasonSessionMFAExtension:
		return "this target requires a second factor for every session, which the browser extension cannot present — reveal it in the portal instead"
	}
	if viaHeader {
		return "this target requires a second factor for every session — mint a ticket (POST /api/session-mfa) and send it in the " + sessionMFAHeader + " header"
	}
	return "this target requires a second factor for every session — mint a ticket (POST /api/session-mfa) and open the viewer with it"
}
