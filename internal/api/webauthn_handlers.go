package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/morandeirachema/pamv1/internal/store"
)

// webauthnChallengeTTL bounds how long a stored ceremony challenge stays
// takeable. This is pamv1's own deadline, computed independently of
// SessionData.Expires — the library only populates that field when
// Config.Timeouts.{Registration,Login}.Enforce is turned on, which pamv1
// does not set (there is no need to also configure the library's client-side
// timeout hint just to get a server-side expiry), so relying on it here would
// silently store an always-already-expired zero time.Time.
const webauthnChallengeTTL = 2 * time.Minute

// webauthnUser adapts a username and its registered credentials to the
// webauthn.User interface the library's ceremonies need. It is built fresh
// from a store read on every call — there is nothing to cache, since a
// credential list changes rarely and a stale copy would defeat the whole
// point of checking it.
type webauthnUser struct {
	username string
	creds    []store.WebAuthnCredential
}

// WebAuthnID returns a stable, opaque per-user handle derived deterministically
// from the username, so no separate "webauthn_users" table is needed the way
// the library's own storage guidance describes for a multi-RP-ID deployment —
// pamv1 has exactly one RP ID at a time (PAM_WEBAUTHN_RP_ID), so the same
// username always yields the same handle with nothing to persist.
func (u webauthnUser) WebAuthnID() []byte {
	h := sha256.Sum256([]byte("pamv1-webauthn-id:" + u.username))
	return h[:]
}

func (u webauthnUser) WebAuthnName() string        { return u.username }
func (u webauthnUser) WebAuthnDisplayName() string { return u.username }

func (u webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(u.creds))
	for _, c := range u.creds {
		out = append(out, webauthn.Credential{
			ID:                c.CredentialID,
			PublicKey:         c.PublicKey,
			AttestationType:   c.AttestationType,
			AttestationFormat: c.AttestationFormat,
			Authenticator: webauthn.Authenticator{
				AAGUID:       c.AAGUID,
				SignCount:    c.SignCount,
				CloneWarning: c.CloneWarning,
			},
		})
	}
	return out
}

// joinTransports serializes the transport hints a registration reports into
// the same comma-separated form WebAuthnCredential.Transports stores.
func joinTransports(ts []protocol.AuthenticatorTransport) string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = string(t)
	}
	return strings.Join(out, ",")
}

// webauthnRegisterBegin starts the registration ceremony for a new
// authenticator on the calling (already fully authenticated) identity. Any
// signed-in user may add one, the same self-service posture /api/mfa/enroll
// already has.
func (s *Server) webauthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if s.webAuthn == nil {
		writeError(w, http.StatusServiceUnavailable, "WebAuthn is not configured")
		return
	}
	p := principalFrom(r.Context())
	creds, err := s.store.ListWebAuthnCredentials(r.Context(), p.Name)
	if err != nil {
		storeError(w, err)
		return
	}
	creation, sess, err := s.webAuthn.BeginRegistration(webauthnUser{username: p.Name, creds: creds})
	if err != nil {
		s.log.Warn("webauthn: begin registration failed", "user", p.Name, "err", err)
		writeError(w, http.StatusInternalServerError, "could not begin registration")
		return
	}
	sessJSON, err := json.Marshal(sess)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.store.PutWebAuthnChallenge(r.Context(), p.Name, "register", sessJSON, time.Now().Add(webauthnChallengeTTL)); err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

// webauthnRegisterFinish completes registration: verifies the browser's
// response against the stored challenge, then persists the new credential. A
// nickname may be supplied as ?name= (the request body is reserved for the
// raw WebAuthn client response the library parses directly).
func (s *Server) webauthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if s.webAuthn == nil {
		writeError(w, http.StatusServiceUnavailable, "WebAuthn is not configured")
		return
	}
	p := principalFrom(r.Context())
	raw, ok, err := s.store.TakeWebAuthnChallenge(r.Context(), p.Name, "register", time.Now())
	if err != nil {
		storeError(w, err)
		return
	}
	if !ok {
		writeError(w, http.StatusBadRequest, "no registration in progress, or it expired — start again")
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
	cred, err := s.webAuthn.FinishRegistration(webauthnUser{username: p.Name, creds: creds}, sess, r)
	if err != nil {
		s.audit(r.Context(), "mfa.webauthn_register_failed", "reason:"+auditField(err.Error(), 128))
		writeError(w, http.StatusBadRequest, "registration failed: "+err.Error())
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Authenticator"
	}
	wc := store.WebAuthnCredential{
		Username:          p.Name,
		CredentialID:      cred.ID,
		PublicKey:         cred.PublicKey,
		AttestationType:   cred.AttestationType,
		AttestationFormat: cred.AttestationFormat,
		Transports:        joinTransports(cred.Transport),
		AAGUID:            cred.Authenticator.AAGUID,
		SignCount:         cred.Authenticator.SignCount,
		CloneWarning:      cred.Authenticator.CloneWarning,
		Name:              auditField(name, 64),
	}
	if err := s.store.CreateWebAuthnCredential(r.Context(), &wc); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "mfa.webauthn_registered", fmt.Sprintf("id:%d name:%s", wc.ID, wc.Name))
	writeJSON(w, http.StatusCreated, wc)
}

// webauthnListCredentials returns the caller's own registered authenticators.
func (s *Server) webauthnListCredentials(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	creds, err := s.store.ListWebAuthnCredentials(r.Context(), p.Name)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": creds})
}

// webauthnDeleteCredential removes one of the caller's own authenticators.
// Scoped to username at the store layer, so an id cannot delete someone
// else's credential even if guessed.
func (s *Server) webauthnDeleteCredential(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteWebAuthnCredential(r.Context(), id, p.Name); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "mfa.webauthn_deleted", fmt.Sprintf("id:%d", id))
	w.WriteHeader(http.StatusNoContent)
}

// webauthnLoginBegin starts the assertion ceremony for a password-verified,
// MFA-pending login (see login() in authn.go and the mfaPendingOnly
// middleware — the caller's identity comes from that narrow session, never
// from a client-supplied username).
func (s *Server) webauthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	if s.webAuthn == nil {
		writeError(w, http.StatusServiceUnavailable, "WebAuthn is not configured")
		return
	}
	p := principalFrom(r.Context())
	creds, err := s.store.ListWebAuthnCredentials(r.Context(), p.Name)
	if err != nil {
		storeError(w, err)
		return
	}
	if len(creds) == 0 {
		// Should not happen — login() only mints an MFAPending session when
		// creds already exist — but a credential could be deleted mid-ceremony.
		writeError(w, http.StatusBadRequest, "no WebAuthn credentials registered")
		return
	}
	assertion, sess, err := s.webAuthn.BeginLogin(webauthnUser{username: p.Name, creds: creds})
	if err != nil {
		s.log.Warn("webauthn: begin login failed", "user", p.Name, "err", err)
		writeError(w, http.StatusInternalServerError, "could not begin login")
		return
	}
	sessJSON, err := json.Marshal(sess)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.store.PutWebAuthnChallenge(r.Context(), p.Name, "login", sessJSON, time.Now().Add(webauthnChallengeTTL)); err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

// webauthnLoginFinish verifies the browser's assertion and, on success,
// issues a full session token — the same shape login() returns for TOTP,
// so the console's post-login handling does not need to know which factor
// was used.
func (s *Server) webauthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	if s.webAuthn == nil {
		writeError(w, http.StatusServiceUnavailable, "WebAuthn is not configured")
		return
	}
	p := principalFrom(r.Context())
	raw, ok, err := s.store.TakeWebAuthnChallenge(r.Context(), p.Name, "login", time.Now())
	if err != nil {
		storeError(w, err)
		return
	}
	if !ok {
		s.auditAs(r.Context(), p.Name, "login.failed", "reason:webauthn-challenge-expired")
		writeError(w, http.StatusUnauthorized, "login expired — sign in again")
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
		s.log.Warn("webauthn login failed", "user", p.Name, "remote", r.RemoteAddr, "err", err)
		s.auditAs(r.Context(), p.Name, "login.failed", "reason:webauthn remote:"+r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "webauthn verification failed")
		return
	}
	// Write back the sign counter and clone-warning flag — required on every
	// successful login, not just at registration, so the next assertion is
	// checked against the current value rather than a stale one.
	if stored, gerr := s.store.GetWebAuthnCredentialByCredentialID(r.Context(), cred.ID); gerr == nil && stored.Username == p.Name {
		if uerr := s.store.UpdateWebAuthnSignCount(r.Context(), stored.ID, cred.Authenticator.SignCount, cred.Authenticator.CloneWarning, time.Now()); uerr != nil {
			s.log.Warn("webauthn: sign-count write-back failed", "user", p.Name, "credential_id", stored.ID, "err", uerr)
		}
		if cred.Authenticator.CloneWarning {
			s.log.Warn("webauthn: possible cloned authenticator", "user", p.Name, "credential_id", stored.ID)
		}
	}
	token, fullSess, err := s.issueSession(r.Context(), p, "")
	if err != nil {
		storeError(w, err)
		return
	}
	setActor(r.Context(), p.Name)
	s.audit(withPrincipal(r.Context(), p), "login", fmt.Sprintf("user:%s role:%s factor:webauthn", p.Name, p.Role))
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":      token,
		"username":   p.Name,
		"role":       p.Role,
		"expires_at": fullSess.ExpiresAt,
	})
}
