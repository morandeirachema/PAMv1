package api

import (
	"net/http"
	"net/url"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/saml"
)

// samlStateTTL bounds an in-flight SAML login: the AuthnRequest ID is persisted
// in the store (keyed by the ID itself, through the same single-use, expiring
// login-state table the OIDC flow uses) so the ACS POST can land on any replica
// (HA), and the same TTL the OIDC state uses.
const samlStateTTL = oidcStateTTL

// samlStateCookie binds an in-flight SAML login to the browser that started it:
// the Response's InResponseTo must equal this cookie's value, so an attacker
// cannot complete their own IdP login in a victim's browser (login CSRF /
// session fixation) — the same defence the OIDC state cookie provides.
const samlStateCookie = "pam_saml_state"

// samlStateMarker is what the shared login-state table stores in the OIDC
// "verifier" slot for a SAML request ID, so a SAML ID can never be consumed by
// the OIDC callback and vice versa: the callback that takes the row checks the
// marker matches its own protocol.
const samlStateMarker = "saml"

// setSAMLStateCookie writes (maxAge > 0) or clears (maxAge < 0) the SAML state
// cookie. Unlike the OIDC callback, which is a top-level GET the IdP redirects
// to, the ACS is a cross-site top-level POST from the IdP's page — a
// SameSite=Lax cookie is not sent on it, so over TLS the cookie is
// SameSite=None + Secure (the only combination browsers accept cross-site).
// Over plain HTTP, SameSite=None would be refused outright by browsers, so the
// attribute is left unset there and the browser's default handling applies —
// which in practice (Chrome's "Lax + POST" allowance) still carries a cookie
// set within the last two minutes, enough for a login round trip in a
// development deployment. Every real deployment terminates TLS.
func setSAMLStateCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	c := &http.Cookie{ // #nosec G124 -- Secure conditional on TLS (requestIsHTTPS); HttpOnly always; SameSite=None is required for the cross-site ACS POST and browsers only honour it with Secure
		Name: samlStateCookie, Value: value, Path: saml.StatePath,
		MaxAge: maxAge, HttpOnly: true,
	}
	if requestIsHTTPS(r) {
		c.Secure = true
		c.SameSite = http.SameSiteNoneMode
	}
	http.SetCookie(w, c)
}

// samlStart mints an AuthnRequest, remembers its ID (store + browser cookie) and
// redirects the browser to the IdP.
func (s *Server) samlStart(w http.ResponseWriter, r *http.Request) {
	sp := s.rt().saml // snapshot once (a concurrent hot-swap could null it)
	if sp == nil {
		writeError(w, http.StatusNotFound, "SAML login is not configured")
		return
	}
	redirect, requestID, err := sp.StartURL()
	if err != nil {
		s.log.Error("saml start failed", "err", err)
		writeError(w, http.StatusInternalServerError, "saml init failed")
		return
	}
	if err := s.store.PutOIDCState(r.Context(), requestID, samlStateMarker, "", time.Now().Add(samlStateTTL)); err != nil {
		writeError(w, http.StatusInternalServerError, "saml init failed")
		return
	}
	setSAMLStateCookie(w, r, requestID, int(samlStateTTL.Seconds()))
	http.Redirect(w, r, redirect, http.StatusFound)
}

// samlACS is the Assertion Consumer Service: it receives the IdP's HTTP-POST
// Response, binds it to the browser that started the login (cookie), consumes
// the single-use request ID (store), validates the signed assertion end to end,
// maps the group claims to a role and issues a session, then redirects back to
// the portal with the token in the URL fragment — the same landing the OIDC
// callback uses, so the portal needs no SAML-specific code.
func (s *Server) samlACS(w http.ResponseWriter, r *http.Request) {
	rt := s.rt() // snapshot once: provider and role map from the same config generation
	sp := rt.saml
	if sp == nil {
		writeError(w, http.StatusNotFound, "SAML login is not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, saml.MaxResponseBytes+4096)
	if err := r.ParseForm(); err != nil {
		s.redirectPortal(w, r, "pam_error=login_failed")
		return
	}
	// Bind to the initiating browser first: without the cookie there is no
	// request ID to check the Response against, and a foreign POST must not be
	// able to burn a legitimate in-flight login.
	sc, cerr := r.Cookie(samlStateCookie)
	setSAMLStateCookie(w, r, "", -1)
	if cerr != nil || sc.Value == "" {
		s.log.Warn("saml acs: no state cookie", "remote", r.RemoteAddr)
		s.redirectPortal(w, r, "pam_error=invalid_state")
		return
	}
	requestID := sc.Value
	marker, _, ok, err := s.store.TakeOIDCState(r.Context(), requestID, time.Now())
	if err != nil {
		s.log.Error("saml state lookup failed", "err", err)
		s.redirectPortal(w, r, "pam_error=login_failed")
		return
	}
	if !ok || marker != samlStateMarker {
		s.log.Warn("saml acs: invalid or replayed state", "remote", r.RemoteAddr)
		s.redirectPortal(w, r, "pam_error=invalid_state")
		return
	}
	claims, err := sp.ParseResponse(r.PostForm.Get("SAMLResponse"), requestID)
	if err != nil {
		s.log.Warn("saml response rejected", "err", err, "remote", r.RemoteAddr)
		s.redirectPortal(w, r, "pam_error=login_failed")
		return
	}
	role, roles, ok := auth.MatchedRoles(claims.Groups, rt.samlRoleMap)
	if !ok {
		s.log.Warn("saml login: no mapped role", "user", claims.Name)
		s.redirectPortal(w, r, "pam_error=no_role")
		return
	}
	if claims.Name == "" {
		s.log.Warn("saml login: assertion carries no usable subject")
		s.redirectPortal(w, r, "pam_error=login_failed")
		return
	}
	principal := &auth.Principal{Name: claims.Name, Role: role, Roles: roles}
	token, _, err := s.issueSession(r.Context(), principal, "")
	if err != nil {
		s.redirectPortal(w, r, "pam_error=session_failed")
		return
	}
	setActor(r.Context(), principal.Name)
	s.audit(withPrincipal(r.Context(), principal), "login",
		"user:"+principal.Name+" via:saml role:"+string(role)+" idp:"+auditField(sp.IDPEntityID(), 256))
	s.redirectPortal(w, r, "pam_token="+url.QueryEscape(token))
}

// samlMetadata serves the SP metadata document the IdP administrator imports
// to register pamv1 as a relying party. Public and unauthenticated by design —
// it holds only the entity ID, the ACS URL and (if configured) the SP's public
// certificate, all of which the IdP must know before any login can happen.
func (s *Server) samlMetadata(w http.ResponseWriter, r *http.Request) {
	sp := s.rt().saml
	if sp == nil {
		writeError(w, http.StatusNotFound, "SAML login is not configured")
		return
	}
	md, err := sp.Metadata()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "saml metadata failed")
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(md)
}
