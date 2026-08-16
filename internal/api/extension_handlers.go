package api

import (
	"net/http"

	"github.com/morandeirachema/pamv1/internal/auth"
)

// extensionToken mints a browser-extension autofill token (Phase 147): it
// inherits the caller's own identity and capabilities, exactly like an
// RDP/VNC viewer token (issueSessionTTL), but with s.extensionTokenTTL's
// hours-to-days lifetime instead of rdpTokenTTL's seconds, since this token
// lives in the extension's own local storage rather than a URL.
//
// Requires CapRevealSecret — the same capability the reveal route itself
// requires — so a principal who could never use the token is refused before
// one is ever minted, not just when it is first used. The minted token is
// refused everywhere except POST /api/credentials/{id}/reveal (authzExtOK);
// Can(cap) still applies there normally.
func (s *Server) extensionToken(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	token, sess, err := s.issueSessionTTL(r.Context(), p, auth.SessionScopeExtension, s.extensionTokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not mint extension token")
		return
	}
	s.audit(r.Context(), "extension.token_issued", "ttl:"+s.extensionTokenTTL.String())
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expires_at": sess.ExpiresAt})
}
