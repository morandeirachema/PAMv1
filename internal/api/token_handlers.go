package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/morandeirachema/pamv1/internal/agentid"
)

// maxExchangeBodyBytes bounds an RFC 8693 form body. Two JWTs and a handful of
// short parameters; anything larger is not a token exchange.
const maxExchangeBodyBytes = 64 << 10

// exchangeToken is the broker's RFC 8693 token-exchange endpoint (Phase 57):
// an agent delegates its own authority to a sub-agent and receives a
// broker-signed, short-lived delegated JWT-SVID whose actor chain grows by
// exactly one link. Phase 13 shipped only the verifying half of delegation;
// this is the minting half, and it is what makes the accountability chain the
// audit trail records something pamv1 can *issue* rather than only *observe*.
//
// It authenticates like every other broker call (agentAuth), so the delegator
// is the authenticated caller — never a token in the body. That is the
// difference between delegating your own authority and minting a delegation
// between two credentials you merely hold.
//
// Refusals follow RFC 6749 §5.2: HTTP 400 with `{"error", "error_description"}`
// — deliberately unlike the broker's tool-call contract (HTTP 200 carrying a
// decision), because this is an OAuth endpoint and OAuth clients parse OAuth
// errors. 401 is left to agentAuth.
func (s *Server) exchangeToken(w http.ResponseWriter, r *http.Request, id *agentid.Identity) {
	if s.exchanger == nil {
		writeError(w, http.StatusNotFound, "token exchange is not enabled")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxExchangeBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeExchangeError(w, "invalid_request", "body must be application/x-www-form-urlencoded")
		return
	}
	req, err := agentid.ParseExchangeForm(r.PostForm)
	if err != nil {
		writeExchangeErr(w, err)
		return
	}
	issued, err := s.exchanger.Exchange(r.Context(), req, id)
	if err != nil {
		// Audit the refusal too: a stream of refused exchanges is what a runaway
		// or probing agent looks like, and it is invisible if only successes are
		// recorded. Best-effort — a refusal has no side effect to gate.
		s.audit(r.Context(), "broker.token.refused", fmt.Sprintf("delegator:%s reason:%s",
			auditField(id.AgentName, 128), auditField(exchangeCode(err), 64)))
		writeExchangeErr(w, err)
		return
	}
	// Fail closed BEFORE handing over the token. A delegated credential that
	// exists with no record of who delegated it to whom is precisely the gap this
	// endpoint was built to close — the same rule the SSH certificate issue path
	// and every secret-delivery path already follow (invariant §6.4).
	if !s.mustAudit(w, r.Context(), "broker.token.exchanged", auditField(issued.Audit, 512)) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      issued.Token,
		"issued_token_type": agentid.TokenTypeJWT,
		"token_type":        "N_A", // RFC 8693 §2.2.1: the issued token is not a bearer for another audience
		"expires_in":        issued.ExpiresIn,
	})
}

// exchangeCode extracts the RFC 6749 error code from an exchange failure.
func exchangeCode(err error) string {
	if e, ok := err.(*agentid.ExchangeError); ok {
		return e.Code
	}
	return "invalid_request"
}

// writeExchangeErr renders an *agentid.ExchangeError (or any other error, as a
// generic invalid_request) in RFC 6749 §5.2 shape.
func writeExchangeErr(w http.ResponseWriter, err error) {
	if e, ok := err.(*agentid.ExchangeError); ok {
		writeExchangeError(w, e.Code, e.Description)
		return
	}
	writeExchangeError(w, "invalid_request", "the token exchange request was refused")
}

// writeExchangeError writes an RFC 6749 §5.2 error body.
func writeExchangeError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusBadRequest, map[string]string{
		"error": code, "error_description": description,
	})
}

// tokenJWKS publishes the public half of the token-exchange signing key as a
// JWKS, so an auditor holding a delegated token from the trail can confirm which
// key signed it — and confirm a rotation actually changed the key. Gated on
// CapReadAudit like the broker audit chain's JWKS: the broker is the only party
// that needs these keys to verify anything, so publishing them wider buys
// nothing.
func (s *Server) tokenJWKS(w http.ResponseWriter, r *http.Request) {
	if s.exchanger == nil {
		writeError(w, http.StatusNotFound, "token exchange is not enabled")
		return
	}
	pub := s.exchanger.PublicKey()
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
			"kid": s.exchanger.KeyID(),
			"x":   base64.RawURLEncoding.EncodeToString(ed25519.PublicKey(pub)),
		}},
	})
}
