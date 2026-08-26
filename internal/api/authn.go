package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/mfa"
	"github.com/morandeirachema/pamv1/internal/store"
)

const sessionTTL = 12 * time.Hour

// mfaPendingTTL bounds how long a password-verified, WebAuthn-pending login
// has to complete the ceremony — generous enough for a user to be prompted by
// their browser and touch a physical key, short enough that an abandoned
// attempt does not linger as a live, if narrow, credential.
const mfaPendingTTL = 5 * time.Minute

type loginIn struct {
	Username string `json:"username"`
	Password string `json:"password"`
	OTP      string `json:"otp"`
}

// login verifies a username + password against the configured identity source
// (e.g. Active Directory) and issues a short-lived session token. The token is
// used as X-API-Key (portal) or the SSH proxy password, exactly like a per-user
// token — its role comes from the user's directory groups.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	// Snapshot the runtime config once: a concurrent hot-swap (e.g. clearing the
	// LDAP override) could otherwise null authn between the nil-check and the call.
	rt := s.rt()
	if rt.authn == nil {
		writeError(w, http.StatusServiceUnavailable, "password login is not configured")
		return
	}
	var in loginIn
	if !readJSON(w, r, &in) {
		return
	}
	principal, err := rt.authn.Authenticate(r.Context(), in.Username, in.Password)
	if err != nil {
		s.log.Warn("login failed", "user", in.Username, "remote", r.RemoteAddr)
		// The username is UNAUTHENTICATED client input here — a failed login,
		// so nothing has vouched for it. It becomes the audit `actor`, which the
		// SIEM forwarder renders unquoted, so an unbounded value like
		// `alice detail=routine` would inject a competing field into every
		// forwarded record (2026-08-26 audit, M-2). Bound and quote it, exactly
		// as the SSH proxy already does with c.User() on the identical input.
		s.auditAs(r.Context(), auditField(in.Username, 64), "login.failed", "reason:credentials remote:"+r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	enr, mfaErr := s.store.GetMFAEnrollment(r.Context(), principal.Name)
	if mfaErr != nil && !errors.Is(mfaErr, store.ErrNotFound) {
		// A store error must not silently downgrade a confirmed-MFA user to
		// password-only login — fail closed.
		storeError(w, mfaErr)
		return
	}
	// A user with confirmed TOTP is checked above WebAuthn deliberately: TOTP
	// fits in this one request (password+otp together), so leaving its branch
	// untouched keeps every existing TOTP user's login byte-for-byte the same.
	// WebAuthn only gets a look-in for a user with NO confirmed TOTP.
	var webauthnCreds []store.WebAuthnCredential
	if s.webAuthn != nil {
		var werr error
		webauthnCreds, werr = s.store.ListWebAuthnCredentials(r.Context(), principal.Name)
		if werr != nil {
			storeError(w, werr)
			return
		}
	}
	switch {
	case mfaErr == nil && enr.Confirmed:
		// User has MFA — require a valid code (or a single-use recovery code).
		if in.OTP == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "multi-factor code required", "mfa_required": true,
			})
			return
		}
		if !s.checkSecondFactor(r.Context(), principal.Name, enr, in.OTP) {
			s.log.Warn("mfa failed", "user", principal.Name, "remote", r.RemoteAddr)
			s.auditAs(r.Context(), principal.Name, "login.failed", "reason:mfa remote:"+r.RemoteAddr)
			writeError(w, http.StatusUnauthorized, "invalid multi-factor code")
			return
		}
	case len(webauthnCreds) > 0:
		// Password verified; this user's second factor is WebAuthn, which
		// cannot fit in one request — BeginLogin needs to build a challenge
		// scoped to their credentials first. Mint a narrow MFAPending session
		// (usable for nothing but POST /api/webauthn/login/begin|finish) rather
		// than trusting a client-supplied username on a later, separate call —
		// that would let an unauthenticated caller enumerate who has WebAuthn
		// enrolled just by asking.
		token, _, err := s.issueSessionTTL(r.Context(), principal, auth.SessionScopeMFAPending, mfaPendingTTL)
		if err != nil {
			storeError(w, err)
			return
		}
		setActor(r.Context(), principal.Name)
		s.audit(withPrincipal(r.Context(), principal), "login", "user:"+principal.Name+" scope:mfa_pending")
		writeJSON(w, http.StatusOK, map[string]any{
			"webauthn_required": true,
			"token":             token,
			"username":          principal.Name,
		})
		return
	case rt.mfaRequired:
		// Policy requires MFA but the user has none yet: issue an
		// enrollment-only session so they can set it up, nothing else.
		token, _, err := s.issueSession(r.Context(), principal, auth.SessionScopeEnroll)
		if err != nil {
			storeError(w, err)
			return
		}
		setActor(r.Context(), principal.Name)
		s.audit(withPrincipal(r.Context(), principal), "login", "user:"+principal.Name+" scope:enroll")
		writeJSON(w, http.StatusOK, map[string]any{
			"mfa_enrollment_required": true,
			"token":                   token,
			"username":                principal.Name,
			"role":                    principal.Role,
		})
		return
	}

	token, sess, err := s.issueSession(r.Context(), principal, "")
	if err != nil {
		storeError(w, err)
		return
	}
	setActor(r.Context(), principal.Name)
	s.audit(withPrincipal(r.Context(), principal), "login",
		fmt.Sprintf("user:%s role:%s", principal.Name, principal.Role))
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":      token,
		"username":   principal.Name,
		"role":       principal.Role,
		"expires_at": sess.ExpiresAt,
	})
}

// issueSession mints a session token (scope "" = full, "enroll" = MFA setup only).
func (s *Server) issueSession(ctx context.Context, p *auth.Principal, scope string) (string, store.Session, error) {
	return s.issueSessionTTL(ctx, p, scope, sessionTTL)
}

// issueSessionTTL mints a session token with an explicit lifetime (break-glass
// sessions use a short TTL).
func (s *Server) issueSessionTTL(ctx context.Context, p *auth.Principal, scope string, ttl time.Duration) (string, store.Session, error) {
	token, err := generateToken()
	if err != nil {
		return "", store.Session{}, err
	}
	// Persist the full matched role set only when it's a genuine multi-group union
	// (more than the primary role), so single-role sessions stay unchanged.
	roles := ""
	if len(p.Roles) > 1 {
		roles = auth.JoinRoles(p.Roles)
	}
	sess := store.Session{
		Username:  p.Name,
		Role:      string(p.Role),
		Roles:     roles,
		Scope:     scope,
		TokenHash: hashHex(token),
		ExpiresAt: time.Now().Add(ttl).UTC(),
	}
	if err := s.store.CreateSession(ctx, &sess); err != nil {
		return "", store.Session{}, err
	}
	return token, sess, nil
}

// me returns the calling identity — name, role, break-glass flag, and the stable
// names of the capabilities its role holds — so the portal can show only the menu
// options the identity may use (panels still tolerate a 403 as defense in depth).
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"name":         p.Name,
		"role":         string(p.Role),
		"break_glass":  p.BreakGlass,
		"capabilities": p.CapabilityNames(),
	})
}

// checkSecondFactor accepts a valid TOTP code or a single-use recovery code.
func (s *Server) checkSecondFactor(ctx context.Context, username string, enr *store.MFAEnrollment, otp string) bool {
	if secret, err := s.vault.Decrypt(ctx, enr.SecretEnc, store.MFAAAD(username)); err == nil {
		if step, ok := mfa.ValidateStep(secret, otp, time.Now()); ok {
			// Anti-replay: accept a valid code only if its time-step has not been
			// used yet. The replay guard is a security control, so a store error
			// that prevents recording the step must fail closed (reject), not accept.
			consumed, cerr := s.store.ConsumeTOTPStep(ctx, username, step)
			if cerr != nil {
				s.log.Warn("totp replay check failed; rejecting code", "user", username, "err", cerr)
				return false
			}
			return consumed
		}
	}
	code := strings.ToLower(strings.TrimSpace(otp))
	if consumed, err := s.store.ConsumeMFARecoveryCode(ctx, username, hashHex(code)); err == nil && consumed {
		s.audit(ctx, "mfa.recovery_used", "user:"+username)
		return true
	}
	return false
}

// hashHex returns the hex-encoded SHA-256 of s. Used to derive the lookup hashes
// stored for session/user tokens and recovery codes (plaintext is never stored).
// It delegates to auth.TokenHash so every token-hashing site shares one
// definition — see the rationale there.
func hashHex(s string) string { return auth.TokenHash(s) }

// logout revokes the caller's own session token.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	// ErrNotFound is fine — bootstrap/token identities have no session row — but a
	// real store error must not be reported as a successful revocation.
	err := s.store.DeleteSession(r.Context(), hashHex(r.Header.Get("X-API-Key")))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "logout", actorFrom(r.Context()))
	w.WriteHeader(http.StatusNoContent)
}

// --- multi-factor authentication (TOTP) ---

// mfaEnroll generates a new TOTP secret for the caller and returns it once
// (plus an otpauth:// URI for the authenticator app). The enrollment is
// unconfirmed until the user proves a code via mfaVerify.
