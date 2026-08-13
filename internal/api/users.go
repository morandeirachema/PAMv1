package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

type userIn struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	// IPAllowlist optionally restricts this user to a comma-separated set of
	// CIDR blocks (Phase 118), e.g. "10.0.0.0/8, 192.168.1.0/24". Empty (the
	// default) means unrestricted.
	IPAllowlist string `json:"ip_allowlist,omitempty"`
}

// createUser mints a new local identity and returns its access token exactly
// once. Only the token's SHA-256 is stored; the plaintext is never persisted.
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in userIn
	if !readJSON(w, r, &in) {
		return
	}
	// The role is a built-in role or an existing custom profile (Phase 12).
	grantCaps, err := s.capsForGrant(r.Context(), in.Role)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, `role must be a built-in role (admin|user|auditor|approver) or an existing profile`)
		return
	}
	// You cannot mint a user more capable than yourself (privilege-escalation
	// guard for delegated user-admins). The bootstrap/break-glass admin holds
	// every capability and so is unconstrained.
	if !principalFrom(r.Context()).Covers(grantCaps) {
		writeError(w, http.StatusForbidden, "cannot assign a role or profile with capabilities you do not hold")
		return
	}
	if !checkName(w, "username", in.Username) {
		return
	}
	if err := auth.ValidateCIDRList(in.IPAllowlist); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	token, err := generateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	u := store.User{Username: in.Username, Role: in.Role, IPAllowlist: in.IPAllowlist, TokenHash: hashHex(token)}
	if err := s.store.CreateUser(r.Context(), &u); err != nil {
		storeError(w, err)
		return
	}
	createDetail := fmt.Sprintf("%s role:%s", u.Username, u.Role)
	if u.IPAllowlist != "" {
		createDetail += " ip_allowlist:" + auditField(u.IPAllowlist, 128)
	}
	s.audit(r.Context(), "user.create", createDetail)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":           u.ID,
		"username":     u.Username,
		"role":         u.Role,
		"ip_allowlist": u.IPAllowlist,
		"token":        token, // shown once; store it now
	})
}

// listUsers returns a page of the local users (?limit=&after=); token hashes
// are never serialized.

// updateUser changes a user's role/profile and, optionally, IP allowlist in
// place, so a promotion or demotion no longer means delete + re-mint (which
// would revoke the token). The same privilege-escalation guard as createUser
// applies: you cannot assign capabilities you do not hold. The username and
// token are immutable. IPAllowlist is a *string so a caller can distinguish
// "omitted, leave it alone" (nil) from "explicitly clear it" (a pointer to
// "") — unlike Role, which every caller already sends every time (an omitted
// Role fails capsForGrant loudly), silently treating an omitted IPAllowlist
// as "clear the restriction" would be a security-relevant field failing open
// on a caller that simply didn't know about it.
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in struct {
		Role        string  `json:"role"`
		IPAllowlist *string `json:"ip_allowlist"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	grantCaps, err := s.capsForGrant(r.Context(), in.Role)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, `role must be a built-in role (admin|user|auditor|approver) or an existing profile`)
		return
	}
	if !principalFrom(r.Context()).Covers(grantCaps) {
		writeError(w, http.StatusForbidden, "cannot assign a role or profile with capabilities you do not hold")
		return
	}
	if in.IPAllowlist != nil {
		if err := auth.ValidateCIDRList(*in.IPAllowlist); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
	}
	u, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	if err := s.store.UpdateUserRole(r.Context(), id, in.Role); err != nil {
		storeError(w, err)
		return
	}
	auditDetail := fmt.Sprintf("%s role:%s->%s", u.Username, u.Role, in.Role)
	if in.IPAllowlist != nil {
		if err := s.store.UpdateUserIPAllowlist(r.Context(), id, *in.IPAllowlist); err != nil {
			storeError(w, err)
			return
		}
		auditDetail += fmt.Sprintf(" ip_allowlist:%s->%s", auditField(u.IPAllowlist, 128), auditField(*in.IPAllowlist, 128))
		u.IPAllowlist = *in.IPAllowlist
	}
	s.audit(r.Context(), "user.update", auditDetail)
	u.Role = in.Role
	writeJSON(w, http.StatusOK, u)
}

// deleteUser removes a user by id and audits it.
func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "user.delete", strconv.FormatInt(id, 10))
	w.WriteHeader(http.StatusNoContent)
}

// listLoginSessions returns all active password/SSO login sessions (never their
// token hashes), so an admin can see who is logged in and revoke them. This is
// distinct from GET /api/sessions, which lists live proxied target sessions.
func (s *Server) listLoginSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.store.ListSessions(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

// revokeLoginSessions force-invalidates every active login session for a username
// — the admin control missing for directory (AD/SSO) logins, which create session
// rows rather than user rows and so survive a directory disable until they expire.
func (s *Server) revokeLoginSessions(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !checkName(w, "username", in.Username) {
		return
	}
	n, err := s.store.DeleteSessionsByUsername(r.Context(), in.Username)
	if err != nil {
		storeError(w, err)
		return
	}
	// Revoking a login cuts the user off entirely — also terminate any in-flight
	// proxied target sessions they hold, not just their login tokens.
	killed := s.killUserSessions(r.Context(), in.Username, "login-revoked")
	s.audit(r.Context(), "session.revoked", fmt.Sprintf("user:%s sessions:%d killed:%d", in.Username, n, killed))
	writeJSON(w, http.StatusOK, map[string]any{"username": in.Username, "revoked": n, "killed": killed})
}

// killUserSessions terminates every live proxied session an actor holds (via the
// shared session registry) and audits it. Returns how many were killed; a no-op
// when no registry is wired. Note: the registry is per-replica, so in an HA
// deployment this cuts sessions on this replica only.
func (s *Server) killUserSessions(ctx context.Context, username, reason string) int {
	if s.sessions == nil {
		return 0
	}
	killed := s.sessions.KillByActor(username)
	// Audited unconditionally. The count is what THIS replica killed, but the kill
	// is broadcast cluster-wide, so killed == 0 routinely means "the sessions are on
	// another replica" rather than "there was nothing to cut" — and recording only
	// the non-zero case left the most consequential HA outcome, a termination that
	// took effect elsewhere, with no evidence on the deciding side. The applying
	// replica records session.kill via:bus; this is the intent half.
	s.audit(ctx, "session.killed", fmt.Sprintf("user:%s killed_here:%d reason:%s", username, killed, reason))
	return killed
}

// capsForGrant resolves a built-in role name or an existing custom profile name
// to the capability set it would confer on a user, or an error if the name is
// neither. Used to bound what a caller may grant.
func (s *Server) capsForGrant(ctx context.Context, name string) (auth.CapSet, error) {
	if role, err := auth.ParseRole(name); err == nil {
		return role.CapabilitySet(), nil
	}
	prof, err := s.store.GetProfile(ctx, name)
	if err != nil {
		return nil, err
	}
	return auth.ParseCapabilities(prof.Capabilities)
}

// generateToken returns a new random access token with the "pamt_" prefix.
func generateToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "pamt_" + hex.EncodeToString(b), nil
}

// --- live sessions (listing + kill-switch) ---

// listSessions returns the live proxy/RDP sessions, or an empty list when no
// session registry is wired.
