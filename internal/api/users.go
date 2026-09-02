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
	// DeviceFingerprint optionally binds this user to one enrolled
	// client-certificate fingerprint (Phase 133), checked against
	// PAM_DEVICE_HEADER's value at HTTP authz time. Empty (the default)
	// means unbound.
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
	// SlackUserID optionally links this user to one Slack member ID (Phase
	// 236, e.g. "U0123456789"), the only way a Slack button click can decide
	// an access request as this user. Empty (the default) means the user
	// cannot decide from Slack.
	SlackUserID string `json:"slack_user_id,omitempty"`
}

// maxSlackUserIDLen bounds a linked Slack member ID. Real ids are "U" or
// "W" followed by 8–10 alphanumerics; this is a sanity cap, not a format
// check, so an enterprise-grid or future id shape is not refused.
const maxSlackUserIDLen = 64

// validSlackUserID refuses a member id that could not be one: too long, or
// carrying whitespace/control characters that an audit detail or a lookup
// key must never contain.
func validSlackUserID(w http.ResponseWriter, id string) bool {
	if len(id) > maxSlackUserIDLen {
		writeError(w, http.StatusUnprocessableEntity, "slack_user_id is too long")
		return false
	}
	for _, c := range id {
		if c <= ' ' || c == 0x7f {
			writeError(w, http.StatusUnprocessableEntity, "slack_user_id must not contain whitespace or control characters")
			return false
		}
	}
	return true
}

// maxDeviceFingerprintLen bounds the enrolled fingerprint's stored length.
// There is no single canonical format across reverse proxies (a SHA-1 hex
// digest is 40 chars, SHA-256 is 64, some inject colon separators), so this
// is a sanity cap against an abusive value, not a format check.
const maxDeviceFingerprintLen = 256

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
	if len(in.DeviceFingerprint) > maxDeviceFingerprintLen {
		writeError(w, http.StatusUnprocessableEntity, "device_fingerprint is too long")
		return
	}
	if !validSlackUserID(w, in.SlackUserID) {
		return
	}
	token, err := generateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	u := store.User{Username: in.Username, Role: in.Role, IPAllowlist: in.IPAllowlist, DeviceFingerprint: in.DeviceFingerprint, SlackUserID: in.SlackUserID, TokenHash: hashHex(token)}
	if err := s.store.CreateUser(r.Context(), &u); err != nil {
		storeError(w, err)
		return
	}
	createDetail := fmt.Sprintf("%s role:%s", u.Username, u.Role)
	if u.IPAllowlist != "" {
		createDetail += " ip_allowlist:" + auditField(u.IPAllowlist, 128)
	}
	if u.DeviceFingerprint != "" {
		createDetail += " device_fingerprint:" + auditField(u.DeviceFingerprint, 128)
	}
	if u.SlackUserID != "" {
		createDetail += " slack_user_id:" + auditField(u.SlackUserID, 64)
	}
	s.audit(r.Context(), "user.create", createDetail)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":                 u.ID,
		"username":           u.Username,
		"role":               u.Role,
		"ip_allowlist":       u.IPAllowlist,
		"device_fingerprint": u.DeviceFingerprint,
		"slack_user_id":      u.SlackUserID,
		"token":              token, // shown once; store it now
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
		Role              string  `json:"role"`
		IPAllowlist       *string `json:"ip_allowlist"`
		DeviceFingerprint *string `json:"device_fingerprint"`
		SlackUserID       *string `json:"slack_user_id"`
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
	if in.DeviceFingerprint != nil && len(*in.DeviceFingerprint) > maxDeviceFingerprintLen {
		writeError(w, http.StatusUnprocessableEntity, "device_fingerprint is too long")
		return
	}
	if in.SlackUserID != nil && !validSlackUserID(w, *in.SlackUserID) {
		return
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
	if u.Role != in.Role {
		// A session carries the role it was minted with, so the old role would
		// otherwise keep acting through it until it expired (2026-08-27 audit).
		s.cutUserAccess(r.Context(), u.Username, "role-changed")
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
	if in.DeviceFingerprint != nil {
		if err := s.store.UpdateUserDeviceFingerprint(r.Context(), id, *in.DeviceFingerprint); err != nil {
			storeError(w, err)
			return
		}
		auditDetail += fmt.Sprintf(" device_fingerprint:%s->%s", auditField(u.DeviceFingerprint, 128), auditField(*in.DeviceFingerprint, 128))
		u.DeviceFingerprint = *in.DeviceFingerprint
	}
	if in.SlackUserID != nil {
		if err := s.store.UpdateUserSlackUserID(r.Context(), id, *in.SlackUserID); err != nil {
			storeError(w, err)
			return
		}
		auditDetail += fmt.Sprintf(" slack_user_id:%s->%s", auditField(u.SlackUserID, 64), auditField(*in.SlackUserID, 64))
		u.SlackUserID = *in.SlackUserID
	}
	s.audit(r.Context(), "user.update", auditDetail)
	u.Role = in.Role
	writeJSON(w, http.StatusOK, u)
}

// deleteUser removes a user by id, suspends every agent identity that human
// owned, and audits both.
//
// The user row is read BEFORE the delete because the agent keys are keyed on the
// owner's username, which the row is the only source of — after the delete there
// is nothing left to look it up from.
func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	u, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "user.delete", strconv.FormatInt(id, 10))
	s.cutUserAccess(r.Context(), u.Username, "user-deleted")
	s.suspendOwnedAgents(r.Context(), u.Username)
	// The same cascade for the identity kind that has no key to suspend: a
	// SPIFFE-attested agent is stopped by quarantining its subject (Phase 170).
	s.suspendOwnedIdentities(r.Context(), u.Username)
	w.WriteHeader(http.StatusNoContent)
}

// suspendOwnedAgents disables every agent key owned by a departing human.
//
// Offboarding a person used to leave their agents running with nobody
// accountable for them — and, worse, with nobody left to fail the broker's
// four-eyes check, which is keyed on that owner's name. Suspension (not
// deletion) is deliberate: the keys, their names and their audit history stay
// intact for the investigation, and a successor can re-enable them.
//
// It runs AFTER the user row is gone and never reports failure to the caller:
// the deletion has already happened and must not be reversed by a follow-up
// problem. Every failure is logged and audited so a half-finished offboarding is
// visible in the system of record rather than silently swallowed.
func (s *Server) suspendOwnedAgents(ctx context.Context, username string) {
	keys, err := s.store.ListAgentKeysByOwner(ctx, username)
	if err != nil {
		s.log.Error("could not list agent keys for a deleted user", "user", username, "err", err)
		s.audit(ctx, "agent.disable.failed",
			fmt.Sprintf("owner:%s reason:list-failed", auditField(username, 128)))
		return
	}
	for _, k := range keys {
		if k.Disabled {
			continue
		}
		if err := s.store.SetAgentKeyDisabled(ctx, k.ID, true); err != nil {
			s.log.Error("could not suspend an agent key of a deleted user", "agent", k.Name, "err", err)
			s.audit(ctx, "agent.disable.failed",
				fmt.Sprintf("agent:%d owner:%s reason:suspend-failed", k.ID, auditField(username, 128)))
			continue
		}
		s.audit(ctx, "agent.disable",
			fmt.Sprintf("agent:%d owner:%s reason:owner-offboarded", k.ID, auditField(username, 128)))
	}
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

// cutUserAccess ends every way a username can still act once its account has
// been deleted, deactivated or re-roled: the login-session rows the resolver
// turns into principals — a browser-extension token lives for
// PAM_EXTENSION_TOKEN_TTL_HOURS, a viewer token for seconds, a directory
// login for its TTL — and its live proxied sessions. Until the 2026-08-27
// audit none of those write paths did this: a deleted or SCIM-deactivated
// user kept a working extension token until it expired, and a re-roled user
// kept the old role's sessions. The resolver now also refuses a session whose
// local row is inactive (defence in depth), but a deleted row cannot be
// consulted and a role change is not a deactivation, so the sessions are cut
// here, at the write, the way POST /api/login-sessions/revoke always could.
//
// Never reported to the caller as a failure: the account change has already
// happened and must not be reversed by a follow-up problem. A failed revoke is
// logged and audited so a half-finished offboarding is visible.
func (s *Server) cutUserAccess(ctx context.Context, username, reason string) {
	n, err := s.store.DeleteSessionsByUsername(ctx, username)
	if err != nil {
		s.log.Error("could not revoke login sessions", "user", username, "reason", reason, "err", err)
		s.audit(ctx, "session.revoke_failed", fmt.Sprintf("user:%s reason:%s", username, reason))
		return
	}
	killed := s.killUserSessions(ctx, username, reason)
	s.audit(ctx, "session.revoked", fmt.Sprintf("user:%s sessions:%d killed:%d reason:%s", username, n, killed, reason))
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
