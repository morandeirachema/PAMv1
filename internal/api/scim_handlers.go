package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// scimHandler is a handler that runs after scimAuth has resolved the SCIM
// client identity.
type scimHandler func(w http.ResponseWriter, r *http.Request, key *store.ScimKey)

// scimAuth authenticates a SCIM client bearer key (Phase 149) and invokes
// next with the resolved key, or returns 401. Mirrors appAuth exactly: only
// the SHA-256 hash of the token is stored, a disabled key is treated as not
// found (fail-closed), and this path never resolves an auth.Principal at
// all — a SCIM key is not a human and must never carry a human's capability
// set, so every handler behind it reaches the store directly rather than
// through Can(cap).
func (s *Server) scimAuth(next scimHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			writeError(w, http.StatusUnauthorized, "missing SCIM credential")
			return
		}
		key, err := s.store.GetScimKeyByTokenHash(r.Context(), hashHex(tok))
		if err != nil {
			s.authFailed(w, r, "scim", "invalid SCIM credential")
			return
		}
		setActor(r.Context(), "scim:"+key.Name)
		next(w, r, key)
	}
}

// --- SCIM client key administration (human-facing, CapManageUsers) ---

type scimKeyIn struct {
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

// createScimKey mints a new SCIM client identity for an admin; the token is
// shown once and only its SHA-256 hash is stored.
func (s *Server) createScimKey(w http.ResponseWriter, r *http.Request) {
	var in scimKeyIn
	if !readJSON(w, r, &in) {
		return
	}
	if !checkName(w, "name", in.Name) {
		return
	}
	token, err := generateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	k := store.ScimKey{Name: in.Name, Owner: in.Owner, TokenHash: hashHex(token)}
	if err := s.store.CreateScimKey(r.Context(), &k); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "scim.key_create", fmt.Sprintf("%s owner:%s", k.Name, k.Owner))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": k.ID, "name": k.Name, "owner": k.Owner, "token": token,
		"note": "Give this token to the IdP's SCIM connector; only its hash is stored. Prefer HTTPS.",
	})
}

// listScimKeys returns the registered SCIM client identities (never a token hash).
func (s *Server) listScimKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListScimKeys(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

// deleteScimKey revokes a SCIM client so its bearer token stops resolving.
func (s *Server) deleteScimKey(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteScimKey(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "scim.key_revoke", fmt.Sprintf("scim_key:%d", id))
	w.WriteHeader(http.StatusNoContent)
}

// --- SCIM 2.0 wire schema (RFC 7643/7644) ---

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"

type scimMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created"`
	LastModified string `json:"lastModified"`
}

// scimUser is the wire representation of a PAMv1 user. PAMv1's User model
// has no name/emails fields, so — honestly, rather than fabricating
// placeholder values — this resource only ever carries the attributes
// PAMv1 actually has: id, userName, externalId, active. An IdP that sends
// name/emails on create/update has them silently accepted and dropped, the
// same way any SCIM server drops attributes it does not implement.
type scimUser struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id"`
	ExternalID string   `json:"externalId,omitempty"`
	UserName   string   `json:"userName"`
	Active     bool     `json:"active"`
	Meta       scimMeta `json:"meta"`
}

func scimUserFromStore(u *store.User) scimUser {
	ts := u.CreatedAt.UTC().Format("2006-01-02T15:04:05Z")
	return scimUser{
		Schemas:    []string{scimUserSchema},
		ID:         strconv.FormatInt(u.ID, 10),
		ExternalID: u.ExternalID,
		UserName:   u.Username,
		Active:     u.Active,
		// PAMv1 does not track a separate update timestamp for a user row;
		// Created is the only real one available, so it is reused for both
		// rather than fabricating a LastModified PAMv1 cannot actually attest to.
		Meta: scimMeta{ResourceType: "User", Created: ts, LastModified: ts},
	}
}

type scimListResponse struct {
	Schemas      []string   `json:"schemas"`
	TotalResults int        `json:"totalResults"`
	StartIndex   int        `json:"startIndex"`
	ItemsPerPage int        `json:"itemsPerPage"`
	Resources    []scimUser `json:"Resources"`
}

// scimWriteError writes a SCIM-shaped error body (RFC 7644 §3.12), so a real
// SCIM client's error handling — which looks for "detail", not PAMv1's own
// generic {"error": msg} — actually sees the failure reason.
func scimWriteError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"detail":  detail,
		"status":  strconv.Itoa(status),
	})
}

// scimStoreError maps a store error to a SCIM-shaped response.
func scimStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		scimWriteError(w, http.StatusNotFound, "resource not found")
	case errors.Is(err, store.ErrConflict):
		writeJSON(w, http.StatusConflict, map[string]any{
			"schemas":  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			"detail":   "a user with this userName or externalId already exists",
			"status":   "409",
			"scimType": "uniqueness",
		})
	default:
		scimWriteError(w, http.StatusInternalServerError, "internal error")
	}
}

// scimIDParam parses the {id} path value as a positive int64, the same rule
// idParam enforces, but reporting failure in SCIM's own error shape.
func scimIDParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		scimWriteError(w, http.StatusNotFound, "no such user")
		return 0, false
	}
	return id, true
}

// scimReadJSON is readJSON reporting a decode failure in SCIM's own error shape.
func scimReadJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		scimWriteError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// scimFilterRe matches the one filter shape real IdPs actually send for an
// idempotent-provisioning existence check — `<attr> eq "<value>"` — not the
// full SCIM filter grammar (RFC 7644 §3.4.2.2), which this server does not
// implement. Attribute names are matched case-insensitively, per SCIM's own
// attribute-name case-insensitivity rule.
var scimFilterRe = regexp.MustCompile(`(?i)^\s*(\w+)\s+eq\s+"([^"]*)"\s*$`)

// parseScimFilter extracts (attr, value) from a `filter` query value in the
// one supported shape, lower-casing attr for a case-insensitive match.
func parseScimFilter(filter string) (attr, value string, ok bool) {
	m := scimFilterRe.FindStringSubmatch(filter)
	if m == nil {
		return "", "", false
	}
	return strings.ToLower(m[1]), m[2], true
}

// scimMaxResults bounds a single unfiltered GET /Users page — this is a PAM
// system's user roster, not a consumer directory, so an in-memory fetch-all
// (ListUsers with no limit) then slice by startIndex/count gives correct
// results for any offset at a cost this scale never notices, rather than
// forcing SCIM's 1-indexed pagination onto the store's cursor-based one.
const scimMaxResults = 200

// scimServiceProviderConfig statically describes what this server supports,
// so an IdP's own "test connection" step can discover it — patch and filter
// (the one shape above) are supported; bulk, sorting and ETags are not.
func (s *Server) scimServiceProviderConfig(w http.ResponseWriter, r *http.Request, _ *store.ScimKey) {
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":          map[string]bool{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": scimMaxResults},
		"changePassword": map[string]bool{"supported": false},
		"sort":           map[string]bool{"supported": false},
		"etag":           map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type":        "oauthbearertoken",
			"name":        "OAuth Bearer Token",
			"description": "A SCIM client key minted via POST /v1/scim-keys, presented as a bearer token",
			"primary":     true,
		}},
	})
}

// listScimUsers implements GET /scim/v2/Users. With a `filter` query value
// it looks up exactly one user (an empty ListResponse, not a 404, when
// there is no match — this is the normal "does this user already exist"
// shape an idempotent IdP provisioning flow depends on). Without one it
// returns a startIndex/count page over the whole roster.
func (s *Server) listScimUsers(w http.ResponseWriter, r *http.Request, _ *store.ScimKey) {
	if f := r.URL.Query().Get("filter"); f != "" {
		attr, value, ok := parseScimFilter(f)
		if !ok {
			scimWriteError(w, http.StatusBadRequest, `unsupported filter — only <attr> eq "value" is supported`)
			return
		}
		var u *store.User
		var err error
		switch attr {
		case "username":
			u, err = s.store.GetUserByUsername(r.Context(), value)
		case "externalid":
			u, err = s.store.GetUserByExternalID(r.Context(), value)
		default:
			scimWriteError(w, http.StatusBadRequest, `unsupported filter attribute — only userName and externalId are supported`)
			return
		}
		resources := []scimUser{}
		if err == nil {
			resources = append(resources, scimUserFromStore(u))
		} else if !errors.Is(err, store.ErrNotFound) {
			scimStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, scimListResponse{
			Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, TotalResults: len(resources),
			StartIndex: 1, ItemsPerPage: len(resources), Resources: resources,
		})
		return
	}
	startIndex := 1
	if v, err := strconv.Atoi(r.URL.Query().Get("startIndex")); err == nil && v > 0 {
		startIndex = v
	}
	count := scimMaxResults
	if v, err := strconv.Atoi(r.URL.Query().Get("count")); err == nil && v > 0 && v < count {
		count = v
	}
	all, err := s.store.ListUsers(r.Context(), 0, 0)
	if err != nil {
		scimStoreError(w, err)
		return
	}
	resources := []scimUser{}
	if lo := startIndex - 1; lo < len(all) {
		hi := lo + count
		if hi > len(all) {
			hi = len(all)
		}
		for _, u := range all[lo:hi] {
			u := u
			resources = append(resources, scimUserFromStore(&u))
		}
	}
	writeJSON(w, http.StatusOK, scimListResponse{
		Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, TotalResults: len(all),
		StartIndex: startIndex, ItemsPerPage: len(resources), Resources: resources,
	})
}

type scimUserIn struct {
	UserName   string `json:"userName"`
	ExternalID string `json:"externalId"`
	Active     *bool  `json:"active"`
}

// createScimUser implements POST /scim/v2/Users. Every SCIM-provisioned
// user gets the fixed, least-privileged built-in role (auth.RoleUser) — a
// SCIM key is not an auth.Principal and holds no capabilities of its own,
// so unlike POST /api/users there is no caller capability set to bound a
// requested role against; a fixed floor is the only safe universal choice.
// A local access token is still minted (every store.User row needs one),
// but never returned here: a SCIM-provisioned user is expected to
// authenticate through the same IdP that is provisioning them (AD/Entra/
// OIDC), not a standalone PAMv1 bearer token — see ADMIN-GUIDE.md.
func (s *Server) createScimUser(w http.ResponseWriter, r *http.Request, key *store.ScimKey) {
	var in scimUserIn
	if !scimReadJSON(w, r, &in) {
		return
	}
	if err := validName(in.UserName); err != nil {
		scimWriteError(w, http.StatusBadRequest, "userName "+err.Error())
		return
	}
	if in.ExternalID != "" {
		if err := validName(in.ExternalID); err != nil {
			scimWriteError(w, http.StatusBadRequest, "externalId "+err.Error())
			return
		}
	}
	token, err := generateToken()
	if err != nil {
		scimWriteError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	u := store.User{Username: in.UserName, Role: string(auth.RoleUser), ExternalID: in.ExternalID, TokenHash: hashHex(token)}
	if err := s.store.CreateUser(r.Context(), &u); err != nil {
		scimStoreError(w, err)
		return
	}
	if in.Active != nil && !*in.Active {
		if err := s.store.UpdateUserActive(r.Context(), u.ID, false); err != nil {
			scimStoreError(w, err)
			return
		}
		u.Active = false
	}
	detail := fmt.Sprintf("username:%s role:user", auditField(u.Username, 128))
	if u.ExternalID != "" {
		detail += " external_id:" + auditField(u.ExternalID, 128)
	}
	if !u.Active {
		detail += " active:false"
	}
	_ = s.auditAs(r.Context(), "scim:"+key.Name, "scim.user_create", detail)
	writeJSON(w, http.StatusCreated, scimUserFromStore(&u))
}

// getScimUser implements GET /scim/v2/Users/{id}.
func (s *Server) getScimUser(w http.ResponseWriter, r *http.Request, _ *store.ScimKey) {
	id, ok := scimIDParam(w, r)
	if !ok {
		return
	}
	u, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		scimStoreError(w, err)
		return
	}
	if !s.scimInScope(r.Context(), w, u) {
		return
	}
	writeJSON(w, http.StatusOK, scimUserFromStore(u))
}

// replaceScimUser implements PUT /scim/v2/Users/{id}: a full-replace request
// that, given PAMv1's user model, can only actually change ExternalID and
// Active. userName is immutable everywhere else in this codebase ("re-keying
// an identity is a delete + re-mint, not an edit" — see UserStore.
// UpdateUserRole's own doc comment) and stays immutable here too: a PUT
// naming a different userName is refused rather than silently ignored,
// since silently ignoring part of a full-replace request is its own kind of
// wrong answer.
func (s *Server) replaceScimUser(w http.ResponseWriter, r *http.Request, key *store.ScimKey) {
	id, ok := scimIDParam(w, r)
	if !ok {
		return
	}
	var in scimUserIn
	if !scimReadJSON(w, r, &in) {
		return
	}
	u, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		scimStoreError(w, err)
		return
	}
	if !s.scimInScope(r.Context(), w, u) {
		return
	}
	if in.UserName != "" && in.UserName != u.Username {
		scimWriteError(w, http.StatusBadRequest, "userName is immutable in PAMv1; delete and re-create this user instead of renaming")
		return
	}
	if in.ExternalID != u.ExternalID {
		if in.ExternalID != "" {
			if err := validName(in.ExternalID); err != nil {
				scimWriteError(w, http.StatusBadRequest, "externalId "+err.Error())
				return
			}
		}
		if err := s.store.UpdateUserExternalID(r.Context(), id, in.ExternalID); err != nil {
			scimStoreError(w, err)
			return
		}
		u.ExternalID = in.ExternalID
	}
	if err := s.applyScimActiveChange(r.Context(), key, u, in.Active); err != nil {
		scimStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, scimUserFromStore(u))
}

type scimPatchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

type scimPatchIn struct {
	Operations []scimPatchOp `json:"Operations"`
}

// patchScimUser implements PATCH /scim/v2/Users/{id} — the operation real
// IdPs actually use for deprovisioning. Two wire shapes are honored, both
// seen from real IdP connectors: the RFC 7644 §3.5.2 form with an explicit
// "path" ({"op":"replace","path":"active","value":false}), and Azure AD's
// documented no-path variant, where the changed attributes arrive directly
// as an object in "value" ({"op":"Replace","value":{"active":false}}).
// Unrecognized operations/paths are skipped rather than failing the whole
// request — a PATCH may bundle several operations, and this server
// implements only the two attributes PAMv1 actually has (active,
// externalId), the same "accept and drop what you don't model" posture
// createScimUser already takes for name/emails.
func (s *Server) patchScimUser(w http.ResponseWriter, r *http.Request, key *store.ScimKey) {
	id, ok := scimIDParam(w, r)
	if !ok {
		return
	}
	var in scimPatchIn
	if !scimReadJSON(w, r, &in) {
		return
	}
	u, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		scimStoreError(w, err)
		return
	}
	if !s.scimInScope(r.Context(), w, u) {
		return
	}
	var newActive *bool
	var newExternalID *string
	for _, op := range in.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			continue
		}
		switch strings.ToLower(op.Path) {
		case "active":
			var v bool
			if json.Unmarshal(op.Value, &v) == nil {
				newActive = &v
			}
		case "externalid":
			var v string
			if json.Unmarshal(op.Value, &v) == nil {
				newExternalID = &v
			}
		case "":
			// Azure AD's no-path shape: the changed attributes are keys of
			// the value object itself.
			var obj struct {
				Active     *bool   `json:"active"`
				ExternalID *string `json:"externalId"`
			}
			if json.Unmarshal(op.Value, &obj) == nil {
				if obj.Active != nil {
					newActive = obj.Active
				}
				if obj.ExternalID != nil {
					newExternalID = obj.ExternalID
				}
			}
		}
	}
	if newExternalID != nil && *newExternalID != u.ExternalID {
		if *newExternalID != "" {
			if err := validName(*newExternalID); err != nil {
				scimWriteError(w, http.StatusBadRequest, "externalId "+err.Error())
				return
			}
		}
		if err := s.store.UpdateUserExternalID(r.Context(), id, *newExternalID); err != nil {
			scimStoreError(w, err)
			return
		}
		u.ExternalID = *newExternalID
	}
	if err := s.applyScimActiveChange(r.Context(), key, u, newActive); err != nil {
		scimStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, scimUserFromStore(u))
}

// scimInScope reports whether a SCIM key may act on this user. A SCIM key is a
// machine credential held by an IdP connector; it manages ordinary user
// lifecycle, and deprovisioning a pre-existing local user is a documented,
// intended flow (see TestScimDeactivateBlocksAccess). What it must NOT do is
// touch a PRIVILEGED user — reactivating one an operator deliberately
// deactivated restores a privileged bearer token the kill switch was meant to
// revoke, and deactivating one is a DoS on privileged human access (2026-08-26
// audit, F-5). Out of scope answers 404, the SCIM convention for a resource the
// caller may not see.
//
// "Privileged" is the EFFECTIVE-CAPABILITY test, not the role string: u.Role
// holds either a built-in role or a custom profile name, so a first cut that
// compared against "admin" would have let a connector touch a user whose
// profile carries manage_users or unlimited_vault_access without being the
// built-in admin. The role/profile is resolved to its capability set and
// refused if it can administer users or holds the vault override. A profile
// that cannot be resolved (an unreadable store, a deleted profile) fails
// closed — an unknown privilege level is treated as privileged.
func (s *Server) scimInScope(ctx context.Context, w http.ResponseWriter, u *store.User) bool {
	prin, err := s.resolver.PrincipalForRole(ctx, u.Username, u.Role)
	if err != nil || prin.IsAdmin() || prin.Can(auth.CapManageUsers) || prin.Can(auth.CapUnlimitedVaultAccess) {
		scimWriteError(w, http.StatusNotFound, "no such SCIM-manageable user")
		return false
	}
	return true
}

// applyScimActiveChange sets u's Active flag when want is non-nil and
// differs from the current value, persists it, and audits the transition —
// shared by replaceScimUser and patchScimUser, the two paths that can flip
// this user's own access on or off. u is updated in place so the caller's
// subsequent response reflects the new value without a second fetch.
func (s *Server) applyScimActiveChange(ctx context.Context, key *store.ScimKey, u *store.User, want *bool) error {
	if want == nil || *want == u.Active {
		return nil
	}
	if err := s.store.UpdateUserActive(ctx, u.ID, *want); err != nil {
		// Surface it (2026-08-26 audit, F-5). This is the deprovisioning write —
		// silently swallowing it while answering 200 tells the IdP the account
		// was deactivated when it was not, which is the failure a deprovisioning
		// call exists to prevent.
		return err
	}
	u.Active = *want
	if !*want {
		// Deprovisioning must actually cut access — including the sessions the
		// user already holds, not only the per-user token (2026-08-27 audit).
		s.cutUserAccess(ctx, u.Username, "deactivated")
	}
	action := "scim.user_deactivate"
	if *want {
		action = "scim.user_reactivate"
	}
	_ = s.auditAs(ctx, "scim:"+key.Name, action, fmt.Sprintf("username:%s", auditField(u.Username, 128)))
	return nil
}

// deleteScimUser implements DELETE /scim/v2/Users/{id} as a SOFT delete —
// it sets Active false, the same as PATCH active:false, rather than calling
// the human REST API's DeleteUser (a hard row delete). This is a deliberate
// divergence from that existing route's own semantics, not an oversight:
// SCIM's provisioning model is built around being able to reactivate a
// deprovisioned identity later, which a hard delete forecloses. Always
// audited, even if the user was already inactive — a repeat deprovisioning
// call from the IdP is itself a meaningful signal for the audit trail.
func (s *Server) deleteScimUser(w http.ResponseWriter, r *http.Request, key *store.ScimKey) {
	id, ok := scimIDParam(w, r)
	if !ok {
		return
	}
	u, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		scimStoreError(w, err)
		return
	}
	if !s.scimInScope(r.Context(), w, u) {
		return
	}
	if err := s.store.UpdateUserActive(r.Context(), id, false); err != nil {
		scimStoreError(w, err)
		return
	}
	_ = s.auditAs(r.Context(), "scim:"+key.Name, "scim.user_deactivate", fmt.Sprintf("username:%s via:delete", auditField(u.Username, 128)))
	w.WriteHeader(http.StatusNoContent)
}
