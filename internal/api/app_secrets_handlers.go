package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/morandeirachema/pamv1/internal/store"
)

// appHandler is a handler that runs after appAuth has resolved the application.
type appHandler func(w http.ResponseWriter, r *http.Request, app *store.AppKey)

// appAuth authenticates an application bearer key (Phase 24) and invokes next
// with the resolved application, or returns 401. Only the SHA-256 hash of the
// token is stored, so the lookup is over the hash; a disabled app is treated as
// not found (fail-closed).
func (s *Server) appAuth(next appHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			writeError(w, http.StatusUnauthorized, "missing application credential")
			return
		}
		app, err := s.store.GetAppKeyByTokenHash(r.Context(), hashHex(tok))
		if err != nil {
			// This surface vends plaintext secrets to machines, so a guessed token
			// must be both throttled and recorded.
			s.authFailed(w, r, "app", "invalid application credential")
			return
		}
		setActor(r.Context(), "app:"+app.Name)
		next(w, r, app)
	}
}

// fetchAppSecret returns the secret of the credential named by the {id} path
// value to an authenticated application, but only if the application has an
// explicit grant for it (default-deny). The secret is decrypted just-in-time and
// the retrieval is audited (never the secret itself). This is the deliberate,
// opt-in Conjur-style secret-delivery path for non-agent applications.
func (s *Server) fetchAppSecret(w http.ResponseWriter, r *http.Request, app *store.AppKey) {
	// Honor the global reveal-disabled kill switch: when an operator has turned off
	// plaintext secret delivery, the application-secrets path is disabled too (it
	// is a secret-delivery path like reveal/checkout/broker-reveal).
	if s.rt().revealDisabled {
		s.auditAs(r.Context(), "app:"+app.Name, "app.secret_denied", "reason:reveal-disabled-by-policy")
		writeError(w, http.StatusForbidden, "secret delivery is disabled by policy")
		return
	}
	credID, ok := idParam(w, r)
	if !ok {
		return
	}
	s.deliverAppSecret(w, r, app, credID, "")
}

// maxAliasLen bounds the alias a caller may ask about — the same cap a name gets
// anywhere else here, so a long path segment cannot become a long audit detail.
const maxAliasLen = 128

// fetchAppSecretByAlias is the same delivery, addressed by the grant's stable
// name instead of a credential row id (Phase 197).
//
// It exists for declarative consumers. An External Secrets Operator SecretStore
// templates `{{ .remoteRef.key }}` into this URL and lives in git, and a
// credential's BIGSERIAL id is not stable across environments, a restore, or a
// delete-and-recreate — so addressing by id makes the manifest wrong the first
// time somebody rebuilds an estate. The alias is resolved WITHIN this app's own
// grants, so resolution and authorization are one lookup.
func (s *Server) fetchAppSecretByAlias(w http.ResponseWriter, r *http.Request, app *store.AppKey) {
	if s.rt().revealDisabled {
		s.auditAs(r.Context(), "app:"+app.Name, "app.secret_denied", "reason:reveal-disabled-by-policy")
		writeError(w, http.StatusForbidden, "secret delivery is disabled by policy")
		return
	}
	alias := r.PathValue("alias")
	if alias == "" || len(alias) > maxAliasLen {
		writeError(w, http.StatusBadRequest, "alias is required and must be at most 128 characters")
		return
	}
	credID, err := s.store.AppCredentialByAlias(r.Context(), app.ID, alias)
	if errors.Is(err, store.ErrNotFound) {
		// 404 here is deliberate and load-bearing: an External Secrets Operator
		// reads 404 as "this secret no longer exists" and DELETES the Kubernetes
		// Secret it manages. That is the right answer for an alias nobody has
		// defined. It is emphatically NOT the right answer for a revoked grant —
		// see deliverAppSecret, which answers 403 there so a policy change can
		// never masquerade as a deletion and take a running workload's Secret
		// with it. TestESOStatusContract pins both.
		s.auditAs(r.Context(), "app:"+app.Name, "app.secret_denied",
			fmt.Sprintf("alias:%s reason:no-such-alias", auditField(alias, maxAliasLen)))
		writeError(w, http.StatusNotFound, "no secret with that alias is granted to this application")
		return
	}
	if err != nil {
		storeError(w, err)
		return
	}
	s.deliverAppSecret(w, r, app, credID, alias)
}

// deliverAppSecret is the one delivery path both routes share: check the grant,
// refuse a ZSP credential, decrypt, audit fail-closed, then answer.
func (s *Server) deliverAppSecret(w http.ResponseWriter, r *http.Request, app *store.AppKey, credID int64, alias string) {
	allowed, err := s.store.AppMayAccessCredential(r.Context(), app.ID, credID)
	if err != nil {
		storeError(w, err)
		return
	}
	if !allowed {
		// 403, never 404. An External Secrets Operator treats 404 as "deleted" and
		// removes the Kubernetes Secret it manages, so answering 404 for a grant
		// that was REVOKED would let an authorization change delete a running
		// workload's secret. A refusal must read as a refusal.
		s.auditAs(r.Context(), "app:"+app.Name, "app.secret_denied", fmt.Sprintf("credential:%d reason:not-granted", credID))
		writeError(w, http.StatusForbidden, "this application is not granted access to that credential")
		return
	}
	cred, err := s.store.GetCredential(r.Context(), credID)
	if err != nil {
		storeError(w, err)
		return
	}
	// A Zero Standing Privilege credential has no stored secret to deliver.
	if cred.IsZSP() {
		writeError(w, http.StatusUnprocessableEntity, "this credential has no stored secret (zero standing privilege)")
		return
	}
	target, err := s.store.GetTarget(r.Context(), cred.TargetID)
	if err != nil {
		storeError(w, err)
		return
	}
	secret, err := s.vault.Decrypt(r.Context(), cred.SecretEnc, store.CredentialAAD(cred.TargetID, cred.ID))
	if err != nil {
		s.auditAs(r.Context(), "app:"+app.Name, "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%s op:app-secret", cred.ID, target.Name))
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	// Fail closed: the retrieval must be durably audited before the secret leaves.
	detail := fmt.Sprintf("credential:%d target:%s user:%s", cred.ID, target.Name, cred.Username)
	if alias != "" {
		detail += " alias:" + auditField(alias, maxAliasLen)
	}
	if !s.mustAuditAs(w, r.Context(), "app:"+app.Name, "app.secret_retrieved", detail) {
		return
	}
	body := map[string]any{
		"credential_id": cred.ID,
		"target":        target.Name,
		"username":      cred.Username,
		"secret_type":   cred.SecretType,
		"secret":        secret,
	}
	if alias != "" {
		body["alias"] = alias
	}
	writeJSON(w, http.StatusOK, body)
}

type appKeyIn struct {
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

// createAppKey mints a new application identity for an admin; the token is shown
// once and only its SHA-256 hash is stored.
func (s *Server) createAppKey(w http.ResponseWriter, r *http.Request) {
	var in appKeyIn
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
	k := store.AppKey{Name: in.Name, Owner: in.Owner, TokenHash: hashHex(token)}
	if err := s.store.CreateAppKey(r.Context(), &k); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "app.create", fmt.Sprintf("%s owner:%s", k.Name, k.Owner))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": k.ID, "name": k.Name, "owner": k.Owner, "token": token,
		"note": "Give this token to the application; only its hash is stored. Prefer HTTPS.",
	})
}

// listAppKeys returns the registered application identities (never a token hash).
func (s *Server) listAppKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListAppKeys(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

// deleteAppKey revokes an application so its bearer token stops resolving (its
// secret grants cascade away).
func (s *Server) deleteAppKey(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteAppKey(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "app.revoke", fmt.Sprintf("app:%d", id))
	w.WriteHeader(http.StatusNoContent)
}

type appGrantIn struct {
	CredentialID int64 `json:"credential_id"`
}

// grantAppSecret authorizes an application to retrieve one credential's secret.
// It needs CapRevealSecret — granting an app a secret is delegating reveal
// access, so only a principal who could reveal the secret itself may hand it out.
func (s *Server) grantAppSecret(w http.ResponseWriter, r *http.Request) {
	appID, ok := idParam(w, r)
	if !ok {
		return
	}
	var in appGrantIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.CredentialID <= 0 {
		writeError(w, http.StatusUnprocessableEntity, "credential_id is required")
		return
	}
	// Enforce the rule this handler's own doc comment states: you may only delegate
	// a secret you could reveal yourself. Without it the grant laundered a secret
	// past every gate reveal obeys — per-target grants, safe membership, the
	// approval window and the vendor contract — because GET /v1/app-secrets/{id}
	// then vends the plaintext on the app's grant alone. With PAM_REQUIRE_APPROVAL
	// set, POST /api/credentials/42/reveal was refused without an approved request
	// while POST /v1/apps/3/grants {"credential_id":42} handed over the same
	// secret with no approval at all.
	cred, target, ok := s.loadCredentialTarget(w, r, in.CredentialID)
	if !ok {
		return
	}
	if !s.gateCredentialAccess(w, r, target, cred.Username, "app.grant") {
		return
	}
	g := store.AppSecretGrant{AppID: appID, CredentialID: in.CredentialID}
	if err := s.store.GrantAppSecret(r.Context(), &g); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "app.grant", fmt.Sprintf("app:%d credential:%d", appID, in.CredentialID))
	writeJSON(w, http.StatusCreated, g)
}

// listAppSecretGrants returns the credentials an application may retrieve.
func (s *Server) listAppSecretGrants(w http.ResponseWriter, r *http.Request) {
	appID, ok := idParam(w, r)
	if !ok {
		return
	}
	grants, err := s.store.ListAppSecretGrants(r.Context(), appID)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grants)
}

// deleteAppSecretGrant revokes one of an application's secret grants. The route
// is scoped to the app, so a grant belonging to a different app is not removed.
func (s *Server) deleteAppSecretGrant(w http.ResponseWriter, r *http.Request) {
	appID, ok := idParam(w, r)
	if !ok {
		return
	}
	gid, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil || gid < 1 {
		writeError(w, http.StatusUnprocessableEntity, "invalid grant id")
		return
	}
	grants, err := s.store.ListAppSecretGrants(r.Context(), appID)
	if err != nil {
		storeError(w, err)
		return
	}
	found := false
	for _, g := range grants {
		if g.ID == gid {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "grant not found for this application")
		return
	}
	if err := s.store.DeleteAppSecretGrant(r.Context(), gid); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "app.grant_revoked", fmt.Sprintf("app:%d grant:%d", appID, gid))
	w.WriteHeader(http.StatusNoContent)
}

// setAppGrantAlias names one of an application's grants, or clears the name with
// an empty alias. It is CapRevealSecret rather than CapManageUsers because naming
// a grant is part of deciding what an application may fetch, not part of managing
// identities — the same reasoning that put granting and revoking there.
func (s *Server) setAppGrantAlias(w http.ResponseWriter, r *http.Request) {
	gid, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "grant id must be a number")
		return
	}
	var in struct {
		Alias string `json:"alias"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	alias := strings.TrimSpace(in.Alias)
	if len(alias) > maxAliasLen {
		writeError(w, http.StatusBadRequest, "alias must be at most 128 characters")
		return
	}
	// The alias travels in a URL path segment on the way back in, so keep it to
	// characters that survive one without escaping and without introducing a
	// traversal segment.
	if alias != "" && !validAlias(alias) {
		writeError(w, http.StatusBadRequest,
			"alias may contain only letters, digits, dot, dash and underscore")
		return
	}
	if err := s.store.SetAppGrantAlias(r.Context(), gid, alias); err != nil {
		storeError(w, err)
		return
	}
	action := "app.grant_alias_set"
	if alias == "" {
		action = "app.grant_alias_cleared"
	}
	s.audit(r.Context(), action, fmt.Sprintf("grant:%d alias:%s", gid, auditField(alias, maxAliasLen)))
	writeJSON(w, http.StatusOK, map[string]any{"grant_id": gid, "alias": alias})
}

// validAlias reports whether an alias is safe to carry in a URL path segment. A
// deliberately narrow set: a name that needs escaping to be addressed is a name
// that will be addressed wrongly by somebody, and "." / ".." must never be a
// grant's name.
func validAlias(a string) bool {
	if a == "." || a == ".." {
		return false
	}
	for _, r := range a {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}
