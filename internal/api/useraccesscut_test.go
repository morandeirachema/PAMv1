package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"net/http/httptest"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/store"
)

func TestDeleteUserRevokesItsSessions(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{ExtensionTokenTTL: time.Hour})
	credID := seedCredentialFor(t, srv)
	uid, userTok := seedUserWithID(t, srv, "bob", "admin")
	extTok := mintExtension(t, srv, userTok)
	if code, _ := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(credID)+"/reveal", extTok, nil); code != http.StatusOK {
		t.Fatalf("extension token should reveal before the delete: %d", code)
	}
	if code, d := do(t, srv, http.MethodDelete, "/api/users/"+itoa(uid), testAPIKey, nil); code != http.StatusNoContent {
		t.Fatalf("delete user: %d %s", code, d)
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(credID)+"/reveal", extTok, nil); code != http.StatusUnauthorized {
		t.Fatalf("a deleted user's extension token still works: %d, want 401", code)
	}
	if code, _ := do(t, srv, http.MethodGet, "/api/me", userTok, nil); code != http.StatusUnauthorized {
		t.Fatalf("a deleted user's token still works: %d, want 401", code)
	}
	wantAudit(t, st, "session.revoked", "user:bob", "reason:user-deleted")
}

func TestRoleChangeRevokesSessions(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{ExtensionTokenTTL: time.Hour})
	credID := seedCredentialFor(t, srv)
	uid, userTok := seedUserWithID(t, srv, "bob", "admin")
	extTok := mintExtension(t, srv, userTok)
	if code, _ := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(credID)+"/reveal", extTok, nil); code != http.StatusOK {
		t.Fatalf("extension token should reveal before the role change: %d", code)
	}
	// A no-op role write keeps the sessions (nothing changed).
	if code, d := do(t, srv, http.MethodPut, "/api/users/"+itoa(uid), testAPIKey, map[string]any{"role": "admin"}); code != http.StatusOK {
		t.Fatalf("same-role update: %d %s", code, d)
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(credID)+"/reveal", extTok, nil); code != http.StatusOK {
		t.Fatalf("a same-role update must not revoke sessions: %d", code)
	}
	if code, d := do(t, srv, http.MethodPut, "/api/users/"+itoa(uid), testAPIKey, map[string]any{"role": "user"}); code != http.StatusOK {
		t.Fatalf("role change: %d %s", code, d)
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(credID)+"/reveal", extTok, nil); code != http.StatusUnauthorized {
		t.Fatalf("an extension token minted under the OLD role still works after the change: %d, want 401", code)
	}
	// The per-user token survives and now carries the new role.
	code, data := do(t, srv, http.MethodGet, "/api/me", userTok, nil)
	if code != http.StatusOK || !strings.Contains(string(data), `"role":"user"`) {
		t.Fatalf("/api/me after role change: %d %s", code, data)
	}
	wantAudit(t, st, "session.revoked", "user:bob", "reason:role-changed")
}

func TestScimDeactivateRevokesSessions(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{ScimEnabled: true, ExtensionTokenTTL: time.Hour})
	scimTok := mintScimKey(t, srv, "azuread")
	credID := seedCredentialFor(t, srv)
	// SCIM may not manage an admin (Phase 212, F-5), so bob is a plain user on
	// a custom profile that can reveal — enough to mint an extension token.
	_ = seedProfileUser(t, srv, "revealer", "bob-seed", "read_inventory", "reveal_secret")
	uid, userTok := seedUserWithID(t, srv, "bob", "revealer")
	extTok := mintExtension(t, srv, userTok)
	if code, _ := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(credID)+"/reveal", extTok, nil); code != http.StatusOK {
		t.Fatalf("extension token should reveal before deactivation: %d", code)
	}
	if status, data := scimDo(t, srv, http.MethodPatch, "/scim/v2/Users/"+itoa(uid), scimTok, map[string]any{
		"Operations": []map[string]any{{"op": "Replace", "value": map[string]any{"active": false}}},
	}); status != http.StatusOK {
		t.Fatalf("patch deactivate: %d %s", status, data)
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(credID)+"/reveal", extTok, nil); code != http.StatusUnauthorized {
		t.Fatalf("a SCIM-deactivated user's extension token still works: %d, want 401", code)
	}
	// Reactivation restores the per-user token (no re-mint), but the sessions
	// were REVOKED, not paused: the old extension token stays dead.
	if status, data := scimDo(t, srv, http.MethodPatch, "/scim/v2/Users/"+itoa(uid), scimTok, map[string]any{
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": true}},
	}); status != http.StatusOK {
		t.Fatalf("patch reactivate: %d %s", status, data)
	}
	if code, _ := do(t, srv, http.MethodGet, "/api/me", userTok, nil); code != http.StatusOK {
		t.Fatalf("reactivated user's token: %d, want 200", code)
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(credID)+"/reveal", extTok, nil); code != http.StatusUnauthorized {
		t.Fatalf("a revoked extension token came back on reactivation: %d, want 401", code)
	}
	wantAudit(t, st, "session.revoked", "user:bob", "reason:deactivated")
}

// TestExtensionTokenHonoursIPAllowlist pins the other half of the fix: a
// session token minted for a local user now carries the user's IP allowlist,
// so an extension token used from outside it is refused at reveal exactly as
// the per-user token would be. Before, only the per-user-token path copied
// the allowlist, so the hours-long extension token was never restricted.
func TestExtensionTokenHonoursIPAllowlist(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{ExtensionTokenTTL: time.Hour})
	credID := seedCredentialFor(t, srv)
	uid, userTok := seedUserWithID(t, srv, "bob", "admin")
	extTok := mintExtension(t, srv, userTok)
	// Same role, so the sessions survive the update — only the allowlist changes.
	if code, d := do(t, srv, http.MethodPut, "/api/users/"+itoa(uid), testAPIKey,
		map[string]any{"role": "admin", "ip_allowlist": "10.0.0.0/8"}); code != http.StatusOK {
		t.Fatalf("set allowlist: %d %s", code, d)
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(credID)+"/reveal", extTok, nil); code != http.StatusForbidden {
		t.Fatalf("extension token from outside the allowlist: %d, want 403", code)
	}
	if code, _ := do(t, srv, http.MethodGet, "/api/me", userTok, nil); code != http.StatusForbidden {
		t.Fatalf("per-user token from outside the allowlist: %d, want 403", code)
	}
	wantAudit(t, st, "authz.denied", "reason:source-ip-not-allowed", "")
}

// seedCredentialFor creates a target with one password credential and returns
// the credential id.
func seedCredentialFor(t *testing.T, srv *httptest.Server) int64 {
	t.Helper()
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "t-cut", "host": "h", "os_type": "linux", "protocol": "ssh",
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	_, cd := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "root", "secret": secretPassword,
	})
	return int64(jsonMap(t, cd)["id"].(float64))
}

// seedUserWithID is seedUser plus the user's id, for the routes keyed on it.
func seedUserWithID(t *testing.T, srv *httptest.Server, username, role string) (int64, string) {
	t.Helper()
	status, data := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": username, "role": role})
	if status != http.StatusCreated {
		t.Fatalf("seed user %s: %d %s", username, status, data)
	}
	m := jsonMap(t, data)
	return int64(m["id"].(float64)), m["token"].(string)
}

// mintExtension mints a browser-extension token for the caller.
func mintExtension(t *testing.T, srv *httptest.Server, userTok string) string {
	t.Helper()
	code, data := do(t, srv, http.MethodPost, "/api/extension-token", userTok, nil)
	if code != http.StatusOK {
		t.Fatalf("mint extension token: %d %s", code, data)
	}
	return jsonMap(t, data)["token"].(string)
}

// wantAudit fails unless an audit event with the action exists whose detail
// contains every non-empty needle.
func wantAudit(t *testing.T, st store.Store, action string, needles ...string) {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action != action {
			continue
		}
		ok := true
		for _, n := range needles {
			if n != "" && !strings.Contains(e.Detail, n) {
				ok = false
			}
		}
		if ok {
			return
		}
	}
	t.Fatalf("no %s audit event with %v; got %+v", action, needles, auditActions(events))
}
