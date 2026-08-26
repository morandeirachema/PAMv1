package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// scimDo is do (see api_test.go) for a SCIM bearer token: Authorization:
// Bearer, not X-API-Key.
func scimDo(t *testing.T, srv *httptest.Server, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, buf)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

// mintScimKey mints a SCIM client key as the bootstrap admin and returns its token.
func mintScimKey(t *testing.T, srv *httptest.Server, name string) string {
	t.Helper()
	status, data := do(t, srv, http.MethodPost, "/v1/scim-keys", testAPIKey, map[string]any{"name": name, "owner": "idp-team"})
	if status != http.StatusCreated {
		t.Fatalf("mint scim key: %d %s", status, data)
	}
	tok, _ := jsonMap(t, data)["token"].(string)
	if tok == "" {
		t.Fatalf("scim key token not returned: %s", data)
	}
	return tok
}

// TestScimDisabled proves the SCIM surface is entirely absent when the
// feature is off (the default), matching the app-secrets and extension
// precedents for an opt-in, off-by-default bearer-key surface.
func TestScimDisabled(t *testing.T) {
	srv, _ := newTestServerStore(t) // default options: SCIM off
	if s, _ := do(t, srv, http.MethodPost, "/v1/scim-keys", testAPIKey, map[string]any{"name": "x"}); s != http.StatusNotFound {
		t.Fatalf("scim-keys route must be absent when disabled, got %d", s)
	}
	if s, _ := scimDo(t, srv, http.MethodGet, "/scim/v2/Users", "whatever", nil); s != http.StatusNotFound {
		t.Fatalf("scim Users route must be absent when disabled, got %d", s)
	}
}

// TestScimKeyMintRequiresCapManageUsers proves a plain user cannot mint a
// SCIM client key — only an identity holding CapManageUsers can.
func TestScimKeyMintRequiresCapManageUsers(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{ScimEnabled: true})
	userTok := seedUser(t, srv, "plain-user", "user")
	if s, _ := do(t, srv, http.MethodPost, "/v1/scim-keys", userTok, map[string]any{"name": "x"}); s != http.StatusForbidden {
		t.Fatalf("a plain user must not mint scim keys, got %d", s)
	}
}

// TestScimUserCreateAndFilter proves the create + idempotent-provisioning
// filter path end to end: a SCIM POST creates a user with the fixed "user"
// role (never whatever a caller might ask for, since a SCIM key holds no
// human capability set to bound a requested role against); filtering by
// userName or externalId finds it, matching the exact "does this user
// already exist" check a real IdP performs before deciding to POST; a
// filter that matches nothing returns an empty ListResponse, not a 404.
func TestScimUserCreateAndFilter(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{ScimEnabled: true})
	scimTok := mintScimKey(t, srv, "okta")

	status, data := scimDo(t, srv, http.MethodPost, "/scim/v2/Users", scimTok, map[string]any{
		"userName": "alice", "externalId": "okta-001",
	})
	if status != http.StatusCreated {
		t.Fatalf("create scim user: %d %s", status, data)
	}
	created := jsonMap(t, data)
	if created["userName"] != "alice" {
		t.Fatalf("userName = %v, want alice", created["userName"])
	}
	if created["active"] != true {
		t.Fatalf("active = %v, want true by default", created["active"])
	}
	scimID := atoi64(t, created["id"].(string))

	// Prove pamv1's own view agrees: fixed role "user", regardless of the
	// fact the SCIM payload above never even offered a role to pick.
	u, err := st.GetUser(context.Background(), scimID)
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != "user" {
		t.Fatalf("stored role = %q, want the fixed floor role \"user\"", u.Role)
	}

	// Idempotent-provisioning filters: an IdP checks existence this way
	// before deciding whether to POST a duplicate.
	status, data = scimDo(t, srv, http.MethodGet, `/scim/v2/Users?filter=userName+eq+"alice"`, scimTok, nil)
	if status != http.StatusOK {
		t.Fatalf("filter by userName: %d %s", status, data)
	}
	if n := jsonMap(t, data)["totalResults"]; n != float64(1) {
		t.Fatalf("filter by userName found %v results, want 1: %s", n, data)
	}

	status, data = scimDo(t, srv, http.MethodGet, `/scim/v2/Users?filter=externalId+eq+"okta-001"`, scimTok, nil)
	if status != http.StatusOK || jsonMap(t, data)["totalResults"] != float64(1) {
		t.Fatalf("filter by externalId: %d %s", status, data)
	}

	status, data = scimDo(t, srv, http.MethodGet, `/scim/v2/Users?filter=userName+eq+"nobody"`, scimTok, nil)
	if status != http.StatusOK {
		t.Fatalf("filter with no match should still be 200, got %d %s", status, data)
	}
	if jsonMap(t, data)["totalResults"] != float64(0) {
		t.Fatalf("filter with no match should return 0 results, got %s", data)
	}

	// A second create with the same userName is a real conflict, reported
	// in SCIM's own error shape.
	status, data = scimDo(t, srv, http.MethodPost, "/scim/v2/Users", scimTok, map[string]any{"userName": "alice"})
	if status != http.StatusConflict {
		t.Fatalf("duplicate userName should be 409, got %d %s", status, data)
	}
	if jsonMap(t, data)["scimType"] != "uniqueness" {
		t.Fatalf("conflict should report scimType uniqueness: %s", data)
	}
}

// TestScimDeactivateBlocksAccess is the load-bearing security property this
// whole phase exists for: SCIM's PATCH active:false must actually cut the
// deprovisioned user's own access, not just flip a flag nothing reads. It
// proves this against the real auth.Resolver path (GET /api/me, gated only
// by "authenticated at all"), not by inspecting the stored row — the same
// end-to-end-over-mocking discipline the JIT-injection proxy tests use for
// the analogous claim.
//
// The test user is seeded directly through the store (a known plaintext
// token whose hash is inserted), not through SCIM's own create route —
// createScimUser deliberately never returns a token (see its doc comment),
// so this simulates the realistic case SCIM deactivation exists for: an
// identity that already has working local access, which an IdP's push
// must now be able to cut off. It also proves the Azure AD no-path PATCH
// shape works (a real, documented interop gotcha, not a hypothetical one),
// and that reactivating restores access without a new token ever being minted.
func TestScimDeactivateBlocksAccess(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{ScimEnabled: true})
	scimTok := mintScimKey(t, srv, "azuread")

	const plainToken = "pamt_scim_test_deactivate_token"
	u := store.User{Username: "bob", Role: "user", TokenHash: auth.TokenHash(plainToken)}
	if err := st.CreateUser(context.Background(), &u); err != nil {
		t.Fatal(err)
	}
	if !u.Active {
		t.Fatal("CreateUser should always create an active user")
	}

	if s, _ := do(t, srv, http.MethodGet, "/api/me", plainToken, nil); s != http.StatusOK {
		t.Fatalf("this user's token should authenticate before deactivation, got %d", s)
	}

	scimID := itoa(u.ID)
	// Azure AD's documented no-path PATCH shape.
	status, data := scimDo(t, srv, http.MethodPatch, "/scim/v2/Users/"+scimID, scimTok, map[string]any{
		"Operations": []map[string]any{{"op": "Replace", "value": map[string]any{"active": false}}},
	})
	if status != http.StatusOK {
		t.Fatalf("patch deactivate: %d %s", status, data)
	}
	if jsonMap(t, data)["active"] != false {
		t.Fatalf("patch response should reflect active:false: %s", data)
	}

	if s, b := do(t, srv, http.MethodGet, "/api/me", plainToken, nil); s != http.StatusUnauthorized {
		t.Fatalf("deactivated user's token must be refused, got %d %s", s, b)
	}

	// The standard RFC 7644 path-based shape reactivates.
	status, data = scimDo(t, srv, http.MethodPatch, "/scim/v2/Users/"+scimID, scimTok, map[string]any{
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": true}},
	})
	if status != http.StatusOK || jsonMap(t, data)["active"] != true {
		t.Fatalf("patch reactivate: %d %s", status, data)
	}
	if s, b := do(t, srv, http.MethodGet, "/api/me", plainToken, nil); s != http.StatusOK {
		t.Fatalf("reactivated user's ORIGINAL token should authenticate again (no re-mint), got %d %s", s, b)
	}
}

// TestScimDeleteIsSoftDelete proves DELETE /scim/v2/Users/{id} deactivates
// rather than hard-deleting — a deliberate divergence from DELETE
// /api/users/{id}'s own hard-delete semantics, not an oversight. The row
// must still exist afterward, just inactive.
func TestScimDeleteIsSoftDelete(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{ScimEnabled: true})
	scimTok := mintScimKey(t, srv, "onelogin")

	status, data := scimDo(t, srv, http.MethodPost, "/scim/v2/Users", scimTok, map[string]any{"userName": "carol"})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, data)
	}
	scimID := jsonMap(t, data)["id"].(string)

	if s, b := scimDo(t, srv, http.MethodDelete, "/scim/v2/Users/"+scimID, scimTok, nil); s != http.StatusNoContent {
		t.Fatalf("scim delete: %d %s", s, b)
	}

	u, err := st.GetUser(context.Background(), atoi64(t, scimID))
	if err != nil {
		t.Fatalf("row should still exist after a SCIM delete (soft), got error: %v", err)
	}
	if u.Active {
		t.Fatal("row should be inactive after a SCIM delete")
	}
}

// TestScimUserNameImmutableOnReplace proves PUT refuses to rename a user
// rather than silently ignoring the requested change, matching this
// codebase's existing "username is immutable" invariant.
func TestScimUserNameImmutableOnReplace(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{ScimEnabled: true})
	scimTok := mintScimKey(t, srv, "idp")

	status, data := scimDo(t, srv, http.MethodPost, "/scim/v2/Users", scimTok, map[string]any{"userName": "dave"})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, data)
	}
	scimID := jsonMap(t, data)["id"].(string)

	status, data = scimDo(t, srv, http.MethodPut, "/scim/v2/Users/"+scimID, scimTok, map[string]any{"userName": "someone-else"})
	if status != http.StatusBadRequest {
		t.Fatalf("renaming userName via PUT should be refused, got %d %s", status, data)
	}
}

// TestScimBadOrDisabledKeyRefused proves an unknown bearer token, and a
// revoked SCIM key's token, both fail closed.
func TestScimBadOrDisabledKeyRefused(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{ScimEnabled: true})
	if s, _ := scimDo(t, srv, http.MethodGet, "/scim/v2/Users", "not-a-real-token", nil); s != http.StatusUnauthorized {
		t.Fatalf("unknown token should be 401, got %d", s)
	}

	status, data := do(t, srv, http.MethodPost, "/v1/scim-keys", testAPIKey, map[string]any{"name": "revoke-me"})
	if status != http.StatusCreated {
		t.Fatalf("mint: %d %s", status, data)
	}
	m := jsonMap(t, data)
	keyID := int64(mustFloat(t, m["id"]))
	tok := m["token"].(string)

	if s, _ := scimDo(t, srv, http.MethodGet, "/scim/v2/Users", tok, nil); s != http.StatusOK {
		t.Fatalf("freshly minted key should work, got %d", s)
	}
	if s, b := do(t, srv, http.MethodDelete, "/v1/scim-keys/"+itoa(keyID), testAPIKey, nil); s != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", s, b)
	}
	if s, _ := scimDo(t, srv, http.MethodGet, "/scim/v2/Users", tok, nil); s != http.StatusUnauthorized {
		t.Fatalf("revoked key's token should be refused, got %d", s)
	}
}

// mustFloat asserts v is a JSON number (unmarshaled as float64) and returns it.
func mustFloat(t *testing.T, v any) float64 {
	t.Helper()
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("expected a JSON number, got %T: %v", v, v)
	}
	return f
}

// atoi64 parses a SCIM resource id (a decimal string) back into pamv1's own
// int64 row id, failing the test on a malformed value.
func atoi64(t *testing.T, s string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		t.Fatalf("id %q is not a valid int64: %v", s, err)
	}
	return n
}

// TestScimCannotTouchAdmin is the regression for the 2026-08-26 audit's F-5. A
// SCIM key is an IdP connector's machine credential; it manages ordinary users,
// but must not deactivate, delete, or reactivate an ADMIN — that would let a
// compromised connector revoke privileged access, or restore an admin an
// operator deliberately killed.
func TestScimCannotTouchAdmin(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{ScimEnabled: true})
	scimTok := mintScimKey(t, srv, "azuread")

	admin := store.User{Username: "root-admin", Role: string(auth.RoleAdmin), TokenHash: auth.TokenHash("pamt_admin_tok")}
	if err := st.CreateUser(context.Background(), &admin); err != nil {
		t.Fatal(err)
	}
	sid := itoa(admin.ID)

	// PATCH deactivate — the deprovisioning path — is refused.
	if code, d := scimDo(t, srv, http.MethodPatch, "/scim/v2/Users/"+sid, scimTok, map[string]any{
		"Operations": []map[string]any{{"op": "Replace", "value": map[string]any{"active": false}}},
	}); code != http.StatusNotFound {
		t.Fatalf("SCIM deactivated an admin: %d %s, want 404", code, d)
	}
	// DELETE (soft-delete) is refused.
	if code, d := scimDo(t, srv, http.MethodDelete, "/scim/v2/Users/"+sid, scimTok, nil); code != http.StatusNotFound {
		t.Fatalf("SCIM soft-deleted an admin: %d %s, want 404", code, d)
	}
	// PUT (replace, which could set active) is refused.
	if code, d := scimDo(t, srv, http.MethodPut, "/scim/v2/Users/"+sid, scimTok, map[string]any{
		"userName": "root-admin", "active": true,
	}); code != http.StatusNotFound {
		t.Fatalf("SCIM replaced an admin: %d %s, want 404", code, d)
	}

	// The admin is untouched and still active.
	if got, _ := st.GetUser(context.Background(), admin.ID); got == nil || !got.Active {
		t.Fatal("the admin was modified by a SCIM write")
	}
}
