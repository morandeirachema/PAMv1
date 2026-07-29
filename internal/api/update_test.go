package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// createTestTarget creates a target through the API and returns its id.
func createTestTarget(t *testing.T, srv *httptest.Server, name, host string) int64 {
	t.Helper()
	code, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": name, "host": host, "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if code != http.StatusCreated {
		t.Fatalf("create target %s: %d %s", name, code, data)
	}
	return int64(jsonMap(t, data)["id"].(float64))
}

// TestUpdateTargetEndpoint proves PUT /api/targets/{id} edits a target in place
// — its credentials and grants survive, unlike the old delete + recreate — with
// create-equivalent validation, conflict detection, authorization and audit.
func TestUpdateTargetEndpoint(t *testing.T) {
	srv, st := newTestServerStore(t)
	id := createTestTarget(t, srv, "web-01", "10.0.0.5")
	otherID := createTestTarget(t, srv, "web-02", "10.0.0.6")

	// Attach a credential and a grant — the dependents that delete+recreate
	// would cascade away.
	if code, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": id, "username": "root", "secret": secretPassword,
	}); code != http.StatusCreated {
		t.Fatalf("create credential: %d %s", code, d)
	}
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", id), testAPIKey, map[string]any{
		"subject_type": "user", "subject": "alice",
	}); code != http.StatusCreated {
		t.Fatalf("create grant: %d %s", code, d)
	}

	// Edit host and port in place.
	code, data := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d", id), testAPIKey, map[string]any{
		"name": "web-01", "host": "10.0.0.50", "port": 2222, "os_type": "linux", "protocol": "ssh",
	})
	if code != http.StatusOK {
		t.Fatalf("update target: %d %s", code, data)
	}
	if m := jsonMap(t, data); m["host"] != "10.0.0.50" || m["port"].(float64) != 2222 {
		t.Fatalf("update response: %s", data)
	}
	auditHas(t, st, "target.update", "target:")

	// The dependents survived the edit.
	if _, d := do(t, srv, http.MethodGet, fmt.Sprintf("/api/credentials?target_id=%d", id), testAPIKey, nil); string(d) == "[]" {
		t.Fatal("credential did not survive the target update")
	}
	if _, d := do(t, srv, http.MethodGet, fmt.Sprintf("/api/targets/%d/grants", id), testAPIKey, nil); string(d) == "[]" {
		t.Fatal("grant did not survive the target update")
	}

	// Validation mirrors create; conflicts and absence map to 409/404; a plain
	// user may not edit.
	if code, _ := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d", id), testAPIKey, map[string]any{
		"name": "web-01", "host": "h", "port": 70000, "os_type": "linux", "protocol": "ssh",
	}); code != http.StatusUnprocessableEntity {
		t.Fatalf("bad port: want 422, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d", otherID), testAPIKey, map[string]any{
		"name": "web-01", "host": "h", "port": 22, "os_type": "linux", "protocol": "ssh",
	}); code != http.StatusConflict {
		t.Fatalf("rename onto taken name: want 409, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodPut, "/api/targets/99999", testAPIKey, map[string]any{
		"name": "ghost", "host": "h", "port": 22, "os_type": "linux", "protocol": "ssh",
	}); code != http.StatusNotFound {
		t.Fatalf("unknown target: want 404, got %d", code)
	}
	userTok := seedUser(t, srv, "eve", "user")
	if code, _ := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d", id), userTok, map[string]any{
		"name": "web-01", "host": "h", "port": 22, "os_type": "linux", "protocol": "ssh",
	}); code != http.StatusForbidden {
		t.Fatalf("user update target: want 403, got %d", code)
	}
}

// TestUpdateSafeEndpoint proves PUT /api/safes/{id} renames in place with
// conflict/absence mapping and manage-targets authorization.
func TestUpdateSafeEndpoint(t *testing.T) {
	srv, st := newTestServerStore(t)
	code, data := do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{"name": "prod", "description": "production"})
	if code != http.StatusCreated {
		t.Fatalf("create safe: %d %s", code, data)
	}
	id := int64(jsonMap(t, data)["id"].(float64))
	code, data = do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{"name": "dmz"})
	if code != http.StatusCreated {
		t.Fatalf("create safe 2: %d %s", code, data)
	}
	otherID := int64(jsonMap(t, data)["id"].(float64))

	if code, d := do(t, srv, http.MethodPut, fmt.Sprintf("/api/safes/%d", id), testAPIKey, map[string]any{
		"name": "prod-eu", "description": "EU production",
	}); code != http.StatusOK || jsonMap(t, d)["name"] != "prod-eu" {
		t.Fatalf("update safe: %d %s", code, d)
	}
	auditHas(t, st, "safe.update", "prod-eu")
	if code, _ := do(t, srv, http.MethodPut, fmt.Sprintf("/api/safes/%d", otherID), testAPIKey, map[string]any{"name": "prod-eu"}); code != http.StatusConflict {
		t.Fatalf("rename onto taken safe name: want 409, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodPut, fmt.Sprintf("/api/safes/%d", id), testAPIKey, map[string]any{"name": ""}); code != http.StatusUnprocessableEntity {
		t.Fatalf("empty name: want 422, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodPut, "/api/safes/99999", testAPIKey, map[string]any{"name": "ghost"}); code != http.StatusNotFound {
		t.Fatalf("unknown safe: want 404, got %d", code)
	}
	userTok := seedUser(t, srv, "sam", "user")
	if code, _ := do(t, srv, http.MethodPut, fmt.Sprintf("/api/safes/%d", id), userTok, map[string]any{"name": "x"}); code != http.StatusForbidden {
		t.Fatalf("user update safe: want 403, got %d", code)
	}
}

// TestUpdateUserRoleEndpoint proves PUT /api/users/{id} changes a role in place
// — the existing token keeps working and immediately carries the new role —
// with the same privilege-escalation guard as create.
func TestUpdateUserRoleEndpoint(t *testing.T) {
	srv, st := newTestServerStore(t)
	bobTok := seedUser(t, srv, "bob", "user")
	var bobID int64
	_, ud := do(t, srv, http.MethodGet, "/api/users", testAPIKey, nil)
	var users []map[string]any
	if err := json.Unmarshal(ud, &users); err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u["username"] == "bob" {
			bobID = int64(u["id"].(float64))
		}
	}
	if bobID == 0 {
		t.Fatal("seeded user not listed")
	}

	// As a plain user, bob cannot read the audit trail.
	if code, _ := do(t, srv, http.MethodGet, "/api/audit", bobTok, nil); code != http.StatusForbidden {
		t.Fatalf("user reads audit: want 403, got %d", code)
	}
	// Promote bob to auditor — same token, new capabilities, no re-mint.
	if code, d := do(t, srv, http.MethodPut, fmt.Sprintf("/api/users/%d", bobID), testAPIKey, map[string]any{"role": "auditor"}); code != http.StatusOK {
		t.Fatalf("update role: %d %s", code, d)
	}
	auditHas(t, st, "user.update", "role:user->auditor")
	if code, _ := do(t, srv, http.MethodGet, "/api/audit", bobTok, nil); code != http.StatusOK {
		t.Fatalf("promoted token reads audit: want 200, got %d", code)
	}

	// Validation + absence.
	if code, _ := do(t, srv, http.MethodPut, fmt.Sprintf("/api/users/%d", bobID), testAPIKey, map[string]any{"role": "nonsense"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("bad role: want 422, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodPut, "/api/users/99999", testAPIKey, map[string]any{"role": "user"}); code != http.StatusNotFound {
		t.Fatalf("unknown user: want 404, got %d", code)
	}

	// Privilege-escalation guard: a delegated user-admin (manage_users only)
	// cannot promote anyone to full admin.
	if code, d := do(t, srv, http.MethodPost, "/api/profiles", testAPIKey, map[string]any{
		"name": "useradmin", "capabilities": []string{"manage_users", "read_inventory"},
	}); code != http.StatusCreated {
		t.Fatalf("create profile: %d %s", code, d)
	}
	delegateTok := seedUser(t, srv, "delegate", "useradmin")
	if code, _ := do(t, srv, http.MethodPut, fmt.Sprintf("/api/users/%d", bobID), delegateTok, map[string]any{"role": "admin"}); code != http.StatusForbidden {
		t.Fatalf("delegated promote-to-admin: want 403, got %d", code)
	}
}

// TestUpdateVendorEndpoint proves PUT /api/vendors/{id} edits the org label in
// place and audits it; the username is immutable by design (no field to send).
func TestUpdateVendorEndpoint(t *testing.T) {
	srv, st := newTestServerStore(t)
	code, data := do(t, srv, http.MethodPost, "/api/vendors", testAPIKey, map[string]any{"username": "acme-tech", "org": "ACME"})
	if code != http.StatusCreated {
		t.Fatalf("create vendor: %d %s", code, data)
	}
	id := int64(jsonMap(t, data)["id"].(float64))

	if code, d := do(t, srv, http.MethodPut, fmt.Sprintf("/api/vendors/%d", id), testAPIKey, map[string]any{"org": "ACME Industries"}); code != http.StatusOK || jsonMap(t, d)["org"] != "ACME Industries" {
		t.Fatalf("update vendor: %d %s", code, d)
	}
	auditHas(t, st, "vendor.update", "acme-tech")
	if code, _ := do(t, srv, http.MethodPut, "/api/vendors/99999", testAPIKey, map[string]any{"org": "x"}); code != http.StatusNotFound {
		t.Fatalf("unknown vendor: want 404, got %d", code)
	}
	userTok := seedUser(t, srv, "pat", "user")
	if code, _ := do(t, srv, http.MethodPut, fmt.Sprintf("/api/vendors/%d", id), userTok, map[string]any{"org": "x"}); code != http.StatusForbidden {
		t.Fatalf("user update vendor: want 403, got %d", code)
	}
}

// TestListWindowPagination proves the inventory list endpoints serve bounded,
// cursor-pageable windows: ?limit= caps the page, ?after= resumes past the
// last id, and an out-of-range limit falls back to the clamped default.
func TestListWindowPagination(t *testing.T) {
	srv := newTestServer(t)
	var ids []int64
	for i := 1; i <= 3; i++ {
		ids = append(ids, createTestTarget(t, srv, fmt.Sprintf("pg-%d", i), fmt.Sprintf("10.1.0.%d", i)))
	}

	page := func(path string) []map[string]any {
		t.Helper()
		code, d := do(t, srv, http.MethodGet, path, testAPIKey, nil)
		if code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, code, d)
		}
		var rows []map[string]any
		if err := json.Unmarshal(d, &rows); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		return rows
	}

	if rows := page("/api/targets?limit=2"); len(rows) != 2 || int64(rows[0]["id"].(float64)) != ids[0] {
		t.Fatalf("limit=2: got %d rows", len(rows))
	}
	if rows := page(fmt.Sprintf("/api/targets?limit=2&after=%d", ids[1])); len(rows) != 1 || int64(rows[0]["id"].(float64)) != ids[2] {
		t.Fatalf("after=%d: got %+v", ids[1], rows)
	}
	if rows := page(fmt.Sprintf("/api/targets?after=%d", ids[2])); len(rows) != 0 {
		t.Fatalf("after=last: got %d rows", len(rows))
	}
	// A hostile or typo'd limit cannot disable the bound — it falls back to the
	// clamped default rather than "return everything".
	if rows := page("/api/targets?limit=0"); len(rows) != 3 {
		t.Fatalf("limit=0 fallback: got %d rows", len(rows))
	}
	if rows := page("/api/targets?limit=99999"); len(rows) != 3 {
		t.Fatalf("limit clamp: got %d rows", len(rows))
	}
	// The same window applies to the other inventory lists (spot-check users).
	seedUser(t, srv, "w1", "user")
	seedUser(t, srv, "w2", "user")
	if rows := page("/api/users?limit=1"); len(rows) != 1 {
		t.Fatalf("users limit=1: got %d rows", len(rows))
	}
}

// TestTargetClipboardOverrideCRUD proves the per-target RDP clipboard override
// round-trips through create, read and update, and that a value outside the
// enum is refused — a typo that silently inherited the global would read as
// "this target is locked down" while it wasn't.
func TestTargetClipboardOverrideCRUD(t *testing.T) {
	srv := newTestServer(t)

	code, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "vault-jump", "host": "10.0.0.40", "port": 3389, "os_type": "windows", "protocol": "rdp",
		"rdp_clipboard": "readonly", "rdp_clipboard_audit": "meta",
	})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, data)
	}
	id := int64(jsonMap(t, data)["id"].(float64))

	_, got := do(t, srv, http.MethodGet, fmt.Sprintf("/api/targets/%d", id), testAPIKey, nil)
	m := jsonMap(t, got)
	if m["rdp_clipboard"] != "readonly" || m["rdp_clipboard_audit"] != "meta" {
		t.Fatalf("round-trip: clipboard=%v audit=%v", m["rdp_clipboard"], m["rdp_clipboard_audit"])
	}

	// Tighten to deny, drop the audit override back to inherit.
	if code, body := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d", id), testAPIKey, map[string]any{
		"name": "vault-jump", "host": "10.0.0.40", "port": 3389, "os_type": "windows", "protocol": "rdp",
		"rdp_clipboard": "deny",
	}); code != http.StatusOK {
		t.Fatalf("update: %d %s", code, body)
	}
	_, got = do(t, srv, http.MethodGet, fmt.Sprintf("/api/targets/%d", id), testAPIKey, nil)
	m = jsonMap(t, got)
	if m["rdp_clipboard"] != "deny" {
		t.Fatalf("after update: clipboard=%v, want deny", m["rdp_clipboard"])
	}
	if _, ok := m["rdp_clipboard_audit"]; ok {
		t.Fatalf("after update: audit override should be inherit (omitted), got %v", m["rdp_clipboard_audit"])
	}

	// Outside the enum → 422, on create and on update.
	if code, _ := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "bad-clip", "host": "10.0.0.41", "port": 3389, "os_type": "windows", "protocol": "rdp",
		"rdp_clipboard": "sometimes",
	}); code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid rdp_clipboard on create: %d, want 422", code)
	}
	if code, _ := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d", id), testAPIKey, map[string]any{
		"name": "vault-jump", "host": "10.0.0.40", "port": 3389, "os_type": "windows", "protocol": "rdp",
		"rdp_clipboard_audit": "verbose",
	}); code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid rdp_clipboard_audit on update: %d, want 422", code)
	}
}

// TestCreateMSSQLTarget proves the target inventory accepts the SQL Server
// protocol (Phase 53) — the enum, the portal selects and the proxy's own
// target check all have to agree, and this is the API half of that agreement.
func TestCreateMSSQLTarget(t *testing.T) {
	srv := newTestServer(t)

	code, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "sql-01", "host": "10.0.0.60", "port": 1433, "os_type": "windows", "protocol": "mssql",
	})
	if code != http.StatusCreated {
		t.Fatalf("create mssql target: %d %s", code, data)
	}
	if got := jsonMap(t, data)["protocol"]; got != "mssql" {
		t.Fatalf("protocol round-trip = %v", got)
	}

	if code, _ := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "bad-proto", "host": "10.0.0.61", "port": 1433, "os_type": "windows", "protocol": "sqlserver",
	}); code != http.StatusUnprocessableEntity {
		t.Fatalf("an unknown protocol was accepted: %d", code)
	}
}
