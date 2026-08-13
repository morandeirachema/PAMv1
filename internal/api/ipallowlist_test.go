package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// TestCreateUserWithIPAllowlist proves POST /api/users accepts and persists
// an ip_allowlist, rejects a malformed one, and that a fresh user with none
// stays unrestricted (Phase 118).
func TestCreateUserWithIPAllowlist(t *testing.T) {
	srv := newTestServer(t)

	code, data := do(t, srv, http.MethodPost, "/api/users", testAPIKey,
		map[string]any{"username": "alice", "role": "user", "ip_allowlist": "10.0.0.0/8, 192.168.1.0/24"})
	if code != http.StatusCreated {
		t.Fatalf("create with allowlist: %d %s", code, data)
	}
	if got := jsonMap(t, data)["ip_allowlist"]; got != "10.0.0.0/8, 192.168.1.0/24" {
		t.Fatalf("ip_allowlist in response = %v", got)
	}

	if code, d := do(t, srv, http.MethodPost, "/api/users", testAPIKey,
		map[string]any{"username": "bob", "role": "user", "ip_allowlist": "not-a-cidr"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("create with malformed allowlist: %d %s, want 422", code, d)
	}

	code, data = do(t, srv, http.MethodPost, "/api/users", testAPIKey,
		map[string]any{"username": "carol", "role": "user"})
	if code != http.StatusCreated {
		t.Fatalf("create without allowlist: %d %s", code, data)
	}
	if got, ok := jsonMap(t, data)["ip_allowlist"]; ok && got != "" {
		t.Fatalf("ip_allowlist for a user who never set one = %v, want empty/absent", got)
	}
}

// TestUpdateUserIPAllowlistOmitVsClear proves PUT /api/users/{id} leaves an
// existing allowlist untouched when ip_allowlist is omitted from the body,
// and clears it only when the field is explicitly sent as "" — the
// omit-means-leave-alone semantics that keep a role-only update from
// silently disabling a security restriction (Phase 118).
func TestUpdateUserIPAllowlistOmitVsClear(t *testing.T) {
	srv := newTestServer(t)
	_, data := do(t, srv, http.MethodPost, "/api/users", testAPIKey,
		map[string]any{"username": "alice", "role": "user", "ip_allowlist": "10.0.0.0/8"})
	id := int64(jsonMap(t, data)["id"].(float64))
	path := "/api/users/" + itoa(id)

	// Omitting ip_allowlist entirely (only role sent) must NOT clear it.
	if code, d := do(t, srv, http.MethodPut, path, testAPIKey, map[string]any{"role": "auditor"}); code != http.StatusOK {
		t.Fatalf("role-only update: %d %s", code, d)
	}
	code, data := do(t, srv, http.MethodGet, "/api/users", testAPIKey, nil)
	if code != http.StatusOK || !strings.Contains(string(data), "10.0.0.0/8") {
		t.Fatalf("allowlist should survive a role-only update: %d %s", code, data)
	}

	// Explicitly sending an empty string DOES clear it.
	if code, d := do(t, srv, http.MethodPut, path, testAPIKey,
		map[string]any{"role": "auditor", "ip_allowlist": ""}); code != http.StatusOK {
		t.Fatalf("explicit clear: %d %s", code, d)
	}
	code, data = do(t, srv, http.MethodGet, "/api/users", testAPIKey, nil)
	if code != http.StatusOK || strings.Contains(string(data), "10.0.0.0/8") {
		t.Fatalf("allowlist should be cleared: %d %s", code, data)
	}

	// A malformed allowlist on update is rejected.
	if code, d := do(t, srv, http.MethodPut, path, testAPIKey,
		map[string]any{"role": "auditor", "ip_allowlist": "not-a-cidr"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("update with malformed allowlist: %d %s, want 422", code, d)
	}
}

// TestAuthzRefusesOutsideIPAllowlist proves the shared authz middleware
// enforces a principal's IPAllowlist on every authenticated request (Phase
// 118), using PAM_TRUSTED_PROXY_HOPS + X-Forwarded-For to present a chosen
// apparent client address (the httptest.Server's real peer is always
// 127.0.0.1, so simulating a different source is the only way to prove both
// the allow and deny sides against a single running server).
func TestAuthzRefusesOutsideIPAllowlist(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{TrustedProxyHops: 1})
	_, data := do(t, srv, http.MethodPost, "/api/users", testAPIKey,
		map[string]any{"username": "alice", "role": "user", "ip_allowlist": "10.0.0.0/8"})
	m := jsonMap(t, data)
	tok := m["token"].(string)

	get := func(xff string) int {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/targets", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-API-Key", tok)
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("203.0.113.5"); code != http.StatusForbidden {
		t.Fatalf("request from outside the allowlist: %d, want 403", code)
	}
	if code := get("10.1.2.3"); code != http.StatusOK {
		t.Fatalf("request from inside the allowlist: %d, want 200", code)
	}

	// The refusal is audited.
	events, err := st.ListAudit(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "authz.denied" && strings.Contains(e.Detail, "reason:source-ip-not-allowed") {
			found = true
		}
	}
	if !found {
		t.Fatal("no authz.denied reason:source-ip-not-allowed audit event")
	}
}
