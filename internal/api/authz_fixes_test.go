package api_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// TestConfigRequiresAdmin proves PUT/DELETE /api/config are restricted to a
// built-in admin — a delegated manage_users profile can reach the route (it holds
// CapManageUsers) but cannot change configuration, closing the escalation vector.
func TestConfigRequiresAdmin(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})
	if code, _ := do(t, srv, http.MethodPost, "/api/profiles", testAPIKey, map[string]any{"name": "helpdesk", "capabilities": []string{"manage_users"}}); code != http.StatusCreated {
		t.Fatalf("create profile: %d", code)
	}
	_, ud := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "hd", "role": "helpdesk"})
	tok, _ := jsonMap(t, ud)["token"].(string)

	// The delegated user-admin cannot weaken config (would remap admin / disable MFA).
	if code, _ := do(t, srv, http.MethodPut, "/api/config", tok, map[string]any{"key": "PAM_MFA_REQUIRED", "value": "false"}); code != http.StatusForbidden {
		t.Fatalf("helpdesk PUT config: want 403, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodDelete, "/api/config/PAM_MFA_REQUIRED", tok, nil); code != http.StatusForbidden {
		t.Fatalf("helpdesk DELETE config: want 403, got %d", code)
	}
	// The bootstrap admin still can.
	if code, _ := do(t, srv, http.MethodPut, "/api/config", testAPIKey, map[string]any{"key": "PAM_MFA_REQUIRED", "value": "true"}); code != http.StatusOK {
		t.Fatalf("admin PUT config: want 200, got %d", code)
	}
}

// TestRevealAndCheckoutObeyApproval proves reveal and checkout now honor the
// four-eyes approval gate, exactly like the connect paths.
func TestRevealAndCheckoutObeyApproval(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{RequireApproval: true})
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{"name": "lnx", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh"})
	tid := int64(jsonMap(t, td)["id"].(float64))
	_, cd := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{"target_id": tid, "username": "root", "secret": "pw"})
	cid := int64(jsonMap(t, cd)["id"].(float64))

	// With global approval required and no approved request, both are 403.
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reveal", cid), testAPIKey, nil); code != http.StatusForbidden {
		t.Fatalf("reveal under approval policy: want 403, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout", cid), testAPIKey, nil); code != http.StatusForbidden {
		t.Fatalf("checkout under approval policy: want 403, got %d", code)
	}
}

// TestCheckinHolderOnly proves only the lease holder (or an admin) may check a
// credential back in.
func TestCheckinHolderOnly(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{"name": "lnx", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh"})
	tid := int64(jsonMap(t, td)["id"].(float64))
	_, cd := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{"target_id": tid, "username": "root", "secret": "pw"})
	cid := int64(jsonMap(t, cd)["id"].(float64))

	// Admin checks it out (holder = bootstrap-admin).
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout", cid), testAPIKey, nil); code != http.StatusCreated {
		t.Fatalf("admin checkout: %d", code)
	}
	// A different reveal-capable user cannot check in someone else's lease.
	do(t, srv, http.MethodPost, "/api/profiles", testAPIKey, map[string]any{"name": "revealer", "capabilities": []string{"reveal_secret"}})
	_, ud := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "bob", "role": "revealer"})
	bob, _ := jsonMap(t, ud)["token"].(string)
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkin", cid), bob, nil); code != http.StatusForbidden {
		t.Fatalf("non-holder checkin: want 403, got %d", code)
	}
	// The admin (override) can.
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkin", cid), testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("admin checkin: want 200, got %d", code)
	}
}

// TestDelegatedUserAdminCannotOverruleAGreaterIdentity is the Phase 290
// regression for the writes on an EXISTING identity. Minting and re-roling
// were bounded by the role being assigned, and token rotation (Phase 248) by
// the identity being rotated — but updateUser never looked at the identity's
// current role, and lock, unlock and delete looked at nothing. A delegated
// user-admin could demote an administrator to a role it did cover, lock one
// out, lift another administrator's lock, or delete one. Each is now refused
// and audited; an identity within the delegate's own reach is unaffected.
func TestDelegatedUserAdminCannotOverruleAGreaterIdentity(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{})
	for name, caps := range map[string][]string{"helpdesk": {"manage_users"}, "nobody": {}} {
		if code, d := do(t, srv, http.MethodPost, "/api/profiles", testAPIKey, map[string]any{"name": name, "capabilities": caps}); code != http.StatusCreated {
			t.Fatalf("create profile %s: %d %s", name, code, d)
		}
	}
	mint := func(username, role string) (int64, string) {
		t.Helper()
		code, d := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": username, "role": role})
		if code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", username, code, d)
		}
		m := jsonMap(t, d)
		return int64(m["id"].(float64)), m["token"].(string)
	}
	_, hd := mint("hd", "helpdesk")
	adminID, adminTok := mint("root2", "admin")
	peerID, _ := mint("temp", "nobody")
	user := func(id int64, suffix string) string { return fmt.Sprintf("/api/users/%d%s", id, suffix) }
	lock := map[string]any{"reason": "testing"}

	// Above the delegate: every write is refused, and the administrator is
	// untouched by any of them.
	for _, tc := range []struct {
		verb, method, path string
		body               any
	}{
		{"update", http.MethodPut, user(adminID, ""), map[string]any{"role": "nobody"}}, // a demotion
		{"lock", http.MethodPost, user(adminID, "/lock"), lock},
		{"rotate", http.MethodPost, user(adminID, "/token"), nil},
		{"delete", http.MethodDelete, user(adminID, ""), nil},
	} {
		if code, d := do(t, srv, tc.method, tc.path, hd, tc.body); code != http.StatusForbidden {
			t.Errorf("helpdesk %s of an administrator: %d %s, want 403", tc.verb, code, d)
		}
		auditHas(t, st, "authz.denied", "user:root2 reason:"+tc.verb+"-beyond-caps")
	}
	if code, d := do(t, srv, http.MethodGet, "/api/me", adminTok, nil); code != http.StatusOK || jsonMap(t, d)["role"] != "admin" {
		t.Fatalf("the administrator after the refused writes: %d %s", code, d)
	}
	// A lock another administrator placed is not the delegate's to lift.
	if code, d := do(t, srv, http.MethodPost, user(adminID, "/lock"), testAPIKey, lock); code != http.StatusOK {
		t.Fatalf("bootstrap lock: %d %s", code, d)
	}
	if code, d := do(t, srv, http.MethodDelete, user(adminID, "/lock"), hd, nil); code != http.StatusForbidden {
		t.Errorf("helpdesk unlock of an administrator: %d %s, want 403", code, d)
	}
	if code, _ := do(t, srv, http.MethodGet, "/api/me", adminTok, nil); code != http.StatusUnauthorized {
		t.Errorf("the locked administrator still resolves: %d", code)
	}

	// Within the delegate's reach: unchanged.
	for _, tc := range []struct {
		what, method, path string
		body               any
		want               int
	}{
		{"update", http.MethodPut, user(peerID, ""), map[string]any{"role": "nobody"}, http.StatusOK},
		{"lock", http.MethodPost, user(peerID, "/lock"), lock, http.StatusOK},
		{"unlock", http.MethodDelete, user(peerID, "/lock"), nil, http.StatusOK},
		{"rotate", http.MethodPost, user(peerID, "/token"), nil, http.StatusOK},
		{"delete", http.MethodDelete, user(peerID, ""), nil, http.StatusNoContent},
	} {
		if code, d := do(t, srv, tc.method, tc.path, hd, tc.body); code != tc.want {
			t.Errorf("helpdesk %s of an identity within its reach: %d %s, want %d", tc.what, code, d, tc.want)
		}
	}
	// And a built-in administrator manages anyone.
	if code, d := do(t, srv, http.MethodDelete, user(adminID, ""), testAPIKey, nil); code != http.StatusNoContent {
		t.Errorf("bootstrap delete of an administrator: %d %s", code, d)
	}
}
