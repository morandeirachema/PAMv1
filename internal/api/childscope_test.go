package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// TestSafeMemberDeleteScopedToSafe proves a delegated manager of one safe cannot
// remove a member of ANOTHER safe by its (global) member id. The authorization
// check is per-safe, so the member the route acts on must belong to the safe in
// the path — otherwise delegated safe administration would be a lever to strip
// access anywhere in the system.
func TestSafeMemberDeleteScopedToSafe(t *testing.T) {
	srv := newTestServer(t)

	newSafe := func(name string) int64 {
		t.Helper()
		code, data := do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{"name": name})
		if code != http.StatusCreated {
			t.Fatalf("create safe %s: status %d body %s", name, code, data)
		}
		return int64(jsonMap(t, data)["id"].(float64))
	}
	addMember := func(safeID int64, subject string, canManage bool) int64 {
		t.Helper()
		code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeID), testAPIKey,
			map[string]any{"subject_type": "user", "subject": subject, "can_manage": canManage})
		if code != http.StatusCreated {
			t.Fatalf("add member %s: status %d body %s", subject, code, data)
		}
		return int64(jsonMap(t, data)["id"].(float64))
	}
	memberCount := func(safeID int64) int {
		t.Helper()
		_, data := do(t, srv, http.MethodGet, fmt.Sprintf("/api/safes/%d/members", safeID), testAPIKey, nil)
		var members []map[string]any
		if err := json.Unmarshal(data, &members); err != nil {
			t.Fatalf("decode members: %v", err)
		}
		return len(members)
	}

	safeA, safeB := newSafe("team-a"), newSafe("team-b")
	// bob administers safe A only; carol is a member of safe B.
	bobTok := seedUser(t, srv, "bob", "user")
	addMember(safeA, "bob", true)
	victim := addMember(safeB, "carol", false)

	// bob aims his own safe's route at safe B's member id.
	if code, body := do(t, srv, http.MethodDelete,
		fmt.Sprintf("/api/safes/%d/members/%d", safeA, victim), bobTok, nil); code != http.StatusNotFound {
		t.Fatalf("cross-safe member delete: status %d body %s, want 404", code, body)
	}
	if n := memberCount(safeB); n != 1 {
		t.Fatalf("safe B member count = %d, want 1 (carol must survive)", n)
	}

	// Positive control: bob may still remove a member of the safe he manages.
	own := addMember(safeA, "dave", false)
	if code, body := do(t, srv, http.MethodDelete,
		fmt.Sprintf("/api/safes/%d/members/%d", safeA, own), bobTok, nil); code != http.StatusNoContent {
		t.Fatalf("in-safe member delete: status %d body %s, want 204", code, body)
	}
}

// TestDependencyDeleteScopedToCredential proves the credential in the path bounds
// which dependency the route may remove, so one credential's route cannot unlink
// another credential's consumer (and the audit names the owning credential).
func TestDependencyDeleteScopedToCredential(t *testing.T) {
	srv := newTestServer(t)
	credA := seedTargetCred(t, srv, "ssh", "", "secret-a")
	credB := seedTargetCred(t, srv, "ssh", "", "secret-b")

	code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/dependencies", credB), testAPIKey,
		map[string]any{"kind": "windows_service", "host": "app-01", "name": "SvcB"})
	if code != http.StatusCreated {
		t.Fatalf("declare dependency: status %d body %s", code, data)
	}
	depB := int64(jsonMap(t, data)["id"].(float64))

	// Credential A's route must not reach credential B's dependency.
	if code, body := do(t, srv, http.MethodDelete,
		fmt.Sprintf("/api/credentials/%d/dependencies/%d", credA, depB), testAPIKey, nil); code != http.StatusNotFound {
		t.Fatalf("cross-credential dependency delete: status %d body %s, want 404", code, body)
	}
	_, listed := do(t, srv, http.MethodGet, fmt.Sprintf("/api/credentials/%d/dependencies", credB), testAPIKey, nil)
	var deps []map[string]any
	if err := json.Unmarshal(listed, &deps); err != nil {
		t.Fatalf("decode dependencies: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("credential B dependency count = %d, want 1 (it must survive)", len(deps))
	}

	// Through its own credential the delete succeeds.
	if code, body := do(t, srv, http.MethodDelete,
		fmt.Sprintf("/api/credentials/%d/dependencies/%d", credB, depB), testAPIKey, nil); code != http.StatusNoContent {
		t.Fatalf("in-credential dependency delete: status %d body %s, want 204", code, body)
	}
}
