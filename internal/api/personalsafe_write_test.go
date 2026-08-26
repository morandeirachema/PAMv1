package api_test

import (
	"fmt"
	"net/http"
	"testing"
)

// TestPersonalSafeWritesRestricted pins the 2026-08-27 audit fix: a plain
// manage_targets/manage_credentials principal — enough for any ordinary safe
// — can neither plant a credential on, delete a credential of, nor delete a
// target that sits in someone else's personal safe. Phase 212's M-5 closed
// the privacy bypasses; these are the integrity ones. The safe's own owner
// keeps full control of their target, and the override capability manages it.
func TestPersonalSafeWritesRestricted(t *testing.T) {
	srv := newTestServer(t)
	targetID, credID := seedPersonalSafeTarget(t, srv, "alice")

	carol := seedProfileUser(t, srv, "plain-manager", "carol",
		"read_inventory", "manage_targets", "manage_credentials")
	newCred := map[string]any{"target_id": targetID, "username": "planted", "secret": secretPassword}

	if code, d := do(t, srv, http.MethodPost, "/api/credentials", carol, newCred); code != http.StatusForbidden {
		t.Fatalf("plain manager planting a credential on a personal target: want 403, got %d: %s", code, d)
	}
	if code, d := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/credentials/%d", credID), carol, nil); code != http.StatusForbidden {
		t.Fatalf("plain manager deleting a personal target's credential: want 403, got %d: %s", code, d)
	}
	if code, d := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/targets/%d", targetID), carol, nil); code != http.StatusForbidden {
		t.Fatalf("plain manager deleting a personal target: want 403, got %d: %s", code, d)
	}

	// The owner (seeded as a can_manage member of their own safe) is admitted.
	alice := seedProfileUser(t, srv, "owner-manager", "alice",
		"read_inventory", "manage_targets", "manage_credentials")
	code, data := do(t, srv, http.MethodPost, "/api/credentials", alice, newCred)
	if code != http.StatusCreated {
		t.Fatalf("owner adding a credential to their own personal target: want 201, got %d: %s", code, data)
	}
	planted := int64(jsonMap(t, data)["id"].(float64))
	if code, d := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/credentials/%d", planted), alice, nil); code != http.StatusNoContent {
		t.Fatalf("owner deleting their own credential: want 204, got %d: %s", code, d)
	}

	// So is the override capability, and so is an ordinary target for carol.
	override := seedProfileUser(t, srv, "vault-override3", "security-lead3",
		"read_inventory", "manage_targets", "unlimited_vault_access")
	if code, d := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/targets/%d", targetID), override, nil); code != http.StatusNoContent {
		t.Fatalf("override deleting a personal target: want 204, got %d: %s", code, d)
	}
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "plain-box", "host": "10.0.0.10", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	plainID := int64(jsonMap(t, td)["id"].(float64))
	if code, d := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/targets/%d", plainID), carol, nil); code != http.StatusNoContent {
		t.Fatalf("plain manager deleting an ordinary target: want 204, got %d: %s", code, d)
	}
}
