package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// seedPersonalSafeTarget creates a personal safe owned by owner, a target
// placed in it, and a credential on that target — returning the target and
// credential IDs. The safe's own membership check is exercised separately;
// this just gets a personal-safe-scoped credential in place quickly.
func seedPersonalSafeTarget(t *testing.T, srv *httptest.Server, owner string) (targetID, credID int64) {
	t.Helper()
	code, data := do(t, srv, http.MethodPost, "/api/safes", testAPIKey,
		map[string]any{"name": owner + "-personal", "personal": true, "owner": owner})
	if code != http.StatusCreated {
		t.Fatalf("create personal safe: %d %s", code, data)
	}
	safeID := int64(jsonMap(t, data)["id"].(float64))

	code, data = do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": owner + "-box", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if code != http.StatusCreated {
		t.Fatalf("create target: %d %s", code, data)
	}
	targetID = int64(jsonMap(t, data)["id"].(float64))
	if code, d := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d/safe", targetID), testAPIKey,
		map[string]any{"safe_id": safeID}); code != http.StatusNoContent {
		t.Fatalf("assign target to safe: %d %s", code, d)
	}

	code, data = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": targetID, "username": "root", "secret": secretPassword,
	})
	if code != http.StatusCreated {
		t.Fatalf("create credential: %d %s", code, data)
	}
	credID = int64(jsonMap(t, data)["id"].(float64))
	return targetID, credID
}

// TestPersonalSafeRequiresOwner proves createSafe's bootstrap invariant: a
// personal safe cannot be created without an owner (it would be
// unmanageable — see canManageSafe), and owner is rejected on an ordinary
// safe as meaningless. The owner is seeded as a can_manage member in the
// same call.
func TestPersonalSafeRequiresOwner(t *testing.T) {
	srv := newTestServer(t)

	if code, d := do(t, srv, http.MethodPost, "/api/safes", testAPIKey,
		map[string]any{"name": "orphan", "personal": true}); code != http.StatusUnprocessableEntity {
		t.Fatalf("personal safe with no owner: want 422, got %d: %s", code, d)
	}
	if code, d := do(t, srv, http.MethodPost, "/api/safes", testAPIKey,
		map[string]any{"name": "confused", "owner": "alice"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("owner on a non-personal safe: want 422, got %d: %s", code, d)
	}

	code, data := do(t, srv, http.MethodPost, "/api/safes", testAPIKey,
		map[string]any{"name": "alice-personal", "personal": true, "owner": "alice"})
	if code != http.StatusCreated {
		t.Fatalf("create personal safe: %d %s", code, data)
	}
	safeID := int64(jsonMap(t, data)["id"].(float64))
	if p, _ := jsonMap(t, data)["personal"].(bool); !p {
		t.Fatalf("created safe does not report personal:true: %s", data)
	}

	_, ld := do(t, srv, http.MethodGet, fmt.Sprintf("/api/safes/%d/members", safeID), testAPIKey, nil)
	var members []map[string]any
	if err := json.Unmarshal(ld, &members); err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0]["subject"] != "alice" || members[0]["can_manage"] != true {
		t.Fatalf("owner should be seeded as a can_manage member: %s", ld)
	}
}

// TestPersonalSafeDeniesPlainAdminReveal is the actual security property
// Phase 139 exists for: the bootstrap admin key — which holds reveal_secret
// unconditionally — is still turned away from a credential in someone
// else's personal safe, exactly like authorizedForTarget denies it a
// connect. A principal explicitly granted CapUnlimitedVaultAccess via a
// custom profile CAN reveal it, and that specific use is loudly audited.
// The safe's own owner, an ordinary non-admin profile, reveals normally.
func TestPersonalSafeDeniesPlainAdminReveal(t *testing.T) {
	srv := newTestServer(t)
	ownerTok := seedProfileUser(t, srv, "vault-user", "alice", "read_inventory", "connect", "reveal_secret")
	_, credID := seedPersonalSafeTarget(t, srv, "alice")

	// The built-in admin key holds reveal_secret unconditionally, and would
	// have succeeded before Phase 139 — that is exactly the bypass this
	// phase closes.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reveal", credID), testAPIKey, nil); code != http.StatusForbidden {
		t.Fatalf("plain admin reveal of a personal-safe credential: want 403, got %d: %s", code, d)
	}

	// The safe's own owner — a non-admin custom profile — reveals normally.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reveal", credID), ownerTok, nil); code != http.StatusOK {
		t.Fatalf("owner reveal: want 200, got %d: %s", code, d)
	}

	// A principal holding the named override reveals it too, and the use is
	// loudly audited — mirroring break-glass.
	overrideTok := seedProfileUser(t, srv, "vault-override", "security-lead",
		"read_inventory", "connect", "reveal_secret", "unlimited_vault_access")
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reveal", credID), overrideTok, nil); code != http.StatusOK {
		t.Fatalf("override reveal: want 200, got %d: %s", code, d)
	}
	_, ad := do(t, srv, http.MethodGet, "/api/audit", testAPIKey, nil)
	var events []map[string]any
	if err := json.Unmarshal(ad, &events); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e["action"] == "safe.personal_override_used" && e["actor"] == "security-lead" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a loud safe.personal_override_used audit event for security-lead, got %s", ad)
	}
}

// TestPersonalSafeManagementRestricted proves canManageSafe's own fix: a
// principal holding only CapManageTargets — enough to manage any ORDINARY
// safe's roster — cannot add themselves (or anyone else) to a personal
// safe they are not already a can_manage member of. Left open, this would
// be a side door around the reveal-time protection: add yourself, then
// connect/reveal as an ordinary member.
func TestPersonalSafeManagementRestricted(t *testing.T) {
	srv := newTestServer(t)
	_, _ = seedPersonalSafeTarget(t, srv, "alice") // safe "alice-personal"

	_, ld := do(t, srv, http.MethodGet, "/api/safes", testAPIKey, nil)
	var safes []map[string]any
	if err := json.Unmarshal(ld, &safes); err != nil {
		t.Fatal(err)
	}
	var safeID int64
	for _, sf := range safes {
		if sf["name"] == "alice-personal" {
			safeID = int64(sf["id"].(float64))
		}
	}
	if safeID == 0 {
		t.Fatalf("could not find the seeded personal safe: %s", ld)
	}

	// A target manager — sufficient for any ordinary safe — is refused here.
	managerTok := seedProfileUser(t, srv, "target-manager", "carol", "read_inventory", "manage_targets")
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeID), managerTok,
		map[string]any{"subject_type": "user", "subject": "carol"}); code != http.StatusForbidden {
		t.Fatalf("manage_targets self-add to a personal safe: want 403, got %d: %s", code, d)
	}

	// The override capability manages it instead.
	overrideTok := seedProfileUser(t, srv, "vault-override2", "security-lead2",
		"read_inventory", "unlimited_vault_access")
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeID), overrideTok,
		map[string]any{"subject_type": "user", "subject": "dave"}); code != http.StatusCreated {
		t.Fatalf("override add member: want 201, got %d: %s", code, d)
	}
}

// TestPersonalSafeImmutableOnUpdate proves Personal cannot be flipped after
// creation through updateSafe, at either the API or the store layer under
// it — a later rename/policy edit must never silently un-personalize (or
// personalize) a safe.
func TestPersonalSafeImmutableOnUpdate(t *testing.T) {
	srv := newTestServer(t)
	code, data := do(t, srv, http.MethodPost, "/api/safes", testAPIKey,
		map[string]any{"name": "alice-personal", "personal": true, "owner": "alice"})
	if code != http.StatusCreated {
		t.Fatalf("create personal safe: %d %s", code, data)
	}
	safeID := int64(jsonMap(t, data)["id"].(float64))

	// updateSafe's request body never even carries "personal" as an input
	// the handler reads — try anyway, to prove a client-supplied false does
	// not leak through.
	code, data = do(t, srv, http.MethodPut, fmt.Sprintf("/api/safes/%d", safeID), testAPIKey,
		map[string]any{"name": "alice-personal", "description": "renamed", "personal": false})
	if code != http.StatusOK {
		t.Fatalf("update safe: %d %s", code, data)
	}
	if p, _ := jsonMap(t, data)["personal"].(bool); !p {
		t.Fatalf("updateSafe must not clear personal: %s", data)
	}

	_, gd := do(t, srv, http.MethodGet, "/api/safes", testAPIKey, nil)
	if !strings.Contains(string(gd), `"personal":true`) {
		t.Fatalf("listSafes should still show the safe as personal: %s", gd)
	}
}
