package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// seedSafeTarget creates a target with a credential and places it in safeID,
// returning the target's id.
func seedSafeTarget(t *testing.T, srv *httptest.Server, name string, safeID int64) int64 {
	t.Helper()
	code, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": name, "host": "10.0.0.11", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if code != http.StatusCreated {
		t.Fatalf("seed target: %d %s", code, data)
	}
	id := int64(jsonMap(t, data)["id"].(float64))
	if code, d := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d/safe", id), testAPIKey,
		map[string]any{"safe_id": safeID}); code != http.StatusNoContent {
		t.Fatalf("assign target to safe: %d %s", code, d)
	}
	if code, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": id, "username": "root", "secret": "s3cr3t",
	}); code != http.StatusCreated {
		t.Fatalf("seed credential: %d %s", code, d)
	}
	return id
}

// firstCredentialID returns the id of the target's first credential.
func firstCredentialID(t *testing.T, srv *httptest.Server, targetID int64) int64 {
	t.Helper()
	_, data := do(t, srv, http.MethodGet, fmt.Sprintf("/api/credentials?target_id=%d", targetID), testAPIKey, nil)
	var creds []map[string]any
	if err := json.Unmarshal(data, &creds); err != nil || len(creds) == 0 {
		t.Fatalf("list credentials: %s (%v)", data, err)
	}
	return int64(creds[0]["id"].(float64))
}

// TestSafeScopedApprovalPolicy proves the phase's central claim: a safe's
// policy governs every target in it, even one whose own require_approval flag
// is false and with no global requirement set. Before this, that target was
// reachable with no approval at all.
func TestSafeScopedApprovalPolicy(t *testing.T) {
	srv := newTestServer(t)

	// A safe that demands approval, and a target placed in it that does NOT set
	// the flag itself.
	code, data := do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{
		"name": "prod", "description": "production", "require_approval": true,
	})
	if code != http.StatusCreated {
		t.Fatalf("create safe: %d %s", code, data)
	}
	safe := jsonMap(t, data)
	if safe["require_approval"] != true {
		t.Fatalf("safe policy not returned: %s", data)
	}
	safeID := int64(safe["id"].(float64))
	targetID := seedSafeTarget(t, srv, "prod-web", safeID)

	// Revealing the credential is a privileged use, so it runs the same gate the
	// connect paths do — and it must now be refused.
	credID := firstCredentialID(t, srv, targetID)
	if code, body := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reveal", credID), testAPIKey, nil); code != http.StatusForbidden {
		t.Fatalf("reveal of a target in an approval-required safe: want 403, got %d %s", code, body)
	}

	// The same target OUTSIDE the safe is reachable, which is what proves the
	// refusal came from the safe and not from something else.
	if code, body := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d/safe", targetID), testAPIKey,
		map[string]any{"safe_id": nil}); code != http.StatusNoContent {
		t.Fatalf("unassign target from safe: %d %s", code, body)
	}
	if code, body := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reveal", credID), testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("reveal outside the safe: want 200, got %d %s", code, body)
	}
}

// TestSafeDualControl proves the dual-control floor: a safe demanding two
// distinct approvers makes a single approval insufficient, and the floor is
// re-read when each approval is cast — so RAISING it binds requests already in
// flight, which is the difference between a policy and a suggestion.
func TestSafeDualControl(t *testing.T) {
	srv := newTestServer(t)

	code, data := do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{
		"name": "vault-room", "require_approval": true,
	})
	if code != http.StatusCreated {
		t.Fatalf("create safe: %d %s", code, data)
	}
	safeID := int64(jsonMap(t, data)["id"].(float64))
	targetID := seedSafeTarget(t, srv, "hsm-01", safeID)

	requester := seedUser(t, srv, "rita", "user")
	code, data = do(t, srv, http.MethodPost, "/api/access-requests", requester, map[string]any{
		"target_id": targetID, "reason": "maintenance",
	})
	if code != http.StatusCreated {
		t.Fatalf("file request: %d %s", code, data)
	}
	reqID := int64(jsonMap(t, data)["id"].(float64))

	// Now raise the floor to two. The request already exists with the old
	// number stamped on it.
	if code, body := do(t, srv, http.MethodPut, fmt.Sprintf("/api/safes/%d", safeID), testAPIKey, map[string]any{
		"name": "vault-room", "require_approval": true, "min_approvers": 2,
	}); code != http.StatusOK {
		t.Fatalf("raise the floor: %d %s", code, body)
	}

	// One approver is no longer enough: the request stays pending.
	first := seedUser(t, srv, "ann", "approver")
	code, data = do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", reqID), first, nil)
	if code != http.StatusOK {
		t.Fatalf("first approval: %d %s", code, data)
	}
	if got := jsonMap(t, data)["status"]; got != "pending" {
		t.Fatalf("after one approval status = %v, want pending (the safe demands two)", got)
	}

	// A second, DISTINCT approver grants it.
	second := seedUser(t, srv, "ben", "approver")
	code, data = do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", reqID), second, nil)
	if code != http.StatusOK {
		t.Fatalf("second approval: %d %s", code, data)
	}
	if got := jsonMap(t, data)["status"]; got != "approved" {
		t.Fatalf("after two approvals status = %v, want approved", got)
	}
}

// TestSafeDualControlFloorAtRequestTime proves the floor is also applied when
// the request is filed, so a requester cannot ask for fewer approvers than the
// safe demands.
func TestSafeDualControlFloorAtRequestTime(t *testing.T) {
	srv := newTestServer(t)
	code, data := do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{
		"name": "ot-cell", "min_approvers": 3,
	})
	if code != http.StatusCreated {
		t.Fatalf("create safe: %d %s", code, data)
	}
	safeID := int64(jsonMap(t, data)["id"].(float64))
	targetID := seedSafeTarget(t, srv, "plc-01", safeID)

	requester := seedUser(t, srv, "ray", "user")
	code, data = do(t, srv, http.MethodPost, "/api/access-requests", requester, map[string]any{
		"target_id": targetID, "reason": "patch", "approvals": 1, // asking for the minimum
	})
	if code != http.StatusCreated {
		t.Fatalf("file request: %d %s", code, data)
	}
	if got := jsonMap(t, data)["required_approvals"]; got != float64(3) {
		t.Fatalf("required_approvals = %v, want the safe's floor of 3", got)
	}
}

// TestSafePolicyValidation proves an unusable floor is refused at the API rather
// than stored — a safe nobody can ever satisfy is a denial of service written as
// a setting.
func TestSafePolicyValidation(t *testing.T) {
	srv := newTestServer(t)
	for _, n := range []any{-1, 99} {
		if code, body := do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{
			"name": fmt.Sprintf("bad-%v", n), "min_approvers": n,
		}); code != http.StatusUnprocessableEntity {
			t.Fatalf("min_approvers=%v: want 422, got %d %s", n, code, body)
		}
	}
}
