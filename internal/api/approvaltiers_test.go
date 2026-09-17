package api_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestTieredApproval proves an ordered approval chain (Phase 256) is enforced
// at the decision, not just stored: with "manager; approver" on a target, an
// approver who acts before the requester's manager is refused for the wrong
// tier, the manager satisfies level 1, the approver then completes the chain
// — and the request is granted only then. It also proves the manager tier's
// two edges: a requester with no manager is refused at creation, and the
// manager is looked up on the requester, not on whoever asks.
func TestTieredApproval(t *testing.T) {
	srv, st := newTestServerStore(t)
	tid := createTestTarget(t, srv, "prod-db", "10.0.0.7")
	if code, d := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d", tid), testAPIKey, map[string]any{
		"name": "prod-db", "host": "10.0.0.7", "port": 22, "os_type": "linux", "protocol": "ssh",
		"approval_tiers": "manager; approver",
	}); code != http.StatusOK {
		t.Fatalf("set tiers: %d %s", code, d)
	}
	// A bad chain is refused on write, with the parser's own reason.
	if code, d := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d", tid), testAPIKey, map[string]any{
		"name": "prod-db", "host": "10.0.0.7", "port": 22, "os_type": "linux", "protocol": "ssh",
		"approval_tiers": "manager:2; approver",
	}); code != http.StatusUnprocessableEntity {
		t.Fatalf("bad chain: want 422, got %d %s", code, d)
	}

	miaTok := seedUser(t, srv, "mia", "user")     // alice's manager: a plain user, no approver role
	patTok := seedUser(t, srv, "pat", "approver") // level 2
	_ = miaTok
	// alice with no manager: refused at creation, answerably.
	aliceID, aliceTok := seedUserWithID(t, srv, "alice", "user")
	if code, d := do(t, srv, http.MethodPost, "/api/access-requests", aliceTok, map[string]any{"target_id": tid, "reason": "deploy"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("request with no manager: want 422, got %d %s", code, d)
	}
	// Manager validation: self and unknown are refused; an existing user is accepted.
	for _, bad := range []string{"alice", "nobody"} {
		if code, _ := do(t, srv, http.MethodPut, fmt.Sprintf("/api/users/%d", aliceID), testAPIKey, map[string]any{"role": "user", "manager": bad}); code != http.StatusUnprocessableEntity {
			t.Errorf("manager %q: want 422, got %d", bad, code)
		}
	}
	if code, d := do(t, srv, http.MethodPut, fmt.Sprintf("/api/users/%d", aliceID), testAPIKey, map[string]any{"role": "user", "manager": "mia"}); code != http.StatusOK {
		t.Fatalf("set manager: %d %s", code, d)
	}

	code, d := do(t, srv, http.MethodPost, "/api/access-requests", aliceTok, map[string]any{"target_id": tid, "reason": "deploy"})
	if code != http.StatusCreated {
		t.Fatalf("request: %d %s", code, d)
	}
	rid := int64(jsonMap(t, d)["id"].(float64))
	approve := func(tok string) (int, []byte) {
		return do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", rid), tok, nil)
	}

	// Level 2 before level 1: refused for the wrong tier, nothing recorded.
	if code, d := approve(patTok); code != http.StatusForbidden {
		t.Fatalf("approver before manager: want 403, got %d %s", code, d)
	}
	auditHas(t, st, "access.decision_denied", fmt.Sprintf("request:%d approver:pat reason:not-in-current-tier", rid))
	// The manager: level 1 satisfied, chain still open, request still pending.
	// (mia holds no approve capability — the manager tier is what admits her.)
	code, d = approve(miaTok)
	if code != http.StatusOK {
		t.Fatalf("manager approves: %d %s", code, d)
	}
	m := jsonMap(t, d)
	if m["status"] != "pending" {
		t.Fatalf("after the manager the request must still be pending: %s", d)
	}
	if !strings.Contains(string(d), `"satisfied":true`) || !strings.Contains(string(d), `"current":true`) {
		t.Fatalf("the response must report tier progress: %s", d)
	}
	// The manager again: already approved.
	if code, _ := approve(miaTok); code != http.StatusConflict {
		t.Errorf("a second approval by the same person: want 409, got %d", code)
	}
	// Level 2 now completes the chain.
	code, d = approve(patTok)
	if code != http.StatusOK || jsonMap(t, d)["status"] != "approved" {
		t.Fatalf("approver completes the chain: %d %s", code, d)
	}
	auditHas(t, st, "access.approve", fmt.Sprintf("request:%d requester:alice", rid))

	// The list reports the chain for a pending request on a tiered target.
	code, d = do(t, srv, http.MethodPost, "/api/access-requests", aliceTok, map[string]any{"target_id": tid, "reason": "again"})
	if code != http.StatusCreated {
		t.Fatalf("second request: %d %s", code, d)
	}
	code, d = do(t, srv, http.MethodGet, "/api/access-requests?status=pending", testAPIKey, nil)
	if code != http.StatusOK || !strings.Contains(string(d), `"kind":"manager"`) {
		t.Fatalf("the pending list must carry tier state: %d %s", code, d)
	}
}

// TestTieredApprovalFromSafe proves a safe's chain binds every target in it
// that sets none of its own, and that a target's own chain wins over the
// safe's — the more specific statement governs.
func TestTieredApprovalFromSafe(t *testing.T) {
	srv, _ := newTestServerStore(t)
	code, d := do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{"name": "prod", "approval_tiers": "admin:2"})
	if code != http.StatusCreated {
		t.Fatalf("safe: %d %s", code, d)
	}
	safeID := int64(jsonMap(t, d)["id"].(float64))
	if got := jsonMap(t, d)["approval_tiers"]; got != "admin:2" {
		t.Errorf("safe chain = %v", got)
	}
	inherits := createTestTarget(t, srv, "inherits", "10.0.1.1")
	own := createTestTarget(t, srv, "own", "10.0.1.2")
	for _, id := range []int64{inherits, own} {
		if code, d := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d/safe", id), testAPIKey, map[string]any{"safe_id": safeID}); code != http.StatusOK && code != http.StatusNoContent {
			t.Fatalf("assign %d to safe: %d %s", id, code, d)
		}
	}
	if code, d := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d", own), testAPIKey, map[string]any{
		"name": "own", "host": "10.0.1.2", "port": 22, "os_type": "linux", "protocol": "ssh", "approval_tiers": "approver",
	}); code != http.StatusOK {
		t.Fatalf("own chain: %d %s", code, d)
	}
	bobTok := seedUser(t, srv, "bob", "user")
	patTok := seedUser(t, srv, "pat", "approver")
	rootTok := seedUser(t, srv, "root", "admin")

	// inherits: the safe's admin:2 chain — an approver is the wrong tier, one admin is not enough.
	code, d = do(t, srv, http.MethodPost, "/api/access-requests", bobTok, map[string]any{"target_id": inherits, "reason": "x"})
	if code != http.StatusCreated {
		t.Fatalf("request: %d %s", code, d)
	}
	rid := int64(jsonMap(t, d)["id"].(float64))
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", rid), patTok, nil); code != http.StatusForbidden {
		t.Errorf("approver on an admin:2 chain: want 403, got %d", code)
	}
	code, d = do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", rid), rootTok, nil)
	if code != http.StatusOK || jsonMap(t, d)["status"] != "pending" {
		t.Fatalf("one admin of two: %d %s", code, d)
	}
	// own: its own "approver" chain wins over the safe's.
	code, d = do(t, srv, http.MethodPost, "/api/access-requests", bobTok, map[string]any{"target_id": own, "reason": "y"})
	if code != http.StatusCreated {
		t.Fatalf("request: %d %s", code, d)
	}
	rid2 := int64(jsonMap(t, d)["id"].(float64))
	code, d = do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", rid2), patTok, nil)
	if code != http.StatusOK || jsonMap(t, d)["status"] != "approved" {
		t.Fatalf("the target's own chain must govern: %d %s", code, d)
	}
}
