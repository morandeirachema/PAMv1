package api_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestCredentialScopedGrantRoutes proves a grant can be scoped to one
// credential on its target (Phase 252 — object-level access control), that the
// scope is validated and audited, and that the REST secret-delivery path
// honours it: a subject granted `deploy` reveals `deploy` and is refused
// `root` on the same target.
func TestCredentialScopedGrantRoutes(t *testing.T) {
	srv, st := newTestServerStore(t)
	tid := createTestTarget(t, srv, "db-01", "10.0.0.5")
	other := createTestTarget(t, srv, "db-02", "10.0.0.6")
	mk := func(target int64, user string) int64 {
		t.Helper()
		code, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
			"target_id": target, "username": user, "secret": "pw-" + user,
		})
		if code != http.StatusCreated {
			t.Fatalf("create credential %s: %d %s", user, code, d)
		}
		return int64(jsonMap(t, d)["id"].(float64))
	}
	deployID := mk(tid, "deploy")
	rootID := mk(tid, "root")
	foreignID := mk(other, "svc")

	// A profile that can reveal but is not an admin, so the grant decides.
	if code, d := do(t, srv, http.MethodPost, "/api/profiles", testAPIKey, map[string]any{
		"name": "revealer", "capabilities": []string{"read_inventory", "connect", "reveal_secret"},
	}); code != http.StatusCreated {
		t.Fatalf("create profile: %d %s", code, d)
	}
	aliceTok := seedUser(t, srv, "alice", "revealer")

	// A credential on another target is refused.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", tid), testAPIKey, map[string]any{
		"subject_type": "user", "subject": "alice", "credential_id": foreignID,
	}); code != http.StatusUnprocessableEntity {
		t.Fatalf("grant naming another target's credential: want 422, got %d %s", code, d)
	}
	// alice may retrieve deploy only.
	code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", tid), testAPIKey, map[string]any{
		"subject_type": "user", "subject": "alice", "credential_id": deployID,
	})
	if code != http.StatusCreated {
		t.Fatalf("scoped grant: %d %s", code, d)
	}
	if got := jsonMap(t, d)["credential_id"]; got == nil || int64(got.(float64)) != deployID {
		t.Errorf("the scope must be returned: %s", d)
	}
	auditHas(t, st, "grant.create", fmt.Sprintf("cred:%d cred_user:deploy", deployID))
	// The same scope twice is a conflict; a second scope for the same subject is not.
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", tid), testAPIKey, map[string]any{
		"subject_type": "user", "subject": "alice", "credential_id": deployID,
	}); code != http.StatusConflict {
		t.Errorf("duplicate scoped grant: want 409, got %d", code)
	}

	// The decision: deploy reveals, root is refused — and refused rather than
	// open, because alice's scoped grant gates the target.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reveal", deployID), aliceTok, nil); code != http.StatusOK {
		t.Fatalf("alice reveals deploy: want 200, got %d %s", code, d)
	}
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reveal", rootID), aliceTok, nil); code != http.StatusForbidden {
		t.Fatalf("alice reveals root: want 403, got %d %s", code, d)
	}
	auditHas(t, st, "credential.reveal_denied", "target:db-01 reason:target-policy")

	// The list carries the scope; the reach view names it.
	code, d = do(t, srv, http.MethodGet, fmt.Sprintf("/api/targets/%d/grants", tid), testAPIKey, nil)
	if code != http.StatusOK || !strings.Contains(string(d), fmt.Sprintf(`"credential_id":%d`, deployID)) {
		t.Fatalf("list must carry the scope: %d %s", code, d)
	}
	code, d = do(t, srv, http.MethodGet, "/api/access/reach?subject=alice", testAPIKey, nil)
	if code != http.StatusOK || !strings.Contains(string(d), fmt.Sprintf(`"credential_ids":[%d]`, deployID)) {
		t.Fatalf("the reach view must name the credential the reach is scoped to: %d %s", code, d)
	}

	// Widening: a whole-target grant beside the scoped one opens root too.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", tid), testAPIKey, map[string]any{
		"subject_type": "user", "subject": "alice",
	}); code != http.StatusCreated {
		t.Fatalf("whole-target grant beside a scoped one: %d %s", code, d)
	}
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reveal", rootID), aliceTok, nil); code != http.StatusOK {
		t.Errorf("with a whole-target grant alice reveals root, got %d", code)
	}
}
