package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// spTarget creates a WinRM target (optionally approval-gated) with a credential
// and returns its id.
func spTarget(t *testing.T, srv *httptest.Server, name string, requireApproval bool) int64 {
	t.Helper()
	code, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": name, "host": "10.0.0.20", "port": 5986, "os_type": "windows", "protocol": "winrm", "require_approval": requireApproval,
	})
	if code != http.StatusCreated {
		t.Fatalf("create target %s: %d %s", name, code, data)
	}
	id := int64(jsonMap(t, data)["id"].(float64))
	if code, data := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey,
		map[string]any{"target_id": id, "username": "Administrator", "secret": "Win-S3cret!"}); code != http.StatusCreated {
		t.Fatalf("create credential: %d %s", code, data)
	}
	return id
}

// spSafe creates a safe, places the given targets in it and returns its id.
func spSafe(t *testing.T, srv *httptest.Server, name string, targetIDs ...int64) int64 {
	t.Helper()
	code, data := do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{"name": name})
	if code != http.StatusCreated {
		t.Fatalf("create safe: %d %s", code, data)
	}
	id := int64(jsonMap(t, data)["id"].(float64))
	for _, tid := range targetIDs {
		if code, data := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d/safe", tid), testAPIKey, map[string]any{"safe_id": id}); code != http.StatusNoContent {
			t.Fatalf("assign target %d: %d %s", tid, code, data)
		}
	}
	return id
}

// credentialOf returns the id of the one credential on targetID.
func credentialOf(t *testing.T, srv *httptest.Server, targetID int64) int64 {
	t.Helper()
	code, data := do(t, srv, http.MethodGet, "/api/credentials", testAPIKey, nil)
	if code != http.StatusOK {
		t.Fatalf("list credentials: %d %s", code, data)
	}
	for _, c := range jsonArray(t, data) {
		if int64(c["target_id"].(float64)) == targetID {
			return int64(c["id"].(float64))
		}
	}
	t.Fatalf("no credential on target %d", targetID)
	return 0
}

// jsonArray unmarshals a JSON array of objects.
func jsonArray(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal %q: %v", data, err)
	}
	return out
}

// TestSafePermissionSets proves what a membership confers is what it names
// (Phase 246), on the two kinds of path that matter: a use-only member runs a
// brokered WinRM command but is refused the secret, a retrieve-only member
// reveals the secret but is refused the command, and a subject in no safe gets
// neither. The member route validates the set, defaults it to use + retrieve
// when omitted, and records it in the audit trail.
func TestSafePermissionSets(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	srv, st := newTestServerOpts(t, nil, api.Options{WinRM: fake})
	target := spTarget(t, srv, "win-safe", false)
	safeID := spSafe(t, srv, "ops", target)
	members := fmt.Sprintf("/api/safes/%d/members", safeID)
	cred := credentialOf(t, srv, target)

	// A profile holding both global capabilities, so that what is refused below
	// is refused by the membership and nothing else.
	if code, data := do(t, srv, http.MethodPost, "/api/profiles", testAPIKey,
		map[string]any{"name": "operator", "capabilities": []string{"read_inventory", "connect", "reveal_secret"}}); code != http.StatusCreated {
		t.Fatalf("create profile: %d %s", code, data)
	}
	alice := seedUser(t, srv, "alice", "operator")
	carol := seedUser(t, srv, "carol", "operator")
	dave := seedUser(t, srv, "dave", "operator")

	if code, data := do(t, srv, http.MethodPost, members, testAPIKey, map[string]any{"subject_type": "user", "subject": "x", "permissions": []string{"root"}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown permission: %d %s", code, data)
	}
	if code, data := do(t, srv, http.MethodPost, members, testAPIKey, map[string]any{"subject_type": "user", "subject": "x", "permissions": []string{}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("no permissions and no management right: %d %s", code, data)
	}
	if code, data := do(t, srv, http.MethodPost, members, testAPIKey, map[string]any{"subject_type": "user", "subject": "mgr", "can_manage": true, "permissions": []string{}}); code != http.StatusCreated {
		t.Fatalf("a manage-only member is valid: %d %s", code, data)
	}
	code, data := do(t, srv, http.MethodPost, members, testAPIKey, map[string]any{"subject_type": "user", "subject": "legacy"})
	if code != http.StatusCreated || fmt.Sprint(jsonMap(t, data)["permissions"]) != "[use retrieve]" {
		t.Fatalf("omitted permissions must default to use,retrieve: %d %s", code, data)
	}
	for user, perms := range map[string][]string{"alice": {"use"}, "carol": {"retrieve"}} {
		if code, data := do(t, srv, http.MethodPost, members, testAPIKey, map[string]any{"subject_type": "user", "subject": user, "permissions": perms}); code != http.StatusCreated {
			t.Fatalf("add %s: %d %s", user, code, data)
		}
	}
	auditHas(t, st, "safe.member.add", "user:alice manage:false permissions:use")

	run := fmt.Sprintf("/api/targets/%d/winrm", target)
	reveal := fmt.Sprintf("/api/credentials/%d/reveal", cred)
	cases := []struct {
		who                string
		tok                string
		wantRun, wantShown int
	}{
		{"use-only alice", alice, http.StatusOK, http.StatusForbidden},
		{"retrieve-only carol", carol, http.StatusForbidden, http.StatusOK},
		{"non-member dave", dave, http.StatusForbidden, http.StatusForbidden},
	}
	for _, tc := range cases {
		if code, data := do(t, srv, http.MethodPost, run, tc.tok, map[string]any{"command": "whoami"}); code != tc.wantRun {
			t.Errorf("%s winrm: %d %s, want %d", tc.who, code, data, tc.wantRun)
		}
		if code, data := do(t, srv, http.MethodPost, reveal, tc.tok, nil); code != tc.wantShown {
			t.Errorf("%s reveal: %d %s, want %d", tc.who, code, data, tc.wantShown)
		}
	}
	auditHas(t, st, "credential.reveal_denied", "reason:target-policy")
	auditHas(t, st, "winrm.denied", "target:win-safe reason:target-policy")
}

// TestScopedApprover proves a safe's approve permission (Phase 246): a member
// holding it — globally a plain user — lists and decides access requests for
// that safe's targets and no others, is told so by /api/me, still cannot
// approve their own request, and gains no target access from it; a user with
// no approval right anywhere is refused exactly as before.
func TestScopedApprover(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	srv, st := newTestServerOpts(t, nil, api.Options{WinRM: fake})
	inSafe := spTarget(t, srv, "win-ops", true)
	outside := spTarget(t, srv, "win-other", true)
	safeID := spSafe(t, srv, "ops", inSafe)

	alice := seedUser(t, srv, "alice", "user")
	erin := seedUser(t, srv, "erin", "user")
	frank := seedUser(t, srv, "frank", "user")
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeID), testAPIKey,
		map[string]any{"subject_type": "user", "subject": "erin", "permissions": []string{"approve"}}); code != http.StatusCreated {
		t.Fatalf("add approver member: %d %s", code, data)
	}
	// alice needs use on the safe's target to have anything to request.
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeID), testAPIKey,
		map[string]any{"subject_type": "user", "subject": "alice", "permissions": []string{"use"}}); code != http.StatusCreated {
		t.Fatalf("add alice: %d %s", code, data)
	}

	file := func(tok string, target int64) int64 {
		t.Helper()
		code, data := do(t, srv, http.MethodPost, "/api/access-requests", tok, map[string]any{"target_id": target, "reason": "patch"})
		if code != http.StatusCreated {
			t.Fatalf("file request: %d %s", code, data)
		}
		return int64(jsonMap(t, data)["id"].(float64))
	}
	inReq := file(alice, inSafe)
	outReq := file(alice, outside)

	code, data := do(t, srv, http.MethodGet, "/api/access-requests", erin, nil)
	if code != http.StatusOK {
		t.Fatalf("scoped approver list: %d %s", code, data)
	}
	if list := jsonArray(t, data); len(list) != 1 || int64(list[0]["id"].(float64)) != inReq {
		t.Fatalf("a scoped approver must see only the safe's requests: %s", data)
	}
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", outReq), erin, nil); code != http.StatusForbidden {
		t.Fatalf("approve outside the safe: %d %s", code, data)
	}
	auditHas(t, st, "access.decision_denied", fmt.Sprintf("request:%d target:%d reason:not-an-approver", outReq, outside))
	code, data = do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", inReq), erin, nil)
	if code != http.StatusOK || jsonMap(t, data)["status"] != "approved" {
		t.Fatalf("approve inside the safe: %d %s", code, data)
	}
	auditHas(t, st, "access.approve", fmt.Sprintf("request:%d", inReq))

	// Four-eyes still binds a scoped approver.
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeID), testAPIKey,
		map[string]any{"subject_type": "user", "subject": "gina", "permissions": []string{"use", "approve"}}); code != http.StatusCreated {
		t.Fatalf("add gina: %d %s", code, data)
	}
	gina := seedUser(t, srv, "gina", "user")
	own := file(gina, inSafe)
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", own), gina, nil); code != http.StatusForbidden {
		t.Fatalf("self-approval by a scoped approver: %d %s", code, data)
	}
	auditHas(t, st, "access.decision_denied", fmt.Sprintf("request:%d reason:self-approval", own))

	// A use-only member is no approver: the right is the permission, not the
	// membership.
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", own), alice, nil); code != http.StatusForbidden {
		t.Fatalf("a use-only member approved a request: %d %s", code, data)
	}

	// The approve permission confers no target access — shown on a target in
	// the same safe that needs no approval, so nothing but the membership can
	// be what refuses the command.
	free := spTarget(t, srv, "win-ops-free", false)
	if code, data := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d/safe", free), testAPIKey, map[string]any{"safe_id": safeID}); code != http.StatusNoContent {
		t.Fatalf("assign free target: %d %s", code, data)
	}
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/winrm", free), erin, map[string]any{"command": "whoami"}); code != http.StatusForbidden {
		t.Fatalf("an approve-only member ran a command: %d %s", code, data)
	}
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/winrm", free), alice, map[string]any{"command": "whoami"}); code != http.StatusOK {
		t.Fatalf("a use member on the same target: %d %s", code, data)
	}

	// No approval right anywhere: refused as the capability middleware refused.
	if code, _ := do(t, srv, http.MethodGet, "/api/access-requests", frank, nil); code != http.StatusForbidden {
		t.Fatalf("plain user list: %d", code)
	}
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/deny", outReq), frank, nil); code != http.StatusForbidden {
		t.Fatalf("plain user deny: %d", code)
	}
	auditHas(t, st, "authz.denied", "GET /api/access-requests role:user")

	for tok, want := range map[string]bool{erin: true, frank: false} {
		code, data := do(t, srv, http.MethodGet, "/api/me", tok, nil)
		if code != http.StatusOK || jsonMap(t, data)["scoped_approver"] != want {
			t.Fatalf("/api/me scoped_approver: %d %s, want %v", code, data, want)
		}
	}
}
