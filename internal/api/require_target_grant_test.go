package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// TestRequireTargetGrantAppliesFromStartup is the Phase 290 regression for
// PAM_REQUIRE_TARGET_GRANT on the API server. api.New built its first runtime
// snapshot without the flag, so Options.RequireTargetGrant was never read:
// the session proxies refused a target nobody had granted, while the paths
// that reach a target through the HTTP server (REST WinRM here; the desktop
// viewer, kubectl and the broker's tools read the same snapshot) left it open
// to any connect-capable user until the first PUT /api/config rebuilt the
// snapshot. No test built a server with the option set, so nothing noticed.
func TestRequireTargetGrantAppliesFromStartup(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\n"}}
	srv, _ := newTestServerOpts(t, nil, api.Options{WinRM: fake, RequireTargetGrant: true})

	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "win", "host": "h", "port": 5986, "os_type": "windows", "protocol": "winrm",
	})
	tid := int64(jsonMap(t, data)["id"].(float64))
	do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "Administrator", "secret": "s",
	})
	aliceTok := seedUser(t, srv, "alice", "user")
	winrmPath := "/api/targets/" + itoa(tid) + "/winrm"
	run := map[string]any{"command": "whoami"}

	// No grants at all: closed to a plain user, and the command never ran.
	if status, body := do(t, srv, http.MethodPost, winrmPath, aliceTok, run); status != http.StatusForbidden {
		t.Fatalf("ungated target under RequireTargetGrant: %d %s, want 403", status, body)
	}
	if fake.gotCmd != "" {
		t.Fatalf("the command reached the target (%q) for a caller with no grant", fake.gotCmd)
	}
	// The reach review states the policy in force.
	if status, body := do(t, srv, http.MethodGet, "/api/access/reach?subject=alice", testAPIKey, nil); status != http.StatusOK ||
		!strings.Contains(string(body), `"require_target_grant":true`) || !strings.Contains(string(body), `"total":0`) {
		t.Fatalf("reach review: %d %s, want require_target_grant:true and no reachable target", status, body)
	}
	// An administrator still bypasses, and a grant opens it to its subject.
	if status, body := do(t, srv, http.MethodPost, winrmPath, testAPIKey, run); status != http.StatusOK {
		t.Fatalf("admin on an ungated target: %d %s, want 200", status, body)
	}
	if status, body := do(t, srv, http.MethodPost, "/api/targets/"+itoa(tid)+"/grants", testAPIKey,
		map[string]any{"subject_type": "user", "subject": "alice"}); status != http.StatusCreated {
		t.Fatalf("create grant: %d %s", status, body)
	}
	if status, body := do(t, srv, http.MethodPost, winrmPath, aliceTok, run); status != http.StatusOK {
		t.Fatalf("granted user: %d %s, want 200", status, body)
	}
}
