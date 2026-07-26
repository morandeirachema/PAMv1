package api_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/session"
)

// TestStepUpEndpoints proves the in-session step-up API (Phase 30): a paused
// statement appears in the listing and a supervisor's approval resolves it, and
// a missing session yields 404. Deciding needs CapApprove: an auditor may WATCH
// (the listing and the live stream are read_audit) but releasing a statement the
// step-up policy flagged is an execution-authorizing act, so a read-only role is
// refused.
func TestStepUpEndpoints(t *testing.T) {
	su := session.NewStepUp()
	srv, _ := newTestServerOpts(t, nil, api.Options{StepUp: su})

	// A DB proxy would call Await; simulate one paused statement in a goroutine.
	result := make(chan bool, 1)
	go func() {
		result <- su.Await(t.Context(), "sess-1", "alice", "DELETE FROM accounts", 3*time.Second)
	}()

	// Give the Await goroutine a moment to register, then the paused statement
	// shows up for a supervisor.
	time.Sleep(50 * time.Millisecond)
	_, ld := do(t, srv, http.MethodGet, "/api/sessions/stepups", testAPIKey, nil)
	if !strings.Contains(string(ld), "sess-1") || !strings.Contains(string(ld), "DELETE FROM accounts") {
		t.Fatalf("step-up listing missing the paused statement: %s", ld)
	}

	// An auditor can see the paused statement but must NOT be able to release it.
	auditor := seedUser(t, srv, "su-auditor", "auditor")
	if code, ld := do(t, srv, http.MethodGet, "/api/sessions/stepups", auditor, nil); code != http.StatusOK {
		t.Fatalf("auditor list step-ups: %d %s", code, ld)
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/sessions/sess-1/stepup", auditor, map[string]any{"approve": true}); code != http.StatusForbidden {
		t.Fatalf("auditor decide step-up: want 403, got %d", code)
	}

	// An approver holds CapApprove and decides it.
	approver := seedUser(t, srv, "su-approver", "approver")
	if code, dd := do(t, srv, http.MethodPost, "/api/sessions/sess-1/stepup", approver, map[string]any{"approve": true}); code != http.StatusOK {
		t.Fatalf("approve step-up: %d %s", code, dd)
	}
	select {
	case ok := <-result:
		if !ok {
			t.Fatal("Await should have returned approved")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Await did not resolve after the approval")
	}

	// Deciding a session with no pending step-up is 404.
	if code, _ := do(t, srv, http.MethodPost, "/api/sessions/sess-1/stepup", approver, map[string]any{"approve": true}); code != http.StatusNotFound {
		t.Fatalf("decide with nothing pending: want 404, got %d", code)
	}
}
