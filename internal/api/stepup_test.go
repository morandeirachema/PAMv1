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
// statement appears in the listing and a supervisor's approval resolves it; a
// missing session yields 404, and an auditor role may decide.
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

	// An auditor (holds read_audit, the live-monitor gate) approves it.
	auditor := seedUser(t, srv, "su-auditor", "auditor")
	if code, dd := do(t, srv, http.MethodPost, "/api/sessions/sess-1/stepup", auditor, map[string]any{"approve": true}); code != http.StatusOK {
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
	if code, _ := do(t, srv, http.MethodPost, "/api/sessions/sess-1/stepup", auditor, map[string]any{"approve": true}); code != http.StatusNotFound {
		t.Fatalf("decide with nothing pending: want 404, got %d", code)
	}
}
