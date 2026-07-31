package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
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

// TestStepUpCrossReplica proves Phase 56 through the API: the request lands on
// "replica B" (the test server) while the statement is paused on "replica A" (a
// second coordinator sharing the store). The supervisor must see the pause in
// B's listing — statement in the clear, naming A — and their decision must be
// dispatched (202, not a claimed 200) over the bus and release A's Await. The
// self-approval refusal must hold across replicas too, before anything is
// dispatched.
func TestStepUpCrossReplica(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	busKey := make([]byte, session.LiveBusKeySize)
	for i := range busKey {
		busKey[i] = byte(i + 3)
	}
	suA := session.NewStepUp()
	if err := suA.StartBus(ctx, st, session.StepUpBusConfig{BusKey: busKey, Replica: "rep-a"}); err != nil {
		t.Fatalf("StartBus(rep-a): %v", err)
	}
	suB := session.NewStepUp()
	if err := suB.StartBus(ctx, st, session.StepUpBusConfig{BusKey: busKey, Replica: "rep-b"}); err != nil {
		t.Fatalf("StartBus(rep-b): %v", err)
	}
	srv, _ := newTestServerStoreOpts(t, nil, st, api.Options{StepUp: suB})

	result := make(chan bool, 1)
	go func() {
		result <- suA.Await(ctx, "sess-far", "alice", "DROP TABLE prod", 10*time.Second)
	}()

	// B's listing shows A's pause: cluster-wide since Phase 56.
	deadline := time.After(5 * time.Second)
	for {
		_, ld := do(t, srv, http.MethodGet, "/api/sessions/stepups", testAPIKey, nil)
		if strings.Contains(string(ld), "sess-far") {
			if !strings.Contains(string(ld), "DROP TABLE prod") || !strings.Contains(string(ld), "rep-a") {
				t.Fatalf("cluster listing lacks the opened statement or hosting replica: %s", ld)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatalf("the remote pause never appeared in the listing: %s", ld)
		case <-time.After(20 * time.Millisecond):
		}
	}

	// The paused operator, holding CapApprove on another replica, still may not
	// decide their own statement — refused before any dispatch.
	alice := seedUser(t, srv, "alice", "approver")
	if code, body := do(t, srv, http.MethodPost, "/api/sessions/sess-far/stepup", alice, map[string]any{"approve": true}); code != http.StatusForbidden {
		t.Fatalf("cross-replica self-approval: want 403, got %d %s", code, body)
	}

	// A second person's decision is DISPATCHED (202) and releases A's pause.
	boss := seedUser(t, srv, "boss", "approver")
	code, body := do(t, srv, http.MethodPost, "/api/sessions/sess-far/stepup", boss, map[string]any{"approve": true})
	if code != http.StatusAccepted || !strings.Contains(string(body), `"dispatched":true`) {
		t.Fatalf("cross-replica decide: want 202 with dispatched:true, got %d %s", code, body)
	}
	select {
	case ok := <-result:
		if !ok {
			t.Fatal("the dispatched approval arrived as a refusal")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Await on replica A never saw the dispatched approval")
	}

	// With the bus attached, "nothing pending" is now a cluster-wide truth.
	if code, _ := do(t, srv, http.MethodPost, "/api/sessions/sess-far/stepup", boss, map[string]any{"approve": true}); code != http.StatusNotFound {
		t.Fatalf("decide with nothing pending anywhere: want 404, got %d", code)
	}
}
