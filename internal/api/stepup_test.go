package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
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

	// The paused statement shows up for a supervisor. Waited for rather than
	// slept on: a fixed sleep is a bet that a goroutine is scheduled within N
	// milliseconds, which is true on an idle laptop and a coin toss on a loaded
	// CI runner. Polling to a deadline is the same test without the bet.
	ld := awaitPending(t, srv, "sess-1")
	if !strings.Contains(string(ld), "DELETE FROM accounts") {
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

// TestStepUpRefusalLeavesNoDecisionRecord proves the fail-closed
// `session.stepup_decided` record is written only when a decision is actually
// attempted — the audit-fidelity half of the step-up decision point.
//
// It used to be written first, unconditionally, so the two ordinary refusals
// both left a record asserting the opposite of what happened. The self-approval
// case is the sharp one: the trail recorded the PAUSED OPERATOR as having
// decided their own statement, which is precisely what the refusal exists to
// prevent, and what makes an audit trail that says an approval happened worse
// than no gate at all. The 404 case let any approver spray decision records for
// sessions that were never paused into a chained trail the retention worker
// will not prune.
//
// Verified to fail against the pre-fix code, which recorded both.
func TestStepUpRefusalLeavesNoDecisionRecord(t *testing.T) {
	su := session.NewStepUp()
	srv, st := newTestServerOpts(t, nil, api.Options{StepUp: su})

	// alice holds CapApprove and is also the operator whose statement is paused.
	alice := seedUser(t, srv, "alice", "approver")
	result := make(chan bool, 1)
	go func() {
		result <- su.Await(t.Context(), "sess-af", "alice", "DELETE FROM ledger", 3*time.Second)
	}()
	awaitPending(t, srv, "sess-af")

	// (1) Self-approval: refused, and it must leave no "decided" record.
	if code, body := do(t, srv, http.MethodPost, "/api/sessions/sess-af/stepup", alice, map[string]any{"approve": true}); code != http.StatusForbidden {
		t.Fatalf("self-approval: want 403, got %d %s", code, body)
	}
	// (2) Nothing pending anywhere: 404, and likewise no record.
	approver := seedUser(t, srv, "su-approver2", "approver")
	if code, _ := do(t, srv, http.MethodPost, "/api/sessions/no-such-session/stepup", approver, map[string]any{"approve": true}); code != http.StatusNotFound {
		t.Fatal("deciding a session that is paused nowhere must be 404")
	}

	decided, selfDenied := countAuditActions(t, st, "session.stepup_decided", "session.self_stepup_denied")
	if decided != 0 {
		t.Fatalf("refusals wrote %d session.stepup_decided records; a refused decision is not a decision", decided)
	}
	if selfDenied != 1 {
		t.Fatalf("session.self_stepup_denied written %d times, want 1", selfDenied)
	}

	// The pause survived both refusals and a second person can still decide it —
	// a refusal must never consume the gate.
	if code, body := do(t, srv, http.MethodPost, "/api/sessions/sess-af/stepup", approver, map[string]any{"approve": true}); code != http.StatusOK {
		t.Fatalf("approve by a second person: %d %s", code, body)
	}
	select {
	case ok := <-result:
		if !ok {
			t.Fatal("the second person's approval did not release the statement")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Await did not resolve after the approval")
	}
	// And the genuine decision IS recorded.
	if decided, _ := countAuditActions(t, st, "session.stepup_decided", ""); decided != 1 {
		t.Fatalf("the real decision wrote %d records, want exactly 1", decided)
	}
}

// countAuditActions returns how many audit events carry each of two actions.
func countAuditActions(t *testing.T, st store.Store, a, b string) (int, int) {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 500)
	if err != nil {
		t.Fatal(err)
	}
	na, nb := 0, 0
	for _, e := range events {
		switch e.Action {
		case a:
			na++
		case b:
			nb++
		}
	}
	return na, nb
}

// awaitPending polls the step-up listing until sessionID appears, and returns
// the listing. It replaces a fixed sleep: the Await goroutine registers the
// pause on its own schedule, and how long that takes is a property of the
// machine, not of the code under test.
func awaitPending(t *testing.T, srv *httptest.Server, sessionID string) []byte {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, body := do(t, srv, http.MethodGet, "/api/sessions/stepups", testAPIKey, nil)
		if strings.Contains(string(body), sessionID) {
			return body
		}
		if time.Now().After(deadline) {
			t.Fatalf("step-up for %s never appeared in the listing: %s", sessionID, body)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// failPublishStore is a StepUpStore that mirrors and lists pauses normally but
// refuses to publish a decision — the store hiccup that leaves DispatchRemote
// with a decided-record already written and nothing dispatched.
type failPublishStore struct{ session.StepUpStore }

func (failPublishStore) PublishStepUpDecision(context.Context, session.StepUpDecision) error {
	return errors.New("bus down")
}

// TestStepUpDispatchFailureVoidsTheDecidedRecord is the regression for finding
// AO's residual (Phase 89). The decision audit is written BEFORE the dispatch,
// on purpose — a released statement must never outlive the evidence of who
// released it. But a failed dispatch then left a positive "decided" record for a
// decision that never took effect: a four-eyes release an investigator would read
// as having happened. The compensating session.stepup_decision_voided nets it
// out.
func TestStepUpDispatchFailureVoidsTheDecidedRecord(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	busKey := make([]byte, session.LiveBusKeySize)
	for i := range busKey {
		busKey[i] = byte(i + 7)
	}
	// A hosts the real pause; B serves the API but its bus cannot publish.
	suA := session.NewStepUp()
	if err := suA.StartBus(ctx, st, session.StepUpBusConfig{BusKey: busKey, Replica: "rep-a"}); err != nil {
		t.Fatalf("StartBus(rep-a): %v", err)
	}
	suB := session.NewStepUp()
	if err := suB.StartBus(ctx, failPublishStore{st}, session.StepUpBusConfig{BusKey: busKey, Replica: "rep-b"}); err != nil {
		t.Fatalf("StartBus(rep-b): %v", err)
	}
	srv, _ := newTestServerStoreOpts(t, nil, st, api.Options{StepUp: suB})

	go func() { _ = suA.Await(ctx, "sess-df", "alice", "DROP TABLE prod", 10*time.Second) }()
	// Wait for A's sealed pause to be visible cluster-wide.
	deadline := time.After(5 * time.Second)
	for {
		if _, ld := do(t, srv, http.MethodGet, "/api/sessions/stepups", testAPIKey, nil); strings.Contains(string(ld), "sess-df") {
			break
		}
		select {
		case <-deadline:
			t.Fatal("the remote pause never appeared")
		case <-time.After(20 * time.Millisecond):
		}
	}

	boss := seedUser(t, srv, "boss", "approver")
	// The dispatch fails, so the operator is told it was NOT applied.
	if code, _ := do(t, srv, http.MethodPost, "/api/sessions/sess-df/stepup", boss, map[string]any{"approve": true}); code != http.StatusServiceUnavailable {
		t.Fatalf("a failed dispatch must report 503, got %d", code)
	}

	decided, voided := countAuditActions(t, st, "session.stepup_decided", "session.stepup_decision_voided")
	if decided != 1 {
		t.Fatalf("expected the decided-record to be written before the dispatch (got %d)", decided)
	}
	if voided != 1 {
		t.Fatalf("a failed dispatch left %d compensating records; the trail shows a decision that never applied", voided)
	}
}
