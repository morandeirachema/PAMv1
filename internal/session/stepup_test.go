package session

import (
	"context"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/testutil"
)

// TestStepUpApproveDeny proves an awaited step-up resolves to the supervisor's
// decision, that a second concurrent await for the same session is denied, and
// that a timeout denies.
func TestStepUpApproveDeny(t *testing.T) {
	su := NewStepUp()

	// Approve.
	go func() {
		waitPending(t, su, "s1")
		if !su.Decide("s1", true) {
			t.Errorf("Decide(approve) returned false")
		}
	}()
	if !su.Await(context.Background(), "s1", "alice", "DELETE FROM x", 2*time.Second) {
		t.Fatal("await should be approved")
	}

	// Deny.
	go func() {
		waitPending(t, su, "s2")
		su.Decide("s2", false)
	}()
	if su.Await(context.Background(), "s2", "alice", "DROP TABLE x", 2*time.Second) {
		t.Fatal("await should be denied")
	}

	// Timeout denies.
	if su.Await(context.Background(), "s3", "alice", "x", 50*time.Millisecond) {
		t.Fatal("await should time out (deny)")
	}

	// No pending after all resolve.
	if len(su.Pending()) != 0 {
		t.Fatalf("expected no pending step-ups, got %d", len(su.Pending()))
	}

	// Decide with nothing pending returns false.
	if su.Decide("nope", true) {
		t.Fatal("Decide with no pending step-up must return false")
	}
}

// waitPending blocks until a step-up for sid is registered.
func waitPending(t *testing.T, su *StepUp, sid string) {
	t.Helper()
	ok := testutil.WaitFor(t, time.Second, func() bool {
		for _, p := range su.Pending() {
			if p.SessionID == sid {
				return true
			}
		}
		return false
	})
	if !ok {
		t.Fatalf("step-up for %q never registered", sid)
	}
}

// TestStepUpRefusesSelfApproval proves the operator whose session is paused
// cannot decide their own step-up, and that the entry stays pending so a real
// supervisor can still resolve it.
//
// A step-up exists to put a SECOND person in the loop before a sensitive
// statement runs. Self-approval turns the pause into a confirmation prompt, and
// leaves an audit entry that reads like independent review — worse than having
// no gate at all, because it manufactures false assurance. Every other decision
// point in pamv1 (access requests, vendor grants, broker approvals, access
// certification) already refused this; this one did not.
func TestStepUpRefusesSelfApproval(t *testing.T) {
	su := NewStepUp()

	decided := make(chan bool, 1)
	go func() {
		decided <- su.Await(context.Background(), "s-self", "alice", "DROP TABLE customers", 3*time.Second)
	}()
	waitPending(t, su, "s-self")

	// Alice tries to approve her own paused statement.
	ok, self := su.DecideBy("s-self", true, "alice")
	if ok {
		t.Fatal("alice approved the step-up for her own session")
	}
	if !self {
		t.Fatal("the refusal was not reported as self-approval, so the caller cannot distinguish it from 'nothing pending' and would return the wrong status")
	}
	// Denying her own is refused too: a step-up is not hers to resolve either way.
	if ok, self := su.DecideBy("s-self", false, "alice"); ok || !self {
		t.Fatalf("alice decided her own step-up (deny): ok=%v self=%v", ok, self)
	}

	// Crucially, the entry is still pending — a refused self-approval must not
	// consume the decision, or an operator could silently discard the gate.
	if len(su.Pending()) != 1 {
		t.Fatalf("after a refused self-approval there are %d pending step-ups, want 1 still awaiting a supervisor", len(su.Pending()))
	}

	// A different person can resolve it, which is the whole point.
	if ok, self := su.DecideBy("s-self", true, "bob"); !ok || self {
		t.Fatalf("bob could not decide alice's step-up: ok=%v self=%v", ok, self)
	}
	select {
	case approved := <-decided:
		if !approved {
			t.Fatal("the session was not released after the supervisor approved")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Await never returned after the supervisor decided")
	}

	// An empty decider means "caller has not established identity" and skips the
	// check, so the plain Decide wrapper (tests, internal callers) still works.
	go func() { _ = su.Await(context.Background(), "s-anon", "carol", "x", 3*time.Second) }()
	waitPending(t, su, "s-anon")
	if !su.Decide("s-anon", true) {
		t.Fatal("Decide with no decider identity must still resolve")
	}
}
