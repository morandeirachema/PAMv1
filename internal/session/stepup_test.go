package session

import (
	"context"
	"testing"
	"time"
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
	for i := 0; i < 200; i++ {
		for _, p := range su.Pending() {
			if p.SessionID == sid {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("step-up for %q never registered", sid)
}
