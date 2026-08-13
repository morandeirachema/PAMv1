package api

import (
	"context"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestRecurringAccessRequestsSpawnAndStop proves the recurring-access-window
// schedule (Phase 120): a due, APPROVED anchor auto-files a fresh, still-
// PENDING successor carrying its requester/target/reason, the anchor's next
// run moves so it does not fire again immediately, and STOPPING RECURRENCE
// ends the series — the stop button an operator reaches for first, mirroring
// TestRecurringCampaignsSpawnAndStop's shape exactly.
func TestRecurringAccessRequestsSpawnAndStop(t *testing.T) {
	srv, st := newRetentionServer(t, t.TempDir())
	ctx := context.Background()

	tgt := &store.Target{Name: "prod-db", Host: "10.0.0.5", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, tgt); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	past := now.Add(-time.Minute)
	anchor := &store.AccessRequest{
		Requester: "alice", TargetID: tgt.ID, Reason: "weekly patch window",
		Status: "pending", ExpiresAt: now.Add(time.Hour),
		RequiredApprovals: 1, RecurDays: 7,
	}
	if err := st.CreateAccessRequest(ctx, anchor); err != nil {
		t.Fatal(err)
	}
	// A pending anchor must never be due — recurrence only starts once the
	// anchor itself is approved, and NextRunAt is set separately (the way the
	// API layer sets it, at approval time).
	if n := srv.spawnDueAccessRequests(ctx, now); n != 0 {
		t.Fatalf("spawned %d requests from a still-PENDING anchor, want 0", n)
	}
	if err := st.SetApprovalState(ctx, anchor.ID, "bob", "approved", "bob", &now); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAccessRequestNextRun(ctx, anchor.ID, past); err != nil {
		t.Fatal(err)
	}

	if n := srv.spawnDueAccessRequests(ctx, now); n != 1 {
		t.Fatalf("spawned %d requests, want 1", n)
	}
	all, err := st.ListAccessRequests(ctx, "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("want the anchor plus one child, got %d", len(all))
	}
	var child *store.AccessRequest
	for i := range all {
		if all[i].ID != anchor.ID {
			child = &all[i]
		}
	}
	if child == nil {
		t.Fatal("no child request found")
	}
	// The child must be PENDING, never pre-approved: recurrence automates the
	// paperwork, not the four-eyes decision.
	if child.Status != "pending" {
		t.Fatalf("child must be pending, not pre-approved: %+v", child)
	}
	if child.TargetID != tgt.ID || child.Requester != "alice" || child.Reason != anchor.Reason {
		t.Fatalf("child did not inherit requester/target/reason: %+v", child)
	}
	// ...and carries no schedule of its own, so a series can never fork.
	if child.RecurDays != 0 || child.NextRunAt != nil {
		t.Fatalf("child must not itself be an anchor: %+v", child)
	}
	// The anchor advanced, so the next tick does not spawn again.
	if n := srv.spawnDueAccessRequests(ctx, now); n != 0 {
		t.Fatalf("spawned %d more on an already-advanced anchor, want 0", n)
	}

	// Bring it due again, then STOP RECURRENCE: the series must end.
	if err := st.SetAccessRequestNextRun(ctx, anchor.ID, past); err != nil {
		t.Fatal(err)
	}
	if err := st.StopAccessRequestRecurrence(ctx, anchor.ID); err != nil {
		t.Fatal(err)
	}
	if n := srv.spawnDueAccessRequests(ctx, now); n != 0 {
		t.Fatalf("a STOPPED anchor spawned %d requests; stopping is the stop button", n)
	}
}
