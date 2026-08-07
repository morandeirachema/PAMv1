package api

import (
	"context"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestRecurringCampaignsSpawnAndStop proves the recertification schedule: a due
// anchor opens a successor carrying its scope, the anchor's next run moves so it
// does not fire again immediately, and CLOSING THE ANCHOR ENDS THE SERIES.
//
// That last one is the stop button. "Close the recurring campaign" is what an
// operator would try first, so it had better be the thing that works — a
// schedule you cannot stop is worse than no schedule.
func TestRecurringCampaignsSpawnAndStop(t *testing.T) {
	srv, st := newRetentionServer(t, t.TempDir())
	ctx := context.Background()

	// A safe with a member, so a scoped snapshot has something to capture.
	sf := &store.Safe{Name: "pci"}
	if err := st.CreateSafe(ctx, sf); err != nil {
		t.Fatal(err)
	}
	if err := st.AddSafeMember(ctx, &store.SafeMember{SafeID: sf.ID, SubjectType: "user", Subject: "alice"}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	past := now.Add(-time.Minute)
	anchor := &store.Campaign{
		Name: "PCI quarterly", CreatedBy: "alice", Status: "open",
		ScopeKind: store.CampaignScopeSafe, ScopeSafeID: &sf.ID,
		RecurDays: 90, NextRunAt: &past,
	}
	if err := st.CreateCampaign(ctx, anchor); err != nil {
		t.Fatal(err)
	}

	if n := srv.spawnDueCampaigns(ctx, now); n != 1 {
		t.Fatalf("spawned %d campaigns, want 1", n)
	}
	all, err := st.ListCampaigns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("want the anchor plus one child, got %d", len(all))
	}
	var child *store.Campaign
	for i := range all {
		if all[i].ID != anchor.ID {
			child = &all[i]
		}
	}
	// The child inherits the scope — a successor that reviewed the whole estate
	// would quietly undo the scoping on every occurrence after the first.
	if child.ScopeKind != store.CampaignScopeSafe || child.ScopeSafeID == nil || *child.ScopeSafeID != sf.ID {
		t.Fatalf("child did not inherit the scope: %+v", child)
	}
	// ...and carries no schedule of its own, so a series can never fork.
	if child.RecurDays != 0 || child.NextRunAt != nil {
		t.Fatalf("child must not be an anchor: %+v", child)
	}
	if items, _ := st.ListCampaignItems(ctx, child.ID); len(items) != 1 {
		t.Fatalf("child captured %d items, want the safe's one member", len(items))
	}
	// The anchor advanced, so the next tick does not spawn again.
	if n := srv.spawnDueCampaigns(ctx, now); n != 0 {
		t.Fatalf("spawned %d more campaigns on an already-advanced anchor, want 0", n)
	}

	// Bring it due again, then close it: the series must stop.
	if err := st.SetCampaignNextRun(ctx, anchor.ID, past); err != nil {
		t.Fatal(err)
	}
	if err := st.CloseCampaign(ctx, anchor.ID, now); err != nil {
		t.Fatal(err)
	}
	if n := srv.spawnDueCampaigns(ctx, now); n != 0 {
		t.Fatalf("a CLOSED anchor spawned %d campaigns; closing it is the stop button", n)
	}
}
