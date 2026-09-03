package auth

import (
	"context"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestReachHonoursGrantLifetime proves the entitlement view reads a grant's
// bounds the way the connect gate does (Phase 240): an expired grant is not a
// reach, and a target whose only grant has expired stays CLOSED — it does not
// become "open to everyone" the way a target with no grants at all is.
func TestReachHonoursGrantLifetime(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	tg := &store.Target{Name: "db-01", Host: "h", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, tg); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err := st.CreateTargetGrant(ctx, &store.TargetGrant{TargetID: tg.ID, SubjectType: "user", Subject: "bob", ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bob", "carol"} {
		p := &Principal{Name: name, Role: RoleUser}
		out, err := ReachableTargets(ctx, st, p, UngatedOpen)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 0 {
			t.Fatalf("%s reaches %+v through an expired grant", name, out)
		}
		if CanConnectTarget(p, mustGrants(t, st, tg.ID), false, false, UngatedOpen) {
			t.Fatalf("%s can connect through an expired grant", name)
		}
	}
	// A live grant is a reach, reported with its bound.
	future := time.Now().Add(time.Hour)
	if err := st.CreateTargetGrant(ctx, &store.TargetGrant{TargetID: tg.ID, SubjectType: "user", Subject: "alice", ExpiresAt: &future}); err != nil {
		t.Fatal(err)
	}
	out, err := ReachableTargets(ctx, st, &Principal{Name: "alice", Role: RoleUser}, UngatedOpen)
	if err != nil || len(out) != 1 || out[0].Subject != "alice" {
		t.Fatalf("alice's reach = %+v err %v", out, err)
	}
}

func mustGrants(t *testing.T, st store.Store, targetID int64) []store.TargetGrant {
	t.Helper()
	gs, err := st.EffectiveTargetGrants(context.Background(), targetID)
	if err != nil {
		t.Fatal(err)
	}
	return gs
}
