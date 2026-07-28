package session_test

// killbus_test.go proves the cross-replica kill bus with two independent Registry
// instances sharing one store (the memory store's in-process hub stands in for
// Postgres LISTEN/NOTIFY). A kill issued to one "replica" must terminate a
// session hosted on the other — the HA gap this closes.

import (
	"context"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// waitKilled blocks until ch fires or the test times out.
func waitKilled(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: session was not killed across replicas", what)
	}
}

// TestKillBusCrossReplica proves a kill reaches a session hosted on a DIFFERENT
// replica: one registry publishes the selector, the other receives it over the
// bus and terminates its local session. Without this, "terminate that session"
// works only if the operator's request happens to land on the replica holding
// it — which in an HA deployment is a coin toss.
func TestKillBusCrossReplica(t *testing.T) {
	st := memstore.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Two replicas, each its own registry, both on the shared bus.
	repA, repB := session.NewRegistry(), session.NewRegistry()
	if err := repA.StartKillBus(ctx, st); err != nil {
		t.Fatal(err)
	}
	if err := repB.StartKillBus(ctx, st); err != nil {
		t.Fatal(err)
	}

	// A session is hosted on replica A.
	killed := make(chan struct{})
	repA.Register(session.Info{Actor: "mallory", Target: "db-01"}, func() { close(killed) })

	// The kill is issued to replica B (which does not host it) — via KillByActor,
	// as the analytics auto-response and revoke cascade do.
	if n := repB.KillByActor("mallory"); n != 0 {
		t.Fatalf("replica B killed %d locally, want 0 (session is on A)", n)
	}
	waitKilled(t, killed, "KillByActor")

	// KillByActorTarget also propagates.
	killed2 := make(chan struct{})
	repA.Register(session.Info{Actor: "eve", Target: "web-01"}, func() { close(killed2) })
	repB.KillByActorTarget("eve", "web-01")
	waitKilled(t, killed2, "KillByActorTarget")

	// A single-session kill by id propagates, and the issuing replica reports it as
	// dispatched to the cluster (not found locally, but a bus is configured).
	killed3 := make(chan struct{})
	id := repA.Register(session.Info{Actor: "dan", Target: "win-01"}, func() { close(killed3) })
	if got := repB.KillDistributed(id); got != session.KillDispatched {
		t.Fatalf("KillDistributed on the non-hosting replica = %v, want KillDispatched", got)
	}
	waitKilled(t, killed3, "KillDistributed")
}

// TestKillDistributedLocalAndNoBus covers the non-HA outcomes: a session killed on
// the same replica is KillLocal, and with no bus a missing id is KillNotFound.
func TestKillDistributedLocalAndNoBus(t *testing.T) {
	// No bus: a session on this replica is KillLocal; a missing id is KillNotFound.
	reg := session.NewRegistry()
	id := reg.Register(session.Info{Actor: "a", Target: "t"}, func() {})
	if got := reg.KillDistributed(id); got != session.KillLocal {
		t.Fatalf("local kill = %v, want KillLocal", got)
	}
	if got := reg.KillDistributed("nonexistent"); got != session.KillNotFound {
		t.Fatalf("unknown id with no bus = %v, want KillNotFound", got)
	}
}
