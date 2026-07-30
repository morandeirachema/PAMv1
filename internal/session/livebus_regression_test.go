package session_test

// Regression tests for three defects in the Phase 55 cross-replica live-monitoring
// relay, found by a review sweep the day after it shipped. Each one is written so
// that it FAILS against the original code — a test that passes either way would
// only record that the bug once existed.

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestClusterEndMarkerDoesNotOvertakeOutput proves a remote watcher receives a
// session's FINAL output before its stream closes.
//
// Data frames go through the async publisher queue; the end marker used to be
// published straight to the bus from the teardown path. On an exec-shaped run —
// the broker's ssh_exec, the REST WinRM endpoint — the whole output is published
// and the session released microseconds later, so the end could reach the bus
// first: the remote supervisor saw the command echo, then stream-end, and never
// the output. That is precisely the "ran silently" failure the local path was
// fixed for. Both frames now share one queue, so order is preserved.
//
// Repeated, because without the fix it is a race rather than a certainty.
func TestClusterEndMarkerDoesNotOvertakeOutput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	regA, hubA, _ := replica(t, ctx, st, "replica-a")
	_, hubB, cB := replica(t, ctx, st, "replica-b")

	want := []byte("winrm> whoami\r\nnt authority\\system\r\n")
	for i := 0; i < 20; i++ {
		id := regA.Register(session.Info{Actor: "op", Target: "win-01", Protocol: "winrm"}, func() {})
		frames, unsub := hubB.Subscribe(id)
		ok, err := cB.WatchRemote(ctx, id)
		if err != nil || !ok {
			unsub()
			t.Fatalf("WatchRemote = %v, %v; want true, nil", ok, err)
		}
		// Wait for the interest announcement to open the hosting replica's gate,
		// otherwise the output is legitimately not forwarded at all.
		deadline := time.Now().Add(5 * time.Second)
		for !hubA.HasSubscribers(id) {
			if time.Now().After(deadline) {
				unsub()
				cB.UnwatchRemote(id)
				t.Fatal("the hosting replica never saw the remote watcher's interest")
			}
			time.Sleep(time.Millisecond)
		}

		// The shape that broke: publish the whole output, then end the session
		// immediately.
		hubA.Publish(id, want)
		regA.Remove(id)

		var got []byte
		closed := false
		timeout := time.After(5 * time.Second)
	collect:
		for {
			select {
			case b, open := <-frames:
				if !open {
					closed = true
					break collect
				}
				got = append(got, b...)
			case <-timeout:
				break collect
			}
		}
		unsub()
		cB.UnwatchRemote(id)

		if !closed {
			t.Fatalf("round %d: the watch stream did not close when the session ended", i)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("round %d: remote watcher saw %q before the stream closed, want %q — the end marker overtook the output",
				i, got, want)
		}
	}
}

// TestClusterHeartbeatDoesNotResurrectEndedSession proves the inventory row of an
// ended session stays deleted.
//
// runHeartbeat snapshots the registry and then upserts each row. A session ending
// inside that window was deleted by its teardown and then RE-INSERTED by the
// pending upsert, with a fresh seen-at stamp and nothing left to delete it again:
// it stayed listed and 200-watchable for the whole freshness window (~45s) while
// its watchers got silence. A short-lived tombstone set closes it.
//
// Deterministic rather than probabilistic: the teardown bookkeeping is run while
// the id is still in the registry, which is exactly the state the race produces,
// and then one heartbeat pass is driven by hand.
func TestClusterHeartbeatDoesNotResurrectEndedSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	reg, _, c := replica(t, ctx, st, "replica-a")

	id := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	rows, err := st.ListLiveSessions(ctx, time.Hour)
	if err != nil || len(rows) != 1 {
		t.Fatalf("after Register: %d rows, %v; want 1, nil", len(rows), err)
	}

	// The session ends — its row is deleted and it is tombstoned — but it is still
	// in the registry, as it would be in a heartbeat's snapshot.
	c.TestingSessionRemoved(id)
	if rows, err = st.ListLiveSessions(ctx, time.Hour); err != nil || len(rows) != 0 {
		t.Fatalf("after teardown: %d rows, %v; want 0, nil", len(rows), err)
	}

	c.TestingHeartbeatOnce(ctx)

	if rows, err = st.ListLiveSessions(ctx, time.Hour); err != nil {
		t.Fatal(err)
	} else if len(rows) != 0 {
		t.Fatalf("the heartbeat resurrected an ended session: %+v", rows)
	}
}
