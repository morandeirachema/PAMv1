package session_test

// livebus_test.go proves cross-replica live monitoring (Phase 55) with two
// independent Registry+Hub pairs sharing one memory store, exactly as
// killbus_test.go does for the kill switch: the memory store's in-process
// fan-out stands in for Postgres LISTEN/NOTIFY, so these tests drive the same
// Cluster code an HA deployment runs. A supervisor on "replica B" must be able
// to list, watch and see the end of a session hosted on "replica A" — and a
// session nobody watches must never reach the bus.

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// testBusKey is a fixed live-bus key. Real deployments derive one into shared
// custody; a test only needs every simulated replica to share the same bytes.
func testBusKey() []byte {
	k := make([]byte, session.LiveBusKeySize)
	for i := range k {
		k[i] = byte(i + 7)
	}
	return k
}

// replica builds one simulated replica: a registry and hub wired to the shared
// store under the given name, with the cluster machinery started.
func replica(t *testing.T, ctx context.Context, st *memstore.Memstore, name string) (*session.Registry, *session.Hub, *session.Cluster) {
	t.Helper()
	reg := session.NewRegistry()
	hub := session.NewHub()
	reg.AttachHub(hub)
	c, err := session.StartCluster(ctx, session.ClusterConfig{
		Store: st, Registry: reg, Hub: hub, Replica: name, BusKey: testBusKey(),
	})
	if err != nil {
		t.Fatalf("StartCluster(%s): %v", name, err)
	}
	return reg, hub, c
}

// waitClosed asserts ch is closed (not merely drained) within the deadline,
// returning the frames received before the close.
func waitClosed(t *testing.T, ch <-chan []byte, within time.Duration) [][]byte {
	t.Helper()
	var got [][]byte
	deadline := time.After(within)
	for {
		select {
		case b, open := <-ch:
			if !open {
				return got
			}
			got = append(got, b)
		case <-deadline:
			t.Fatal("watch stream was not closed in time")
		}
	}
}

// TestClusterRemoteWatchEndToEnd is the flagship: a session hosted on replica A
// is watched from replica B — B subscribes to its OWN hub, announces interest,
// A's hub forwards over the store bus, B's bridge injects — and when A removes
// the session, B's stream closes and the shared inventory row is gone.
func TestClusterRemoteWatchEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	regA, hubA, _ := replica(t, ctx, st, "replica-a")
	_, hubB, cB := replica(t, ctx, st, "replica-b")

	id := regA.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})

	frames, unsub := hubB.Subscribe(id)
	defer unsub()
	ok, err := cB.WatchRemote(ctx, id)
	if err != nil || !ok {
		t.Fatalf("WatchRemote = %v, %v; want true, nil", ok, err)
	}
	defer cB.UnwatchRemote(id)

	// Interest propagates asynchronously; keep publishing on A until a frame
	// lands on B (each publish is one frame, so receiving proves the path).
	want := []byte("root@web-01:~# whoami\r\n")
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
receive:
	for {
		select {
		case b := <-frames:
			if !bytes.Equal(b, want) {
				t.Fatalf("frame = %q, want %q", b, want)
			}
			break receive
		case <-tick.C:
			hubA.Publish(id, want)
		case <-deadline:
			t.Fatal("remote watcher never received the hosted session's output")
		}
	}

	// Ending the session on A closes B's stream (the end marker crosses the
	// bus) and deletes the shared inventory row.
	regA.Remove(id)
	waitClosed(t, frames, 5*time.Second)
	rows, err := st.ListLiveSessions(ctx, time.Hour)
	if err != nil {
		t.Fatalf("ListLiveSessions: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("inventory after Remove = %d rows, want 0", len(rows))
	}
}

// TestClusterListMergesReplicas proves the cluster listing shows every
// replica's sessions, each naming its host, from whichever replica lists.
func TestClusterListMergesReplicas(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	regA, _, cA := replica(t, ctx, st, "replica-a")
	regB, _, cB := replica(t, ctx, st, "replica-b")

	idA := regA.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh", Started: time.Now().Add(-time.Minute)}, func() {})
	idB := regB.Register(session.Info{Actor: "bob", Target: "db-01", Protocol: "postgres", Started: time.Now()}, func() {})

	for _, c := range []*session.Cluster{cA, cB} {
		infos, err := c.List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(infos) != 2 {
			t.Fatalf("List = %d sessions, want 2 (both replicas)", len(infos))
		}
		if infos[0].ID != idA || infos[0].Replica != "replica-a" {
			t.Fatalf("oldest = %+v, want session %s on replica-a", infos[0], idA)
		}
		if infos[1].ID != idB || infos[1].Replica != "replica-b" {
			t.Fatalf("newest = %+v, want session %s on replica-b", infos[1], idB)
		}
	}

	regB.Remove(idB)
	infos, err := cA.List(ctx)
	if err != nil {
		t.Fatalf("List after remove: %v", err)
	}
	if len(infos) != 1 || infos[0].ID != idA {
		t.Fatalf("List after remove = %+v, want only %s", infos, idA)
	}
}

// TestClusterInterestGatesTheBus proves an unwatched session's output never
// reaches the bus — the property that keeps N replicas' worth of session
// bytes from flowing through the store around the clock — and that the gate
// closes again once the last watcher leaves and its interest expires.
func TestClusterInterestGatesTheBus(t *testing.T) {
	restore := session.ShrinkClusterTimersForTest()
	defer restore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	regA, hubA, cA := replica(t, ctx, st, "replica-a")
	_, _, cB := replica(t, ctx, st, "replica-b")

	id := regA.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})

	// A raw bus observer: what an unwatched session must never appear on.
	busFrames, _, err := st.SubscribeLive(ctx)
	if err != nil {
		t.Fatalf("SubscribeLive: %v", err)
	}
	hubA.Publish(id, []byte("unwatched output"))
	select {
	case f := <-busFrames:
		t.Fatalf("unwatched session leaked to the bus: %+v", f)
	case <-time.After(100 * time.Millisecond):
	}

	// A watcher on B opens the gate...
	if ok, err := cB.WatchRemote(ctx, id); err != nil || !ok {
		t.Fatalf("WatchRemote = %v, %v; want true, nil", ok, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !cA.TestingWants(id) {
		if time.Now().After(deadline) {
			t.Fatal("hosting replica never learned of the watcher's interest")
		}
		time.Sleep(5 * time.Millisecond)
	}
	const secret = "watched output"
	hubA.Publish(id, []byte(secret))
	select {
	case f := <-busFrames:
		// A frame DID cross the bus — and it is SEALED. A raw observer of the
		// transport (which for Postgres is anything that can LISTEN, since
		// notification channels have no privilege model) must not be able to read
		// session content out of it.
		if f.ID != id {
			t.Fatalf("bus frame is for session %q, want %q", f.ID, id)
		}
		if bytes.Contains(f.Data, []byte(secret)) {
			t.Fatalf("session output crossed the bus in the CLEAR: %q", f.Data)
		}
		if len(f.Data) == 0 {
			t.Fatal("bus frame carried no payload at all")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watched session's output never reached the bus")
	}

	// ...and leaving closes it again by silence: announcements stop, interest
	// expires, and the hosting replica stops forwarding.
	cB.UnwatchRemote(id)
	for time.Now().Before(deadline) && cA.TestingWants(id) {
		time.Sleep(5 * time.Millisecond)
	}
	if cA.TestingWants(id) {
		t.Fatal("interest never expired after the last watcher left")
	}
	for len(busFrames) > 0 {
		<-busFrames // drain frames forwarded while interest was live
	}
	hubA.Publish(id, []byte("after expiry"))
	select {
	case f := <-busFrames:
		t.Fatalf("output leaked to the bus after interest expired: %+v", f)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestClusterCrashBackstop proves a remote watch does not hang forever when
// the hosting replica dies without publishing an end marker: its inventory
// rows stop being refreshed, and the watching replica's staleness pass closes
// the stream.
func TestClusterCrashBackstop(t *testing.T) {
	restore := session.ShrinkClusterTimersForTest()
	defer restore()
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	ctxA, cancelA := context.WithCancel(context.Background())
	st := memstore.New()
	regA, _, _ := replica(t, ctxA, st, "replica-a")
	_, hubB, cB := replica(t, ctxB, st, "replica-b")

	id := regA.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	frames, unsub := hubB.Subscribe(id)
	defer unsub()
	if ok, err := cB.WatchRemote(ctxB, id); err != nil || !ok {
		t.Fatalf("WatchRemote = %v, %v; want true, nil", ok, err)
	}
	defer cB.UnwatchRemote(id)

	cancelA() // replica A "crashes": no end marker, no more heartbeats
	waitClosed(t, frames, 5*time.Second)
}

// TestClusterHeartbeatRepairsInventory proves a lost inventory row (a failed
// Register-time upsert, an operator's stray delete) reappears at the next
// heartbeat — the self-healing that makes the Register-time write best-effort.
func TestClusterHeartbeatRepairsInventory(t *testing.T) {
	restore := session.ShrinkClusterTimersForTest()
	defer restore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	regA, _, cA := replica(t, ctx, st, "replica-a")

	id := regA.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	if err := st.DeleteLiveSession(ctx, id); err != nil {
		t.Fatalf("DeleteLiveSession: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		infos, err := cA.List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		// The registry overlay lists it regardless; the repair is proven by
		// the STORE row coming back.
		rows, err := st.ListLiveSessions(ctx, time.Hour)
		if err != nil {
			t.Fatalf("ListLiveSessions: %v", err)
		}
		if len(rows) == 1 && rows[0].ID == id && len(infos) == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("heartbeat never restored the inventory row (store rows: %+v)", rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestClusterRemoteKillClosesWatch chains the two buses end to end: a kill
// issued on replica B terminates a session hosted on replica A (kill bus),
// whose teardown publishes the end marker (live bus) that closes B's own
// watch stream — the full supervisor story: see it, watch it, kill it, and
// see it end, all from the wrong replica.
func TestClusterRemoteKillClosesWatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	regA, _, _ := replica(t, ctx, st, "replica-a")
	regB, hubB, cB := replica(t, ctx, st, "replica-b")
	if err := regA.StartKillBus(ctx, st); err != nil {
		t.Fatalf("StartKillBus(A): %v", err)
	}
	if err := regB.StartKillBus(ctx, st); err != nil {
		t.Fatalf("StartKillBus(B): %v", err)
	}

	var id string
	// The kill func mimics a real proxy: closing the connection ends the
	// session, whose cleanup removes it from the registry.
	id = regA.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() { regA.Remove(id) })

	frames, unsub := hubB.Subscribe(id)
	defer unsub()
	if ok, err := cB.WatchRemote(ctx, id); err != nil || !ok {
		t.Fatalf("WatchRemote = %v, %v; want true, nil", ok, err)
	}
	defer cB.UnwatchRemote(id)

	if out := regB.KillDistributed(id); out != session.KillDispatched {
		t.Fatalf("KillDistributed = %v, want KillDispatched (session is on A)", out)
	}
	waitClosed(t, frames, 5*time.Second)
	if regA.Exists(id) {
		t.Fatal("session still registered on A after the cross-replica kill")
	}
}
