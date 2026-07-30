package session_test

// The cross-replica live bus rides Postgres LISTEN/NOTIFY, which has no privilege
// model: notifications are visible to every user of the database and LISTEN needs
// no grant. So anything holding a database session could, with a plaintext bus,
// announce interest to make a hosting replica start streaming a live privileged
// session's output and then read it, or inject frames to write fabricated output
// into a supervisor's pane. These tests pin the two properties that close that:
// a payload the cluster's key does not vouch for is DROPPED, and session content
// never crosses the bus in the clear.

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestForgedInterestCannotStartATap proves an unauthenticated interest
// announcement — the shape `NOTIFY pam_live_interest, '<session id>'` — does not
// open the hosting replica's forwarding gate.
func TestForgedInterestCannotStartATap(t *testing.T) {
	restore := session.ShrinkClusterTimersForTest()
	defer restore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	regA, hubA, cA := replica(t, ctx, st, "replica-a")

	id := regA.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})

	// Watch the raw transport, exactly as a database observer would.
	busFrames, _, err := st.SubscribeLive(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// The forgery: a bare session id, which is what the id looked like on the wire
	// before the payload was authenticated.
	for i := 0; i < 5; i++ {
		if perr := st.PublishLiveInterest(ctx, id); perr != nil {
			t.Fatal(perr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cA.TestingWants(id) {
		t.Fatal("a forged interest announcement opened the forwarding gate")
	}

	// And with the gate shut, output does not reach the bus at all.
	hubA.Publish(id, []byte("privileged output"))
	select {
	case f := <-busFrames:
		t.Fatalf("output was relayed on the strength of a forged announcement: %+v", f)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestForgedFrameNeverReachesAWatcher proves a frame that does not authenticate is
// dropped by the bridge, so a database observer cannot write fabricated output
// into a supervisor's live pane — nor close their watch with a forged end marker.
func TestForgedFrameNeverReachesAWatcher(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	_, hubB, _ := replica(t, ctx, st, "replica-b")

	// A session this replica does not host, which is the case the bridge injects
	// for. No registry entry, so nothing filters the frame as a self-echo.
	const id = "aaaabbbbccccdddd"
	frames, unsub := hubB.Subscribe(id)
	defer unsub()

	forged := []byte("sudo rm -rf / # never typed by the operator")
	for i := 0; i < 5; i++ {
		if perr := st.PublishLiveFrame(ctx, session.LiveFrame{
			ID: id, Kind: session.LiveFrameData, Data: forged,
		}); perr != nil {
			t.Fatal(perr)
		}
	}
	// An end marker too: forging one would close a supervisor's pane as "session
	// ended" while the session kept running.
	if perr := st.PublishLiveFrame(ctx, session.LiveFrame{ID: id, Kind: session.LiveFrameEnd}); perr != nil {
		t.Fatal(perr)
	}

	select {
	case b, open := <-frames:
		if !open {
			t.Fatal("a forged end marker closed the watcher's stream")
		}
		if bytes.Contains(b, forged) {
			t.Fatalf("forged output reached the watcher's pane: %q", b)
		}
		t.Fatalf("an unauthenticated frame reached the watcher: %q", b)
	case <-time.After(500 * time.Millisecond):
		// Nothing arrived and the stream stayed open: both forgeries were dropped.
	}
}

// TestForgedKillIsRejectedAndRealKillIsAudited proves the cross-replica kill bus
// authenticates its instructions, and that an applied one leaves a trace.
//
// `NOTIFY pam_session_kill, '{"actor":"alice"}'` used to terminate every one of an
// actor's live privileged sessions on every replica — an availability attack on
// privileged access available to anything holding a database session — and the
// applying replica audited nothing, so the only evidence was the abrupt end.
func TestForgedKillIsRejectedAndRealKillIsAudited(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()

	audited := make(chan string, 4)
	regA := session.NewRegistry()
	hubA := session.NewHub()
	regA.AttachHub(hubA)
	if err := regA.StartKillBus(ctx, st, session.KillBusConfig{
		BusKey: testBusKey(),
		Audit: func(_ context.Context, action, detail string) {
			select {
			case audited <- action + " " + detail:
			default:
			}
		},
	}); err != nil {
		t.Fatal(err)
	}

	killed := make(chan struct{}, 1)
	id := regA.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"},
		func() {
			select {
			case killed <- struct{}{}:
			default:
			}
		})

	// The forgery: a selector with no seal, exactly what a hand-written NOTIFY
	// would carry.
	for i := 0; i < 5; i++ {
		if err := st.PublishSessionKill(ctx, session.KillSelector{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-killed:
		t.Fatal("a forged cross-replica kill terminated a live session")
	case <-time.After(300 * time.Millisecond):
	}

	// A genuine kill from a second replica sharing the key still works, and the
	// applying replica audits it.
	regB := session.NewRegistry()
	if err := regB.StartKillBus(ctx, st, session.KillBusConfig{BusKey: testBusKey()}); err != nil {
		t.Fatal(err)
	}
	if out := regB.KillDistributed(id); out != session.KillDispatched {
		t.Fatalf("KillDistributed = %v, want KillDispatched", out)
	}
	select {
	case <-killed:
	case <-time.After(5 * time.Second):
		t.Fatal("a legitimately sealed cross-replica kill did not terminate the session")
	}
	select {
	case got := <-audited:
		if !strings.Contains(got, "session.kill") || !strings.Contains(got, "via:bus") {
			t.Fatalf("audit = %q, want a session.kill … via:bus event", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an applied cross-replica kill was not audited")
	}
}
