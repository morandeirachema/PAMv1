package session

import (
	"testing"
	"time"
)

// TestRegistry covers register, list, kill (found and unknown id) and remove.
func TestRegistry(t *testing.T) {
	r := NewRegistry()
	killed := false
	id := r.Register(Info{Actor: "alice", Target: "web-01", Protocol: "ssh", Started: time.Unix(1, 0)}, func() { killed = true })
	if id == "" {
		t.Fatal("empty id")
	}

	list := r.List()
	if len(list) != 1 || list[0].Actor != "alice" || list[0].ID != id {
		t.Fatalf("unexpected list: %+v", list)
	}

	if !r.Kill(id) {
		t.Fatal("kill should find the session")
	}
	if !killed {
		t.Fatal("kill func not invoked")
	}
	if r.Kill("nope") {
		t.Fatal("kill of unknown id should return false")
	}

	r.Remove(id)
	if len(r.List()) != 0 {
		t.Fatal("session should be gone after Remove")
	}
}

// TestRegistryOrdering checks List returns sessions oldest first.
func TestRegistryOrdering(t *testing.T) {
	r := NewRegistry()
	r.Register(Info{Actor: "b", Started: time.Unix(2, 0)}, nil)
	r.Register(Info{Actor: "a", Started: time.Unix(1, 0)}, nil)
	list := r.List()
	if list[0].Actor != "a" || list[1].Actor != "b" {
		t.Fatalf("expected oldest first, got %+v", list)
	}
}

// TestRemoveEndsWatchStreams proves the registry→hub link: with a hub attached,
// removing a session (the path every session end funnels through — normal
// completion and kills alike) closes its live watch streams; without the
// attachment, removal leaves the hub alone.
func TestRemoveEndsWatchStreams(t *testing.T) {
	reg := NewRegistry()
	hub := NewHub()
	reg.AttachHub(hub)

	sid := reg.Register(Info{Actor: "op", Target: "web-01", Protocol: "ssh"}, func() {})
	if !reg.Exists(sid) {
		t.Fatal("registered session not reported by Exists")
	}
	frames, cancel := hub.Subscribe(sid)
	defer cancel()

	reg.Remove(sid)
	if reg.Exists(sid) {
		t.Fatal("removed session still reported by Exists")
	}
	select {
	case _, open := <-frames:
		if open {
			t.Fatal("got a frame instead of a close after Remove")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watch stream not closed by Remove")
	}

	// Without an attached hub, Remove must leave subscriptions alone.
	lone := NewRegistry()
	sid2 := lone.Register(Info{Actor: "op", Target: "web-02", Protocol: "ssh"}, func() {})
	frames2, cancel2 := hub.Subscribe(sid2)
	defer cancel2()
	lone.Remove(sid2)
	select {
	case _, open := <-frames2:
		if !open {
			t.Fatal("Remove closed a stream with no hub attached")
		}
		t.Fatal("unexpected frame")
	default: // still open — correct
	}
}
