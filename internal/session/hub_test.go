package session

import (
	"testing"
	"time"
)

// TestHubPubSub proves a subscriber receives published frames, a cancelled
// subscriber stops receiving, and a publish to an id with no subscribers (or a
// nil hub) is a harmless no-op.
func TestHubPubSub(t *testing.T) {
	h := NewHub()

	// No subscribers: publish must not block or panic.
	h.Publish("s1", []byte("dropped"))

	frames, cancel := h.Subscribe("s1")
	h.Publish("s1", []byte("hello"))
	select {
	case b := <-frames:
		if string(b) != "hello" {
			t.Fatalf("got %q, want hello", b)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive the frame")
	}

	// A frame for another session id is not delivered here.
	h.Publish("other", []byte("nope"))
	select {
	case b := <-frames:
		t.Fatalf("received a frame for a different session: %q", b)
	case <-time.After(50 * time.Millisecond):
	}

	// After cancel, the subscription is removed (publish is a no-op for it).
	cancel()
	h.Publish("s1", []byte("after-cancel"))
	select {
	case b, ok := <-frames:
		if ok && string(b) == "after-cancel" {
			t.Fatal("received a frame after cancel")
		}
	case <-time.After(50 * time.Millisecond):
	}

	// A nil hub is a no-op.
	var nilHub *Hub
	nilHub.Publish("x", []byte("y"))
}

// TestHubSlowWatcherDropsFrames proves a full subscriber buffer drops frames
// instead of blocking the publisher (the session it watches must never stall).
func TestHubSlowWatcherDropsFrames(t *testing.T) {
	h := NewHub()
	_, cancel := h.Subscribe("s")
	defer cancel()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10000; i++ {
			h.Publish("s", []byte("frame")) // never read; must not block
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a slow watcher")
	}
}

// TestEndSessionClosesWatchers proves the end-of-session signal: EndSession
// closes every subscriber channel for that id (and only that id), a Publish
// after the end is a safe no-op, and a subscriber's own cancel after the end
// does not panic. Without this signal a watcher could not tell "session over"
// from "session quiet".
func TestEndSessionClosesWatchers(t *testing.T) {
	h := NewHub()
	a1, cancel1 := h.Subscribe("s-1")
	a2, _ := h.Subscribe("s-1")
	other, cancelOther := h.Subscribe("s-2")
	defer cancelOther()

	h.EndSession("s-1")
	if _, open := <-a1; open {
		t.Fatal("first watcher channel still open after EndSession")
	}
	if _, open := <-a2; open {
		t.Fatal("second watcher channel still open after EndSession")
	}
	select {
	case _, open := <-other:
		if !open {
			t.Fatal("EndSession closed a different session's watcher")
		}
		t.Fatal("unexpected frame on the other session")
	default: // still open, nothing delivered — correct
	}

	h.Publish("s-1", []byte("late")) // must not panic or deliver
	cancel1()                        // cancel after end must be safe

	// A nil hub and an unknown id are no-ops.
	var nilHub *Hub
	nilHub.EndSession("s-1")
	h.EndSession("never-registered")
}
