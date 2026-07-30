package memstore_test

// Regression test for a `send on closed channel` panic in the in-process live
// bus: PublishLiveFrame snapshotted its subscribers, released the mutex and then
// sent, while the ctx-cancel goroutine deleted and closed those same channels —
// and `select`/`default` does not protect a send on a closed channel.
//
// It fired at shutdown, where the cluster publishes an end marker for every
// ending session on a background context (deliberately, so teardown survives a
// cancelled server context) exactly while the subscriber contexts are being
// cancelled. Memstore backs demo mode and the in-process multi-replica tests, so
// this was also a CI flake source. The kill bus was written from the same
// template and had the same defect.

import (
	"context"
	"sync"
	"testing"

	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestLiveBusPublishDuringSubscriberCancel hammers publish against subscriber
// cancellation. Against the original code this panics in well under a second;
// the panic is not recoverable by the test, so a regression fails the suite
// loudly rather than subtly.
func TestLiveBusPublishDuringSubscriberCancel(t *testing.T) {
	for round := 0; round < 50; round++ {
		m := memstore.New()
		ctx, cancel := context.WithCancel(context.Background())
		for i := 0; i < 8; i++ {
			if _, _, err := m.SubscribeLive(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := m.SubscribeSessionKills(ctx); err != nil {
				t.Fatal(err)
			}
		}

		var wg sync.WaitGroup
		for p := 0; p < 6; p++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 300; i++ {
					// A background context on purpose: this is how session teardown
					// publishes its end marker, and it is why the race is reachable
					// during shutdown.
					_ = m.PublishLiveFrame(context.Background(),
						session.LiveFrame{ID: "s1", Kind: session.LiveFrameEnd})
					_ = m.PublishLiveInterest(context.Background(), "s1")
					_ = m.PublishSessionKill(context.Background(), session.KillSelector{ID: "s1"})
				}
			}()
		}
		cancel() // close the subscriber channels while the publishers are running
		wg.Wait()
	}
}
