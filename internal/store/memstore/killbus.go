package memstore

// killbus.go is the in-process implementation of the cross-replica session
// kill bus. A single memory store is one process, so this is a simple fan-out
// hub: PublishSessionKill delivers to every subscriber's channel, and each
// Registry (there may be several in a test simulating replicas) applies inbound
// kills to the sessions it hosts. It mirrors pgstore's Postgres LISTEN/NOTIFY so
// the demo/test path exercises the same registry code the HA path does.

import (
	"context"

	"github.com/morandeirachema/pamv1/internal/session"
)

// PublishSessionKill fans a kill selector out to every current subscriber. A slow
// subscriber (buffer full) is skipped rather than blocking the publisher — a lost
// kill notification is degraded reach, not a stall, and the caller has already
// applied the kill to its own replica.
func (m *Memstore) PublishSessionKill(_ context.Context, sel session.KillSelector) error {
	m.killMu.Lock()
	subs := make([]chan session.KillSelector, 0, len(m.killSubs))
	for ch := range m.killSubs {
		subs = append(subs, ch)
	}
	m.killMu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- sel:
		default:
		}
	}
	return nil
}

// SubscribeSessionKills registers a buffered channel and returns it; the channel
// receives every kill published while ctx is live and is unregistered and closed
// when ctx is cancelled.
func (m *Memstore) SubscribeSessionKills(ctx context.Context) (<-chan session.KillSelector, error) {
	ch := make(chan session.KillSelector, 64)
	m.killMu.Lock()
	m.killSubs[ch] = struct{}{}
	m.killMu.Unlock()
	go func() {
		<-ctx.Done()
		m.killMu.Lock()
		delete(m.killSubs, ch)
		m.killMu.Unlock()
		close(ch)
	}()
	return ch, nil
}
