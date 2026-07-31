package memstore

// stepupbus.go is the in-process implementation of cross-replica step-up
// decisions (Phase 56): the shared pending-pause inventory and the decision
// fan-out. A single memory store is one process, so the bus is a hub mirroring
// killbus.go and the inventory a map mirroring livebus.go — several step-up
// coordinators sharing one Memstore in a test exercise exactly the code a
// multi-replica Postgres deployment runs. Statements arrive already sealed by
// the session layer; this store treats them as opaque strings.

import (
	"context"
	"sort"
	"time"

	"github.com/morandeirachema/pamv1/internal/session"
)

// stepUpRow is one shared-inventory entry: the pause plus its expiry, judged by
// this store's own clock (the single-clock rule of session.StepUpStore).
type stepUpRow struct {
	p       session.PendingStepUp
	expires time.Time
}

// PutStepUp creates or replaces a pending-pause row, expiring ttl from now. It
// also sweeps rows expired more than an hour ago — a crashed replica's leftovers
// are already invisible to ListStepUps, but nothing else would ever free them.
func (m *Memstore) PutStepUp(_ context.Context, p session.PendingStepUp, ttl time.Duration) error {
	now := time.Now()
	m.stepupMu.Lock()
	for id, row := range m.stepups {
		if now.Sub(row.expires) > time.Hour {
			delete(m.stepups, id)
		}
	}
	m.stepups[p.SessionID] = stepUpRow{p: p, expires: now.Add(ttl)}
	m.stepupMu.Unlock()
	return nil
}

// DeleteStepUp removes a pause's row at the claim. Deleting an absent row is a
// no-op, not an error — claim paths must be idempotent.
func (m *Memstore) DeleteStepUp(_ context.Context, sessionID string) error {
	m.stepupMu.Lock()
	delete(m.stepups, sessionID)
	m.stepupMu.Unlock()
	return nil
}

// ListStepUps returns the unexpired rows, oldest requested first (session id as
// tiebreaker, matching pgstore's ORDER BY). Expiry is judged against this
// store's own clock, the one that stamped it.
func (m *Memstore) ListStepUps(_ context.Context) ([]session.PendingStepUp, error) {
	now := time.Now()
	m.stepupMu.Lock()
	out := make([]session.PendingStepUp, 0, len(m.stepups))
	for _, row := range m.stepups {
		if now.Before(row.expires) {
			p := row.p
			p.Expires = row.expires
			out = append(out, p)
		}
	}
	m.stepupMu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Requested.Equal(out[j].Requested) {
			return out[i].Requested.Before(out[j].Requested)
		}
		return out[i].SessionID < out[j].SessionID
	})
	return out, nil
}

// PublishStepUpDecision fans a decision out to every current subscriber. A slow
// subscriber's full buffer drops it rather than blocking the publisher — the
// sends happen UNDER the lock, and SubscribeStepUpDecisions closes under the
// same lock, for the reason spelled out in PublishSessionKill: a
// snapshot-then-send version can send on a channel the ctx-cancel goroutine has
// already closed, which panics.
func (m *Memstore) PublishStepUpDecision(_ context.Context, d session.StepUpDecision) error {
	m.stepupMu.Lock()
	for ch := range m.stepupSubs {
		select {
		case ch <- d:
		default:
		}
	}
	m.stepupMu.Unlock()
	return nil
}

// SubscribeStepUpDecisions registers a buffered channel and returns it; it
// receives every decision published while ctx is live and is unregistered and
// closed when ctx is cancelled.
func (m *Memstore) SubscribeStepUpDecisions(ctx context.Context) (<-chan session.StepUpDecision, error) {
	ch := make(chan session.StepUpDecision, 16)
	m.stepupMu.Lock()
	m.stepupSubs[ch] = struct{}{}
	m.stepupMu.Unlock()
	go func() {
		<-ctx.Done()
		// Delete AND close under the lock, so a concurrent publisher can never be
		// mid-send on a channel this is closing.
		m.stepupMu.Lock()
		delete(m.stepupSubs, ch)
		close(ch)
		m.stepupMu.Unlock()
	}()
	return ch, nil
}
