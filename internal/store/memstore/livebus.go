package memstore

// livebus.go is the in-process implementation of cross-replica live monitoring
// (Phase 55): the live-frame and watch-interest buses, and the shared
// live-session inventory. A single memory store is one process, so the buses
// are fan-out hubs (mirroring killbus.go) and the inventory is a map — but
// several session registries sharing one Memstore in a test exercise exactly
// the code a multi-replica Postgres deployment runs.

import (
	"context"
	"sort"
	"time"

	"github.com/morandeirachema/pamv1/internal/session"
)

// sortLiveInfos orders inventory rows oldest started first, id as tiebreaker,
// matching pgstore's ORDER BY so listings are deterministic on either store.
func sortLiveInfos(infos []session.Info) {
	sort.Slice(infos, func(i, j int) bool {
		if !infos[i].Started.Equal(infos[j].Started) {
			return infos[i].Started.Before(infos[j].Started)
		}
		return infos[i].ID < infos[j].ID
	})
}

// liveRow is one shared-inventory entry: the session plus the moment its
// replica last confirmed it alive.
type liveRow struct {
	info session.Info
	seen time.Time
}

// PublishLiveFrame fans a live-output frame (or end marker) out to every
// current subscriber. A slow subscriber's full buffer drops the frame rather
// than blocking the publisher — the live view is lossy by design; the
// recording is the faithful copy.
func (m *Memstore) PublishLiveFrame(_ context.Context, f session.LiveFrame) error {
	// The sends happen UNDER the lock, and SubscribeLive closes under the same
	// lock after removing the channel from the map. Snapshotting the subscribers
	// and sending after unlocking is the obvious-looking version and it panics:
	// the ctx-cancel goroutine can close a channel that a publisher still holds in
	// its snapshot, and `select`/`default` does not protect a send on a closed
	// channel. Reproduced as `send on closed channel` at shutdown, where every
	// ending session publishes an end marker on a background context while the
	// subscriber contexts are being cancelled. Holding the lock is cheap because
	// every send here is already non-blocking.
	m.liveMu.Lock()
	for ch := range m.frameSubs {
		select {
		case ch <- f:
		default:
		}
	}
	m.liveMu.Unlock()
	return nil
}

// PublishLiveInterest fans a watch-interest announcement (a session id) out to
// every current subscriber, non-blocking like the frame bus — a lost
// announcement is re-sent by the announcer within seconds.
func (m *Memstore) PublishLiveInterest(_ context.Context, sessionID string) error {
	// Under the lock, for the reason spelled out in PublishLiveFrame.
	m.liveMu.Lock()
	for ch := range m.interestSubs {
		select {
		case ch <- sessionID:
		default:
		}
	}
	m.liveMu.Unlock()
	return nil
}

// SubscribeLive registers buffered frame and interest channels and returns
// them; both receive everything published while ctx is live and are
// unregistered and closed when ctx is cancelled.
func (m *Memstore) SubscribeLive(ctx context.Context) (<-chan session.LiveFrame, <-chan string, error) {
	frames := make(chan session.LiveFrame, 256)
	interest := make(chan string, 16)
	m.liveMu.Lock()
	m.frameSubs[frames] = struct{}{}
	m.interestSubs[interest] = struct{}{}
	m.liveMu.Unlock()
	go func() {
		<-ctx.Done()
		// Delete AND close under the lock, so a concurrent publisher can never be
		// mid-send on a channel this is closing.
		m.liveMu.Lock()
		delete(m.frameSubs, frames)
		delete(m.interestSubs, interest)
		close(frames)
		close(interest)
		m.liveMu.Unlock()
	}()
	return frames, interest, nil
}

// PutLiveSession creates or replaces a live-session inventory row, stamping it
// seen-now — the same call serves initial registration and the heartbeat.
func (m *Memstore) PutLiveSession(_ context.Context, info session.Info) error {
	m.liveMu.Lock()
	m.liveSessions[info.ID] = liveRow{info: info, seen: time.Now()}
	m.liveMu.Unlock()
	return nil
}

// DeleteLiveSession removes a live-session inventory row at session end.
// Deleting an absent row is a no-op, not an error — teardown paths must be
// idempotent.
func (m *Memstore) DeleteLiveSession(_ context.Context, id string) error {
	m.liveMu.Lock()
	delete(m.liveSessions, id)
	m.liveMu.Unlock()
	return nil
}

// DeleteReplicaLiveSessions removes every inventory row a replica owns; a
// restarting replica calls it so a previous crash leaves no ghost rows.
func (m *Memstore) DeleteReplicaLiveSessions(_ context.Context, replica string) error {
	m.liveMu.Lock()
	for id, row := range m.liveSessions {
		if row.info.Replica == replica {
			delete(m.liveSessions, id)
		}
	}
	m.liveMu.Unlock()
	return nil
}

// ListLiveSessions returns the inventory rows seen within maxAge, oldest
// started first. Freshness is judged against this store's own clock (the
// single-clock rule of session.LiveStore).
func (m *Memstore) ListLiveSessions(_ context.Context, maxAge time.Duration) ([]session.Info, error) {
	cutoff := time.Now().Add(-maxAge)
	m.liveMu.Lock()
	out := make([]session.Info, 0, len(m.liveSessions))
	for _, row := range m.liveSessions {
		if row.seen.After(cutoff) {
			out = append(out, row.info)
		}
	}
	m.liveMu.Unlock()
	sortLiveInfos(out)
	return out, nil
}
