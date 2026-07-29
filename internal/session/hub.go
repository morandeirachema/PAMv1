package session

import "sync"

// Hub fans out live session output to subscribed watchers, keyed by session id.
// The proxy publishes each recorded output chunk; the API's live-stream endpoint
// subscribes a supervisor to watch a session as it happens (Phase 16). Delivery
// is non-blocking: a slow watcher drops frames rather than stalling the session
// it is observing. A nil Hub is a no-op, so callers can hold one unconditionally.
type Hub struct {
	mu   sync.Mutex
	subs map[string]map[chan []byte]struct{}
}

// NewHub returns an empty, ready-to-use live-output hub.
func NewHub() *Hub { return &Hub{subs: make(map[string]map[chan []byte]struct{})} }

// Publish delivers a copy of b to every current subscriber of session id. It
// never blocks the caller: a watcher whose buffer is full drops the frame.
func (h *Hub) Publish(id string, b []byte) {
	if h == nil || id == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	subs := h.subs[id]
	if len(subs) == 0 {
		return
	}
	cp := append([]byte(nil), b...) // the caller may reuse its buffer
	for ch := range subs {
		select {
		case ch <- cp:
		default: // slow watcher: drop this frame rather than stall the session
		}
	}
}

// EndSession closes every subscriber channel for session id and forgets the
// id, so a watcher's read loop ends the moment the session does. Before this
// existed, a supervisor's stream simply went silent when the watched session
// was killed or completed — indistinguishable from a session that had nothing
// to say. Closing here cannot race Publish: both hold the same mutex, and the
// closed channels leave the map inside the same critical section, so nothing
// ever writes to them afterwards. A subscriber's own cancel only deletes map
// entries, so calling it after EndSession is safe too.
func (h *Hub) EndSession(id string) {
	if h == nil || id == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[id] {
		close(ch)
	}
	delete(h.subs, id)
}

// Subscribe registers a watcher for session id, returning a channel of output
// frames and a cancel func that unsubscribes it. The channel is closed only by
// EndSession — i.e. when the session itself ends; a watcher who leaves early
// calls cancel, which just releases the subscription. A concurrent Publish can
// never write a closed channel (both operations hold the hub mutex).
func (h *Hub) Subscribe(id string) (<-chan []byte, func()) {
	ch := make(chan []byte, 256)
	h.mu.Lock()
	if h.subs[id] == nil {
		h.subs[id] = make(map[chan []byte]struct{})
	}
	h.subs[id][ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if m := h.subs[id]; m != nil {
			delete(m, ch)
			if len(m) == 0 {
				delete(h.subs, id)
			}
		}
		h.mu.Unlock()
	}
}
