package session

import "sync"

// Hub fans out live session output to subscribed watchers, keyed by session id.
// The proxy publishes each recorded output chunk; the API's live-stream endpoint
// subscribes a supervisor to watch a session as it happens (Phase 16). Delivery
// is non-blocking: a slow watcher drops frames rather than stalling the session
// it is observing. A nil Hub is a no-op, so callers can hold one unconditionally.
//
// With a relay attached (Phase 55), Publish also forwards chunks to the
// cross-replica bus while a REMOTE replica has announced a watcher — so the
// hub is the single tee point for both local and cluster-wide monitoring, and
// none of the many Publish call sites know the difference.
type Hub struct {
	mu    sync.Mutex
	subs  map[string]map[chan []byte]struct{}
	relay hubRelay // cross-replica forwarder (nil = single-replica)
}

// hubRelay is what the Hub needs from the cluster machinery: whether anyone
// remote wants a session's output, and a non-blocking forward for a chunk.
// wants is called under the hub mutex on every Publish, so implementations
// must be cheap leaf operations that never call back into the Hub.
type hubRelay interface {
	wants(id string) bool
	forward(id string, b []byte)
}

// setRelay attaches the cross-replica forwarder. Called once at wiring time by
// StartCluster.
func (h *Hub) setRelay(r hubRelay) {
	h.mu.Lock()
	h.relay = r
	h.mu.Unlock()
}

// NewHub returns an empty, ready-to-use live-output hub.
func NewHub() *Hub { return &Hub{subs: make(map[string]map[chan []byte]struct{})} }

// Publish delivers a copy of b to every current subscriber of session id, and
// forwards it to the cross-replica bus when a remote replica has announced a
// watcher. It never blocks the caller: a watcher whose buffer is full drops
// the frame, and the relay forward only enqueues.
func (h *Hub) Publish(id string, b []byte) { h.publish(id, b, true) }

// publishLocal delivers to local subscribers ONLY, never the relay. It is the
// cluster bridge's inject path for frames that arrived FROM the bus: consulting
// the relay there would let a watching replica re-forward what it received —
// its own inbound interest announcement echoes back to itself, so the gate
// would be open — and the frame would circulate forever.
func (h *Hub) publishLocal(id string, b []byte) { h.publish(id, b, false) }

// publish implements Publish/publishLocal; viaRelay selects whether the
// cross-replica forward is considered.
func (h *Hub) publish(id string, b []byte, viaRelay bool) {
	if h == nil || id == "" {
		return
	}
	h.mu.Lock()
	subs := h.subs[id]
	relay := h.relay
	remote := viaRelay && relay != nil && relay.wants(id)
	if len(subs) == 0 && !remote {
		h.mu.Unlock()
		return
	}
	cp := append([]byte(nil), b...) // the caller may reuse its buffer
	for ch := range subs {
		select {
		case ch <- cp:
		default: // slow watcher: drop this frame rather than stall the session
		}
	}
	h.mu.Unlock()
	if remote {
		relay.forward(id, cp) // outside the lock; forward never blocks
	}
}

// HasSubscribers reports whether anyone is currently watching session id —
// locally, or on a remote replica that has announced interest. It lets a
// publisher skip building a large payload — a WinRM run's entire output —
// when nobody would receive it: Publish already drops frames with no
// subscribers, but only after the caller has paid to build the frame. A
// subscriber arriving between this check and the Publish misses that frame,
// which is the hub's normal contract — a watcher only ever sees output from
// the moment it subscribed.
func (h *Hub) HasSubscribers(id string) bool {
	if h == nil || id == "" {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subs[id]) > 0 {
		return true
	}
	return h.relay != nil && h.relay.wants(id)
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
