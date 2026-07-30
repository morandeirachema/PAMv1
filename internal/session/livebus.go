package session

// livebus.go makes live monitoring work across replicas (Phase 55), closing the
// deferral Phase 34 recorded when it made the kill-switch cluster-wide. Without
// it, GET /api/sessions listed only the sessions of whichever replica the load
// balancer picked, and a supervisor's SSE watch 404ed unless it happened to land
// on the pod hosting the session.
//
// The shape mirrors the kill bus — the store is the transport (Postgres
// LISTEN/NOTIFY in pgstore, an in-process fan-out in memstore) — but session
// BYTES are a heavier cargo than a kill signal, so the fan-out is
// interest-gated: a replica forwards a session's output onto the bus only while
// some other replica has announced a live watcher for it. An unwatched session
// costs the bus nothing.
//
// Three cooperating parts, all owned by one Cluster value:
//
//   - Inventory: every replica upserts its live sessions into the store
//     (heartbeat-refreshed), so listing is cluster-wide. Rows from a crashed
//     replica stop being refreshed and age out of every listing — no
//     distributed GC, just a freshness filter at read time.
//   - Interest: a replica whose supervisor watches a remote session announces
//     the session id on the bus, immediately and then periodically. The hosting
//     replica holds each announcement for interestTTL, so a watcher's crash
//     stops the forwarding by silence, not by a goodbye message.
//   - Frames: the hosting replica's Hub consults the Cluster on every Publish
//     and forwards a copy of the chunk (and, at session end, an end marker) to
//     the bus; the watching replica's bridge injects inbound frames into its
//     own local Hub, so the SSE handler code is identical for local and remote
//     sessions.
//
// Loop prevention follows the kill bus: everything a replica publishes is also
// delivered back to itself, so inbound frames for a session in the LOCAL
// registry are dropped (they are the replica's own forwards), and the bridge
// injects via the Hub's local-only publish, which never re-forwards.

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Kinds of LiveFrame carried on the cross-replica bus.
const (
	// LiveFrameData carries a chunk of session output (terminal bytes).
	LiveFrameData = "data"
	// LiveFrameEnd marks the session as over, so remote watch streams close
	// instead of going silent. Published on every session end, watched or not —
	// it is one tiny frame per session lifetime.
	LiveFrameEnd = "end"
)

// LiveFrame is one unit of live-session traffic on the cross-replica bus: a
// chunk of a session's output, or its end marker. Data is JSON-encoded as
// base64 by encoding/json, which keeps the payload valid text for transports
// with that requirement (Postgres NOTIFY).
type LiveFrame struct {
	ID   string `json:"id"`             // session id the frame belongs to
	Kind string `json:"kind"`           // LiveFrameData | LiveFrameEnd
	Data []byte `json:"data,omitempty"` // output bytes when Kind is data
}

// LiveStore is what the store must provide for cross-replica live monitoring:
// the frame + interest bus and the shared live-session inventory. Both store
// implementations satisfy it (pgstore over LISTEN/NOTIFY and an UNLOGGED
// table; memstore in-process, so tests and the demo drive the same Cluster
// code the HA path does).
type LiveStore interface {
	// PublishLiveFrame delivers a frame to every replica's SubscribeLive
	// stream, including the publisher's own (self-delivery is filtered by the
	// receiver). Implementations may split a large data frame into several
	// smaller ones — watchers see the same bytes either way.
	PublishLiveFrame(ctx context.Context, f LiveFrame) error
	// PublishLiveInterest announces "this replica has a live watcher for
	// session id", telling the hosting replica to start (or keep) forwarding.
	PublishLiveInterest(ctx context.Context, sessionID string) error
	// SubscribeLive returns the inbound frame and interest streams. Both
	// channels close when ctx is cancelled.
	SubscribeLive(ctx context.Context) (frames <-chan LiveFrame, interest <-chan string, err error)
	// PutLiveSession upserts one live-session inventory row (refreshing its
	// seen-at stamp); DeleteLiveSession removes it at session end; and
	// DeleteReplicaLiveSessions clears every row a replica owns, which a
	// restarting replica calls so its previous crash leaves no ghosts.
	PutLiveSession(ctx context.Context, info Info) error
	DeleteLiveSession(ctx context.Context, id string) error
	DeleteReplicaLiveSessions(ctx context.Context, replica string) error
	// ListLiveSessions returns rows whose seen-at stamp is younger than maxAge,
	// oldest first. The single-clock rule: each implementation compares the
	// stamp against ITS OWN notion of now (Postgres now() in pgstore, Go time
	// in memstore), so replica clock skew never decides freshness.
	ListLiveSessions(ctx context.Context, maxAge time.Duration) ([]Info, error)
}

// Timing knobs for the cluster machinery. Package variables rather than
// constants only so in-package tests can shrink them; production always runs
// the defaults — they are deliberately not configuration, because getting the
// ratios wrong (a TTL shorter than its refresh period) silently breaks
// liveness in ways an operator would struggle to diagnose.
var (
	// inventoryHeartbeat is how often a replica re-upserts its live sessions;
	// inventoryMaxAge (3×) is how stale a row may be before listings drop it,
	// which is also how long a crashed replica's sessions linger in the list.
	inventoryHeartbeat = 15 * time.Second
	inventoryMaxAge    = 45 * time.Second
	// interestEvery is how often a watching replica re-announces its interest;
	// interestTTL (3×) is how long the hosting replica forwards after the last
	// announcement — so a vanished watcher stops the forwarding by silence.
	interestEvery = 10 * time.Second
	interestTTL   = 30 * time.Second
)

const (
	// forwardQueueSize bounds the async forward queue between the Hub and the
	// bus publisher. When it fills (a slow bus), data frames are dropped — the
	// live view is lossy by design, exactly like a slow local watcher; the
	// recording remains the faithful copy.
	forwardQueueSize = 1024
	// endMarkerEnqueueWait bounds how long a session teardown waits to hand its
	// end marker to the publisher queue. Short on purpose: teardown is on the
	// session's own path, and the staleness backstop covers a dropped marker.
	endMarkerEnqueueWait = 500 * time.Millisecond
	// busOpTimeout bounds every store call the cluster machinery makes, so a
	// hung store can never wedge a session's registration or teardown path.
	busOpTimeout = 5 * time.Second
)

// Cluster is the cross-replica live-monitoring coordinator: shared inventory
// (listing), interest-gated frame forwarding (hosting side) and the bridge +
// announcer (watching side). Wire one per process with StartCluster; a nil
// *Cluster means single-replica behavior everywhere it is consulted.
type Cluster struct {
	st      LiveStore
	reg     *Registry
	hub     *Hub
	replica string

	// The timing knobs, copied from the package variables ONCE in StartCluster
	// so the background loops never read shared mutable state (the variables
	// exist only for tests to shrink between clusters).
	heartbeat, maxAge, announceEvery, ttl time.Duration

	// imu guards interest — inbound announcements, keyed by session id, each
	// valued with its expiry. It is a LEAF lock: Hub.Publish calls wants()
	// while holding the hub mutex, so nothing here may call back into the Hub
	// or Registry while holding imu.
	imu      sync.Mutex
	interest map[string]time.Time

	// rmu guards removed — a short-lived tombstone set of session ids whose
	// inventory rows have been deleted. Without it the heartbeat can RESURRECT a
	// dead session: it snapshots the registry, a session ends (deleting its row),
	// and the pending upsert re-inserts it with a fresh seen-at stamp. Nothing
	// deletes it again, so it stays listed and 200-watchable for inventoryMaxAge
	// while its watchers get silence. A leaf lock like the two below.
	rmu     sync.Mutex
	removed map[string]time.Time

	// wmu guards watched — this replica's remote watches, refcounted per
	// session id so N supervisors watching the same remote session share one
	// announcement stream. A leaf lock like imu.
	wmu     sync.Mutex
	watched map[string]int

	frames  chan LiveFrame // async forward queue drained by runPublisher
	dropped atomic.Int64   // frames dropped on a full queue since the last report
}

// StartCluster wires cross-replica live monitoring over the store and returns
// the Cluster handle the API consults for listing and remote watches. replica
// names this replica in the inventory (pass the hostname; a random id is used
// if empty). It subscribes to the bus, purges this replica's leftover
// inventory rows from a previous run, hooks the registry (inventory upkeep)
// and the hub (interest-gated forwarding), and starts the background loops,
// which run until ctx is cancelled. An error means the bus subscription
// failed and live monitoring stays replica-local — the caller logs and
// continues, exactly like the kill bus.
func StartCluster(ctx context.Context, st LiveStore, reg *Registry, hub *Hub, replica string) (*Cluster, error) {
	if replica == "" {
		replica = randID()
	}
	// A previous run of this replica may have crashed without deleting its
	// rows; they would age out of listings anyway, but purging now means a
	// restart never shows ghosts even briefly.
	purgeCtx, cancel := context.WithTimeout(ctx, busOpTimeout)
	if err := st.DeleteReplicaLiveSessions(purgeCtx, replica); err != nil {
		slog.Warn("live inventory: purging previous rows failed; stale rows will age out", "replica", replica, "err", err)
	}
	cancel()

	inFrames, inInterest, err := st.SubscribeLive(ctx)
	if err != nil {
		return nil, err
	}
	c := &Cluster{
		st:            st,
		reg:           reg,
		hub:           hub,
		replica:       replica,
		heartbeat:     inventoryHeartbeat,
		maxAge:        inventoryMaxAge,
		announceEvery: interestEvery,
		ttl:           interestTTL,
		interest:      make(map[string]time.Time),
		removed:       make(map[string]time.Time),
		watched:       make(map[string]int),
		frames:        make(chan LiveFrame, forwardQueueSize),
	}
	reg.attachCluster(c)
	hub.setRelay(c)
	go c.runPublisher(ctx)
	go c.runBridge(ctx, inFrames)
	go c.runInterest(ctx, inInterest)
	go c.runAnnouncer(ctx)
	go c.runHeartbeat(ctx)
	return c, nil
}

// List returns the cluster-wide live sessions, oldest first: the store
// inventory (fresh rows only) overlaid with this replica's own registry, which
// wins on conflict and covers any local session whose inventory write has not
// landed yet. The error surfaces a store failure — the caller reports it
// rather than presenting a silently partial listing as the whole cluster.
func (c *Cluster) List(ctx context.Context) ([]Info, error) {
	rows, err := c.st.ListLiveSessions(ctx, c.maxAge)
	if err != nil {
		return nil, err
	}
	merged := make(map[string]Info, len(rows))
	for _, in := range rows {
		merged[in.ID] = in
	}
	for _, in := range c.reg.List() {
		in.Replica = c.replica
		merged[in.ID] = in
	}
	out := make([]Info, 0, len(merged))
	for _, in := range merged {
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Started.Equal(out[j].Started) {
			return out[i].Started.Before(out[j].Started)
		}
		return out[i].ID < out[j].ID // stable order for equal start times
	})
	return out, nil
}

// WatchRemote begins a remote watch of session id: it verifies the id against
// the fresh cluster inventory (false means unknown or already ended — the
// caller refuses the watch) and announces interest so the hosting replica
// starts forwarding. Callers subscribe to the local Hub FIRST, then call this,
// and pair it with UnwatchRemote. The error reports a store failure, which is
// neither "live" nor "not live" — the caller should say so rather than 404.
func (c *Cluster) WatchRemote(ctx context.Context, id string) (bool, error) {
	rows, err := c.st.ListLiveSessions(ctx, c.maxAge)
	if err != nil {
		return false, err
	}
	known := false
	for _, in := range rows {
		if in.ID == id {
			known = true
			break
		}
	}
	if !known {
		return false, nil
	}
	c.wmu.Lock()
	c.watched[id]++
	c.wmu.Unlock()
	// Announce immediately so forwarding starts now, not at the next tick; a
	// failure is retried by the announcer, so it is logged, not fatal.
	actx, cancel := context.WithTimeout(ctx, busOpTimeout)
	defer cancel()
	if err := c.st.PublishLiveInterest(actx, id); err != nil {
		slog.Warn("live watch: interest announcement failed; retrying on the next tick", "session", id, "err", err)
	}
	return true, nil
}

// UnwatchRemote ends one remote watch begun by WatchRemote. When the last
// watcher of an id leaves, the announcements stop and the hosting replica's
// interest expires by silence within interestTTL.
func (c *Cluster) UnwatchRemote(id string) {
	c.wmu.Lock()
	if n := c.watched[id] - 1; n > 0 {
		c.watched[id] = n
	} else {
		delete(c.watched, id)
	}
	c.wmu.Unlock()
}

// --- hosting side: the Hub's relay ---

// wants reports whether any replica currently holds a live watcher for session
// id (an unexpired interest announcement). The Hub calls it under its own
// mutex on every Publish, so it must stay a cheap leaf: one map lookup.
func (c *Cluster) wants(id string) bool {
	now := time.Now()
	c.imu.Lock()
	exp, ok := c.interest[id]
	c.imu.Unlock()
	return ok && now.Before(exp)
}

// forward enqueues an output chunk for the bus publisher. It never blocks the
// session's I/O path: a full queue drops the frame (counted, reported by the
// announcer tick), mirroring how a slow local watcher drops frames.
func (c *Cluster) forward(id string, b []byte) {
	select {
	case c.frames <- LiveFrame{ID: id, Kind: LiveFrameData, Data: b}:
	default:
		c.dropped.Add(1)
	}
}

// --- registry hooks: inventory upkeep + the end marker ---

// sessionRegistered upserts the new session into the shared inventory so every
// replica's listing shows it. Called by Registry.Register; an error is logged,
// not returned — the inventory is advisory and the heartbeat re-upserts, so a
// transient store failure heals itself.
func (c *Cluster) sessionRegistered(info Info) {
	info.Replica = c.replica
	ctx, cancel := context.WithTimeout(context.Background(), busOpTimeout)
	defer cancel()
	if err := c.st.PutLiveSession(ctx, info); err != nil {
		slog.Warn("live inventory: session upsert failed; the heartbeat will retry", "session", info.ID, "err", err)
	}
}

// sessionRemoved deletes the session's inventory row and publishes the end
// marker, so remote listings drop it and remote watch streams close. Called by
// Registry.Remove on every session-end path (completion, kill, cross-replica
// kill). Uses a background context: teardown must still reach the store when
// the server context is already winding down, bounded by busOpTimeout.
func (c *Cluster) sessionRemoved(id string) {
	// Tombstone first: from here on the heartbeat must not re-upsert this id, even
	// if it snapshotted the registry a moment ago.
	c.rmu.Lock()
	c.removed[id] = time.Now()
	c.rmu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), busOpTimeout)
	defer cancel()
	if err := c.st.DeleteLiveSession(ctx, id); err != nil {
		slog.Warn("live inventory: session delete failed; the row will age out", "session", id, "err", err)
	}
	// The end marker goes through the SAME queue as the data frames, not straight
	// to the bus. Publishing it directly raced the queue: an exec-shaped run
	// (broker ssh_exec, REST WinRM) publishes its whole output and then releases
	// the session microseconds later, so the end could reach the bus first and a
	// remote watcher would see the command echo, then stream-end, and never the
	// output — the same "ran silently" failure the local path was fixed for.
	// A short wait rather than a drop: this frame closes watchers' panes, and the
	// only thing that makes the queue full is a bus that is already failing.
	select {
	case c.frames <- LiveFrame{ID: id, Kind: LiveFrameEnd}:
	case <-time.After(endMarkerEnqueueWait):
		slog.Warn("live relay: end marker could not be queued; remote watchers will close on staleness",
			"session", id)
	}
}

// --- background loops ---

// runPublisher drains the forward queue onto the bus. One outage warning per
// streak, not one per frame — a dead bus during a busy session would otherwise
// flood the log.
func (c *Cluster) runPublisher(ctx context.Context) {
	warned := false
	for {
		select {
		case <-ctx.Done():
			return
		case f := <-c.frames:
			pctx, cancel := context.WithTimeout(ctx, busOpTimeout)
			err := c.st.PublishLiveFrame(pctx, f)
			cancel()
			if err != nil {
				if !warned && ctx.Err() == nil {
					slog.Warn("live relay: frame publish failed; remote watchers are missing output", "err", err)
					warned = true
				}
			} else {
				warned = false
			}
		}
	}
}

// runBridge injects inbound bus frames into the LOCAL hub, which is what makes
// the SSE handler identical for local and remote sessions. Frames for a
// session in the local registry are this replica's own forwards echoed back
// (the bus delivers to everyone, publisher included) and are dropped — for a
// data frame a re-inject would duplicate every chunk a local supervisor sees,
// and the inject path uses the hub's local-only publish so a watching replica
// with its own inbound interest can never re-forward what it received.
func (c *Cluster) runBridge(ctx context.Context, in <-chan LiveFrame) {
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-in:
			if !ok {
				return
			}
			if c.reg.Exists(f.ID) {
				continue // our own forward, echoed back by the bus
			}
			switch f.Kind {
			case LiveFrameEnd:
				c.hub.EndSession(f.ID)
			case LiveFrameData:
				c.hub.publishLocal(f.ID, f.Data)
			}
		}
	}
}

// runInterest records inbound interest announcements with their expiry. Its
// own announcements come back too (self-delivery); the entry is harmless — a
// watching replica never publishes frames for a session it does not host, and
// its bridge injects via the local-only path, which skips the relay gate.
func (c *Cluster) runInterest(ctx context.Context, in <-chan string) {
	for {
		select {
		case <-ctx.Done():
			return
		case id, ok := <-in:
			if !ok {
				return
			}
			c.imu.Lock()
			c.interest[id] = time.Now().Add(c.ttl)
			c.imu.Unlock()
		}
	}
}

// runAnnouncer is the watching side's periodic loop: re-announce interest for
// every remote watch so the hosting replica keeps forwarding, and end the
// local streams of any watched session that has left the fresh inventory —
// the backstop that closes a remote watch when the hosting replica crashed
// and no end marker will ever arrive. It also prunes expired inbound interest
// and reports dropped frames, so those maps and counters cannot grow silently.
func (c *Cluster) runAnnouncer(ctx context.Context) {
	tick := time.NewTicker(c.announceEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		c.wmu.Lock()
		ids := make([]string, 0, len(c.watched))
		for id := range c.watched {
			ids = append(ids, id)
		}
		c.wmu.Unlock()
		if len(ids) > 0 {
			actx, cancel := context.WithTimeout(ctx, busOpTimeout)
			live := make(map[string]bool)
			rows, err := c.st.ListLiveSessions(actx, c.maxAge)
			for _, in := range rows {
				live[in.ID] = true
			}
			for _, id := range ids {
				if err == nil && !live[id] {
					// Gone from the inventory: ended while the end marker was
					// lost, or its replica crashed. Close the local streams so
					// watchers see the end rather than eternal silence.
					c.hub.EndSession(id)
					continue
				}
				if perr := c.st.PublishLiveInterest(actx, id); perr != nil {
					slog.Warn("live watch: interest re-announcement failed", "session", id, "err", perr)
					break // one failure means the bus is down; do not warn per id
				}
			}
			cancel()
		}
		now := time.Now()
		c.imu.Lock()
		for id, exp := range c.interest {
			if now.After(exp) {
				delete(c.interest, id)
			}
		}
		c.imu.Unlock()
		// Tombstones only need to outlive an in-flight heartbeat pass; keeping them
		// for twice the freshness window is generous and bounds the map.
		c.rmu.Lock()
		for id, at := range c.removed {
			if now.Sub(at) > 2*c.maxAge {
				delete(c.removed, id)
			}
		}
		c.rmu.Unlock()
		if n := c.dropped.Swap(0); n > 0 {
			slog.Warn("live relay: forward queue overflowed; remote watchers missed output frames", "dropped", n)
		}
	}
}

// wasRemoved reports whether a session has been torn down recently enough that
// the heartbeat must not re-upsert its inventory row.
func (c *Cluster) wasRemoved(id string) bool {
	c.rmu.Lock()
	_, ok := c.removed[id]
	c.rmu.Unlock()
	return ok
}

// runHeartbeat re-upserts this replica's live sessions so their inventory rows
// stay fresh — and so a row missed by a failed Register-time upsert appears at
// the next beat. When the replica crashes instead, the beats stop and its rows
// age out of every listing within inventoryMaxAge.
func (c *Cluster) runHeartbeat(ctx context.Context) {
	tick := time.NewTicker(c.heartbeat)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		c.heartbeatOnce(ctx)
	}
}

// heartbeatOnce refreshes this replica's inventory rows once. Split out from the
// loop so a test can drive exactly one pass and pin the resurrection bug the
// tombstone set exists to prevent.
func (c *Cluster) heartbeatOnce(ctx context.Context) {
	hctx, cancel := context.WithTimeout(ctx, busOpTimeout)
	defer cancel()
	for _, info := range c.reg.List() {
		if c.wasRemoved(info.ID) {
			continue // ended between the snapshot and now; do not resurrect it
		}
		info.Replica = c.replica
		if err := c.st.PutLiveSession(hctx, info); err != nil {
			if ctx.Err() == nil {
				slog.Warn("live inventory: heartbeat upsert failed", "err", err)
			}
			return // one failure means the store is down; retry next beat
		}
	}
}
