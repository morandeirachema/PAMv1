// Package session tracks live brokered sessions so operators can see who is
// connected and terminate a session. The registry is shared between the SSH
// proxy (which registers sessions) and the API (which lists and kills them).
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/morandeirachema/pamv1/internal/logging"
)

// Info describes a live session (safe to serialize to auditors).
type Info struct {
	ID       string    `json:"id"`
	Actor    string    `json:"actor"`
	Target   string    `json:"target"`
	Protocol string    `json:"protocol"` // ssh | rdp | vnc | winrm | postgres | mssql | ssh_exec
	Remote   string    `json:"remote"`
	Started  time.Time `json:"started"`
	// Replica names the replica hosting the session. Stamped by the cluster
	// inventory (Phase 55); empty in a single-replica deployment.
	Replica string `json:"replica,omitempty"`
	// Deadline, when set, is the instant the session must end because the
	// authorization that admitted it ends then (Phase 240): a grant's expiry
	// or the close of its time-frame window. DeadlineReason names which
	// ("grant-expiry" | "time-frame"). The lifetime monitor enforces it; the
	// deployment-wide maximum duration is not stamped here, it is computed
	// from Started.
	Deadline       *time.Time `json:"deadline,omitempty"`
	DeadlineReason string     `json:"deadline_reason,omitempty"`
}

type entry struct {
	info Info
	kill func()
	// last is the Unix nanosecond of the most recent operator input (Phase
	// 240), touched by the proxies' input legs through Activity; the idle
	// timeout reads it. Register seeds it with Started.
	last *atomic.Int64
}

// Registry is a thread-safe set of live sessions.
type Registry struct {
	mu          sync.Mutex
	m           map[string]entry
	maxPerActor int         // 0 = unlimited
	maxTotal    int         // 0 = unlimited
	bus         KillBus     // cross-replica kill transport (nil = single-replica)
	hub         *Hub        // live-output hub to end when a session is removed (nil = none)
	cluster     *Cluster    // cross-replica inventory + live relay (nil = single-replica)
	sealer      *liveSealer // authenticates cross-replica kills (nil = bus disabled)
	killAudit   func(ctx context.Context, action, detail string)
	log         *slog.Logger // operational logger, tagged service=session
}

// NewRegistry returns an empty, ready-to-use session registry.
//
// The logger is resolved here rather than at package scope on purpose:
// logging.Component binds slog.Default(), which main replaces in logging.Setup
// after this package is loaded — a package-level logger would capture the
// pre-Setup default. Every NewRegistry call is at runtime, after Setup.
func NewRegistry() *Registry {
	return &Registry{m: make(map[string]entry), log: logging.Component("session")}
}

// SetLimits configures the concurrent-session caps: at most perActor live
// sessions for a single actor and maxTotal across all actors (0 = unlimited).
// Call once at startup before serving.
func (r *Registry) SetLimits(perActor, maxTotal int) {
	r.mu.Lock()
	r.maxPerActor, r.maxTotal = perActor, maxTotal
	r.mu.Unlock()
}

// AllowNew reports whether a new session for actor is within the concurrent-session
// caps. It is a pre-flight check the proxies run BEFORE decrypting/dialing, so a
// refused session never touches a secret; the tiny window before Register is
// acceptable for a resource limit. Note the registry is per-replica, so the cap
// is per-replica in an HA deployment.
func (r *Registry) AllowNew(actor string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maxTotal > 0 && len(r.m) >= r.maxTotal {
		return false
	}
	if r.maxPerActor > 0 {
		n := 0
		for _, e := range r.m {
			if e.info.Actor == actor {
				n++
			}
		}
		if n >= r.maxPerActor {
			return false
		}
	}
	return true
}

// Register records a session and returns its id; kill terminates it when called
// (e.g. closes the underlying connection). With a cluster attached, the session
// is also upserted into the shared inventory so every replica's listing shows
// it (best-effort; the heartbeat repairs a missed write).
func (r *Registry) Register(info Info, kill func()) string {
	id := randID()
	info.ID = id
	// Normalize the start time to UTC at the one choke point every session
	// enters through (the SSH/DB/MSSQL proxies, the RDP/VNC viewer and the
	// broker all call Register with a bare time.Now()). The Info is serialized
	// into the cross-replica inventory, so a mixed local/UTC zone would reach a
	// SIEM reading the listing; fixing it here covers every caller.
	info.Started = info.Started.UTC()
	if info.Deadline != nil {
		d := info.Deadline.UTC()
		info.Deadline = &d
	}
	last := &atomic.Int64{}
	last.Store(info.Started.UnixNano())
	r.mu.Lock()
	r.m[id] = entry{info: info, kill: kill, last: last}
	c := r.cluster
	r.mu.Unlock()
	if c != nil {
		c.sessionRegistered(info)
	}
	return id
}

// attachCluster links the cross-replica live-monitoring coordinator, so
// Register and Remove keep the shared inventory in step with this replica's
// sessions. Called once at wiring time by StartCluster.
func (r *Registry) attachCluster(c *Cluster) {
	r.mu.Lock()
	r.cluster = c
	r.mu.Unlock()
}

// AttachHub links the live-monitoring hub, so removing a session also ends its
// watch streams. Every session-end path — normal completion, a kill, a
// cross-replica kill landing on this host — funnels through Remove, which makes
// this the one place the "session is over" signal can reach a supervisor's
// otherwise-eternal SSE subscription. Call once at wiring time.
func (r *Registry) AttachHub(h *Hub) {
	r.mu.Lock()
	r.hub = h
	r.mu.Unlock()
}

// Exists reports whether a session id is currently registered. The live-stream
// endpoint uses it to refuse a watch on a session that is unknown or already
// over, instead of subscribing the caller to eternal silence.
func (r *Registry) Exists(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.m[id]
	return ok
}

// Remove drops a session (call when it ends) and, when a hub is attached,
// closes the session's live watch streams so supervisors see the end rather
// than an indefinitely silent pane. With a cluster attached it also deletes
// the session's shared-inventory row and publishes the cluster-wide end
// marker, so remote listings drop it and remote watch streams close too.
func (r *Registry) Remove(id string) {
	r.mu.Lock()
	delete(r.m, id)
	hub := r.hub
	c := r.cluster
	r.mu.Unlock()
	// Outside the registry lock: the hub has its own mutex, and holding both at
	// once would create an ordering to get wrong later.
	hub.EndSession(id)
	if c != nil {
		c.sessionRemoved(id)
	}
}

// List returns the live sessions, oldest first.
func (r *Registry) List() []Info {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Info, 0, len(r.m))
	for _, e := range r.m {
		out = append(out, e.info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out
}

// Kill terminates a session by id, returning whether it was found on this
// replica. It also broadcasts the kill to other replicas via the kill bus (if
// configured), so the session is terminated wherever it is hosted.
func (r *Registry) Kill(id string) bool {
	local := r.killLocalByID(id)
	r.publish(KillSelector{ID: id})
	return local
}

// killLocalByID terminates a session by id on THIS replica only (no broadcast),
// returning whether it was found. It is the target of an inbound bus kill.
func (r *Registry) killLocalByID(id string) bool {
	r.mu.Lock()
	e, ok := r.m[id]
	r.mu.Unlock()
	if !ok {
		return false
	}
	if e.kill != nil {
		e.kill()
	}
	return true
}

// KillByActor terminates every live session owned by actor and returns how many
// were killed on this replica; it also broadcasts to other replicas. It backs
// automated threat-analytics response (Phase 23): when an actor's risk score
// crosses critical, their active sessions can be cut off.
func (r *Registry) KillByActor(actor string) int {
	n := r.killLocalByActor(actor)
	r.publish(KillSelector{Actor: actor})
	return n
}

// killLocalByActor terminates actor's sessions on THIS replica only (no broadcast).
func (r *Registry) killLocalByActor(actor string) int {
	r.mu.Lock()
	var kills []func()
	for _, e := range r.m {
		if e.info.Actor == actor && e.kill != nil {
			kills = append(kills, e.kill)
		}
	}
	r.mu.Unlock()
	for _, k := range kills {
		k()
	}
	return len(kills)
}

// KillByActorTarget terminates every live session an actor holds to a specific
// target and returns how many were killed on this replica; it also broadcasts to
// other replicas. It backs kill-on-revoke: when a user's grant to one target is
// removed, their in-flight session to that target is cut, while their sessions to
// other still-authorized targets are left running.
func (r *Registry) KillByActorTarget(actor, target string) int {
	n := r.killLocalByActorTarget(actor, target)
	r.publish(KillSelector{Actor: actor, Target: target})
	return n
}

// killLocalByActorTarget terminates actor's sessions to target on THIS replica
// only (no broadcast).
func (r *Registry) killLocalByActorTarget(actor, target string) int {
	r.mu.Lock()
	var kills []func()
	for _, e := range r.m {
		if e.info.Actor == actor && e.info.Target == target && e.kill != nil {
			kills = append(kills, e.kill)
		}
	}
	r.mu.Unlock()
	for _, k := range kills {
		k()
	}
	return len(kills)
}

// randID returns a random 16-hex-character session id.
func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Activity returns a function the session's input leg calls on every read of
// operator input, feeding the idle timeout (Phase 240). It is resolved once
// per session so the hot path is a single atomic store, not a map lookup. An
// unknown or empty id (a proxy running without a registry) returns a no-op.
func (r *Registry) Activity(id string) func() {
	if r == nil || id == "" {
		return func() {}
	}
	r.mu.Lock()
	e, ok := r.m[id]
	r.mu.Unlock()
	if !ok || e.last == nil {
		return func() {}
	}
	last := e.last
	return func() { last.Store(time.Now().UnixNano()) }
}

// LifetimeConfig bounds every session hosted on this replica (Phase 240).
type LifetimeConfig struct {
	// MaxDuration ends a session this long after it started, whatever it is
	// doing (0 = unlimited). IdleTimeout ends a session that has seen no
	// operator input for this long (0 = never). Either is checked alongside
	// the per-session Deadline a grant's bounds may have stamped.
	MaxDuration time.Duration
	IdleTimeout time.Duration
	// Tick is how often the monitor looks (default 5s).
	Tick time.Duration
	// Audit records each enforced end as "session.killed" with the reason
	// (max-duration | idle-timeout | grant-expiry | time-frame); nil skips.
	Audit func(ctx context.Context, action, detail string)
}

// StartLifetimeMonitor runs the lifetime sweep until ctx ends. It is
// replica-local by construction: every session it can end is one this
// replica hosts, so no bus is involved. A monitor with nothing configured —
// no maximum, no idle timeout — still runs, because a per-session Deadline
// can be stamped by a grant regardless of deployment-wide limits.
func (r *Registry) StartLifetimeMonitor(ctx context.Context, cfg LifetimeConfig) {
	if cfg.Tick <= 0 {
		cfg.Tick = 5 * time.Second
	}
	go func() {
		t := time.NewTicker(cfg.Tick)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				r.SweepLifetimes(ctx, now, cfg)
			}
		}
	}()
}

// SweepLifetimes ends every local session past its deadline, its maximum
// duration or its idle timeout at now, auditing each, and returns how many
// it ended. Exported so a test can drive it with a chosen instant.
func (r *Registry) SweepLifetimes(ctx context.Context, now time.Time, cfg LifetimeConfig) int {
	type victim struct {
		e      entry
		reason string
	}
	r.mu.Lock()
	var victims []victim
	for _, e := range r.m {
		if e.kill == nil {
			continue
		}
		switch {
		case e.info.Deadline != nil && !now.Before(*e.info.Deadline):
			reason := e.info.DeadlineReason
			if reason == "" {
				reason = "deadline"
			}
			victims = append(victims, victim{e, reason})
		case cfg.MaxDuration > 0 && now.Sub(e.info.Started) >= cfg.MaxDuration:
			victims = append(victims, victim{e, "max-duration"})
		case cfg.IdleTimeout > 0 && e.last != nil && now.Sub(time.Unix(0, e.last.Load())) >= cfg.IdleTimeout:
			victims = append(victims, victim{e, "idle-timeout"})
		}
	}
	r.mu.Unlock()
	for _, v := range victims {
		r.log.Info("session lifetime reached", "session", v.e.info.ID, "actor", v.e.info.Actor, "target", v.e.info.Target, "reason", v.reason)
		if cfg.Audit != nil {
			cfg.Audit(ctx, "session.killed", fmt.Sprintf("session:%s actor:%s target:%s reason:%s", v.e.info.ID, v.e.info.Actor, v.e.info.Target, v.reason))
		}
		v.e.kill()
	}
	return len(victims)
}
