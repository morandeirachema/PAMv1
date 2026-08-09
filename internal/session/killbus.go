package session

// killbus.go makes the session kill-switch work across replicas. The live-session
// registry is per-replica (each pod holds the cancel funcs for the sessions IT
// hosts), so a kill issued to one pod cannot, by itself, terminate a session
// pinned to another. The KillBus closes that gap: a kill published on any replica
// is delivered to every replica's subscriber, which applies it to its own local
// registry. So the kill-switch (DELETE /api/sessions/{id}), the revoke cascade,
// vendor offboarding and analytics auto-response all terminate a session wherever
// it is hosted. Listing and live watching crossed replicas later, in Phase 55
// (livebus.go); Registry.List itself remains the local-only view.

import (
	"context"
	"time"
)

// KillSelector identifies which live sessions a cross-replica kill targets: a
// single session ID, all of an Actor's sessions, or an Actor's sessions to one
// Target. It is JSON-encoded onto the bus.
type KillSelector struct {
	ID     string `json:"id,omitempty"`
	Actor  string `json:"actor,omitempty"`
	Target string `json:"target,omitempty"`
	// Seal authenticates the selector under the cluster's shared-custody bus key
	// (livecrypto.go). Without it, anything able to `NOTIFY pam_session_kill` —
	// which on PostgreSQL is anything holding a database session, since
	// notification channels have no privilege model — could terminate live
	// privileged sessions at will, and the only trace was the abrupt end. It is
	// base64 of a sealed timestamp bound to the selector's fields as AAD, so it
	// can be neither forged nor replayed beyond a short window.
	Seal string `json:"seal,omitempty"`
}

// KillBus is the cross-replica transport for session kills, implemented by the
// store (Postgres LISTEN/NOTIFY in pgstore; an in-process fan-out hub in the
// memory store). Publish delivers a selector to every subscriber in the cluster,
// including the publisher's own — that self-delivery is harmless because applying
// a kill locally never re-publishes.
type KillBus interface {
	PublishSessionKill(ctx context.Context, sel KillSelector) error
	SubscribeSessionKills(ctx context.Context) (<-chan KillSelector, error)
}

// KillOutcome reports how a distributed single-session kill resolved.
type KillOutcome int

const (
	// KillNotFound: no bus is configured and the session was not on this replica —
	// it does not exist (single-replica deployment).
	KillNotFound KillOutcome = iota
	// KillLocal: the session was found and terminated on this replica.
	KillLocal
	// KillDispatchFailed: the session was not on this replica and the broadcast
	// to the cluster FAILED, so nothing was killed anywhere. Distinguished from
	// KillDispatched because an operator cutting off a live privileged session
	// must not be told it worked when it did not — "accepted" would leave them
	// believing the session was gone while it kept running on another replica.
	KillDispatchFailed
	// KillDispatched: the session was not on this replica, but the kill was
	// broadcast to the cluster; whichever replica hosts it will terminate it.
	KillDispatched
)

// KillBusConfig is what StartKillBus needs. BusKey is mandatory — it is the same
// shared-custody key that seals the live-monitoring relay — and Audit is optional.
type KillBusConfig struct {
	BusKey []byte
	Audit  func(ctx context.Context, action, detail string)
}

// StartKillBus wires the registry to a cross-replica kill bus: outbound kills are
// broadcast, and a background subscriber applies inbound kills to the local
// registry. It returns an error only if the initial subscribe fails; the
// subscriber then runs until ctx is cancelled. Call once at startup.
func (r *Registry) StartKillBus(ctx context.Context, bus KillBus, cfg KillBusConfig) error {
	// Fail closed, like the live relay: an unsealed kill bus is a remote
	// session-termination primitive with no authentication in front of it.
	sealer, serr := newLiveSealer(cfg.BusKey)
	if serr != nil {
		return serr
	}
	ch, err := bus.SubscribeSessionKills(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.bus = bus
	r.sealer = sealer
	r.killAudit = cfg.Audit
	r.mu.Unlock()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case sel, ok := <-ch:
				if !ok {
					return
				}
				r.applyKill(sel)
			}
		}
	}()
	return nil
}

// applyKill terminates the sessions a bus selector targets, on THIS replica only
// (the local variants never re-publish, so an inbound kill cannot loop).
func (r *Registry) applyKill(sel KillSelector) {
	// Verify before acting. An inbound kill is an unauthenticated instruction to
	// terminate privileged sessions until proven otherwise.
	r.mu.Lock()
	sealer := r.sealer
	audit := r.killAudit
	r.mu.Unlock()
	if sealer == nil {
		return
	}
	if err := sealer.openKill(sel, time.Now()); err != nil {
		r.log.Warn("REJECTED an unauthenticated cross-replica session kill",
			"selector_id", sel.ID, "selector_actor", sel.Actor, "selector_target", sel.Target)
		return
	}
	// Audit the arrival, not just the API-side issue. The kill-switch, revoke
	// cascade, vendor offboard and analytics auto-response all publish here, and
	// before this the applying replica recorded nothing — so a session terminated
	// by the bus left no trace in the trail but its own abrupt end.
	if audit != nil {
		actx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		detail := "via:bus"
		if sel.ID != "" {
			detail += " session:" + sel.ID
		}
		if sel.Actor != "" {
			detail += " actor:" + sel.Actor
		}
		if sel.Target != "" {
			detail += " target:" + sel.Target
		}
		audit(actx, "session.kill", detail)
		cancel()
	}
	switch {
	case sel.ID != "":
		r.killLocalByID(sel.ID)
	case sel.Actor != "" && sel.Target != "":
		r.killLocalByActorTarget(sel.Actor, sel.Target)
	case sel.Actor != "":
		r.killLocalByActor(sel.Actor)
	}
}

// publish broadcasts a kill selector to the cluster when a bus is configured,
// reporting whether a bus exists and whether the broadcast succeeded.
//
// It stays bounded by a short timeout — a slow bus must not block the caller,
// whose local kill has already happened — but the error is no longer discarded.
// A caller that cannot distinguish "broadcast" from "broadcast failed" can only
// report success, and for a kill that is the wrong default: an operator cutting
// off a live privileged session would be told it worked while it kept running on
// another replica.
func (r *Registry) publish(sel KillSelector) (hasBus, published bool) {
	r.mu.Lock()
	bus := r.bus
	sealer := r.sealer
	r.mu.Unlock()
	if bus == nil {
		return false, false
	}
	if sealer == nil {
		r.log.Error("session kill not broadcast: the kill bus has no key")
		return true, false
	}
	sealed, serr := sealer.sealKill(sel, time.Now())
	if serr != nil {
		r.log.Error("session kill not broadcast: sealing the selector failed", "err", serr)
		return true, false
	}
	sel = sealed
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := bus.PublishSessionKill(ctx, sel); err != nil {
		// The bulk-kill paths (by actor, by actor+target) do not return an outcome
		// to a caller, so a log line is all they can offer — but a silent failure
		// here means a revoked operator keeps a live session on another replica,
		// which is worth an operator noticing.
		r.log.Error("session kill broadcast failed; other replicas were not told",
			"selector_id", sel.ID, "selector_actor", sel.Actor, "selector_target", sel.Target, "err", err)
		return true, false
	}
	return true, true
}

// KillDistributed terminates a single session by id and reports the outcome:
// KillLocal if it was on this replica, KillDispatched if it was broadcast to the
// cluster (a bus is configured but the session is not local), or KillNotFound if
// there is no bus and the session is not here. It underpins DELETE
// /api/sessions/{id} in an HA deployment.
func (r *Registry) KillDistributed(id string) KillOutcome {
	local := r.killLocalByID(id)
	hasBus, published := r.publish(KillSelector{ID: id})
	switch {
	case local:
		// Killed here. A failed broadcast cannot un-kill it, and the session is
		// registered on exactly one replica, so this is the honest answer.
		return KillLocal
	case hasBus && published:
		return KillDispatched
	case hasBus:
		return KillDispatchFailed
	default:
		return KillNotFound
	}
}
