package session

// killbus.go makes the session kill-switch work across replicas. The live-session
// registry is per-replica (each pod holds the cancel funcs for the sessions IT
// hosts), so a kill issued to one pod cannot, by itself, terminate a session
// pinned to another. The KillBus closes that gap: a kill published on any replica
// is delivered to every replica's subscriber, which applies it to its own local
// registry. So the kill-switch (DELETE /api/sessions/{id}), the revoke cascade,
// vendor offboarding and analytics auto-response all terminate a session wherever
// it is hosted. Inventory listing (List) stays per-replica — a documented
// limitation; the security-critical action (termination) is cluster-wide.

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
	// KillDispatched: the session was not on this replica, but the kill was
	// broadcast to the cluster; whichever replica hosts it will terminate it.
	KillDispatched
)

// StartKillBus wires the registry to a cross-replica kill bus: outbound kills are
// broadcast, and a background subscriber applies inbound kills to the local
// registry. It returns an error only if the initial subscribe fails; the
// subscriber then runs until ctx is cancelled. Call once at startup.
func (r *Registry) StartKillBus(ctx context.Context, bus KillBus) error {
	ch, err := bus.SubscribeSessionKills(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.bus = bus
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
	switch {
	case sel.ID != "":
		r.killLocalByID(sel.ID)
	case sel.Actor != "" && sel.Target != "":
		r.killLocalByActorTarget(sel.Actor, sel.Target)
	case sel.Actor != "":
		r.killLocalByActor(sel.Actor)
	}
}

// publish broadcasts a kill selector to the cluster when a bus is configured. It
// is fire-and-forget with a short timeout: a broadcast failure must not block the
// caller (the local kill has already happened), only lose cross-replica reach.
func (r *Registry) publish(sel KillSelector) {
	r.mu.Lock()
	bus := r.bus
	r.mu.Unlock()
	if bus == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = bus.PublishSessionKill(ctx, sel)
}

// KillDistributed terminates a single session by id and reports the outcome:
// KillLocal if it was on this replica, KillDispatched if it was broadcast to the
// cluster (a bus is configured but the session is not local), or KillNotFound if
// there is no bus and the session is not here. It underpins DELETE
// /api/sessions/{id} in an HA deployment.
func (r *Registry) KillDistributed(id string) KillOutcome {
	local := r.killLocalByID(id)
	r.mu.Lock()
	hasBus := r.bus != nil
	r.mu.Unlock()
	r.publish(KillSelector{ID: id})
	switch {
	case local:
		return KillLocal
	case hasBus:
		return KillDispatched
	default:
		return KillNotFound
	}
}
