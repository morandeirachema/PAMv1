package pgstore

// killbus.go implements the cross-replica session kill bus over Postgres
// LISTEN/NOTIFY. A kill published on any replica (pg_notify) is delivered to
// every replica LISTENing on the channel, which terminates the session it hosts.
// This makes the kill-switch, revoke cascade and analytics auto-response work in
// an HA deployment where the target session may be pinned to a different pod.

import (
	"context"
	"encoding/json"
	"time"

	"github.com/morandeirachema/pamv1/internal/session"
)

// sessionKillChannel is the Postgres NOTIFY channel carrying JSON kill selectors.
const sessionKillChannel = "pam_session_kill"

// PublishSessionKill emits a NOTIFY with the JSON-encoded selector so every
// replica LISTENing on the channel applies the kill locally.
func (s *PGStore) PublishSessionKill(ctx context.Context, sel session.KillSelector) error {
	payload, err := json.Marshal(sel)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `SELECT pg_notify($1, $2)`, sessionKillChannel, string(payload))
	return err
}

// SubscribeSessionKills returns a channel of kill selectors published by any
// replica. It runs a dedicated LISTEN connection, reconnecting after a transient
// failure, until ctx is cancelled (which closes the channel).
func (s *PGStore) SubscribeSessionKills(ctx context.Context) (<-chan session.KillSelector, error) {
	out := make(chan session.KillSelector, 64)
	go func() {
		defer close(out)
		for ctx.Err() == nil {
			if err := s.listenKills(ctx, out); err != nil && ctx.Err() == nil {
				// Log it: this error was the only evidence the kill bus is dead, and
				// discarding it made the startup fallback in main unreachable.
				s.log.Warn("cross-replica kill bus listener failed; retrying", "err", err)
				// Lost the listener connection: back off briefly, then re-LISTEN.
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Second):
				}
			}
		}
	}()
	return out, nil
}

// listenKills hijacks one connection out of the pool (so a LISTEN-polluted
// connection is never returned to it), LISTENs on the kill channel, and forwards
// decoded selectors until ctx is cancelled or the connection errors — returning
// the error so SubscribeSessionKills can reconnect.
func (s *PGStore) listenKills(ctx context.Context, out chan<- session.KillSelector) error {
	pooled, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	conn := pooled.Hijack() // own it outright; do not return it to the pool
	defer conn.Close(context.Background())

	if _, err := conn.Exec(ctx, "LISTEN "+sessionKillChannel); err != nil {
		return err
	}
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var sel session.KillSelector
		if json.Unmarshal([]byte(n.Payload), &sel) != nil {
			continue // ignore a malformed payload rather than tear down the listener
		}
		select {
		case out <- sel:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
