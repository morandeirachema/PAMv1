package pgstore

// stepupbus.go implements cross-replica step-up decisions (Phase 56) over
// Postgres: the UNLOGGED stepups table holds the shared pending-pause
// inventory behind cluster-wide GET /api/sessions/stepups, and LISTEN/NOTIFY
// carries sealed decisions to the replica whose memory holds the pause — its
// own dedicated, reconnecting listener connection, in the kill bus's mold.
// Statements arrive already sealed by the session layer; this store treats
// them as opaque strings.

import (
	"context"
	"encoding/json"
	"time"

	"github.com/morandeirachema/pamv1/internal/session"
)

// stepUpDecisionChannel is the Postgres NOTIFY channel carrying JSON
// session.StepUpDecision payloads.
const stepUpDecisionChannel = "pam_stepup_decision"

// PutStepUp upserts one pending-pause row, expiring ttl from now BY THE
// DATABASE CLOCK — the same clock ListStepUps filters against, so replica
// clock skew never expires a live pause (the single-clock rule of
// session.StepUpStore). It also sweeps rows expired more than an hour ago:
// they are already invisible to listings, but a crashed replica's leftovers
// would otherwise accumulate forever in the table.
func (s *PGStore) PutStepUp(ctx context.Context, p session.PendingStepUp, ttl time.Duration) error {
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM stepups WHERE expires_at < now() - interval '1 hour'`); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO stepups (id, actor, statement, replica, requested, expires_at)
		VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))
		ON CONFLICT (id) DO UPDATE SET
			actor = EXCLUDED.actor, statement = EXCLUDED.statement,
			replica = EXCLUDED.replica, requested = EXCLUDED.requested,
			expires_at = EXCLUDED.expires_at`,
		p.SessionID, p.Actor, p.Statement, p.Replica, p.Requested, ttl.Seconds())
	return err
}

// DeleteStepUp removes a pause's row at the claim; an absent row is a no-op,
// so the decision and timeout claim paths stay idempotent.
func (s *PGStore) DeleteStepUp(ctx context.Context, sessionID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM stepups WHERE id = $1`, sessionID)
	return err
}

// ListStepUps returns the unexpired rows, oldest requested first (id as
// tiebreaker, matching memstore). The expiry comparison happens entirely in
// SQL against now(), the same clock PutStepUp stamped.
func (s *PGStore) ListStepUps(ctx context.Context) ([]session.PendingStepUp, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, actor, statement, replica, requested, expires_at
		FROM stepups
		WHERE expires_at > now()
		ORDER BY requested, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []session.PendingStepUp
	for rows.Next() {
		var p session.PendingStepUp
		if err := rows.Scan(&p.SessionID, &p.Actor, &p.Statement, &p.Replica, &p.Requested, &p.Expires); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PublishStepUpDecision emits a NOTIFY with the JSON-encoded decision so the
// replica holding the pause applies it.
func (s *PGStore) PublishStepUpDecision(ctx context.Context, d session.StepUpDecision) error {
	payload, err := json.Marshal(d)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `SELECT pg_notify($1, $2)`, stepUpDecisionChannel, string(payload))
	return err
}

// SubscribeStepUpDecisions returns a channel of decisions published by any
// replica. It runs a dedicated LISTEN connection, reconnecting after a
// transient failure, until ctx is cancelled (which closes the channel).
func (s *PGStore) SubscribeStepUpDecisions(ctx context.Context) (<-chan session.StepUpDecision, error) {
	out := make(chan session.StepUpDecision, 16)
	go func() {
		defer close(out)
		for ctx.Err() == nil {
			if err := s.listenStepUpDecisions(ctx, out); err != nil && ctx.Err() == nil {
				// Log it: this error is the only evidence the decision bus is dead
				// (discarding it would make main's replica-local fallback unreachable,
				// the kill-bus lesson).
				s.log.Warn("cross-replica step-up decision listener failed; retrying", "err", err)
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Second):
				}
			}
		}
	}()
	return out, nil
}

// listenStepUpDecisions hijacks one connection out of the pool (so a
// LISTEN-polluted connection is never returned to it), LISTENs on the decision
// channel, and forwards decoded decisions until ctx is cancelled or the
// connection errors — returning the error so SubscribeStepUpDecisions can
// reconnect.
func (s *PGStore) listenStepUpDecisions(ctx context.Context, out chan<- session.StepUpDecision) error {
	pooled, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	conn := pooled.Hijack() // own it outright; do not return it to the pool
	defer conn.Close(context.Background())

	if _, err := conn.Exec(ctx, "LISTEN "+stepUpDecisionChannel); err != nil {
		return err
	}
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var d session.StepUpDecision
		if json.Unmarshal([]byte(n.Payload), &d) != nil {
			continue // ignore a malformed payload rather than tear down the listener
		}
		select {
		case out <- d:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
