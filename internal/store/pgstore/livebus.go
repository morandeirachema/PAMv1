package pgstore

// livebus.go implements cross-replica live monitoring (Phase 55) over
// Postgres: LISTEN/NOTIFY carries the live-output frames and the
// watch-interest announcements (two channels multiplexed onto ONE dedicated
// listener connection — the kill bus keeps its own), and the UNLOGGED
// live_sessions table holds the shared inventory behind cluster-wide session
// listing. The frame payload rides NOTIFY's ~8000-byte text limit, so a large
// output chunk is split into several smaller frames — the session package
// treats a frame as raw terminal bytes, so the split is invisible to watchers.

import (
	"context"
	"encoding/json"
	"time"

	"github.com/morandeirachema/pamv1/internal/session"
)

const (
	// liveFrameChannel and liveInterestChannel are the NOTIFY channels for
	// output frames (JSON LiveFrame, data base64-encoded) and watch-interest
	// announcements (the bare session id).
	liveFrameChannel    = "pam_live_frame"
	liveInterestChannel = "pam_live_interest"
	// liveFrameChunk caps the raw bytes per published frame. Base64 grows data
	// 4/3× and the JSON envelope adds a few dozen bytes; 4096 raw bytes keeps
	// the payload comfortably under the ~8000-byte NOTIFY limit.
	liveFrameChunk = 4096
)

// PublishLiveFrame emits the frame as one or more NOTIFYs, splitting an
// oversized data chunk to respect the payload limit. Chunks are published
// sequentially, so listeners receive them in order.
func (s *PGStore) PublishLiveFrame(ctx context.Context, f session.LiveFrame) error {
	for {
		part := f
		if len(f.Data) > liveFrameChunk {
			part.Data = f.Data[:liveFrameChunk]
			f.Data = f.Data[liveFrameChunk:]
		} else {
			f.Data = nil
		}
		payload, err := json.Marshal(part)
		if err != nil {
			return err
		}
		if _, err := s.pool.Exec(ctx, `SELECT pg_notify($1, $2)`, liveFrameChannel, string(payload)); err != nil {
			return err
		}
		if len(f.Data) == 0 {
			return nil
		}
	}
}

// PublishLiveInterest emits a watch-interest NOTIFY carrying the session id.
func (s *PGStore) PublishLiveInterest(ctx context.Context, sessionID string) error {
	_, err := s.pool.Exec(ctx, `SELECT pg_notify($1, $2)`, liveInterestChannel, sessionID)
	return err
}

// SubscribeLive returns the inbound frame and interest streams, backed by one
// dedicated listener connection LISTENing on both channels and reconnecting
// after a transient failure, until ctx is cancelled (which closes both).
func (s *PGStore) SubscribeLive(ctx context.Context) (<-chan session.LiveFrame, <-chan string, error) {
	frames := make(chan session.LiveFrame, 256)
	interest := make(chan string, 16)
	go func() {
		defer close(frames)
		defer close(interest)
		for ctx.Err() == nil {
			if err := s.listenLive(ctx, frames, interest); err != nil && ctx.Err() == nil {
				// Lost the listener connection: back off briefly, then re-LISTEN.
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Second):
				}
			}
		}
	}()
	return frames, interest, nil
}

// listenLive hijacks one connection out of the pool (so a LISTEN-polluted
// connection is never returned to it), LISTENs on both live channels, and
// dispatches notifications by channel until ctx is cancelled or the
// connection errors — returning the error so SubscribeLive can reconnect.
func (s *PGStore) listenLive(ctx context.Context, frames chan<- session.LiveFrame, interest chan<- string) error {
	pooled, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	conn := pooled.Hijack() // own it outright; do not return it to the pool
	defer conn.Close(context.Background())

	if _, err := conn.Exec(ctx, "LISTEN "+liveFrameChannel); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, "LISTEN "+liveInterestChannel); err != nil {
		return err
	}
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		switch n.Channel {
		case liveFrameChannel:
			var f session.LiveFrame
			if json.Unmarshal([]byte(n.Payload), &f) != nil {
				continue // ignore a malformed payload rather than tear down the listener
			}
			select {
			case frames <- f:
			default: // a saturated bridge drops the frame, like every live path
			}
		case liveInterestChannel:
			select {
			case interest <- n.Payload:
			default:
			}
		}
	}
}

// PutLiveSession upserts one shared-inventory row, stamping seen_at with the
// DATABASE clock — freshness is always judged by the clock that wrote the
// stamp, so replica clock skew never expires a live session's row.
func (s *PGStore) PutLiveSession(ctx context.Context, info session.Info) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO live_sessions (id, actor, target, protocol, remote, replica, started, seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		ON CONFLICT (id) DO UPDATE SET
			actor = EXCLUDED.actor, target = EXCLUDED.target,
			protocol = EXCLUDED.protocol, remote = EXCLUDED.remote,
			replica = EXCLUDED.replica, started = EXCLUDED.started,
			seen_at = now()`,
		info.ID, info.Actor, info.Target, info.Protocol, info.Remote, info.Replica, info.Started)
	return err
}

// DeleteLiveSession removes a session's inventory row at session end; an
// absent row is a no-op, so teardown paths stay idempotent.
func (s *PGStore) DeleteLiveSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM live_sessions WHERE id = $1`, id)
	return err
}

// DeleteReplicaLiveSessions removes every row a replica owns; a restarting
// replica calls it so a previous crash leaves no ghost rows.
func (s *PGStore) DeleteReplicaLiveSessions(ctx context.Context, replica string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM live_sessions WHERE replica = $1`, replica)
	return err
}

// ListLiveSessions returns the rows seen within maxAge, oldest started first
// (id as tiebreaker, matching memstore). The freshness comparison happens
// entirely in SQL against now(), the same clock PutLiveSession stamped.
func (s *PGStore) ListLiveSessions(ctx context.Context, maxAge time.Duration) ([]session.Info, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, actor, target, protocol, remote, replica, started
		FROM live_sessions
		WHERE seen_at > now() - make_interval(secs => $1)
		ORDER BY started, id`,
		maxAge.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []session.Info
	for rows.Next() {
		var in session.Info
		if err := rows.Scan(&in.ID, &in.Actor, &in.Target, &in.Protocol, &in.Remote, &in.Replica, &in.Started); err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}
