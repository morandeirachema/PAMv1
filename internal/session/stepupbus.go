package session

// stepupbus.go makes in-session step-up decisions work across replicas
// (Phase 56), closing the deferral Phase 55 recorded: a paused statement blocks
// in the memory of the replica hosting its session, so the pending list and the
// decision endpoint were the last session views still replica-local — a remote
// supervisor could WATCH the pause arrive over the live relay but had to decide
// it on the hosting replica.
//
// The shape is the kill bus's, with the live bus's inventory alongside:
//
//   - Inventory: every Await mirrors its pause into a shared, TTL-bounded store
//     row (deleted at the claim, expired by the store's own clock otherwise), so
//     PendingCluster lists every replica's pauses. The statement travels and
//     rests SEALED under the cluster bus key: the transport and the table have
//     no privilege model, so a database observer sees ciphertext, and a
//     fabricated row fails to open and is never shown to a supervisor.
//   - Decisions: a replica that does not hold the pause seals
//     {session, pause, approve, decider} with a freshness-bound timestamp and
//     publishes it; every replica receives it (self-delivery included, as on the
//     kill bus) and the ONE holding that pending entry applies it through the
//     same claim point, with the same self-approval refusal, while the rest
//     ignore it. The publisher can never hold the entry (the API decides locally
//     first), so an echo is never applied twice. The decision names the PAUSE
//     and not merely the session, because a session pauses once per flagged
//     statement: without that, a decision captured off the bus — which anything
//     holding a database session can do — released the operator's next flagged
//     statement for as long as its timestamp stayed fresh.
//
// What deliberately does NOT change: the pause itself. The blocked statement
// stays in the hosting replica's memory; the bus only carries visibility and
// the decision. The deciding replica's API records the fail-closed
// session.stepup_decided audit BEFORE publishing (who decided, durably), so the
// applying side audits after the fact, best-effort, marking via:bus.

import (
	"context"
	"log/slog"
	"sort"
	"time"
)

// StepUpDecision is a supervisor's verdict on another replica's paused
// statement, JSON-encoded onto the bus.
type StepUpDecision struct {
	SessionID string `json:"session_id"`
	Approve   bool   `json:"approve"`
	Decider   string `json:"decider"`
	// Pause names WHICH pause of that session this decision releases (PauseID of
	// the pending entry's request time). A session id is not enough: `pending` is
	// keyed by session id and a session pauses once per flagged statement, so the
	// applying replica needs to be told which one — otherwise a decision released
	// whatever happened to be pending when it arrived.
	//
	// That is the difference between a stale message and a bypass. A sealed
	// decision is readable to anything holding a database session (NOTIFY has no
	// privilege model, which is why it is sealed rather than trusted), and its
	// timestamp stays fresh for interestSkew. Replaying one inside that window
	// used to release the operator's NEXT flagged statement with no supervisor in
	// the loop — and audit it under the name of the supervisor who decided the
	// previous one. Bound to a pause, a replay finds the pause it names already
	// gone and is refused.
	Pause int64 `json:"pause,omitempty"`
	// Seal authenticates the decision under the cluster's shared-custody bus key
	// (livecrypto.go). Without it, anything able to NOTIFY the decision channel —
	// on PostgreSQL, anything holding a database session — could release a
	// statement a supervisor paused. It is base64 of a sealed timestamp bound to
	// the other fields as AAD, so it can be neither forged, re-pointed at another
	// session, verdict or pause, nor replayed beyond a short window.
	Seal string `json:"seal,omitempty"`
}

// StepUpStore is what the store must provide for cross-replica step-up
// decisions: the shared pending inventory and the decision bus. Both store
// implementations satisfy it (pgstore over an UNLOGGED table + LISTEN/NOTIFY;
// memstore in-process, so tests and the demo drive the same code the HA path
// does). Rows carry the statement SEALED (see PendingStepUp) — the store treats
// it as an opaque string.
type StepUpStore interface {
	// PutStepUp upserts one pending-pause row, expiring ttl from now BY THE
	// STORE'S OWN CLOCK (the single-clock rule of LiveStore: the clock that
	// stamps a row is the clock that judges it, so replica skew never expires a
	// live pause). The row's Expires field is ignored on write and populated
	// from that same clock on List.
	PutStepUp(ctx context.Context, p PendingStepUp, ttl time.Duration) error
	// DeleteStepUp removes a pause's row at the claim (decision or timeout).
	// Deleting an absent row is a no-op — claim paths must be idempotent.
	DeleteStepUp(ctx context.Context, sessionID string) error
	// ListStepUps returns the unexpired rows, oldest requested first (session id
	// as tiebreaker). Rows a crashed replica left behind fall out at expiry —
	// exactly when the pause they mirrored would have timed out.
	ListStepUps(ctx context.Context) ([]PendingStepUp, error)
	// PublishStepUpDecision delivers a decision to every replica's subscriber,
	// including the publisher's own (self-delivery is harmless: the publisher
	// never holds the pending entry). SubscribeStepUpDecisions returns the
	// inbound stream; the channel closes when ctx is cancelled.
	PublishStepUpDecision(ctx context.Context, d StepUpDecision) error
	SubscribeStepUpDecisions(ctx context.Context) (<-chan StepUpDecision, error)
}

// RemoteDecision reports how DecideRemote resolved.
type RemoteDecision int

const (
	// StepUpNoBus: no bus is attached — the coordinator is replica-local and
	// cannot say anything about other replicas.
	StepUpNoBus RemoteDecision = iota
	// StepUpNotFound: no replica has this pause mirrored in the shared
	// inventory — nothing is pending anywhere in the cluster.
	StepUpNotFound
	// StepUpSelfApproval: the inventory row names the decider as the paused
	// session's own operator; refused without dispatching. Advisory — the
	// hosting replica's DecideBy re-checks under its claim lock either way.
	StepUpSelfApproval
	// StepUpDispatched: the sealed decision was published; the hosting replica
	// will apply it. Verify via the pending list, as with a dispatched kill.
	StepUpDispatched
)

// StepUpBusConfig is what StartBus needs. BusKey is mandatory — the same
// shared-custody key that seals the kill and live buses — and Audit is optional
// (it records the bus-side application of a decision).
type StepUpBusConfig struct {
	BusKey  []byte
	Replica string
	Audit   func(ctx context.Context, action, detail string)
}

// StartBus attaches the cross-replica machinery to the coordinator: pauses are
// mirrored into the shared inventory from here on, and a background subscriber
// applies inbound sealed decisions to this replica's pending entries. It returns
// an error only if the key is unusable or the initial subscribe fails — the
// caller logs it and step-up decisions stay replica-local, exactly like the
// kill bus. Call once at startup, before the proxies serve sessions.
func (s *StepUp) StartBus(ctx context.Context, st StepUpStore, cfg StepUpBusConfig) error {
	// Fail closed: an unsealed decision bus is a remote statement-release
	// primitive with no authentication in front of it.
	sealer, err := newLiveSealer(cfg.BusKey)
	if err != nil {
		return err
	}
	ch, err := st.SubscribeStepUpDecisions(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.st = st
	s.sealer = sealer
	s.replica = cfg.Replica
	s.audit = cfg.Audit
	s.mu.Unlock()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case d, ok := <-ch:
				if !ok {
					return
				}
				s.applyDecision(d)
			}
		}
	}()
	return nil
}

// bus returns the attached store and sealer (nil, nil before StartBus).
func (s *StepUp) bus() (StepUpStore, *liveSealer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st, s.sealer
}

// putRow mirrors a freshly registered pause into the shared inventory,
// statement sealed. Best-effort and bounded: the pause works without the row.
func (s *StepUp) putRow(p *pendingStepUp, ttl time.Duration) {
	st, sealer := s.bus()
	if st == nil {
		return
	}
	s.mu.Lock()
	replica := s.replica
	s.mu.Unlock()
	sealed, err := sealer.sealStepUpStatement(p.sessionID, p.actor, replica, p.statement)
	if err != nil {
		slog.Warn("step-up inventory: sealing the statement failed; the pause stays replica-local", "session", p.sessionID, "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), busOpTimeout)
	defer cancel()
	row := PendingStepUp{SessionID: p.sessionID, Actor: p.actor, Statement: sealed,
		Requested: p.requested, Replica: replica}
	if err := st.PutStepUp(ctx, row, ttl); err != nil {
		slog.Warn("step-up inventory: row upsert failed; remote supervisors will not see this pause", "session", p.sessionID, "err", err)
	}
}

// deleteRow removes a pause's shared-inventory row at the claim. Best-effort:
// a leaked row expires on its own TTL. Background context on purpose — claims
// happen on session teardown paths whose contexts may already be cancelled.
func (s *StepUp) deleteRow(sessionID string) {
	st, _ := s.bus()
	if st == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), busOpTimeout)
	defer cancel()
	if err := st.DeleteStepUp(ctx, sessionID); err != nil {
		slog.Warn("step-up inventory: row delete failed; it will expire on its TTL", "session", sessionID, "err", err)
	}
}

// PendingCluster lists every replica's paused statements: the shared inventory
// (statements opened under the bus key; a row that does not open is not vouched
// for and is skipped) overlaid with this replica's own pending map, which wins
// on conflict — it is the memory actually holding the pause. Without a bus it
// is exactly Pending. The error surfaces a store failure so the caller can
// refuse to present a silently partial list as the whole cluster.
func (s *StepUp) PendingCluster(ctx context.Context) ([]PendingStepUp, error) {
	if s == nil {
		return nil, nil
	}
	st, sealer := s.bus()
	local := s.Pending()
	if st == nil {
		return local, nil
	}
	rows, err := st.ListStepUps(ctx)
	if err != nil {
		return nil, err
	}
	merged := make(map[string]PendingStepUp, len(rows))
	rejected := 0
	for _, r := range rows {
		stmt, oerr := sealer.openStepUpStatement(r.SessionID, r.Actor, r.Replica, r.Statement)
		if oerr != nil {
			rejected++
			continue
		}
		r.Statement = stmt
		merged[r.SessionID] = r
	}
	if rejected > 0 {
		// Benign causes exist (a replica still sealing under an old key mid-swap),
		// but so does the one the seal was added for: fabricated rows luring a
		// supervisor into an approval.
		slog.Warn("step-up inventory: REJECTED rows that did not authenticate under the bus key", "rows", rejected)
	}
	for _, p := range local {
		merged[p.SessionID] = p
	}
	out := make([]PendingStepUp, 0, len(merged))
	for _, p := range merged {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Requested.Equal(out[j].Requested) {
			return out[i].Requested.Before(out[j].Requested)
		}
		return out[i].SessionID < out[j].SessionID // stable order for equal times
	})
	return out, nil
}

// DecideRemote resolves a paused statement this replica does NOT hold: it looks
// the pause up in the shared inventory and, if some replica mirrors it there,
// publishes the sealed decision for that replica to apply. Callers try DecideBy
// first — DecideRemote is the not-local path. The self-approval pre-check here
// is a courtesy answer for the decider; the authoritative check runs under the
// hosting replica's claim lock regardless (an inventory row is advisory data).
// The error reports a store or publish failure — the caller must not present
// either as "nothing is pending" or "decided".
func (s *StepUp) DecideRemote(ctx context.Context, sessionID string, approve bool, decider string) (RemoteDecision, error) {
	if s == nil {
		return StepUpNoBus, nil
	}
	st, sealer := s.bus()
	if st == nil {
		return StepUpNoBus, nil
	}
	rows, err := st.ListStepUps(ctx)
	if err != nil {
		return StepUpNotFound, err
	}
	for _, r := range rows {
		if r.SessionID != sessionID {
			continue
		}
		// A row our key does not vouch for is not a pending step-up.
		if _, oerr := sealer.openStepUpStatement(r.SessionID, r.Actor, r.Replica, r.Statement); oerr != nil {
			break
		}
		if decider != "" && r.Actor == decider {
			return StepUpSelfApproval, nil
		}
		// Name the pause, not just the session: the row we just read IS the pause
		// this supervisor is deciding, and binding it into the sealed decision is
		// what keeps the message from applying to a later one.
		d, serr := sealer.sealStepUpDecision(StepUpDecision{SessionID: sessionID, Approve: approve,
			Decider: decider, Pause: PauseID(r.Requested)}, time.Now())
		if serr != nil {
			return StepUpNotFound, serr
		}
		pctx, cancel := context.WithTimeout(ctx, busOpTimeout)
		defer cancel()
		if perr := st.PublishStepUpDecision(pctx, d); perr != nil {
			// Like a failed kill broadcast: the one wrong answer is "dispatched".
			return StepUpNotFound, perr
		}
		return StepUpDispatched, nil
	}
	return StepUpNotFound, nil
}

// applyDecision applies one inbound bus decision to THIS replica's pending
// entries. Verify before acting — an inbound decision is an unauthenticated
// instruction to release a paused statement until proven otherwise — then claim
// under the lock exactly as a local decision does, with one addition: the claim
// is BOUND to the pause the decision names. Decisions for pauses this replica
// does not hold (another replica's, an echo of our own publish, or one that
// raced its timeout) are ignored; some replica held it when the row was read,
// and if that was us the claim resolves it.
//
// A decision that authenticates but names a pause this replica has already
// resolved is a stale or REPLAYED message — the case the pause binding exists
// for. It is logged, not audited: the payload is readable to anything holding a
// database session, so appending a row per arrival would let a flood of replays
// amplify into the audit trail the retention worker refuses to prune with the
// chain on (the lesson of the unauthenticated-input finding). The refusal itself
// is the control; the log line is the evidence.
//
// The audit here is AFTER the apply and best-effort, unlike the API path's
// fail-closed audit-before-release — because the deciding replica already wrote
// that record (who decided, durably, before publishing). This one adds where it
// was applied, marked via:bus, in the kill bus's arrival-audit mold.
func (s *StepUp) applyDecision(d StepUpDecision) {
	_, sealer := s.bus()
	if sealer == nil {
		return
	}
	if err := sealer.openStepUpDecision(d, time.Now()); err != nil {
		slog.Warn("REJECTED an unauthenticated cross-replica step-up decision",
			"session", d.SessionID, "decider", d.Decider)
		return
	}
	outcome := s.claim(d.SessionID, d.Pause, d.Approve, d.Decider)
	if outcome == stepUpClaimStale {
		slog.Warn("REFUSED a cross-replica step-up decision naming a pause this replica has already resolved; "+
			"the session is paused again, so this is a stale or replayed message and a supervisor must decide the current pause",
			"session", d.SessionID, "decider", d.Decider, "pause", d.Pause)
		return
	}
	ok, selfApproval := outcome == stepUpClaimOK, outcome == stepUpClaimSelf
	s.mu.Lock()
	audit := s.audit
	s.mu.Unlock()
	if audit == nil || (!ok && !selfApproval) {
		return
	}
	actx, cancel := context.WithTimeout(context.Background(), busOpTimeout)
	defer cancel()
	if selfApproval {
		audit(actx, "session.self_stepup_denied", "session:"+d.SessionID+" decider:"+d.Decider+" via:bus")
		return
	}
	verdict := "approve:false"
	if d.Approve {
		verdict = "approve:true"
	}
	audit(actx, "session.stepup_decided", "session:"+d.SessionID+" "+verdict+" decider:"+d.Decider+" via:bus")
}
