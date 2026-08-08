package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/morandeirachema/pamv1/internal/session"
)

// listStepUps returns the sessions currently paused awaiting an in-session
// step-up decision (Phase 30), so a supervisor can see what needs approval.
// Requires CapReadAudit.
//
// CLUSTER-WIDE since Phase 56: every replica mirrors its pauses into a shared,
// TTL-bounded inventory (statements sealed under the cluster bus key), so this
// lists them all — the row's replica field names where each pause is held. A
// store failure is a 500, not a silently partial list presented as the whole
// cluster, the same honesty GET /api/sessions applies. Without the bus (no
// store attached), the list is this replica's own, as it was before.
func (s *Server) listStepUps(w http.ResponseWriter, r *http.Request) {
	if s.stepup == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	pending, err := s.stepup.PendingCluster(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing the cluster's pending step-ups failed")
		return
	}
	if pending == nil {
		pending = []session.PendingStepUp{}
	}
	writeJSON(w, http.StatusOK, pending)
}

type stepUpDecisionIn struct {
	Approve bool `json:"approve"`
}

// decideStepUp resolves a session's paused step-up: approve lets the statement
// run, deny refuses it — the session stays open either way. The supervisor is the
// one watching the session (CapReadAudit, the live-monitor gate). 404 if no
// step-up is pending for the session.
//
// An operator may not decide their own session's step-up. The whole point of the
// pause is to put a second person in the loop before a sensitive statement runs;
// self-approval would turn it into a confirmation prompt while leaving an audit
// entry that reads like independent review. Every other decision point in pamv1
// already refuses this, so the refusal is audited here in the same shape
// (`*.self_*_denied`) rather than silently 403ing.
//
// Since Phase 56 a pause held by ANOTHER replica is decidable from here: the
// sealed decision is published on the store bus and the hosting replica applies
// it through the same claim point. That path answers 202 — dispatched, not
// proven applied — in the kill-switch's mold; the (now cluster-wide) pending
// list is the verification.
// voidStepUpDecision annotates the trail when a session.stepup_decided written
// moments earlier did NOT take effect — the remote dispatch failed, or the local
// claim lost a race. It is the compensating half of auditing the decision BEFORE
// its side effect: that ordering is right (a released statement must never
// outlive the evidence of who released it), but it means a decision that then
// fails to apply leaves a positive record. Without this a four-eyes "decided"
// could stand for a release that never happened, in a chained trail the retention
// worker will not prune.
//
// Best-effort: the primary record already exists and the failure is logged, so a
// failed compensation is a warning, not a refusal — there is nothing to fail
// closed against, the sensitive side effect did not occur.
func (s *Server) voidStepUpDecision(ctx context.Context, id string, approve bool, reason string) {
	detail := fmt.Sprintf("session:%s approve:%t reason:%s", auditField(id, 64), approve, reason)
	if err := s.auditAs(ctx, actorFrom(ctx), "session.stepup_decision_voided", detail); err != nil {
		s.log.Warn("a step-up decision could not be voided; the trail shows a decided record that did not apply",
			"session", id, "reason", reason, "err", err)
	}
}

func (s *Server) decideStepUp(w http.ResponseWriter, r *http.Request) {
	if s.stepup == nil {
		writeError(w, http.StatusNotFound, "in-session step-up is not enabled")
		return
	}
	var in stepUpDecisionIn
	if !readJSON(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	decider := actorFrom(r.Context())

	// FIRST establish that a decision will actually be attempted, and that this
	// decider may make it. Both checks are read-only and claim nothing.
	//
	// The audit below is fail-closed and says a step-up WAS decided, which is the
	// four-eyes evidence an investigator reads back. Writing it before knowing the
	// outcome meant every ordinary refusal left a record asserting the opposite of
	// what happened: a refused self-approval recorded the paused operator as
	// having decided their own statement — exactly what the refusal exists to
	// prevent — and a decision for a session paused on no replica recorded a
	// release that could never have occurred, which any approver could spray into
	// the chained trail the retention worker will not prune.
	//
	// The look is advisory: a pause can time out between it and the claim, so
	// DecideBy still enforces self-approval under the lock and both refusals are
	// still handled below. What this removes is the systematic case, not the race.
	//
	// `id` is quoted and bounded everywhere it reaches a detail, including here.
	// It comes from the request path, so it is client-supplied text; today only a
	// value matching a real pending session id can reach these branches, which
	// makes it safe by circumstance rather than by construction. Circumstance is
	// what changes when someone adds a branch.
	pausedActor, heldHere := s.stepup.Holder(id)
	if heldHere && decider != "" && pausedActor == decider {
		s.audit(r.Context(), "session.self_stepup_denied", "session:"+auditField(id, 64))
		writeError(w, http.StatusForbidden, "you cannot decide the step-up for your own session")
		return
	}
	var remotePause int64
	if !heldHere {
		outcome, pause, lerr := s.stepup.LookupRemote(r.Context(), id, decider)
		if lerr != nil {
			// A store failure is neither "nothing is pending" nor "decided" — say
			// so instead of picking one.
			writeError(w, http.StatusServiceUnavailable,
				"could not reach the cluster's step-up inventory; the decision was NOT applied — retry, or decide on the replica hosting the session")
			return
		}
		switch outcome {
		case session.StepUpFound:
			remotePause = pause
		case session.StepUpSelfApproval:
			s.audit(r.Context(), "session.self_stepup_denied", "session:"+auditField(id, 64))
			writeError(w, http.StatusForbidden, "you cannot decide the step-up for your own session")
			return
		default:
			s.stepUpNotPending(w, r, id, outcome)
			return
		}
	}

	// Audit BEFORE applying. DecideBy releases the paused statement, so auditing
	// afterwards meant a failed append left the statement running on the production
	// database with the four-eyes evidence — WHO released it — gone, while the
	// proxy's own db.stepup_approved (attributed to the session's actor, not the
	// decider) still read like an approved review. The broker chains its
	// requested-event before every side effect for the same reason. The same
	// record covers the dispatched case: it is written before the bus publish.
	if !s.mustAudit(w, r.Context(), "session.stepup_decided",
		fmt.Sprintf("session:%s approve:%t", auditField(id, 64), in.Approve)) {
		return
	}

	if !heldHere {
		// Phase 56: another replica holds the pause — dispatch the sealed decision
		// to it, bound to the pause LookupRemote found (Phase 62).
		if derr := s.stepup.DispatchRemote(r.Context(), id, remotePause, in.Approve, decider); derr != nil {
			// The decided-record above was written before this publish, on purpose
			// (evidence must precede the side effect). The publish failed, so no
			// decision took effect — void the record so the trail nets out, or an
			// investigator reads a four-eyes release that never happened.
			s.voidStepUpDecision(r.Context(), id, in.Approve, "dispatch-failed")
			writeError(w, http.StatusServiceUnavailable,
				"could not publish the decision to the replica hosting the session; it was NOT applied — retry, or decide on that replica")
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"session": id, "approved": in.Approve, "dispatched": true})
		return
	}

	ok, selfApproval := s.stepup.DecideBy(id, in.Approve, decider)
	if selfApproval {
		// The advisory Holder check above passed but the authoritative claim under
		// the lock found this decider IS the pauser (a race the pre-check cannot
		// close). The decided-record is now false — void it before recording the
		// refusal.
		s.voidStepUpDecision(r.Context(), id, in.Approve, "self-approval-race")
		s.audit(r.Context(), "session.self_stepup_denied", "session:"+auditField(id, 64))
		writeError(w, http.StatusForbidden, "you cannot decide the step-up for your own session")
		return
	}
	if ok {
		writeJSON(w, http.StatusOK, map[string]any{"session": id, "approved": in.Approve})
		return
	}
	// Held a moment ago and gone now: it timed out, or another supervisor got
	// there first. The decided-record was written on the assumption it was still
	// held, so void it — nothing was released here.
	s.voidStepUpDecision(r.Context(), id, in.Approve, "already-resolved")
	writeError(w, http.StatusConflict,
		"the step-up was resolved (timed out, or decided by someone else) before this decision could be applied")
}

// stepUpNotPending answers a decision for a session no replica has paused. It is
// its own function because the honest answer depends on whether a bus is
// attached at all.
func (s *Server) stepUpNotPending(w http.ResponseWriter, r *http.Request, id string, outcome session.RemoteDecision) {
	switch outcome {
	case session.StepUpNoBus:
		// Replica-local coordinator (no bus): be replica-honest, as before Phase 56.
		// A paused statement blocks in the memory of the replica hosting the
		// session, so "no step-up is pending" is false when one is pending
		// elsewhere — and Phase 55 made that the visible case: a supervisor can
		// watch the pause arrive over the relay from another replica.
		if s.cluster != nil && s.sessions != nil && !s.sessions.Exists(id) {
			if known, kerr := s.cluster.Exists(r.Context(), id); kerr == nil && known {
				writeError(w, http.StatusConflict,
					"this session is hosted on another replica: a paused step-up is decided on the replica running the session")
				return
			}
		}
	}
	// With the bus attached this is now a cluster-wide truth: no replica mirrors
	// a pause for this session.
	writeError(w, http.StatusNotFound, "no step-up is pending for this session")
}
