package api

import (
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
	ok, selfApproval := s.stepup.DecideBy(id, in.Approve, actorFrom(r.Context()))
	if selfApproval {
		s.audit(r.Context(), "session.self_stepup_denied", "session:"+id)
		writeError(w, http.StatusForbidden, "you cannot decide the step-up for your own session")
		return
	}
	if ok {
		writeJSON(w, http.StatusOK, map[string]any{"session": id, "approved": in.Approve})
		return
	}
	// Not paused here. Phase 56: consult the shared inventory and, if another
	// replica holds the pause, dispatch the sealed decision to it.
	outcome, derr := s.stepup.DecideRemote(r.Context(), id, in.Approve, actorFrom(r.Context()))
	if derr != nil {
		// A store or publish failure is neither "nothing is pending" nor
		// "decided" — say so instead of picking one.
		writeError(w, http.StatusServiceUnavailable,
			"could not reach the cluster's step-up inventory; the decision was NOT applied — retry, or decide on the replica hosting the session")
		return
	}
	switch outcome {
	case session.StepUpDispatched:
		writeJSON(w, http.StatusAccepted, map[string]any{"session": id, "approved": in.Approve, "dispatched": true})
		return
	case session.StepUpSelfApproval:
		s.audit(r.Context(), "session.self_stepup_denied", "session:"+id)
		writeError(w, http.StatusForbidden, "you cannot decide the step-up for your own session")
		return
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
