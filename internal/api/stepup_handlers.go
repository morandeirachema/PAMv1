package api

import (
	"fmt"
	"net/http"
)

// listStepUps returns the sessions currently paused awaiting an in-session
// step-up decision (Phase 30), so a supervisor can see what needs approval.
// Requires CapReadAudit.
//
// REPLICA-LOCAL, deliberately: a paused statement blocks in the memory of the
// replica hosting its session, so only that replica can list or release it. Since
// Phase 55 made session listing and live watching cluster-wide, this is the one
// session view that is still local — which is why decideStepUp answers 409 with an
// explanation rather than a misleading 404 for a session hosted elsewhere.
func (s *Server) listStepUps(w http.ResponseWriter, r *http.Request) {
	if s.stepup == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.stepup.Pending())
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
	ok, selfApproval := s.stepup.DecideBy(id, in.Approve, actorFrom(r.Context()))
	if selfApproval {
		s.audit(r.Context(), "session.self_stepup_denied", "session:"+id)
		writeError(w, http.StatusForbidden, "you cannot decide the step-up for your own session")
		return
	}
	if !ok {
		// Be replica-honest. A paused statement blocks in the memory of the replica
		// hosting the session, so "no step-up is pending" is false when one is
		// pending elsewhere — and Phase 55 made that the visible case: a supervisor
		// can now watch the pause arrive over the relay from another replica, so
		// this endpoint was contradicting what they could see on screen. The watch
		// endpoint was given exactly this treatment; its sibling was missed.
		if s.cluster != nil && s.sessions != nil && !s.sessions.Exists(id) {
			if known, kerr := s.cluster.Exists(r.Context(), id); kerr == nil && known {
				writeError(w, http.StatusConflict,
					"this session is hosted on another replica: a paused step-up is decided on the replica running the session")
				return
			}
		}
		writeError(w, http.StatusNotFound, "no step-up is pending for this session")
		return
	}
	s.audit(r.Context(), "session.stepup_decided", fmt.Sprintf("session:%s approve:%t", id, in.Approve))
	writeJSON(w, http.StatusOK, map[string]any{"session": id, "approved": in.Approve})
}
