package api

import (
	"fmt"
	"net/http"
)

// listStepUps returns the sessions currently paused awaiting an in-session
// step-up decision (Phase 30), so a supervisor can see what needs approval.
// Requires CapReadAudit.
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
		writeError(w, http.StatusNotFound, "no step-up is pending for this session")
		return
	}
	s.audit(r.Context(), "session.stepup_decided", fmt.Sprintf("session:%s approve:%t", id, in.Approve))
	writeJSON(w, http.StatusOK, map[string]any{"session": id, "approved": in.Approve})
}
