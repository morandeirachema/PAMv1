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
	if !s.stepup.Decide(id, in.Approve) {
		writeError(w, http.StatusNotFound, "no step-up is pending for this session")
		return
	}
	s.audit(r.Context(), "session.stepup_decided", fmt.Sprintf("session:%s approve:%t", id, in.Approve))
	writeJSON(w, http.StatusOK, map[string]any{"session": id, "approved": in.Approve})
}
