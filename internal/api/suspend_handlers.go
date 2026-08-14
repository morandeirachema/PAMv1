package api

import (
	"fmt"
	"net/http"
)

// --- suspend / resume a live session's input (Phase 122) ---
//
// Closes CyberArk's documented suspend/resume capability: freeze an
// operator's typing without ending their session, then explicitly release
// it — a rung below killing them outright. Wallix has no equivalent (its own
// session-restriction model only exposes kill/notify), so this is the one
// CyberArk-primary phase in an otherwise Wallix-weighted run.
//
// Built on Phase 116's session-sharing input mux (internal/session/share.go),
// which every interactive SSH session already opens unconditionally, whether
// or not sharing is ever used — so suspend/resume needs no new per-session
// plumbing, only two new gates on state that already exists.

// suspendSession freezes session id's operator input: the session stays
// open and output keeps flowing, only the operator's own keystrokes stop
// reaching the target. Gated the same as a step-up decision (CapApprove) —
// pausing someone's live input is the same class of authorization decision.
// Idempotent (suspending an already-suspended session succeeds), matching
// ShareRegistry.Suspend's own idempotency.
func (s *Server) suspendSession(w http.ResponseWriter, r *http.Request) {
	if s.shares == nil {
		writeError(w, http.StatusNotFound, "session sharing is not enabled")
		return
	}
	id := r.PathValue("id")
	if !s.shares.Suspend(id) {
		writeError(w, http.StatusNotFound, "session is not live on this replica (unknown, already ended, or hosted on another replica)")
		return
	}
	actor := actorFrom(r.Context())
	s.shares.Notify(id, fmt.Sprintf(
		"\r\n*** your input has been SUSPENDED by %s — output keeps flowing, but keystrokes will not reach the target until resumed ***\r\n",
		actor))
	s.audit(r.Context(), "session.suspended", "session:"+auditField(id, 64))
	writeJSON(w, http.StatusOK, map[string]any{"session": id, "suspended": true})
}

// sessionSuspendStatus reports whether session id is currently suspended
// (Phase 122) — replica-local, like every ShareRegistry query: a session
// hosted on another replica (or already ended) 404s, the same "not live on
// this replica" honesty streamSession already gives a watcher, rather than a
// bare `false` a poller could mistake for "confirmed not suspended."
func (s *Server) sessionSuspendStatus(w http.ResponseWriter, r *http.Request) {
	if s.shares == nil || s.sessions == nil {
		writeError(w, http.StatusNotFound, "session sharing is not enabled")
		return
	}
	id := r.PathValue("id")
	if !s.sessions.Exists(id) {
		writeError(w, http.StatusNotFound, "session is not live on this replica (unknown, already ended, or hosted on another replica)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": id, "suspended": s.shares.Suspended(id)})
}

// resumeSession un-freezes session id's operator input, releasing a prior
// suspendSession. Idempotent, same as suspend.
func (s *Server) resumeSession(w http.ResponseWriter, r *http.Request) {
	if s.shares == nil {
		writeError(w, http.StatusNotFound, "session sharing is not enabled")
		return
	}
	id := r.PathValue("id")
	if !s.shares.Resume(id) {
		writeError(w, http.StatusNotFound, "session is not live on this replica (unknown, already ended, or hosted on another replica)")
		return
	}
	actor := actorFrom(r.Context())
	s.shares.Notify(id, fmt.Sprintf("\r\n*** your input has been RESUMED by %s ***\r\n", actor))
	s.audit(r.Context(), "session.resumed", "session:"+auditField(id, 64))
	writeJSON(w, http.StatusOK, map[string]any{"session": id, "suspended": false})
}
