package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// listSessions returns the sessions currently live on THIS replica, so a
// supervisor can see who is connected to what and kill a session. In an HA
// deployment each replica knows only its own; the kill path is what crosses
// replicas, via the kill bus. Requires CapReadAudit.
func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.sessions.List())
}

// streamSession streams a live session's output to a supervisor as Server-Sent
// Events (Phase 16 live monitoring). Each output frame is one `data:` event; the
// stream ends when the client disconnects or the session ends. Requires
// CapReadAudit and audits the start of monitoring.
func (s *Server) streamSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.live == nil {
		writeError(w, http.StatusNotFound, "live monitoring is not enabled")
		return
	}
	rc, ok := s.beginStream(w)
	if !ok {
		return
	}
	frames, cancel := s.live.Subscribe(id)
	defer cancel()

	s.audit(r.Context(), "session.monitor", "session:"+id)
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-frames:
			// SSE frames are newline-delimited; encode as one data: field per
			// output chunk (any embedded newlines are re-prefixed by the client).
			if _, err := fmt.Fprintf(w, "data: %s\n\n", sseEscape(b)); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}
}

// sseEscape renders an output frame safe for a single SSE data: line by
// replacing raw newlines (which would otherwise split the event) with a literal
// marker; the terminal content is otherwise passed through.
func sseEscape(b []byte) string {
	// BOTH line terminators must be escaped, not just LF. Server-Sent Events
	// treats CR, LF and CRLF alike as end-of-line, so a lone CR ends the `data:`
	// field just as an LF does — and the data being escaped here is deliberately
	// CRLF-bearing: the SSH proxy emits \r\n, and the DB proxy frames statements
	// as "psql> " + sql + "\r\n". Escaping LF alone left every one of those
	// carriage returns able to terminate the field early, so a supervisor's view
	// of a live session could be split into frames the session never produced.
	s := strings.ReplaceAll(string(b), "\r", "\\r")
	return strings.ReplaceAll(s, "\n", "\\n")
}

// killSession terminates a live session by id via the registry and audits it. In
// an HA deployment the session may be hosted on another replica: the kill is
// broadcast over the kill bus and the response is 202 Accepted (dispatched). A
// session found and killed on this replica is 204; an unknown id with no bus is
// 404.
func (s *Server) killSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.sessions == nil {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	switch s.sessions.KillDistributed(id) {
	case session.KillLocal:
		s.audit(r.Context(), "session.kill", "session:"+id)
		w.WriteHeader(http.StatusNoContent)
	case session.KillDispatched:
		s.audit(r.Context(), "session.kill", "session:"+id+" scope:cluster")
		w.WriteHeader(http.StatusAccepted)
	case session.KillDispatchFailed:
		// The session is on another replica and the broadcast did not get there.
		// Say so: reporting 202 would tell an operator the privileged session was
		// cut off while it kept running.
		s.audit(r.Context(), "session.kill_failed", "session:"+id+" scope:cluster reason:broadcast-failed")
		writeError(w, http.StatusServiceUnavailable, "the session is on another replica and the kill could not be broadcast; retry")
	default:
		writeError(w, http.StatusNotFound, "session not found")
	}
}

// --- audit ---

// listAudit returns recent audit events, capped by ?limit= (default 100).
// listWindow parses the shared ?limit=&after= cursor of the inventory list
// endpoints (Phase 44): limit defaults to 100 and is clamped to 1..500 — the
// same bound listAudit uses — so an authenticated client can never pull an
// unbounded result set; after is the last id of the previous page (rows with
// id > after are returned, ascending). Page until a short page comes back.
func listWindow(r *http.Request) (limit int, after int64) {
	limit = 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil {
			limit = n
		}
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if q := r.URL.Query().Get("after"); q != "" {
		if n, err := strconv.ParseInt(q, 10, 64); err == nil && n > 0 {
			after = n
		}
	}
	return limit, after
}

// maxAuditResponsePage bounds how many audit events one HTTP response may carry.
// Deliberately far below store.MaxAuditPage: an internal job like the retention
// archiver may legitimately read thousands of rows, an API client should page.
const maxAuditResponsePage = 500

// listAudit returns the most recent audit events, newest first, capped by
// ?limit= so an authenticated client cannot pull the whole trail in one request.
// Requires CapReadAudit.
//
// The clamp is applied here as well as in the store. That is not redundancy for
// its own sake: this bound is an API contract about response size, while the
// store's is about how much a caller may load into memory, and they are allowed
// to differ — the store permits far more for internal jobs such as retention
// archiving than any HTTP response should carry.
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit := store.DefaultAuditPage
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil {
			limit = n
		}
	}
	if limit <= 0 || limit > maxAuditResponsePage {
		limit = store.DefaultAuditPage
	}
	events, err := s.store.ListAudit(r.Context(), limit)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// verifyAudit recomputes the tamper-evident chain over the primary audit trail
// and reports whether it is intact. It returns 501 when chaining is not enabled
// (no PAM_AUDIT_HMAC_KEY). A broken chain reports ok=false with the offending id.
func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	ok, brokeAtID, err := s.store.VerifyAuditChain(r.Context())
	if err != nil {
		writeError(w, http.StatusNotImplemented, "audit chain is not enabled (set PAM_AUDIT_HMAC_KEY)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "broke_at_id": brokeAtID})
}

// auditHead returns an ed25519-signed checkpoint of the primary audit chain's
// current head. An auditor stores it out-of-band and later detects TAIL
// TRUNCATION (which the HMAC chain alone cannot catch) by re-verifying the signed
// (last_id, head) against the published public key. Returns 501 when checkpoint
// signing is not configured (no PAM_AUDIT_SIGN_SEED).
func (s *Server) auditHead(w http.ResponseWriter, r *http.Request) {
	if s.auditSignKey == nil {
		writeError(w, http.StatusNotImplemented, "audit checkpoints are not enabled (set PAM_AUDIT_HMAC_KEY and PAM_AUDIT_SIGN_SEED)")
		return
	}
	head, err := s.store.GetAuditHead(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	var lastID int64
	var h []byte
	if head != nil {
		lastID, h = head.ID, head.HMAC
	}
	writeJSON(w, http.StatusOK, auditchain.SignCheckpoint(s.auditSignKey, lastID, h, time.Now()))
}

// --- helpers ---

// writeJSON writes v as a JSON response body with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON {"error": msg} body with the given status code.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// readJSON decodes the request body (capped at 1 MiB) into v, writing a 400 and
// returning false on a decode failure.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// idParam parses the {id} path value as a positive int64, writing a 422 and
// returning false when it is missing or invalid.
func idParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	return idParamNamed(w, r, "id")
}

// idParamNamed parses a named path value as a positive int64 (for routes with a
// second id, e.g. {gid}).
func idParamNamed(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusUnprocessableEntity, "invalid id")
		return 0, false
	}
	return id, true
}

// storeError maps a store error to an HTTP response: ErrNotFound to 404,
// ErrConflict to 409, and anything else to 500 (logged).
func storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "already exists")
	default:
		slog.Error("store error", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}
