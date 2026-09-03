package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// listSessions returns the live sessions, so a supervisor can see who is
// connected to what and kill or watch a session. With the cluster inventory
// wired (Phase 55) the listing is CLUSTER-WIDE — the shared store rows merged
// with this replica's own registry, each row naming its hosting replica; a
// store failure is a 500, not a silently partial list presented as the whole
// cluster. Without it (single replica, or the bus failed at startup), the
// listing is this replica's registry, the pre-HA behavior. Requires
// CapReadAudit.
func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	if s.cluster != nil {
		infos, err := s.cluster.List(r.Context())
		if err != nil {
			storeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, infos)
		return
	}
	writeJSON(w, http.StatusOK, s.sessions.List())
}

// streamSession streams a live session's output to a supervisor as Server-Sent
// Events (Phase 16 live monitoring). Each output frame is one `data:` event; the
// stream ends when the client disconnects or the session ends. With the cluster
// relay wired (Phase 55) a session hosted on ANOTHER replica streams too: the
// relay announces watch interest, the hosting replica forwards its output over
// the store bus, and the bridge feeds this replica's hub — so the loop below is
// identical either way. Requires CapReadAudit and audits the start of
// monitoring (`via:relay` marks a cross-replica watch).
func (s *Server) streamSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.live == nil {
		writeError(w, http.StatusNotFound, "live monitoring is not enabled")
		return
	}
	frames, cancel := s.live.Subscribe(id)
	defer cancel()
	// Subscribe FIRST, then validate: if the session ends between the two,
	// EndSession closes the just-created subscription and the loop below exits —
	// checking first would leave that gap open. An id that is unknown (or
	// already over) is refused outright; before this, watching a dead session
	// subscribed the caller to eternal silence. With no registry wired the id
	// cannot be validated and any id streams (test-only shape). The same
	// ordering protects the remote path: the announcer's staleness pass ends
	// any watched id that has left the fresh inventory, so a session that dies
	// in the subscribe/validate window still closes this stream.
	detail := "session:" + id
	if s.sessions != nil && !s.sessions.Exists(id) {
		if s.cluster == nil {
			// No cluster relay (single replica, or the bus failed at startup):
			// the registry is replica-local, and the 404 body says so honestly —
			// an authoritative-sounding "no such session" would tell a
			// supervisor a running session had ended. The refusal is audited so
			// probing leaves a trace.
			s.audit(r.Context(), "session.monitor", "session:"+auditField(id, 64)+" refused:not-live-on-this-replica")
			writeError(w, http.StatusNotFound, "session is not live on this replica (unknown, already ended, or hosted on another replica)")
			return
		}
		ok, err := s.cluster.WatchRemote(r.Context(), id)
		if err != nil {
			// A store failure is neither "live" nor "not live"; a 404 here
			// would report a running session as over.
			storeError(w, err)
			return
		}
		if !ok {
			s.audit(r.Context(), "session.monitor", "session:"+auditField(id, 64)+" refused:not-live")
			writeError(w, http.StatusNotFound, "session is not live (unknown or already ended)")
			return
		}
		defer s.cluster.UnwatchRemote(id)
		detail += " via:relay"
	}
	rc, ok := s.beginStream(w)
	if !ok {
		return
	}

	s.audit(r.Context(), "session.monitor", detail)
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case b, open := <-frames:
			if !open {
				// The session ended (completed or killed): end the stream, so
				// the watcher's pane reports it instead of sitting silent on a
				// channel that will never speak again.
				return
			}
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
	// The id is attacker-chosen and percent-decoded out of the path, so it is
	// quoted and bounded before it can become part of an audit detail — it could
	// otherwise carry newlines or forged `key:value` pairs into a column the
	// retention worker refuses to prune when the HMAC chain is on.
	qid := auditField(id, 64)

	// Refuse an id that no replica is hosting. Without this the 404 branch below
	// was DEAD CODE — `main` wires the kill bus unconditionally, so KillDistributed
	// always found a bus and every unknown id came back 202 Accepted plus a
	// `session.kill … scope:cluster` audit row: the trail asserted kills that never
	// happened, for sessions that may never have existed. The cluster inventory is
	// the authority here; without it (no relay) we genuinely cannot tell, and
	// dispatching remains the honest answer.
	if s.cluster != nil && !s.sessions.Exists(id) {
		known, err := s.cluster.Exists(r.Context(), id)
		if err != nil {
			storeError(w, err)
			return
		}
		if !known {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
	}
	switch s.sessions.KillDistributed(id) {
	case session.KillLocal:
		s.audit(r.Context(), "session.kill", "session:"+qid)
		w.WriteHeader(http.StatusNoContent)
	case session.KillDispatched:
		s.audit(r.Context(), "session.kill", "session:"+qid+" scope:cluster")
		w.WriteHeader(http.StatusAccepted)
	case session.KillDispatchFailed:
		// The session is on another replica and the broadcast did not get there.
		// Say so: reporting 202 would tell an operator the privileged session was
		// cut off while it kept running.
		s.audit(r.Context(), "session.kill_failed", "session:"+qid+" scope:cluster reason:broadcast-failed")
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

// pagedList builds a GET handler for a store list method that takes only the
// (limit, after) window — the plainest listing shape, with no filter parameters.
// It reads the window, calls list, maps a store error to its status, and writes
// the page as JSON. A free function, not a method, because Go does not allow type
// parameters on methods. Handlers whose store method takes a filter (a target id,
// a status, an active flag) keep their own bodies.
func pagedList[T any](s *Server, list func(context.Context, int, int64) ([]T, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, after := listWindow(r)
		items, err := list(r.Context(), limit, after)
		if err != nil {
			storeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, items)
	}
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
	case errors.Is(err, errIdentityLocked):
		writeError(w, http.StatusForbidden, "this identity is locked")
	default:
		// storeError is a package function (no *Server receiver), so it cannot
		// reach s.log; logging.Component is resolved here at call time — a request
		// path, long after logging.Setup — so it carries service=api and the
		// configured format, matching every other line the api package emits.
		logging.Component("api").Error("store error", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}
