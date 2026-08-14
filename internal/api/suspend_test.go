package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/session"
)

// TestSuspendResumeSession proves the HTTP round trip end to end: suspending
// a live session freezes it (reflected both in the response and in the
// underlying ShareRegistry an operator's own connection reads from),
// resuming un-freezes it, and both are fail-visible in the audit trail
// (Phase 122).
func TestSuspendResumeSession(t *testing.T) {
	reg, hub, shares := shareTestRegs()
	srv, st := newTestServerOpts(t, nil, api.Options{Sessions: reg, Live: hub, Shares: shares})
	sid := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	shares.Open(sid)
	defer shares.Close(sid)
	approverTok := seedUser(t, srv, "dana-approver", "approver")

	code, data := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/suspend", approverTok, nil)
	if code != http.StatusOK {
		t.Fatalf("suspend: %d %s", code, data)
	}
	if got := jsonMap(t, data)["suspended"]; got != true {
		t.Fatalf("suspend response suspended = %v, want true", got)
	}
	if !shares.Suspended(sid) {
		t.Fatal("ShareRegistry does not report the session as suspended after the API call")
	}

	code, data = do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/resume", approverTok, nil)
	if code != http.StatusOK {
		t.Fatalf("resume: %d %s", code, data)
	}
	if got := jsonMap(t, data)["suspended"]; got != false {
		t.Fatalf("resume response suspended = %v, want false", got)
	}
	if shares.Suspended(sid) {
		t.Fatal("ShareRegistry still reports the session as suspended after resume")
	}

	events, err := st.ListAudit(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	var sawSuspended, sawResumed bool
	for _, e := range events {
		if e.Action == "session.suspended" && strings.Contains(e.Detail, sid) {
			sawSuspended = true
		}
		if e.Action == "session.resumed" && strings.Contains(e.Detail, sid) {
			sawResumed = true
		}
	}
	if !sawSuspended {
		t.Fatal("no session.suspended audit event")
	}
	if !sawResumed {
		t.Fatal("no session.resumed audit event")
	}
}

// TestSuspendStatus proves the GET status endpoint reflects the current
// suspend state and 404s for a session that isn't live on this replica —
// what the console polls to show/hide the right F-key.
func TestSuspendStatus(t *testing.T) {
	reg, hub, shares := shareTestRegs()
	srv, _ := newTestServerOpts(t, nil, api.Options{Sessions: reg, Live: hub, Shares: shares})
	sid := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	shares.Open(sid)
	defer shares.Close(sid)
	auditorTok := seedUser(t, srv, "eve-auditor", "auditor")

	code, data := do(t, srv, http.MethodGet, "/api/sessions/"+sid+"/suspend", auditorTok, nil)
	if code != http.StatusOK {
		t.Fatalf("status before suspend: %d %s", code, data)
	}
	if got := jsonMap(t, data)["suspended"]; got != false {
		t.Fatalf("status before suspend = %v, want false", got)
	}

	if !shares.Suspend(sid) {
		t.Fatal("Suspend reported false")
	}
	code, data = do(t, srv, http.MethodGet, "/api/sessions/"+sid+"/suspend", auditorTok, nil)
	if code != http.StatusOK {
		t.Fatalf("status after suspend: %d %s", code, data)
	}
	if got := jsonMap(t, data)["suspended"]; got != true {
		t.Fatalf("status after suspend = %v, want true", got)
	}

	if code, d := do(t, srv, http.MethodGet, "/api/sessions/no-such-session/suspend", auditorTok, nil); code != http.StatusNotFound {
		t.Fatalf("status(unknown session): %d %s, want 404", code, d)
	}
}

// TestSuspendResumeIdempotent proves calling suspend (or resume) twice in a
// row both succeed — a supervisor re-clicking the button must never see an
// error.
func TestSuspendResumeIdempotent(t *testing.T) {
	reg, hub, shares := shareTestRegs()
	srv, _ := newTestServerOpts(t, nil, api.Options{Sessions: reg, Live: hub, Shares: shares})
	sid := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	shares.Open(sid)
	defer shares.Close(sid)
	approverTok := seedUser(t, srv, "dana-approver2", "approver")

	if code, d := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/suspend", approverTok, nil); code != http.StatusOK {
		t.Fatalf("suspend 1: %d %s", code, d)
	}
	if code, d := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/suspend", approverTok, nil); code != http.StatusOK {
		t.Fatalf("suspend 2 (already suspended): %d %s", code, d)
	}
	if code, d := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/resume", approverTok, nil); code != http.StatusOK {
		t.Fatalf("resume 1: %d %s", code, d)
	}
	if code, d := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/resume", approverTok, nil); code != http.StatusOK {
		t.Fatalf("resume 2 (already resumed): %d %s", code, d)
	}
}

// TestSuspendRequiresCapApprove proves a plain `user` (no CapApprove) cannot
// suspend or resume someone else's live session — the same authorization
// class as deciding a step-up.
func TestSuspendRequiresCapApprove(t *testing.T) {
	reg, hub, shares := shareTestRegs()
	srv, _ := newTestServerOpts(t, nil, api.Options{Sessions: reg, Live: hub, Shares: shares})
	sid := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	shares.Open(sid)
	defer shares.Close(sid)
	plainTok := seedUser(t, srv, "plainuser", "user")

	if code, d := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/suspend", plainTok, nil); code != http.StatusForbidden {
		t.Fatalf("suspend by non-approver: %d %s, want 403", code, d)
	}
	if code, d := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/resume", plainTok, nil); code != http.StatusForbidden {
		t.Fatalf("resume by non-approver: %d %s, want 403", code, d)
	}
}

// TestSuspendUnknownSessionNotFound proves suspend/resume against a session
// id that was never opened (or already ended) 404s cleanly, matching the
// "not live on this replica" wording every other live-session endpoint uses.
func TestSuspendUnknownSessionNotFound(t *testing.T) {
	reg, hub, shares := shareTestRegs()
	srv, _ := newTestServerOpts(t, nil, api.Options{Sessions: reg, Live: hub, Shares: shares})
	approverTok := seedUser(t, srv, "dana-approver3", "approver")

	if code, d := do(t, srv, http.MethodPost, "/api/sessions/no-such-session/suspend", approverTok, nil); code != http.StatusNotFound {
		t.Fatalf("suspend(unknown): %d %s, want 404", code, d)
	}
	if code, d := do(t, srv, http.MethodPost, "/api/sessions/no-such-session/resume", approverTok, nil); code != http.StatusNotFound {
		t.Fatalf("resume(unknown): %d %s, want 404", code, d)
	}
}
