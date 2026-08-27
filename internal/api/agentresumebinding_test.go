package api_test

import (
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/winrm"
)

// TestBrokerResumeTokenBoundToCollector — Phase 222, the 2026-08-26 audit's
// F-7. A resume token was single-use and its call id 96-bit random, so a token
// that leaked from one agent to another was already worth one collection at
// most. It is now worth nothing to anyone but the agent whose call it belongs
// to: a different agent presenting it — on the right path, with a valid token
// — is answered exactly as a bad token would be, and the presentation spends
// nothing, so the owner still collects. Verified to fail with the binding
// removed.
func TestBrokerResumeTokenBoundToCollector(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, approvalRules))
	seedWinRMTarget(t, srv, "win-coll", "pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-owner", "owner": "alice"})
	owner, _ := jsonMap(t, ad)["token"].(string)
	_, bd := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-other", "owner": "alice"})
	other, _ := jsonMap(t, bd)["token"].(string)

	_, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", owner,
		map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-coll", "command": "x"}})
	m := jsonMap(t, data)
	callID, _ := m["call_id"].(string)
	resume, _ := m["resume_token"].(string)
	if m["status"] != "pending_approval" || callID == "" || resume == "" {
		t.Fatalf("want a parked call with a resume token: %s", data)
	}
	if st, dd := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey,
		map[string]any{"approve": true}); st != http.StatusOK || jsonMap(t, dd)["status"] != "executed" {
		t.Fatalf("approve: %d %s", st, dd)
	}

	// The other agent holds the owner's token and the call id — everything a
	// leak would give it — and gets the answer a bad token gets.
	if st, rd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls/"+callID+"/resume", other,
		map[string]any{"token": resume}); st != http.StatusNotFound {
		t.Fatalf("another agent collecting with a leaked token: want 404, got %d %s", st, rd)
	}
	// Nothing was spent: the owner collects exactly once, as before.
	if st, rd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls/"+callID+"/resume", owner,
		map[string]any{"token": resume}); st != http.StatusOK || jsonMap(t, rd)["status"] != "executed" {
		t.Fatalf("the owner must still collect after a stranger's refused attempt: %d %s", st, rd)
	}
	if st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls/"+callID+"/resume", owner,
		map[string]any{"token": resume}); st != http.StatusNotFound {
		t.Fatalf("second collection by the owner: want 404 (single use), got %d", st)
	}
}
