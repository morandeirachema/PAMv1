package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// mintAgent creates an agent identity and returns its id and its one-time
// bearer token. body lets a test add `expires_in_days`.
func mintAgent(t *testing.T, srv *httptest.Server, name, owner string, body map[string]any) (int64, string) {
	t.Helper()
	in := map[string]any{"name": name, "owner": owner}
	for k, v := range body {
		in[k] = v
	}
	status, data := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, in)
	if status != http.StatusCreated {
		t.Fatalf("mint agent: %d %s", status, data)
	}
	m := jsonMap(t, data)
	tok, _ := m["token"].(string)
	if tok == "" {
		t.Fatalf("no agent token: %s", data)
	}
	return int64(m["id"].(float64)), tok
}

// callTool makes one brokered tool call as the agent and returns the HTTP
// status (the outcome status lives in the body).
func callTool(t *testing.T, srv *httptest.Server, token, target string) (int, []byte) {
	t.Helper()
	return doBearer(t, srv, http.MethodPost, "/v1/tool-calls", token, map[string]any{
		"tool": "winrm_exec", "args": map[string]any{"target": target, "command": "whoami"},
	})
}

// lifecycleServer wires a broker-enabled server with one WinRM target the
// policy allows, and returns it with its store.
func lifecycleServer(t *testing.T) (*httptest.Server, store.Store) {
	t.Helper()
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	srv, st := newTestServerOpts(t, nil, brokerOpts(t, fake, brokerRules))
	seedWinRMTarget(t, srv, "win-life", "vaulted-pw")
	return srv, st
}

// TestAgentSuspendResume proves the control this phase exists for: an agent
// identity can be stopped WITHOUT destroying it, and started again. Before this,
// `Disabled` was honoured on read but no code path could set it, so the only
// answer to "stop this agent while we investigate" was to delete the row an
// investigation needs.
func TestAgentSuspendResume(t *testing.T) {
	srv, _ := lifecycleServer(t)
	id, tok := mintAgent(t, srv, "bot-suspend", "alice", nil)

	if status, d := callTool(t, srv, tok, "win-life"); status != http.StatusOK {
		t.Fatalf("a fresh agent should work: %d %s", status, d)
	}
	if status, d := do(t, srv, http.MethodPost, "/v1/agents/"+itoa(id)+"/disable", testAPIKey, nil); status != http.StatusNoContent {
		t.Fatalf("disable: %d %s", status, d)
	}
	// Refused at the front door, and indistinguishable from an unknown bearer:
	// a suspended agent learns nothing from the reply about why it stopped.
	if status, _ := callTool(t, srv, tok, "win-life"); status != http.StatusUnauthorized {
		t.Fatalf("a suspended agent must be refused, got %d", status)
	}
	// The identity itself survives — that is the whole point of suspend.
	_, ld := do(t, srv, http.MethodGet, "/v1/agents", testAPIKey, nil)
	if !strings.Contains(string(ld), "bot-suspend") || !strings.Contains(string(ld), `"disabled":true`) {
		t.Fatalf("the suspended agent should still be listed as disabled: %s", ld)
	}
	// Resume restores the SAME token — suspension is not a re-issue.
	if status, d := do(t, srv, http.MethodPost, "/v1/agents/"+itoa(id)+"/enable", testAPIKey, nil); status != http.StatusNoContent {
		t.Fatalf("enable: %d %s", status, d)
	}
	if status, d := callTool(t, srv, tok, "win-life"); status != http.StatusOK {
		t.Fatalf("a resumed agent should work with its original token: %d %s", status, d)
	}
	_, adata := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	for _, want := range []string{"agent.disable", "agent.enable"} {
		if !strings.Contains(string(adata), want) {
			t.Fatalf("missing audit %q: %s", want, adata)
		}
	}
}

// TestAgentKeyExpiry proves an agent identity can be time-boxed: an expired key
// stops authenticating on the same path a suspended one does, and the expiry
// rides on the resolved identity so it reaches the post-park re-validation too.
func TestAgentKeyExpiry(t *testing.T) {
	srv, st := lifecycleServer(t)
	_, tok := mintAgent(t, srv, "bot-expiry", "alice", map[string]any{"expires_in_days": 30})
	if status, d := callTool(t, srv, tok, "win-life"); status != http.StatusOK {
		t.Fatalf("an unexpired key should work: %d %s", status, d)
	}
	// Wind the expiry into the past directly in the store — the only honest way
	// to test a clock-driven control without waiting 30 days.
	ctx := context.Background()
	keys, err := st.ListAgentKeys(ctx)
	if err != nil || len(keys) == 0 {
		t.Fatalf("list agent keys: %+v %v", keys, err)
	}
	past := time.Now().Add(-time.Hour)
	for i := range keys {
		if keys[i].Name == "bot-expiry" {
			k := keys[i]
			k.ExpiresAt = &past
			// memstore/pgstore have no "update expiry" method by design (expiry is
			// set at creation), so re-create the row through the store the way an
			// operator would by minting a new short-lived key.
			if err := st.DeleteAgentKey(ctx, k.ID); err != nil {
				t.Fatal(err)
			}
			k.ID = 0
			if err := st.CreateAgentKey(ctx, &k); err != nil {
				t.Fatal(err)
			}
		}
	}
	if status, _ := callTool(t, srv, tok, "win-life"); status != http.StatusUnauthorized {
		t.Fatalf("an expired key must be refused, got %d", status)
	}
	// And an expired key is refused with the same opaque error as an unknown one.
	if status, _ := callTool(t, srv, "not-a-real-token", "win-life"); status != http.StatusUnauthorized {
		t.Fatal("an unknown bearer should also be 401")
	}
	// Bad input is refused up front rather than silently clamped.
	if status, _ := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey,
		map[string]any{"name": "bot-bad", "owner": "alice", "expires_in_days": 99999}); status != http.StatusUnprocessableEntity {
		t.Fatalf("an absurd lifetime should be refused, got %d", status)
	}
}

// TestAgentQuarantineCoversBothIdentityKinds is the phase's flagship: quarantine
// is keyed on the agent's canonical NAME, which is what lets one list stop both
// authentication paths — a static key (which could also be disabled) and an
// SVID-attested agent, which has NO key row at all and, before this phase, could
// not be stopped locally by anything.
func TestAgentQuarantineCoversBothIdentityKinds(t *testing.T) {
	srv, st := lifecycleServer(t)
	_, tok := mintAgent(t, srv, "bot-quarantine", "alice", nil)
	if status, d := callTool(t, srv, tok, "win-life"); status != http.StatusOK {
		t.Fatalf("baseline call: %d %s", status, d)
	}

	// (a) A static-key agent, quarantined by its name.
	status, qd := do(t, srv, http.MethodPost, "/v1/agents/quarantine", testAPIKey,
		map[string]any{"subject": "bot-quarantine", "reason": "anomalous volume, INC-4471"})
	if status != http.StatusCreated {
		t.Fatalf("quarantine: %d %s", status, qd)
	}
	qid := int64(jsonMap(t, qd)["id"].(float64))
	if status, _ := callTool(t, srv, tok, "win-life"); status != http.StatusUnauthorized {
		t.Fatalf("a quarantined agent must be refused, got %d", status)
	}
	// Its key was never touched — quarantine and suspend are independent controls.
	_, ld := do(t, srv, http.MethodGet, "/v1/agents", testAPIKey, nil)
	if !strings.Contains(string(ld), `"disabled":false`) {
		t.Fatalf("quarantine must not flip the key's own disabled flag: %s", ld)
	}
	// Release restores it.
	if status, _ := do(t, srv, http.MethodDelete, "/v1/agents/quarantine/"+itoa(qid), testAPIKey, nil); status != http.StatusNoContent {
		t.Fatal("release should succeed")
	}
	if status, d := callTool(t, srv, tok, "win-life"); status != http.StatusOK {
		t.Fatalf("a released agent should work again: %d %s", status, d)
	}

	// (b) The case the phase exists for: an SVID-shaped identity, whose KeyID is
	// 0 and which therefore has no row any disable could reach. Quarantining its
	// SPIFFE ID is the only local stop button it has. That an SVID subject can be
	// quarantined and listed is asserted here; that the quarantine also holds at
	// APPROVAL time for such an identity — the parked-call path, which no HTTP
	// request can reach without a SPIFFE deployment — is asserted in-package by
	// TestRevalidateAgentQuarantineCoversSVIDIdentities.
	const spiffeID = "spiffe://corp.example/ns/prod/sa/planner"
	if status, d := do(t, srv, http.MethodPost, "/v1/agents/quarantine", testAPIKey,
		map[string]any{"subject": spiffeID, "reason": "suspected prompt injection"}); status != http.StatusCreated {
		t.Fatalf("quarantine an SVID subject: %d %s", status, d)
	}

	// The list is readable and the refusals are on the trail under the agent's
	// own name, where the responder looks.
	_, qlist := do(t, srv, http.MethodGet, "/v1/agents/quarantine", testAPIKey, nil)
	if !strings.Contains(string(qlist), spiffeID) {
		t.Fatalf("quarantine list should carry the SPIFFE subject: %s", qlist)
	}
	_, adata := do(t, srv, http.MethodGet, "/api/audit?limit=80", testAPIKey, nil)
	for _, want := range []string{"agent.quarantine", "agent.quarantine_release", "agent.quarantine_refused"} {
		if !strings.Contains(string(adata), want) {
			t.Fatalf("missing audit %q: %s", want, adata)
		}
	}
	// A duplicate subject is a conflict, not a second row to release twice.
	if status, _ := do(t, srv, http.MethodPost, "/v1/agents/quarantine", testAPIKey,
		map[string]any{"subject": spiffeID, "reason": "again"}); status != http.StatusConflict {
		t.Fatal("a duplicate quarantine subject should be 409")
	}
	_ = st
}

// TestAgentLastUsedRecorded proves the dormancy signal: every successful agent
// authentication stamps last-used, so "is anyone still using this standing
// credential?" has an answer. It is best-effort by design and must never gate a
// call, which the successful call above already demonstrates.
func TestAgentLastUsedRecorded(t *testing.T) {
	srv, st := lifecycleServer(t)
	id, tok := mintAgent(t, srv, "bot-dormant", "alice", nil)
	keys, _ := st.ListAgentKeys(context.Background())
	for _, k := range keys {
		if k.ID == id && k.LastUsedAt != nil {
			t.Fatal("a freshly minted key cannot have been used yet")
		}
	}
	if status, _ := callTool(t, srv, tok, "win-life"); status != http.StatusOK {
		t.Fatal("call should succeed")
	}
	keys, _ = st.ListAgentKeys(context.Background())
	var seen bool
	for _, k := range keys {
		if k.ID == id {
			seen = k.LastUsedAt != nil
		}
	}
	if !seen {
		t.Fatal("last-used was not stamped on a successful authentication")
	}
}

// TestDeletingOwnerSuspendsTheirAgents proves offboarding cascades: when the
// accountable human is gone the agent stops — but the identity and its history
// stay, because an investigation needs them and a successor may re-enable.
func TestDeletingOwnerSuspendsTheirAgents(t *testing.T) {
	srv, _ := lifecycleServer(t)
	// A real user row, so the delete path is the real one.
	status, ud := do(t, srv, http.MethodPost, "/api/users", testAPIKey,
		map[string]any{"username": "carol", "role": "user"})
	if status != http.StatusCreated {
		t.Fatalf("create user: %d %s", status, ud)
	}
	uid := int64(jsonMap(t, ud)["id"].(float64))
	_, tok := mintAgent(t, srv, "bot-of-carol", "carol", nil)
	_, otherTok := mintAgent(t, srv, "bot-of-dave", "dave", nil)

	if status, _ := do(t, srv, http.MethodDelete, "/api/users/"+itoa(uid), testAPIKey, nil); status != http.StatusNoContent {
		t.Fatal("delete user should succeed")
	}
	if status, _ := callTool(t, srv, tok, "win-life"); status != http.StatusUnauthorized {
		t.Fatalf("the departed owner's agent must be suspended, got %d", status)
	}
	// Another owner's agent is untouched — the cascade is scoped, not a sweep.
	if status, d := callTool(t, srv, otherTok, "win-life"); status != http.StatusOK {
		t.Fatalf("another owner's agent must keep working: %d %s", status, d)
	}
	_, ld := do(t, srv, http.MethodGet, "/v1/agents", testAPIKey, nil)
	if !strings.Contains(string(ld), "bot-of-carol") {
		t.Fatalf("the suspended agent must still exist for the investigation: %s", ld)
	}
	_, adata := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if !strings.Contains(string(adata), "owner-offboarded") {
		t.Fatalf("the cascade must say why: %s", adata)
	}
}

// TestAgentLifecycleAuthorization pins the capability boundary: these are
// identity-management routes, so they need manage_users like every other
// /v1/agents route — a connect-capable user cannot stop or start an agent.
func TestAgentLifecycleAuthorization(t *testing.T) {
	srv, _ := lifecycleServer(t)
	id, _ := mintAgent(t, srv, "bot-authz", "alice", nil)
	user := seedUser(t, srv, "plain-user", "user")
	for _, c := range []struct {
		method, path string
		body         map[string]any
	}{
		{http.MethodPost, "/v1/agents/" + itoa(id) + "/disable", nil},
		{http.MethodPost, "/v1/agents/" + itoa(id) + "/enable", nil},
		{http.MethodPost, "/v1/agents/quarantine", map[string]any{"subject": "x", "reason": "y"}},
		{http.MethodGet, "/v1/agents/quarantine", nil},
		{http.MethodDelete, "/v1/agents/quarantine/1", nil},
	} {
		if status, d := do(t, srv, c.method, c.path, user, c.body); status != http.StatusForbidden {
			t.Fatalf("%s %s as a plain user = %d %s, want 403", c.method, c.path, status, d)
		}
	}
	// And an unknown key id is a clean 404, not a silent success.
	if status, _ := do(t, srv, http.MethodPost, "/v1/agents/999999/disable", testAPIKey, nil); status != http.StatusNotFound {
		t.Fatal("disabling an unknown agent should 404")
	}
	if status, _ := do(t, srv, http.MethodDelete, "/v1/agents/quarantine/999999", testAPIKey, nil); status != http.StatusNotFound {
		t.Fatal("releasing an unknown quarantine should 404")
	}
	// A subject is required, and a control character in one is refused so it
	// cannot split an audit record in two.
	if status, _ := do(t, srv, http.MethodPost, "/v1/agents/quarantine", testAPIKey,
		map[string]any{"subject": "", "reason": "x"}); status != http.StatusUnprocessableEntity {
		t.Fatal("an empty subject should be refused")
	}
	if status, _ := do(t, srv, http.MethodPost, "/v1/agents/quarantine", testAPIKey,
		map[string]any{"subject": "bot\nactor:admin", "reason": "x"}); status != http.StatusUnprocessableEntity {
		t.Fatal("a newline in a subject should be refused")
	}
}
