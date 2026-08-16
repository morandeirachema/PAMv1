package api_test

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// nopOpener is a stand-in live agent link for the API tests.
type nopOpener struct{ closed bool }

func (n *nopOpener) OpenTunnel() (net.Conn, error) { a, _ := net.Pipe(); return a, nil }
func (n *nopOpener) Close() error                  { n.closed = true; return nil }

// TestEndpointAgentsAPI covers the admin surface: create (key returned once,
// SSH targets only, one live agent per target, name validation), list with
// live status from the shared registry, revoke (idempotent, kicks the live
// link), the capability boundaries, and 404 when the feature is off.
func TestEndpointAgentsAPI(t *testing.T) {
	hub := session.NewEndpointAgents()
	srv, st := newTestServerOpts(t, nil, api.Options{EndpointAgents: hub})

	status, body := do(t, srv, http.MethodPost, "/api/targets", testAPIKey,
		map[string]any{"name": "branch-box", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh"})
	if status != http.StatusCreated {
		t.Fatalf("create target: %d %s", status, body)
	}
	var tgt store.Target
	_ = json.Unmarshal(body, &tgt)
	status, body = do(t, srv, http.MethodPost, "/api/targets", testAPIKey,
		map[string]any{"name": "win-box", "host": "10.0.0.6", "port": 5986, "os_type": "windows", "protocol": "winrm"})
	if status != http.StatusCreated {
		t.Fatalf("create winrm target: %d %s", status, body)
	}
	var win store.Target
	_ = json.Unmarshal(body, &win)

	// Create: key returned once, login form spelled out.
	status, body = do(t, srv, http.MethodPost, "/api/endpoint-agents", testAPIKey,
		map[string]any{"name": "branch-agent", "target_id": tgt.ID})
	if status != http.StatusCreated {
		t.Fatalf("create agent: %d %s", status, body)
	}
	var created struct {
		ID    int64  `json:"id"`
		Key   string `json:"key"`
		Login string `json:"login"`
	}
	_ = json.Unmarshal(body, &created)
	if created.Key == "" || created.Login != "endpoint-agent:branch-agent" {
		t.Fatalf("create response: %s", body)
	}
	if a, err := st.GetEndpointAgentByKeyHash(t.Context(), auth.TokenHash(created.Key)); err != nil || a.ID != created.ID || a.CreatedBy == "" {
		t.Fatalf("stored agent by key hash: %+v %v", a, err)
	}
	// One live agent per target; non-SSH targets refused; bad names refused.
	if status, _ = do(t, srv, http.MethodPost, "/api/endpoint-agents", testAPIKey,
		map[string]any{"name": "second", "target_id": tgt.ID}); status != http.StatusConflict {
		t.Fatalf("second agent for the target: %d", status)
	}
	if status, _ = do(t, srv, http.MethodPost, "/api/endpoint-agents", testAPIKey,
		map[string]any{"name": "win-agent", "target_id": win.ID}); status != http.StatusUnprocessableEntity {
		t.Fatalf("winrm target should be refused: %d", status)
	}
	if status, _ = do(t, srv, http.MethodPost, "/api/endpoint-agents", testAPIKey,
		map[string]any{"name": "bad:name", "target_id": tgt.ID}); status != http.StatusUnprocessableEntity {
		t.Fatalf("name with a colon should be refused: %d", status)
	}
	if status, _ = do(t, srv, http.MethodPost, "/api/endpoint-agents", testAPIKey,
		map[string]any{"name": "orphan", "target_id": 999999}); status != http.StatusNotFound {
		t.Fatalf("missing target: %d", status)
	}

	// List: not connected until the registry says so; never leaks the hash.
	status, body = do(t, srv, http.MethodGet, "/api/endpoint-agents", testAPIKey, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"connected":false`) || strings.Contains(string(body), "key_hash") ||
		!strings.Contains(string(body), `"target_name":"branch-box"`) {
		t.Fatalf("list: %d %s", status, body)
	}
	op := &nopOpener{}
	hub.Register(session.EndpointAgentLink{AgentID: created.ID, Name: "branch-agent", TargetID: tgt.ID, Remote: "203.0.113.7:4444"}, op)
	_, body = do(t, srv, http.MethodGet, "/api/endpoint-agents", testAPIKey, nil)
	if !strings.Contains(string(body), `"connected":true`) || !strings.Contains(string(body), "203.0.113.7:4444") {
		t.Fatalf("list should show the live link: %s", body)
	}

	// Capability boundaries: an auditor can list (inventory) but not create/revoke.
	auditor := seedUser(t, srv, "aud", "auditor")
	if status, _ = do(t, srv, http.MethodGet, "/api/endpoint-agents", auditor, nil); status != http.StatusOK {
		t.Fatalf("auditor list: %d", status)
	}
	if status, _ = do(t, srv, http.MethodPost, "/api/endpoint-agents", auditor,
		map[string]any{"name": "x", "target_id": tgt.ID}); status != http.StatusForbidden {
		t.Fatalf("auditor create should be 403: %d", status)
	}
	if status, _ = do(t, srv, http.MethodDelete, "/api/endpoint-agents/1", auditor, nil); status != http.StatusForbidden {
		t.Fatalf("auditor revoke should be 403: %d", status)
	}

	// Revoke: live link kicked, row revoked, idempotent, target free for a new one.
	if status, _ = do(t, srv, http.MethodDelete, "/api/endpoint-agents/"+itoa(created.ID), testAPIKey, nil); status != http.StatusNoContent {
		t.Fatalf("revoke: %d", status)
	}
	if !op.closed {
		t.Fatal("revoke should kick the live link")
	}
	if _, ok := hub.Lookup(tgt.ID); ok {
		t.Fatal("link should be gone after revoke")
	}
	if status, _ = do(t, srv, http.MethodDelete, "/api/endpoint-agents/"+itoa(created.ID), testAPIKey, nil); status != http.StatusNoContent {
		t.Fatalf("revoke again should be idempotent: %d", status)
	}
	if status, _ = do(t, srv, http.MethodDelete, "/api/endpoint-agents/999999", testAPIKey, nil); status != http.StatusNotFound {
		t.Fatalf("revoke missing: %d", status)
	}
	if status, _ = do(t, srv, http.MethodPost, "/api/endpoint-agents", testAPIKey,
		map[string]any{"name": "branch-agent-2", "target_id": tgt.ID}); status != http.StatusCreated {
		t.Fatalf("new agent after revoke: %d", status)
	}
	_, body = do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	for _, want := range []string{"endpoint_agent.create", "endpoint_agent.revoke"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("expected audit %s: %s", want, body)
		}
	}

	// Feature off: routes absent.
	plain := newTestServer(t)
	if status, _ = do(t, plain, http.MethodGet, "/api/endpoint-agents", testAPIKey, nil); status != http.StatusNotFound {
		t.Fatalf("disabled feature should 404: %d", status)
	}
}
