package api_test

import (
	"bufio"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/winrm"
)

// sodRules parks winrm_exec for approval restricted to the admin group.
const sodRules = "rules:\n  - id: needs-admin\n    tool: winrm_exec\n    effect: require_approval\n    approvers: [admin]\n    scope: \"t:{target}:x\"\n"

// TestBrokerApproverSoD proves separation of duties on a parked call: the rule
// restricts approval to the `admin` group, so an approver-role decider (who holds
// CapApprove and reaches the route) is refused (403, the call stays decidable),
// while an administrator satisfies it. Groups are matched against ROLES, never a
// mintable username, so a manage_users delegate can't create a user named after
// the group to self-approve.
func TestBrokerApproverSoD(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, sodRules))
	seedWinRMTarget(t, srv, "win-sod", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-sod", "owner": "owner"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	// An approver-role decider — holds CapApprove but is NOT in the rule's group.
	outsider := seedUser(t, srv, "alice", "approver")

	_, cd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-sod", "command": "whoami"}})
	callID, _ := jsonMap(t, cd)["call_id"].(string)
	if callID == "" || jsonMap(t, cd)["status"] != "pending_approval" {
		t.Fatalf("expected a parked call: %s", cd)
	}

	// The pending listing shows which group may decide.
	_, ld := do(t, srv, http.MethodGet, "/v1/approvals", testAPIKey, nil)
	if !strings.Contains(string(ld), "admin") {
		t.Fatalf("approvals listing should expose the approver group: %s", ld)
	}

	// Outsider: refused, and the call remains parked (SoD, not consumed).
	if code, _ := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", outsider, map[string]any{"approve": true}); code != http.StatusForbidden {
		t.Fatalf("outsider decision: want 403, got %d", code)
	}
	if _, ld2 := do(t, srv, http.MethodGet, "/v1/approvals", testAPIKey, nil); !strings.Contains(string(ld2), callID) {
		t.Fatal("a refused SoD decision must leave the call parked")
	}

	// The administrator (bootstrap key) satisfies the admin group and executes JIT.
	code, dd := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey, map[string]any{"approve": true})
	if code != http.StatusOK || jsonMap(t, dd)["status"] != "executed" {
		t.Fatalf("admin decision: %d %s", code, dd)
	}
	if fake.gotPass != "vault-pw" {
		t.Fatalf("runner got %q, want vault-pw", fake.gotPass)
	}
}

// TestBrokerAuditJWKSAndFloor proves the checkpoint-signing keys are published as
// a JWKS and that the verify endpoint reports checkpoints and the tail-truncation
// floor.
func TestBrokerAuditJWKSAndFloor(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	opts := brokerOpts(t, fake, brokerRules)
	opts.BrokerCheckpointEvery = 1 // a checkpoint after every event
	srv, _ := newTestServerOpts(t, nil, opts)
	seedWinRMTarget(t, srv, "win-cp", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-cp", "owner": "o"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	// Drive a couple of allowed calls so the chain has events + checkpoints.
	for i := 0; i < 2; i++ {
		doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-cp", "command": "whoami"}})
	}

	// JWKS publishes at least the current ed25519 signer.
	_, jd := do(t, srv, http.MethodGet, "/v1/audit/jwks", testAPIKey, nil)
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(jd, &jwks); err != nil || len(jwks.Keys) == 0 {
		t.Fatalf("jwks: %s (err %v)", jd, err)
	}
	if jwks.Keys[0]["kty"] != "OKP" || jwks.Keys[0]["crv"] != "Ed25519" || jwks.Keys[0]["kid"] == "" {
		t.Fatalf("jwks key shape: %+v", jwks.Keys[0])
	}

	// Verify: intact, with checkpoints present.
	_, vd := do(t, srv, http.MethodGet, "/v1/audit/verify", testAPIKey, nil)
	v := jsonMap(t, vd)
	if v["ok"] != true || v["checkpoints"].(float64) < 1 {
		t.Fatalf("verify: %s", vd)
	}
	// A floor above the current count reports truncation.
	_, td := do(t, srv, http.MethodGet, "/v1/audit/verify?min_entries=100000", testAPIKey, nil)
	if tm := jsonMap(t, td); tm["truncated"] != true || tm["ok"] != false {
		t.Fatalf("floor verify: %s", td)
	}
}

// TestAuditOCSFExport proves the OCSF export endpoint returns mapped events in
// both the JSON-array and NDJSON forms, and is itself audited.
func TestAuditOCSFExport(t *testing.T) {
	srv, _ := newTestServerStore(t)
	// Generate an event to export.
	do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "ocsf-tgt", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	code, data := do(t, srv, http.MethodGet, "/api/audit/ocsf", testAPIKey, nil)
	if code != http.StatusOK {
		t.Fatalf("ocsf export: %d %s", code, data)
	}
	var out struct {
		Schema string           `json:"schema"`
		Count  int              `json:"count"`
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.Count == 0 {
		t.Fatalf("ocsf body: %s (err %v)", data, err)
	}
	if _, ok := out.Events[0]["class_uid"]; !ok {
		t.Fatalf("ocsf event missing class_uid: %+v", out.Events[0])
	}
	// NDJSON form: one JSON object per line.
	_, nd := do(t, srv, http.MethodGet, "/api/audit/ocsf?format=ndjson&action=target.create", testAPIKey, nil)
	lines := strings.Split(strings.TrimSpace(string(nd)), "\n")
	if len(lines) == 0 || !json.Valid([]byte(lines[0])) {
		t.Fatalf("ndjson first line invalid: %q", nd)
	}
	// The export is audited.
	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if !strings.Contains(string(aud), "audit.ocsf_export") {
		t.Fatalf("ocsf export not audited: %s", aud)
	}
}

// readSSEEvent reads one Server-Sent Event (event/data lines terminated by a
// blank line), skipping comment/heartbeat lines. Returns the event name and its
// concatenated data.
func readSSEEvent(t *testing.T, br *bufio.Reader) (string, string) {
	t.Helper()
	var event, data string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("sse read: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			if event != "" || data != "" {
				return event, data
			}
		case strings.HasPrefix(line, ":"): // comment / heartbeat
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(line[len("event:"):])
		case strings.HasPrefix(line, "data:"):
			data += strings.TrimSpace(line[len("data:"):])
		}
	}
}

// TestMCPSSEElicitation proves the MCP SSE transport (Phase 27): the stream emits
// an `endpoint` event, an elicitation-capable client's approval-gated tool call
// triggers a server elicitation/create push, and declining it withdraws the
// requester's own parked call.
func TestMCPSSEElicitation(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, approvalRules))
	seedWinRMTarget(t, srv, "win-el", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-el", "owner": "o"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	// Open the SSE stream and read the endpoint event.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sse open: %d", res.StatusCode)
	}
	br := bufio.NewReader(res.Body)
	ev, data := readSSEEvent(t, br)
	if ev != "endpoint" || !strings.HasPrefix(data, "/mcp?session=") {
		t.Fatalf("first event = %q data %q, want endpoint", ev, data)
	}
	msgPath := data // "/mcp?session=<id>"

	// initialize declaring elicitation support.
	doBearer(t, srv, http.MethodPost, msgPath, tok, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"capabilities": map[string]any{"elicitation": map[string]any{}}},
	})

	// A require_approval tool call blocks server-side awaiting the elicitation.
	callDone := make(chan []byte, 1)
	go func() {
		_, d := doBearer(t, srv, http.MethodPost, msgPath, tok, map[string]any{
			"jsonrpc": "2.0", "id": 2, "method": "tools/call",
			"params": map[string]any{"name": "winrm_exec", "arguments": map[string]any{"target": "win-el", "command": "whoami"}},
		})
		callDone <- d
	}()

	// Read the server's elicitation/create push and extract its request id.
	ev, data = readSSEEvent(t, br)
	if ev != "message" {
		t.Fatalf("expected an elicitation message, got event %q", ev)
	}
	var srvReq struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if err := json.Unmarshal([]byte(data), &srvReq); err != nil || srvReq.Method != "elicitation/create" {
		t.Fatalf("server push = %s (err %v)", data, err)
	}

	// Decline the elicitation.
	if code, _ := doBearer(t, srv, http.MethodPost, msgPath, tok, map[string]any{
		"jsonrpc": "2.0", "id": json.RawMessage(srvReq.ID), "result": map[string]any{"action": "decline"},
	}); code != http.StatusAccepted {
		t.Fatalf("elicitation response: want 202, got %d", code)
	}

	// The tool call returns with the call withdrawn (denied), and no credential
	// ever reached the runner.
	select {
	case d := <-callDone:
		sc, _ := jsonMap(t, d)["result"].(map[string]any)
		content, _ := sc["structuredContent"].(map[string]any)
		if content["status"] != "denied" {
			t.Fatalf("declined call status = %v, want denied: %s", content["status"], d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tool call did not return after the elicitation was declined")
	}
	if fake.gotPass != "" {
		t.Fatal("a declined call must not inject a credential")
	}
}

// delegatedRules parks winrm_exec for approval restricted to the `approver`
// group — a group the bootstrap admin does NOT need to be in.
const delegatedRules = "rules:\n  - id: needs-approver\n    tool: winrm_exec\n    effect: require_approval\n    approvers: [approver]\n    scope: \"t:{target}:x\"\n"

// TestBrokerDelegatedApproverGroupGrants proves a NON-admin decider whose group
// matches the rule can actually approve — the case that makes separation of
// duties a delegation mechanism rather than an admin-only ceremony.
//
// This needs its own test because the sibling above cannot reach it.
// `approverPermitted` short-circuits on `IsAdmin` before the group loop runs,
// and every other successful broker approval in this suite decides as the
// bootstrap admin — so the group-matching loop, which is the whole of Phase 27's
// separation of duties and is named as a control in
// docs/AGENT-THREAT-MODEL.md, had never once returned true.
//
// That gap fails dangerously in both directions. If the match were too loose, an
// out-of-group approver could grant — the authorization bypass the threat model
// explicitly disclaims. If it were too tight, no non-admin could ever approve
// anything, and nobody would find out until the first operator delegated.
func TestBrokerDelegatedApproverGroupGrants(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, delegatedRules))
	seedWinRMTarget(t, srv, "win-deleg", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-deleg", "owner": "owner"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	// A decider who is NOT an administrator, but whose role — which is what
	// ApproverGroups reports — matches the rule's approver group.
	delegate := seedUser(t, srv, "dana", "approver")

	_, cd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok,
		map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-deleg", "command": "whoami"}})
	callID, _ := jsonMap(t, cd)["call_id"].(string)
	if callID == "" || jsonMap(t, cd)["status"] != "pending_approval" {
		t.Fatalf("expected a parked call: %s", cd)
	}

	// The delegate approves. This is the assertion that has never held: a grant
	// reached through the group loop rather than through the admin bypass.
	code, dd := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", delegate,
		map[string]any{"approve": true})
	if code != http.StatusOK {
		t.Fatalf("a delegate in the rule's approver group was refused: %d %s — separation of duties is admin-only, which is not what it claims to be", code, dd)
	}
	if jsonMap(t, dd)["status"] != "executed" {
		t.Fatalf("delegate decision did not execute the call: %s", dd)
	}
	// And the approval really did drive a just-in-time execution.
	if fake.gotPass != "vault-pw" {
		t.Fatalf("runner got %q, want vault-pw — the call was marked executed without injecting the credential", fake.gotPass)
	}
}
