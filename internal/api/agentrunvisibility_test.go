package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/ocsf"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// denyRules refuses winrm_exec outright, so a call reaches a terminal DENIED
// outcome without a human in the loop.
const denyRules = "rules:\n  - id: no-winrm\n    tool: winrm_exec\n    effect: deny\n"

// allowRules permits winrm_exec, for the executed-outcome cases.
const allowRules = "rules:\n  - id: yes-winrm\n    tool: winrm_exec\n    effect: allow\n    scope: \"t:{target}:x\"\n"

// trailActions lists the action names in a primary-audit-trail JSON response.
//
// The trail is read through the REST endpoint an operator would use, not out of
// the store directly, so these tests prove what a SIEM or console would actually
// see rather than what the code intended to write.
func trailActions(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "},{") {
		i := strings.Index(line, `"action":"`)
		if i < 0 {
			continue
		}
		rest := line[i+len(`"action":"`):]
		if j := strings.Index(rest, `"`); j >= 0 {
			out = append(out, rest[:j])
		}
	}
	return out
}

// TestBrokeredCallAuditsTheOutcome proves the primary audit trail records WHICH
// WAY a brokered tool call went, in the action name.
//
// This is the Phase 161 fix. Before it, every tool call — executed, denied,
// parked — wrote the single action `broker.tool_call`, with the outcome buried in
// the detail text. Both consumers of that trail key on the action name, so both
// were blind: `internal/ocsf` classified `broker.tool_call.denied` as a Detection
// Finding while nothing could emit it into this trail, and the risk engine had no
// agent action in any signal map at all. An agent could be refused a privileged
// call every minute for a week and neither surface would show anything unusual.
func TestBrokeredCallAuditsTheOutcome(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, denyRules))
	seedWinRMTarget(t, srv, "win-vis", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-vis", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	if _, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{
		"tool": "winrm_exec", "args": map[string]any{"target": "win-vis", "command": "whoami"},
	}); jsonMap(t, d)["status"] != "denied" {
		t.Fatalf("want a denied call to work with: %s", d)
	}

	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	actions := trailActions(aud)
	if !contains(actions, "broker.tool_call.denied") {
		t.Fatalf("the denial must be visible in the ACTION, got actions %v", actions)
	}
	if contains(actions, "broker.tool_call") {
		t.Fatalf("the outcome-less action must be gone (it is what made the trail unreadable), got %v", actions)
	}

	// And the point of the rename: that action is what the SIEM export classifies
	// as a Detection Finding rather than routine API activity.
	rec := ocsf.FromAudit(store.AuditEvent{Action: "broker.tool_call.denied", Actor: "bot-vis", Detail: "tool:winrm_exec"})
	if rec["class_uid"] != ocsf.ClassDetectionFinding {
		t.Fatalf("a denied agent tool call must export as an OCSF Detection Finding (%d), got class %v",
			ocsf.ClassDetectionFinding, rec["class_uid"])
	}
}

// TestBrokeredCallAuditRecordsTheRun proves an investigator can reassemble one
// agent run: the trail carries the agent's declared run id, its declared client,
// and the target the call reached for.
//
// The target matters twice over — it is also what the risk engine's baseline
// reads to notice an agent touching a system it has never touched before.
func TestBrokeredCallAuditRecordsTheRun(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, allowRules))
	seedWinRMTarget(t, srv, "win-run", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-run", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	_, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{
		"session_id": "run-42", "client": "claude-code/2.1",
		"tool": "winrm_exec", "args": map[string]any{"target": "win-run", "command": "whoami"},
	})
	m := jsonMap(t, d)
	if m["status"] != "executed" {
		t.Fatalf("want executed: %s", d)
	}
	// The run id comes back with the answer, so an agent firing several calls at
	// once can match each result to the run that asked for it.
	if m["session_id"] != "run-42" {
		t.Fatalf("outcome must echo the run id, got %v", m["session_id"])
	}

	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	for _, want := range []string{`session:\"run-42\"`, `client:\"claude-code/2.1\"`, `target:\"win-run\"`} {
		if !strings.Contains(string(aud), want) {
			t.Fatalf("audit trail is missing %s; run reconstruction needs it: %s", want, aud)
		}
	}
	if !contains(trailActions(aud), "broker.tool_call.executed") {
		t.Fatal("an executed call must be recorded as executed")
	}
}

// TestBrokeredRunFieldsCannotForgeAuditFields proves the two caller-declared
// values are quoted before they reach the trail.
//
// They arrive straight off the wire from the agent, and an audit detail is
// `key:value` text that other code parses back — the console splits it and takes
// last-wins. Interpolating them raw would let an agent name any actor it liked in
// its own audit record, which is the exact defect Phase 76 fixed elsewhere and
// exactly the trap a new sink falls into.
func TestBrokeredRunFieldsCannotForgeAuditFields(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, allowRules))
	seedWinRMTarget(t, srv, "win-forge", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-forge", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{
		"session_id": "r1 actor:admin status:executed",
		"client":     "x\nsession:other",
		"tool":       "winrm_exec", "args": map[string]any{"target": "win-forge", "command": "whoami"},
	})

	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	// The forged pairs survive only INSIDE the quoted token: never as free-standing
	// structure, and never as a raw newline that could split a syslog record.
	if strings.Contains(string(aud), `session:r1 actor:admin`) {
		t.Fatalf("a declared run id forged a second field in the record: %s", aud)
	}
	if !strings.Contains(string(aud), `session:\"r1 actor:admin status:executed\"`) {
		t.Fatalf("the value should be preserved, quoted, not dropped: %s", aud)
	}
	if !strings.Contains(string(aud), `client:\"x\\nsession:other\"`) {
		t.Fatalf("a newline in a declared client must be escaped, not passed through: %s", aud)
	}
}

// TestResumeIsRecordedInTheChain proves the moment an agent actually COLLECTS a
// parked result is written to the tamper-evident chain, joined to the token that
// unlocked it.
//
// Until Phase 161 the chain ended at the human's approval decision. The later
// step — the agent spending its single-use token and taking the result, which for
// reveal_credential is the moment a secret leaves pamv1 — appeared only in the
// primary trail, which is not the authoritative record. The `jti` is the token's
// SHA-256, so the collection event joins to the park event that minted it and to
// the `broker_tokens` row that was spent, without the trail ever holding anything
// spendable.
func TestResumeIsRecordedInTheChain(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "done", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, approvalRules))
	seedWinRMTarget(t, srv, "win-res", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-res", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	_, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{
		"session_id": "run-99",
		"tool":       "winrm_exec", "args": map[string]any{"target": "win-res", "command": "whoami"},
	})
	m := jsonMap(t, d)
	callID, _ := m["call_id"].(string)
	resume, _ := m["resume_token"].(string)
	if callID == "" || resume == "" {
		t.Fatalf("want a parked call: %s", d)
	}
	if st, dd := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey, map[string]any{"approve": true}); st != http.StatusOK {
		t.Fatalf("approve: %d %s", st, dd)
	}
	if st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls/"+callID+"/resume", tok, map[string]any{"token": resume}); st != http.StatusOK {
		t.Fatalf("resume should succeed")
	}

	_, chain := do(t, srv, http.MethodGet, "/v1/audit", testAPIKey, nil)
	if !strings.Contains(string(chain), "broker.tool_call.resumed") {
		t.Fatalf("the chain must record the collection, not just the approval: %s", chain)
	}
	// The park event and the collection event must name the SAME token id, which
	// is what makes them one story rather than two unrelated rows.
	jtis := jtiValues(string(chain))
	if len(jtis) < 2 {
		t.Fatalf("want a jti on both the park and the resume event, found %d: %s", len(jtis), chain)
	}
	if jtis[0] != jtis[len(jtis)-1] {
		t.Fatalf("park and resume name different tokens (%s vs %s)", jtis[0], jtis[len(jtis)-1])
	}
	// The run id follows the call across the approval boundary, so the parked
	// call and its eventual collection belong to the same reconstructed run.
	if !strings.Contains(string(chain), `session:\"run-99\"`) {
		t.Fatalf("the chain lost the run id across the approval: %s", chain)
	}
	// And the raw token itself is never written anywhere.
	if strings.Contains(string(chain), resume) {
		t.Fatal("the chain recorded the spendable resume token, not just its hash")
	}
	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if strings.Contains(string(aud), resume) {
		t.Fatal("the primary trail recorded the spendable resume token")
	}
}

// jtiValues extracts every `jti:<hex>` value from an audit dump, in order.
func jtiValues(s string) []string {
	var out []string
	for {
		i := strings.Index(s, "jti:")
		if i < 0 {
			return out
		}
		s = s[i+len("jti:"):]
		j := strings.IndexAny(s, ` "\`)
		if j < 0 {
			return append(out, s)
		}
		out = append(out, s[:j])
	}
}

// contains reports whether want is in list.
func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
