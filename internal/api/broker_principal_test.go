package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/winrm"
)

// principalRules allows winrm_exec for ONE named agent and nobody else, plus a
// rule that refuses any call arriving through a delegated token. Both are things
// a policy could not express at all before Phase 173.
const principalRules = `
rules:
  - id: no-exec-through-delegation
    tool: winrm_exec
    when: { caller.delegation_depth: { gte: 1 } }
    effect: deny
    reason: a delegated token may not run commands
  - id: exec-for-the-runner-only
    tool: winrm_exec
    agents: [runner-bot]
    effect: allow
  - id: everyone-lists
    tool: list_targets
    effect: allow
`

// TestBrokerPolicyHasAPrincipalSide proves end to end that the broker hands the
// VERIFIED identity to the policy engine, so one `allow` no longer enables a tool
// for every agent in the deployment.
//
// Before Phase 173 `Evaluate(tool, args)` never saw who was calling — the
// identity sat one line above the call site and was not passed — so
// `exec-for-the-runner-only` was inexpressible and any agent holding a valid
// bearer could run the tool.
func TestBrokerPolicyHasAPrincipalSide(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, principalRules))
	seedWinRMTarget(t, srv, "win-principal", "pw")
	_, allowed := mintAgent(t, srv, "runner-bot", "alice", nil)
	_, other := mintAgent(t, srv, "planner-bot", "alice", nil)

	call := map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-principal", "command": "whoami"}}

	_, ad := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", allowed, call)
	if m := jsonMap(t, ad); m["status"] != "executed" || m["rule_id"] != "exec-for-the-runner-only" {
		t.Fatalf("the named agent should execute under its own rule: %s", ad)
	}

	_, od := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", other, call)
	if m := jsonMap(t, od); m["status"] != "denied" || m["rule_id"] != "implicit-default-deny" {
		t.Fatalf("an agent the rule does not name must fall through to the default deny: %s", od)
	}

	// Both agents still share the rule that names nobody, so a policy written
	// before this phase keeps behaving as it did.
	for _, tok := range []string{allowed, other} {
		_, ld := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "list_targets"})
		if jsonMap(t, ld)["status"] != "executed" {
			t.Fatalf("a rule with no principal side must still match every agent: %s", ld)
		}
	}
}

// TestCallerConditionCannotBeForgedOverTheWire is the wire-level twin of the
// engine's forgery test: an agent cannot talk its way into a `caller.*`
// condition by sending an argument of the same name.
//
// Two independent gates stop it, which is worth pinning together: the tool's
// argument schema refuses an undeclared argument outright (Phase 163), and even
// if one slipped through, a caller.* condition never reads the argument map.
func TestCallerConditionCannotBeForgedOverTheWire(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, principalRules))
	seedWinRMTarget(t, srv, "win-forge", "pw")
	_, other := mintAgent(t, srv, "planner-bot", "alice", nil)

	_, fd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", other, map[string]any{
		"tool": "winrm_exec",
		"args": map[string]any{
			"target": "win-forge", "command": "whoami",
			"caller.agent": "runner-bot",
		},
	})
	if m := jsonMap(t, fd); m["status"] == "executed" {
		t.Fatalf("a forged caller argument must never authorize a call: %s", fd)
	}
	if fake.gotPass != "" {
		t.Fatal("no credential should have been injected for a refused call")
	}
	if strings.Contains(string(fd), "\"rule_id\":\"exec-for-the-runner-only\"") {
		t.Fatalf("the forged argument must not have matched the named-agent rule: %s", fd)
	}
}
