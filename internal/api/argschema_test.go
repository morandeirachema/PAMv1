package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/winrm"
)

// allowAnyExecRules permits winrm_exec unconditionally, so a call's fate is
// decided by argument validation rather than by policy.
const allowAnyExecRules = "rules:\n  - id: yes-exec\n    tool: winrm_exec\n    effect: allow\n"

// listGuardRules is the guard an operator would naturally write to keep an agent
// away from a sensitive target's credentials — and, before Phase 163, the
// exact rule an agent bypassed by sending less data. `list_credentials` lists
// EVERY credential when `target` is omitted, and `not_in` used to be satisfied
// by an absent argument, so omitting the filter matched this allow rule and
// listed the very targets it names.
const listGuardRules = "rules:\n  - id: not-the-vault\n    tool: list_credentials\n    effect: allow\n    when:\n      target: { not_in: [vault-prod] }\n"

// TestNegativeGuardCannotBeBypassedByOmission is the regression test for the
// omission bypass: a rule that block-lists targets must not admit a call that
// simply leaves the target out.
//
// The rule is an ALLOW with a negative condition, which is the shape that makes
// this dangerous — with the condition satisfied by absence, the widest possible
// form of the call (list everything) was the one form the guard could not stop.
// There is no matching rule for the unfiltered call now, so the engine's
// implicit deny takes it.
func TestNegativeGuardCannotBeBypassedByOmission(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, listGuardRules))
	seedWinRMTarget(t, srv, "vault-prod", "vault-pw")
	seedWinRMTarget(t, srv, "ordinary-host", "other-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-omit", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	// The guarded form still works: a target the block-list does not name.
	_, ok := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok,
		map[string]any{"tool": "list_credentials", "args": map[string]any{"target": "ordinary-host"}})
	if got := jsonMap(t, ok)["status"]; got != "executed" {
		t.Fatalf("an allowed, filtered listing should still run, got %v: %s", got, ok)
	}

	// The bypass: omit the argument the rule guards.
	_, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok,
		map[string]any{"tool": "list_credentials", "args": map[string]any{}})
	if got := jsonMap(t, d)["status"]; got != "denied" {
		t.Fatalf("omitting the guarded argument must NOT satisfy `not_in` — that is the bypass; got %v: %s", got, d)
	}
	if strings.Contains(string(d), "vault-prod") {
		t.Fatal("the unfiltered listing leaked the very target the rule block-lists")
	}

	// The same bypass, one character heavier: an EMPTY target is "present" as far
	// as the policy engine is concerned — so it satisfies the block-list — while
	// the tool reads it as "no filter" and lists everything. Closing the omission
	// hole without closing this one would have moved the exploit, not fixed it.
	_, e := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok,
		map[string]any{"tool": "list_credentials", "args": map[string]any{"target": ""}})
	me := jsonMap(t, e)
	if me["status"] != "failed" || !strings.Contains(me["reason"].(string), "must not be empty") {
		t.Fatalf("an empty filter must be refused, not read as `no filter`: %s", e)
	}
	if strings.Contains(string(e), "vault-prod") {
		t.Fatal("an empty filter listed the block-listed target")
	}
}

// TestToolCallRejectsUndeclaredArgument proves an argument the tool does not
// declare is refused rather than ignored.
//
// Ignoring it is the friendlier behaviour and the worse one: the policy engine
// only inspects fields a rule names, so an undeclared argument is a value that
// reached the system through no guard at all — and a typo'd argument name
// silently becomes "not supplied", which for a tool with an optional filter is
// the difference between listing one thing and listing everything.
func TestToolCallRejectsUndeclaredArgument(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, allowAnyExecRules))
	seedWinRMTarget(t, srv, "win-arg", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-arg", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	_, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{
		"tool": "winrm_exec",
		"args": map[string]any{"target": "win-arg", "command": "whoami", "shell": "cmd"},
	})
	m := jsonMap(t, d)
	if m["status"] != "failed" || !strings.Contains(strings.ToLower(m["reason"].(string)), "unknown argument") {
		t.Fatalf("an undeclared argument must be refused, got: %s", d)
	}
	if fake.gotPass != "" {
		t.Fatal("the tool ran despite an argument it never declared")
	}

	// A missing REQUIRED argument is refused too, rather than reaching the tool as
	// an empty string.
	_, d2 := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{
		"tool": "winrm_exec", "args": map[string]any{"target": "win-arg"},
	})
	m2 := jsonMap(t, d2)
	if m2["status"] != "failed" || !strings.Contains(strings.ToLower(m2["reason"].(string)), "missing required") {
		t.Fatalf("a missing required argument must be refused, got: %s", d2)
	}
}

// TestToolCallRejectsWrongArgumentType proves a value whose type does not match
// the declared schema is refused before the policy engine evaluates the call.
//
// This is not tidiness. The policy engine compares a STRINGIFIED argument while
// the tool reads the raw JSON value, so a type the two disagree about is a value
// a rule can be made to match while the tool does something else with it
// entirely. Validating first means the engine always judges the same types the
// tool will act on.
func TestToolCallRejectsWrongArgumentType(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, allowAnyExecRules))
	seedWinRMTarget(t, srv, "win-typ", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-typ", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	for _, c := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"a number where a string is declared", map[string]any{"target": 42, "command": "whoami"}, "must be a string"},
		{"an object where a string is declared", map[string]any{"target": map[string]any{"x": 1}, "command": "whoami"}, "must be a string"},
		{"a list where a string is declared", map[string]any{"target": []any{"a"}, "command": "whoami"}, "must be a string"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok,
				map[string]any{"tool": "winrm_exec", "args": c.args})
			m := jsonMap(t, d)
			if m["status"] != "failed" || !strings.Contains(m["reason"].(string), c.want) {
				t.Fatalf("want a %q refusal, got: %s", c.want, d)
			}
			if fake.gotPass != "" {
				t.Fatal("the tool ran on an argument of the wrong type")
			}
		})
	}
}

// TestUnknownToolIsStillDenied pins the ordering the validation had to preserve:
// a tool nothing has registered has no schema to check against, so it must fall
// through to the policy decision and be DENIED by the implicit default — not
// reported as a validation failure. Fail-closed is the more important answer of
// the two, and it is the one an auditor reads.
func TestUnknownToolIsStillDenied(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, allowAnyExecRules))
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-unk", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	_, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok,
		map[string]any{"tool": "delete_everything", "args": map[string]any{"really": true}})
	if got := jsonMap(t, d)["status"]; got != "denied" {
		t.Fatalf("an unregistered tool must be denied by the implicit default, got %v: %s", got, d)
	}
}

// TestMCPReportsDenialAsAnError proves an MCP client is told the truth about a
// refusal.
//
// `isError` previously covered only transport-ish failures, so a policy denial
// came back flagged false — and a client that trusts the flag (which is what the
// flag is for) reads that as "the tool ran and returned some text". An agent
// looping on "did that work?" would conclude yes. A call parked for approval is
// deliberately still not an error: it has not failed, it is waiting for a human.
func TestMCPReportsDenialAsAnError(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, denyRules))
	seedWinRMTarget(t, srv, "win-err", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-err", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	_, d := doBearer(t, srv, http.MethodPost, "/mcp", tok, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "winrm_exec", "arguments": map[string]any{"target": "win-err", "command": "whoami"}},
	})
	if !strings.Contains(string(d), `"isError":true`) || !strings.Contains(string(d), "denied") {
		t.Fatalf("a denied tool call must come back flagged as an error: %s", d)
	}

	// The parked case, for contrast, on a server whose policy parks the call.
	fake2 := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv2, _ := newTestServerOpts(t, nil, brokerOpts(t, fake2, approvalRules))
	seedWinRMTarget(t, srv2, "win-park", "vault-pw")
	_, ad2 := do(t, srv2, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-park", "owner": "a"})
	tok2, _ := jsonMap(t, ad2)["token"].(string)
	_, p := doBearer(t, srv2, http.MethodPost, "/mcp", tok2, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "winrm_exec", "arguments": map[string]any{"target": "win-park", "command": "whoami"}},
	})
	if strings.Contains(string(p), `"isError":true`) {
		t.Fatalf("a call awaiting a human approver has not failed and must not be flagged an error: %s", p)
	}
}

// TestMCPToolsListDeclaresRequiredArguments proves the advertised JSON Schema
// says which arguments a client must send — so a well-behaved client can get the
// call right the first time instead of discovering it from a refusal.
func TestMCPToolsListDeclaresRequiredArguments(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, allowAnyExecRules))
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-schema", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	_, d := doBearer(t, srv, http.MethodPost, "/mcp", tok,
		map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	body := string(d)
	if !strings.Contains(body, `"required":["command","target"]`) {
		t.Fatalf("winrm_exec must advertise both its arguments as required: %s", body)
	}
	// list_credentials' target is optional (omitting it is a legitimate, if wide,
	// inventory read), so it must NOT be advertised as required — and the tool
	// with no arguments at all must not carry an empty `required` list.
	for _, unwanted := range []string{`"required":["target"]`, `"required":[]`} {
		if strings.Contains(body, unwanted) {
			t.Fatalf("unexpected %s in the advertised schema: %s", unwanted, body)
		}
	}
}
