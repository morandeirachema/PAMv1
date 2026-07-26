package api_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/cmdguard"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// denyGuard compiles a guard for the tests, failing loudly on a bad pattern.
func denyGuard(t *testing.T, patterns ...string) *cmdguard.Guard {
	t.Helper()
	g, err := cmdguard.New(patterns)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// blockedAudit reports whether a command.blocked event naming pattern was
// recorded for the given target.
func blockedAudit(t *testing.T, st store.Store, target, pattern string) bool {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == "command.blocked" &&
			strings.Contains(e.Detail, "target:"+target) &&
			strings.Contains(e.Detail, "pattern:"+pattern) {
			return true
		}
	}
	return false
}

// TestWinRMRunCommandBlocked proves the REST WinRM endpoint honors the command
// denylist: the command is refused with 403, the audit records it with the
// matched pattern, and — the point of the fix — it never reaches the target.
// Before Phase 38 the guard lived only in the session proxies, so a pattern
// blocked for an operator's `ssh target "cmd"` ran freely through this endpoint.
func TestWinRMRunCommandBlocked(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "should never run", ExitCode: 0}}
	srv, st := newTestServerOpts(t, nil, api.Options{
		WinRM:        fake,
		RecordingDir: t.TempDir(),
		CommandGuard: denyGuard(t, `(?i)format\s+c:`),
	})

	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "win-guard", "host": "10.0.0.5", "port": 5986, "os_type": "windows", "protocol": "winrm",
	})
	targetID := int64(jsonMap(t, data)["id"].(float64))
	if code, body := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": targetID, "username": "Administrator", "secret": "vaulted-pw",
	}); code != http.StatusCreated {
		t.Fatalf("seed credential: %d %s", code, body)
	}

	runURL := fmt.Sprintf("/api/targets/%d/winrm", targetID)
	if code, body := do(t, srv, http.MethodPost, runURL, testAPIKey,
		map[string]any{"command": "format C: /q"}); code != http.StatusForbidden {
		t.Fatalf("blocked command: status %d body %s, want 403", code, body)
	}
	if fake.gotCmd != "" {
		t.Fatalf("the blocked command reached the target: %q", fake.gotCmd)
	}
	if fake.gotPass != "" {
		t.Fatal("the credential was decrypted for a command that was refused")
	}
	if !blockedAudit(t, st, "win-guard", `(?i)format\s+c:`) {
		t.Fatal("no command.blocked audit event for the refused WinRM run")
	}

	// A command that matches nothing still runs.
	if code, body := do(t, srv, http.MethodPost, runURL, testAPIKey,
		map[string]any{"command": "whoami"}); code != http.StatusOK {
		t.Fatalf("allowed command: status %d body %s, want 200", code, body)
	}
	if fake.gotCmd != "whoami" {
		t.Fatalf("runner got %q, want whoami", fake.gotCmd)
	}
}

// TestBrokerWinRMCommandBlocked proves an AI agent gets the same treatment as a
// human: the broker's winrm_exec shares execWinRM, so the denylist refuses the
// call before any credential is decrypted.
func TestBrokerWinRMCommandBlocked(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "should never run", ExitCode: 0}}
	opts := brokerOpts(t, fake, brokerRules)
	opts.CommandGuard = denyGuard(t, `(?i)format\s+c:`)
	srv, st := newTestServerOpts(t, nil, opts)
	seedWinRMTarget(t, srv, "win-01", "vaulted-pw")

	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-guard", "owner": "alice"})
	agentTok, _ := jsonMap(t, ad)["token"].(string)

	status, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", agentTok, map[string]any{
		"tool": "winrm_exec",
		"args": map[string]any{"target": "win-01", "command": "format C: /q"},
	})
	if status != http.StatusOK {
		t.Fatalf("tool call transport: %d %s", status, data)
	}
	if m := jsonMap(t, data); m["status"] == "executed" {
		t.Fatalf("a blocked command was executed for an agent: %s", data)
	}
	if fake.gotCmd != "" {
		t.Fatalf("the blocked command reached the target: %q", fake.gotCmd)
	}
	if !blockedAudit(t, st, "win-01", `(?i)format\s+c:`) {
		t.Fatal("no command.blocked audit event for the refused agent tool call")
	}
}

// TestBrokerSSHExecCommandBlocked proves ssh_exec is guarded too. The target
// address is unroutable, so a passing test also shows the refusal happened
// BEFORE the dial: a guard that ran late would surface a connection error
// instead of the policy refusal.
func TestBrokerSSHExecCommandBlocked(t *testing.T) {
	opts := brokerOpts(t, &fakeWinRM{}, brokerSSHRules)
	opts.CommandGuard = denyGuard(t, `rm\s+-rf`)
	srv, st := newTestServerOpts(t, nil, opts)

	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "lin-01", "host": "192.0.2.1", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	targetID := int64(jsonMap(t, td)["id"].(float64))
	if code, body := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": targetID, "username": "root", "secret": "vaulted-pw",
	}); code != http.StatusCreated {
		t.Fatalf("seed credential: %d %s", code, body)
	}

	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-ssh", "owner": "alice"})
	agentTok, _ := jsonMap(t, ad)["token"].(string)

	status, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", agentTok, map[string]any{
		"tool": "ssh_exec",
		"args": map[string]any{"target": "lin-01", "command": "rm -rf /"},
	})
	if status != http.StatusOK {
		t.Fatalf("tool call transport: %d %s", status, data)
	}
	m := jsonMap(t, data)
	if m["status"] == "executed" {
		t.Fatalf("a blocked command was executed: %s", data)
	}
	if !strings.Contains(strings.ToLower(string(data)), "blocked") {
		t.Fatalf("expected a policy refusal, got: %s", data)
	}
	if !blockedAudit(t, st, "lin-01", `rm\s+-rf`) {
		t.Fatal("no command.blocked audit event for the refused ssh_exec")
	}
}

// brokerSSHRules allows ssh_exec so the guard, not the policy engine, is what
// refuses the call under test.
const brokerSSHRules = `
rules:
  - id: allow-ssh
    tool: ssh_exec
    effect: allow
    scope: "target:{target}:exec"
    ttl_seconds: 60
`
