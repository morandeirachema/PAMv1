package api_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/winrm"
)

// brokerVendorRules allows winrm_exec, rotate_credential and reveal_credential,
// so the test can prove the vendor-contract gate refuses each one on its own:
// the policy layer says yes, and the account-scoped contract gate still says no.
const brokerVendorRules = `
rules:
  - id: allow-winrm
    tool: winrm_exec
    effect: allow
  - id: allow-rotate
    tool: rotate_credential
    effect: allow
  - id: allow-reveal
    tool: reveal_credential
    effect: allow
`

// TestBrokerVendorContractGate proves the Phase 29 vendor-contract gate binds
// the agent-broker tools exactly as it binds every operator path: an agent
// identity that is also a registered vendor reaches a target account only while
// an approved, in-window contract grant covers it — for winrm_exec (the
// target-tools path) and for reveal_credential/rotate_credential (the
// credential-tools path). Refusals surface in the main audit trail under the
// same access.denied/vendor-contract vocabulary the proxies use, so SIEM
// export and risk analytics see broker refusals too.
func TestBrokerVendorContractGate(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	srv, st := newTestServerOpts(t, nil, brokerOpts(t, fake, brokerVendorRules))
	seedWinRMTarget(t, srv, "win-vend", "vaulted-pw")
	creds, err := st.ListCredentials(context.Background(), 0, 0, 0)
	if err != nil || len(creds) != 1 {
		t.Fatalf("seed creds: %v %d", err, len(creds))
	}
	credID := creds[0].ID

	// The agent identity doubles as a registered vendor: same username.
	vc, vd := do(t, srv, http.MethodPost, "/api/vendors", testAPIKey, map[string]any{"username": "vend-bot", "org": "ACME"})
	if vc != http.StatusCreated {
		t.Fatalf("create vendor: %d %s", vc, vd)
	}
	vendorID := int64(jsonMap(t, vd)["id"].(float64))
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "vend-bot", "owner": "alice"})
	tok, _ := jsonMap(t, ad)["token"].(string)
	if tok == "" {
		t.Fatalf("no agent token: %s", ad)
	}

	call := func(tool string, args map[string]any) (map[string]any, string) {
		t.Helper()
		_, rd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": tool, "args": args})
		return jsonMap(t, rd), string(rd)
	}
	winrmArgs := map[string]any{"target": "win-vend", "command": "whoami"}
	credArgs := map[string]any{"credential_id": credID}

	// Without a contract grant, every policy-allowed tool is refused by the gate.
	for _, tool := range []string{"winrm_exec", "reveal_credential", "rotate_credential"} {
		args := credArgs
		if tool == "winrm_exec" {
			args = winrmArgs
		}
		if m, raw := call(tool, args); m["status"] != "failed" || !strings.Contains(raw, "vendor access requires") {
			t.Fatalf("%s without a contract grant should be refused by the vendor gate: %s", tool, raw)
		}
	}
	if fake.gotPass != "" {
		t.Fatal("a refused winrm_exec still reached the runner with a credential")
	}

	// The refusals landed in the main audit trail under the shared vocabulary.
	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if !strings.Contains(string(aud), "access.denied") || !strings.Contains(string(aud), "vendor-contract") {
		t.Fatalf("vendor refusal missing from the audit trail: %s", aud)
	}

	// File a contract grant for the credential's account and approve it.
	nb := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	na := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	gc, gd := do(t, srv, http.MethodPost, fmt.Sprintf("/api/vendors/%d/grants", vendorID), testAPIKey, map[string]any{
		"target": "win-vend", "principal": "svc", "not_before": nb, "not_after": na,
	})
	if gc != http.StatusCreated {
		t.Fatalf("create grant: %d %s", gc, gd)
	}
	grantID := int64(jsonMap(t, gd)["id"].(float64))
	approver := seedUser(t, srv, "customer-appr", "approver")
	if code, apd := do(t, srv, http.MethodPost, fmt.Sprintf("/api/vendor-grants/%d/approve", grantID), approver, nil); code != http.StatusOK {
		t.Fatalf("approve grant: %d %s", code, apd)
	}

	// In-window, the same calls pass the gate.
	if m, raw := call("winrm_exec", winrmArgs); m["status"] != "executed" {
		t.Fatalf("winrm_exec inside the contract window: %s", raw)
	}
	if fake.gotPass != "vaulted-pw" {
		t.Fatalf("runner got password %q, want the vaulted secret", fake.gotPass)
	}
	if m, raw := call("reveal_credential", credArgs); m["status"] != "executed" {
		t.Fatalf("reveal_credential inside the contract window: %s", raw)
	}
}
