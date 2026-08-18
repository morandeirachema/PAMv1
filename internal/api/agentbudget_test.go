package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/winrm"
)

// budgetServer stands up a broker server that allows winrm_exec unconditionally,
// with a default per-agent daily budget of def (0 = unlimited), and returns the
// server plus a registered agent's token and key id.
func budgetServer(t *testing.T, def int) (srv *httptest.Server, token string, keyID int64) {
	t.Helper()
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	opts := brokerOpts(t, fake, allowAnyExecRules)
	opts.BrokerBudgetPerDay = def
	ts, _ := newTestServerOpts(t, nil, opts)
	seedWinRMTarget(t, ts, "win-bud", "vault-pw")
	_, ad := do(t, ts, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-bud", "owner": "a"})
	m := jsonMap(t, ad)
	tok, _ := m["token"].(string)
	id, _ := m["id"].(float64)
	return ts, tok, int64(id)
}

// budgetCall makes one brokered tool call and returns its outcome map.
func budgetCall(t *testing.T, srv *httptest.Server, token string) map[string]any {
	t.Helper()
	_, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", token,
		map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-bud", "command": "whoami"}})
	return jsonMap(t, d)
}

// TestBudgetStopsAnAgentARateLimitCannotStop is the phase in one test.
//
// A per-minute rate limit bounds bursts and nothing else: an agent capped at 60
// calls a minute may still make 86,400 privileged calls a day, and nobody chose
// that number. The budget is the total, and once it is spent the agent is
// refused with a reason that says so rather than a generic denial.
func TestBudgetStopsAnAgentARateLimitCannotStop(t *testing.T) {
	srv, tok, _ := budgetServer(t, 2)
	for i := 1; i <= 2; i++ {
		if got := budgetCall(t, srv, tok)["status"]; got != "executed" {
			t.Fatalf("call %d should run inside the budget, got %v", i, got)
		}
	}
	out := budgetCall(t, srv, tok)
	if out["status"] != "denied" {
		t.Fatalf("the call past the budget must be denied, got %v", out["status"])
	}
	reason, _ := out["reason"].(string)
	if !strings.Contains(reason, "budget") {
		t.Fatalf("the refusal must say it was the budget, not just 'denied': %q", reason)
	}

	// And it is audited under its own action, because "this agent hit its
	// ceiling" is a thing to alert on directly — as often a sign the budget is
	// set too low as a sign the agent is running away.
	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=80", testAPIKey, nil)
	if !strings.Contains(string(aud), "agent.budget_exhausted") {
		t.Fatalf("the exhaustion must be audited under its own action: %s", aud)
	}
}

// TestPerAgentBudgetOverridesTheServerDefault proves the per-agent value wins,
// in both directions, and that clearing it returns the agent to the default.
func TestPerAgentBudgetOverridesTheServerDefault(t *testing.T) {
	srv, tok, keyID := budgetServer(t, 0) // server default: unlimited

	// Unlimited by default: several calls all run.
	for i := 0; i < 3; i++ {
		if got := budgetCall(t, srv, tok)["status"]; got != "executed" {
			t.Fatalf("with no budget configured every call should run, got %v", got)
		}
	}
	// Give this one agent a budget it has already spent.
	if st, d := do(t, srv, http.MethodPost, "/v1/agents/"+strconv.FormatInt(keyID, 10)+"/budget", testAPIKey,
		map[string]any{"budget_per_day": 1}); st != http.StatusNoContent {
		t.Fatalf("set budget: %d %s", st, d)
	}
	if got := budgetCall(t, srv, tok)["status"]; got != "denied" {
		t.Fatalf("a per-agent budget must override an unlimited default, got %v", got)
	}
	// Clearing it (explicit null, not omission) puts the agent back on the
	// server default — which here is unlimited.
	if st, d := do(t, srv, http.MethodPost, "/v1/agents/"+strconv.FormatInt(keyID, 10)+"/budget", testAPIKey,
		map[string]any{"budget_per_day": nil}); st != http.StatusNoContent {
		t.Fatalf("clear budget: %d %s", st, d)
	}
	if got := budgetCall(t, srv, tok)["status"]; got != "executed" {
		t.Fatalf("clearing the budget must restore the default, got %v", got)
	}
}

// TestBudgetZeroIsAHardStop pins the distinction the pointer exists for: an
// explicit 0 means "this agent may make no calls at all", which must not be
// confused with "unset, use the default" — those two would be the same value in
// a plain int, and the difference is between a deliberate hard stop and an
// agent with no limit at all.
func TestBudgetZeroIsAHardStop(t *testing.T) {
	srv, tok, keyID := budgetServer(t, 0) // default unlimited
	if st, d := do(t, srv, http.MethodPost, "/v1/agents/"+strconv.FormatInt(keyID, 10)+"/budget", testAPIKey,
		map[string]any{"budget_per_day": 0}); st != http.StatusNoContent {
		t.Fatalf("set zero budget: %d %s", st, d)
	}
	if got := budgetCall(t, srv, tok)["status"]; got != "denied" {
		t.Fatalf("an explicit zero budget must refuse every call, got %v", got)
	}
}

// TestBudgetDoesNotBlockCollectingAnApprovedResult proves the budget bounds NEW
// work only.
//
// Refusing to hand over the result of a call a human already approved would hide
// the output while keeping the side effect — the same trap the result cap avoids
// by truncating rather than failing. The work is done; the budget's job was to
// decide whether it should start.
func TestBudgetDoesNotBlockCollectingAnApprovedResult(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "done", ExitCode: 0}}
	opts := brokerOpts(t, fake, approvalRules)
	opts.BrokerBudgetPerDay = 1
	srv, _ := newTestServerOpts(t, nil, opts)
	seedWinRMTarget(t, srv, "win-ap-bud", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-ap-bud", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	_, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok,
		map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-ap-bud", "command": "whoami"}})
	m := jsonMap(t, d)
	callID, _ := m["call_id"].(string)
	resume, _ := m["resume_token"].(string)
	if m["status"] != "pending_approval" || callID == "" || resume == "" {
		t.Fatalf("want a parked call: %s", d)
	}
	if st, dd := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey,
		map[string]any{"approve": true}); st != http.StatusOK {
		t.Fatalf("approve: %d %s", st, dd)
	}
	// The execution has now spent the agent's single call. Collecting it must
	// still work.
	st, rd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls/"+callID+"/resume", tok,
		map[string]any{"token": resume})
	if st != http.StatusOK || jsonMap(t, rd)["status"] != "executed" {
		t.Fatalf("collecting an approved result must not be refused for budget: %d %s", st, rd)
	}
}

// TestAgentListingReportsBudgetUsage proves an operator can see who is close to
// their ceiling before they hit it — the screen is the point of the feature as
// much as the refusal is.
func TestAgentListingReportsBudgetUsage(t *testing.T) {
	srv, tok, _ := budgetServer(t, 5)
	budgetCall(t, srv, tok)
	budgetCall(t, srv, tok)

	_, data := do(t, srv, http.MethodGet, "/v1/agents", testAPIKey, nil)
	var list []struct {
		Name                 string `json:"name"`
		BudgetPerDay         *int   `json:"budget_per_day"`
		BudgetUsedToday      int    `json:"budget_used_today"`
		BudgetLimitEffective int    `json:"budget_limit_effective"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatalf("listing: %v (%s)", err, data)
	}
	var found bool
	for _, a := range list {
		if a.Name != "bot-bud" {
			continue
		}
		found = true
		if a.BudgetUsedToday != 2 {
			t.Fatalf("used should be 2, got %d", a.BudgetUsedToday)
		}
		if a.BudgetLimitEffective != 5 {
			t.Fatalf("the effective limit should be the server default (5), got %d", a.BudgetLimitEffective)
		}
		if a.BudgetPerDay != nil {
			t.Fatalf("an agent riding the default must report no per-agent budget, got %v", *a.BudgetPerDay)
		}
	}
	if !found {
		t.Fatalf("the agent is missing from the listing: %s", data)
	}
}

// TestSetBudgetAuthorization pins that changing a budget is an administrative
// act: an agent must never be able to raise its own ceiling, which would make
// the control decorative.
func TestSetBudgetAuthorization(t *testing.T) {
	srv, tok, keyID := budgetServer(t, 1)
	req := map[string]any{"budget_per_day": 1000}
	if st, _ := doBearer(t, srv, http.MethodPost, "/v1/agents/"+strconv.FormatInt(keyID, 10)+"/budget", tok, req); st == http.StatusNoContent {
		t.Fatal("an agent's own bearer token must not be able to raise its budget")
	}
	if st, d := do(t, srv, http.MethodPost, "/v1/agents/"+strconv.FormatInt(keyID, 10)+"/budget", testAPIKey, req); st != http.StatusNoContent {
		t.Fatalf("an admin must be able to set it: %d %s", st, d)
	}
	// And a nonsense value is refused rather than stored.
	if st, _ := do(t, srv, http.MethodPost, "/v1/agents/"+strconv.FormatInt(keyID, 10)+"/budget", testAPIKey,
		map[string]any{"budget_per_day": -1}); st != http.StatusUnprocessableEntity {
		t.Fatalf("a negative budget must be refused, got %d", st)
	}
}
