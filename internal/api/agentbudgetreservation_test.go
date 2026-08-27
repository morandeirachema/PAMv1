package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/morandeirachema/pamv1/internal/winrm"
)

// Phase 219 — the 2026-08-26 audit's M-3, reservation half. The daily budget
// and the per-token ceiling were count-then-call: each call counted the audit
// trail and then ran, so a burst arriving together all read the same count and
// the limit over-ran by the burst's width. A reservation written at the instant
// of the decision, under the store's own serialisation, is the compare-and-spend
// the counts could not be. These tests pin the property and the bookkeeping
// around it; each was verified to fail with the reservation removed.

// rawBudgetCall is budgetCall without t.Fatalf, so it can run in a goroutine:
// a transport error is returned as an empty status rather than failing the test
// from the wrong goroutine.
func rawBudgetCall(srv *httptest.Server, token, tool string) (string, string) {
	body, _ := json.Marshal(map[string]any{"tool": tool, "args": map[string]any{"target": "win-bud", "command": "whoami"}})
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/tool-calls", bytes.NewReader(body))
	if err != nil {
		return "", err.Error()
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err.Error()
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	status, _ := m["status"].(string)
	reason, _ := m["reason"].(string)
	return status, reason
}

// TestBudgetBurstAtTheBoundaryCannotOverrun is the phase in one test: twelve
// calls arrive together against a budget of two, and exactly two execute.
// Before the reservation every one of them counted zero spent calls, and the
// budget was a suggestion under load.
func TestBudgetBurstAtTheBoundaryCannotOverrun(t *testing.T) {
	srv, tok, _ := budgetServer(t, 2)
	const burst = 12
	var wg sync.WaitGroup
	statuses := make(chan [2]string, burst)
	start := make(chan struct{})
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s, r := rawBudgetCall(srv, tok, "winrm_exec")
			statuses <- [2]string{s, r}
		}()
	}
	close(start)
	wg.Wait()
	close(statuses)
	executed, denied := 0, 0
	for sr := range statuses {
		switch sr[0] {
		case "executed":
			executed++
		case "denied":
			denied++
			if !strings.Contains(sr[1], "budget") {
				t.Fatalf("a refused call must say it was the budget: %q", sr[1])
			}
		default:
			t.Fatalf("unexpected outcome %q (%s)", sr[0], sr[1])
		}
	}
	if executed != 2 || denied != burst-2 {
		t.Fatalf("a burst of %d against a budget of 2: %d executed, %d denied; want exactly 2 and %d", burst, executed, denied, burst-2)
	}
}

// TestRefusedCallGivesItsBudgetSlotBack: a reservation is made before the
// broker decides, so a call the policy then refuses must release it — the
// budget's own contract is that denials and failures never consume it.
func TestRefusedCallGivesItsBudgetSlotBack(t *testing.T) {
	srv, tok, _ := budgetServer(t, 1)
	// ssh_exec is not allowed by the fixture's policy: denied, and free.
	if s, r := rawBudgetCall(srv, tok, "ssh_exec"); s != "denied" || strings.Contains(r, "budget") {
		t.Fatalf("the policy refusal must not be a budget refusal: %s %q", s, r)
	}
	if s, r := rawBudgetCall(srv, tok, "winrm_exec"); s != "executed" {
		t.Fatalf("the one budgeted call must still run after a refused one: %s %q", s, r)
	}
	if s, r := rawBudgetCall(srv, tok, "winrm_exec"); s != "denied" || !strings.Contains(r, "budget") {
		t.Fatalf("and the budget is then spent: %s %q", s, r)
	}
}

// approvalBudgetServer is budgetServer under a policy that parks every
// winrm_exec for human approval.
func approvalBudgetServer(t *testing.T, def int) (*httptest.Server, string) {
	t.Helper()
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	opts := brokerOpts(t, fake, approvalRules)
	opts.BrokerBudgetPerDay = def
	srv, _ := newTestServerOpts(t, nil, opts)
	seedWinRMTarget(t, srv, "win-bud", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-bud-ap", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)
	return srv, tok
}

// TestParkedCallHoldsItsBudgetSlot: a call parked for approval is requested
// work, and it holds its slot while it waits. Before the reservation the trail
// counted a parked call only once it was collected, and the approval path never
// re-checked — so an agent could park any number of calls under a budget of one
// and have them all approved.
func TestParkedCallHoldsItsBudgetSlot(t *testing.T) {
	srv, tok := approvalBudgetServer(t, 1)
	if s, r := rawBudgetCall(srv, tok, "winrm_exec"); s != "pending_approval" {
		t.Fatalf("first call must park: %s %q", s, r)
	}
	if s, r := rawBudgetCall(srv, tok, "winrm_exec"); s != "denied" || !strings.Contains(r, "budget") {
		t.Fatalf("a second call while the first holds the only slot must be refused for budget: %s %q", s, r)
	}
}

// TestApproverDenialGivesTheBudgetSlotBack: the approver says no, the call did
// no work, and the slot it held comes back — the same rule a policy refusal
// follows, one hop later.
func TestApproverDenialGivesTheBudgetSlotBack(t *testing.T) {
	srv, tok := approvalBudgetServer(t, 1)
	_, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok,
		map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-bud", "command": "whoami"}})
	m := jsonMap(t, d)
	callID, _ := m["call_id"].(string)
	if m["status"] != "pending_approval" || callID == "" {
		t.Fatalf("want a parked call: %s", d)
	}
	if st, dd := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey,
		map[string]any{"approve": false}); st != http.StatusOK {
		t.Fatalf("deny: %d %s", st, dd)
	}
	if s, r := rawBudgetCall(srv, tok, "winrm_exec"); s != "pending_approval" {
		t.Fatalf("after the approver's denial the slot must be free again: %s %q", s, r)
	}
}
