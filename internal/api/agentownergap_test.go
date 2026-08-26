package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/winrm"
)

// TestOwnerKnownMatchesTheControlItReportsOn is the fix for the defect this
// sweep found in Phase 175's own code.
//
// `owner_known` exists to say "the offboarding cascade can reach this agent".
// The cascade matches an owner as a literal string (`WHERE owner = $1`), and so
// does every other owner lookup in PAMv1 — but the flag was computed
// case-insensitively. An agent owned by "Carol" while the user is "carol" was
// reported as fine and is, in fact, unreachable: deleting carol suspends
// nothing. A flag that claims a reachability the control does not have is the
// same failure class as a dead field that reads like a control.
func TestOwnerKnownMatchesTheControlItReportsOn(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, &fakeWinRM{}, brokerRules))
	seedUser(t, srv, "carol", "user")
	mintAgent(t, srv, "exact-bot", "carol", nil)
	mintAgent(t, srv, "case-bot", "Carol", nil)

	_, kl := do(t, srv, http.MethodGet, "/v1/agents", testAPIKey, nil)
	var keys []map[string]any
	if err := json.Unmarshal(kl, &keys); err != nil {
		t.Fatalf("agent listing: %v (%s)", err, kl)
	}
	for _, k := range keys {
		want := k["name"] == "exact-bot"
		if k["owner_known"] != want {
			t.Fatalf("owner_known for %v should be %v — the flag must match the exact-string lookup the cascade uses: %+v",
				k["name"], want, k)
		}
	}

	// And the claim is true in the direction that matters: deleting the user
	// reaches the exactly-owned agent and not the case-mismatched one.
	_, ul := do(t, srv, http.MethodGet, "/api/users", testAPIKey, nil)
	var users []map[string]any
	if err := json.Unmarshal(ul, &users); err != nil {
		t.Fatalf("user listing: %v (%s)", err, ul)
	}
	var carolID int64
	for _, u := range users {
		if u["username"] == "carol" {
			carolID = int64(u["id"].(float64))
		}
	}
	if carolID == 0 {
		t.Fatalf("seeded user not found: %s", ul)
	}
	if st, d := do(t, srv, http.MethodDelete, "/api/users/"+itoa(carolID), testAPIKey, nil); st != http.StatusNoContent {
		t.Fatalf("delete user: %d %s", st, d)
	}
	_, after := do(t, srv, http.MethodGet, "/v1/agents", testAPIKey, nil)
	var post []map[string]any
	if err := json.Unmarshal(after, &post); err != nil {
		t.Fatal(err)
	}
	for _, k := range post {
		suspended := k["disabled"] == true
		if want := k["name"] == "exact-bot"; suspended != want {
			t.Fatalf("offboarding should reach %v == %v (this is what owner_known promises): %+v",
				k["name"], want, k)
		}
	}
}

// TestFourEyesRecordsWhatItCouldNotVerify covers the gap the same finding
// exposed on the decision path: the gate refuses when owner == approver, so an
// owner nobody holds can never match and the real owner may approve their own
// agent's call — four-eyes silently not applying, which is worse than four-eyes
// visibly absent.
//
// PAMv1 does not guess. The decision proceeds and the trail says the second pair
// of eyes could not be established; a deployment that wants the stricter reading
// sets PAM_BROKER_REQUIRE_KNOWN_OWNER.
func TestFourEyesRecordsWhatItCouldNotVerify(t *testing.T) {
	park := func(t *testing.T, requireKnown bool) (string, *httptest.Server) {
		t.Helper()
		opts := brokerOpts(t, &fakeWinRM{result: winrm.Result{Stdout: "ok"}}, approvalRules)
		opts.BrokerRequireKnownOwner = requireKnown
		srv, _ := newTestServerOpts(t, nil, opts)
		seedWinRMTarget(t, srv, "win-owner-gap", "pw")
		// Owned by a name no PAMv1 user holds — a typo, or a team address.
		_, tok := mintAgent(t, srv, "orphan-bot", "platform-team", nil)
		_, pd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok,
			map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-owner-gap", "command": "id"}})
		m := jsonMap(t, pd)
		if m["status"] != "pending_approval" {
			t.Fatalf("want pending_approval: %s", pd)
		}
		return m["call_id"].(string), srv
	}

	// Default: the decision goes through, and the trail records that four-eyes
	// was unverified rather than pretending it held.
	callID, srv := park(t, false)
	if st, d := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey,
		map[string]any{"approve": true}); st != http.StatusOK {
		t.Fatalf("an unrecognised owner must not block by default: %d %s", st, d)
	}
	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if !strings.Contains(string(aud), "broker.approval.four_eyes_unverified") ||
		!strings.Contains(string(aud), "platform-team") {
		t.Fatalf("the trail must say four-eyes could not be established, and name the owner: %s", aud)
	}

	// Opt in, and the same decision is refused instead.
	callID2, srv2 := park(t, true)
	st, d := do(t, srv2, http.MethodPost, "/v1/approvals/"+callID2+"/decision", testAPIKey,
		map[string]any{"approve": true})
	if st != http.StatusForbidden || !strings.Contains(string(d), "not a PAMv1 user") {
		t.Fatalf("with PAM_BROKER_REQUIRE_KNOWN_OWNER the decision must be refused: %d %s", st, d)
	}
	// Refused, not consumed: the call is still there for somebody to decide once
	// the owner is corrected.
	_, ld := do(t, srv2, http.MethodGet, "/v1/approvals", testAPIKey, nil)
	if !strings.Contains(string(ld), callID2) {
		t.Fatalf("a refused decision must leave the call parked: %s", ld)
	}
}
