package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/winrm"
)

// jsonRows unmarshals a JSON array body into a slice of objects, failing the
// test on error.
func jsonRows(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	var rows []map[string]any
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatalf("unmarshal %q: %v", data, err)
	}
	return rows
}

// parkSVIDCall drives a delegated SVID agent's tool call to pending_approval and
// returns the parked call's id, so a four-eyes assertion can be made about the
// decision rather than about the call.
func parkSVIDCall(t *testing.T, srv *httptest.Server, svid, target string) string {
	t.Helper()
	_, pd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", svid,
		map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": target, "command": "whoami"}})
	m := jsonMap(t, pd)
	if m["status"] != "pending_approval" {
		t.Fatalf("want pending_approval, got: %s", pd)
	}
	callID, _ := m["call_id"].(string)
	if callID == "" {
		t.Fatalf("no call id: %s", pd)
	}
	return callID
}

// svidApprovalServer builds a broker server that accepts a delegated SVID and
// parks winrm_exec for a human decision, plus a target to call.
func svidApprovalServer(t *testing.T, sub, root string) (*httptest.Server, string) {
	t.Helper()
	svid, verifier := mintDelegatedSVID(t, sub, root)
	opts := brokerOpts(t, &fakeWinRM{result: winrm.Result{Stdout: "ok"}}, approvalRules)
	opts.BrokerSVIDVerifier = verifier
	srv, _ := newTestServerOpts(t, nil, opts)
	seedWinRMTarget(t, srv, "win-owner", "pw")
	return srv, svid
}

// TestFourEyesHoldsOnTheSPIFFEPath is Phase 170's flagship.
//
// The gate compares a parked call's accountable owner against the approving
// human's username. For an SVID-authenticated agent that owner was a SPIFFE ID,
// which can never equal a person's name — so the refusal could not fire, and the
// human operating an agent could approve their own agent's privileged call
// single-handed, in the deployment posture the roadmap calls the intended one.
// It is the Phase 159 bug's shape exactly: the least-trusted actor got the
// weakest gate.
func TestFourEyesHoldsOnTheSPIFFEPath(t *testing.T) {
	const (
		root = "spiffe://example.org/ns/prod/sa/planner"
		sub  = "spiffe://example.org/ns/prod/sa/worker"
	)
	srv, svid := svidApprovalServer(t, sub, root)

	// Register both links of the chain. The approving human — the bootstrap
	// admin, whose actor name is "bootstrap-admin" — owns the ROOT, not the
	// agent that actually made the call, which is the case a presenter-only
	// check would miss.
	for spiffeID, owner := range map[string]string{root: "bootstrap-admin", sub: "carol"} {
		if st, d := do(t, srv, http.MethodPost, "/v1/agents/identities", testAPIKey,
			map[string]any{"spiffe_id": spiffeID, "owner": owner}); st != http.StatusCreated {
			t.Fatalf("register %s: %d %s", spiffeID, st, d)
		}
	}

	callID := parkSVIDCall(t, srv, svid, "win-owner")
	if st, d := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey,
		map[string]any{"approve": true}); st != http.StatusForbidden {
		t.Fatalf("the owner of an agent in the chain must not approve its call: want 403, got %d %s", st, d)
	}
	// The call is still parked and still decidable — a refused self-approval
	// must not consume it.
	_, ld := do(t, srv, http.MethodGet, "/v1/approvals", testAPIKey, nil)
	if !strings.Contains(string(ld), callID) {
		t.Fatalf("a refused self-approval must leave the call parked: %s", ld)
	}
	// Hand the root over to somebody else and the same approver may decide: the
	// refusal is about ownership, not about the approver.
	_, idl := do(t, srv, http.MethodGet, "/v1/agents/identities", testAPIKey, nil)
	rootID := int64(0)
	for _, row := range jsonRows(t, idl) {
		if row["spiffe_id"] == root {
			rootID = int64(row["id"].(float64))
		}
	}
	if rootID == 0 {
		t.Fatalf("registered root not listed: %s", idl)
	}
	if st, d := do(t, srv, http.MethodPost, "/v1/agents/identities/"+itoa(rootID)+"/owner", testAPIKey,
		map[string]any{"owner": "dave"}); st != http.StatusNoContent {
		t.Fatalf("reassign owner: %d %s", st, d)
	}
	if st, d := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey,
		map[string]any{"approve": true}); st != http.StatusOK {
		t.Fatalf("an approver who owns none of the chain must be able to decide: %d %s", st, d)
	}
}

// TestApprovalRefusedWhenSPIFFEAgentHasNoOwner pins the fail-closed half: an
// attested agent nobody has claimed cannot have its calls approved at all.
//
// Four-eyes cannot be proven when one side of it is unknown — the same stance
// Phase 159 took when it made an owner mandatory at agent-key creation, applied
// to the identity kind that is admitted by the trust domain rather than created
// here. The call stays parked, so recording an owner unblocks it rather than
// forcing the agent to ask again.
func TestApprovalRefusedWhenSPIFFEAgentHasNoOwner(t *testing.T) {
	const (
		root = "spiffe://example.org/ns/prod/sa/planner"
		sub  = "spiffe://example.org/ns/prod/sa/worker"
	)
	srv, svid := svidApprovalServer(t, sub, root)
	callID := parkSVIDCall(t, srv, svid, "win-owner")

	st, d := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey,
		map[string]any{"approve": true})
	if st != http.StatusForbidden {
		t.Fatalf("an unattributed SPIFFE agent's call must not be approvable: want 403, got %d %s", st, d)
	}
	if !strings.Contains(string(d), "no recorded owner") {
		t.Fatalf("the refusal should say what is missing: %s", d)
	}
	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if !strings.Contains(string(aud), "agent-has-no-owner") {
		t.Fatalf("the refusal should be on the trail: %s", aud)
	}

	// Registering owners for the whole chain unblocks the SAME parked call.
	for _, spiffeID := range []string{root, sub} {
		if st, d := do(t, srv, http.MethodPost, "/v1/agents/identities", testAPIKey,
			map[string]any{"spiffe_id": spiffeID, "owner": "carol", "note": "prod release agent"}); st != http.StatusCreated {
			t.Fatalf("register %s: %d %s", spiffeID, st, d)
		}
	}
	if st, d := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey,
		map[string]any{"approve": true}); st != http.StatusOK {
		t.Fatalf("once an owner exists the parked call is decidable: %d %s", st, d)
	}
}

// TestOffboardingQuarantinesOwnedSPIFFEIdentities proves the cascade covers both
// identity kinds. Deleting a human suspends the agent KEYS they owned (Phase
// 159), which reaches nothing for an attested agent — it has no key row. The
// equivalent stop for that kind is quarantine, so that is what the cascade uses.
func TestOffboardingQuarantinesOwnedSPIFFEIdentities(t *testing.T) {
	const owned = "spiffe://example.org/ns/prod/sa/carol-bot"
	const other = "spiffe://example.org/ns/prod/sa/team-bot"
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, &fakeWinRM{}, brokerRules))

	st, ud := do(t, srv, http.MethodPost, "/api/users", testAPIKey,
		map[string]any{"username": "carol", "role": "user"})
	if st != http.StatusCreated {
		t.Fatalf("create user: %d %s", st, ud)
	}
	uid := int64(jsonMap(t, ud)["id"].(float64))
	for spiffeID, owner := range map[string]string{owned: "carol", other: "dave"} {
		if st, d := do(t, srv, http.MethodPost, "/v1/agents/identities", testAPIKey,
			map[string]any{"spiffe_id": spiffeID, "owner": owner}); st != http.StatusCreated {
			t.Fatalf("register %s: %d %s", spiffeID, st, d)
		}
	}

	if st, d := do(t, srv, http.MethodDelete, "/api/users/"+itoa(uid), testAPIKey, nil); st != http.StatusNoContent {
		t.Fatalf("delete user: %d %s", st, d)
	}
	_, ql := do(t, srv, http.MethodGet, "/v1/agents/quarantine", testAPIKey, nil)
	if !strings.Contains(string(ql), owned) {
		t.Fatalf("the departing owner's SPIFFE identity must be quarantined: %s", ql)
	}
	if strings.Contains(string(ql), other) {
		t.Fatalf("somebody else's identity must be left alone: %s", ql)
	}
	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if !strings.Contains(string(aud), "reason:owner-offboarded") {
		t.Fatalf("the cascade should be audited: %s", aud)
	}
}

// TestAgentIdentityRegistryValidation covers the registry's own edges: only a
// SPIFFE ID may be registered (a static key carries its owner on its own row),
// one identity has exactly one owner, and the routes need manage_users.
func TestAgentIdentityRegistryValidation(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, &fakeWinRM{}, brokerRules))
	const id = "spiffe://example.org/ns/prod/sa/planner"

	if st, d := do(t, srv, http.MethodPost, "/v1/agents/identities", testAPIKey,
		map[string]any{"spiffe_id": "deploy-bot", "owner": "carol"}); st != http.StatusUnprocessableEntity {
		t.Fatalf("a static key name is not a SPIFFE ID: want 422, got %d %s", st, d)
	}
	if st, d := do(t, srv, http.MethodPost, "/v1/agents/identities", testAPIKey,
		map[string]any{"spiffe_id": id}); st != http.StatusUnprocessableEntity {
		t.Fatalf("an owner is the whole point of the row: want 422, got %d %s", st, d)
	}
	if st, _ := do(t, srv, http.MethodPost, "/v1/agents/identities", testAPIKey,
		map[string]any{"spiffe_id": id, "owner": "carol"}); st != http.StatusCreated {
		t.Fatal("registering an identity should succeed")
	}
	if st, _ := do(t, srv, http.MethodPost, "/v1/agents/identities", testAPIKey,
		map[string]any{"spiffe_id": id, "owner": "dave"}); st != http.StatusConflict {
		t.Fatal("one identity has one owner: a second registration is a conflict")
	}
	if st, _ := do(t, srv, http.MethodDelete, "/v1/agents/identities/999999", testAPIKey, nil); st != http.StatusNotFound {
		t.Fatal("deleting an unknown registration should 404")
	}

	// Every route needs manage_users, like the rest of the agent surface.
	_, td := do(t, srv, http.MethodPost, "/api/users", testAPIKey,
		map[string]any{"username": "reader", "role": "auditor"})
	userTok, _ := jsonMap(t, td)["token"].(string)
	for _, c := range []struct {
		method, path string
		body         map[string]any
	}{
		{http.MethodPost, "/v1/agents/identities", map[string]any{"spiffe_id": "spiffe://example.org/x", "owner": "carol"}},
		{http.MethodGet, "/v1/agents/identities", nil},
		{http.MethodPost, "/v1/agents/identities/1/owner", map[string]any{"owner": "dave"}},
		{http.MethodDelete, "/v1/agents/identities/1", nil},
	} {
		if st, d := do(t, srv, c.method, c.path, userTok, c.body); st != http.StatusForbidden {
			t.Fatalf("%s %s as an auditor: want 403, got %d %s", c.method, c.path, st, d)
		}
	}
}
