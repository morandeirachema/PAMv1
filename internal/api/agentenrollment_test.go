package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/winrm"
)

// svidServer builds a broker server that accepts one undelegated SVID, with
// enrollment optionally required.
func svidServer(t *testing.T, spiffeID string, requireEnrolled bool) (*httptest.Server, string) {
	t.Helper()
	// mintDelegatedSVID gives a chain; for enrollment the presenter is what
	// matters, and passing the same id as its own actor keeps depth at 0.
	svid, verifier := mintDelegatedSVID(t, spiffeID, "")
	opts := brokerOpts(t, &fakeWinRM{result: winrm.Result{Stdout: "ok"}}, toolsetRules)
	opts.BrokerSVIDVerifier = verifier
	opts.BrokerRequireEnrolledSVID = requireEnrolled
	srv, _ := newTestServerOpts(t, nil, opts)
	return srv, svid
}

// TestSVIDInventoryBuildsItself is Phase 174's first half: pamv1 records every
// attested identity that authenticates, so the inventory exists whether or not
// anyone remembered to enrol one.
//
// A static agent key is knowable by definition — pamv1 minted it. An SVID is the
// opposite: any workload the trust domain vouches for may call, and until this
// phase pamv1 knew only about the ones an admin had typed into the owner
// registry. That matters because every containment control built for this
// identity kind (quarantine, four-eyes, the offboarding cascade) keys on a
// SUBJECT a responder must be able to name.
func TestSVIDInventoryBuildsItself(t *testing.T) {
	const id = "spiffe://example.org/ns/prod/sa/unknown-worker"
	srv, svid := svidServer(t, id, false)

	// It authenticates — enrollment is not required — and the call runs.
	if st, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", svid,
		map[string]any{"tool": "list_targets"}); st != http.StatusOK {
		t.Fatalf("an unenrolled identity should still work by default: %d %s", st, d)
	}

	_, ld := do(t, srv, http.MethodGet, "/v1/agents/identities", testAPIKey, nil)
	rows := jsonRows(t, ld)
	if len(rows) != 1 || rows[0]["spiffe_id"] != id {
		t.Fatalf("the identity that called should be inventoried: %s", ld)
	}
	if rows[0]["enrolled"] != false || rows[0]["owner"] != "" {
		t.Fatalf("a discovered row is seen, not claimed: %s", ld)
	}
	if rows[0]["first_seen"] == nil || rows[0]["last_seen"] == nil {
		t.Fatalf("both sighting stamps should be set: %s", ld)
	}
	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if !strings.Contains(string(aud), "agent.identity_first_seen") {
		t.Fatalf("a first sighting should be audited once: %s", aud)
	}

	// A second call does not create a second row, and does not re-audit.
	if st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", svid,
		map[string]any{"tool": "list_targets"}); st != http.StatusOK {
		t.Fatal("the second call should work too")
	}
	_, ld2 := do(t, srv, http.MethodGet, "/v1/agents/identities", testAPIKey, nil)
	if len(jsonRows(t, ld2)) != 1 {
		t.Fatalf("a repeat sighting must not add a row: %s", ld2)
	}
	_, aud2 := do(t, srv, http.MethodGet, "/api/audit?limit=80", testAPIKey, nil)
	if n := strings.Count(string(aud2), "agent.identity_first_seen"); n != 1 {
		t.Fatalf("a first sighting is audited once, got %d", n)
	}

	// Registering the identity ADOPTS the discovered row rather than colliding
	// with it — otherwise the inventory would tell an operator about an identity
	// they then could not claim.
	if st, d := do(t, srv, http.MethodPost, "/v1/agents/identities", testAPIKey,
		map[string]any{"spiffe_id": id, "owner": "carol", "note": "prod worker"}); st != http.StatusCreated {
		t.Fatalf("registering a discovered identity should adopt it: %d %s", st, d)
	}
	_, ld3 := do(t, srv, http.MethodGet, "/v1/agents/identities", testAPIKey, nil)
	rows3 := jsonRows(t, ld3)
	if len(rows3) != 1 || rows3[0]["enrolled"] != true || rows3[0]["owner"] != "carol" ||
		rows3[0]["first_seen"] == nil {
		t.Fatalf("adoption should enrol the same row and keep its first sighting: %s", ld3)
	}
	// A second registration of an already-enrolled identity is a real conflict.
	if st, _ := do(t, srv, http.MethodPost, "/v1/agents/identities", testAPIKey,
		map[string]any{"spiffe_id": id, "owner": "dave"}); st != http.StatusConflict {
		t.Fatal("re-registering an enrolled identity should 409")
	}
}

// TestRequireEnrolledSVIDRefusesTheUnclaimed is the opt-in half: with
// PAM_BROKER_REQUIRE_ENROLLED_SVID set, the trust domain's word is necessary but
// no longer sufficient — somebody must have claimed the identity.
//
// The refusal still records the sighting, deliberately: the operator enrols FROM
// the inventory, so an identity that knocked and was turned away has to appear
// in the list they are looking at.
func TestRequireEnrolledSVIDRefusesTheUnclaimed(t *testing.T) {
	const id = "spiffe://example.org/ns/prod/sa/stranger"
	srv, svid := svidServer(t, id, true)

	if st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", svid,
		map[string]any{"tool": "list_targets"}); st != http.StatusUnauthorized {
		t.Fatal("an unenrolled identity must be refused when enrollment is required")
	}
	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if !strings.Contains(string(aud), "agent.not_enrolled") {
		t.Fatalf("the refusal should be audited: %s", aud)
	}
	_, ld := do(t, srv, http.MethodGet, "/v1/agents/identities", testAPIKey, nil)
	if rows := jsonRows(t, ld); len(rows) != 1 || rows[0]["enrolled"] != false {
		t.Fatalf("a refused identity must still be listed, so it can be enrolled: %s", ld)
	}

	// Enrol it, and the same credential works.
	if st, d := do(t, srv, http.MethodPost, "/v1/agents/identities", testAPIKey,
		map[string]any{"spiffe_id": id, "owner": "carol"}); st != http.StatusCreated {
		t.Fatalf("enrolling: %d %s", st, d)
	}
	if st, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", svid,
		map[string]any{"tool": "list_targets"}); st != http.StatusOK {
		t.Fatalf("an enrolled identity should be admitted: %d %s", st, d)
	}

	// A static agent key is unaffected: pamv1 issued it, so there is nothing to
	// enrol and requiring enrollment must not lock the other identity kind out.
	_, tok := mintAgent(t, srv, "static-bot", "alice", nil)
	if st, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok,
		map[string]any{"tool": "list_targets"}); st != http.StatusOK {
		t.Fatalf("a static key must be unaffected by SVID enrollment: %d %s", st, d)
	}
}

// TestDiscoveredIdentityIsUnattributedForFourEyes pins the interaction with
// Phase 170: an inventory row with no owner must refuse an approval exactly as a
// missing row does. A row existing is not the same as somebody answering for it,
// and a four-eyes gate satisfied by an empty string would be worse than none.
func TestDiscoveredIdentityIsUnattributedForFourEyes(t *testing.T) {
	const id = "spiffe://example.org/ns/prod/sa/parker"
	svid, verifier := mintDelegatedSVID(t, id, "")
	opts := brokerOpts(t, &fakeWinRM{result: winrm.Result{Stdout: "ok"}}, approvalRules)
	opts.BrokerSVIDVerifier = verifier
	srv, _ := newTestServerOpts(t, nil, opts)
	seedWinRMTarget(t, srv, "win-parked", "pw")

	callID := parkSVIDCall(t, srv, svid, "win-parked")
	// The call itself created the inventory row (unowned).
	_, ld := do(t, srv, http.MethodGet, "/v1/agents/identities", testAPIKey, nil)
	if rows := jsonRows(t, ld); len(rows) != 1 || rows[0]["owner"] != "" {
		t.Fatalf("the calling identity should be inventoried unowned: %s", ld)
	}
	if st, d := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey,
		map[string]any{"approve": true}); st != http.StatusForbidden {
		t.Fatalf("an unowned inventory row must not establish four-eyes: %d %s", st, d)
	}
	// Adopting it — naming an owner — is what makes the decision possible.
	if st, d := do(t, srv, http.MethodPost, "/v1/agents/identities", testAPIKey,
		map[string]any{"spiffe_id": id, "owner": "carol"}); st != http.StatusCreated {
		t.Fatalf("adopting: %d %s", st, d)
	}
	if st, d := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey,
		map[string]any{"approve": true}); st != http.StatusOK {
		t.Fatalf("once owned, the parked call is decidable: %d %s", st, d)
	}
}

// TestDelegationChainIsInventoried covers the inventory gap a fresh pass found
// in Phase 174's own code: only the presenting identity was recorded.
//
// The controls that read the inventory read the whole chain — quarantine walks
// it (169), four-eyes resolves an owner for every link (170) — so a delegating
// root that never calls pamv1 directly had no row at all. An operator could not
// enrol it from the list, and every approval of a call it delegated was refused
// as unattributed until they typed the SPIFFE ID by hand.
func TestDelegationChainIsInventoried(t *testing.T) {
	const (
		root = "spiffe://example.org/ns/prod/sa/root-planner"
		sub  = "spiffe://example.org/ns/prod/sa/sub-worker"
	)
	svid, verifier := mintDelegatedSVID(t, sub, root)
	opts := brokerOpts(t, &fakeWinRM{result: winrm.Result{Stdout: "ok"}}, toolsetRules)
	opts.BrokerSVIDVerifier = verifier
	srv, _ := newTestServerOpts(t, nil, opts)

	if st, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", svid,
		map[string]any{"tool": "list_targets"}); st != http.StatusOK {
		t.Fatalf("delegated call: %d %s", st, d)
	}

	_, ld := do(t, srv, http.MethodGet, "/v1/agents/identities", testAPIKey, nil)
	seen := map[string]bool{}
	for _, row := range jsonRows(t, ld) {
		seen[row["spiffe_id"].(string)] = true
	}
	if !seen[sub] || !seen[root] {
		t.Fatalf("both the presenter and the actor it acts for should be inventoried: %s", ld)
	}
	// The trail says how pamv1 learned about an identity that never called it.
	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if !strings.Contains(string(aud), "via:") {
		t.Fatalf("a chain member's first sighting should name the presenter: %s", aud)
	}

	// The last-seen stamp is damped, so a busy agent does not rewrite its rows
	// on every call: a second call within the interval changes nothing and adds
	// no second first-sighting record.
	if st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", svid,
		map[string]any{"tool": "list_targets"}); st != http.StatusOK {
		t.Fatal("second call should work")
	}
	_, aud2 := do(t, srv, http.MethodGet, "/api/audit?limit=80", testAPIKey, nil)
	if n := strings.Count(string(aud2), "agent.identity_first_seen"); n != 2 {
		t.Fatalf("two identities, one first sighting each, got %d", n)
	}
	_, ld2 := do(t, srv, http.MethodGet, "/v1/agents/identities", testAPIKey, nil)
	if len(jsonRows(t, ld2)) != 2 {
		t.Fatalf("no extra rows from a repeat call: %s", ld2)
	}
}
