package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
)

// seedReachEstate builds the estate the reach tests read: one ungated target,
// one granted to alice by name, one granted to the auditor role, and one in a
// safe alice is a member of.
func seedReachEstate(t *testing.T, st store.Store) {
	t.Helper()
	ctx := context.Background()
	sf := &store.Safe{Name: "reach-safe"}
	if err := st.CreateSafe(ctx, sf); err != nil {
		t.Fatalf("CreateSafe: %v", err)
	}
	// Assign the safe in its own call — CreateTarget does not persist SafeID
	// (see store.TargetStore.CreateTarget).
	mk := func(name string, safeID *int64) int64 {
		tg := &store.Target{Name: name, Host: "10.0.0.1", Port: 22, OSType: "linux", Protocol: "ssh"}
		if err := st.CreateTarget(ctx, tg); err != nil {
			t.Fatalf("CreateTarget(%s): %v", name, err)
		}
		if safeID != nil {
			if err := st.AssignTargetSafe(ctx, tg.ID, safeID); err != nil {
				t.Fatalf("AssignTargetSafe(%s): %v", name, err)
			}
		}
		return tg.ID
	}
	mk("reach-ungated", nil)
	granted := mk("reach-granted", nil)
	roleGranted := mk("reach-role", nil)
	mk("reach-insafe", &sf.ID)

	for _, g := range []store.TargetGrant{
		{TargetID: granted, SubjectType: "user", Subject: "reach-alice"},
		{TargetID: roleGranted, SubjectType: "role", Subject: "auditor"},
	} {
		gg := g
		if err := st.CreateTargetGrant(ctx, &gg); err != nil {
			t.Fatalf("CreateTargetGrant: %v", err)
		}
	}
	m := &store.SafeMember{SafeID: sf.ID, SubjectType: "user", Subject: "reach-alice"}
	if err := st.AddSafeMember(ctx, m); err != nil {
		t.Fatalf("AddSafeMember: %v", err)
	}
}

// reachAnswer is the decoded response shape (the handler's own struct is
// unexported, and a test that re-declares it also pins the wire contract).
type reachAnswer struct {
	Subject   string         `json:"subject"`
	Kind      string         `json:"kind"`
	Known     bool           `json:"known"`
	AgentKind string         `json:"agent_kind"`
	Roles     []string       `json:"roles"`
	Total     int            `json:"total"`
	Counts    map[string]int `json:"counts"`
	Targets   []struct {
		Target      string `json:"target"`
		Via         string `json:"via"`
		SubjectType string `json:"subject_type"`
		Subject     string `json:"subject"`
		Safe        string `json:"safe"`
	} `json:"targets"`
}

// TestSubjectReach walks the subject-indexed review end to end: a user's own
// grants, the role grants it inherits, safe membership, and the targets nothing
// gates — each reported with the reason it is reachable, which is the half a
// yes/no connect gate cannot give a reviewer.
func TestSubjectReach(t *testing.T) {
	srv, st := newTestServerStore(t)
	seedReachEstate(t, st)
	auditorTok := seedUser(t, srv, "reach-alice", "auditor")

	status, body := do(t, srv, http.MethodGet, "/api/access/reach?subject=reach-alice", auditorTok, nil)
	if status != http.StatusOK {
		t.Fatalf("reach: status %d body %s", status, body)
	}
	var got reachAnswer
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if !got.Known || got.Kind != "user" {
		t.Fatalf("unexpected identity in the answer: %+v", got)
	}
	via := map[string]string{}
	for _, tg := range got.Targets {
		via[tg.Target] = tg.Via
	}
	for name, want := range map[string]string{
		"reach-ungated": "open",
		"reach-granted": "grant",
		"reach-role":    "grant", // the auditor role grant
		"reach-insafe":  "safe",
	} {
		if via[name] != want {
			t.Errorf("%s reachable via %q, want %q (answer: %+v)", name, via[name], want, got)
		}
	}
	if got.Total != len(got.Targets) || got.Total != 4 {
		t.Errorf("total = %d with %d rows, want 4", got.Total, len(got.Targets))
	}
	if got.Counts["open"] != 1 || got.Counts["grant"] != 2 || got.Counts["safe"] != 1 {
		t.Errorf("counts = %v", got.Counts)
	}
	// The safe-derived row names the safe, so the reviewer can act on it.
	for _, tg := range got.Targets {
		if tg.Target == "reach-insafe" && tg.Safe != "reach-safe" {
			t.Errorf("safe-derived reach does not name its safe: %+v", tg)
		}
		if tg.Target == "reach-role" && (tg.SubjectType != "role" || tg.Subject != "auditor") {
			t.Errorf("role grant not reported as one: %+v", tg)
		}
	}

	// A user with no grants at all still reaches whatever nothing gates — and
	// the answer says so, rather than reporting an empty estate.
	seedUser(t, srv, "reach-bob", "user")
	status, body = do(t, srv, http.MethodGet, "/api/access/reach?subject=reach-bob", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("reach(bob): status %d body %s", status, body)
	}
	var bob reachAnswer
	if err := json.Unmarshal(body, &bob); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bob.Total != 1 || bob.Targets[0].Target != "reach-ungated" || bob.Targets[0].Via != "open" {
		t.Fatalf("a user with no grants should reach exactly the ungated target: %+v", bob)
	}

	// An admin reaches everything, and the reason is the bypass rather than a
	// grant nobody wrote.
	status, body = do(t, srv, http.MethodGet, "/api/access/reach?subject=reach-admin", testAPIKey, nil)
	if status != http.StatusNotFound {
		t.Fatalf("unknown local user: status %d body %s, want 404", status, body)
	}
	seedUser(t, srv, "reach-admin", "admin")
	status, body = do(t, srv, http.MethodGet, "/api/access/reach?subject=reach-admin", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("reach(admin): status %d body %s", status, body)
	}
	var admin reachAnswer
	if err := json.Unmarshal(body, &admin); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if admin.Total != 4 || admin.Counts["admin"] != 4 {
		t.Fatalf("an admin should reach every target by role bypass: %+v", admin)
	}

	// The query is audited: asking who can reach what across the whole estate is
	// itself a reviewable act.
	events, err := st.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Action == "access.reach_query" {
			found = true
		}
	}
	if !found {
		t.Error("the reach query appended no audit event")
	}
}

// TestSubjectReachAgent covers the agent side, including the case Phase 174's
// inventory left open: a workload nobody has enrolled still reaches every
// ungated target, and the answer must say so rather than refuse the question.
func TestSubjectReachAgent(t *testing.T) {
	srv, st := newTestServerStore(t)
	seedReachEstate(t, st)

	status, body := do(t, srv, http.MethodGet,
		"/api/access/reach?subject=spiffe://example.org/ns/prod/sa/planner&kind=agent", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("reach(agent): status %d body %s", status, body)
	}
	var unknown reachAnswer
	if err := json.Unmarshal(body, &unknown); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if unknown.Known {
		t.Errorf("an unregistered SPIFFE ID must be reported as unknown: %+v", unknown)
	}
	if unknown.Total != 1 || unknown.Targets[0].Via != "open" {
		t.Errorf("an unknown agent reaches what nothing gates: %+v", unknown)
	}

	// Once registered, the same question names the accountable owner.
	if err := st.CreateAgentIdentity(context.Background(), &store.AgentIdentity{
		SPIFFEID: "spiffe://example.org/ns/prod/sa/planner", Owner: "alice",
		Enrolled: true, CreatedBy: "test",
	}); err != nil {
		t.Fatalf("CreateAgentIdentity: %v", err)
	}
	status, body = do(t, srv, http.MethodGet,
		"/api/access/reach?subject=spiffe://example.org/ns/prod/sa/planner&kind=agent", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("reach(registered agent): status %d body %s", status, body)
	}
	var known reachAnswer
	if err := json.Unmarshal(body, &known); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !known.Known || known.AgentKind != "identity" {
		t.Errorf("a registered SPIFFE identity should be found: %+v", known)
	}
}

// TestSubjectReachAuthz pins the gate and the argument validation: the review is
// a CapReadAudit read, and a subject is required.
func TestSubjectReachAuthz(t *testing.T) {
	srv, st := newTestServerStore(t)
	seedReachEstate(t, st)
	userTok := seedUser(t, srv, "reach-plain", "user")

	if status, _ := do(t, srv, http.MethodGet, "/api/access/reach?subject=reach-plain", userTok, nil); status != http.StatusForbidden {
		t.Errorf("a plain user may not review who reaches what: status %d, want 403", status)
	}
	if status, _ := do(t, srv, http.MethodGet, "/api/access/reach", testAPIKey, nil); status != http.StatusBadRequest {
		t.Errorf("missing subject: status %d, want 400", status)
	}
	if status, _ := do(t, srv, http.MethodGet, "/api/access/reach?subject=x&kind=group", testAPIKey, nil); status != http.StatusBadRequest {
		t.Errorf("unknown kind: status %d, want 400", status)
	}
}
