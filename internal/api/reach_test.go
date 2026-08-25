package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	Blocked   []string       `json:"blocked"`
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

// hasBlocked reports whether a reason appears in an answer's blocked list.
func hasBlocked(a reachAnswer, reason string) bool {
	for _, b := range a.Blocked {
		if b == reason {
			return true
		}
	}
	return false
}

// getReach asks the review route and decodes the answer, failing the test on
// anything but 200.
func getReach(t *testing.T, srv *httptest.Server, query string) reachAnswer {
	t.Helper()
	status, body := do(t, srv, http.MethodGet, "/api/access/reach?"+query, testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("reach(%s): status %d body %s", query, status, body)
	}
	var a reachAnswer
	if err := json.Unmarshal(body, &a); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return a
}

// TestSubjectReachBlocked pins the half of the answer that says the count
// OVERSTATES what the subject can do today (Phase 191).
//
// Every case here used to report a clean list of reachable targets with nothing
// marking it: an auditor holds no capability that can use a target at all, a
// SCIM-deprovisioned user's token no longer resolves, a revoked or expired agent
// key no longer authenticates, and a quarantined identity is stopped outright.
// The targets are still reported in each case — a suspended account's grants are
// still grants — but a reviewer has to be told, because these are the states in
// which the bare total is wrong in the dangerous direction.
func TestSubjectReachBlocked(t *testing.T) {
	srv, st := newTestServerStore(t)
	seedReachEstate(t, st)
	ctx := context.Background()

	// A user with grants and the capability to use them: nothing blocks it.
	seedUser(t, srv, "reach-alice", "user")
	if a := getReach(t, srv, "subject=reach-alice"); len(a.Blocked) != 0 {
		t.Errorf("an ordinary user should have nothing blocking it: %v", a.Blocked)
	}

	// An auditor "reaches" every ungated target and every auditor-role grant,
	// and can act on none of them: it holds read_inventory and read_audit only.
	seedUser(t, srv, "reach-auditor", "auditor")
	aud := getReach(t, srv, "subject=reach-auditor")
	if !hasBlocked(aud, "no_usable_capability") {
		t.Errorf("an auditor cannot use any target it reaches: %+v", aud)
	}
	if aud.Total == 0 {
		t.Errorf("the standing entitlement is still reported, only annotated: %+v", aud)
	}

	// SCIM deprovisioning: the row survives so re-activating restores access,
	// which is exactly why the entitlement is still listed — and why it must
	// not read as live.
	seedUser(t, srv, "reach-gone", "user")
	u, err := st.GetUserByUsername(ctx, "reach-gone")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if err := st.UpdateUserActive(ctx, u.ID, false); err != nil {
		t.Fatalf("UpdateUserActive: %v", err)
	}
	if a := getReach(t, srv, "subject=reach-gone"); !hasBlocked(a, "deactivated") {
		t.Errorf("a deprovisioned user must be flagged: %+v", a)
	}

	// A revoked static key — what a certification campaign's revoke produces.
	revoked := &store.AgentKey{Name: "reach-revoked", Owner: "alice", TokenHash: "reach-h1"}
	if err := st.CreateAgentKey(ctx, revoked); err != nil {
		t.Fatalf("CreateAgentKey: %v", err)
	}
	if err := st.SetAgentKeyDisabled(ctx, revoked.ID, true); err != nil {
		t.Fatalf("SetAgentKeyDisabled: %v", err)
	}
	a := getReach(t, srv, "subject=reach-revoked&kind=agent")
	if !a.Known || a.AgentKind != "key" || !hasBlocked(a, "key_disabled") {
		t.Errorf("a revoked agent key must be found AND flagged: %+v", a)
	}

	// A key past its hard end date.
	past := time.Now().Add(-time.Hour)
	if err := st.CreateAgentKey(ctx, &store.AgentKey{
		Name: "reach-expired", Owner: "alice", TokenHash: "reach-h2", ExpiresAt: &past,
	}); err != nil {
		t.Fatalf("CreateAgentKey(expired): %v", err)
	}
	if a := getReach(t, srv, "subject=reach-expired&kind=agent"); !hasBlocked(a, "key_expired") {
		t.Errorf("an expired agent key must be flagged: %+v", a)
	}

	// Quarantine is checked for EVERY agent subject, including one no registry
	// lists — that is the case where a reviewer most needs to be told, since
	// there is no row anywhere else to carry the state.
	if err := st.QuarantineAgent(ctx, &store.AgentQuarantine{
		Subject: "reach-stopped", Reason: "test", CreatedBy: "test",
	}); err != nil {
		t.Fatalf("QuarantineAgent: %v", err)
	}
	q := getReach(t, srv, "subject=reach-stopped&kind=agent")
	if q.Known {
		t.Errorf("this subject is in no registry: %+v", q)
	}
	if !hasBlocked(q, "quarantined") {
		t.Errorf("a quarantined agent must be flagged even when unknown: %+v", q)
	}

	// An agent key with an explicit per-day budget of ZERO: not "unset" (nil,
	// which takes the server default) but a deliberate hard stop of no calls at
	// all. It stops the subject exactly as a disabled key does.
	zero := 0
	if err := st.CreateAgentKey(ctx, &store.AgentKey{
		Name: "reach-nobudget", Owner: "alice", TokenHash: "reach-h3", BudgetPerDay: &zero,
	}); err != nil {
		t.Fatalf("CreateAgentKey(zero budget): %v", err)
	}
	if a := getReach(t, srv, "subject=reach-nobudget&kind=agent"); !hasBlocked(a, "budget_zero") {
		t.Errorf("a zero-budget agent key must be flagged: %+v", a)
	}

	// An attested identity pamv1 recorded on sight and nobody has claimed.
	// SeeAgentIdentity is the path that builds that row; enrolment is what
	// claiming it means (an operator-registered identity is enrolled already).
	//
	// With PAM_BROKER_REQUIRE_ENROLLED_SVID OFF — the default — being unenrolled
	// blocks NOTHING: that identity authenticates and reaches every ungated
	// target, which is exactly the finding this review exists to surface. Saying
	// it is blocked would understate its reach, the one direction this whole
	// field is meant to prevent.
	if _, err := st.SeeAgentIdentity(ctx, "spiffe://example.org/ns/prod/sa/seen", time.Now()); err != nil {
		t.Fatalf("SeeAgentIdentity: %v", err)
	}
	if a := getReach(t, srv, "subject=spiffe://example.org/ns/prod/sa/seen&kind=agent"); hasBlocked(a, "not_enrolled") {
		t.Errorf("with enrollment not required, unenrolled blocks nothing: %+v", a)
	}
}

// TestSubjectReachNotEnrolledOnlyWhenRequired is the other half: the same
// identity, on a deployment that actually refuses unenrolled SVIDs. The flag is
// what turns "unclaimed" into "stopped", so it is what the flag must follow.
func TestSubjectReachNotEnrolledOnlyWhenRequired(t *testing.T) {
	// The flag lives on the broker wiring, which setupBroker skips entirely when
	// no policy is supplied — so a broker-enabled options set is what actually
	// turns it on.
	opts := brokerOpts(t, &fakeWinRM{}, toolsetRules)
	opts.BrokerRequireEnrolledSVID = true
	srv, st := newTestServerOpts(t, nil, opts)
	seedReachEstate(t, st)
	ctx := context.Background()

	if _, err := st.SeeAgentIdentity(ctx, "spiffe://example.org/ns/prod/sa/seen", time.Now()); err != nil {
		t.Fatalf("SeeAgentIdentity: %v", err)
	}
	if a := getReach(t, srv, "subject=spiffe://example.org/ns/prod/sa/seen&kind=agent"); !hasBlocked(a, "not_enrolled") {
		t.Errorf("with enrollment required, an unclaimed identity is stopped: %+v", a)
	}
}

// TestSubjectReachExpiryBoundary pins the expiry comparison against the one the
// auth path uses. store.AgentKey.Active treats now == ExpiresAt as expired
// (now.Before(exp) is false), so a hand-written ExpiresAt.Before(now) would
// disagree at exactly that instant — which is why the handler decomposes
// Active rather than re-deriving it.
func TestSubjectReachExpiryBoundary(t *testing.T) {
	srv, st := newTestServerStore(t)
	seedReachEstate(t, st)
	ctx := context.Background()

	exp := time.Now().Add(-time.Nanosecond)
	if err := st.CreateAgentKey(ctx, &store.AgentKey{
		Name: "reach-edge", Owner: "alice", TokenHash: "reach-h4", ExpiresAt: &exp,
	}); err != nil {
		t.Fatalf("CreateAgentKey: %v", err)
	}
	a := getReach(t, srv, "subject=reach-edge&kind=agent")
	if !hasBlocked(a, "key_expired") {
		t.Errorf("a key at or past its expiry must be flagged: %+v", a)
	}
	if hasBlocked(a, "key_disabled") {
		t.Errorf("expired is not disabled — the two reasons must stay distinct: %+v", a)
	}
}
