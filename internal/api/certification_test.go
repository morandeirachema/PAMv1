package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// campaignItem mirrors the fields the test inspects.
type campaignItem struct {
	ID          int64  `json:"id"`
	Kind        string `json:"kind"`
	Subject     string `json:"subject"`
	SubjectType string `json:"subject_type"`
	Decision    string `json:"decision"`
}

// TestCertificationCampaign proves a campaign snapshots current access, a revoke
// decision deletes the underlying grant, certify keeps it, and a closed campaign
// refuses further decisions.
func TestCertificationCampaign(t *testing.T) {
	srv := newTestServer(t)

	// A target with a grant, and a safe with a member — the access to review.
	tc, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-cert", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if tc != http.StatusCreated {
		t.Fatalf("create target: %d %s", tc, td)
	}
	targetID := int64(jsonMap(t, td)["id"].(float64))
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", targetID), testAPIKey,
		map[string]any{"subject_type": "role", "subject": "user"}); code != http.StatusCreated {
		t.Fatalf("create grant: %d", code)
	}
	sc, sd := do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{"name": "cert-safe"})
	if sc != http.StatusCreated {
		t.Fatalf("create safe: %d %s", sc, sd)
	}
	safeID := int64(jsonMap(t, sd)["id"].(float64))
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeID), testAPIKey,
		map[string]any{"subject_type": "role", "subject": "auditor"}); code != http.StatusCreated {
		t.Fatalf("add safe member: %d", code)
	}

	// Create the campaign — it snapshots both access items.
	cc, cd := do(t, srv, http.MethodPost, "/api/campaigns", testAPIKey, map[string]any{"name": "Q3 review"})
	if cc != http.StatusCreated {
		t.Fatalf("create campaign: %d %s", cc, cd)
	}
	m := jsonMap(t, cd)
	if int(m["items"].(float64)) < 2 {
		t.Fatalf("campaign captured %v items, want >= 2", m["items"])
	}
	campaignID := int64(m["campaign"].(map[string]any)["id"].(float64))

	// Read the items; revoke the target grant, certify the safe member.
	_, gd := do(t, srv, http.MethodGet, fmt.Sprintf("/api/campaigns/%d", campaignID), testAPIKey, nil)
	var got struct {
		Items []campaignItem `json:"items"`
	}
	if err := json.Unmarshal(gd, &got); err != nil {
		t.Fatal(err)
	}
	var grantItem, memberItem int64
	for _, it := range got.Items {
		switch it.Kind {
		case "target_grant":
			grantItem = it.ID
		case "safe_member":
			memberItem = it.ID
		}
	}
	if grantItem == 0 || memberItem == 0 {
		t.Fatalf("expected a target_grant and a safe_member item, got %+v", got.Items)
	}

	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/campaigns/%d/items/%d/decision", campaignID, grantItem), testAPIKey,
		map[string]any{"decision": "revoke"}); code != http.StatusNoContent {
		t.Fatalf("revoke item: %d", code)
	}
	// Certifying is done by a DIFFERENT approver: the bootstrap admin created
	// the member, and since Phase 46 the grantor may not certify their own
	// grant (that refusal is covered by TestCertificationFourEyes).
	reviewerTok := seedUser(t, srv, "cert-reviewer", "approver")
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/campaigns/%d/items/%d/decision", campaignID, memberItem), reviewerTok,
		map[string]any{"decision": "certify"}); code != http.StatusNoContent {
		t.Fatalf("certify item: %d", code)
	}

	// The revoked grant is actually gone from the target.
	_, grants := do(t, srv, http.MethodGet, fmt.Sprintf("/api/targets/%d/grants", targetID), testAPIKey, nil)
	var gs []map[string]any
	if err := json.Unmarshal(grants, &gs); err != nil {
		t.Fatal(err)
	}
	if len(gs) != 0 {
		t.Fatalf("revoke did not delete the underlying grant: %s", grants)
	}
	// The certified safe member is retained.
	_, members := do(t, srv, http.MethodGet, fmt.Sprintf("/api/safes/%d/members", safeID), testAPIKey, nil)
	var ms []map[string]any
	if err := json.Unmarshal(members, &ms); err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 {
		t.Fatalf("certified safe member should be retained, got %s", members)
	}

	// Close the campaign; further decisions are refused.
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/campaigns/%d/close", campaignID), testAPIKey, nil); code != http.StatusNoContent {
		t.Fatalf("close campaign: %d", code)
	}
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/campaigns/%d/items/%d/decision", campaignID, memberItem), testAPIKey,
		map[string]any{"decision": "revoke"}); code != http.StatusConflict {
		t.Fatalf("decision on a closed campaign: want 409, got %d", code)
	}
}

// TestCertificationAuthz proves the three-way split: creating/closing a campaign
// needs CapManageUsers, reading it needs CapReadAudit, and DECIDING an item needs
// CapApprove — so a dedicated reviewer can run the recertification without also
// holding the capability that grants access (Phase 39).
func TestCertificationAuthz(t *testing.T) {
	srv := newTestServer(t)
	userTok := seedUser(t, srv, "bob", "user")       // no CapManageUsers, no CapReadAudit
	auditorTok := seedUser(t, srv, "amy", "auditor") // CapReadAudit, no CapManageUsers

	if code, _ := do(t, srv, http.MethodPost, "/api/campaigns", userTok, map[string]any{"name": "x"}); code != http.StatusForbidden {
		t.Fatalf("user create campaign: want 403, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodGet, "/api/campaigns", userTok, nil); code != http.StatusForbidden {
		t.Fatalf("user list campaigns: want 403, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodGet, "/api/campaigns", auditorTok, nil); code != http.StatusOK {
		t.Fatalf("auditor list campaigns: want 200, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/campaigns", auditorTok, map[string]any{"name": "x"}); code != http.StatusForbidden {
		t.Fatalf("auditor create campaign: want 403, got %d", code)
	}

	// Deciding an item is a review decision (CapApprove), not user administration.
	// Snapshot a campaign with one item to decide.
	tc, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "authz-target", "host": "10.0.0.11", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if tc != http.StatusCreated {
		t.Fatalf("create target: %d %s", tc, td)
	}
	targetID := int64(jsonMap(t, td)["id"].(float64))
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", targetID), testAPIKey,
		map[string]any{"subject_type": "user", "subject": "carol"}); code != http.StatusCreated {
		t.Fatal("seed grant")
	}
	ccode, cd := do(t, srv, http.MethodPost, "/api/campaigns", testAPIKey, map[string]any{"name": "authz review"})
	if ccode != http.StatusCreated {
		t.Fatalf("create campaign: %d %s", ccode, cd)
	}
	campaignID := int64(jsonMap(t, cd)["campaign"].(map[string]any)["id"].(float64))
	_, gd := do(t, srv, http.MethodGet, fmt.Sprintf("/api/campaigns/%d", campaignID), testAPIKey, nil)
	var snapshot struct {
		Items []campaignItem `json:"items"`
	}
	if err := json.Unmarshal(gd, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Items) == 0 {
		t.Fatalf("campaign has no items: %s", gd)
	}
	decisionURL := fmt.Sprintf("/api/campaigns/%d/items/%d/decision", campaignID, snapshot.Items[0].ID)

	// An auditor reads the campaign but cannot decide; a plain user cannot either.
	if code, _ := do(t, srv, http.MethodPost, decisionURL, auditorTok, map[string]any{"decision": "certify"}); code != http.StatusForbidden {
		t.Fatalf("auditor decide item: want 403, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodPost, decisionURL, userTok, map[string]any{"decision": "certify"}); code != http.StatusForbidden {
		t.Fatalf("user decide item: want 403, got %d", code)
	}
	// An approver — who holds no CapManageUsers — can.
	approverTok := seedUser(t, srv, "ann", "approver")
	if code, body := do(t, srv, http.MethodPost, decisionURL, approverTok, map[string]any{"decision": "certify"}); code != http.StatusNoContent {
		t.Fatalf("approver decide item: want 204, got %d %s", code, body)
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/campaigns", approverTok, map[string]any{"name": "x"}); code != http.StatusForbidden {
		t.Fatalf("approver create campaign: want 403 (management stays manage_users), got %d", code)
	}
}

// TestCampaignScope proves a scoped campaign snapshots only what it was asked to
// review — the point of the feature, since an unscoped campaign over the whole
// estate is a list nobody completes.
//
// It also pins the two refusals that matter: an unknown scope and a safe that
// does not exist are 422 rather than silently widening to "everything", which is
// how a typo would otherwise produce exactly the unreviewable campaign scoping
// exists to prevent.
func TestCampaignScope(t *testing.T) {
	srv := newTestServer(t)

	mk := func(path string, body map[string]any) int64 {
		t.Helper()
		code, data := do(t, srv, http.MethodPost, path, testAPIKey, body)
		if code != http.StatusCreated {
			t.Fatalf("POST %s: %d %s", path, code, data)
		}
		return int64(jsonMap(t, data)["id"].(float64))
	}
	// Two safes, a target in each, a grant on each target, and a member in each.
	safeA := mk("/api/safes", map[string]any{"name": "scope-safe-a"})
	safeB := mk("/api/safes", map[string]any{"name": "scope-safe-b"})
	newTarget := func(name string, safe int64) int64 {
		id := mk("/api/targets", map[string]any{
			"name": name, "host": "10.0.0.1", "port": 22, "os_type": "linux", "protocol": "ssh",
		})
		if code, d := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d/safe", id), testAPIKey,
			map[string]any{"safe_id": safe}); code != http.StatusOK && code != http.StatusNoContent {
			t.Fatalf("assign %s to safe: %d %s", name, code, d)
		}
		return id
	}
	tgtA, tgtB := newTarget("scope-web-a", safeA), newTarget("scope-web-b", safeB)
	grant := func(target int64, subject string) {
		t.Helper()
		if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", target), testAPIKey,
			map[string]any{"subject_type": "user", "subject": subject}); code != http.StatusCreated {
			t.Fatalf("grant %s: %d %s", subject, code, d)
		}
	}
	grant(tgtA, "alice")
	grant(tgtB, "bob")
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeA), testAPIKey,
		map[string]any{"subject_type": "user", "subject": "alice"}); code != http.StatusCreated {
		t.Fatalf("safe member: %d %s", code, d)
	}

	items := func(body []byte) int { return int(jsonMap(t, body)["items"].(float64)) }

	// Unscoped: everything (2 grants + 1 member).
	_, all := do(t, srv, http.MethodPost, "/api/campaigns", testAPIKey, map[string]any{"name": "all"})
	if n := items(all); n != 3 {
		t.Fatalf("unscoped campaign captured %d items, want 3", n)
	}
	// Safe-scoped: safe A's member AND the grant on the target assigned to it —
	// covering only the members would leave that target reachable by a direct
	// grant the review never showed.
	_, bySafe := do(t, srv, http.MethodPost, "/api/campaigns", testAPIKey,
		map[string]any{"name": "safe A", "scope_kind": "safe", "scope_safe_id": safeA})
	if n := items(bySafe); n != 2 {
		t.Fatalf("safe-scoped campaign captured %d items, want 2 (one grant + one member)", n)
	}
	// Subject-scoped: everything alice holds, anywhere (her grant + her membership).
	_, bySubj := do(t, srv, http.MethodPost, "/api/campaigns", testAPIKey,
		map[string]any{"name": "alice", "scope_kind": "subject", "scope_subject": "alice"})
	if n := items(bySubj); n != 2 {
		t.Fatalf("subject-scoped campaign captured %d items, want 2", n)
	}
	// bob holds one thing.
	_, byBob := do(t, srv, http.MethodPost, "/api/campaigns", testAPIKey,
		map[string]any{"name": "bob", "scope_kind": "subject", "scope_subject": "bob"})
	if n := items(byBob); n != 1 {
		t.Fatalf("bob's campaign captured %d items, want 1", n)
	}

	// Refusals: an unknown scope must not fall through to "everything".
	for _, bad := range []map[string]any{
		{"name": "typo", "scope_kind": "safes"},
		{"name": "no id", "scope_kind": "safe"},
		{"name": "missing safe", "scope_kind": "safe", "scope_safe_id": 999999},
		{"name": "no subject", "scope_kind": "subject"},
		{"name": "too often", "recur_days": 4000},
		{"name": "negative", "recur_days": -1},
	} {
		if code, d := do(t, srv, http.MethodPost, "/api/campaigns", testAPIKey, bad); code != http.StatusUnprocessableEntity {
			t.Fatalf("campaign %v: want 422, got %d %s", bad["name"], code, d)
		}
	}
}

// TestCampaignReviewerAssignment proves an item can have an owner: items inherit
// the campaign's reviewer, one can be reassigned, and a reviewer's queue is their
// pending items across open campaigns.
//
// It also pins two things that are easy to get wrong. `GET /api/campaigns/mine`
// sits under the same prefix as `GET /api/campaigns/{id}` and must not be
// swallowed by it; and reassignment is scoped to the campaign in the path, so one
// campaign's route cannot touch another's item.
func TestCampaignReviewerAssignment(t *testing.T) {
	srv := newTestServer(t)

	tc, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "rev-web", "host": "10.0.0.11", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if tc != http.StatusCreated {
		t.Fatalf("create target: %d %s", tc, td)
	}
	targetID := int64(jsonMap(t, td)["id"].(float64))
	for _, sub := range []string{"alice", "bob"} {
		if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", targetID), testAPIKey,
			map[string]any{"subject_type": "user", "subject": sub}); code != http.StatusCreated {
			t.Fatalf("grant %s: %d %s", sub, code, d)
		}
	}

	// The campaign names a reviewer; every item it snapshots inherits it.
	code, cd := do(t, srv, http.MethodPost, "/api/campaigns", testAPIKey,
		map[string]any{"name": "with reviewer", "reviewer": "carol"})
	if code != http.StatusCreated {
		t.Fatalf("create campaign: %d %s", code, cd)
	}
	campID := int64(jsonMap(t, cd)["campaign"].(map[string]any)["id"].(float64))

	_, vd := do(t, srv, http.MethodGet, fmt.Sprintf("/api/campaigns/%d", campID), testAPIKey, nil)
	var view struct {
		Items []struct {
			ID       int64  `json:"id"`
			Reviewer string `json:"reviewer"`
		} `json:"items"`
	}
	if err := json.Unmarshal(vd, &view); err != nil {
		t.Fatalf("decode campaign: %v (%s)", err, vd)
	}
	if len(view.Items) != 2 {
		t.Fatalf("want 2 items, got %d", len(view.Items))
	}
	for _, it := range view.Items {
		if it.Reviewer != "carol" {
			t.Fatalf("item %d inherited reviewer %q, want carol", it.ID, it.Reviewer)
		}
	}

	// Carol's queue is both items. `mine` must not be parsed as a campaign id.
	carol := seedUser(t, srv, "carol", "approver")
	qc, qd := do(t, srv, http.MethodGet, "/api/campaigns/mine", carol, nil)
	if qc != http.StatusOK {
		t.Fatalf("review queue: %d %s — /campaigns/mine must not be swallowed by /campaigns/{id}", qc, qd)
	}
	var queue []struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(qd, &queue); err != nil {
		t.Fatalf("decode queue: %v (%s)", err, qd)
	}
	if len(queue) != 2 {
		t.Fatalf("carol's queue has %d items, want 2", len(queue))
	}

	// Reassign one to dave; carol's queue shrinks and dave's is that item.
	first := view.Items[0].ID
	if code, d := do(t, srv, http.MethodPut, fmt.Sprintf("/api/campaigns/%d/items/%d/reviewer", campID, first),
		testAPIKey, map[string]any{"reviewer": "dave"}); code != http.StatusOK {
		t.Fatalf("reassign: %d %s", code, d)
	}
	_, qd2 := do(t, srv, http.MethodGet, "/api/campaigns/mine", carol, nil)
	queue = queue[:0]
	if err := json.Unmarshal(qd2, &queue); err != nil {
		t.Fatal(err)
	}
	if len(queue) != 1 {
		t.Fatalf("after reassignment carol has %d items, want 1", len(queue))
	}
	dave := seedUser(t, srv, "dave", "approver")
	_, dq := do(t, srv, http.MethodGet, "/api/campaigns/mine", dave, nil)
	var daveQ []struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(dq, &daveQ); err != nil {
		t.Fatal(err)
	}
	if len(daveQ) != 1 || daveQ[0].ID != first {
		t.Fatalf("dave's queue = %+v, want just item %d", daveQ, first)
	}

	// Reassignment is scoped to the campaign in the path: another campaign's
	// route must not reach this item.
	_, od := do(t, srv, http.MethodPost, "/api/campaigns", testAPIKey, map[string]any{"name": "other"})
	otherID := int64(jsonMap(t, od)["campaign"].(map[string]any)["id"].(float64))
	if code, _ := do(t, srv, http.MethodPut, fmt.Sprintf("/api/campaigns/%d/items/%d/reviewer", otherID, first),
		testAPIKey, map[string]any{"reviewer": "mallory"}); code != http.StatusNotFound {
		t.Fatalf("cross-campaign reassignment: want 404, got %d", code)
	}

	// Deciding an item takes it out of the queue — a queue that still shows
	// decided work is not a queue. Decided AS DAVE: the bootstrap admin created
	// these grants, and Phase 46's four-eyes rule refuses the grantor, which is
	// exactly the separation the assignment is meant to operate inside.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/campaigns/%d/items/%d/decision", campID, first),
		dave, map[string]any{"decision": "certify"}); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("decide: %d %s", code, d)
	}
	_, dq2 := do(t, srv, http.MethodGet, "/api/campaigns/mine", dave, nil)
	daveQ = daveQ[:0]
	if err := json.Unmarshal(dq2, &daveQ); err != nil {
		t.Fatal(err)
	}
	if len(daveQ) != 0 {
		t.Fatalf("a decided item stayed in the queue: %+v", daveQ)
	}
}
