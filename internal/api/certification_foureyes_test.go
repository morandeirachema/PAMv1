package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestCertificationFourEyes proves the per-item separation of duties (Phase 46):
// the principal who created a grant cannot CERTIFY it (403, audited), a
// different approver can, self-REVOKE stays allowed (it reduces access), and an
// item whose creator was never recorded (pre-migration) is not blocked.
func TestCertificationFourEyes(t *testing.T) {
	srv, st := newTestServerStore(t)
	ctx := context.Background()
	targetID := createTestTarget(t, srv, "cert-t1", "10.2.0.1")

	// Two grants created through the API by the bootstrap admin — their creator
	// is recorded — and one written directly with no creator (a legacy row).
	for _, subject := range []string{"alice", "bob"} {
		if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", targetID), testAPIKey,
			map[string]any{"subject_type": "user", "subject": subject}); code != http.StatusCreated {
			t.Fatalf("create grant for %s: %d %s", subject, code, d)
		}
	}
	if err := st.CreateTargetGrant(ctx, &store.TargetGrant{TargetID: targetID, SubjectType: "user", Subject: "carl"}); err != nil {
		t.Fatalf("legacy grant: %v", err)
	}

	code, data := do(t, srv, http.MethodPost, "/api/campaigns", testAPIKey, map[string]any{"name": "four-eyes"})
	if code != http.StatusCreated {
		t.Fatalf("create campaign: %d %s", code, data)
	}
	campID := int64(jsonMap(t, data)["campaign"].(map[string]any)["id"].(float64))

	_, cd := do(t, srv, http.MethodGet, fmt.Sprintf("/api/campaigns/%d", campID), testAPIKey, nil)
	var cv struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(cd, &cv); err != nil {
		t.Fatal(err)
	}
	itemBySubject := map[string]int64{}
	for _, it := range cv.Items {
		itemBySubject[it["subject"].(string)] = int64(it["id"].(float64))
		if it["subject"] == "alice" && it["granted_by"] != "bootstrap-admin" {
			t.Fatalf("snapshot did not carry the grant creator: %+v", it)
		}
	}
	decide := func(key string, item int64, decision string) int {
		t.Helper()
		code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/campaigns/%d/items/%d/decision", campID, item), key,
			map[string]any{"decision": decision})
		return code
	}

	// The grantor certifying their own grant is refused and audited.
	if code := decide(testAPIKey, itemBySubject["alice"], "certify"); code != http.StatusForbidden {
		t.Fatalf("self-certify: want 403, got %d", code)
	}
	auditHas(t, st, "certification.decision_denied", "reason:four-eyes")

	// A DIFFERENT approver certifies it fine.
	veraTok := seedUser(t, srv, "vera", "approver")
	if code := decide(veraTok, itemBySubject["alice"], "certify"); code != http.StatusNoContent {
		t.Fatalf("other approver certify: want 204, got %d", code)
	}
	// Self-revoke is allowed — removing your own grant only reduces access.
	if code := decide(testAPIKey, itemBySubject["bob"], "revoke"); code != http.StatusNoContent {
		t.Fatalf("self-revoke: want 204, got %d", code)
	}
	// A legacy item with no recorded creator cannot be enforced retroactively.
	if code := decide(testAPIKey, itemBySubject["carl"], "certify"); code != http.StatusNoContent {
		t.Fatalf("legacy certify: want 204, got %d", code)
	}
}
