package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// campaignItems creates an all-scope campaign and returns its items.
func campaignItems(t *testing.T, srv *httptest.Server, name string) (int64, []map[string]any) {
	t.Helper()
	code, data := do(t, srv, http.MethodPost, "/api/campaigns", testAPIKey, map[string]any{"name": name})
	if code != http.StatusCreated {
		t.Fatalf("create campaign: %d %s", code, data)
	}
	id := int64(jsonMap(t, data)["campaign"].(map[string]any)["id"].(float64))
	_, cd := do(t, srv, http.MethodGet, fmt.Sprintf("/api/campaigns/%d", id), testAPIKey, nil)
	var cv struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(cd, &cv); err != nil {
		t.Fatalf("campaign items: %v (%s)", err, cd)
	}
	return id, cv.Items
}

// TestCampaignCertifiesAgentIdentities is Phase 175's headline: the identities
// that hold brokered access to the estate are reviewed like everyone else.
//
// A campaign snapshotted target grants and safe membership only, so no reviewer
// was ever asked whether an AI-agent identity should still exist — and the one
// place an agent did appear (a grant naming it) was filed under subject type
// "user", reviewed as though it were a person.
func TestCampaignCertifiesAgentIdentities(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, &fakeWinRM{}, brokerRules))
	seedUser(t, srv, "carol", "user")
	keyID, _ := mintAgent(t, srv, "rotation-bot", "carol", nil)
	const spiffeID = "spiffe://example.org/ns/prod/sa/planner"
	if st, d := do(t, srv, http.MethodPost, "/v1/agents/identities", testAPIKey,
		map[string]any{"spiffe_id": spiffeID, "owner": "carol"}); st != http.StatusCreated {
		t.Fatalf("register identity: %d %s", st, d)
	}

	campID, items := campaignItems(t, srv, "agents-q3")
	byKind := map[string]map[string]any{}
	for _, it := range items {
		byKind[it["kind"].(string)] = it
	}
	keyItem, idItem := byKind["agent_key"], byKind["agent_identity"]
	if keyItem == nil || idItem == nil {
		t.Fatalf("both agent identity kinds should be snapshotted: %+v", items)
	}
	if keyItem["subject"] != "rotation-bot" || keyItem["subject_type"] != "agent" {
		t.Fatalf("an agent key is reviewed AS an agent, not as a user: %+v", keyItem)
	}
	if !strings.Contains(keyItem["detail"].(string), "last used") ||
		!strings.Contains(idItem["detail"].(string), "last seen") {
		t.Fatalf("the reviewer needs the dormancy signal: %+v %+v", keyItem, idItem)
	}
	if idItem["granted_by"] != "carol" {
		t.Fatalf("the item should name the accountable owner: %+v", idItem)
	}

	// A reviewer who is not the owner revokes both.
	vera := seedUser(t, srv, "vera", "approver")
	for _, it := range []map[string]any{keyItem, idItem} {
		id := int64(it["id"].(float64))
		if code, d := do(t, srv, http.MethodPost,
			fmt.Sprintf("/api/campaigns/%d/items/%d/decision", campID, id), vera,
			map[string]any{"decision": "revoke"}); code != http.StatusNoContent {
			t.Fatalf("revoke %v: %d %s", it["kind"], code, d)
		}
	}

	// Revoking STOPS each identity with the control that fits it, and deletes
	// neither: the row is the evidence an investigation needs afterwards.
	_, kl := do(t, srv, http.MethodGet, "/v1/agents", testAPIKey, nil)
	if !strings.Contains(string(kl), `"disabled":true`) {
		t.Fatalf("a revoked agent key must be suspended, not deleted: %s", kl)
	}
	if !strings.Contains(string(kl), fmt.Sprintf(`"id":%d`, keyID)) {
		t.Fatalf("the key row must survive the revocation: %s", kl)
	}
	_, ql := do(t, srv, http.MethodGet, "/v1/agents/quarantine", testAPIKey, nil)
	if !strings.Contains(string(ql), spiffeID) {
		t.Fatalf("a revoked SPIFFE identity must be quarantined: %s", ql)
	}
	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=80", testAPIKey, nil)
	if !strings.Contains(string(aud), "reason:certification-revoked") {
		t.Fatalf("both revocations should be audited under their own reason: %s", aud)
	}
}

// TestCampaignFlagsAnOwnerNobodyCanOffboard covers the quieter half of the same
// finding. An owner is free text, and the offboarding cascade matches it as a
// username STRING — so "caro1" makes an agent no cascade can ever reach, while
// the row still reads as though somebody were accountable.
//
// pamv1 does not refuse an unrecognised owner (a team address is a legitimate
// answer), so it says so where a human is already looking: the agent listings
// and the review that exists to ask exactly this question.
func TestCampaignFlagsAnOwnerNobodyCanOffboard(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, &fakeWinRM{}, brokerRules))
	seedUser(t, srv, "carol", "user")
	mintAgent(t, srv, "good-bot", "carol", nil)
	mintAgent(t, srv, "typo-bot", "caro1", nil)

	_, kl := do(t, srv, http.MethodGet, "/v1/agents", testAPIKey, nil)
	var keys []map[string]any
	if err := json.Unmarshal(kl, &keys); err != nil {
		t.Fatalf("agent listing: %v (%s)", err, kl)
	}
	for _, k := range keys {
		want := k["name"] == "good-bot"
		if k["owner_known"] != want {
			t.Fatalf("owner_known for %v should be %v: %+v", k["name"], want, k)
		}
	}

	_, items := campaignItems(t, srv, "owners")
	var flagged, clean int
	for _, it := range items {
		if it["kind"] != "agent_key" {
			continue
		}
		if strings.Contains(it["detail"].(string), "offboarding cannot reach") {
			flagged++
		} else {
			clean++
		}
	}
	if flagged != 1 || clean != 1 {
		t.Fatalf("exactly the typo'd owner should be flagged (flagged=%d clean=%d): %+v", flagged, clean, items)
	}
}
