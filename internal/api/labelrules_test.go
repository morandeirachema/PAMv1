package api_test

import (
	"fmt"
	"net/http"
	"testing"
)

// TestLabelRuleRoutes proves the three routes validate what they store (Phase
// 250). A selector is parsed on the way in rather than on the way out,
// because an unparsable one matches nothing: an operator would be looking at
// a deny rule in the list that denies nobody, which is the one failure where
// silence is indistinguishable from enforcement.
func TestLabelRuleRoutes(t *testing.T) {
	srv, st := newTestServerStore(t)

	code, d := do(t, srv, http.MethodPost, "/api/label-rules", testAPIKey, map[string]any{
		"selector": "env=prod", "subject_type": "role", "subject": "user",
	})
	if code != http.StatusCreated {
		t.Fatalf("create allow rule: %d %s", code, d)
	}
	m := jsonMap(t, d)
	ruleID := int64(m["id"].(float64))
	if m["effect"] != "allow" {
		t.Errorf("effect defaults to allow, got %v", m["effect"])
	}
	auditHas(t, st, "labelrule.create", `selector:"env=prod" role:user effect:allow`)

	if code, d := do(t, srv, http.MethodPost, "/api/label-rules", testAPIKey, map[string]any{
		"selector": "tier=db", "subject_type": "user", "subject": "mallory", "effect": "deny",
	}); code != http.StatusCreated {
		t.Fatalf("create deny rule: %d %s", code, d)
	}

	// Validation: every one of these would otherwise be stored as text that
	// reads differently than it enforces.
	for _, bad := range []struct {
		name string
		body map[string]any
	}{
		{"empty selector", map[string]any{"selector": "", "subject_type": "user", "subject": "bob"}},
		{"unparsable selector", map[string]any{"selector": "not a selector", "subject_type": "user", "subject": "bob"}},
		{"contradictory selector", map[string]any{"selector": "env=prod,env=dev", "subject_type": "user", "subject": "bob"}},
		{"bad subject type", map[string]any{"selector": "env=prod", "subject_type": "group", "subject": "bob"}},
		{"unknown role", map[string]any{"selector": "env=prod", "subject_type": "role", "subject": "wizard"}},
		{"bad effect", map[string]any{"selector": "env=prod", "subject_type": "user", "subject": "bob", "effect": "maybe"}},
		{"deny with permissions", map[string]any{"selector": "env=prod", "subject_type": "user", "subject": "bob", "effect": "deny", "permissions": []string{"use"}}},
		{"allow with no permissions", map[string]any{"selector": "env=prod", "subject_type": "user", "subject": "bob", "permissions": []string{}}},
		{"past expiry", map[string]any{"selector": "env=prod", "subject_type": "user", "subject": "bob", "expires_at": "2000-01-01T00:00:00Z"}},
		{"bad time frame", map[string]any{"selector": "env=prod", "subject_type": "user", "subject": "bob", "time_frame": "Funday 08:00-18:00"}},
	} {
		if code, d := do(t, srv, http.MethodPost, "/api/label-rules", testAPIKey, bad.body); code != http.StatusUnprocessableEntity {
			t.Errorf("%s: want 422, got %d %s", bad.name, code, d)
		}
	}
	// The same rule twice is a conflict, not a duplicate that must be revoked twice.
	if code, d := do(t, srv, http.MethodPost, "/api/label-rules", testAPIKey, map[string]any{
		"selector": "env=prod", "subject_type": "role", "subject": "user",
	}); code != http.StatusConflict {
		t.Errorf("duplicate rule: want 409, got %d %s", code, d)
	}

	if code, d := do(t, srv, http.MethodGet, "/api/label-rules", testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("list: %d %s", code, d)
	}
	// An auditor reads the policy but cannot write it; a plain user does neither.
	auditorTok := seedUser(t, srv, "ana", "auditor")
	if code, _ := do(t, srv, http.MethodGet, "/api/label-rules", auditorTok, nil); code != http.StatusOK {
		t.Errorf("an auditor must be able to read who is denied what, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/label-rules", auditorTok, map[string]any{
		"selector": "env=prod", "subject_type": "user", "subject": "ana",
	}); code != http.StatusForbidden {
		t.Errorf("an auditor must not write a rule, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/label-rules/%d", ruleID), auditorTok, nil); code != http.StatusForbidden {
		t.Errorf("an auditor must not delete a rule, got %d", code)
	}

	if code, d := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/label-rules/%d", ruleID), testAPIKey, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", code, d)
	}
	// The detail carries the selector and effect, not just the id: deleting a
	// deny widens access across every target the selector matched.
	auditHas(t, st, "labelrule.delete", `selector:"env=prod"`)
	if code, _ := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/label-rules/%d", ruleID), testAPIKey, nil); code != http.StatusNotFound {
		t.Error("deleting a gone rule must be 404")
	}
}

// TestTargetLabelsRoundTripAndAudit proves labels are validated, canonicalized
// and audited on both create and update (Phase 250). Clearing them is audited
// too: a PUT that drops the labels a deny rule matched on silently widens
// access, which is exactly the edit that must not be invisible.
func TestTargetLabelsRoundTripAndAudit(t *testing.T) {
	srv, st := newTestServerStore(t)
	code, d := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "db-01", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh",
		"labels": map[string]string{"tier": "db", "env": "prod"},
	})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, d)
	}
	id := int64(jsonMap(t, d)["id"].(float64))
	// Canonical form: sorted by key, whatever order they arrived in.
	if got := jsonMap(t, d)["labels"]; got != "env=prod,tier=db" {
		t.Errorf("labels = %v, want the canonical sorted form", got)
	}
	auditHas(t, st, "target.create", `labels:"env=prod,tier=db"`)

	for _, bad := range []map[string]string{
		{"env": ""}, {"": "prod"}, {"env": "*"}, {"bad key": "prod"}, {"env": "pro,d"},
	} {
		if code, _ := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
			"name": "bad-01", "host": "10.0.0.10", "port": 22, "os_type": "linux", "protocol": "ssh", "labels": bad,
		}); code != http.StatusUnprocessableEntity {
			t.Errorf("labels %v: want 422, got %d", bad, code)
		}
	}

	// A PUT with no labels clears them, and says so in the trail.
	if code, d := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d", id), testAPIKey, map[string]any{
		"name": "db-01", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh",
	}); code != http.StatusOK {
		t.Fatalf("update: %d %s", code, d)
	}
	auditHas(t, st, "target.update", "labels:-")
}
