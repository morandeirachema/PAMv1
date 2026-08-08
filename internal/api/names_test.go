package api_test

import (
	"net/http"
	"strings"
	"testing"
)

// The audit trail is evidence against insiders — which is the whole reason
// four-eyes and break-glass exist. So "only an admin can forge it" is the wrong
// resting place: an admin who names a target
// `prod-db action:approved reason:emergency` puts forged fields into the record
// of EVERY operator's session on that target, not just their own.
//
// The fix is at the boundary rather than at the ~145 sinks that interpolate a
// name, because quoting the sinks would rewrite the format every audit assertion
// in this suite greps for, while rejecting the two characters that matter closes
// the class in one place per input and changes no record format.

// hostileNames are the values a name must never be allowed to carry.
var hostileNames = map[string]string{
	"colon forges a field": "prod-db action:approved reason:emergency",
	"newline splits a row": "prod-db\nactor:root",
	"carriage return":      "prod-db\ractor:root",
	"tab":                  "prod-db\tactor:root",
	"nul":                  "prod-db\x00",
	"too long":             strings.Repeat("a", 200),
}

// legitimateNames must keep working. The rule is deliberately permissive: a name
// with spaces but no colon cannot forge a `key:value` pair, so there is no reason
// to forbid "Prod DB 01" — and a rule that breaks ordinary names gets reverted.
var legitimateNames = []string{
	"prod-db", "Prod DB 01", "web_01.example", "sûreté", "データベース",
	"a/b", "svc@corp", "x-1.2.3", strings.Repeat("a", 128),
}

// TestNamesAreValidatedAtEveryBoundary walks the create endpoints that accept a
// human-chosen name and proves each refuses the hostile forms with 422.
func TestNamesAreValidatedAtEveryBoundary(t *testing.T) {
	srv := newTestServer(t)

	// Each entry: a create endpoint, and the body with the name field to poison.
	endpoints := []struct {
		name  string
		path  string
		field string
		body  func(v string) map[string]any
	}{
		{"target", "/api/targets", "name", func(v string) map[string]any {
			return map[string]any{"name": v, "host": "h", "port": 22, "os_type": "linux", "protocol": "ssh"}
		}},
		{"user", "/api/users", "username", func(v string) map[string]any {
			return map[string]any{"username": v, "role": "user"}
		}},
		{"safe", "/api/safes", "name", func(v string) map[string]any {
			return map[string]any{"name": v}
		}},
		{"campaign", "/api/campaigns", "name", func(v string) map[string]any {
			return map[string]any{"name": v}
		}},
		{"profile", "/api/profiles", "name", func(v string) map[string]any {
			return map[string]any{"name": v, "caps": []string{"read_inventory"}}
		}},
		{"vendor", "/api/vendors", "username", func(v string) map[string]any {
			return map[string]any{"username": v, "org": "acme"}
		}},
	}

	for _, ep := range endpoints {
		for why, bad := range hostileNames {
			// Unique per endpoint: vendors and users share a username space, so a
			// shared fixture let a 409 from an earlier endpoint stand in for the
			// 422 this is actually asserting.
			bad := ep.name + "-" + bad
			code, body := do(t, srv, http.MethodPost, ep.path, testAPIKey, ep.body(bad))
			if code != http.StatusUnprocessableEntity {
				t.Errorf("%s %s (%s): want 422, got %d — %s", ep.path, ep.field, why, code, body)
			}
		}
	}
}

// TestOrdinaryNamesStillWork is the other half, and the one that matters for the
// rule surviving contact with users: a validator that rejects real names is worse
// than none, because it gets removed.
func TestOrdinaryNamesStillWork(t *testing.T) {
	srv := newTestServer(t)
	for i, good := range legitimateNames {
		body := map[string]any{"name": good, "host": "h", "port": 22, "os_type": "linux", "protocol": "ssh"}
		if code, resp := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, body); code != http.StatusCreated {
			t.Errorf("legitimate name %d (%q): want 201, got %d — %s", i, good, code, resp)
		}
	}
}

// TestGrantSubjectIsValidated covers the subject fields, which name a person or
// role rather than an object and reach the audit trail the same way.
func TestGrantSubjectIsValidated(t *testing.T) {
	srv := newTestServer(t)
	code, _ := do(t, srv, http.MethodPost, "/api/targets", testAPIKey,
		map[string]any{"name": "t1", "host": "h", "port": 22, "os_type": "linux", "protocol": "ssh"})
	if code != http.StatusCreated {
		t.Fatalf("seed target: %d", code)
	}
	for why, bad := range hostileNames {
		body := map[string]any{"subject_type": "user", "subject": bad}
		if code, resp := do(t, srv, http.MethodPost, "/api/targets/1/grants", testAPIKey, body); code != http.StatusUnprocessableEntity {
			t.Errorf("grant subject (%s): want 422, got %d — %s", why, code, resp)
		}
	}
}
