package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// TestTelnetTargetsAndScenarios proves Phase 279's API half: a telnet
// target is refused until PAM_TELNET_ENABLED accepts cleartext, then
// defaults to port 23; a scenario is validated, stored canonical, only
// allowed where it can run, and recorded on the target's audit row by its
// digest.
func TestTelnetTargetsAndScenarios(t *testing.T) {
	off, _ := newTestServerOpts(t, nil, api.Options{})
	body := map[string]any{"name": "sw-01", "host": "10.0.0.9", "os_type": "linux", "protocol": "telnet"}
	if code, d := do(t, off, http.MethodPost, "/api/targets", testAPIKey, body); code != http.StatusUnprocessableEntity || !strings.Contains(string(d), "PAM_TELNET_ENABLED") {
		t.Fatalf("telnet while disabled: %d %s", code, d)
	}

	srv, st := newTestServerOpts(t, nil, api.Options{TelnetEnabled: true})
	body["scenario"] = "  expect Username:\nsend ${login}\nexpect \"Password: \"\nsend ${password}\n# then\nexpect >\nsend enable"
	code, d := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, body)
	m := jsonMap(t, d)
	if code != http.StatusCreated || m["port"] != float64(23) {
		t.Fatalf("telnet target: %d %s", code, d)
	}
	want := "expect Username:\nsend ${login}\nexpect \"Password: \"\nsend ${password}\nexpect >\nsend enable"
	if m["scenario"] != want {
		t.Fatalf("scenario stored as %q, want %q", m["scenario"], want)
	}
	auditHas(t, st, "target.create", "scenario:")

	for name, tc := range map[string]map[string]any{
		"bad scenario":    {"name": "x1", "host": "h", "os_type": "linux", "protocol": "ssh", "scenario": "wait 5"},
		"expect a secret": {"name": "x2", "host": "h", "os_type": "linux", "protocol": "ssh", "scenario": "expect ${password}"},
		"rdp scenario":    {"name": "x3", "host": "h", "os_type": "windows", "protocol": "rdp", "scenario": "send x"},
	} {
		if code, d := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, tc); code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d %s, want 422", name, code, d)
		}
	}
}

// TestScenarioTypingPasswordNeedsReveal (review of 274-280): a scenario that
// types ${password} decides what is done with the secret — `send echo
// ${password}` would print it — so only a principal who may reveal secrets
// may set or change one. A target manager without reveal may still edit
// the target if the scenario is left as it was.
func TestScenarioTypingPasswordNeedsReveal(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{})
	if code, d := do(t, srv, http.MethodPost, "/api/profiles", testAPIKey, map[string]any{
		"name": "targeteer", "capabilities": []string{"read_inventory", "manage_targets"}}); code != http.StatusCreated {
		t.Fatalf("profile: %d %s", code, d)
	}
	tok := seedUser(t, srv, "tom", "targeteer")
	echo := "expect $\nsend echo ${password}"
	body := map[string]any{"name": "web-01", "host": "10.0.0.5", "os_type": "linux", "protocol": "ssh", "scenario": echo}
	if code, d := do(t, srv, http.MethodPost, "/api/targets", tok, body); code != http.StatusForbidden {
		t.Fatalf("a manager without reveal set a password-typing scenario: %d %s", code, d)
	}
	auditHas(t, st, "authz.denied", "reason:scenario-types-password")
	code, d := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, body)
	if code != http.StatusCreated {
		t.Fatalf("admin: %d %s", code, d)
	}
	id := itoa(int64(jsonMap(t, d)["id"].(float64)))
	// Unchanged scenario: the manager may edit the rest.
	body["host"] = "10.0.0.6"
	if code, d := do(t, srv, http.MethodPut, "/api/targets/"+id, tok, body); code != http.StatusOK {
		t.Fatalf("an edit leaving the scenario as it was: %d %s", code, d)
	}
	body["scenario"] = "expect $\nsend sudo -i\nexpect password\nsend ${password}"
	if code, d := do(t, srv, http.MethodPut, "/api/targets/"+id, tok, body); code != http.StatusForbidden {
		t.Fatalf("a manager without reveal changed a password-typing scenario: %d %s", code, d)
	}
}
