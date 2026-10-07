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
