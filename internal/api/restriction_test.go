package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// TestRestrictionRulesAPI (Phase 275): rules are validated, listed and
// deleted; an auditor may read but not write; and on a REST-brokered
// command the caller's set is consulted after the deployment guard — a
// notify match is audited and runs, a kill match refuses the call.
func TestRestrictionRulesAPI(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	srv, st := newTestServerOpts(t, nil, api.Options{WinRM: fake})
	status, body := do(t, srv, http.MethodPost, "/api/targets", testAPIKey,
		map[string]any{"name": "win-box", "host": "10.0.0.6", "port": 5986, "os_type": "windows", "protocol": "winrm"})
	if status != http.StatusCreated {
		t.Fatalf("create target: %d %s", status, body)
	}
	var win store.Target
	_ = json.Unmarshal(body, &win)
	status, body = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey,
		map[string]any{"target_id": win.ID, "username": "Administrator", "secret": "pw", "secret_type": "password"})
	if status != http.StatusCreated {
		t.Fatalf("create credential: %d %s", status, body)
	}

	for _, bad := range []map[string]any{
		{"subject_type": "group", "subject": "x", "pattern": "a"},
		{"subject_type": "role", "subject": "root", "pattern": "a"},
		{"subject_type": "role", "subject": "user", "pattern": "("},
		{"subject_type": "role", "subject": "user", "pattern": "a", "action": "block"},
		{"subject_type": "role", "subject": "user", "subprotocol": "telnet", "pattern": "a"},
		{"subject_type": "role", "subject": "user", "subprotocol": "ssh_exec", "pattern": "$filesize:>1m"},
	} {
		if s, b := do(t, srv, http.MethodPost, "/api/restriction-rules", testAPIKey, bad); s != http.StatusUnprocessableEntity {
			t.Fatalf("bad rule %v: %d %s", bad, s, b)
		}
	}
	status, body = do(t, srv, http.MethodPost, "/api/restriction-rules", testAPIKey,
		map[string]any{"subject_type": "role", "subject": "admin", "subprotocol": "winrm", "pattern": "(?i)^Get-", "action": "Notify", "note": "reads are fine"})
	if status != http.StatusCreated {
		t.Fatalf("create notify rule: %d %s", status, body)
	}
	var notify store.RestrictionRule
	_ = json.Unmarshal(body, &notify)
	if notify.Action != "notify" || notify.Subprotocol != "winrm" {
		t.Fatalf("notify rule: %+v", notify)
	}
	status, body = do(t, srv, http.MethodPost, "/api/restriction-rules", testAPIKey,
		map[string]any{"subject_type": "role", "subject": "admin", "pattern": "(?i)Remove-Item"})
	if status != http.StatusCreated {
		t.Fatalf("create kill rule: %d %s", status, body)
	}
	var kill store.RestrictionRule
	_ = json.Unmarshal(body, &kill)
	if kill.Action != "kill" || kill.Subprotocol != "*" {
		t.Fatalf("kill rule defaults: %+v", kill)
	}
	status, body = do(t, srv, http.MethodGet, "/api/restriction-rules", testAPIKey, nil)
	var list []store.RestrictionRule
	_ = json.Unmarshal(body, &list)
	if status != http.StatusOK || len(list) != 2 {
		t.Fatalf("list: %d %s", status, body)
	}
	auditor := seedUser(t, srv, "aud", "auditor")
	if s, _ := do(t, srv, http.MethodGet, "/api/restriction-rules", auditor, nil); s != http.StatusOK {
		t.Fatalf("auditor list: %d", s)
	}
	if s, _ := do(t, srv, http.MethodPost, "/api/restriction-rules", auditor, map[string]any{"subject_type": "role", "subject": "user", "pattern": "x"}); s != http.StatusForbidden {
		t.Fatalf("auditor create: %d", s)
	}

	// A WinRM run by the admin: Get-Process notifies and runs; Remove-Item is killed.
	run := "/api/targets/" + itoa64(win.ID) + "/winrm"
	if s, b := do(t, srv, http.MethodPost, run, testAPIKey, map[string]any{"command": "Get-Process"}); s != http.StatusOK {
		t.Fatalf("notify run: %d %s", s, b)
	}
	if s, b := do(t, srv, http.MethodPost, run, testAPIKey, map[string]any{"command": "Remove-Item C:\\x"}); s != http.StatusForbidden {
		t.Fatalf("kill run: %d %s", s, b)
	}
	events, _ := st.ListAudit(t.Context(), 50)
	seen := map[string]bool{}
	for _, e := range events {
		if e.Action == "restriction.notified" && strings.Contains(e.Detail, "path:winrm rule:"+itoa64(notify.ID)) {
			seen["notified"] = true
		}
		if e.Action == "restriction.killed" && strings.Contains(e.Detail, "path:winrm rule:"+itoa64(kill.ID)) {
			seen["killed"] = true
		}
		if e.Action == "restriction.create" && strings.Contains(e.Detail, "action:notify") {
			seen["create"] = true
		}
	}
	for _, w := range []string{"notified", "killed", "create"} {
		if !seen[w] {
			t.Fatalf("missing audit %s in %v", w, seen)
		}
	}
	if fake.gotCmd != "Get-Process" {
		t.Fatalf("WinRM last ran %q; the killed command must never reach it", fake.gotCmd)
	}
	if s, _ := do(t, srv, http.MethodDelete, "/api/restriction-rules/"+itoa64(kill.ID), testAPIKey, nil); s != http.StatusNoContent {
		t.Fatalf("delete: %d", s)
	}
	if s, _ := do(t, srv, http.MethodDelete, "/api/restriction-rules/"+itoa64(kill.ID), testAPIKey, nil); s != http.StatusNotFound {
		t.Fatalf("delete twice: %d", s)
	}
}
