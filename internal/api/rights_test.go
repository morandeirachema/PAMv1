package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestTargetAndGrantRights covers the REST surface of Phase 270: rights are
// normalized and validated on a target and on a grant, stored, listed, and
// written to the audit rows that record who may do what.
func TestTargetAndGrantRights(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{})
	status, body := do(t, srv, http.MethodPost, "/api/targets", testAPIKey,
		map[string]any{"name": "box", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh", "rights": " SSH_SFTP, ssh_shell ,ssh_sftp"})
	if status != http.StatusCreated {
		t.Fatalf("create target: %d %s", status, body)
	}
	var tgt store.Target
	_ = json.Unmarshal(body, &tgt)
	if tgt.Rights != "ssh_sftp,ssh_shell" {
		t.Fatalf("rights not normalized: %q", tgt.Rights)
	}
	if status, body = do(t, srv, http.MethodPost, "/api/targets", testAPIKey,
		map[string]any{"name": "box2", "host": "10.0.0.6", "port": 22, "os_type": "linux", "protocol": "ssh", "rights": "ssh_telnet"}); status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "unknown right") {
		t.Fatalf("unknown right: %d %s", status, body)
	}
	// Update clears it with "*".
	status, body = do(t, srv, http.MethodPut, "/api/targets/"+itoa64(tgt.ID), testAPIKey,
		map[string]any{"name": "box", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh", "rights": "*"})
	if status != http.StatusOK {
		t.Fatalf("update target: %d %s", status, body)
	}
	if got, _ := st.GetTarget(t.Context(), tgt.ID); got.Rights != "" {
		t.Fatalf("rights not cleared: %q", got.Rights)
	}
	// A grant with rights.
	status, body = do(t, srv, http.MethodPost, "/api/targets/"+itoa64(tgt.ID)+"/grants", testAPIKey,
		map[string]any{"subject_type": "role", "subject": "user", "rights": "ssh_exec,ssh_shell"})
	if status != http.StatusCreated {
		t.Fatalf("create grant: %d %s", status, body)
	}
	if status, _ = do(t, srv, http.MethodPost, "/api/targets/"+itoa64(tgt.ID)+"/grants", testAPIKey,
		map[string]any{"subject_type": "user", "subject": "bob", "rights": "rdp_clipboard"}); status != http.StatusUnprocessableEntity {
		t.Fatalf("grant with unknown right: %d", status)
	}
	status, body = do(t, srv, http.MethodGet, "/api/targets/"+itoa64(tgt.ID)+"/grants", testAPIKey, nil)
	var grants []store.TargetGrant
	_ = json.Unmarshal(body, &grants)
	if status != http.StatusOK || len(grants) != 1 || grants[0].Rights != "ssh_exec,ssh_shell" {
		t.Fatalf("list grants: %d %s", status, body)
	}
	events, _ := st.ListAudit(t.Context(), 50)
	var sawTarget, sawGrant bool
	for _, e := range events {
		if e.Action == "target.create" && strings.Contains(e.Detail, "rights:ssh_sftp,ssh_shell") {
			sawTarget = true
		}
		if e.Action == "grant.create" && strings.Contains(e.Detail, "rights:ssh_exec,ssh_shell") {
			sawGrant = true
		}
	}
	if !sawTarget || !sawGrant {
		t.Fatalf("rights missing from audit rows: target=%v grant=%v", sawTarget, sawGrant)
	}
}
