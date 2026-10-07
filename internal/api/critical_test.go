package api_test

import (
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// TestTargetCriticalFlag proves the critical flag (Phase 277) is accepted on
// create, returned, cleared by a PUT that omits it, and that both edges are
// on the target's audit row — clearing it silences the per-connection alert,
// so it must never be an invisible edit.
func TestTargetCriticalFlag(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{})
	code, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey,
		map[string]any{"name": "core-db", "host": "10.0.0.9", "os_type": "linux", "protocol": "ssh", "critical": true})
	if code != http.StatusCreated || jsonMap(t, data)["critical"] != true {
		t.Fatalf("create critical target: %d %s", code, data)
	}
	auditHas(t, st, "target.create", "critical:true")
	id := int64(jsonMap(t, data)["id"].(float64))

	code, data = do(t, srv, http.MethodPut, "/api/targets/"+itoa(id), testAPIKey,
		map[string]any{"name": "core-db", "host": "10.0.0.9", "os_type": "linux", "protocol": "ssh"})
	if code != http.StatusOK || jsonMap(t, data)["critical"] != false {
		t.Fatalf("a PUT without critical must clear it: %d %s", code, data)
	}
	auditHas(t, st, "target.update", "critical:false")
}
