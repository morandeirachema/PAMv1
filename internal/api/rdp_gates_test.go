package api_test

import (
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// TestRDPTunnelEnforcesIPAllowlist pins the 2026-08-27 audit fix: the viewer
// tunnel, which resolves its own principal from a query-string token, runs the
// same source-IP gate the authz middleware and the session proxies run. Before
// the fix a tunnel token minted from inside a user's allowlist opened the
// desktop from anywhere it was relayed to — and, separately, a session token
// carried no allowlist at all.
func TestRDPTunnelEnforcesIPAllowlist(t *testing.T) {
	// guacd at a closed port: a request that passes every gate fails at the
	// dial with 502, which is the control that separates "refused by the gate"
	// from "never reached it".
	srv, st := newTestServerOpts(t, nil, api.Options{GuacdAddr: "127.0.0.1:1"})
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "win-gate", "host": "10.0.0.5", "port": 3389, "os_type": "windows", "protocol": "rdp",
	})
	rdpID := int64(jsonMap(t, data)["id"].(float64))
	do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": rdpID, "username": "Administrator", "secret": "s",
	})
	uid, vicTok := seedUserWithID(t, srv, "vic", "user")
	code, data := do(t, srv, http.MethodPost, "/api/rdp-token", vicTok, nil)
	if code != http.StatusOK {
		t.Fatalf("mint viewer token: %d %s", code, data)
	}
	viewerTok := jsonMap(t, data)["token"].(string)
	path := "/api/targets/" + itoa(rdpID) + "/rdp?token=" + viewerTok

	if code, d := do(t, srv, http.MethodGet, path, "", nil); code != http.StatusBadGateway {
		t.Fatalf("control (no allowlist): %d %s, want 502 from the guacd dial", code, d)
	}
	// Same role, so the viewer session survives the update; only the allowlist changes.
	if code, d := do(t, srv, http.MethodPut, "/api/users/"+itoa(uid), testAPIKey,
		map[string]any{"role": "user", "ip_allowlist": "10.0.0.0/8"}); code != http.StatusOK {
		t.Fatalf("set allowlist: %d %s", code, d)
	}
	if code, d := do(t, srv, http.MethodGet, path, "", nil); code != http.StatusForbidden {
		t.Fatalf("tunnel from outside the allowlist: %d %s, want 403", code, d)
	}
	wantAudit(t, st, "authz.denied", "/rdp", "reason:source-ip-not-allowed")
}
