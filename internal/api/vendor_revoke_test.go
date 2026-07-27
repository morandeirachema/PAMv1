package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// TestVendorGrantRevoke proves POST /api/vendor-grants/{gid}/revoke ends an
// approved contract early: the grant shows revoked, the vendor's access is
// gone, and the action is authorized like other target management.
func TestVendorGrantRevoke(t *testing.T) {
	srv, st := newTestServerStore(t)
	createTestTarget(t, srv, "vg-target", "10.5.0.1")

	code, data := do(t, srv, http.MethodPost, "/api/vendors", testAPIKey, map[string]any{"username": "vg-tech", "org": "VG"})
	if code != http.StatusCreated {
		t.Fatalf("create vendor: %d %s", code, data)
	}
	vid := int64(jsonMap(t, data)["id"].(float64))
	code, data = do(t, srv, http.MethodPost, fmt.Sprintf("/api/vendors/%d/grants", vid), testAPIKey, map[string]any{
		"target": "vg-target", "principal": "root", "not_after": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	})
	if code != http.StatusCreated {
		t.Fatalf("create grant: %d %s", code, data)
	}
	gid := int64(jsonMap(t, data)["id"].(float64))
	approverTok := seedUser(t, srv, "vg-approver", "approver")
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/vendor-grants/%d/approve", gid), approverTok, nil); code != http.StatusOK {
		t.Fatalf("approve grant: %d %s", code, d)
	}

	// A plain user cannot revoke a contract grant.
	userTok := seedUser(t, srv, "vg-user", "user")
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/vendor-grants/%d/revoke", gid), userTok, nil); code != http.StatusForbidden {
		t.Fatalf("user revoke: want 403, got %d", code)
	}
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/vendor-grants/%d/revoke", gid), testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("revoke grant: %d %s", code, d)
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/vendor-grants/99999/revoke", testAPIKey, nil); code != http.StatusNotFound {
		t.Fatalf("revoke unknown grant: want 404, got %d", code)
	}

	_, gl := do(t, srv, http.MethodGet, fmt.Sprintf("/api/vendors/%d/grants", vid), testAPIKey, nil)
	var grants []map[string]any
	if err := json.Unmarshal(gl, &grants); err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0]["status"] != "revoked" {
		t.Fatalf("grant not revoked: %s", gl)
	}
	auditHas(t, st, "vendor.grant_revoked", fmt.Sprintf("grant:%d", gid))

	// The revoked contract no longer admits the vendor anywhere.
	if isVendor, allowed, err := st.VendorSessionAllowed(t.Context(), "vg-tech", "vg-target", "root", time.Now()); err != nil || !isVendor || allowed {
		t.Fatalf("revoked grant still admits: isVendor=%v allowed=%v err=%v", isVendor, allowed, err)
	}
}
