package api_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// TestVendorAccessGate drives the Phase 29 vendor lifecycle over the API: mint a
// vendor, file a contract grant, a customer approves it, and only then does the
// vendor pass the connect gate (a WinRM run — CapConnect, which a vendor holds).
// Offboarding revokes everything and blocks the vendor again. Evidence exports
// with a digest.
func TestVendorAccessGate(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	srv, _ := newTestServerOpts(t, nil, api.Options{WinRM: fake})

	// A WinRM target + credential the contract will cover.
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "vend-win", "host": "10.0.0.9", "port": 5985, "os_type": "windows", "protocol": "winrm",
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "svc", "secret": "pw",
	})
	winrmPath := fmt.Sprintf("/api/targets/%d/winrm", tid)
	runBody := map[string]any{"command": "whoami"}

	// Mint a vendor (a user-role login with a token).
	vc, vd := do(t, srv, http.MethodPost, "/api/vendors", testAPIKey, map[string]any{"username": "acme-tech", "org": "ACME"})
	if vc != http.StatusCreated {
		t.Fatalf("create vendor: %d %s", vc, vd)
	}
	vendorID := int64(jsonMap(t, vd)["id"].(float64))
	vendorTok, _ := jsonMap(t, vd)["token"].(string)
	if vendorTok == "" {
		t.Fatalf("no vendor token: %s", vd)
	}

	// Before any grant, the vendor is refused by the contract gate.
	if code, rd := do(t, srv, http.MethodPost, winrmPath, vendorTok, runBody); code != http.StatusForbidden {
		t.Fatalf("vendor run without grant: want 403, got %d %s", code, rd)
	}

	// File a contract grant (pending): now-1m .. +1h.
	nb := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	na := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	gc, gd := do(t, srv, http.MethodPost, fmt.Sprintf("/api/vendors/%d/grants", vendorID), testAPIKey, map[string]any{
		"target": "vend-win", "principal": "svc", "not_before": nb, "not_after": na,
	})
	if gc != http.StatusCreated {
		t.Fatalf("create grant: %d %s", gc, gd)
	}
	grantID := int64(jsonMap(t, gd)["id"].(float64))

	// A pending grant does not yet admit the vendor.
	if code, _ := do(t, srv, http.MethodPost, winrmPath, vendorTok, runBody); code != http.StatusForbidden {
		t.Fatalf("vendor run on a pending grant: want 403, got %d", code)
	}

	// A customer approver activates the grant.
	approver := seedUser(t, srv, "customer-appr", "approver")
	if code, ad := do(t, srv, http.MethodPost, fmt.Sprintf("/api/vendor-grants/%d/approve", grantID), approver, nil); code != http.StatusOK {
		t.Fatalf("approve grant: %d %s", code, ad)
	}

	// Now the vendor passes the gate and the WinRM command runs.
	if code, rd := do(t, srv, http.MethodPost, winrmPath, vendorTok, runBody); code != http.StatusOK {
		t.Fatalf("vendor run after approval: want 200, got %d %s", code, rd)
	}

	// Offboard: revoke grants + block the vendor again.
	if code, od := do(t, srv, http.MethodPost, fmt.Sprintf("/api/vendors/%d/offboard", vendorID), testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("offboard: %d %s", code, od)
	}
	if code, _ := do(t, srv, http.MethodPost, winrmPath, vendorTok, runBody); code != http.StatusForbidden {
		t.Fatalf("vendor run after offboard: want 403, got %d", code)
	}

	// Evidence bundle carries the vendor's record + audit slice (its SHA-256 digest
	// is recorded in the vendor.evidence_export audit event asserted below).
	ec, ev, _, _ := playbackGet(t, srv.URL+fmt.Sprintf("/api/vendors/%d/evidence", vendorID), testAPIKey)
	if ec != http.StatusOK || !strings.Contains(string(ev), "acme-tech") {
		t.Fatalf("evidence: %d body=%s", ec, ev)
	}
	// The offboard and evidence export are audited.
	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=80", testAPIKey, nil)
	for _, want := range []string{"vendor.create", "vendor.grant_approved", "vendor.offboard", "vendor.evidence_export"} {
		if !strings.Contains(string(aud), want) {
			t.Fatalf("audit missing %q: %s", want, aud)
		}
	}
}
