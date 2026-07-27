package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestListSSHCertsEndpoint proves GET /api/ca/ssh/certs lists issued operator
// certificates newest-first with their revocation state — the serials the
// console's revoke screen needs — behind authentication, working even when the
// CA itself is not configured (the rows are the revocation handles either way).
func TestListSSHCertsEndpoint(t *testing.T) {
	srv, st := newTestServerStore(t)
	ctx := context.Background()
	for _, c := range []store.SSHCert{
		{Serial: 101, KeyID: "pamv1-alice-1", Principal: "root", Actor: "alice"},
		{Serial: 102, KeyID: "pamv1-bob-1", Principal: "deploy", Actor: "bob"},
	} {
		cert := c
		if err := st.RecordSSHCert(ctx, &cert); err != nil {
			t.Fatalf("RecordSSHCert: %v", err)
		}
	}
	if err := st.RevokeSSHCert(ctx, 101, "admin", time.Now()); err != nil {
		t.Fatalf("RevokeSSHCert: %v", err)
	}

	code, data := do(t, srv, http.MethodGet, "/api/ca/ssh/certs", testAPIKey, nil)
	if code != http.StatusOK {
		t.Fatalf("list certs: %d %s", code, data)
	}
	var certs []map[string]any
	if err := json.Unmarshal(data, &certs); err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || certs[0]["serial"].(float64) != 102 {
		t.Fatalf("want 2 certs newest-first, got %s", data)
	}
	if certs[1]["revoked_at"] == nil || certs[1]["revoked_by"] != "admin" {
		t.Fatalf("revocation state not surfaced: %s", data)
	}

	// Authentication is required; any inventory-reading role may list.
	if code, _ := do(t, srv, http.MethodGet, "/api/ca/ssh/certs", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: want 401, got %d", code)
	}
	audTok := seedUser(t, srv, "aud-cert", "auditor")
	if code, _ := do(t, srv, http.MethodGet, "/api/ca/ssh/certs", audTok, nil); code != http.StatusOK {
		t.Fatalf("auditor list: want 200, got %d", code)
	}
}
