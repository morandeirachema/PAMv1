package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
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
	// Realistic serials: sshca seeds them from a nanosecond clock, so a real one
	// is ~1.7e18 — far above 2^53, the largest integer a JavaScript number holds
	// exactly. The original version of this test used 101 and 102, which is
	// exactly why it passed while the console's revoke option could not revoke a
	// real certificate.
	const (
		serialAlice int64 = 1753622400123456789
		serialBob   int64 = 1753622400123456790 // differs from Alice's only in the last digit
	)
	for _, c := range []store.SSHCert{
		{Serial: serialAlice, KeyID: "pamv1-alice-1", Principal: "root", Actor: "alice"},
		{Serial: serialBob, KeyID: "pamv1-bob-1", Principal: "deploy", Actor: "bob"},
	} {
		cert := c
		if err := st.RecordSSHCert(ctx, &cert); err != nil {
			t.Fatalf("RecordSSHCert: %v", err)
		}
	}
	if err := st.RevokeSSHCert(ctx, serialAlice, "admin", time.Now()); err != nil {
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
	if len(certs) != 2 {
		t.Fatalf("want 2 certs newest-first, got %s", data)
	}
	// The serial must arrive as a STRING carrying every digit. As a JSON number
	// it would round to …6790 for both certificates, and a rounded serial revokes
	// nothing: the published KRL would name a certificate that does not exist
	// while the real one stayed valid until it expired.
	gotSerial, ok := certs[0]["serial"].(string)
	if !ok {
		t.Fatalf("serial is %T, want a JSON string — a number loses precision above 2^53: %s", certs[0]["serial"], data)
	}
	if want := strconv.FormatInt(serialBob, 10); gotSerial != want {
		t.Fatalf("serial round-tripped as %q, want %q (every digit must survive)", gotSerial, want)
	}
	// And the two serials must still be distinguishable, which is the whole point.
	if certs[1]["serial"] == certs[0]["serial"] {
		t.Fatalf("the two serials collapsed to the same value: %s", data)
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
