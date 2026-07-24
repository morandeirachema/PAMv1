package vendor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAttestor proves the employment-attestation webhook: a nil Attestor accepts
// anyone, a 2xx response attests the vendor, and a non-2xx refuses.
func TestAttestor(t *testing.T) {
	ctx := context.Background()

	// Disabled (nil) accepts every vendor.
	var none *Attestor
	if none.Enabled() {
		t.Fatal("nil attestor must be disabled")
	}
	if err := none.Attest(ctx, "acme", "ACME"); err != nil {
		t.Fatalf("nil attestor must accept: %v", err)
	}

	// A webhook that receives the vendor and answers 2xx attests.
	var gotVendor string
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Vendor, Org string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotVendor = body.Vendor
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	a := NewAttestor(ok.URL)
	if !a.Enabled() {
		t.Fatal("configured attestor must be enabled")
	}
	if err := a.Attest(ctx, "acme-tech", "ACME"); err != nil {
		t.Fatalf("2xx must attest: %v", err)
	}
	if gotVendor != "acme-tech" {
		t.Fatalf("webhook got vendor %q, want acme-tech", gotVendor)
	}

	// A 403 (offboarded by employer) refuses.
	no := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer no.Close()
	if err := NewAttestor(no.URL).Attest(ctx, "acme-tech", "ACME"); err == nil {
		t.Fatal("a non-2xx attestation must be refused")
	}
}
