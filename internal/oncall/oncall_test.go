package oncall

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAttestor proves the on-call webhook: a nil Attestor accepts anyone, a
// 2xx response attests the user is on call, and a non-2xx refuses.
func TestAttestor(t *testing.T) {
	ctx := context.Background()

	// Disabled (nil) accepts every user.
	var none *Attestor
	if none.Enabled() {
		t.Fatal("nil attestor must be disabled")
	}
	if err := none.Attest(ctx, "alice"); err != nil {
		t.Fatalf("nil attestor must accept: %v", err)
	}

	// A webhook that receives the user and answers 2xx attests.
	var gotUser string
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ User string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotUser = body.User
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	a := NewAttestor(ok.URL)
	if !a.Enabled() {
		t.Fatal("configured attestor must be enabled")
	}
	if err := a.Attest(ctx, "alice"); err != nil {
		t.Fatalf("2xx must attest: %v", err)
	}
	if gotUser != "alice" {
		t.Fatalf("webhook got user %q, want alice", gotUser)
	}

	// A 403 (not on call) refuses.
	no := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer no.Close()
	if err := NewAttestor(no.URL).Attest(ctx, "alice"); err == nil {
		t.Fatal("a non-2xx attestation must be refused")
	}
}
