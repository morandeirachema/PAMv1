package api_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/mfa"
)

// TestMFAStatusReportsRecoveryCodesLeft covers Phase 177's first wired-up
// finding: the store could count a user's remaining recovery codes since Phase
// 3b and nothing ever asked. Codes are single-use and only regenerated
// deliberately, so an account can reach zero silently — one lost phone away from
// a support ticket.
func TestMFAStatusReportsRecoveryCodesLeft(t *testing.T) {
	srv := newTestServer(t)
	tok := seedUser(t, srv, "mona", "user")

	// Before enrolling there is no count to report — the status is the two
	// booleans it always was.
	_, sd := do(t, srv, http.MethodGet, "/api/mfa", tok, nil)
	if m := jsonMap(t, sd); m["enrolled"] != false {
		t.Fatalf("unenrolled status: %s", sd)
	}
	st, ed := do(t, srv, http.MethodPost, "/api/mfa/enroll", tok, nil)
	if st != http.StatusCreated {
		t.Fatalf("enroll: %d %s", st, ed)
	}
	secret, _ := jsonMap(t, ed)["secret"].(string)
	code, err := mfa.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if st, d := do(t, srv, http.MethodPost, "/api/mfa/verify", tok, map[string]any{"otp": code}); st != http.StatusOK {
		t.Fatalf("confirm: %d %s", st, d)
	}
	_, sd2 := do(t, srv, http.MethodGet, "/api/mfa", tok, nil)
	if m := jsonMap(t, sd2); m["recovery_codes_remaining"] != float64(0) {
		t.Fatalf("a fresh enrollment has no recovery codes yet: %s", sd2)
	}

	if st, d := do(t, srv, http.MethodPost, "/api/mfa/recovery-codes", tok, nil); st != http.StatusCreated {
		t.Fatalf("generate recovery codes: %d %s", st, d)
	}
	_, sd3 := do(t, srv, http.MethodGet, "/api/mfa", tok, nil)
	n, _ := jsonMap(t, sd3)["recovery_codes_remaining"].(float64)
	if n <= 0 {
		t.Fatalf("generated codes should be counted: %s", sd3)
	}
	if strings.Contains(string(sd3), "\"codes\"") {
		t.Fatalf("the status must report the COUNT, never the codes: %s", sd3)
	}
}

// TestVendorEmailIsCorrectable covers Phase 177's second wired-up finding. A
// vendor's contact address is where a magic-link approval invite is sent, and it
// could be set at creation and never fixed — a typo meant every invite went
// nowhere, with the store method to correct it sitting unused since Phase 116.
func TestVendorEmailIsCorrectable(t *testing.T) {
	srv := newTestServer(t)
	st, cd := do(t, srv, http.MethodPost, "/api/vendors", testAPIKey,
		map[string]any{"username": "acme-tech", "org": "ACME", "email": "wrong@acme.example"})
	if st != http.StatusCreated {
		t.Fatalf("create vendor: %d %s", st, cd)
	}
	id := int64(jsonMap(t, cd)["id"].(float64))

	// A malformed address is refused rather than stored and mailed into the void.
	if st, d := do(t, srv, http.MethodPut, "/api/vendors/"+itoa(id), testAPIKey,
		map[string]any{"org": "ACME", "email": "not-an-address"}); st != http.StatusUnprocessableEntity {
		t.Fatalf("a malformed email must be refused: %d %s", st, d)
	}
	if st, d := do(t, srv, http.MethodPut, "/api/vendors/"+itoa(id), testAPIKey,
		map[string]any{"org": "ACME", "email": "ops@acme.example"}); st != http.StatusOK {
		t.Fatalf("correcting the address: %d %s", st, d)
	}
	_, ld := do(t, srv, http.MethodGet, "/api/vendors", testAPIKey, nil)
	if !strings.Contains(string(ld), "ops@acme.example") || strings.Contains(string(ld), "wrong@acme.example") {
		t.Fatalf("the corrected address should be the one on file: %s", ld)
	}

	// An org-only edit leaves the address alone — "not supplied" is not "clear
	// it", which is why the field is a pointer.
	if st, d := do(t, srv, http.MethodPut, "/api/vendors/"+itoa(id), testAPIKey,
		map[string]any{"org": "ACME Industries"}); st != http.StatusOK {
		t.Fatalf("org-only edit: %d %s", st, d)
	}
	_, ld2 := do(t, srv, http.MethodGet, "/api/vendors", testAPIKey, nil)
	if !strings.Contains(string(ld2), "ops@acme.example") || !strings.Contains(string(ld2), "ACME Industries") {
		t.Fatalf("an org edit must not wipe the email: %s", ld2)
	}
}
