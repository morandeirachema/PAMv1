package slack

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sign(secret, timestamp, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + timestamp + ":" + body))
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

// TestVerifySignature proves Slack's v0 request-signing scheme: a correctly
// signed, fresh request verifies; a wrong secret, a tampered body, a stale
// timestamp and a missing signature are all refused.
func TestVerifySignature(t *testing.T) {
	secret := "shh"
	body := `{"hello":"world"}`
	now := strconv.FormatInt(time.Now().Unix(), 10)

	if !VerifySignature(secret, now, body, sign(secret, now, body)) {
		t.Fatal("a correctly signed, fresh request must verify")
	}
	if VerifySignature("wrong-secret", now, body, sign(secret, now, body)) {
		t.Fatal("a signature computed with a different secret must not verify")
	}
	if VerifySignature(secret, now, body+"tampered", sign(secret, now, body)) {
		t.Fatal("a tampered body must not verify")
	}
	stale := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	if VerifySignature(secret, stale, body, sign(secret, stale, body)) {
		t.Fatal("a stale (replayed) timestamp must not verify even with a correct signature")
	}
	if VerifySignature(secret, now, body, "") {
		t.Fatal("an empty signature must not verify")
	}
	if VerifySignature("", now, body, sign(secret, now, body)) {
		t.Fatal("an empty signing secret must never verify (disabled, not permissive)")
	}
}

// TestSignAndParseToken proves the button-value token round-trips, and
// that forgery, tampering and expiry are all refused.
func TestSignAndParseToken(t *testing.T) {
	secret := "shh"
	exp := time.Now().Add(time.Hour)

	tok := SignToken(secret, 42, "approved", exp)
	gotID, gotDecision, err := ParseToken(secret, tok)
	if err != nil {
		t.Fatalf("a validly signed token must parse: %v", err)
	}
	if gotID != 42 || gotDecision != "approved" {
		t.Fatalf("got (%d, %q), want (42, approved)", gotID, gotDecision)
	}

	if _, _, err := ParseToken("wrong-secret", tok); err == nil {
		t.Fatal("a token signed with a different secret must not parse")
	}
	tampered := strings.Replace(tok, "42", "43", 1)
	if _, _, err := ParseToken(secret, tampered); err == nil {
		t.Fatal("a tampered token must not parse")
	}
	expired := SignToken(secret, 42, "approved", time.Now().Add(-time.Minute))
	if _, _, err := ParseToken(secret, expired); err == nil {
		t.Fatal("an expired token must not parse")
	}
	if _, _, err := ParseToken(secret, "not-a-token"); err == nil {
		t.Fatal("a malformed token must not parse")
	}
}

// TestPostJSON proves the outbound POST succeeds on 2xx and fails
// otherwise.
func TestPostJSON(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	if err := PostJSON(t.Context(), ok.URL, []byte(`{}`)); err != nil {
		t.Fatalf("a 2xx response must succeed: %v", err)
	}

	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer fail.Close()
	if err := PostJSON(t.Context(), fail.URL, []byte(`{}`)); err == nil {
		t.Fatal("a non-2xx response must fail")
	}
}
