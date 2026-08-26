package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
)

// dlReveal is a small helper around a DoubleLock-adjacent request that lets a
// test set (or omit) the X-DoubleLock-Password header, which the shared do()
// helper (api_test.go) has no way to attach.
func dlReveal(t *testing.T, srv *httptest.Server, method, path, apiKey, dlPassword string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", apiKey)
	if dlPassword != "" {
		req.Header.Set("X-DoubleLock-Password", dlPassword)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, buf[:n]
}

// seedTargetAndCred creates a target and a password credential over the
// existing REST surface, returning the credential ID.
func seedTargetAndCred(t *testing.T, srv *httptest.Server) int64 {
	t.Helper()
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "t-dl", "host": "h", "os_type": "linux", "protocol": "ssh",
	})
	tid := int64(jsonMap(t, data)["id"].(float64))
	_, data = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "root", "secret": secretPassword,
	})
	return int64(jsonMap(t, data)["id"].(float64))
}

// TestDoubleLockLifecycle proves the whole Phase 135 flow end to end: a plain
// reveal works before DoubleLock is ever set; enabling it requires holder
// and password; a reveal with no password (or the wrong one) is refused
// once set; the right password returns the ORIGINAL secret; and — the
// entire point of the feature — an admin alone cannot disable it without
// that same password.
func TestDoubleLockLifecycle(t *testing.T) {
	srv := newTestServer(t)
	cid := seedTargetAndCred(t, srv)
	path := "/api/credentials/" + itoa(cid)

	// Baseline: reveal works normally before DoubleLock is ever set.
	code, data := do(t, srv, http.MethodPost, path+"/reveal", testAPIKey, nil)
	if code != http.StatusOK || jsonMap(t, data)["secret"] != secretPassword {
		t.Fatalf("baseline reveal: %d %s", code, data)
	}

	// Enabling requires both holder and password.
	if code, d := do(t, srv, http.MethodPost, path+"/doublelock", testAPIKey,
		map[string]any{"holder": "alice"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("enable with no password: %d %s, want 422", code, d)
	}
	if code, d := do(t, srv, http.MethodPost, path+"/doublelock", testAPIKey,
		map[string]any{"holder": "alice", "password": "correct horse battery staple"}); code != http.StatusNoContent {
		t.Fatalf("enable doublelock: %d %s", code, d)
	}

	// Reveal with no password header is refused.
	if code, d := dlReveal(t, srv, http.MethodPost, path+"/reveal", testAPIKey, ""); code != http.StatusForbidden {
		t.Fatalf("reveal with no doublelock password: %d %s, want 403", code, d)
	}
	// Reveal with the WRONG password is refused.
	if code, d := dlReveal(t, srv, http.MethodPost, path+"/reveal", testAPIKey, "wrong-password"); code != http.StatusForbidden {
		t.Fatalf("reveal with wrong doublelock password: %d %s, want 403", code, d)
	}
	// Reveal with the RIGHT password returns the ORIGINAL secret.
	code, data = dlReveal(t, srv, http.MethodPost, path+"/reveal", testAPIKey, "correct horse battery staple")
	if code != http.StatusOK || jsonMap(t, data)["secret"] != secretPassword {
		t.Fatalf("reveal with correct doublelock password: %d %s", code, data)
	}

	// The entire point: an admin holding CapRevealSecret CANNOT disable
	// DoubleLock without the password.
	if code, d := do(t, srv, http.MethodDelete, path+"/doublelock", testAPIKey,
		map[string]any{"password": "wrong-password"}); code != http.StatusForbidden {
		t.Fatalf("disable with wrong password: %d %s, want 403", code, d)
	}
	// Reveal still requires the password — the failed disable attempt above
	// must not have weakened anything.
	if code, d := dlReveal(t, srv, http.MethodPost, path+"/reveal", testAPIKey, ""); code != http.StatusForbidden {
		t.Fatalf("reveal after failed disable attempt: %d %s, want still 403", code, d)
	}
	// The correct password disables it.
	if code, d := do(t, srv, http.MethodDelete, path+"/doublelock", testAPIKey,
		map[string]any{"password": "correct horse battery staple"}); code != http.StatusNoContent {
		t.Fatalf("disable with correct password: %d %s", code, d)
	}
	// Reveal is back to normal, no header needed.
	code, data = do(t, srv, http.MethodPost, path+"/reveal", testAPIKey, nil)
	if code != http.StatusOK || jsonMap(t, data)["secret"] != secretPassword {
		t.Fatalf("reveal after disable: %d %s", code, data)
	}
}

// TestDoubleLockGatesCheckout proves checkout (not just reveal) is gated the
// same way, and that a rejected checkout attempt rolls back the lease it
// tentatively created rather than blocking the credential for the whole TTL.
func TestDoubleLockGatesCheckout(t *testing.T) {
	srv := newTestServer(t)
	cid := seedTargetAndCred(t, srv)
	path := "/api/credentials/" + itoa(cid)
	do(t, srv, http.MethodPost, path+"/doublelock", testAPIKey,
		map[string]any{"holder": "alice", "password": "correct horse battery staple"})

	// No password: refused, and the lease must have been rolled back (a
	// second attempt is not blocked by "already checked out").
	if code, d := dlReveal(t, srv, http.MethodPost, path+"/checkout", testAPIKey, ""); code != http.StatusForbidden {
		t.Fatalf("checkout with no doublelock password: %d %s, want 403", code, d)
	}
	if code, d := dlReveal(t, srv, http.MethodPost, path+"/checkout", testAPIKey, "wrong"); code != http.StatusForbidden {
		t.Fatalf("checkout with wrong doublelock password: %d %s, want 403", code, d)
	}
	// The correct password checks it out and returns the real secret.
	code, data := dlReveal(t, srv, http.MethodPost, path+"/checkout", testAPIKey, "correct horse battery staple")
	if code != http.StatusCreated || jsonMap(t, data)["secret"] != secretPassword {
		t.Fatalf("checkout with correct doublelock password: %d %s", code, data)
	}
}

// TestDoubleLockRejectsZSPCredential proves a Zero Standing Privilege
// credential (no stored secret to protect) cannot be double-locked.
func TestDoubleLockRejectsZSPCredential(t *testing.T) {
	srv := newTestServer(t)
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "t-zsp", "host": "h", "os_type": "linux", "protocol": "ssh",
	})
	tid := int64(jsonMap(t, data)["id"].(float64))
	_, data = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "root", "secret_type": "ssh_ca",
	})
	cid := int64(jsonMap(t, data)["id"].(float64))

	if code, d := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(cid)+"/doublelock", testAPIKey,
		map[string]any{"holder": "alice", "password": "correct horse battery staple"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("doublelock on a ZSP credential: %d %s, want 422", code, d)
	}
}

// TestDoubleLockClearedByRotation proves a real credential rotation (the
// secret value actually changing) clears DoubleLock — a stale
// password-derived ciphertext sealing the OLD secret would otherwise be
// silently handed back as if it were current. The store-contract suite
// already proves the field-clearing invariant directly; this closes the
// loop from the REST caller's perspective.
func TestDoubleLockClearedByRotation(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{})
	cid := seedTargetAndCred(t, srv)
	path := "/api/credentials/" + itoa(cid)
	do(t, srv, http.MethodPost, path+"/doublelock", testAPIKey,
		map[string]any{"holder": "alice", "password": "correct horse battery staple"})

	// Simulate what the rotation worker does: replace the secret and stamp
	// rotated_at.
	if err := st.RotateCredentialSecret(context.Background(), cid, "v2:rotated-placeholder", time.Now()); err != nil {
		t.Fatalf("RotateCredentialSecret: %v", err)
	}

	c, err := st.GetCredential(context.Background(), cid)
	if err != nil {
		t.Fatal(err)
	}
	if c.DoubleLockHolder != "" {
		t.Fatalf("DoubleLock survived rotation: holder=%q", c.DoubleLockHolder)
	}
	// Reveal no longer treats the old password as meaningful — it just fails
	// as a plain decrypt failure ("v2:rotated-placeholder" is not a real
	// vault token), not a doublelock-password refusal.
	code, data := dlReveal(t, srv, http.MethodPost, path+"/reveal", testAPIKey, "correct horse battery staple")
	if code != http.StatusInternalServerError {
		t.Fatalf("reveal after rotation: %d %s, want 500 (plain decrypt failure, not doublelock)", code, data)
	}
	if strings.Contains(strings.ToLower(string(data)), "doublelock") {
		t.Fatalf("reveal error after rotation still mentions doublelock: %s", data)
	}
}

// TestDoubleLockRejectsShortPassword is the regression test for the 2026-08-26
// audit's finding H-3. DoubleLockEnc is a copy of the secret living OUTSIDE the
// KEK, so the password is the only thing protecting it after a database
// compromise — and it was validated only for being non-empty. A short password
// is now refused before anything is sealed.
func TestDoubleLockRejectsShortPassword(t *testing.T) {
	srv := newTestServer(t)
	cid := seedTargetAndCred(t, srv)
	path := "/api/credentials/" + itoa(cid)

	if code, d := do(t, srv, http.MethodPost, path+"/doublelock", testAPIKey,
		map[string]any{"holder": "alice", "password": "short"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("a 5-char double-lock password was accepted: %d %s, want 422", code, d)
	}
	// A password at the floor is accepted.
	if code, d := do(t, srv, http.MethodPost, path+"/doublelock", testAPIKey,
		map[string]any{"holder": "alice", "password": "sixteen-chars-ok"}); code != http.StatusNoContent {
		t.Fatalf("a 16-char password was refused: %d %s", code, d)
	}
}
