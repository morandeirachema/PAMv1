package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
)

// TestLockUser proves an administrator's lock (Phase 242) cuts access at
// once — the token stops resolving, live login sessions are revoked — is
// audited with its reason, refuses a self-lock and an empty reason, lifts
// on unlock, and lifts by itself when its until passes.
func TestLockUser(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{})
	aliceID, aliceTok := seedUserWithID(t, srv, "alice", "user")
	base := fmt.Sprintf("/api/users/%d/lock", aliceID)
	if code, _ := do(t, srv, http.MethodGet, "/api/targets", aliceTok, nil); code != http.StatusOK {
		t.Fatalf("alice's token must work before the lock: %d", code)
	}
	if code, data := do(t, srv, http.MethodPost, base, testAPIKey, map[string]any{"reason": "  "}); code != http.StatusUnprocessableEntity {
		t.Fatalf("empty reason: %d %s", code, data)
	}
	if code, data := do(t, srv, http.MethodPost, base, testAPIKey, map[string]any{"reason": "x", "until": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}); code != http.StatusUnprocessableEntity {
		t.Fatalf("past until: %d %s", code, data)
	}
	code, data := do(t, srv, http.MethodPost, base, testAPIKey, map[string]any{"reason": "suspected credential theft"})
	if code != http.StatusOK || jsonMap(t, data)["locked_reason"] != "suspected credential theft" {
		t.Fatalf("lock: %d %s", code, data)
	}
	if code, _ := do(t, srv, http.MethodGet, "/api/targets", aliceTok, nil); code != http.StatusUnauthorized {
		t.Fatalf("a locked user's token must be refused, got %d", code)
	}
	auditHas(t, st, "user.lock", "alice reason:")
	auditHas(t, st, "session.revoked", "user:alice sessions:0 killed:0 reason:locked")
	if code, data := do(t, srv, http.MethodGet, "/api/users", testAPIKey, nil); code != http.StatusOK || !strings.Contains(string(data), `"locked_reason":"suspected credential theft"`) {
		t.Fatalf("list must show the lock: %d %s", code, data)
	}
	if code, data := do(t, srv, http.MethodDelete, base, testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("unlock: %d %s", code, data)
	}
	auditHas(t, st, "user.unlock", "alice")
	if code, _ := do(t, srv, http.MethodGet, "/api/targets", aliceTok, nil); code != http.StatusOK {
		t.Fatalf("an unlocked user's token must resolve again, got %d", code)
	}
	// A timed lock lifts by itself.
	until := time.Now().Add(400 * time.Millisecond).UTC()
	if code, data := do(t, srv, http.MethodPost, base, testAPIKey, map[string]any{"reason": "cool-down", "until": until.Format(time.RFC3339Nano)}); code != http.StatusOK {
		t.Fatalf("timed lock: %d %s", code, data)
	}
	if code, _ := do(t, srv, http.MethodGet, "/api/targets", aliceTok, nil); code != http.StatusUnauthorized {
		t.Fatalf("timed lock must bind while it lasts, got %d", code)
	}
	time.Sleep(600 * time.Millisecond)
	if code, _ := do(t, srv, http.MethodGet, "/api/targets", aliceTok, nil); code != http.StatusOK {
		t.Fatalf("an expired lock must lift by itself, got %d", code)
	}
	// An admin cannot lock themselves out.
	_, adminTok := seedUserWithID(t, srv, "root2", "admin")
	code, data = do(t, srv, http.MethodGet, "/api/users", adminTok, nil)
	if code != http.StatusOK {
		t.Fatalf("list as root2: %d %s", code, data)
	}
	var users []map[string]any
	if err := json.Unmarshal(data, &users); err != nil {
		t.Fatal(err)
	}
	var rootID int64
	for _, u := range users {
		if u["username"] == "root2" {
			rootID = int64(u["id"].(float64))
		}
	}
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/users/%d/lock", rootID), adminTok, map[string]any{"reason": "oops"}); code != http.StatusForbidden {
		t.Fatalf("self-lock: %d %s, want 403", code, data)
	}
}

// TestRotateUserTokenAndExpiry proves token rotation (Phase 242) returns a
// fresh token once, refuses the old one from that instant, honours a
// per-request TTL and the deployment default, and that an expired token is
// refused while the user row, its role and its grants survive.
func TestRotateUserTokenAndExpiry(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{UserTokenTTL: time.Hour})
	aliceID, oldTok := seedUserWithID(t, srv, "alice", "user")
	// The deployment default applied at mint: an expiry an hour out.
	code, data := do(t, srv, http.MethodGet, "/api/users", testAPIKey, nil)
	if code != http.StatusOK || !strings.Contains(string(data), `"token_expires_at"`) {
		t.Fatalf("minted token must carry the default expiry: %d %s", code, data)
	}
	code, data = do(t, srv, http.MethodPost, fmt.Sprintf("/api/users/%d/token", aliceID), testAPIKey, map[string]any{"token_ttl_hours": 48})
	if code != http.StatusOK {
		t.Fatalf("rotate: %d %s", code, data)
	}
	m := jsonMap(t, data)
	newTok, _ := m["token"].(string)
	exp, _ := time.Parse(time.RFC3339, fmt.Sprint(m["token_expires_at"]))
	if newTok == "" || newTok == oldTok || exp.Before(time.Now().Add(47*time.Hour)) {
		t.Fatalf("rotation response: %+v", m)
	}
	if code, _ := do(t, srv, http.MethodGet, "/api/targets", oldTok, nil); code != http.StatusUnauthorized {
		t.Fatalf("the old token must stop working, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodGet, "/api/targets", newTok, nil); code != http.StatusOK {
		t.Fatalf("the new token must work, got %d", code)
	}
	auditHas(t, st, "user.token_rotate", "alice token_expires:")
	auditHas(t, st, "session.revoked", "reason:token-rotated")
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/users/%d/token", aliceID), testAPIKey, map[string]any{"token_ttl_hours": -1}); code != http.StatusUnprocessableEntity {
		t.Fatalf("negative ttl: %d %s", code, data)
	}
	// An expired token is refused, and the row is intact for the next rotation.
	code, data = do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "bob", "role": "user", "token_ttl_hours": 1})
	if code != http.StatusCreated {
		t.Fatalf("create bob: %d %s", code, data)
	}
	bob := jsonMap(t, data)
	bobTok := bob["token"].(string)
	if code, _ := do(t, srv, http.MethodGet, "/api/targets", bobTok, nil); code != http.StatusOK {
		t.Fatalf("bob's fresh token must work, got %d", code)
	}
	past := time.Now().Add(-time.Second)
	if err := st.RotateUserToken(t.Context(), int64(bob["id"].(float64)), auth.TokenHash(bobTok), &past); err != nil {
		t.Fatal(err)
	}
	if code, _ := do(t, srv, http.MethodGet, "/api/targets", bobTok, nil); code != http.StatusUnauthorized {
		t.Fatalf("an expired token must be refused, got %d", code)
	}
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/users/%d/token", int64(bob["id"].(float64))), testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("rotating an expired token: %d %s", code, data)
	}
}
