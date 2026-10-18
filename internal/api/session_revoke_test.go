package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestRevokeLoginSessions proves an admin can force-invalidate all active login
// sessions for a username (the control missing for directory/SSO logins, which
// create session rows rather than user rows).
func TestRevokeLoginSessions(t *testing.T) {
	srv, st := newTestServerStore(t)
	future := time.Now().Add(time.Hour).UTC()

	// Seed two active sessions for "alice" and one for "bob".
	for _, s := range []store.Session{
		{Username: "alice", Role: "user", TokenHash: "hash-a1", ExpiresAt: future},
		{Username: "alice", Role: "user", TokenHash: "hash-a2", ExpiresAt: future},
		{Username: "bob", Role: "user", TokenHash: "hash-b1", ExpiresAt: future},
	} {
		if err := st.CreateSession(context.Background(), &s); err != nil {
			t.Fatal(err)
		}
	}

	// The admin's view of who is logged in: all three, and never a token hash.
	status, data := do(t, srv, http.MethodGet, "/api/login-sessions", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("list: want 200, got %d (%s)", status, data)
	}
	if n := len(jsonArray(t, data)); n != 3 {
		t.Fatalf("listed %d login sessions, want 3 (%s)", n, data)
	}
	if strings.Contains(string(data), "hash-a1") {
		t.Fatalf("the listing leaked a token hash: %s", data)
	}

	status, data = do(t, srv, http.MethodPost, "/api/login-sessions/revoke", testAPIKey, map[string]any{
		"username": "alice",
	})
	if status != http.StatusOK {
		t.Fatalf("revoke: want 200, got %d (%s)", status, data)
	}
	if got := int(jsonMap(t, data)["revoked"].(float64)); got != 2 {
		t.Fatalf("revoked = %d, want 2", got)
	}

	// alice's sessions are gone; bob's remains.
	if _, err := st.GetSessionByTokenHash(context.Background(), "hash-a1"); err == nil {
		t.Fatal("alice session hash-a1 should have been revoked")
	}
	if _, err := st.GetSessionByTokenHash(context.Background(), "hash-b1"); err != nil {
		t.Fatalf("bob session should survive: %v", err)
	}

	// A non-admin (user) token may not revoke sessions.
	_, ud := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "carol", "role": "user"})
	userToken, _ := jsonMap(t, ud)["token"].(string)
	if userToken == "" {
		t.Fatal("expected a user token")
	}
	status, _ = do(t, srv, http.MethodPost, "/api/login-sessions/revoke", userToken, map[string]any{"username": "bob"})
	if status != http.StatusForbidden {
		t.Fatalf("non-admin revoke: want 403, got %d", status)
	}
}
