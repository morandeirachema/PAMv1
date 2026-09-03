package auth

import (
	"context"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestResolveRefusesLockedAndExpired proves the resolver honours an
// administrator's lock and a token's expiry (Phase 242) on BOTH paths a
// local identity authenticates through: its own token, and a login session
// minted for it. An expired lock lifts by itself.
func TestResolveRefusesLockedAndExpired(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	r, err := NewResolver(st, "bootstrap", "")
	if err != nil {
		t.Fatal(err)
	}
	tok := "alice-token"
	u := &store.User{Username: "alice", Role: "user", TokenHash: TokenHash(tok)}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	sessTok := "alice-session"
	if err := st.CreateSession(ctx, &store.Session{Username: "alice", Role: "user", TokenHash: TokenHash(sessTok), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	mustResolve := func(key string, want bool, why string) {
		t.Helper()
		_, err := r.Resolve(ctx, key)
		if (err == nil) != want {
			t.Fatalf("%s: resolve err=%v, want ok=%v", why, err, want)
		}
	}
	mustResolve(tok, true, "token before lock")
	mustResolve(sessTok, true, "session before lock")

	if err := st.SetUserLock(ctx, u.ID, "incident", nil); err != nil {
		t.Fatal(err)
	}
	mustResolve(tok, false, "token while locked")
	mustResolve(sessTok, false, "session while locked")

	past := time.Now().Add(-time.Minute)
	if err := st.SetUserLock(ctx, u.ID, "incident", &past); err != nil {
		t.Fatal(err)
	}
	mustResolve(tok, true, "token after the lock's until passed")

	if err := st.SetUserLock(ctx, u.ID, "", nil); err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-time.Second)
	if err := st.RotateUserToken(ctx, u.ID, TokenHash(tok), &expired); err != nil {
		t.Fatal(err)
	}
	mustResolve(tok, false, "expired token")
	mustResolve(sessTok, true, "a login session is not the token: it lives by its own expiry")
	future := time.Now().Add(time.Hour)
	if err := st.RotateUserToken(ctx, u.ID, TokenHash(tok), &future); err != nil {
		t.Fatal(err)
	}
	mustResolve(tok, true, "token with a future expiry")
}
