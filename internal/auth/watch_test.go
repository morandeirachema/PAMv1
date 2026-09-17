package auth

import (
	"context"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestWatchScope proves a watch token (Phase 258) resolves to a WatchOnly
// principal whose narrow scope no session door serves: the proxies (ScopeNone),
// the viewer tunnel (ScopeTunnelOnly) and the terminal (ScopeTerminal) all
// refuse it, so a copy lifted from a watch URL can look and never act.
func TestWatchScope(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	if err := st.CreateUser(ctx, &store.User{Username: "theo", Role: "auditor", TokenHash: TokenHash("theo-key")}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(ctx, &store.Session{Username: "theo", Role: "auditor", Scope: SessionScopeWatch,
		TokenHash: TokenHash("watch-tok"), ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	r, err := NewResolver(st, "bootstrap", "")
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.Resolve(ctx, "watch-tok")
	if err != nil {
		t.Fatalf("a watch token must resolve: %v", err)
	}
	if !p.WatchOnly || p.NarrowScope() != ScopeWatch || p.TunnelOnly || p.TerminalOnly {
		t.Fatalf("principal = %+v, want WatchOnly and nothing else", p)
	}
	if !p.Can(CapReadAudit) {
		t.Error("a watch token keeps its minter's capabilities; the doors narrow it, not the caps")
	}
	for _, door := range []SessionScope{ScopeNone, ScopeTunnelOnly, ScopeTerminal} {
		if p.MayOpenSession(door) {
			t.Errorf("a watch token must not open a session at a door serving %v", door)
		}
	}
}
