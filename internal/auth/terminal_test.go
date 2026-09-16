package auth

import (
	"context"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestTerminalScope proves a terminal token (Phase 254) resolves to a
// principal confined to one target, that the scope is a NARROW one — so every
// door with a shorter checklist refuses it — and that MayOpenSession admits it
// only to a caller that declares it serves the terminal.
func TestTerminalScope(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	if err := st.CreateUser(ctx, &store.User{Username: "alice", Role: "user", TokenHash: TokenHash("alice-key")}); err != nil {
		t.Fatal(err)
	}
	tgt := &store.Target{Name: "db-01", Host: "h", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, tgt); err != nil {
		t.Fatal(err)
	}
	r, err := NewResolver(st, "bootstrap", "")
	if err != nil {
		t.Fatal(err)
	}
	mint := func(targetID *int64) string {
		t.Helper()
		tok := "term-" + time.Now().Format(time.RFC3339Nano)
		if err := st.CreateSession(ctx, &store.Session{Username: "alice", Role: "user", Scope: SessionScopeTerminal,
			TokenHash: TokenHash(tok), ExpiresAt: time.Now().Add(time.Minute), TargetID: targetID}); err != nil {
			t.Fatal(err)
		}
		return tok
	}

	p, err := r.Resolve(ctx, mint(&tgt.ID))
	if err != nil {
		t.Fatalf("a terminal token must resolve: %v", err)
	}
	if !p.TerminalOnly || p.TerminalTarget != tgt.ID || p.Name != "alice" {
		t.Fatalf("principal = %+v, want alice, TerminalOnly, bound to %d", p, tgt.ID)
	}
	if p.NarrowScope() != ScopeTerminal {
		t.Errorf("NarrowScope = %v, want ScopeTerminal", p.NarrowScope())
	}
	// A proxy serving no narrow scope refuses it; one serving the terminal
	// admits it; one serving the viewer does not.
	if p.MayOpenSession(ScopeNone) {
		t.Error("a terminal token must not open a session at a door serving no narrow scope")
	}
	if !p.MayOpenSession(ScopeTerminal) {
		t.Error("a terminal token must open a session at the door that serves it")
	}
	if p.MayOpenSession(ScopeTunnelOnly) {
		t.Error("a terminal token is not a viewer token")
	}
	// A terminal row with no target is refused outright, like a ticket.
	if _, err := r.Resolve(ctx, mint(nil)); err == nil {
		t.Error("a terminal token bound to no target must not resolve")
	}
}
