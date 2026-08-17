package api

import (
	"context"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// newQuarantineServer builds a minimal Server over a memstore — enough to call
// revalidateAgent, which is what this file exists to exercise.
func newQuarantineServer(t *testing.T) (*Server, store.Store) {
	t.Helper()
	key, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	st := memstore.New()
	resolver, err := auth.NewResolver(st, "k", "")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, v, resolver, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

// TestRevalidateAgentQuarantineCoversSVIDIdentities is the assertion Phase 159
// exists for, and it has to be made in-package because it is about a code path
// no HTTP request can reach on its own.
//
// revalidateAgent decides whether a call PARKED for approval may still run when
// a human finally approves it. Its key checks are gated on `KeyID > 0`, and an
// SVID identity's KeyID is always 0 (agentid.Identity documents this) — so for a
// SPIFFE deployment, the intended production posture, those checks were no-ops
// and nothing an operator could do would stop a parked call. The quarantine
// check is the half that covers every identity kind, so it is asserted directly
// against an identity shaped exactly like an attested one.
func TestRevalidateAgentQuarantineCoversSVIDIdentities(t *testing.T) {
	srv, st := newQuarantineServer(t)
	ctx := context.Background()
	const spiffeID = "spiffe://corp.example/ns/prod/sa/planner"

	// An SVID identity: no key row anywhere, KeyID 0, name == its SPIFFE ID.
	svid := &agentid.Identity{AgentName: spiffeID, SPIFFEID: spiffeID}
	if !srv.revalidateAgent(ctx, svid) {
		t.Fatal("an unquarantined SVID identity must revalidate")
	}
	if err := st.QuarantineAgent(ctx, &store.AgentQuarantine{
		Subject: spiffeID, Reason: "suspected prompt injection", CreatedBy: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	if srv.revalidateAgent(ctx, svid) {
		t.Fatal("a quarantined SVID identity must NOT revalidate — this is the KeyID == 0 hole the phase closes")
	}
	// Quarantine is per subject, not a blanket stop.
	other := &agentid.Identity{AgentName: "spiffe://corp.example/ns/prod/sa/other"}
	if !srv.revalidateAgent(ctx, other) {
		t.Fatal("quarantining one subject must not stop another")
	}

	// The same control covers a static key, whose own suspension and expiry are
	// checked independently — three separate reasons a parked call can be refused.
	k := store.AgentKey{Name: "bot-1", Owner: "alice", TokenHash: "h1"}
	if err := st.CreateAgentKey(ctx, &k); err != nil {
		t.Fatal(err)
	}
	static := &agentid.Identity{AgentName: k.Name, KeyID: k.ID}
	if !srv.revalidateAgent(ctx, static) {
		t.Fatal("a healthy static key must revalidate")
	}
	if err := st.SetAgentKeyDisabled(ctx, k.ID, true); err != nil {
		t.Fatal(err)
	}
	if srv.revalidateAgent(ctx, static) {
		t.Fatal("a suspended static key must not revalidate")
	}
	if err := st.SetAgentKeyDisabled(ctx, k.ID, false); err != nil {
		t.Fatal(err)
	}
	// An expired identity is refused even though the row is enabled — the two
	// halves of Active() are independent controls.
	expired := &agentid.Identity{AgentName: k.Name, KeyID: k.ID, ExpiresAt: time.Now().Add(-time.Minute)}
	if srv.revalidateAgent(ctx, expired) {
		t.Fatal("an expired identity must not revalidate")
	}
}
