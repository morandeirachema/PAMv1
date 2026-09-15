package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/mfa"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// plainSecret is a Decrypter over an unsealed value, so the second-factor test
// exercises the code check and the replay guard rather than the vault.
type plainSecret struct{}

func (plainSecret) Decrypt(_ context.Context, token, _ string) (string, error) { return token, nil }

// TestResolveSessionMFATicket proves a session-MFA ticket (Phase 244) resolves
// to a principal bound to its target and confined to opening a session, and
// that a ticket row bound to no target resolves to nothing at all.
func TestResolveSessionMFATicket(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	r, err := NewResolver(st, "bootstrap", "")
	if err != nil {
		t.Fatal(err)
	}
	tid := int64(42)
	if err := st.CreateSession(ctx, &store.Session{Username: "alice", Role: "user", Scope: SessionScopeSessionMFA,
		TokenHash: TokenHash("ticket"), ExpiresAt: time.Now().Add(time.Minute), TargetID: &tid}); err != nil {
		t.Fatal(err)
	}
	p, err := r.Resolve(ctx, "ticket")
	if err != nil {
		t.Fatalf("resolve ticket: %v", err)
	}
	if !p.SessionMFATicket || p.SessionMFATarget != tid || p.NarrowScope() != ScopeSessionMFA {
		t.Fatalf("ticket principal = %+v", p)
	}
	if !p.MayOpenSession(ScopeNone) || !p.MayOpenSession(ScopeTunnelOnly) {
		t.Fatal("a ticket must open a session at every session door")
	}
	if !p.Can(CapConnect) {
		t.Fatal("a ticket carries the minting user's role")
	}
	if err := st.CreateSession(ctx, &store.Session{Username: "alice", Role: "user", Scope: SessionScopeSessionMFA,
		TokenHash: TokenHash("unbound"), ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(ctx, "unbound"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("a ticket bound to no target must not resolve: %v", err)
	}
}

// TestCheckSessionMFA pins the gate every door runs: a ticket is spent on its
// first presentation and admits only its own target (burned, not kept, when
// shown to another); break-glass bypasses; a factor proven in-band satisfies;
// nothing else does when the policy requires one.
func TestCheckSessionMFA(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	r, err := NewResolver(st, "bootstrap", "")
	if err != nil {
		t.Fatal(err)
	}
	ticket := func(tok string, target int64) *Principal {
		t.Helper()
		if err := st.CreateSession(ctx, &store.Session{Username: "alice", Role: "user", Scope: SessionScopeSessionMFA,
			TokenHash: TokenHash(tok), ExpiresAt: time.Now().Add(time.Minute), TargetID: &target}); err != nil {
			t.Fatal(err)
		}
		p, err := r.Resolve(ctx, tok)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	plain := &Principal{Name: "alice", Role: RoleUser}

	if f, why, err := CheckSessionMFA(ctx, st, plain, 1, false); f != "" || why != "" || err != nil {
		t.Fatalf("not required: %q %q %v", f, why, err)
	}
	if _, why, _ := CheckSessionMFA(ctx, st, plain, 1, true); why != ReasonSessionMFARequired {
		t.Fatalf("required with no factor: %q", why)
	}
	if f, why, _ := CheckSessionMFA(ctx, st, &Principal{Name: "break-glass", Role: RoleAdmin, BreakGlass: true}, 1, true); f != "" || why != "" {
		t.Fatalf("break-glass must bypass: %q %q", f, why)
	}
	inBand := &Principal{Name: "alice", Role: RoleUser, SessionMFAFactor: FactorTOTP}
	if f, why, _ := CheckSessionMFA(ctx, st, inBand, 1, true); f != FactorTOTP || why != "" {
		t.Fatalf("in-band factor: %q %q", f, why)
	}

	p := ticket("t1", 1)
	if f, why, err := CheckSessionMFA(ctx, st, p, 1, true); f != FactorTicket || why != "" || err != nil {
		t.Fatalf("a ticket for its own target: %q %q %v", f, why, err)
	}
	if _, why, _ := CheckSessionMFA(ctx, st, p, 1, true); why != ReasonSessionMFATicketUsed {
		t.Fatalf("the same ticket again (a racing second use): %q", why)
	}
	if _, err := r.Resolve(ctx, "t1"); err == nil {
		t.Fatal("a spent ticket must not resolve again")
	}

	wrong := ticket("t2", 2)
	if _, why, _ := CheckSessionMFA(ctx, st, wrong, 1, false); why != ReasonSessionMFATicketTarget {
		t.Fatalf("a ticket for another target, even where the policy does not require one: %q", why)
	}
	if _, err := r.Resolve(ctx, "t2"); err == nil {
		t.Fatal("a ticket shown to the wrong target is burned, not left for another try")
	}
}

// TestVerifySecondFactor pins the one code check shared by every place a code
// is typed — login, the ticket mint and the SSH proxy's prompt: a TOTP code is
// accepted once per time step, a recovery code once ever, anything else never.
func TestVerifySecondFactor(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	secret, err := mfa.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	enr := &store.MFAEnrollment{Username: "alice", SecretEnc: secret, Confirmed: true}
	if err := st.UpsertMFAEnrollment(ctx, enr); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code, err := mfa.Code(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := VerifySecondFactor(ctx, st, plainSecret{}, enr, "alice", code, now); f != FactorTOTP || err != nil {
		t.Fatalf("a valid TOTP code: %q %v", f, err)
	}
	if f, _ := VerifySecondFactor(ctx, st, plainSecret{}, enr, "alice", code, now); f != "" {
		t.Fatalf("a replayed TOTP code must be refused, got %q", f)
	}
	const recovery = "abcdef-ghijkl-mnopqr-stuvwx"
	if err := st.ReplaceMFARecoveryCodes(ctx, "alice", []string{TokenHash(recovery)}); err != nil {
		t.Fatal(err)
	}
	if f, _ := VerifySecondFactor(ctx, st, plainSecret{}, enr, "alice", "  ABCDEF-ghijkl-mnopqr-stuvwx ", now); f != FactorRecovery {
		t.Fatalf("a recovery code (case and whitespace tolerated): %q", f)
	}
	if f, _ := VerifySecondFactor(ctx, st, plainSecret{}, enr, "alice", recovery, now); f != "" {
		t.Fatalf("a used recovery code must be refused, got %q", f)
	}
	if f, _ := VerifySecondFactor(ctx, st, plainSecret{}, enr, "alice", "not-a-code", now); f != "" {
		t.Fatalf("garbage must be refused, got %q", f)
	}
}
