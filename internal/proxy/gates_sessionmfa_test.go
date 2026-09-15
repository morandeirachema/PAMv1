package proxy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// gateTicket writes a session-MFA ticket row for alice bound to targetID and
// returns the principal the resolver gives it — the only way to hold one,
// since a ticket's spend handle is unexported by design.
func gateTicket(t *testing.T, env *testEnv, tok string, targetID int64) *auth.Principal {
	t.Helper()
	ctx := context.Background()
	if err := env.st.CreateSession(ctx, &store.Session{Username: "alice", Role: "user", Scope: auth.SessionScopeSessionMFA,
		TokenHash: auth.TokenHash(tok), ExpiresAt: time.Now().Add(time.Minute), TargetID: &targetID}); err != nil {
		t.Fatal(err)
	}
	r, err := auth.NewResolver(env.st, "bootstrap", "")
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.Resolve(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// gateAuditHas reports whether admit wrote action with a detail containing want.
func gateAuditHas(t *testing.T, st store.Store, action, want string) bool {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == action && strings.Contains(e.Detail, want) {
			return true
		}
	}
	return false
}

// TestAdmitSessionMFA proves the per-session MFA gate (Phase 244) inside the
// one admission sequence all three proxies share: where it sits (after target
// authorization, before approval), what satisfies it (an in-band factor, a
// ticket for this target, break-glass), and that a ticket is spent exactly
// when it is read — never by a refusal that happens before its gate.
func TestAdmitSessionMFA(t *testing.T) {
	ctx := context.Background()

	t.Run("required with no factor refuses, ahead of the approval gate", func(t *testing.T) {
		env := newTestEnv(t)
		env.g.sessionMFA = true
		env.g.requireApprv = true
		res := env.g.admit(ctx, baseReq(gatesUser("alice")))
		if res.outcome != admitDenied || res.gate != gateSessionMFA || res.reason != auth.ReasonSessionMFARequired {
			t.Fatalf("outcome %d gate %d reason %q; want the session-MFA refusal, not the approval one", res.outcome, res.gate, res.reason)
		}
	})
	t.Run("the target's own flag requires it", func(t *testing.T) {
		env := newTestEnv(t)
		env.target.RequireSessionMFA = true
		if err := env.st.UpdateTarget(ctx, env.target); err != nil {
			t.Fatal(err)
		}
		if res := env.g.admit(ctx, baseReq(gatesUser("alice"))); res.gate != gateSessionMFA {
			t.Fatalf("gate %d, want gateSessionMFA", res.gate)
		}
	})
	t.Run("an in-band factor admits and is audited", func(t *testing.T) {
		env := newTestEnv(t)
		env.g.sessionMFA = true
		p := gatesUser("alice")
		p.SessionMFAFactor = auth.FactorTOTP
		if res := env.g.admit(ctx, baseReq(p)); res.outcome != admitOK {
			t.Fatalf("outcome %d gate %d", res.outcome, res.gate)
		}
		if !gateAuditHas(t, env.st, "session.mfa_verified", "target:web-01 factor:totp path:ssh") {
			t.Fatal("no session.mfa_verified row")
		}
	})
	t.Run("break-glass bypasses", func(t *testing.T) {
		env := newTestEnv(t)
		env.g.sessionMFA = true
		p := &auth.Principal{Name: "break-glass", Role: auth.RoleAdmin, BreakGlass: true}
		if res := env.g.admit(ctx, baseReq(p)); res.outcome != admitOK {
			t.Fatalf("outcome %d gate %d", res.outcome, res.gate)
		}
	})
	t.Run("a ticket for this target admits once", func(t *testing.T) {
		env := newTestEnv(t)
		env.g.sessionMFA = true
		p := gateTicket(t, env, "ticket-1", env.target.ID)
		if res := env.g.admit(ctx, baseReq(p)); res.outcome != admitOK {
			t.Fatalf("outcome %d gate %d reason %q", res.outcome, res.gate, res.reason)
		}
		if _, err := env.st.GetSessionByTokenHash(ctx, auth.TokenHash("ticket-1")); err == nil {
			t.Fatal("an admitted ticket must be spent")
		}
		if res := env.g.admit(ctx, baseReq(p)); res.gate != gateSessionMFA || res.reason != auth.ReasonSessionMFATicketUsed {
			t.Fatalf("second use: gate %d reason %q", res.gate, res.reason)
		}
	})
	t.Run("a ticket for another target refuses and is burned", func(t *testing.T) {
		env := newTestEnv(t)
		p := gateTicket(t, env, "ticket-2", env.target.ID+1000)
		res := env.g.admit(ctx, baseReq(p))
		if res.gate != gateSessionMFA || res.reason != auth.ReasonSessionMFATicketTarget {
			t.Fatalf("gate %d reason %q", res.gate, res.reason)
		}
		if _, err := env.st.GetSessionByTokenHash(ctx, auth.TokenHash("ticket-2")); err == nil {
			t.Fatal("a ticket shown to the wrong target must be burned")
		}
	})
	t.Run("a caller the target refuses spends no ticket", func(t *testing.T) {
		env := newTestEnv(t)
		env.g.sessionMFA = true
		if err := env.st.CreateTargetGrant(ctx, &store.TargetGrant{TargetID: env.target.ID, SubjectType: "user", Subject: "bob"}); err != nil {
			t.Fatal(err)
		}
		p := gateTicket(t, env, "ticket-3", env.target.ID)
		if res := env.g.admit(ctx, baseReq(p)); res.gate != gateTargetPolicy {
			t.Fatalf("gate %d, want gateTargetPolicy", res.gate)
		}
		if _, err := env.st.GetSessionByTokenHash(ctx, auth.TokenHash("ticket-3")); err != nil {
			t.Fatalf("a ticket must survive a refusal that happens before its gate: %v", err)
		}
	})
}
