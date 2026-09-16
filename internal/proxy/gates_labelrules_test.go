package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// labelTarget puts labels on the test env's target, so the label rules below
// have something to match.
func labelTarget(t *testing.T, env *testEnv, labels string) {
	t.Helper()
	tgt, err := env.st.GetTarget(context.Background(), env.target.ID)
	if err != nil {
		t.Fatal(err)
	}
	tgt.Labels = labels
	if err := env.st.UpdateTarget(context.Background(), tgt); err != nil {
		t.Fatal(err)
	}
}

// TestAdmitLabelRules proves the session gate reads the third authorization
// path (Phase 250) at the same place it reads the other two: an allow rule
// admits a principal no direct grant names, a deny rule refuses at the
// target-policy gate, and — the decision this phase turns on — a deny refuses
// an ADMIN, who needs no grant and passes every other gate on identity alone.
func TestAdmitLabelRules(t *testing.T) {
	ctx := context.Background()
	rule := func(sel, subjectType, subject, effect string) store.LabelRule {
		return store.LabelRule{Selector: sel, SubjectType: subjectType, Subject: subject, Effect: effect}
	}

	t.Run("an allow rule admits a principal no grant names", func(t *testing.T) {
		env := newTestEnv(t)
		labelTarget(t, env, "env=prod,tier=db")
		r := rule("env=prod", "user", "alice", store.GrantAllow)
		if err := env.st.CreateLabelRule(ctx, &r); err != nil {
			t.Fatal(err)
		}
		if res := env.g.admit(ctx, baseReq(gatesUser("alice"))); res.outcome != admitOK {
			t.Fatalf("outcome = %d (gate %d), want admitOK", res.outcome, res.gate)
		}
		// ...and gates the target against everyone the rule does not name.
		if res := env.g.admit(ctx, baseReq(gatesUser("bob"))); res.outcome != admitDenied || res.gate != gateTargetPolicy {
			t.Fatalf("bob: outcome %d gate %d, want denied at the target policy", res.outcome, res.gate)
		}
	})

	t.Run("a selector that does not match leaves the target alone", func(t *testing.T) {
		env := newTestEnv(t)
		labelTarget(t, env, "env=staging")
		r := rule("env=prod", "user", "alice", store.GrantAllow)
		if err := env.st.CreateLabelRule(ctx, &r); err != nil {
			t.Fatal(err)
		}
		// The rule gates nothing here, so the open default still admits bob.
		if res := env.g.admit(ctx, baseReq(gatesUser("bob"))); res.outcome != admitOK {
			t.Fatalf("outcome = %d (gate %d), want admitOK — a non-matching rule must not gate", res.outcome, res.gate)
		}
	})

	t.Run("a deny rule refuses, and refuses an admin", func(t *testing.T) {
		env := newTestEnv(t)
		labelTarget(t, env, "env=prod,tier=db")
		r := rule("tier=db", "role", "admin", store.GrantDeny)
		if err := env.st.CreateLabelRule(ctx, &r); err != nil {
			t.Fatal(err)
		}
		res := env.g.admit(ctx, baseReq(&auth.Principal{Name: "root", Role: auth.RoleAdmin}))
		if res.outcome != admitDenied || res.gate != gateTargetPolicy {
			t.Fatalf("admin: outcome %d gate %d, want denied at the target policy", res.outcome, res.gate)
		}
		// The same admin reaches it once the labels no longer match the rule.
		labelTarget(t, env, "env=prod")
		if res := env.g.admit(ctx, baseReq(&auth.Principal{Name: "root", Role: auth.RoleAdmin})); res.outcome != admitOK {
			t.Fatalf("admin after relabel: outcome %d gate %d, want admitOK", res.outcome, res.gate)
		}
	})

	t.Run("a deny rule does not close the target to everyone else", func(t *testing.T) {
		env := newTestEnv(t)
		labelTarget(t, env, "env=prod")
		r := rule("env=prod", "user", "mallory", store.GrantDeny)
		if err := env.st.CreateLabelRule(ctx, &r); err != nil {
			t.Fatal(err)
		}
		if res := env.g.admit(ctx, baseReq(gatesUser("mallory"))); res.outcome != admitDenied {
			t.Fatalf("mallory: outcome %d, want denied", res.outcome)
		}
		if res := env.g.admit(ctx, baseReq(gatesUser("bob"))); res.outcome != admitOK {
			t.Fatalf("bob: outcome %d (gate %d) — excluding mallory must not close the target", res.outcome, res.gate)
		}
	})

	t.Run("a deny beats a direct grant on the same target", func(t *testing.T) {
		env := newTestEnv(t)
		labelTarget(t, env, "env=prod")
		if err := env.st.CreateTargetGrant(ctx, &store.TargetGrant{TargetID: env.target.ID, SubjectType: "user", Subject: "mallory"}); err != nil {
			t.Fatal(err)
		}
		r := rule("env=prod", "user", "mallory", store.GrantDeny)
		if err := env.st.CreateLabelRule(ctx, &r); err != nil {
			t.Fatal(err)
		}
		if res := env.g.admit(ctx, baseReq(gatesUser("mallory"))); res.outcome != admitDenied {
			t.Fatalf("outcome = %d, want denied — an explicit grant must not out-vote a deny", res.outcome)
		}
	})

	t.Run("an expired deny stops denying", func(t *testing.T) {
		env := newTestEnv(t)
		labelTarget(t, env, "env=prod")
		past := time.Now().Add(-time.Minute)
		r := rule("env=prod", "user", "alice", store.GrantDeny)
		r.ExpiresAt = &past
		if err := env.st.CreateLabelRule(ctx, &r); err != nil {
			t.Fatal(err)
		}
		if res := env.g.admit(ctx, baseReq(gatesUser("alice"))); res.outcome != admitOK {
			t.Fatalf("outcome = %d (gate %d), want admitOK — an expired deny must not deny", res.outcome, res.gate)
		}
	})

	t.Run("an allow rule's own bound becomes the session deadline", func(t *testing.T) {
		env := newTestEnv(t)
		labelTarget(t, env, "env=prod")
		future := time.Now().Add(90 * time.Minute)
		r := rule("env=prod", "user", "alice", store.GrantAllow)
		r.ExpiresAt = &future
		if err := env.st.CreateLabelRule(ctx, &r); err != nil {
			t.Fatal(err)
		}
		res := env.g.admit(ctx, baseReq(gatesUser("alice")))
		if res.outcome != admitOK {
			t.Fatalf("outcome = %d (gate %d), want admitOK", res.outcome, res.gate)
		}
		if res.bounds.deadline == nil || res.bounds.reason != "grant-expiry" || !res.bounds.deadline.Equal(future) {
			t.Fatalf("bounds = %+v, want the rule's own expiry at %s", res.bounds, future)
		}
	})
}
