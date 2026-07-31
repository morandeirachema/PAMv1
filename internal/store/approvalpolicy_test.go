package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
)

// safeStub is a SafeReader that returns one safe, or an error.
type safeStub struct {
	safe *store.Safe
	err  error
}

// GetSafe implements store.SafeReader.
func (s safeStub) GetSafe(context.Context, int64) (*store.Safe, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.safe, nil
}

// TestEffectiveApprovalPolicy pins the fold every enforcement site depends on:
// strictest of global, per-target and safe — and, above all, that a safe can
// only ever tighten.
func TestEffectiveApprovalPolicy(t *testing.T) {
	safeID := int64(7)
	cases := []struct {
		name         string
		global       bool
		target       store.Target
		safe         *store.Safe
		wantRequired bool
		wantMin      int
	}{
		{name: "nothing set", target: store.Target{ID: 1}},
		{name: "global only", global: true, target: store.Target{ID: 1}, wantRequired: true},
		{name: "target flag only", target: store.Target{ID: 1, RequireApproval: true}, wantRequired: true},
		{
			name:         "the safe requires it, the target does not",
			target:       store.Target{ID: 1, SafeID: &safeID},
			safe:         &store.Safe{ID: safeID, RequireApproval: true},
			wantRequired: true,
		},
		{
			// The point of the phase: one setting governs everything in the safe,
			// so a target onboarded without its own flag is still covered.
			name:         "the safe's dual-control floor implies approval",
			target:       store.Target{ID: 1, SafeID: &safeID},
			safe:         &store.Safe{ID: safeID, MinApprovers: 2},
			wantRequired: true,
			wantMin:      2,
		},
		{
			// A safe must never be able to LOOSEN what the global policy demands.
			name:         "a permissive safe cannot undo the global flag",
			global:       true,
			target:       store.Target{ID: 1, SafeID: &safeID},
			safe:         &store.Safe{ID: safeID, RequireApproval: false, MinApprovers: 0},
			wantRequired: true,
		},
		{
			name:         "a permissive safe cannot undo the target flag",
			target:       store.Target{ID: 1, RequireApproval: true, SafeID: &safeID},
			safe:         &store.Safe{ID: safeID},
			wantRequired: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.EffectiveApprovalPolicy(context.Background(), safeStub{safe: tc.safe}, &tc.target, tc.global)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Required != tc.wantRequired || got.MinApprovers != tc.wantMin {
				t.Fatalf("policy = %+v, want required=%v min=%d", got, tc.wantRequired, tc.wantMin)
			}
		})
	}
}

// TestEffectiveApprovalPolicyFailsClosed is the one that matters under failure:
// a store hiccup reading the safe must not quietly downgrade a governed target
// to ungoverned. The policy comes back REQUIRED alongside the error, so even a
// caller that mishandles the error denies.
func TestEffectiveApprovalPolicyFailsClosed(t *testing.T) {
	safeID := int64(7)
	target := store.Target{ID: 1, SafeID: &safeID}
	boom := errors.New("database is down")
	got, err := store.EffectiveApprovalPolicy(context.Background(), safeStub{err: boom}, &target, false)
	if err == nil {
		t.Fatal("a failed safe read was not reported")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want it to wrap the store failure", err)
	}
	if !got.Required {
		t.Fatal("a failed safe read returned a policy that requires NOTHING — fail-open")
	}
}

// TestEffectiveApprovalPolicyNoSafeReader proves a caller with no store (or a
// target in no safe) still gets the global/target fold rather than an error.
func TestEffectiveApprovalPolicyNoSafeReader(t *testing.T) {
	got, err := store.EffectiveApprovalPolicy(context.Background(), nil, &store.Target{ID: 1, RequireApproval: true}, false)
	if err != nil || !got.Required {
		t.Fatalf("policy = %+v, %v; want required with no store", got, err)
	}
	if got, err := store.EffectiveApprovalPolicy(context.Background(), nil, nil, true); err != nil || !got.Required {
		t.Fatalf("nil target = %+v, %v; want the global flag to stand", got, err)
	}
}
