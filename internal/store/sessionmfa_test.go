package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestEffectiveSessionMFA pins the per-session MFA fold (Phase 244): the
// strictest of the deployment flag, the target's own flag and its safe's flag
// — a safe can only tighten — and fail-closed when the safe cannot be read.
func TestEffectiveSessionMFA(t *testing.T) {
	safeID := int64(7)
	cases := []struct {
		name    string
		global  bool
		target  store.Target
		safe    safeStub
		want    bool
		wantErr bool
	}{
		{"nothing requires it", false, store.Target{}, safeStub{}, false, false},
		{"the deployment requires it", true, store.Target{}, safeStub{}, true, false},
		{"the target requires it", false, store.Target{RequireSessionMFA: true}, safeStub{}, true, false},
		{"the safe requires it", false, store.Target{SafeID: &safeID}, safeStub{safe: &store.Safe{RequireSessionMFA: true}}, true, false},
		{"a safe that does not require it changes nothing", false, store.Target{SafeID: &safeID}, safeStub{safe: &store.Safe{}}, false, false},
		{"a safe cannot switch off the target's flag", false, store.Target{RequireSessionMFA: true, SafeID: &safeID}, safeStub{safe: &store.Safe{}}, true, false},
		{"an unreadable safe fails closed", false, store.Target{SafeID: &safeID}, safeStub{err: errors.New("store down")}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.EffectiveSessionMFA(context.Background(), tc.safe, &tc.target, tc.global)
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("EffectiveSessionMFA = %v, %v; want %v (error: %v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}
