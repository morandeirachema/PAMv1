package store

// personalsafe.go answers one question in one place, the same discipline
// approvalpolicy.go established for approval requirements: **is the safe
// this target belongs to Personal (Phase 139)?** auth.CanConnectTarget needs
// the answer at every connect/reveal/checkout call site, and duplicating a
// GetSafe-and-check at each one is exactly the kind of duplication
// approvalpolicy.go's own header comment warns against — a control that has
// to be re-implemented on every path is a control that will be missing from
// one of them.

import (
	"context"
	"fmt"
)

// EffectiveSafePersonal reports whether t sits in a Personal safe. An
// ungated target, or one in an ordinary (non-personal) safe, is never
// personal.
//
// FAIL-CLOSED CONTRACT, mirroring EffectiveApprovalPolicy: when the safe
// cannot be read, it returns true **together with** the error. A caller
// that handles the error denies; a caller that only looks at the bool still
// treats the target as personal (the stricter, safer branch of
// CanConnectTarget) rather than a store hiccup quietly reopening a private
// safe to every admin.
func EffectiveSafePersonal(ctx context.Context, st SafeReader, t *Target) (bool, error) {
	if t == nil || t.SafeID == nil || st == nil {
		return false, nil
	}
	sf, err := st.GetSafe(ctx, *t.SafeID)
	if err != nil {
		return true, fmt.Errorf("store: reading safe %d for target %d: %w", *t.SafeID, t.ID, err)
	}
	return sf.Personal, nil
}
