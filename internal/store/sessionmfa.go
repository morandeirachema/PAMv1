package store

// sessionmfa.go answers the per-session MFA question (Phase 244) in one place,
// for the same reason approvalpolicy.go answers the approval one: **does this
// target require a fresh second factor for every session?** Three inputs — the
// deployment-wide PAM_SESSION_MFA, the target's own flag, and the flag of the
// safe the target sits in — folded STRICTEST WINS, so neither a target nor a
// safe can switch off what the deployment requires.

import (
	"context"
	"fmt"
)

// EffectiveSessionMFA folds the global flag, the target's flag and its safe's
// flag. FAIL-CLOSED, like EffectiveApprovalPolicy: when the safe cannot be
// read it returns true together with the error, so a caller that looks only
// at the boolean still demands the factor.
func EffectiveSessionMFA(ctx context.Context, st SafeReader, t *Target, global bool) (bool, error) {
	if global {
		return true, nil
	}
	if t == nil {
		return false, nil
	}
	if t.RequireSessionMFA {
		return true, nil
	}
	if t.SafeID == nil || st == nil {
		return false, nil
	}
	sf, err := st.GetSafe(ctx, *t.SafeID)
	if err != nil {
		return true, fmt.Errorf("store: reading safe %d for target %d: %w", *t.SafeID, t.ID, err)
	}
	return sf.RequireSessionMFA, nil
}
