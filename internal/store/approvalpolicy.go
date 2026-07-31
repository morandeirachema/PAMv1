package store

// approvalpolicy.go answers one question in one place: **what approval does
// this target require?**
//
// The answer used to be spelled out at five enforcement sites — the API's
// `requireApprovalFor`, the SSH proxy, the PostgreSQL proxy, the SQL Server
// proxy, and the in-portal viewer — each computing `global || target.RequireApproval`
// for itself. That duplication was survivable while there were two inputs. Safe
// policy (Phase 58) adds a third, and the Phase 38 lesson applies: a control
// that has to be re-implemented on every path is a control that will be missing
// from one of them. So the fold lives here, and the enforcement sites call it.
//
// STRICTEST WINS. A safe may tighten what the global setting and the target's
// own flag allow, never loosen them — the same direction the per-target RDP
// clipboard override takes. There is deliberately no way for a safe to say "no
// approval needed" for a target the global policy gates.

import (
	"context"
	"fmt"
)

// SafeReader is the slice of the store EffectiveApprovalPolicy needs. Taking an
// interface this narrow means the proxies can call it with what they already
// hold, and a test can supply a two-line fake.
type SafeReader interface {
	GetSafe(ctx context.Context, id int64) (*Safe, error)
}

// ApprovalPolicy is the approval requirement binding one target: whether a
// privileged use needs an approved access request at all, and the floor on how
// many DISTINCT approvers must have signed it (0 = no floor beyond the
// deployment default).
type ApprovalPolicy struct {
	Required     bool
	MinApprovers int
}

// EffectiveApprovalPolicy folds the deployment-wide flag, the target's own
// flag, and the policy of the safe the target belongs to.
//
// FAIL-CLOSED CONTRACT: when the safe cannot be read, it returns
// `ApprovalPolicy{Required: true}` **together with** the error. A caller that
// handles the error denies; a caller that only looks at the policy still
// denies. The one outcome that must never happen is a store hiccup quietly
// downgrading a governed target to ungoverned — which is exactly what
// returning a zero policy alongside an error would invite.
func EffectiveApprovalPolicy(ctx context.Context, st SafeReader, t *Target, global bool) (ApprovalPolicy, error) {
	p := ApprovalPolicy{Required: global}
	if t == nil {
		return p, nil
	}
	if t.RequireApproval {
		p.Required = true
	}
	if t.SafeID == nil || st == nil {
		return p, nil
	}
	sf, err := st.GetSafe(ctx, *t.SafeID)
	if err != nil {
		return ApprovalPolicy{Required: true}, fmt.Errorf("store: reading safe %d for target %d: %w", *t.SafeID, t.ID, err)
	}
	if sf.RequireApproval {
		p.Required = true
	}
	if sf.MinApprovers > p.MinApprovers {
		p.MinApprovers = sf.MinApprovers
	}
	// A safe that sets a dual-control floor is asking for approvals; requiring
	// two approvers on a target nothing gates would otherwise be a setting with
	// no effect, which reads as a control and is not one.
	if p.MinApprovers > 0 {
		p.Required = true
	}
	return p, nil
}
