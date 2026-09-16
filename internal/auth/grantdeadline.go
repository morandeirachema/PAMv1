package auth

import (
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// GrantDeadline returns the instant p's authorization on a target ends, given
// the target's live grants (Phase 240): the LATEST bound among the grants
// that match p — a subject admitted by two grants keeps access while either
// still admits — and ok=false when any matching grant is unbounded, or when
// p needs no grant at all (an admin outside a personal safe, a
// CapUnlimitedVaultAccess holder inside one, or an open target with no
// grants), because then no grant's edge is the session's edge. reason names
// the binding bound: "grant-expiry" or "time-frame".
//
// It is evaluated once, at admission, and stamped on the session as its
// deadline; nothing re-reads the grants mid-session. A grant DELETED
// mid-session is already handled by kill-on-revoke.
func GrantDeadline(p *Principal, grants []store.TargetGrant, personal bool, now time.Time) (deadline time.Time, reason string, ok bool) {
	return GrantDeadlineFor(p, grants, nil, personal, now)
}

// GrantDeadlineFor is GrantDeadline for a session on ONE credential (Phase
// 252): a grant scoped to a different credential admitted nobody to this
// session, so its edge is not this session's edge. credID nil is the whole
// target.
func GrantDeadlineFor(p *Principal, grants []store.TargetGrant, credID *int64, personal bool, now time.Time) (deadline time.Time, reason string, ok bool) {
	// A denied principal opens no session, so there is no edge to report; the
	// gate has already refused by the time this is asked (Phase 250).
	if DeniedByLabelRule(p, grants, now) {
		return time.Time{}, "", false
	}
	if !personal {
		for _, r := range p.effectiveRoles() {
			if r == RoleAdmin {
				return time.Time{}, "", false
			}
		}
	} else if p.Can(CapUnlimitedVaultAccess) {
		return time.Time{}, "", false
	}
	matched := false
	for _, g := range grants {
		// Only a grant that admits a SESSION bounds one (Phase 246): a
		// retrieve-only membership admitted nobody to this session.
		if g.IsDeny() || !g.CoversCredential(credID) || !store.GrantLive(g.ExpiresAt, g.TimeFrame, now) ||
			!store.GrantPermits(g.Permissions, store.SafePermUse) || !SubjectMatches(p, g.SubjectType, g.Subject) {
			continue
		}
		matched = true
		b, bounded := store.GrantBound(g.ExpiresAt, g.TimeFrame, now)
		if !bounded {
			return time.Time{}, "", false
		}
		if !ok || b.After(deadline) {
			deadline, ok = b, true
			reason = "time-frame"
			if g.ExpiresAt != nil && b.Equal(*g.ExpiresAt) {
				reason = "grant-expiry"
			}
		}
	}
	if !matched {
		return time.Time{}, "", false
	}
	return deadline, reason, ok
}
