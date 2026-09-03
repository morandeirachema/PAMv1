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
		if !store.GrantLive(g.ExpiresAt, g.TimeFrame, now) || !SubjectMatches(p, g.SubjectType, g.Subject) {
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
