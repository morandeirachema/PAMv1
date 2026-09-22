package auth

import (
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// EffectiveRights is the sub-protocol set a session admitted to target may use
// (Phase 270): the target's own set narrowed by the grants that admit p — the
// UNION of the rights on the live allow grants matching p, where a grant with
// no set contributes the target's whole set. Deployment ceilings are applied
// by the caller (each proxy knows its own switches). A principal admitted
// without a matching grant (an admin's bypass, an ungated target) gets the
// target's set. The result is a canonical string ("" = everything the target
// allows), so callers test it with store.RightsAllow.
func EffectiveRights(p *Principal, target *store.Target, grants []store.TargetGrant, now time.Time) string {
	targetSet := store.ParseRights(target.Rights)
	var union map[string]bool
	sawMatch, sawUnbounded := false, false
	for _, g := range grants {
		if g.IsDeny() || !SubjectMatches(p, g.SubjectType, g.Subject) || !store.GrantLive(g.ExpiresAt, g.TimeFrame, now) {
			continue
		}
		sawMatch = true
		if g.Rights == "" {
			sawUnbounded = true
			continue
		}
		if union == nil {
			union = map[string]bool{}
		}
		for r := range store.ParseRights(g.Rights) {
			union[r] = true
		}
	}
	// No grant narrowed anything: the target's set stands.
	if !sawMatch || sawUnbounded {
		return target.Rights
	}
	// Grants narrowed: intersect with the target's set, when it has one.
	var out []string
	for _, r := range store.AllRights {
		if union[r] && (targetSet == nil || targetSet[r]) {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		// Every admitting grant narrowed to nothing the target allows: an
		// explicit, non-empty "nothing" so RightsAllow refuses rather than
		// reading "" as everything.
		return "none"
	}
	s, _ := store.NormalizeRights(joinRights(out))
	return s
}

func joinRights(rs []string) string {
	out := ""
	for i, r := range rs {
		if i > 0 {
			out += ","
		}
		out += r
	}
	return out
}
