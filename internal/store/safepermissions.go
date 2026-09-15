package store

// safepermissions.go is the vocabulary of what a safe membership confers
// (Phase 246) and the one function that reads it, GrantPermits — shared by the
// connect/reveal decision (auth.CanAccessTargetAt), the session deadline, the
// reach view and the scoped approval check, so a permission cannot mean one
// thing at a door and another in a review.

import (
	"fmt"
	"strings"
)

// The permissions a safe membership can carry. CyberArk splits a safe member's
// rights the same way — "use accounts" (connect without seeing the password),
// "retrieve accounts" (show or copy it) and "authorize account requests" — and
// those three are the distinctions PAMv1's paths already draw.
const (
	// SafePermUse opens sessions through the proxies and the viewer, runs the
	// brokered WinRM / kubectl commands and issues operator SSH certificates.
	SafePermUse = "use"
	// SafePermRetrieve hands over the secret itself: reveal, checkout,
	// DoubleLock, an application grant, the broker's reveal_credential.
	SafePermRetrieve = "retrieve"
	// SafePermApprove decides access requests for the safe's targets without
	// the global approve capability. It confers no target access of its own.
	SafePermApprove = "approve"
)

// AccessReach is the action a management path asks for (rotate, reconcile,
// dependencies) and the reach view reports: any membership that confers
// target access at all — use or retrieve. An approve-only membership does not
// reach the target.
const AccessReach = "reach"

// safePermOrder is the canonical order permissions are stored and returned in.
var safePermOrder = []string{SafePermUse, SafePermRetrieve, SafePermApprove}

// DefaultSafePermissions is what a membership confers when none is named:
// what every membership conferred before Phase 246. A fresh slice each call,
// so no caller can alias another's.
func DefaultSafePermissions() []string { return []string{SafePermUse, SafePermRetrieve} }

// NormalizeSafePermissions validates a caller-supplied set, drops duplicates
// and returns it in canonical order. The result is never nil, so an explicitly
// empty set stays distinguishable from "not named".
func NormalizeSafePermissions(in []string) ([]string, error) {
	have := map[string]bool{}
	for _, p := range in {
		p = strings.TrimSpace(p)
		switch p {
		case SafePermUse, SafePermRetrieve, SafePermApprove:
			have[p] = true
		default:
			return nil, fmt.Errorf("unknown safe permission %q (want use, retrieve or approve)", p)
		}
	}
	out := []string{}
	for _, p := range safePermOrder {
		if have[p] {
			out = append(out, p)
		}
	}
	return out, nil
}

// ParseSafePermissions reads the stored comma-separated form. Unknown tokens
// are dropped rather than trusted — a permission this build does not know
// confers nothing. Never nil.
func ParseSafePermissions(s string) []string {
	out, _ := NormalizeSafePermissions(nil)
	for _, p := range strings.Split(s, ",") {
		if n, err := NormalizeSafePermissions([]string{p}); err == nil && len(n) == 1 {
			out = append(out, n[0])
		}
	}
	norm, _ := NormalizeSafePermissions(out)
	return norm
}

// JoinSafePermissions is the stored form of a set.
func JoinSafePermissions(perms []string) string { return strings.Join(perms, ",") }

// GrantPermits reports whether a grant carrying perms admits action ("use",
// "retrieve", "approve" or AccessReach). perms is nil on a direct target
// grant, which confers use and retrieve and never approve; a grant folded in
// from safe membership carries the member's set.
func GrantPermits(perms []string, action string) bool {
	if perms == nil {
		return action != SafePermApprove
	}
	has := func(p string) bool {
		for _, x := range perms {
			if x == p {
				return true
			}
		}
		return false
	}
	if action == AccessReach {
		return has(SafePermUse) || has(SafePermRetrieve)
	}
	return has(action)
}
