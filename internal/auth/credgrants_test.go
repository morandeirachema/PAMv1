package auth

import (
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

func scoped(subject string, credID int64) store.TargetGrant {
	return store.TargetGrant{TargetID: 1, SubjectType: "user", Subject: subject, CredentialID: &credID}
}

// TestCredentialScopedGrant is the decision Phase 252 turns on: a grant
// naming ONE credential admits that credential and no other — and still
// gates the target, so the subject finds the other credential refused rather
// than open. A request about the target as a whole (nil credential) is
// satisfied by any grant on it, which is what the reach view and the
// management paths ask.
func TestCredentialScopedGrant(t *testing.T) {
	now := time.Now()
	alice := &Principal{Name: "alice", Role: RoleUser}
	grants := []store.TargetGrant{scoped("alice", 7)}

	if !CanAccessCredentialAt(alice, grants, 7, false, false, UngatedOpen, now, ActionUse) {
		t.Error("a grant scoped to credential 7 must admit credential 7")
	}
	if CanAccessCredentialAt(alice, grants, 8, false, false, UngatedOpen, now, ActionUse) {
		t.Error("a grant scoped to credential 7 must not admit credential 8")
	}
	// The scoped grant GATES the target: bob, whom nothing names, is refused
	// every credential — including one no grant mentions.
	bob := &Principal{Name: "bob", Role: RoleUser}
	if CanAccessCredentialAt(bob, grants, 8, false, false, UngatedOpen, now, ActionUse) {
		t.Error("a scoped grant must gate the target against unnamed subjects")
	}
	// The target as a whole: alice reaches it (through 7), bob does not.
	if !CanAccessTargetAt(alice, grants, false, false, UngatedOpen, now, ActionReach) {
		t.Error("a subject with a scoped grant reaches the target")
	}
	if CanAccessTargetAt(bob, grants, false, false, UngatedOpen, now, ActionReach) {
		t.Error("bob must not reach a gated target")
	}
	// An unscoped grant covers every credential.
	whole := []store.TargetGrant{{TargetID: 1, SubjectType: "user", Subject: "alice"}}
	for _, id := range []int64{7, 8, 99} {
		if !CanAccessCredentialAt(alice, whole, id, false, false, UngatedOpen, now, ActionRetrieve) {
			t.Errorf("an unscoped grant must admit credential %d", id)
		}
	}
	// Two scoped grants for the same subject are a union.
	two := []store.TargetGrant{scoped("alice", 7), scoped("alice", 8)}
	for _, id := range []int64{7, 8} {
		if !CanAccessCredentialAt(alice, two, id, false, false, UngatedOpen, now, ActionUse) {
			t.Errorf("credential %d is named by one of alice's grants", id)
		}
	}
	if CanAccessCredentialAt(alice, two, 9, false, false, UngatedOpen, now, ActionUse) {
		t.Error("credential 9 is named by neither grant")
	}
	// Admins and break-glass are unaffected: they need no grant.
	if !CanAccessCredentialAt(&Principal{Name: "root", Role: RoleAdmin}, grants, 8, false, false, UngatedOpen, now, ActionUse) {
		t.Error("an admin needs no grant, scoped or not")
	}
}

// TestGrantDeadlineForCredential proves a grant scoped to a different
// credential contributes no session bound: it admitted nobody to THIS session.
func TestGrantDeadlineForCredential(t *testing.T) {
	now := time.Now()
	alice := &Principal{Name: "alice", Role: RoleUser}
	soon := now.Add(10 * time.Minute)
	later := now.Add(2 * time.Hour)
	on7 := scoped("alice", 7)
	on7.ExpiresAt = &soon
	on8 := scoped("alice", 8)
	on8.ExpiresAt = &later
	grants := []store.TargetGrant{on7, on8}

	seven := int64(7)
	dl, reason, ok := GrantDeadlineFor(alice, grants, &seven, false, now)
	if !ok || !dl.Equal(soon) || reason != "grant-expiry" {
		t.Errorf("session on 7: deadline %v %q %v, want the grant on 7's expiry %v", dl, reason, ok, soon)
	}
	eight := int64(8)
	dl, _, ok = GrantDeadlineFor(alice, grants, &eight, false, now)
	if !ok || !dl.Equal(later) {
		t.Errorf("session on 8: deadline %v %v, want %v", dl, ok, later)
	}
	// The whole-target reading is the LATEST edge among all admitting grants,
	// which is what a caller with no credential in hand gets — unchanged.
	dl, _, ok = GrantDeadline(alice, grants, false, now)
	if !ok || !dl.Equal(later) {
		t.Errorf("whole target: %v %v, want the later edge %v", dl, ok, later)
	}
}

// TestReachCredentials proves the entitlement report names the credentials a
// reach is scoped to, and reports the whole target as soon as any admitting
// grant covers it.
func TestReachCredentials(t *testing.T) {
	seven, eight := int64(7), int64(8)
	scopedRows := []store.SubjectGrant{{CredentialID: &eight}, {CredentialID: &seven}, {CredentialID: &seven}}
	if got := reachCredentials(scopedRows); len(got) != 2 || got[0] != 7 || got[1] != 8 {
		t.Errorf("reachCredentials = %v, want [7 8]", got)
	}
	mixed := []store.SubjectGrant{{CredentialID: &seven}, {}}
	if got := reachCredentials(mixed); got != nil {
		t.Errorf("one unscoped grant widens the reach to the whole target, got %v", got)
	}
}
