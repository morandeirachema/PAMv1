package auth

import (
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

func TestEffectiveRights(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	alice := &Principal{Name: "alice", Role: RoleUser}
	target := &store.Target{ID: 1, Rights: "ssh_exec,ssh_sftp,ssh_shell"}
	open := &store.Target{ID: 2}

	// No grants at all (admin bypass / ungated): the target's set stands.
	if got := EffectiveRights(alice, target, nil, now); got != target.Rights {
		t.Fatalf("no grants: %q", got)
	}
	if got := EffectiveRights(alice, open, nil, now); got != "" {
		t.Fatalf("no grants, open target: %q", got)
	}
	// One matching grant with no set: the target's set.
	g := []store.TargetGrant{{SubjectType: "user", Subject: "alice"}}
	if got := EffectiveRights(alice, target, g, now); got != target.Rights {
		t.Fatalf("unbounded grant: %q", got)
	}
	// A narrowing grant: intersected with the target's set.
	g = []store.TargetGrant{{SubjectType: "user", Subject: "alice", Rights: "ssh_shell,ssh_x11"}}
	if got := EffectiveRights(alice, target, g, now); got != "ssh_shell" {
		t.Fatalf("narrowing grant ∩ target: %q", got)
	}
	// On an open target the grant's set is the whole answer.
	if got := EffectiveRights(alice, open, g, now); got != "ssh_shell,ssh_x11" {
		t.Fatalf("narrowing grant on open target: %q", got)
	}
	// Two narrowing grants add up; a grant for someone else, a deny, an
	// expired one and a role grant for another role do not count.
	g = []store.TargetGrant{
		{SubjectType: "user", Subject: "alice", Rights: "ssh_shell"},
		{SubjectType: "role", Subject: "user", Rights: "ssh_sftp"},
		{SubjectType: "user", Subject: "bob", Rights: "ssh_exec"},
		{SubjectType: "user", Subject: "alice", Rights: "ssh_exec", Effect: store.GrantDeny},
		{SubjectType: "user", Subject: "alice", Rights: "ssh_exec", ExpiresAt: &past},
		{SubjectType: "role", Subject: "admin", Rights: "ssh_exec"},
	}
	if got := EffectiveRights(alice, target, g, now); got != "ssh_sftp,ssh_shell" {
		t.Fatalf("union of narrowing grants: %q", got)
	}
	// A narrowing grant plus an unbounded one: the unbounded wins (target's set).
	g = append(g, store.TargetGrant{SubjectType: "user", Subject: "alice"})
	if got := EffectiveRights(alice, target, g, now); got != target.Rights {
		t.Fatalf("unbounded beside narrowing: %q", got)
	}
	// Every admitting grant narrows to something the target does not allow:
	// an explicit "none", never "" (which would mean everything).
	g = []store.TargetGrant{{SubjectType: "user", Subject: "alice", Rights: "rdp_drive"}}
	if got := EffectiveRights(alice, target, g, now); got != "none" || store.RightsAllow(got, store.RightSSHShell) {
		t.Fatalf("disjoint narrowing: %q", got)
	}
}
