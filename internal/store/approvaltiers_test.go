package store

import (
	"strings"
	"testing"
)

func TestParseApprovalTiers(t *testing.T) {
	got, err := ParseApprovalTiers(" manager ;approver : 2; user=carol;admin ")
	if err != nil {
		t.Fatal(err)
	}
	want := []ApprovalTier{{Kind: TierManager, Count: 1}, {Kind: TierRole, Name: "approver", Count: 2}, {Kind: TierUser, Name: "carol", Count: 1}, {Kind: TierRole, Name: "admin", Count: 1}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tier %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if canon, _ := NormalizeApprovalTiers(" manager ;approver : 2; user=carol;admin "); canon != "manager; approver:2; user=carol; admin" {
		t.Errorf("canonical = %q", canon)
	}
	if tiers, err := ParseApprovalTiers("   "); err != nil || tiers != nil {
		t.Errorf("empty spec = %v, %v; want no chain", tiers, err)
	}
	for _, bad := range []string{";", "manager;", "approver:0", "approver:11", "manager:2", "user=:2", "user=bob:2", "role with space", "approver:x", strings.Repeat("approver;", 9) + "admin"} {
		if _, err := ParseApprovalTiers(bad); err == nil {
			t.Errorf("ParseApprovalTiers(%q) accepted", bad)
		}
	}
	if !HasManagerTier(want) || HasManagerTier(want[1:]) {
		t.Error("HasManagerTier")
	}
}

// TestTierProgress proves the replay credits each approver to the first
// unsatisfied tier they qualify for, in approval order, and that an early
// level-2 approval is held back rather than counted or lost.
func TestTierProgress(t *testing.T) {
	tiers, _ := ParseApprovalTiers("manager; approver:2")
	roles := map[string]string{"mia": "user", "pat": "approver", "quinn": "approver", "root": "admin"}
	qual := func(a string, tier ApprovalTier) bool {
		switch tier.Kind {
		case TierManager:
			return a == "mia" // alice's manager
		case TierRole:
			return roles[a] == tier.Name
		}
		return false
	}
	// pat approves before the manager: held, not credited, chain not complete.
	st, cur, done := TierProgress(tiers, []string{"pat"}, qual)
	if done || cur != 0 || st[0].Satisfied || len(st[1].ApprovedBy) != 0 || !st[0].Current {
		t.Fatalf("early level-2 approval must be held: %+v cur=%d done=%v", st, cur, done)
	}
	// The manager approves: tier 1 done, and pat's earlier approval is now credited to tier 2.
	st, cur, done = TierProgress(tiers, []string{"pat", "mia"}, qual)
	if done || cur != 1 || !st[0].Satisfied || len(st[1].ApprovedBy) != 1 || st[1].ApprovedBy[0] != "pat" || !st[1].Current {
		t.Fatalf("after the manager: %+v cur=%d done=%v", st, cur, done)
	}
	// A second approver completes the chain.
	st, cur, done = TierProgress(tiers, []string{"pat", "mia", "quinn"}, qual)
	if !done || cur != 2 || !st[1].Satisfied || len(st[1].ApprovedBy) != 2 {
		t.Fatalf("complete: %+v cur=%d done=%v", st, cur, done)
	}
	// An admin who qualifies for no tier is never credited.
	st, _, done = TierProgress(tiers, []string{"mia", "root", "root"}, qual)
	if done || len(st[1].ApprovedBy) != 0 {
		t.Fatalf("an unqualified approver must not be credited: %+v", st)
	}
	// No chain: complete by definition.
	if _, cur, done := TierProgress(nil, []string{"anyone"}, qual); !done || cur != 0 {
		t.Error("an empty chain is complete")
	}
}
