package auth

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestCanAccessTargetActions pins the decision every target door makes since
// Phase 246: a safe membership admits only the actions it names, a grant that
// does not admit the action still gates the target, a direct grant admits use
// and retrieve, and the admin bypass is a decision about the principal, not
// about a membership's rights.
func TestCanAccessTargetActions(t *testing.T) {
	now := time.Now()
	alice := &Principal{Name: "alice", Role: RoleUser}
	member := func(perms ...string) []store.TargetGrant {
		return []store.TargetGrant{{SubjectType: "user", Subject: "alice", Permissions: append([]string{}, perms...)}}
	}
	direct := []store.TargetGrant{{SubjectType: "user", Subject: "alice"}}
	cases := []struct {
		name   string
		grants []store.TargetGrant
		act    Action
		want   bool
	}{
		{"direct grant: use", direct, ActionUse, true},
		{"direct grant: retrieve", direct, ActionRetrieve, true},
		{"use-only member: use", member("use"), ActionUse, true},
		{"use-only member: retrieve", member("use"), ActionRetrieve, false},
		{"retrieve-only member: use", member("retrieve"), ActionUse, false},
		{"retrieve-only member: retrieve", member("retrieve"), ActionRetrieve, true},
		{"retrieve-only member: reach", member("retrieve"), ActionReach, true},
		{"approve-only member: reach", member("approve"), ActionReach, false},
		{"approve-only member keeps the target gated", member("approve"), ActionUse, false},
		{"a membership with no permissions admits nothing", member(), ActionUse, false},
	}
	for _, tc := range cases {
		if got := CanAccessTargetAt(alice, tc.grants, true, false, UngatedOpen, now, tc.act); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	// An ungated target outside a safe gated ONLY by an approve-only membership
	// is still gated: the row counts, as an expired one does.
	if CanAccessTargetAt(alice, member("approve"), false, false, UngatedOpen, now, ActionUse) {
		t.Fatal("an approve-only membership must not let its target fall open")
	}
	admin := &Principal{Name: "root", Role: RoleAdmin}
	if !CanAccessTargetAt(admin, member("approve"), true, false, UngatedOpen, now, ActionRetrieve) {
		t.Fatal("the admin bypass is about the principal and applies to every action")
	}
	if CanConnectTargetAt(alice, member("retrieve"), true, false, UngatedOpen, now) {
		t.Fatal("CanConnectTargetAt is the use action")
	}
}

// TestGrantDeadlineIgnoresNonUseGrants proves only a grant that admits a
// session bounds one: a retrieve-only membership's expiry is not a session's
// deadline, because it admitted nobody to the session.
func TestGrantDeadlineIgnoresNonUseGrants(t *testing.T) {
	now := time.Now()
	soon := now.Add(time.Hour)
	alice := &Principal{Name: "alice", Role: RoleUser}
	retrieveOnly := []store.TargetGrant{{SubjectType: "user", Subject: "alice", Permissions: []string{"retrieve"}, ExpiresAt: &soon}}
	if _, _, ok := GrantDeadline(alice, retrieveOnly, false, now); ok {
		t.Fatal("a retrieve-only membership must not bound a session")
	}
	useBounded := []store.TargetGrant{{SubjectType: "user", Subject: "alice", Permissions: []string{"use"}, ExpiresAt: &soon}}
	if dl, why, ok := GrantDeadline(alice, useBounded, false, now); !ok || !dl.Equal(soon) || why != "grant-expiry" {
		t.Fatalf("a use membership's expiry is the deadline: %v %q %v", dl, why, ok)
	}
}

// TestReachReportsPermissions proves the reach view reads permissions the way
// the doors do: a retrieve-only member reaches the target and is shown only
// retrieve, an approve-only member does not reach it at all, and a subject a
// direct grant also names is shown both actions.
func TestReachReportsPermissions(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	sf := &store.Safe{Name: "ops"}
	if err := st.CreateSafe(ctx, sf); err != nil {
		t.Fatal(err)
	}
	tg := &store.Target{Name: "db-01", Host: "db-01.example", Port: 22, Protocol: "ssh"}
	if err := st.CreateTarget(ctx, tg); err != nil {
		t.Fatal(err)
	}
	if err := st.AssignTargetSafe(ctx, tg.ID, &sf.ID); err != nil {
		t.Fatal(err)
	}
	for _, m := range []store.SafeMember{
		{SafeID: sf.ID, SubjectType: "user", Subject: "alice", Permissions: []string{"retrieve"}},
		{SafeID: sf.ID, SubjectType: "user", Subject: "bob", Permissions: []string{"approve"}},
		{SafeID: sf.ID, SubjectType: "user", Subject: "carol", Permissions: []string{"retrieve"}},
	} {
		mm := m
		if err := st.AddSafeMember(ctx, &mm); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CreateTargetGrant(ctx, &store.TargetGrant{TargetID: tg.ID, SubjectType: "user", Subject: "carol"}); err != nil {
		t.Fatal(err)
	}
	reach := func(name string) []Reach {
		t.Helper()
		rs, err := ReachableTargets(ctx, st, &Principal{Name: name, Role: RoleUser}, UngatedOpen)
		if err != nil {
			t.Fatal(err)
		}
		return rs
	}
	if rs := reach("alice"); len(rs) != 1 || !reflect.DeepEqual(rs[0].Permissions, []string{"retrieve"}) || rs[0].Via != ReachViaSafe {
		t.Fatalf("alice: %+v", rs)
	}
	if rs := reach("bob"); len(rs) != 0 {
		t.Fatalf("an approve-only member reaches nothing: %+v", rs)
	}
	if rs := reach("carol"); len(rs) != 1 || !reflect.DeepEqual(rs[0].Permissions, []string{"use", "retrieve"}) || rs[0].Via != ReachViaGrant {
		t.Fatalf("carol: %+v", rs)
	}
}
