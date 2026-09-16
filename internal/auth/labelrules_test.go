package auth

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// allowGrant and denyRule build the two row shapes EffectiveTargetGrants folds
// label rules in as.
func allowGrant(subjectType, subject string) store.TargetGrant {
	return store.TargetGrant{TargetID: 1, SubjectType: subjectType, Subject: subject}
}

func denyRule(subjectType, subject string) store.TargetGrant {
	return store.TargetGrant{TargetID: 1, SubjectType: subjectType, Subject: subject, Effect: store.GrantDeny}
}

// TestDenyBeatsEveryBypassButBreakGlass is the decision this phase turns on
// (Phase 250). A deny rule that an administrator can step around is not a
// deny rule: the estate-wide statement an operator writes as "nothing labelled
// tier=db is reachable by contractors" has to hold for the people most able to
// ignore it. Break-glass is the one exemption, matching the CIDR allowlist.
func TestDenyBeatsEveryBypassButBreakGlass(t *testing.T) {
	now := time.Now()
	grants := []store.TargetGrant{denyRule("role", "admin"), allowGrant("role", "admin")}

	admin := &Principal{Name: "root", Role: RoleAdmin}
	if CanAccessTargetAt(admin, grants, false, false, UngatedOpen, now, ActionUse) {
		t.Error("a deny rule naming the admin role must refuse an admin")
	}
	// ...even though the very same principal is admitted with the deny removed.
	if !CanAccessTargetAt(admin, grants[1:], false, false, UngatedOpen, now, ActionUse) {
		t.Error("without the deny rule the admin must be admitted")
	}
	// Break-glass is the declared emergency path and is exempt.
	bg := &Principal{Name: "break-glass", Role: RoleAdmin, BreakGlass: true}
	if !CanAccessTargetAt(bg, grants, false, false, UngatedOpen, now, ActionUse) {
		t.Error("break-glass must not be denied")
	}
	// A deny naming somebody else does not touch this principal.
	other := []store.TargetGrant{denyRule("user", "mallory"), allowGrant("user", "alice")}
	alice := &Principal{Name: "alice", Role: RoleUser}
	if !CanAccessTargetAt(alice, other, false, false, UngatedOpen, now, ActionUse) {
		t.Error("a deny rule naming another subject must not refuse alice")
	}
	if CanAccessTargetAt(&Principal{Name: "mallory", Role: RoleUser}, other, false, false, UngatedOpen, now, ActionUse) {
		t.Error("mallory is named by the deny rule and must be refused")
	}
	// Every action, not just sessions: a deny is not a permission set.
	for _, act := range []Action{ActionUse, ActionRetrieve, ActionReach} {
		if CanAccessTargetAt(&Principal{Name: "mallory", Role: RoleUser}, other, false, false, UngatedOpen, now, act) {
			t.Errorf("deny must refuse action %q too", act)
		}
	}
}

// TestDenyDoesNotGate proves a deny rule subtracts without closing. If a deny
// row counted as a grant for gating, adding "exclude the contractors from
// prod" would quietly convert every open prod target into one only its
// (non-existent) grantees could reach — turning an exclusion into an outage.
func TestDenyDoesNotGate(t *testing.T) {
	now := time.Now()
	onlyDeny := []store.TargetGrant{denyRule("user", "mallory")}
	bob := &Principal{Name: "bob", Role: RoleUser}
	if !CanAccessTargetAt(bob, onlyDeny, false, false, UngatedOpen, now, ActionUse) {
		t.Error("a target whose only row is a deny naming someone else must stay open")
	}
	if CanAccessTargetAt(&Principal{Name: "mallory", Role: RoleUser}, onlyDeny, false, false, UngatedOpen, now, ActionUse) {
		t.Error("...but the denied subject is still refused")
	}
	// The deployment-wide closed default still closes it: deny not gating is
	// not deny opening.
	if CanAccessTargetAt(bob, onlyDeny, false, false, UngatedDeny, now, ActionUse) {
		t.Error("an ungated-deny deployment must still refuse an ungated target")
	}
	// A safe-scoped target with only a deny row stays closed by containment.
	if CanAccessTargetAt(bob, onlyDeny, true, false, UngatedOpen, now, ActionUse) {
		t.Error("a safe-scoped target with no members must stay closed")
	}
	// An ALLOW label rule DOES gate, exactly as a direct grant does.
	onlyAllow := []store.TargetGrant{allowGrant("user", "alice")}
	if CanAccessTargetAt(bob, onlyAllow, false, false, UngatedOpen, now, ActionUse) {
		t.Error("an allow rule naming alice must gate the target against bob")
	}
}

// TestDenyRespectsItsOwnLifetime proves a deny rule is bounded like every
// other authorization row (Phase 240): an expired or out-of-window deny stops
// denying, rather than outliving the decision someone made.
func TestDenyRespectsItsOwnLifetime(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	mallory := &Principal{Name: "mallory", Role: RoleUser}

	expired := denyRule("user", "mallory")
	expired.ExpiresAt = &past
	grants := []store.TargetGrant{expired, allowGrant("role", "user")}
	if !CanAccessTargetAt(mallory, grants, false, false, UngatedOpen, now, ActionUse) {
		t.Error("an expired deny rule must stop denying")
	}
	live := denyRule("user", "mallory")
	future := now.Add(time.Hour)
	live.ExpiresAt = &future
	if CanAccessTargetAt(mallory, []store.TargetGrant{live, allowGrant("role", "user")}, false, false, UngatedOpen, now, ActionUse) {
		t.Error("a deny rule inside its window must still deny")
	}
}

// TestGrantDeadlineIgnoresDenyRows proves a deny row never contributes a
// session bound: a denied principal opens no session, and a deny row is not a
// grant whose edge could end one.
func TestGrantDeadlineIgnoresDenyRows(t *testing.T) {
	now := time.Now()
	soon := now.Add(10 * time.Minute)
	alice := &Principal{Name: "alice", Role: RoleUser}

	// A deny naming alice: no deadline, because there is no session.
	deny := denyRule("user", "alice")
	deny.ExpiresAt = &soon
	if _, _, ok := GrantDeadline(alice, []store.TargetGrant{deny}, false, now); ok {
		t.Error("a denied principal has no session and so no deadline")
	}
	// A deny naming somebody else must not become alice's deadline either.
	otherDeny := denyRule("user", "mallory")
	otherDeny.ExpiresAt = &soon
	allow := allowGrant("user", "alice")
	later := now.Add(2 * time.Hour)
	allow.ExpiresAt = &later
	dl, reason, ok := GrantDeadline(alice, []store.TargetGrant{otherDeny, allow}, false, now)
	if !ok || !dl.Equal(later) || reason != "grant-expiry" {
		t.Errorf("deadline = %v %q %v, want alice's own grant expiry %v", dl, reason, ok, later)
	}
}

// TestReachHonoursLabelRules proves the entitlement report and the connect
// gate read label rules the same way (Phase 250). They have to: a review that
// lists a target the gate refuses — or hides one it admits — stops describing
// the gate it exists to review. Phase 240 made the same argument for expiry.
func TestReachHonoursLabelRules(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	prod := &store.Target{Name: "db-01", Host: "h", Port: 22, OSType: "linux", Protocol: "ssh", Labels: "env=prod,tier=db"}
	staging := &store.Target{Name: "web-01", Host: "h", Port: 22, OSType: "linux", Protocol: "ssh", Labels: "env=staging"}
	for _, tg := range []*store.Target{prod, staging} {
		if err := st.CreateTarget(ctx, tg); err != nil {
			t.Fatal(err)
		}
	}
	// alice is allowed everything labelled env=prod.
	if err := st.CreateLabelRule(ctx, &store.LabelRule{Selector: "env=prod", SubjectType: "user", Subject: "alice", Effect: store.GrantAllow}); err != nil {
		t.Fatal(err)
	}
	reachNames := func(p *Principal) []string {
		t.Helper()
		out, err := ReachableTargets(ctx, st, p, UngatedOpen)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, r := range out {
			names = append(names, r.Target.Name)
		}
		sort.Strings(names)
		return names
	}
	alice := &Principal{Name: "alice", Role: RoleUser}
	// db-01 via the label rule; web-01 is ungated and so open to anyone.
	if got := reachNames(alice); len(got) != 2 {
		t.Fatalf("alice reaches %v, want both targets", got)
	}
	// The allow rule gates db-01, so bob — named by nothing — loses it but
	// keeps the ungated one.
	bob := &Principal{Name: "bob", Role: RoleUser}
	if got := reachNames(bob); len(got) != 1 || got[0] != "web-01" {
		t.Fatalf("bob reaches %v, want only the ungated web-01", got)
	}
	// The report names the path and the selector it matched on.
	out, err := ReachableTargets(ctx, st, alice, UngatedOpen)
	if err != nil {
		t.Fatal(err)
	}
	var sawLabel bool
	for _, r := range out {
		if r.Target.Name == "db-01" {
			if r.Via != ReachViaLabel {
				t.Errorf("db-01 via = %q, want %q", r.Via, ReachViaLabel)
			}
			sawLabel = true
		}
	}
	if !sawLabel {
		t.Fatal("db-01 must be reported as reached through the label rule")
	}

	// A deny rule removes the target from the report, for an ADMIN too — the
	// same order the gate reads, deny ahead of the bypass.
	if err := st.CreateLabelRule(ctx, &store.LabelRule{Selector: "tier=db", SubjectType: "role", Subject: "admin", Effect: store.GrantDeny}); err != nil {
		t.Fatal(err)
	}
	admin := &Principal{Name: "root", Role: RoleAdmin}
	got := reachNames(admin)
	for _, n := range got {
		if n == "db-01" {
			t.Fatalf("the admin's report lists db-01, which a deny rule refuses: %v", got)
		}
	}
	if len(got) != 1 || got[0] != "web-01" {
		t.Fatalf("admin reaches %v, want only web-01", got)
	}
	// And the gate agrees, which is the point.
	grants, err := st.EffectiveTargetGrants(ctx, prod.ID)
	if err != nil {
		t.Fatal(err)
	}
	if CanConnectTarget(admin, grants, false, false, UngatedOpen) {
		t.Fatal("the gate admits an admin the report excludes")
	}
}
