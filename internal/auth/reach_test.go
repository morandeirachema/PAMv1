package auth

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// reachFixture builds a small estate with every shape that changes the answer:
// ungated targets, targets gated by a direct user grant, by a role grant, by a
// safe's membership, a safe with no members at all (closed by containment), and
// a personal safe.
type reachFixture struct {
	st       *memstore.Memstore
	targets  map[string]int64
	safeOpen int64
	safeNone int64
	safePriv int64
}

func newReachFixture(t *testing.T) *reachFixture {
	t.Helper()
	ctx := context.Background()
	st := memstore.New()
	f := &reachFixture{st: st, targets: map[string]int64{}}

	mkSafe := func(name string, personal bool) int64 {
		sf := &store.Safe{Name: name, Personal: personal}
		if err := st.CreateSafe(ctx, sf); err != nil {
			t.Fatalf("CreateSafe(%s): %v", name, err)
		}
		return sf.ID
	}
	f.safeOpen = mkSafe("prod", false)
	f.safeNone = mkSafe("empty", false)
	f.safePriv = mkSafe("personal", true)

	// The safe is assigned in a second call, never as a field on the struct
	// CreateTarget is given — that is the only path that works on both store
	// backends (see store.TargetStore.CreateTarget).
	mkTarget := func(name string, safeID *int64) {
		tg := &store.Target{Name: name, Host: name + ".example", Port: 22, Protocol: "ssh"}
		if err := st.CreateTarget(ctx, tg); err != nil {
			t.Fatalf("CreateTarget(%s): %v", name, err)
		}
		f.targets[name] = tg.ID
		if safeID != nil {
			if err := st.AssignTargetSafe(ctx, tg.ID, safeID); err != nil {
				t.Fatalf("AssignTargetSafe(%s): %v", name, err)
			}
		}
	}
	mkTarget("ungated", nil)           // nothing gates it: open to anyone
	mkTarget("direct", nil)            // a user grant naming alice
	mkTarget("byrole", nil)            // a role grant naming user
	mkTarget("both", nil)              // both of the above, on one target
	mkTarget("other", nil)             // a grant naming somebody else
	mkTarget("insafe", &f.safeOpen)    // reachable through safe membership
	mkTarget("emptysafe", &f.safeNone) // in a safe nobody is a member of
	mkTarget("private", &f.safePriv)   // in a personal safe

	mkGrant := func(target, subjectType, subject string) {
		g := &store.TargetGrant{TargetID: f.targets[target], SubjectType: subjectType, Subject: subject}
		if err := st.CreateTargetGrant(ctx, g); err != nil {
			t.Fatalf("CreateTargetGrant(%s): %v", target, err)
		}
	}
	mkGrant("direct", "user", "alice")
	mkGrant("byrole", "role", string(RoleUser))
	mkGrant("both", "user", "alice")
	mkGrant("both", "role", string(RoleUser))
	mkGrant("other", "user", "mallory")

	for _, m := range []store.SafeMember{
		{SafeID: f.safeOpen, SubjectType: "user", Subject: "alice"},
		{SafeID: f.safePriv, SubjectType: "user", Subject: "alice"},
	} {
		mm := m
		if err := st.AddSafeMember(ctx, &mm); err != nil {
			t.Fatalf("AddSafeMember: %v", err)
		}
	}
	return f
}

// canConnectLoop is the naive, target-indexed answer: the loop every connect
// path runs, one EffectiveTargetGrants read per target. It is the definition
// ReachableTargets must reproduce, kept here as the test's oracle.
func canConnectLoop(ctx context.Context, t *testing.T, st *memstore.Memstore, p *Principal) map[string]bool {
	t.Helper()
	targets, err := st.ListTargets(ctx, 0, 0)
	if err != nil {
		t.Fatalf("ListTargets: %v", err)
	}
	out := map[string]bool{}
	for i := range targets {
		grants, err := st.EffectiveTargetGrants(ctx, targets[i].ID)
		if err != nil {
			t.Fatalf("EffectiveTargetGrants: %v", err)
		}
		personal, err := store.EffectiveSafePersonal(ctx, st, &targets[i])
		if err != nil {
			t.Fatalf("EffectiveSafePersonal: %v", err)
		}
		out[targets[i].Name] = CanConnectTarget(p, grants, targets[i].SafeID != nil, personal)
	}
	return out
}

func reachSet(rs []Reach) map[string]bool {
	out := map[string]bool{}
	for _, r := range rs {
		out[r.Target.Name] = true
	}
	return out
}

// TestReachMatchesCanConnect is the invariant the whole subject-indexed path
// rests on: for every principal shape, the four-read answer names exactly the
// targets the per-target CanConnectTarget loop admits. A second definition of
// "may reach" that drifts from the connect-time one would be worse than no
// query at all — this is what stops that.
func TestReachMatchesCanConnect(t *testing.T) {
	ctx := context.Background()
	f := newReachFixture(t)

	principals := []*Principal{
		{Name: "alice", Role: RoleUser},
		{Name: "bob", Role: RoleUser},
		{Name: "carol", Role: RoleAuditor},
		{Name: "root", Role: RoleAdmin},
		{Name: "alice", Role: RoleAdmin},
		{Name: "multi", Role: RoleUser, Roles: []Role{RoleUser, RoleAuditor}},
		{Name: "unlimited", Role: Role("custodian"), Caps: CapSet{CapUnlimitedVaultAccess: true, CapConnect: true}},
		{Name: "agent-a", Role: RoleAgent},
	}
	for _, p := range principals {
		want := map[string]bool{}
		for name, ok := range canConnectLoop(ctx, t, f.st, p) {
			if ok {
				want[name] = true
			}
		}
		rs, err := ReachableTargets(ctx, f.st, p)
		if err != nil {
			t.Fatalf("ReachableTargets(%s): %v", p.Name, err)
		}
		got := reachSet(rs)
		if len(got) != len(want) {
			t.Fatalf("%s/%s: reach %v, CanConnectTarget %v", p.Name, p.Role, got, want)
		}
		for name := range want {
			if !got[name] {
				t.Fatalf("%s/%s: CanConnectTarget admits %q, reach does not", p.Name, p.Role, name)
			}
		}
	}
}

// TestReachReasons pins the reason each target is reported with, which is the
// half a yes/no gate cannot give a reviewer.
func TestReachReasons(t *testing.T) {
	ctx := context.Background()
	f := newReachFixture(t)

	reasons := func(p *Principal) map[string]Reach {
		rs, err := ReachableTargets(ctx, f.st, p)
		if err != nil {
			t.Fatalf("ReachableTargets: %v", err)
		}
		out := map[string]Reach{}
		for _, r := range rs {
			out[r.Target.Name] = r
		}
		return out
	}

	alice := reasons(&Principal{Name: "alice", Role: RoleUser})
	for name, want := range map[string]string{
		"ungated": ReachViaOpen,
		"direct":  ReachViaGrant,
		"byrole":  ReachViaGrant,
		"both":    ReachViaGrant,
		"insafe":  ReachViaSafe,
		"private": ReachViaSafe,
	} {
		r, ok := alice[name]
		if !ok {
			t.Fatalf("alice cannot reach %q", name)
		}
		if r.Via != want {
			t.Errorf("alice reaches %q via %q, want %q", name, r.Via, want)
		}
	}
	if _, ok := alice["other"]; ok {
		t.Error("alice reaches a target granted to somebody else")
	}
	if _, ok := alice["emptysafe"]; ok {
		t.Error("a safe with no members must contain nothing reachable")
	}
	// "both" is admitted by a user grant AND a role grant: the sharper of the
	// two is the one a review should see.
	if got := alice["both"]; got.SubjectType != "user" || got.Subject != "alice" {
		t.Errorf("both: reported %s:%s, want the direct user grant", got.SubjectType, got.Subject)
	}
	// byrole is admitted only by the role grant, so that is what is reported.
	if got := alice["byrole"]; got.SubjectType != "role" || got.Subject != string(RoleUser) {
		t.Errorf("byrole: reported %s:%s, want role:user", got.SubjectType, got.Subject)
	}
	if got := alice["insafe"]; got.SafeID == nil || *got.SafeID != f.safeOpen {
		t.Errorf("insafe: safe not named on a safe-derived reach: %+v", got.SafeID)
	}

	root := reasons(&Principal{Name: "root", Role: RoleAdmin})
	if got := root["direct"]; got.Via != ReachViaAdmin {
		t.Errorf("admin reaches direct via %q, want %q", got.Via, ReachViaAdmin)
	}
	if _, ok := root["private"]; ok {
		t.Error("a plain admin must not reach a personal safe's target")
	}
	unlimited := reasons(&Principal{Name: "cust", Role: Role("custodian"), Caps: CapSet{CapUnlimitedVaultAccess: true}})
	if got := unlimited["private"]; got.Via != ReachViaUnlimited {
		t.Errorf("unlimited-vault principal reaches private via %q, want %q", got.Via, ReachViaUnlimited)
	}

	counts := ReachSubjectCounts([]Reach{{Via: ReachViaOpen}, {Via: ReachViaOpen}, {Via: ReachViaGrant}})
	if counts[ReachViaOpen] != 2 || counts[ReachViaGrant] != 1 {
		t.Errorf("ReachSubjectCounts = %v", counts)
	}
}

// TestGrantSubjectsMatchesSubjectMatches keeps the query's subject list and the
// connect-time matcher in step: every identifier GrantSubjects emits must be one
// SubjectMatches accepts, and nothing else may be.
func TestGrantSubjectsMatchesSubjectMatches(t *testing.T) {
	ps := []*Principal{
		{Name: "alice", Role: RoleUser},
		{Name: "multi", Role: RoleUser, Roles: []Role{RoleUser, RoleAuditor, RoleApprover}},
		{Name: "profiled", Role: Role("custodian"), Caps: CapSet{CapConnect: true}},
	}
	for _, p := range ps {
		for _, sub := range GrantSubjects(p) {
			if !SubjectMatches(p, sub.Type, sub.Name) {
				t.Errorf("%s: GrantSubjects emitted %s:%s, which SubjectMatches rejects", p.Name, sub.Type, sub.Name)
			}
		}
		for _, bad := range []store.GrantSubject{
			{Type: "user", Name: p.Name + "x"},
			{Type: "role", Name: "nosuchrole"},
			{Type: "group", Name: p.Name},
		} {
			if SubjectMatches(p, bad.Type, bad.Name) {
				t.Errorf("%s: SubjectMatches accepts %s:%s, which GrantSubjects never emits", p.Name, bad.Type, bad.Name)
			}
		}
	}
}

// TestReachMatchesCanConnectRandomized runs the same equivalence over randomly
// generated estates, because the hand-built fixture only covers the shapes its
// author thought of.
func TestReachMatchesCanConnectRandomized(t *testing.T) {
	ctx := context.Background()
	rng := rand.New(rand.NewSource(20260823))
	subjects := []string{"alice", "bob", "mallory"}
	roles := []Role{RoleUser, RoleAuditor, RoleAgent}

	for run := 0; run < 25; run++ {
		st := memstore.New()
		var safeIDs []*int64
		safeIDs = append(safeIDs, nil)
		for i := 0; i < 3; i++ {
			sf := &store.Safe{Name: fmt.Sprintf("safe%d", i), Personal: rng.Intn(3) == 0}
			if err := st.CreateSafe(ctx, sf); err != nil {
				t.Fatalf("CreateSafe: %v", err)
			}
			id := sf.ID
			safeIDs = append(safeIDs, &id)
			if rng.Intn(2) == 0 {
				m := &store.SafeMember{SafeID: id, SubjectType: "user", Subject: subjects[rng.Intn(len(subjects))]}
				if err := st.AddSafeMember(ctx, m); err != nil {
					t.Fatalf("AddSafeMember: %v", err)
				}
			}
			if rng.Intn(3) == 0 {
				m := &store.SafeMember{SafeID: id, SubjectType: "role", Subject: string(roles[rng.Intn(len(roles))])}
				if err := st.AddSafeMember(ctx, m); err != nil {
					t.Fatalf("AddSafeMember: %v", err)
				}
			}
		}
		for i := 0; i < 12; i++ {
			tg := &store.Target{Name: fmt.Sprintf("t%d", i), Host: "h", Port: 22, Protocol: "ssh"}
			if err := st.CreateTarget(ctx, tg); err != nil {
				t.Fatalf("CreateTarget: %v", err)
			}
			if sid := safeIDs[rng.Intn(len(safeIDs))]; sid != nil {
				if err := st.AssignTargetSafe(ctx, tg.ID, sid); err != nil {
					t.Fatalf("AssignTargetSafe: %v", err)
				}
			}
			for n := rng.Intn(3); n > 0; n-- {
				g := &store.TargetGrant{TargetID: tg.ID}
				if rng.Intn(2) == 0 {
					g.SubjectType, g.Subject = "user", subjects[rng.Intn(len(subjects))]
				} else {
					g.SubjectType, g.Subject = "role", string(roles[rng.Intn(len(roles))])
				}
				if err := st.CreateTargetGrant(ctx, g); err != nil && err != store.ErrConflict {
					t.Fatalf("CreateTargetGrant: %v", err)
				}
			}
		}
		for _, p := range []*Principal{
			{Name: "alice", Role: RoleUser},
			{Name: "bob", Role: RoleAgent},
			{Name: "mallory", Role: RoleAuditor},
			{Name: "root", Role: RoleAdmin},
			{Name: "alice", Role: Role("custodian"), Caps: CapSet{CapUnlimitedVaultAccess: true}},
		} {
			want := canConnectLoop(ctx, t, st, p)
			got := reachSet(mustReach(ctx, t, st, p))
			for name, ok := range want {
				if ok != got[name] {
					t.Fatalf("run %d, %s/%s, target %s: CanConnectTarget=%v reach=%v", run, p.Name, p.Role, name, ok, got[name])
				}
			}
		}
	}
}

func mustReach(ctx context.Context, t *testing.T, st *memstore.Memstore, p *Principal) []Reach {
	t.Helper()
	rs, err := ReachableTargets(ctx, st, p)
	if err != nil {
		t.Fatalf("ReachableTargets: %v", err)
	}
	return rs
}

// TestReachGrantSnapshotUnderWriters pins the property ordering could not give.
//
// Phase 191 read the subject's grants before the gated set, which closed the
// window where a newly restricted target was still reported OPEN — reachable by
// anyone — but opened its mirror: revoking THIS subject's grant on a target other
// grants still hold left the deleted row in hand while the target stayed gated,
// so it was reported reachable via a grant that no longer existed. Ordering
// trades one window for the other. Phase 193 takes both answers from one
// snapshot, and this test drives real concurrent writers at it.
//
// The invariant is the one only a snapshot can hold: every target a returned
// grant names must be in the same answer's gated set, because a grant IS what
// gates a target. A pair read at two different moments violates it in one
// direction or the other. Run under -race, this also proves the store's own
// locking holds.
func TestReachGrantSnapshotUnderWriters(t *testing.T) {
	f := newReachFixture(t)
	ctx := context.Background()
	id := f.targets["ungated"]

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			g := &store.TargetGrant{TargetID: id, SubjectType: "user", Subject: "racer"}
			if err := f.st.CreateTargetGrant(ctx, g); err != nil {
				return
			}
			if err := f.st.DeleteTargetGrant(ctx, g.ID); err != nil {
				return
			}
		}
	}()

	p := &Principal{Name: "racer", Role: RoleUser}
	for i := 0; i < 300; i++ {
		grants, gated, err := f.st.ReachGrantSnapshot(ctx, GrantSubjects(p))
		if err != nil {
			t.Fatalf("ReachGrantSnapshot: %v", err)
		}
		set := make(map[int64]struct{}, len(gated))
		for _, g := range gated {
			set[g] = struct{}{}
		}
		for _, g := range grants {
			if _, ok := set[g.TargetID]; !ok {
				close(stop)
				wg.Wait()
				t.Fatalf("grant on target %d that the same snapshot says nothing gates: %+v", g.TargetID, g)
			}
		}
	}
	close(stop)
	wg.Wait()

	// And the reach answer built on it stays sane throughout: a subject whose
	// only grant is being created and destroyed underneath must never be told a
	// gated target is "open".
	got, err := ReachableTargets(ctx, f.st, p)
	if err != nil {
		t.Fatalf("ReachableTargets: %v", err)
	}
	for _, rc := range got {
		if rc.Target.ID == id && rc.Via == ReachViaOpen {
			if _, gatedNow, err := f.st.ReachGrantSnapshot(ctx, nil); err == nil {
				for _, g := range gatedNow {
					if g == id {
						t.Fatalf("target %d reported open while the store says it is gated", id)
					}
				}
			}
		}
	}
}
