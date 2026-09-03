package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// todayFrame is a time frame live right now (today's weekday, all day, UTC);
// neverFrame is one that is not (two days from now).
func todayFrame() string { return time.Now().UTC().Weekday().String()[:3] + " 00:00-24:00" }
func neverFrame() string {
	return time.Now().UTC().AddDate(0, 0, 2).Weekday().String()[:3] + " 00:00-24:00"
}

// TestAdmitGrantLifetime proves the connect gate reads a grant's bounds (Phase
// 240): an expired or out-of-frame grant refuses at the target-policy gate —
// and, because the row still gates the target, refuses rather than falling
// open — while a live bounded grant admits AND stamps the session with the
// grant's edge as its deadline.
func TestAdmitGrantLifetime(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(2 * time.Hour)
	cases := []struct {
		name       string
		grant      store.TargetGrant
		wantKind   admitKind
		wantReason string // the deadline reason on admitOK; "" = no deadline
		wantAt     func() time.Time
	}{
		{"expired grant refuses", store.TargetGrant{SubjectType: "user", Subject: "alice", ExpiresAt: &past}, admitDenied, "", nil},
		{"out-of-frame grant refuses", store.TargetGrant{SubjectType: "user", Subject: "alice", TimeFrame: neverFrame()}, admitDenied, "", nil},
		{"live expiring grant admits with the expiry as deadline", store.TargetGrant{SubjectType: "user", Subject: "alice", ExpiresAt: &future}, admitOK, "grant-expiry", func() time.Time { return future }},
		{"in-frame grant admits with the window's end as deadline", store.TargetGrant{SubjectType: "user", Subject: "alice", TimeFrame: todayFrame()}, admitOK, "time-frame", func() time.Time {
			y, m, d := time.Now().UTC().Date()
			return time.Date(y, m, d+1, 0, 0, 0, 0, time.UTC)
		}},
		{"unbounded grant admits with no deadline", store.TargetGrant{SubjectType: "user", Subject: "alice"}, admitOK, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t)
			g := tc.grant
			g.TargetID = env.target.ID
			if err := env.st.CreateTargetGrant(context.Background(), &g); err != nil {
				t.Fatal(err)
			}
			p := gatesUser("alice")
			res := env.g.admit(context.Background(), baseReq(p))
			if res.outcome != tc.wantKind {
				t.Fatalf("outcome = %d (gate %d), want %d", res.outcome, res.gate, tc.wantKind)
			}
			if tc.wantKind == admitDenied && res.gate != gateTargetPolicy {
				t.Fatalf("gate = %d, want gateTargetPolicy", res.gate)
			}
			if tc.wantKind != admitOK {
				return
			}
			if tc.wantReason == "" {
				if res.bounds.deadline != nil {
					t.Fatalf("unexpected deadline %v", res.bounds)
				}
				return
			}
			if res.bounds.deadline == nil || res.bounds.reason != tc.wantReason || !res.bounds.deadline.Equal(tc.wantAt()) {
				t.Fatalf("bounds = %+v (%v), want %s at %s", res.bounds, res.bounds.deadline, tc.wantReason, tc.wantAt())
			}
		})
	}
	// An admin needs no grant, so no grant's edge is their deadline.
	env := newTestEnv(t)
	if err := env.st.CreateTargetGrant(context.Background(), &store.TargetGrant{TargetID: env.target.ID, SubjectType: "role", Subject: "admin", ExpiresAt: &future}); err != nil {
		t.Fatal(err)
	}
	res := env.g.admit(context.Background(), baseReq(&auth.Principal{Name: "root", Role: auth.RoleAdmin}))
	if res.outcome != admitOK || res.bounds.deadline != nil {
		t.Fatalf("admin: outcome %d bounds %+v", res.outcome, res.bounds)
	}
}
