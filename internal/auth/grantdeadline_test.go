package auth

import (
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

func TestGrantDeadline(t *testing.T) {
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC) // a Monday, 10:00 UTC
	exp := now.Add(2 * time.Hour)
	soon := now.Add(30 * time.Minute)
	alice := &Principal{Name: "alice", Role: RoleUser}
	admin := &Principal{Name: "root", Role: RoleAdmin}
	frame := "Mon-Fri 08:00-18:00"
	cases := []struct {
		name   string
		p      *Principal
		grants []store.TargetGrant
		want   time.Time
		reason string
		ok     bool
	}{
		{"no matching grant", alice, []store.TargetGrant{{SubjectType: "user", Subject: "bob", ExpiresAt: &exp}}, time.Time{}, "", false},
		{"unbounded grant", alice, []store.TargetGrant{{SubjectType: "user", Subject: "alice"}}, time.Time{}, "", false},
		{"expiry only", alice, []store.TargetGrant{{SubjectType: "user", Subject: "alice", ExpiresAt: &exp}}, exp, "grant-expiry", true},
		{"frame only ends at 18:00", alice, []store.TargetGrant{{SubjectType: "user", Subject: "alice", TimeFrame: frame}}, now.Add(8 * time.Hour), "time-frame", true},
		{"sooner of expiry and frame", alice, []store.TargetGrant{{SubjectType: "user", Subject: "alice", ExpiresAt: &soon, TimeFrame: frame}}, soon, "grant-expiry", true},
		{"latest across two matching grants", alice, []store.TargetGrant{{SubjectType: "user", Subject: "alice", ExpiresAt: &soon}, {SubjectType: "role", Subject: "user", ExpiresAt: &exp}}, exp, "grant-expiry", true},
		{"one unbounded match wins", alice, []store.TargetGrant{{SubjectType: "user", Subject: "alice", ExpiresAt: &soon}, {SubjectType: "role", Subject: "user"}}, time.Time{}, "", false},
		{"admin needs no grant", admin, []store.TargetGrant{{SubjectType: "role", Subject: "admin", ExpiresAt: &exp}}, time.Time{}, "", false},
	}
	for _, c := range cases {
		got, reason, ok := GrantDeadline(c.p, c.grants, false, now)
		if ok != c.ok || reason != c.reason || (ok && !got.Equal(c.want)) {
			t.Errorf("%s: got (%s, %q, %v), want (%s, %q, %v)", c.name, got, reason, ok, c.want, c.reason, c.ok)
		}
	}
	// In a personal safe an admin is bound like anyone else unless they hold
	// the unlimited capability.
	if _, _, ok := GrantDeadline(admin, []store.TargetGrant{{SubjectType: "user", Subject: "root", ExpiresAt: &exp}}, true, now); !ok {
		t.Fatal("an admin inside a personal safe is bound by their grant")
	}
}
