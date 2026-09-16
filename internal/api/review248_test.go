package api_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestRotateUserTokenEscalationGuard proves POST /api/users/{id}/token carries
// the same privilege-escalation guard as creating or updating a user (Phase
// 248). Rotation hands the caller a working token for the target identity, so
// without the guard a delegated user-admin — a custom profile holding
// manage_users but nothing else — could mint itself an administrator's token
// and present it as its own key. The delegate keeps the rotations that are
// within its own capabilities.
func TestRotateUserTokenEscalationGuard(t *testing.T) {
	srv, _ := newTestServerStore(t)
	// The delegate covers the plain `user` role (read_inventory + connect) and
	// nothing more, so the guard's two sides are both exercised below.
	if code, d := do(t, srv, http.MethodPost, "/api/profiles", testAPIKey, map[string]any{
		"name": "useradmin", "capabilities": []string{"manage_users", "read_inventory", "connect"},
	}); code != http.StatusCreated {
		t.Fatalf("create profile: %d %s", code, d)
	}
	delegateTok := seedUser(t, srv, "delegate", "useradmin")
	adminID, adminTok := seedUserWithID(t, srv, "root", "admin")
	plainID, _ := seedUserWithID(t, srv, "pat", "user")

	// The escalation itself: a delegate must not be handed an admin's token.
	code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/users/%d/token", adminID), delegateTok, nil)
	if code != http.StatusForbidden {
		t.Fatalf("delegate rotates an admin's token: want 403, got %d %s", code, d)
	}
	// ...and the refusal must not have cut the victim's access on the way out.
	if code, _ := do(t, srv, http.MethodGet, "/api/users", adminTok, nil); code != http.StatusOK {
		t.Fatalf("a refused rotation must leave the victim's token working, got %d", code)
	}
	// The guard is not a blanket refusal: a plain user is within the
	// delegate's own capabilities, so that rotation still works.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/users/%d/token", plainID), delegateTok, nil); code != http.StatusOK {
		t.Fatalf("delegate rotates a plain user's token: want 200, got %d %s", code, d)
	}
	// A built-in admin is unconstrained.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/users/%d/token", adminID), testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("admin rotates an admin's token: want 200, got %d %s", code, d)
	}
}

// TestSafeManagementHonoursMembershipLifetime proves the delegated-management
// decision reads a membership's bounds the way every access decision does
// (Phase 248). Phase 240 put an expiry and a time frame on a safe membership
// and Phase 246 made can_manage independent of what a membership confers, but
// canManageSafe read neither: an expired or out-of-window can_manage row kept
// managing the member list, which is the one right that can rewrite itself.
func TestSafeManagementHonoursMembershipLifetime(t *testing.T) {
	srv, st := newTestServerStore(t)
	code, d := do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{"name": "prod-db"})
	if code != http.StatusCreated {
		t.Fatalf("create safe: %d %s", code, d)
	}
	safeID := int64(jsonMap(t, d)["id"].(float64))
	bobTok := seedUser(t, srv, "bob", "user")

	// An expired can_manage membership: the row is still there (the sweeper
	// runs once a minute), but it must no longer manage.
	carol := store.SafeMember{SafeID: safeID, SubjectType: "user", Subject: "carol", Permissions: []string{"use"}}
	if err := st.AddSafeMember(t.Context(), &carol); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	expired := store.SafeMember{SafeID: safeID, SubjectType: "user", Subject: "bob", CanManage: true,
		Permissions: []string{"use"}, ExpiresAt: &past}
	if err := st.AddSafeMember(t.Context(), &expired); err != nil {
		t.Fatal(err)
	}
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeID), bobTok, map[string]any{
		"subject_type": "user", "subject": "dave", "can_manage": true,
		"permissions": []string{"use", "retrieve", "approve"},
	}); code != http.StatusForbidden {
		t.Fatalf("expired can_manage row still manages: want 403, got %d %s", code, d)
	}
	if code, d := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/safes/%d/members/%d", safeID, carol.ID), bobTok, nil); code != http.StatusForbidden {
		t.Fatalf("expired can_manage row still removes members: want 403, got %d %s", code, d)
	}

	// Same for a membership outside its time frame. Sunday 03:00 is outside
	// "Mon-Fri 08:00-18:00", whatever day the suite runs on.
	if err := st.DeleteSafeMember(t.Context(), expired.ID); err != nil {
		t.Fatal(err)
	}
	framed := store.SafeMember{SafeID: safeID, SubjectType: "user", Subject: "bob", CanManage: true,
		Permissions: []string{"use"}, TimeFrame: outOfHoursFrame(time.Now())}
	if err := st.AddSafeMember(t.Context(), &framed); err != nil {
		t.Fatal(err)
	}
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeID), bobTok, map[string]any{
		"subject_type": "user", "subject": "dave", "can_manage": true,
	}); code != http.StatusForbidden {
		t.Fatalf("out-of-frame can_manage row still manages: want 403, got %d %s", code, d)
	}
	if code, d := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/safes/%d/members/%d", safeID, carol.ID), bobTok, nil); code != http.StatusForbidden {
		t.Fatalf("out-of-frame can_manage row still removes members: want 403, got %d %s", code, d)
	}

	// A live membership still manages, so the filter has not closed the door.
	if err := st.DeleteSafeMember(t.Context(), framed.ID); err != nil {
		t.Fatal(err)
	}
	live := store.SafeMember{SafeID: safeID, SubjectType: "user", Subject: "bob", CanManage: true, Permissions: []string{"use"}}
	if err := st.AddSafeMember(t.Context(), &live); err != nil {
		t.Fatal(err)
	}
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeID), bobTok, map[string]any{
		"subject_type": "user", "subject": "dave", "permissions": []string{"use"},
	}); code != http.StatusCreated {
		t.Fatalf("live can_manage row must still manage: %d %s", code, d)
	}
}

// TestSafeManagerCannotGrantBeyondItsOwn proves a delegated safe manager
// cannot hand out a permission it does not itself hold (Phase 248) — the same
// "you cannot grant more than you have" rule createUser and updateUser apply
// to capabilities. Without it, Phase 246's use-only / retrieve-only split was
// advisory for anyone who also managed the safe: they could simply add
// themselves a second membership carrying retrieve, and read every secret in
// it.
func TestSafeManagerCannotGrantBeyondItsOwn(t *testing.T) {
	srv, st := newTestServerStore(t)
	code, d := do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{"name": "prod-db"})
	if code != http.StatusCreated {
		t.Fatalf("create safe: %d %s", code, d)
	}
	safeID := int64(jsonMap(t, d)["id"].(float64))
	bobTok := seedUser(t, srv, "bob", "user")
	m := store.SafeMember{SafeID: safeID, SubjectType: "user", Subject: "bob", CanManage: true, Permissions: []string{"use"}}
	if err := st.AddSafeMember(t.Context(), &m); err != nil {
		t.Fatal(err)
	}

	// Self-escalation, by way of a ROLE membership — bob holds the user role,
	// so a role:user row carrying retrieve confers it on bob himself.
	for _, perm := range []string{"retrieve", "approve"} {
		if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeID), bobTok, map[string]any{
			"subject_type": "role", "subject": "user", "permissions": []string{"use", perm},
		}); code != http.StatusForbidden {
			t.Fatalf("manager grants role:user %q, which covers itself: want 403, got %d %s", perm, code, d)
		}
	}
	// ...and handing it to somebody else is the same escalation one hop out.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeID), bobTok, map[string]any{
		"subject_type": "user", "subject": "carol", "permissions": []string{"retrieve"},
	}); code != http.StatusForbidden {
		t.Fatalf("manager grants retrieve to another: want 403, got %d %s", code, d)
	}
	// What it does hold, it may delegate — including the management right.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeID), bobTok, map[string]any{
		"subject_type": "user", "subject": "carol", "permissions": []string{"use"}, "can_manage": true,
	}); code != http.StatusCreated {
		t.Fatalf("manager delegates what it holds: %d %s", code, d)
	}
	// A global target manager is unconstrained, as an admin is in Covers.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeID), testAPIKey, map[string]any{
		"subject_type": "user", "subject": "dave", "permissions": []string{"use", "retrieve", "approve"},
	}); code != http.StatusCreated {
		t.Fatalf("admin grants the full set: %d %s", code, d)
	}
}

// outOfHoursFrame returns a weekly window that never contains now, so the test
// does not depend on the day it runs: a one-hour window on the weekday before
// yesterday, at an hour far from the current one.
func outOfHoursFrame(now time.Time) string {
	day := now.Add(-48 * time.Hour).Format("Mon")
	hour := (now.Hour() + 12) % 24
	return fmt.Sprintf("%s %02d:00-%02d:30", day, hour, hour)
}

// TestExtensionRevealUnderSessionMFA proves a browser-extension reveal on a
// target that requires a second factor per session is refused with something
// the caller can act on (Phase 248). Phase 244 stated the limit — an
// extension-scoped token reaches exactly one route, so it can never mint a
// ticket — but the refusal still told it to POST /api/session-mfa, a route
// that refuses that very token. The instruction is now the true one.
func TestExtensionRevealUnderSessionMFA(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{ExtensionTokenTTL: time.Hour})
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "mfa-host", "host": "10.9.9.9", "port": 22, "os_type": "linux", "protocol": "ssh", "require_session_mfa": true,
	})
	tm := jsonMap(t, td)
	if tm["id"] == nil {
		t.Fatalf("create target: %s", td)
	}
	tid := int64(tm["id"].(float64))
	ccode, cd := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "root", "secret": "s3cr3t-pw",
	})
	cm := jsonMap(t, cd)
	if cm["id"] == nil {
		t.Fatalf("create credential: %d %s", ccode, cd)
	}
	cid := int64(cm["id"].(float64))
	_, data := do(t, srv, http.MethodPost, "/api/extension-token", testAPIKey, nil)
	extTok, _ := jsonMap(t, data)["token"].(string)
	if extTok == "" {
		t.Fatal("expected an extension token")
	}

	code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reveal", cid), extTok, nil)
	if code != http.StatusForbidden {
		t.Fatalf("extension reveal on an MFA target: want 403, got %d %s", code, data)
	}
	m := jsonMap(t, data)
	if m["reason"] != "session-mfa-extension-unsupported" {
		t.Errorf("reason = %v, want session-mfa-extension-unsupported", m["reason"])
	}
	if msg, _ := m["error"].(string); strings.Contains(msg, "/api/session-mfa") {
		t.Errorf("the refusal must not send an extension token to a route that refuses it: %q", msg)
	}
}
