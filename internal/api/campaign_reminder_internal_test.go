package api

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/store"
)

// quotedSpan matches one Go-quoted string, so a test can strip the spans a
// quoting-aware reader would never parse fields out of.
var quotedSpan = regexp.MustCompile(`"(\\.|[^"\\])*"`)

// captureAlerts records what the reminder actually sent.
type captureAlerts struct{ events []alert.Event }

func (c *captureAlerts) Notify(_ context.Context, e alert.Event) { c.events = append(c.events, e) }

// TestCampaignRemindersNudgeAndStop proves the reminder loop: a due campaign with
// pending items nudges, names who is holding it up, reschedules itself, and STOPS
// on the two conditions that mean the work is over.
//
// The stop conditions are the point. A reminder that keeps firing after the work
// is done gets the channel muted, and a muted channel is exactly where the next
// lapse hides — so "finished but not closed" cancels rather than repeats.
func TestCampaignRemindersNudgeAndStop(t *testing.T) {
	srv, st := newRetentionServer(t, t.TempDir())
	alerts := &captureAlerts{}
	srv.alerter = alerts
	ctx := context.Background()

	now := time.Now().UTC()
	past := now.Add(-time.Minute)
	overdue := now.Add(-72 * time.Hour)
	c := &store.Campaign{Name: "Q3 review", CreatedBy: "alice", Status: "open",
		DueAt: &overdue, RemindAt: &past, Reviewer: "carol"}
	if err := st.CreateCampaign(ctx, c); err != nil {
		t.Fatal(err)
	}
	add := func(reviewer string) *store.CampaignItem {
		it := &store.CampaignItem{CampaignID: c.ID, Kind: "target_grant", RefID: 1,
			SubjectType: "user", Subject: "u", Detail: "d", Reviewer: reviewer}
		if err := st.AddCampaignItem(ctx, it); err != nil {
			t.Fatal(err)
		}
		return it
	}
	first, second := add("carol"), add("dave")

	if n := srv.sendCampaignReminders(ctx, now); n != 1 {
		t.Fatalf("sent %d reminders, want 1", n)
	}
	if len(alerts.events) != 1 {
		t.Fatalf("alerts = %+v, want 1", alerts.events)
	}
	d := alerts.events[0].Detail
	// It has to say what is pending, that it is overdue, and WHO is holding it up
	// — a nudge nobody can act on is noise.
	for _, want := range []string{"pending:2", "due:overdue_by_3d", `"carol"(1)`, `"dave"(1)`} {
		if !strings.Contains(d, want) {
			t.Fatalf("reminder detail %q is missing %q", d, want)
		}
	}
	// It rescheduled itself rather than firing again on the next tick.
	if n := srv.sendCampaignReminders(ctx, now); n != 0 {
		t.Fatalf("reminder fired twice in one window (%d)", n)
	}
	got, _ := st.GetCampaign(ctx, c.ID)
	if got.RemindAt == nil || !got.RemindAt.After(now) {
		t.Fatalf("reminder was not rescheduled: %+v", got.RemindAt)
	}
	// A day later it nudges again — an overdue review should keep being visible.
	if n := srv.sendCampaignReminders(ctx, now.Add(25*time.Hour)); n != 1 {
		t.Fatalf("want a second nudge a day later, got %d", n)
	}

	// STOP 1: nothing pending. Deciding every item ends the reminders even though
	// nobody closed the campaign.
	for _, it := range []*store.CampaignItem{first, second} {
		if err := st.DecideCampaignItem(ctx, it.ID, "certified", "dave", now); err != nil {
			t.Fatal(err)
		}
	}
	before := len(alerts.events)
	if n := srv.sendCampaignReminders(ctx, now.Add(50*time.Hour)); n != 0 {
		t.Fatalf("reminded about a campaign with nothing pending (%d)", n)
	}
	if len(alerts.events) != before {
		t.Fatal("an alert was sent for a campaign with nothing pending")
	}
	if got, _ := st.GetCampaign(ctx, c.ID); got.RemindAt != nil {
		t.Fatalf("a finished campaign must have its reminder cancelled, got %v", got.RemindAt)
	}

	// STOP 2: a closed campaign never reminds, whatever its schedule says.
	c2 := &store.Campaign{Name: "closed", CreatedBy: "alice", Status: "open", DueAt: &overdue, RemindAt: &past}
	if err := st.CreateCampaign(ctx, c2); err != nil {
		t.Fatal(err)
	}
	if err := st.AddCampaignItem(ctx, &store.CampaignItem{CampaignID: c2.ID, Kind: "target_grant",
		RefID: 2, SubjectType: "user", Subject: "u", Detail: "d"}); err != nil {
		t.Fatal(err)
	}
	if err := st.CloseCampaign(ctx, c2.ID, now); err != nil {
		t.Fatal(err)
	}
	if n := srv.sendCampaignReminders(ctx, now.Add(60*time.Hour)); n != 0 {
		t.Fatalf("a CLOSED campaign reminded (%d) — the review is over", n)
	}
}

// TestFirstReminderWindow pins when the first nudge is scheduled, including the
// case that would otherwise be silently skipped.
func TestFirstReminderWindow(t *testing.T) {
	srv, _ := newRetentionServer(t, t.TempDir())
	srv.certRemindDays = 7
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

	// Comfortably ahead: seven days before the due date.
	due := now.AddDate(0, 0, 30)
	if got := srv.firstReminder(&due, now); got == nil || !got.Equal(due.AddDate(0, 0, -7)) {
		t.Fatalf("first reminder = %v, want %v", got, due.AddDate(0, 0, -7))
	}
	// Already inside the window — or past it — reminds NOW rather than never.
	// "You gave me two days" is when a nudge is worth most.
	soon := now.AddDate(0, 0, 2)
	if got := srv.firstReminder(&soon, now); got == nil || !got.Equal(now) {
		t.Fatalf("a due date inside the window must remind immediately, got %v", got)
	}
	gone := now.AddDate(0, 0, -5)
	if got := srv.firstReminder(&gone, now); got == nil || !got.Equal(now) {
		t.Fatalf("an already-overdue campaign must remind immediately, got %v", got)
	}
	// No due date: nothing to be early for.
	if got := srv.firstReminder(nil, now); got != nil {
		t.Fatalf("no due date must schedule no reminder, got %v", got)
	}
	// Reminders switched off.
	srv.certRemindDays = 0
	if got := srv.firstReminder(&due, now); got != nil {
		t.Fatalf("PAM_CERT_REMIND_DAYS=0 must disable reminders, got %v", got)
	}
}

// TestCampaignReminderResistsAuditInjection pins the sanitisation of the one
// field in a reminder that an operator chooses the text of.
//
// A reviewer name is only trimmed on the way in, so it may hold spaces, colons
// and newlines — and it is interpolated into a detail that both the audit trail
// and the alert channel parse as `key:value` pairs. Before this was fixed a
// reviewer called `carol pending:0 due:in_999d reviewers:nobody` produced
//
//	campaign:1 name:"q3" pending:1 due:overdue_by_2d reviewers:carol pending:0 due:in_999d reviewers:nobody(1)
//
// where the forged pairs land AFTER the real ones, so a last-wins parser reads
// an overdue campaign as having nothing pending: a reminder stating the opposite
// of the truth, delivered over the channel people trust to tell them otherwise.
func TestCampaignReminderResistsAuditInjection(t *testing.T) {
	srv, st := newRetentionServer(t, t.TempDir())
	alerts := &captureAlerts{}
	srv.alerter = alerts
	ctx := context.Background()
	now := time.Now().UTC()
	past, overdue := now.Add(-time.Minute), now.Add(-48*time.Hour)
	c := &store.Campaign{Name: "q3", CreatedBy: "alice", Status: "open", DueAt: &overdue, RemindAt: &past}
	if err := st.CreateCampaign(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := st.AddCampaignItem(ctx, &store.CampaignItem{CampaignID: c.ID, Kind: "target_grant",
		RefID: 1, SubjectType: "user", Subject: "u", Detail: "d",
		Reviewer: "carol pending:0 due:in_999d reviewers:nobody"}); err != nil {
		t.Fatal(err)
	}
	if n := srv.sendCampaignReminders(ctx, now); n != 1 {
		t.Fatalf("sent %d reminders, want 1", n)
	}
	d := alerts.events[0].Detail
	// The truth must survive: one item is pending and the campaign is overdue.
	if !strings.Contains(d, "pending:1") || !strings.Contains(d, "due:overdue_by_2d") {
		t.Fatalf("reminder lost its real fields: %q", d)
	}
	// The forged pairs must not be readable AS FIELDS. Quoting is what stops them,
	// so the check is made the way a quoting-aware reader sees it: remove the
	// quoted spans — which is exactly what the console's detailFields does — and
	// nothing of the injected text may be left behind.
	outside := quotedSpan.ReplaceAllString(d, `""`)
	for _, forged := range []string{"pending:0", "due:in_999d", "reviewers:nobody"} {
		if strings.Contains(outside, forged) {
			t.Fatalf("a reviewer name forged the field %q into the reminder detail: %q", forged, d)
		}
	}
	// And it is genuinely the quoting doing the work, not the name being dropped:
	// the reviewer is still named, so the nudge still says who to chase.
	if !strings.Contains(d, `"carol pending:0`) {
		t.Fatalf("the reviewer name was not quoted: %q", d)
	}
}

// TestReminderNamesABoundedNumberOfReviewers keeps one campaign from writing an
// unbounded audit row and alert payload every day. A campaign with hundreds of
// assignees would otherwise name every one of them, and a reader only needs to
// know who to chase.
func TestReminderNamesABoundedNumberOfReviewers(t *testing.T) {
	byReviewer := map[string]int{}
	for i := range 40 {
		byReviewer[fmt.Sprintf("reviewer-%02d", i)] = 1
	}
	got := reviewerBreakdown(byReviewer)
	if n := strings.Count(got, "("); n > maxReminderReviewers {
		t.Fatalf("named %d reviewers, want at most %d: %q", n, maxReminderReviewers, got)
	}
	if !strings.Contains(got, "+32_more") {
		t.Fatalf("the elided reviewers were not counted: %q", got)
	}
}
