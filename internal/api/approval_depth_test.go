package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

type alertCollector struct {
	mu     sync.Mutex
	events []alert.Event
}

func (a *alertCollector) Notify(_ context.Context, e alert.Event) {
	a.mu.Lock()
	a.events = append(a.events, e)
	a.mu.Unlock()
}
func (a *alertCollector) has(kind string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if e.Type == kind {
			return true
		}
	}
	return false
}

// TestApprovalDepth (Phase 274): an approver's comment is noted on the
// request and audited; a granted duration shortens the window but never
// extends it; a cancel ends an approved request, cuts the requester's live
// sessions on that target, needs a reason and four eyes; a pending request
// cannot be cancelled; the timeout sweep expires stale pending requests.
func TestApprovalDepth(t *testing.T) {
	sink := &alertCollector{}
	reg := session.NewRegistry()
	srv, st := newTestServerOpts(t, nil, api.Options{Alerter: sink, Sessions: reg, ApprovalTimeout: 10 * time.Minute})
	targetID := seedApprovalTarget(t, srv, true)
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")
	carol := seedUser(t, srv, "carol", "approver")

	file := func() store.AccessRequest {
		t.Helper()
		status, body := do(t, srv, http.MethodPost, "/api/access-requests", alice, map[string]any{"target_id": targetID, "reason": "maintenance"})
		if status != http.StatusCreated {
			t.Fatalf("file: %d %s", status, body)
		}
		var ar store.AccessRequest
		_ = json.Unmarshal(body, &ar)
		return ar
	}

	// Approve with a comment and a shorter duration than the 60-minute window.
	ar := file()
	status, body := do(t, srv, http.MethodPost, "/api/access-requests/"+itoa64(ar.ID)+"/approve", bob, map[string]any{"comment": "ticket verified", "duration_min": 15})
	if status != http.StatusOK {
		t.Fatalf("approve: %d %s", status, body)
	}
	got, _ := st.GetAccessRequest(t.Context(), ar.ID)
	if got.Status != "approved" || !strings.Contains(got.Notes, "bob: approved: ticket verified") {
		t.Fatalf("after approve: %+v", got)
	}
	if until := time.Until(got.ExpiresAt); until > 16*time.Minute || until < 13*time.Minute {
		t.Fatalf("granted duration not applied: expires in %v", until)
	}
	// A duration longer than the request cannot extend it.
	ar2 := file()
	if s, b := do(t, srv, http.MethodPost, "/api/access-requests/"+itoa64(ar2.ID)+"/approve", bob, map[string]any{"duration_min": 600}); s != http.StatusOK {
		t.Fatalf("approve long: %d %s", s, b)
	}
	got2, _ := st.GetAccessRequest(t.Context(), ar2.ID)
	if until := time.Until(got2.ExpiresAt); until > 61*time.Minute || until < 58*time.Minute {
		t.Fatalf("a longer duration must not extend the window: expires in %v", until)
	}
	// The old no-body call still works.
	ar3 := file()
	if s, b := do(t, srv, http.MethodPost, "/api/access-requests/"+itoa64(ar3.ID)+"/deny", bob, nil); s != http.StatusOK {
		t.Fatalf("deny without body: %d %s", s, b)
	}
	if s, _ := do(t, srv, http.MethodPost, "/api/access-requests/"+itoa64(file().ID)+"/approve", bob, map[string]any{"duration_min": -5}); s != http.StatusUnprocessableEntity {
		t.Fatalf("negative duration: %d", s)
	}

	// Cancel: four eyes, reason required, only an approved request; the
	// requester's live session on the target is cut.
	targetName := ""
	if tg, err := st.GetTarget(t.Context(), targetID); err == nil {
		targetName = tg.Name
	}
	killed := make(chan struct{}, 1)
	reg.Register(session.Info{Actor: "alice", Target: targetName, Protocol: "ssh", Started: time.Now()}, func() { killed <- struct{}{} })
	if s, _ := do(t, srv, http.MethodPost, "/api/access-requests/"+itoa64(ar.ID)+"/cancel", alice, map[string]any{"comment": "done"}); s != http.StatusForbidden {
		t.Fatalf("requester cancelling own approval: %d", s)
	}
	if s, _ := do(t, srv, http.MethodPost, "/api/access-requests/"+itoa64(ar.ID)+"/cancel", carol, map[string]any{}); s != http.StatusUnprocessableEntity {
		t.Fatalf("cancel without a reason: %d", s)
	}
	pending := file()
	if s, _ := do(t, srv, http.MethodPost, "/api/access-requests/"+itoa64(pending.ID)+"/cancel", carol, map[string]any{"comment": "x"}); s != http.StatusConflict {
		t.Fatalf("cancel a pending request: %d", s)
	}
	status, body = do(t, srv, http.MethodPost, "/api/access-requests/"+itoa64(ar.ID)+"/cancel", carol, map[string]any{"comment": "incident over"})
	if status != http.StatusOK {
		t.Fatalf("cancel: %d %s", status, body)
	}
	select {
	case <-killed:
	case <-time.After(3 * time.Second):
		t.Fatal("the requester's session was not cut")
	}
	got, _ = st.GetAccessRequest(t.Context(), ar.ID)
	if got.Status != "cancelled" || !strings.Contains(got.Notes, "carol: cancelled: incident over") {
		t.Fatalf("after cancel: %+v", got)
	}
	if !sink.has("access.cancel") {
		t.Fatalf("no access.cancel alert: %+v", sink.events)
	}

	// Timeout sweep: the still-pending request, once older than the timeout,
	// expires; audited and alerted.
	// Run the sweep "eleven minutes from now": the pending request is then
	// older than the ten-minute timeout, the approved/denied ones are not
	// pending and stay as they are.
	sweeper := srv.Config.Handler.(interface {
		SweepApprovalTimeouts(context.Context, time.Time) int
	})
	// Two requests are still pending (this one and the negative-duration probe).
	if n := sweeper.SweepApprovalTimeouts(t.Context(), time.Now().Add(11*time.Minute)); n != 2 {
		t.Fatalf("sweep expired %d, want 2", n)
	}
	if n := sweeper.SweepApprovalTimeouts(t.Context(), time.Now().Add(11*time.Minute)); n != 0 {
		t.Fatalf("second sweep expired %d, want 0", n)
	}
	got, _ = st.GetAccessRequest(t.Context(), pending.ID)
	if got.Status != "expired" {
		t.Fatalf("after sweep: %+v", got)
	}
	if !sink.has("access.expired") {
		t.Fatal("no access.expired alert")
	}
	events, _ := st.ListAudit(t.Context(), 100)
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Action] = true
		if e.Action == "access.approve" && strings.Contains(e.Detail, "granted_until:") && strings.Contains(e.Detail, `comment:"ticket verified"`) {
			seen["approve-detail"] = true
		}
		if e.Action == "access.cancel" && strings.Contains(e.Detail, "sessions_killed:1") && strings.Contains(e.Detail, `comment:"incident over"`) {
			seen["cancel-detail"] = true
		}
	}
	for _, w := range []string{"approve-detail", "cancel-detail", "access.expired"} {
		if !seen[w] {
			t.Fatalf("missing audit %s in %v", w, seen)
		}
	}
}

// TestApprovalCommentRequired: with PAM_APPROVAL_COMMENT_REQUIRED a decision
// without a comment is refused.
func TestApprovalCommentRequired(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{ApprovalCommentRequired: true})
	targetID := seedApprovalTarget(t, srv, true)
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")
	status, body := do(t, srv, http.MethodPost, "/api/access-requests", alice, map[string]any{"target_id": targetID, "reason": "r"})
	if status != http.StatusCreated {
		t.Fatalf("file: %d %s", status, body)
	}
	var ar store.AccessRequest
	_ = json.Unmarshal(body, &ar)
	if s, _ := do(t, srv, http.MethodPost, "/api/access-requests/"+itoa64(ar.ID)+"/approve", bob, nil); s != http.StatusUnprocessableEntity {
		t.Fatalf("approve without comment: %d", s)
	}
	if s, _ := do(t, srv, http.MethodPost, "/api/access-requests/"+itoa64(ar.ID)+"/approve", bob, map[string]any{"comment": "ok"}); s != http.StatusOK {
		t.Fatalf("approve with comment: %d", s)
	}
}
