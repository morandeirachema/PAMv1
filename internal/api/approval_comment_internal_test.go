package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestCommentRequiredOnEveryDecisionPath (review of 274-280): the Slack and
// magic-link paths decide with no body, so they reach decideAccessRequest
// without readDecision's check. With PAM_APPROVAL_COMMENT_REQUIRED they are
// refused there, audited, and the request is left pending.
func TestCommentRequiredOnEveryDecisionPath(t *testing.T) {
	srv, st, _, _ := newAnalyticsServer(t, false)
	srv.approvalCommentRequired = true
	tgt := &store.Target{Name: "t", Host: "h", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(t.Context(), tgt); err != nil {
		t.Fatal(err)
	}
	ar := &store.AccessRequest{Requester: "alice", TargetID: tgt.ID, Reason: "r", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}
	if err := st.CreateAccessRequest(t.Context(), ar); err != nil {
		t.Fatal(err)
	}
	for _, decision := range []string{"approved", "denied"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/slack/interactivity", nil)
		if srv.decideAccessRequest(rec, req, ar.ID, decision, "bob") || rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("%s without a comment: %d %s", decision, rec.Code, rec.Body)
		}
	}
	got, err := st.GetAccessRequest(t.Context(), ar.ID)
	if err != nil || got.Status != "pending" {
		t.Fatalf("request after refused decisions: %+v %v", got, err)
	}
	if n := auditActionCount(t, st, "access.decision_denied"); n != 2 {
		t.Fatalf("refusals audited %d times, want 2", n)
	}
}

func auditActionCount(t *testing.T, st store.Store, action string) int {
	t.Helper()
	events, err := st.ListAudit(t.Context(), 200)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Action == action {
			n++
		}
	}
	return n
}
