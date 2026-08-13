package api_test

import (
	"fmt"
	"net/http"
	"testing"
)

// TestCreateAccessRequestRecurDaysValidation proves recur_days is bounded the
// same way a campaign's is (Phase 120): negative or beyond a year is refused
// at request time, not silently clamped.
func TestCreateAccessRequestRecurDaysValidation(t *testing.T) {
	srv := newTestServer(t)
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey,
		map[string]any{"name": "recur-tgt", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh"})
	targetID := int64(jsonMap(t, data)["id"].(float64))

	if code, d := do(t, srv, http.MethodPost, "/api/access-requests", testAPIKey,
		map[string]any{"target_id": targetID, "reason": "x", "recur_days": -1}); code != http.StatusUnprocessableEntity {
		t.Fatalf("negative recur_days: %d %s, want 422", code, d)
	}
	if code, d := do(t, srv, http.MethodPost, "/api/access-requests", testAPIKey,
		map[string]any{"target_id": targetID, "reason": "x", "recur_days": 367}); code != http.StatusUnprocessableEntity {
		t.Fatalf("recur_days > 366: %d %s, want 422", code, d)
	}
	code, data := do(t, srv, http.MethodPost, "/api/access-requests", testAPIKey,
		map[string]any{"target_id": targetID, "reason": "weekly window", "recur_days": 7})
	if code != http.StatusCreated {
		t.Fatalf("valid recur_days: %d %s", code, data)
	}
	if got := jsonMap(t, data)["recur_days"]; got != float64(7) {
		t.Fatalf("recur_days in response = %v, want 7", got)
	}
	if _, has := jsonMap(t, data)["next_run_at"]; has {
		t.Fatalf("a still-pending anchor must not have next_run_at set yet: %s", data)
	}
}

// TestApproveRecurringAccessRequestSetsNextRun proves the recurring anchor's
// clock starts on APPROVAL, not on the original request (Phase 120): a
// pending recurring request carries no next_run_at, and approving it sets one
// RecurDays out from the moment of approval.
func TestApproveRecurringAccessRequestSetsNextRun(t *testing.T) {
	srv := newTestServer(t)
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey,
		map[string]any{"name": "recur-tgt2", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh"})
	targetID := int64(jsonMap(t, data)["id"].(float64))
	approver := seedUser(t, srv, "approver1", "approver")

	code, data := do(t, srv, http.MethodPost, "/api/access-requests", testAPIKey,
		map[string]any{"target_id": targetID, "reason": "weekly window", "recur_days": 7})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, data)
	}
	reqID := int64(jsonMap(t, data)["id"].(float64))

	code, data = do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", reqID), approver, nil)
	if code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, data)
	}
	m := jsonMap(t, data)
	if m["status"] != "approved" {
		t.Fatalf("status after approve = %v, want approved", m["status"])
	}
	if _, has := m["next_run_at"]; !has {
		t.Fatalf("approving a recurring anchor must set next_run_at: %s", data)
	}
}

// TestStopAccessRequestRecurrence proves the anchor's stop button: it clears
// the recurrence, is idempotent, 404s on a missing request, and is gated the
// same as an approve/deny decision (Phase 120).
func TestStopAccessRequestRecurrence(t *testing.T) {
	srv := newTestServer(t)
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey,
		map[string]any{"name": "recur-tgt3", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh"})
	targetID := int64(jsonMap(t, data)["id"].(float64))
	approver := seedUser(t, srv, "approver2", "approver")
	plainUser := seedUser(t, srv, "plainuser", "user")

	code, data := do(t, srv, http.MethodPost, "/api/access-requests", testAPIKey,
		map[string]any{"target_id": targetID, "reason": "weekly window", "recur_days": 7})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, data)
	}
	reqID := int64(jsonMap(t, data)["id"].(float64))
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", reqID), approver, nil); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, d)
	}

	// A plain `user` (no CapApprove) may not stop a recurrence.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/stop-recurrence", reqID), plainUser, nil); code != http.StatusForbidden {
		t.Fatalf("stop by non-approver: %d %s, want 403", code, d)
	}

	code, data = do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/stop-recurrence", reqID), approver, nil)
	if code != http.StatusOK {
		t.Fatalf("stop-recurrence: %d %s", code, data)
	}
	m := jsonMap(t, data)
	if got := m["recur_days"]; got != nil && got != float64(0) {
		t.Fatalf("recur_days after stop = %v, want 0/absent", got)
	}
	if _, has := m["next_run_at"]; has {
		t.Fatalf("next_run_at should be cleared after stop: %s", data)
	}

	// Idempotent: calling it again still succeeds.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/stop-recurrence", reqID), approver, nil); code != http.StatusOK {
		t.Fatalf("stop-recurrence (already stopped): %d %s, want 200", code, d)
	}

	// A missing request 404s.
	if code, d := do(t, srv, http.MethodPost, "/api/access-requests/999999/stop-recurrence", approver, nil); code != http.StatusNotFound {
		t.Fatalf("stop-recurrence(missing): %d %s, want 404", code, d)
	}
}
