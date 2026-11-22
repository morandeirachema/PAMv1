package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
)

// seedPendingRequest creates an approval-gated target and files a pending
// access request as requester, returning (targetID, requestID).
func seedPendingRequest(t *testing.T, srv *httptest.Server, requester string) (int64, int64) {
	t.Helper()
	targetID := seedApprovalTarget(t, srv, true)
	status, data := do(t, srv, http.MethodPost, "/api/access-requests", requester, map[string]any{
		"target_id": targetID, "reason": "patch window",
	})
	if status != http.StatusCreated {
		t.Fatalf("file request: %d %s", status, data)
	}
	return targetID, int64(jsonMap(t, data)["id"].(float64))
}

// TestApprovalInviteLifecycle proves the whole Phase 137 magic-link flow end
// to end: creation requires CapApprove and a still-pending request; preview
// is safe and non-consuming; redeeming with the right decision decides the
// underlying access request through the exact same decideAccessRequest an
// authenticated approve uses; and the invite itself records the outcome.
func TestApprovalInviteLifecycle(t *testing.T) {
	smtpAddr, gotEmail := fakeSMTP(t)
	srv, _ := newTestServerOpts(t, nil, api.Options{
		ShareSMTPAddr: smtpAddr, ShareSMTPFrom: "pam@example.com", PortalURL: "https://pam.example.com",
		ApprovalInviteTTL: time.Hour,
	})
	alice := seedUser(t, srv, "alice", "user") // requester
	bob := seedUser(t, srv, "bob", "approver") // will mint the invite
	_, reqID := seedPendingRequest(t, srv, alice)

	// bob (a CapApprove holder, not the requester) creates an invite.
	status, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/invite", reqID), bob,
		map[string]any{"email": "carol@example.com"})
	if status != http.StatusCreated {
		t.Fatalf("create invite: %d %s", status, data)
	}

	// The email was actually sent, and carries a token-bearing link.
	var raw []byte
	select {
	case raw = <-gotEmail:
	default:
		t.Fatal("no invite email was sent")
	}
	token := extractApprovalToken(t, string(raw))

	// Preview (a safe GET) shows the request's details WITHOUT consuming.
	code, prev := do(t, srv, http.MethodGet, "/api/approval/preview/"+token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("preview: %d %s", code, prev)
	}
	p := jsonMap(t, prev)
	if p["requester"] != "alice" || p["reason"] != "patch window" {
		t.Fatalf("preview details wrong: %+v", p)
	}
	// A second preview still works — it must not have consumed the token.
	if code, d := do(t, srv, http.MethodGet, "/api/approval/preview/"+token, "", nil); code != http.StatusOK {
		t.Fatalf("second preview: %d %s, want 200 (preview must not consume)", code, d)
	}

	// Redeem with an invalid decision value is refused.
	if code, d := do(t, srv, http.MethodPost, "/api/approval/redeem/"+token, "", map[string]any{"decision": "maybe"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("redeem with bad decision: %d %s, want 422", code, d)
	}

	// Redeem with "approved" decides the underlying request.
	code, data = do(t, srv, http.MethodPost, "/api/approval/redeem/"+token, "", map[string]any{"decision": "approved"})
	if code != http.StatusOK {
		t.Fatalf("redeem approve: %d %s", code, data)
	}
	ar := jsonMap(t, data)
	if ar["status"] != "approved" || ar["approver"] != "magiclink:carol@example.com" {
		t.Fatalf("access request after redemption: %+v", ar)
	}

	// Single-use: redeeming again fails.
	if code, d := do(t, srv, http.MethodPost, "/api/approval/redeem/"+token, "", map[string]any{"decision": "approved"}); code == http.StatusOK {
		t.Fatalf("second redemption of the same token should fail, got 200: %s", d)
	}
	// And the dead token can no longer be previewed either.
	if code, d := do(t, srv, http.MethodGet, "/api/approval/preview/"+token, "", nil); code == http.StatusOK {
		t.Fatalf("preview of a consumed token should fail, got 200: %s", d)
	}

	// listApprovalInvites shows the recorded outcome.
	code, data = do(t, srv, http.MethodGet, fmt.Sprintf("/api/access-requests/%d/invites", reqID), bob, nil)
	if code != http.StatusOK {
		t.Fatalf("list invites: %d %s", code, data)
	}
	var invs []map[string]any
	if err := json.Unmarshal(data, &invs); err != nil || len(invs) != 1 {
		t.Fatalf("list invites: %v %s", err, data)
	}
	if invs[0]["decision"] != "approved" {
		t.Fatalf("invite decision not recorded: %+v", invs[0])
	}
}

// TestApprovalInviteCannotSelfApprove proves the two-layer defense: the
// REQUESTER cannot create an invite for their own request even addressed to
// an email they control, closing the path a synthetic-actor check alone
// would miss (see ApprovalInvite's doc comment).
func TestApprovalInviteCannotSelfApprove(t *testing.T) {
	smtpAddr, _ := fakeSMTP(t)
	srv, _ := newTestServerOpts(t, nil, api.Options{
		ShareSMTPAddr: smtpAddr, ShareSMTPFrom: "pam@example.com", PortalURL: "https://pam.example.com",
		ApprovalInviteTTL: time.Hour,
	})
	// alice holds BOTH connect and approve (a custom profile isn't needed
	// for this proof — the bootstrap admin key already holds every
	// capability, so use it as the requester to prove even an
	// admin-as-requester cannot self-delegate).
	_, reqID := seedPendingRequest(t, srv, testAPIKey)

	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/invite", reqID), testAPIKey,
		map[string]any{"email": "self@example.com"}); code != http.StatusForbidden {
		t.Fatalf("requester creating their own invite: %d %s, want 403", code, d)
	}
}

// TestApprovalInviteRequiresPendingRequest proves an invite cannot be
// minted for an already-decided request.
func TestApprovalInviteRequiresPendingRequest(t *testing.T) {
	smtpAddr, _ := fakeSMTP(t)
	srv, _ := newTestServerOpts(t, nil, api.Options{
		ShareSMTPAddr: smtpAddr, ShareSMTPFrom: "pam@example.com", PortalURL: "https://pam.example.com",
		ApprovalInviteTTL: time.Hour,
	})
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")
	_, reqID := seedPendingRequest(t, srv, alice)

	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/deny", reqID), bob, nil); code != http.StatusOK {
		t.Fatalf("deny: %d %s", code, d)
	}
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/invite", reqID), bob,
		map[string]any{"email": "carol@example.com"}); code != http.StatusConflict {
		t.Fatalf("invite for a decided request: %d %s, want 409", code, d)
	}
}

// TestApprovalInviteRevoke proves a revoked invite cannot be redeemed even
// though its token and TTL are otherwise still valid.
func TestApprovalInviteRevoke(t *testing.T) {
	smtpAddr, gotEmail := fakeSMTP(t)
	srv, _ := newTestServerOpts(t, nil, api.Options{
		ShareSMTPAddr: smtpAddr, ShareSMTPFrom: "pam@example.com", PortalURL: "https://pam.example.com",
		ApprovalInviteTTL: time.Hour,
	})
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")
	_, reqID := seedPendingRequest(t, srv, alice)

	_, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/invite", reqID), bob,
		map[string]any{"email": "carol@example.com"})
	invID := int64(jsonMap(t, data)["id"].(float64))
	token := extractApprovalToken(t, string(<-gotEmail))

	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/approval-invites/%d/revoke", invID), bob, nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, d)
	}
	if code, d := do(t, srv, http.MethodPost, "/api/approval/redeem/"+token, "", map[string]any{"decision": "approved"}); code == http.StatusOK {
		t.Fatalf("redeeming a revoked invite should fail, got 200: %s", d)
	}
}

// extractApprovalToken mirrors extractShareToken (sessionshare_test.go)
// exactly, for the approve.html link shape.
func extractApprovalToken(t *testing.T, emailBody string) string {
	t.Helper()
	const marker = "approve.html?token="
	i := strings.Index(emailBody, marker)
	if i < 0 {
		t.Fatalf("no approve.html?token= link in the email: %s", emailBody)
	}
	rest := emailBody[i+len(marker):]
	end := strings.IndexAny(rest, "\"< \r\n")
	if end < 0 {
		end = len(rest)
	}
	return rest[:end]
}

// TestApprovalInviteCountsAsItsCreator is the Phase 290 regression: a magic
// link is its creator's approval handed to someone else, not a second
// approver. Before it, one approver satisfied a two-approver requirement
// alone — approve, mail yourself a link, redeem it — because the link's
// "magiclink:<email>" actor was a distinct string. Both orders are refused,
// a second link from the same creator is refused, and a link from a
// DIFFERENT approver still counts, so delegation keeps working.
func TestApprovalInviteCountsAsItsCreator(t *testing.T) {
	smtpAddr, gotEmail := fakeSMTP(t)
	srv, _ := newTestServerOpts(t, nil, api.Options{
		ShareSMTPAddr: smtpAddr, ShareSMTPFrom: "pam@example.com", PortalURL: "https://pam.example.com",
		ApprovalInviteTTL: time.Hour, ApprovalsRequired: 2,
	})
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")
	dave := seedUser(t, srv, "dave", "approver")

	invite := func(reqID int64, key, email string) string {
		t.Helper()
		code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/invite", reqID), key, map[string]any{"email": email})
		if code != http.StatusCreated {
			t.Fatalf("invite: %d %s", code, data)
		}
		return extractApprovalToken(t, string(<-gotEmail))
	}
	redeem := func(token string) (int, map[string]any) {
		t.Helper()
		code, data := do(t, srv, http.MethodPost, "/api/approval/redeem/"+token, "", map[string]any{"decision": "approved"})
		return code, jsonMap(t, data)
	}
	approve := func(reqID int64, key string) (int, map[string]any) {
		t.Helper()
		code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", reqID), key, nil)
		return code, jsonMap(t, data)
	}

	// Order 1: approve, then redeem your own link.
	targetID, req1 := seedPendingRequest(t, srv, alice)
	if code, m := approve(req1, bob); code != http.StatusOK || m["status"] != "pending" {
		t.Fatalf("bob's first approval: %d %v", code, m)
	}
	if code, m := redeem(invite(req1, bob, "bob@example.com")); code != http.StatusConflict {
		t.Fatalf("bob redeeming his own link after approving: %d %v, want 409", code, m)
	}
	// A different approver's link is a second voice and completes the chain.
	if code, m := redeem(invite(req1, dave, "oncall@example.com")); code != http.StatusOK || m["status"] != "approved" {
		t.Fatalf("dave's link: %d %v, want approved", code, m)
	}

	// Order 2: redeem your own link, then approve — and a second link.
	erin := seedUser(t, srv, "erin", "user")
	code, data := do(t, srv, http.MethodPost, "/api/access-requests", erin, map[string]any{"target_id": targetID, "reason": "second window"})
	if code != http.StatusCreated {
		t.Fatalf("file second request: %d %s", code, data)
	}
	req2 := int64(jsonMap(t, data)["id"].(float64))
	if code, m := redeem(invite(req2, bob, "bob@example.com")); code != http.StatusOK || m["status"] != "pending" {
		t.Fatalf("bob's link as the first approval: %d %v", code, m)
	}
	if code, m := approve(req2, bob); code != http.StatusConflict {
		t.Fatalf("bob approving after his own link: %d %v, want 409", code, m)
	}
	if code, m := redeem(invite(req2, bob, "bob-other@example.com")); code != http.StatusConflict {
		t.Fatalf("bob's second link: %d %v, want 409", code, m)
	}
	if code, m := approve(req2, dave); code != http.StatusOK || m["status"] != "approved" {
		t.Fatalf("dave's direct approval: %d %v, want approved", code, m)
	}
}
