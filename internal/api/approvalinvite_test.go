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
