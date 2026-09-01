package api_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
)

const slackSigningSecret = "test-slack-signing-secret"

// signSlackRequest computes the v0 signature Slack attaches to a real
// interactivity callback, for a test to present the same way Slack would.
func signSlackRequest(secret, timestamp, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + timestamp + ":" + body))
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

// postSlackInteractivity POSTs a Slack-shaped, correctly signed interactivity
// callback for the given button value, optionally naming a response_url the
// server will post its follow-up replacement message to.
func postSlackInteractivity(t *testing.T, srv *httptest.Server, secret, actionValue, userID, username, responseURL string) (int, []byte) {
	t.Helper()
	payload := map[string]any{
		"type": "block_actions",
		"user": map[string]string{"id": userID, "username": username},
		"actions": []map[string]string{
			{"action_id": "pamv1_approve", "value": actionValue},
		},
		"response_url": responseURL,
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	body := "payload=" + url.QueryEscape(string(pb))
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/slack/interactivity", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	req.Header.Set("X-Slack-Signature", signSlackRequest(secret, ts, body))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

// getAccessRequest finds request id in the full list (there is no
// GET /api/access-requests/{id}, only the list route) and returns it as a
// map, failing the test if it is not present.
func getAccessRequest(t *testing.T, srv *httptest.Server, apiKey string, id int64) map[string]any {
	t.Helper()
	code, data := do(t, srv, http.MethodGet, "/api/access-requests", apiKey, nil)
	if code != http.StatusOK {
		t.Fatalf("list access requests: %d %s", code, data)
	}
	var reqs []map[string]any
	if err := json.Unmarshal(data, &reqs); err != nil {
		t.Fatalf("unmarshal access requests: %v (%s)", err, data)
	}
	for _, r := range reqs {
		if int64(r["id"].(float64)) == id {
			return r
		}
	}
	t.Fatalf("request %d not found in %+v", id, reqs)
	return nil
}

// extractSlackTokens pulls the two button values out of the Block Kit JSON
// notifySlackAccessRequest posts to the configured webhook.
func extractSlackTokens(t *testing.T, messageJSON []byte) (approveToken, denyToken string) {
	t.Helper()
	var msg struct {
		Blocks []struct {
			Elements []struct {
				ActionID string `json:"action_id"`
				Value    string `json:"value"`
			} `json:"elements"`
		} `json:"blocks"`
	}
	if err := json.Unmarshal(messageJSON, &msg); err != nil {
		t.Fatalf("unmarshal slack message: %v (%s)", err, messageJSON)
	}
	for _, b := range msg.Blocks {
		for _, el := range b.Elements {
			switch el.ActionID {
			case "pamv1_approve":
				approveToken = el.Value
			case "pamv1_deny":
				denyToken = el.Value
			}
		}
	}
	if approveToken == "" || denyToken == "" {
		t.Fatalf("message missing approve/deny tokens: %s", messageJSON)
	}
	return approveToken, denyToken
}

// TestSlackNotifyAndInteractivityLifecycle proves the whole Phase 234
// chat-ops flow end to end: notifying posts a real interactive message,
// clicking Approve in a correctly signed callback decides the underlying
// access request through the exact same decideAccessRequest an
// authenticated approve uses, and a replacement message is posted back to
// response_url.
func TestSlackNotifyAndInteractivityLifecycle(t *testing.T) {
	var gotMessage []byte
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMessage, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer webhook.Close()

	var gotReplacement []byte
	responseURLServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReplacement, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer responseURLServer.Close()

	srv, _ := newTestServerOpts(t, nil, api.Options{
		SlackWebhookURL: webhook.URL, SlackSigningSecret: slackSigningSecret,
		ApprovalInviteTTL: time.Hour,
	})
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")
	_, reqID := seedPendingRequest(t, srv, alice)

	// bob (a CapApprove holder, not the requester) notifies Slack.
	status, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/slack-notify", reqID), bob, nil)
	if status != http.StatusOK {
		t.Fatalf("notify: %d %s", status, data)
	}
	if gotMessage == nil {
		t.Fatal("no message was posted to the Slack webhook")
	}
	approveToken, _ := extractSlackTokens(t, gotMessage)

	// A wrong signature is refused before the token is ever parsed.
	badReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/slack/interactivity", strings.NewReader("payload=x"))
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badReq.Header.Set("X-Slack-Request-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	badReq.Header.Set("X-Slack-Signature", "v0=deadbeef")
	badResp, err := srv.Client().Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad signature: %d, want 401", badResp.StatusCode)
	}

	// Clicking Approve, correctly signed, decides the request.
	code, respBody := postSlackInteractivity(t, srv, slackSigningSecret, approveToken, "U123", "carol", responseURLServer.URL)
	if code != http.StatusOK {
		t.Fatalf("interactivity: %d %s", code, respBody)
	}

	ar := jsonMap(t, respBody)
	// The Slack-supplied username is bounded/quoted (auditField) before
	// becoming part of the actor string, the same treatment every other
	// externally-sourced actor gets (e.g. a failed login's username) — so
	// the approver reads slack:"carol", not slack:carol.
	if ar["status"] != "approved" || ar["approver"] != `slack:"carol"` {
		t.Fatalf("access request after slack decision: %+v", ar)
	}

	// The replacement message landed at response_url, naming the outcome.
	if gotReplacement == nil {
		t.Fatal("no replacement message was posted to response_url")
	}
	var replacement struct {
		ReplaceOriginal bool   `json:"replace_original"`
		Text            string `json:"text"`
	}
	if err := json.Unmarshal(gotReplacement, &replacement); err != nil {
		t.Fatalf("unmarshal replacement message: %v (%s)", err, gotReplacement)
	}
	if !replacement.ReplaceOriginal || !strings.Contains(replacement.Text, "approved") {
		t.Fatalf("replacement message = %+v, want replace_original and an approved outcome", replacement)
	}

	// Single-use: decideAccessRequest's own compare-and-set refuses a
	// second decision on the same (now-approved) request — clicking Deny
	// on the ORIGINAL message (whose tokens are both still validly signed)
	// must not flip an already-approved request to denied.
	_, denyToken := extractSlackTokens(t, gotMessage)
	code2, body2 := postSlackInteractivity(t, srv, slackSigningSecret, denyToken, "U999", "mallory", "")
	if code2 != http.StatusConflict {
		t.Fatalf("deciding an already-decided request: %d %s, want 409", code2, body2)
	}
	if ar3 := getAccessRequest(t, srv, bob, reqID); ar3["status"] != "approved" {
		t.Fatalf("request status changed after the refused second decision: %+v", ar3)
	}
}

// TestSlackNotifyCannotSelfApprove proves the requester cannot notify Slack
// about their own request, the same four-eyes-at-creation rule the
// magic-link invite enforces.
func TestSlackNotifyCannotSelfApprove(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer webhook.Close()
	srv, _ := newTestServerOpts(t, nil, api.Options{
		SlackWebhookURL: webhook.URL, SlackSigningSecret: slackSigningSecret,
		ApprovalInviteTTL: time.Hour,
	})
	_, reqID := seedPendingRequest(t, srv, testAPIKey)

	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/slack-notify", reqID), testAPIKey, nil); code != http.StatusForbidden {
		t.Fatalf("requester notifying about their own request: %d %s, want 403", code, d)
	}
}

// TestSlackNotifyRequiresPendingRequest proves Slack cannot be notified
// about an already-decided request.
func TestSlackNotifyRequiresPendingRequest(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer webhook.Close()
	srv, _ := newTestServerOpts(t, nil, api.Options{
		SlackWebhookURL: webhook.URL, SlackSigningSecret: slackSigningSecret,
		ApprovalInviteTTL: time.Hour,
	})
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")
	_, reqID := seedPendingRequest(t, srv, alice)

	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/deny", reqID), bob, nil); code != http.StatusOK {
		t.Fatalf("deny: %d %s", code, d)
	}
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/slack-notify", reqID), bob, nil); code != http.StatusConflict {
		t.Fatalf("notify for a decided request: %d %s, want 409", code, d)
	}
}

// TestSlackNotConfigured proves both routes fail closed when Slack chat-ops
// approval is not configured, rather than notifying nobody silently or
// accepting an unverifiable callback.
func TestSlackNotConfigured(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")
	_, reqID := seedPendingRequest(t, srv, alice)

	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/slack-notify", reqID), bob, nil); code != http.StatusServiceUnavailable {
		t.Fatalf("notify with Slack unconfigured: %d %s, want 503", code, d)
	}
	code, d := postSlackInteractivity(t, srv, "any-secret", "irrelevant", "U1", "x", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("interactivity with Slack unconfigured: %d %s, want 401", code, d)
	}
}

// TestSlackInteractivityRejectsExpiredToken proves a token past its expiry
// is refused gracefully (200 with an explanatory message, not a 500 or a
// decision) even though the OUTER Slack signature is valid.
func TestSlackInteractivityRejectsExpiredToken(t *testing.T) {
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer webhook.Close()
	srv, _ := newTestServerOpts(t, nil, api.Options{
		SlackWebhookURL: webhook.URL, SlackSigningSecret: slackSigningSecret,
		ApprovalInviteTTL: time.Hour,
	})
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")
	_, reqID := seedPendingRequest(t, srv, alice)

	status, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/slack-notify", reqID), bob, nil)
	if status != http.StatusOK {
		t.Fatalf("notify: %d %s", status, data)
	}

	// Fabricate an already-expired token with the SAME secret the server
	// holds, rather than waiting out a real TTL.
	expired := fmt.Sprintf("%d|approved|%d", reqID, time.Now().Add(-time.Minute).Unix())
	mac := hmac.New(sha256.New, []byte(slackSigningSecret))
	mac.Write([]byte(expired))
	expiredToken := expired + "." + hex.EncodeToString(mac.Sum(nil))

	code, respBody := postSlackInteractivity(t, srv, slackSigningSecret, expiredToken, "U1", "carol", "")
	if code != http.StatusOK {
		t.Fatalf("expired token: %d %s, want 200 (graceful, not an error)", code, respBody)
	}
	// Must NOT have decided the request.
	if ar := getAccessRequest(t, srv, bob, reqID); ar["status"] != "pending" {
		t.Fatalf("an expired token must not decide the request, got status %v", ar["status"])
	}
}
