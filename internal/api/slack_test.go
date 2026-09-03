package api_test

import (
	"context"
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
	"sync"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	pamslack "github.com/morandeirachema/pamv1/internal/slack"
	"github.com/morandeirachema/pamv1/internal/store"
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

	var fu followUps
	responseURLServer := httptest.NewServer(http.HandlerFunc(fu.handle))
	defer responseURLServer.Close()

	srv, st := newTestServerOpts(t, nil, api.Options{
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

	// An unlinked Slack member's click is acked (Slack's 3-second budget)
	// but refused: nothing is decided, and the clicker gets an ephemeral
	// note through response_url rather than a message everyone sees.
	code, respBody := postSlackInteractivity(t, srv, slackSigningSecret, approveToken, "U999", "stranger", responseURLServer.URL)
	if code != http.StatusOK {
		t.Fatalf("unlinked member: %d %s, want 200 (acked, refused via response_url)", code, respBody)
	}
	if ar := getAccessRequest(t, srv, bob, reqID); ar["status"] != "pending" {
		t.Fatalf("an unlinked member must not decide the request, got %v", ar["status"])
	}
	assertSlackEphemeral(t, fu.next(t), "not linked")

	// carol is a PAMv1 approver linked to Slack member U123. Clicking
	// Approve, correctly signed, decides the request AS carol.
	carolID, _ := seedUserWithID(t, srv, "carol", "approver")
	linkSlackUser(t, srv, carolID, "U123")
	code, respBody = postSlackInteractivity(t, srv, slackSigningSecret, approveToken, "U123", "carol", responseURLServer.URL)
	if code != http.StatusOK {
		t.Fatalf("interactivity: %d %s", code, respBody)
	}
	// The ack body is empty — Slack ignores it for block_actions; the
	// outcome is read back from the store and from response_url.
	if len(strings.TrimSpace(string(respBody))) != 0 {
		t.Fatalf("ack body must be empty, got %q", respBody)
	}
	ar := getAccessRequest(t, srv, bob, reqID)
	// The approver is carol's PAMv1 username — not a "slack:" namespaced
	// actor — so every later identity comparison is like with like.
	if ar["status"] != "approved" || ar["approver"] != "carol" {
		t.Fatalf("access request after slack decision: %+v", ar)
	}

	// The replacement message landed at response_url, naming the outcome.
	gotReplacement := fu.next(t)
	var replacement struct {
		ReplaceOriginal bool   `json:"replace_original"`
		Text            string `json:"text"`
	}
	if err := json.Unmarshal(gotReplacement, &replacement); err != nil {
		t.Fatalf("unmarshal replacement message: %v (%s)", err, gotReplacement)
	}
	if !replacement.ReplaceOriginal || !strings.Contains(replacement.Text, "approved") || !strings.Contains(replacement.Text, "carol") {
		t.Fatalf("replacement message: %+v", replacement)
	}

	// A second click on the same (now decided) request is refused
	// ephemerally — the compare-and-set on `pending` — not re-decided.
	postSlackInteractivity(t, srv, slackSigningSecret, approveToken, "U123", "carol", responseURLServer.URL)
	assertSlackEphemeral(t, fu.next(t), "already")

	// Slack interactivity is audited as its own action, with the PAMv1 user
	// and the Slack member id side by side.
	auditHas(t, st, "access.slack_decision", "carol")
}

// linkSlackUser sets a user's Slack member ID through the users API.
func linkSlackUser(t *testing.T, srv *httptest.Server, userID int64, slackUserID string) {
	t.Helper()
	code, data := do(t, srv, http.MethodGet, "/api/users?limit=1000", testAPIKey, nil)
	if code != http.StatusOK {
		t.Fatalf("list users: %d %s", code, data)
	}
	var users []map[string]any
	if err := json.Unmarshal(data, &users); err != nil {
		t.Fatalf("unmarshal users: %v (%s)", err, data)
	}
	role := ""
	for _, u := range users {
		if int64(u["id"].(float64)) == userID {
			role, _ = u["role"].(string)
		}
	}
	if role == "" {
		t.Fatalf("user %d not found", userID)
	}
	if code, data := do(t, srv, http.MethodPut, fmt.Sprintf("/api/users/%d", userID), testAPIKey, map[string]any{"role": role, "slack_user_id": slackUserID}); code != http.StatusOK {
		t.Fatalf("link slack user: %d %s", code, data)
	}
}

// assertSlackEphemeral checks a response_url follow-up is an ephemeral
// (clicker-only, original left in place) message containing want.
func assertSlackEphemeral(t *testing.T, body []byte, want string) {
	t.Helper()
	if body == nil {
		t.Fatal("no follow-up was posted to response_url")
	}
	var m struct {
		ResponseType    string `json:"response_type"`
		ReplaceOriginal bool   `json:"replace_original"`
		Text            string `json:"text"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal follow-up: %v (%s)", err, body)
	}
	if m.ResponseType != "ephemeral" || m.ReplaceOriginal || !strings.Contains(m.Text, want) {
		t.Fatalf("follow-up = %+v, want ephemeral containing %q", m, want)
	}
}

// TestSlackClickFourEyes proves the click side of four-eyes (Phase 236
// review finding): a requester whose own Slack account is linked cannot
// approve their own request from the channel, because the decision is made
// as their PAMv1 identity and decideAccessRequest's requester check now
// compares like with like.
func TestSlackClickFourEyes(t *testing.T) {
	srv, st, responseURL, getFollowUp := newSlackTestServer(t, api.Options{})
	// alice is an admin: the one built-in role that can both file a request
	// and approve one, which is exactly the identity four-eyes must stop.
	aliceID, alice := seedUserWithID(t, srv, "alice", "admin")
	linkSlackUser(t, srv, aliceID, "UALICE")
	bob := seedUser(t, srv, "bob", "approver")
	_, reqID := seedPendingRequest(t, srv, alice)

	_, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/slack-notify", reqID), bob, nil)
	approveToken, _ := extractSlackTokens(t, lastSlackMessage(t, srv))
	_ = data

	if code, _ := postSlackInteractivity(t, srv, slackSigningSecret, approveToken, "UALICE", "alice", responseURL); code != http.StatusOK {
		t.Fatalf("click: %d", code)
	}
	if ar := getAccessRequest(t, srv, bob, reqID); ar["status"] != "pending" {
		t.Fatalf("the requester approved their own request from Slack: %+v", ar)
	}
	assertSlackEphemeral(t, getFollowUp(), "four-eyes")
	auditHas(t, st, "access.decision_denied", "self-approval")
}

// TestSlackClickDualControl proves one human cannot satisfy a two-person
// floor by approving once through the API and once through Slack (Phase 236
// review finding): both approvals resolve to the same PAMv1 identity.
func TestSlackClickDualControl(t *testing.T) {
	srv, _, responseURL, getFollowUp := newSlackTestServer(t, api.Options{ApprovalsRequired: 2})
	alice := seedUser(t, srv, "alice", "user")
	bobID, bob := seedUserWithID(t, srv, "bob", "approver")
	linkSlackUser(t, srv, bobID, "UBOB")
	_, reqID := seedPendingRequest(t, srv, alice)

	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", reqID), bob, nil); code != http.StatusOK {
		t.Fatalf("first approval: %d %s", code, d)
	}
	if ar := getAccessRequest(t, srv, bob, reqID); ar["status"] != "pending" {
		t.Fatalf("one of two approvals must leave the request pending: %+v", ar)
	}
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/slack-notify", reqID), bob, nil); code != http.StatusOK {
		t.Fatalf("notify: %d %s", code, d)
	}
	approveToken, _ := extractSlackTokens(t, lastSlackMessage(t, srv))

	if code, _ := postSlackInteractivity(t, srv, slackSigningSecret, approveToken, "UBOB", "bob", responseURL); code != http.StatusOK {
		t.Fatalf("click: %d", code)
	}
	ar := getAccessRequest(t, srv, bob, reqID)
	if ar["status"] != "pending" {
		t.Fatalf("bob satisfied a two-person floor alone via Slack: %+v", ar)
	}
	assertSlackEphemeral(t, getFollowUp(), "already approved")

	// A genuinely distinct linked approver completes the chain.
	carolID, _ := seedUserWithID(t, srv, "carol", "approver")
	linkSlackUser(t, srv, carolID, "UCAROL")
	postSlackInteractivity(t, srv, slackSigningSecret, approveToken, "UCAROL", "carol", responseURL)
	if ar := getAccessRequest(t, srv, bob, reqID); ar["status"] != "approved" {
		t.Fatalf("two distinct approvers must approve: %+v", ar)
	}
}

// TestSlackClickRequiresApproverRole proves a linked user whose role lacks
// CapApprove cannot decide from Slack — linking grants identity, not
// capability.
func TestSlackClickRequiresApproverRole(t *testing.T) {
	srv, st, responseURL, getFollowUp := newSlackTestServer(t, api.Options{})
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")
	daveID, _ := seedUserWithID(t, srv, "dave", "user")
	linkSlackUser(t, srv, daveID, "UDAVE")
	_, reqID := seedPendingRequest(t, srv, alice)
	do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/slack-notify", reqID), bob, nil)
	approveToken, _ := extractSlackTokens(t, lastSlackMessage(t, srv))

	postSlackInteractivity(t, srv, slackSigningSecret, approveToken, "UDAVE", "dave", responseURL)
	if ar := getAccessRequest(t, srv, bob, reqID); ar["status"] != "pending" {
		t.Fatalf("a non-approver decided from Slack: %+v", ar)
	}
	assertSlackEphemeral(t, getFollowUp(), "not allowed")
	auditHas(t, st, "access.decision_denied", "slack-not-approver")
}

// TestUserSlackUserIDField proves the users API round-trips slack_user_id,
// refuses a duplicate link with 409, and clears it back to empty.
func TestUserSlackUserIDField(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})
	code, data := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "erin", "role": "approver", "slack_user_id": "UERIN"})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, data)
	}
	erin := jsonMap(t, data)
	if erin["slack_user_id"] != "UERIN" {
		t.Fatalf("create did not echo slack_user_id: %+v", erin)
	}
	erinID := int64(erin["id"].(float64))
	frankID, _ := seedUserWithID(t, srv, "frank", "approver")
	if code, data := do(t, srv, http.MethodPut, fmt.Sprintf("/api/users/%d", frankID), testAPIKey, map[string]any{"role": "approver", "slack_user_id": "UERIN"}); code != http.StatusConflict {
		t.Fatalf("duplicate slack_user_id: %d %s, want 409", code, data)
	}
	if code, data := do(t, srv, http.MethodPut, fmt.Sprintf("/api/users/%d", frankID), testAPIKey, map[string]any{"role": "approver", "slack_user_id": "bad id"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("slack_user_id with whitespace: %d %s, want 422", code, data)
	}
	if code, data := do(t, srv, http.MethodPut, fmt.Sprintf("/api/users/%d", erinID), testAPIKey, map[string]any{"role": "approver", "slack_user_id": ""}); code != http.StatusOK {
		t.Fatalf("clear: %d %s", code, data)
	}
	if code, data := do(t, srv, http.MethodPut, fmt.Sprintf("/api/users/%d", frankID), testAPIKey, map[string]any{"role": "approver", "slack_user_id": "UERIN"}); code != http.StatusOK {
		t.Fatalf("relink after clear: %d %s", code, data)
	}
}

// followUps is a response_url endpoint that records every follow-up it
// receives, in order. Since Phase 238 the ack is complete on the wire BEFORE
// the follow-up is posted, so a test that has just clicked must WAIT for the
// follow-up rather than read it — next does, consuming one follow-up per
// call so a stale one can never satisfy a later click.
type followUps struct {
	mu    sync.Mutex
	got   [][]byte
	taken int
}

func (f *followUps) handle(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.got = append(f.got, b)
	f.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// next returns the oldest follow-up not yet returned, waiting up to three
// seconds for it to arrive.
func (f *followUps) next(t *testing.T) []byte {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		f.mu.Lock()
		if f.taken < len(f.got) {
			b := f.got[f.taken]
			f.taken++
			f.mu.Unlock()
			return b
		}
		f.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("no follow-up was posted to response_url")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// newSlackTestServer builds a Slack-configured test server whose webhook
// remembers the last message posted and whose response_url endpoint
// records every follow-up; getFollowUp waits for and returns the next one.
func newSlackTestServer(t *testing.T, opts api.Options) (srv *httptest.Server, st store.Store, responseURL string, getFollowUp func() []byte) {
	t.Helper()
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		slackMessages.Store(srvKey(r), b)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(webhook.Close)
	var fu followUps
	rurl := httptest.NewServer(http.HandlerFunc(fu.handle))
	t.Cleanup(rurl.Close)
	opts.SlackWebhookURL = webhook.URL
	opts.SlackSigningSecret = slackSigningSecret
	if opts.ApprovalInviteTTL == 0 {
		opts.ApprovalInviteTTL = time.Hour
	}
	srv, st = newTestServerOpts(t, nil, opts)
	slackWebhookOf.Store(srv.URL, webhook.URL)
	return srv, st, rurl.URL, func() []byte { return fu.next(t) }
}

// slackMessages maps a webhook server's host to the last message it received;
// slackWebhookOf maps a PAMv1 test server's URL to its webhook URL.
var slackMessages, slackWebhookOf sync.Map

func srvKey(r *http.Request) string { return r.Host }

// lastSlackMessage returns the last message srv posted to its webhook.
func lastSlackMessage(t *testing.T, srv *httptest.Server) []byte {
	t.Helper()
	wh, ok := slackWebhookOf.Load(srv.URL)
	if !ok {
		t.Fatal("no webhook registered for this server")
	}
	u, _ := url.Parse(wh.(string))
	msg, ok := slackMessages.Load(u.Host)
	if !ok {
		t.Fatal("no message was posted to the Slack webhook")
	}
	return msg.([]byte)
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
	expiredToken := pamslack.SignToken(slackSigningSecret, reqID, "approved", time.Now().Add(-time.Minute))

	code, respBody := postSlackInteractivity(t, srv, slackSigningSecret, expiredToken, "U1", "carol", "")
	if code != http.StatusOK {
		t.Fatalf("expired token: %d %s, want 200 (graceful, not an error)", code, respBody)
	}
	// Must NOT have decided the request.
	if ar := getAccessRequest(t, srv, bob, reqID); ar["status"] != "pending" {
		t.Fatalf("an expired token must not decide the request, got status %v", ar["status"])
	}
}

// TestSlackAckCompletesBeforeFollowUp proves the ack IS an ack (Phase 238
// review finding): Slack's client must see a COMPLETE 200 response before
// PAMv1's response_url follow-up has finished, not just its headers.
// Phase 236 flushed an empty 200 without a Content-Length, which makes Go
// send a chunked response whose terminating chunk only goes out when the
// handler returns — after the follow-up — so a client reading the body
// (every HTTP client does) still waited the full round-trip. The follow-up
// server here blocks until the test has read the ack in full; before the
// fix this read hung until the client timed out.
func TestSlackAckCompletesBeforeFollowUp(t *testing.T) {
	release := make(chan struct{})
	rurl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer rurl.Close()
	defer close(release)
	srv, _, _, _ := newSlackTestServer(t, api.Options{})
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")
	_, reqID := seedPendingRequest(t, srv, alice)
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/slack-notify", reqID), bob, nil); code != http.StatusOK {
		t.Fatalf("notify: %d %s", code, data)
	}
	approveToken, _ := extractSlackTokens(t, lastSlackMessage(t, srv))
	carolID, _ := seedUserWithID(t, srv, "carol", "approver")
	linkSlackUser(t, srv, carolID, "U123")

	pb, _ := json.Marshal(map[string]any{
		"type":         "block_actions",
		"user":         map[string]string{"id": "U123", "username": "carol"},
		"actions":      []map[string]string{{"action_id": "pamv1_approve", "value": approveToken}},
		"response_url": rurl.URL,
	})
	body := "payload=" + url.QueryEscape(string(pb))
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/slack/interactivity", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	req.Header.Set("X-Slack-Signature", signSlackRequest(slackSigningSecret, ts, body))
	// Slack's real budget is 3 s; a client that has to wait for the
	// follow-up would not return in time.
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("ack headers did not arrive while the follow-up was pending: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ack status %d, want 200", resp.StatusCode)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("ack body did not complete while the follow-up was pending: %v", err)
	}
}

// TestSlackDecisionAuditActor proves a Slack decision is attributed to the
// linked PAMv1 user in EVERY audit row it produces (Phase 238 review
// finding), not only in access.slack_decision's detail. The interactivity
// route is unauthenticated (Slack's signature is the authentication), so
// nothing put a principal in the request context and decideAccessRequest's
// own access.approve row — whose detail does not name the approver — was
// attributed to actor "unknown".
func TestSlackDecisionAuditActor(t *testing.T) {
	srv, st, responseURL, _ := newSlackTestServer(t, api.Options{})
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")
	_, reqID := seedPendingRequest(t, srv, alice)
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/slack-notify", reqID), bob, nil); code != http.StatusOK {
		t.Fatalf("notify: %d %s", code, data)
	}
	approveToken, _ := extractSlackTokens(t, lastSlackMessage(t, srv))
	carolID, _ := seedUserWithID(t, srv, "carol", "approver")
	linkSlackUser(t, srv, carolID, "U123")
	if code, data := postSlackInteractivity(t, srv, slackSigningSecret, approveToken, "U123", "carol", responseURL); code != http.StatusOK {
		t.Fatalf("interactivity: %d %s", code, data)
	}
	if ar := getAccessRequest(t, srv, bob, reqID); ar["status"] != "approved" {
		t.Fatalf("request not approved: %+v", ar)
	}
	for _, action := range []string{"access.approve", "access.slack_decision"} {
		if got := auditActorOf(t, st, action); got != "carol" {
			t.Fatalf("%s actor = %q, want the linked PAMv1 user %q", action, got, "carol")
		}
	}
}

// auditActorOf returns the actor of the newest audit event with the given
// action, failing the test if there is none.
func auditActorOf(t *testing.T, st store.Store, action string) string {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == action {
			return e.Actor
		}
	}
	t.Fatalf("no audit event action=%q", action)
	return ""
}
