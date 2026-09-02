// Package slack implements just enough of Slack's platform to post an
// interactive access-request approval message and verify + decode the
// callback when someone clicks a button on it (Phase 234, Britive's
// chat-ops finding) — deliberately not a general Slack SDK.
//
// Two independent primitives:
//
//   - VerifySignature: Slack's v0 request-signing scheme (HMAC-SHA256 over
//     "v0:<timestamp>:<body>", keyed by the app's signing secret, with a
//     freshness window against replay) — the same class of "verify who
//     really sent this" primitive PAMv1 already hand-rolls for SAML,
//     WebAuthn and DPoP proofs.
//   - SignToken/ParseToken: a compact, PAMv1-signed token embedded in each
//     button's value, binding a decision to (access request, outcome,
//     expiry) without needing a database row. It only has to resist
//     forgery, not replay: decideAccessRequest's existing compare-and-set
//     on the request's `pending` status is what makes the DECISION
//     itself single-use, exactly as it already does for the authenticated
//     approve/deny routes and the magic-link redemption path.
//
// Both primitives are keyed by the same signing secret, so the token MAC is
// computed over a domain-prefixed payload (tokenDomain): a MAC PAMv1 minted
// for a button can never be mistaken for one over a Slack request body, or
// vice versa, however the two byte strings happen to line up (Phase 236).
package slack

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// signatureFreshness is how old a request's timestamp may be before
// VerifySignature refuses it — Slack's own documented replay window.
const signatureFreshness = 5 * time.Minute

// tokenDomain is prefixed to a button token's payload before it is MACed,
// separating the token from Slack's own "v0:<ts>:<body>" request signature
// under the shared signing secret. It is not part of the token string.
const tokenDomain = "pamv1-slack-button:"

// mrkdwnEscaper escapes the only three characters Slack's mrkdwn treats as
// control characters (https://api.slack.com/reference/surfaces/formatting#escaping).
// html.EscapeString would also turn ' and " into numeric entities, which
// Slack does NOT decode — a reason of "can't reach db" rendered as
// "can&#39;t reach db" (Phase 236 review finding).
var mrkdwnEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// EscapeText escapes s for inclusion in a Slack mrkdwn or plain_text field.
func EscapeText(s string) string { return mrkdwnEscaper.Replace(s) }

// VerifySignature checks an inbound Slack request against Slack's v0
// signing scheme: sig must equal HMAC-SHA256("v0:<timestamp>:<body>",
// signingSecret), hex-encoded and "v0=" prefixed as Slack sends it, and
// timestamp must be within signatureFreshness of now — an old, replayed
// request is refused even with a valid signature, the same reasoning
// behind every other freshness check this codebase already makes (OIDC
// nonces, DPoP proofs, SAML conditions).
func VerifySignature(signingSecret, timestamp, body, sig string) bool {
	if signingSecret == "" || timestamp == "" || sig == "" {
		return false
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	age := time.Since(time.Unix(ts, 0))
	if age < -signatureFreshness || age > signatureFreshness {
		return false
	}
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte("v0:" + timestamp + ":" + body))
	want := "v0=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(sig))
}

// SignToken produces a compact, tamper-evident token binding requestID and
// decision ("approved"/"denied") to an expiry, for one Approve or Deny
// button's value. The payload is signed, not encrypted — an access request
// id and a decision are not secret, only the binding between them and
// PAMv1's own approval is what must not be forgeable.
func SignToken(secret string, requestID int64, decision string, exp time.Time) string {
	payload := fmt.Sprintf("%d|%s|%d", requestID, decision, exp.Unix())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tokenDomain + payload))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

// ParseToken verifies and decodes a token produced by SignToken, refusing
// a forged, tampered or expired one.
func ParseToken(secret, token string) (requestID int64, decision string, err error) {
	i := strings.LastIndexByte(token, '.')
	if i < 0 {
		return 0, "", fmt.Errorf("malformed token")
	}
	payload, sigHex := token[:i], token[i+1:]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tokenDomain + payload))
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(sigHex)) {
		return 0, "", fmt.Errorf("invalid signature")
	}
	parts := strings.SplitN(payload, "|", 3)
	if len(parts) != 3 {
		return 0, "", fmt.Errorf("malformed payload")
	}
	requestID, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("malformed request id: %w", err)
	}
	decision = parts[1]
	if decision != "approved" && decision != "denied" {
		return 0, "", fmt.Errorf("malformed decision %q", decision)
	}
	expUnix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("malformed expiry: %w", err)
	}
	if time.Now().After(time.Unix(expUnix, 0)) {
		return 0, "", fmt.Errorf("token expired")
	}
	return requestID, decision, nil
}

// BuildApprovalMessage returns the Block Kit JSON body for an incoming
// webhook post: requester/target/reason as text, and Approve/Deny buttons
// carrying the given signed tokens as their value.
func BuildApprovalMessage(requester, target, reason, approveToken, denyToken string) []byte {
	text := fmt.Sprintf("*%s* is requesting access to *%s*", EscapeText(requester), EscapeText(target))
	body := map[string]any{
		"text": text,
		"blocks": []map[string]any{
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": fmt.Sprintf("%s\n>%s", text, EscapeText(reason)),
				},
			},
			{
				"type": "actions",
				"elements": []map[string]any{
					{
						"type":      "button",
						"text":      map[string]string{"type": "plain_text", "text": "Approve"},
						"style":     "primary",
						"action_id": "pamv1_approve",
						"value":     approveToken,
					},
					{
						"type":      "button",
						"text":      map[string]string{"type": "plain_text", "text": "Deny"},
						"style":     "danger",
						"action_id": "pamv1_deny",
						"value":     denyToken,
					},
				},
			},
		},
	}
	b, _ := json.Marshal(body)
	return b
}

// ReplacementMessage returns the Block Kit JSON body for the response_url
// follow-up that replaces the original message once a decision has been
// recorded — Slack's documented shape for updating a message a button
// click came from.
func ReplacementMessage(text string) []byte {
	b, _ := json.Marshal(map[string]any{
		"replace_original": true,
		"text":             text,
	})
	return b
}

// EphemeralMessage returns the response_url body for a follow-up only the
// clicking member sees, leaving the original message — and its buttons —
// in place for everyone else. Used for every refused click (expired token,
// unlinked member, four-eyes, already decided): the ack body of a
// block_actions callback is ignored by Slack, so response_url is the only
// way a refusal ever reaches a human (Phase 236 review finding).
func EphemeralMessage(text string) []byte {
	b, _ := json.Marshal(map[string]any{
		"response_type":    "ephemeral",
		"replace_original": false,
		"text":             text,
	})
	return b
}

// PostJSON POSTs body to url as application/json, refusing anything but a
// 2xx response. Used both for the initial webhook post and the
// response_url follow-up — the same one-shot, no-retry shape
// alert.SendDirect already uses for outbound webhooks elsewhere.
func PostJSON(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("slack post failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack post failed: status %d", resp.StatusCode)
	}
	return nil
}
