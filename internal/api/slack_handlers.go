package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	pamslack "github.com/morandeirachema/pamv1/internal/slack"
)

// --- Slack chat-ops access-request approval (Phase 234, Britive's chat-ops
// finding) ---
//
// Structurally the same delegation shape as the magic-link approval invite
// (Phase 137, approvalinvite_handlers.go) — creating one already requires
// CapApprove, so notifying Slack IS the delegation, not a request for one —
// with Slack's signed interactivity callback standing in for the emailed
// link's single-use token and a human's browser POST. There is no separate
// store-backed invite: each button's value is itself a PAMv1-signed token
// (internal/slack.SignToken) binding the access request and the outcome to
// an expiry, so forging or replaying a decision requires the signing
// secret, and deciding the SAME request twice is refused the same way it
// already is for every other decision path — decideAccessRequest's
// compare-and-set on the request's `pending` status.

const slackNotifyMaxBytes = 1 << 20 // 1 MiB — comfortably above any real interactivity payload

// slackConfigured reports whether both halves of chat-ops approval are
// present. config.Load already refuses one without the other, so in
// practice this is all-or-nothing, but a handler checks its own
// prerequisite rather than trusting that validation ran.
func (s *Server) slackConfigured() bool {
	return s.slackWebhookURL != "" && s.slackSigningSecret != ""
}

// notifySlackAccessRequest is POST /api/access-requests/{id}/slack-notify:
// posts an interactive Approve/Deny message for the named pending access
// request to the configured Slack webhook. Requires CapApprove — the same
// four-eyes-at-creation rule createApprovalInvite enforces, since minting
// a Slack notification delegates the caller's own decision the same way an
// emailed invite does.
func (s *Server) notifySlackAccessRequest(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if !s.slackConfigured() {
		writeError(w, http.StatusServiceUnavailable, "Slack chat-ops approval needs PAM_SLACK_WEBHOOK_URL and PAM_SLACK_SIGNING_SECRET configured")
		return
	}
	ar, err := s.store.GetAccessRequest(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	// Four-eyes at notify time, mirroring createApprovalInvite exactly: a
	// requester delegating their own decision to whoever is in the Slack
	// channel is the same self-approval hole a magic-link invite would open,
	// closed the same way — before any message is ever posted.
	if ar.Requester == actorFrom(r.Context()) {
		s.audit(r.Context(), "access.decision_denied", fmt.Sprintf("request:%d reason:self-approval-slack", ar.ID))
		writeError(w, http.StatusForbidden, "four-eyes: you cannot notify Slack about your own access request")
		return
	}
	if ar.Status != "pending" {
		writeError(w, http.StatusConflict, "request already "+ar.Status)
		return
	}
	target := ar.Reason
	if t, err := s.store.GetTarget(r.Context(), ar.TargetID); err == nil {
		target = t.Name
	}
	exp := time.Now().Add(s.approvalInviteTTL)
	approveToken := pamslack.SignToken(s.slackSigningSecret, ar.ID, "approved", exp)
	denyToken := pamslack.SignToken(s.slackSigningSecret, ar.ID, "denied", exp)
	body := pamslack.BuildApprovalMessage(ar.Requester, target, ar.Reason, approveToken, denyToken)
	if err := pamslack.PostJSON(r.Context(), s.slackWebhookURL, body); err != nil {
		s.log.Error("slack notify failed", "request", ar.ID, "err", err)
		writeError(w, http.StatusBadGateway, "request created but the Slack message could not be posted")
		return
	}
	s.audit(r.Context(), "access.slack_notified", fmt.Sprintf("request:%d", ar.ID))
	writeJSON(w, http.StatusOK, map[string]any{"notified": true})
}

// slackInteractivityPayload is the subset of Slack's block_actions
// interactivity payload this handler reads. See
// https://api.slack.com/interactivity/handling#payloads.
type slackInteractivityPayload struct {
	Type string `json:"type"`
	User struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	} `json:"user"`
	Actions []struct {
		ActionID string `json:"action_id"`
		Value    string `json:"value"`
	} `json:"actions"`
	ResponseURL string `json:"response_url"`
}

// slackInteractivity is POST /api/slack/interactivity: Slack's callback
// when someone clicks a button on a message notifySlackAccessRequest
// posted. Registered WITHOUT the authz(...) wrapper, the same way the
// magic-link redeem/preview pair and the session-share guest routes are —
// Slack's own request signature IS the authentication here, checked before
// anything else runs.
func (s *Server) slackInteractivity(w http.ResponseWriter, r *http.Request) {
	if s.slackSigningSecret == "" {
		s.authFailed(w, r, "slack-interactivity", "Slack chat-ops approval is not configured")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, slackNotifyMaxBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	ts := r.Header.Get("X-Slack-Request-Timestamp")
	sig := r.Header.Get("X-Slack-Signature")
	if !pamslack.VerifySignature(s.slackSigningSecret, ts, string(body), sig) {
		s.authFailed(w, r, "slack-interactivity", "invalid request signature")
		return
	}
	// Slack's interactivity callback is application/x-www-form-urlencoded
	// with a single "payload" field carrying the JSON body. r.Body was
	// already fully consumed above (needed as a whole string for the
	// signature check), so parse the form from those same bytes directly
	// rather than re-populating r.Body for ParseForm to re-read.
	form, err := url.ParseQuery(string(body))
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	var payload slackInteractivityPayload
	if err := json.Unmarshal([]byte(form.Get("payload")), &payload); err != nil || len(payload.Actions) == 0 {
		writeError(w, http.StatusBadRequest, "malformed interactivity payload")
		return
	}
	action := payload.Actions[0]
	requestID, decision, err := pamslack.ParseToken(s.slackSigningSecret, action.Value)
	if err != nil {
		// The signature over the OUTER payload already proved this came from
		// Slack; a bad inner token means an expired or tampered button, not
		// an unauthenticated caller — 200 with a message Slack renders in
		// place of the buttons, not a 401 that would make Slack retry.
		writeJSON(w, http.StatusOK, map[string]any{"text": "This approval link has expired or is no longer valid."})
		return
	}
	who := payload.User.Username
	if who == "" {
		who = payload.User.ID
	}
	// who is Slack-attested (came from a request whose signature we already
	// verified), not client-editable — but it is still text from outside
	// PAMv1 becoming an audit actor, so it is bounded the same way any other
	// externally-sourced actor string is (e.g. a failed login's username).
	who = auditField(who, 64)
	actor := "slack:" + who
	ok := s.decideAccessRequest(w, r, requestID, decision, actor)
	// Best-effort, matching redeemApprovalInvite's own "either way" comment:
	// decideAccessRequest has already written its response to w (the direct
	// ack Slack requires within 3 seconds); this is a SEPARATE, asynchronous
	// follow-up that replaces the original message so the channel shows the
	// outcome instead of live buttons forever.
	text := fmt.Sprintf("Access request #%d %s by %s.", requestID, decision, who)
	if !ok {
		text = fmt.Sprintf("Access request #%d could not be decided (already decided, or an error occurred).", requestID)
	}
	if payload.ResponseURL != "" {
		_ = pamslack.PostJSON(r.Context(), payload.ResponseURL, pamslack.ReplacementMessage(text))
	}
}
