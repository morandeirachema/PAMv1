package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
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
//
// WHO clicked is resolved through the Slack identity mapping (Phase 236,
// User.SlackUserID): the payload's Slack-attested member id must link to an
// active PAMv1 user holding CapApprove, and the decision is then made AS
// that PAMv1 identity — so decideAccessRequest's four-eyes check and its
// distinct-approver count compare a PAMv1 username with a PAMv1 username.
// Phase 234 decided as a synthetic "slack:<handle>" actor instead, and the
// review found both checks could then never match the same human: the
// requester could approve their own request from the channel, and one
// approver could satisfy a two-person floor by approving once via the API
// and once via Slack.

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
	target := fmt.Sprintf("target #%d", ar.TargetID)
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
//
// Response shape: Slack needs a 2xx ack within 3 seconds and IGNORES the
// ack's body for a block_actions payload, so the ack is an empty,
// Content-Length: 0 200 — complete on the wire — sent after the decision
// (store work) and BEFORE the follow-up (network), and everything a human
// should read goes to the payload's response_url — a replacement of the
// original message for a recorded decision, an ephemeral note only the
// clicker sees for a refusal.
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
	// Everything from here on is a human's click on a genuine Slack message.
	// The decision itself is a handful of store operations and is made
	// FIRST, so that when the ack goes out the request's state is already
	// what a Slack retry would find; only then is Slack acked, and only after
	// the ack does the follow-up — the one network round-trip of its own —
	// reach response_url.
	msg := s.slackDecide(r, payload)
	// Content-Length: 0 is what makes the ack COMPLETE on the wire (Phase
	// 238 review finding): without it Go sends the 200 chunked, and the
	// terminating chunk — the byte every HTTP client waits for before it
	// treats the response as received — only went out when this handler
	// returned, i.e. after the response_url round-trip below. With it, the
	// flushed header IS the whole response.
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	if payload.ResponseURL != "" {
		// Best-effort, matching redeemApprovalInvite's own "either way"
		// comment: the ack is already on the wire.
		_ = pamslack.PostJSON(r.Context(), payload.ResponseURL, msg)
	}
}

// slackDecide resolves WHO clicked and makes (or refuses) the decision,
// returning the response_url follow-up that tells the human what happened:
// an ephemeral note for every refusal, a replacement of the original message
// for a recorded decision.
func (s *Server) slackDecide(r *http.Request, payload slackInteractivityPayload) []byte {
	slackUser := auditField(payload.User.ID, 64)

	action := payload.Actions[0]
	requestID, decision, err := pamslack.ParseToken(s.slackSigningSecret, action.Value)
	if err != nil {
		// The signature over the OUTER payload already proved this came from
		// Slack; a bad inner token means an expired or tampered button, not
		// an unauthenticated caller.
		return pamslack.EphemeralMessage("This approval link has expired or is no longer valid.")
	}

	// Slack identity mapping (Phase 236): the member id is Slack-attested
	// (it came from a request whose signature was verified above) but it is
	// not a PAMv1 identity until a user row says so. An unlinked member, a
	// deactivated user, or one whose role lacks CapApprove is refused here,
	// with the same audit action a self-approval attempt already produces.
	u, err := s.store.GetUserBySlackUserID(r.Context(), payload.User.ID)
	if err != nil || !u.Active {
		s.audit(r.Context(), "access.decision_denied", fmt.Sprintf("request:%d reason:slack-unlinked slack_user:%s", requestID, slackUser))
		return pamslack.EphemeralMessage("Your Slack account is not linked to an active PAMv1 user. Ask an administrator to set your Slack member ID on your PAMv1 user.")
	}
	p, err := s.resolver.PrincipalForRole(r.Context(), u.Username, u.Role)
	if err == nil {
		// From here on the click IS this PAMv1 user: put the principal in
		// the request context exactly where the authz middleware would have,
		// so every audit row the decision produces — decideAccessRequest's
		// own access.approve / access.deny / access.approve_partial /
		// access.decision_denied, whose details do not all name the approver
		// — is attributed to the human, not to "unknown" (Phase 238 review
		// finding), and the access log shows who clicked.
		r = r.WithContext(withPrincipal(r.Context(), p))
		setActor(r.Context(), u.Username)
	}
	if err != nil || !p.Can(auth.CapApprove) {
		s.audit(r.Context(), "access.decision_denied", fmt.Sprintf("request:%d reason:slack-not-approver user:%s slack_user:%s", requestID, auditField(u.Username, 64), slackUser))
		return pamslack.EphemeralMessage(fmt.Sprintf("PAMv1 user %s is not allowed to decide access requests.", u.Username))
	}

	// Decide AS the linked PAMv1 identity through the exact path an
	// authenticated approve/deny call takes. decideAccessRequest writes its
	// own HTTP response, which Slack would ignore, so it is captured here and
	// turned into the follow-up text instead.
	rec := &slackDecisionRecorder{status: http.StatusOK}
	ok := s.decideAccessRequest(rec, r, requestID, decision, u.Username)
	s.audit(r.Context(), "access.slack_decision", fmt.Sprintf("request:%d decision:%s user:%s slack_user:%s ok:%t", requestID, decision, auditField(u.Username, 64), slackUser, ok))
	if !ok {
		reason := rec.errorMessage()
		if reason == "" {
			reason = "it could not be decided"
		}
		return pamslack.EphemeralMessage(fmt.Sprintf("Access request #%d was not decided: %s.", requestID, reason))
	}
	if decision == "approved" && rec.status == http.StatusOK && !rec.decided() {
		// A partial approval on a multi-approver chain: the request is still
		// pending and the buttons must stay live for the next approver.
		return pamslack.EphemeralMessage(fmt.Sprintf("Your approval of access request #%d was recorded; more approvals are required.", requestID))
	}
	return pamslack.ReplacementMessage(fmt.Sprintf("Access request #%d %s by %s (via Slack).", requestID, decision, u.Username))
}

// slackDecisionRecorder captures what decideAccessRequest would have written
// to the wire, so the interactivity handler can ack Slack independently and
// report the outcome through response_url. It is deliberately minimal: a
// status code and the body, nothing streamed.
type slackDecisionRecorder struct {
	status int
	header http.Header
	body   bytes.Buffer
}

func (r *slackDecisionRecorder) Header() http.Header {
	if r.header == nil {
		r.header = http.Header{}
	}
	return r.header
}

func (r *slackDecisionRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }

func (r *slackDecisionRecorder) WriteHeader(status int) { r.status = status }

// errorMessage returns the "error" field of a writeError body, or "".
func (r *slackDecisionRecorder) errorMessage() string {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(r.body.Bytes(), &e)
	return e.Error
}

// decided reports whether the recorded success body describes a request
// that is no longer pending (a partial approval leaves it pending).
func (r *slackDecisionRecorder) decided() bool {
	var ar struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(r.body.Bytes(), &ar)
	return ar.Status != "" && ar.Status != "pending"
}
