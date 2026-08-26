package api

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// --- magic-link access-request approval (Phase 137, BeyondTrust's
// out-of-band approval — the buildable "link" half, no native mobile app) ---
//
// Unlike session-share invites, minting one needs no separate approval
// step: creating an ApprovalInvite already requires CapApprove, so the
// invite IS the delegation, not a request for one. Redemption is
// deliberately split into two calls, unlike the session-share guest page's
// single auto-firing POST on load: a state-changing decision must never be
// triggerable by a mail client's link-prefetcher visiting the URL, which a
// bare GET (or an auto-POST on page load) would be. previewApprovalInvite
// is a safe, non-consuming GET the page loads immediately; redeemApprovalInvite
// is the single-use, state-changing POST, fired only once a human clicks
// Approve or Deny on the rendered page.

type approvalInviteIn struct {
	Email string `json:"email"`
}

// createApprovalInvite mints a magic link for the access request named in
// the {id} path value and emails it. Requires CapApprove: minting one
// delegates the caller's own approve/deny capability to whoever holds the
// resulting link, so only someone who could already decide the request
// directly may hand that off.
func (s *Server) createApprovalInvite(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in approvalInviteIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Email == "" {
		writeError(w, http.StatusUnprocessableEntity, "email is required")
		return
	}
	if !s.shareEmailEnabled() {
		writeError(w, http.StatusServiceUnavailable, "approval invites need PAM_ALERT_EMAIL_* and an absolute PAM_PORTAL_URL configured")
		return
	}
	ar, err := s.store.GetAccessRequest(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	// Four-eyes at CREATION, not just redemption: the "magiclink:<email>"
	// synthetic actor decideAccessRequest sees can never equal a real
	// actor's own string, so that check alone does not stop the REQUESTER
	// from minting an invite addressed to their own inbox and redeeming it
	// themselves — the synthetic string is different from "alice" either
	// way. What actually closes the loophole is refusing the requester the
	// ability to create a delegation for their own request in the first
	// place, mirroring the exact rule decideAccessRequest enforces.
	if ar.Requester == actorFrom(r.Context()) {
		s.audit(r.Context(), "access.decision_denied", fmt.Sprintf("request:%d reason:self-approval-invite", ar.ID))
		writeError(w, http.StatusForbidden, "four-eyes: you cannot create an approval invite for your own access request")
		return
	}
	if ar.Status != "pending" {
		writeError(w, http.StatusConflict, "request already "+ar.Status)
		return
	}
	token, tokenHash, err := newShareToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generating the invite token failed")
		return
	}
	inv := store.ApprovalInvite{
		AccessRequestID: ar.ID,
		Email:           in.Email,
		CreatedBy:       actorFrom(r.Context()),
		TokenHash:       tokenHash,
		ExpiresAt:       time.Now().Add(s.approvalInviteTTL).UTC(),
	}
	if err := s.store.CreateApprovalInvite(r.Context(), &inv); err != nil {
		storeError(w, err)
		return
	}
	if err := s.sendApprovalInviteEmail(r.Context(), inv, ar, token); err != nil {
		s.log.Error("approval invite email failed", "invite", inv.ID, "err", err)
		writeError(w, http.StatusBadGateway, "invite created but the email could not be sent")
		return
	}
	s.audit(r.Context(), "access.invite_created", fmt.Sprintf("invite:%d request:%d email:%s", inv.ID, ar.ID, auditField(inv.Email, 128)))
	writeJSON(w, http.StatusCreated, inv)
}

// listApprovalInvites lists the access request named in the {id} path
// value's magic-link invites (outstanding, consumed and revoked).
func (s *Server) listApprovalInvites(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	invs, err := s.store.ListApprovalInvitesForRequest(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, invs)
}

// revokeApprovalInvite marks the invite named in the {id} path value
// revoked, so a later redemption attempt fails even if the link is still
// within its TTL.
func (s *Server) revokeApprovalInvite(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.RevokeApprovalInvite(r.Context(), id, time.Now()); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "access.invite_revoked", fmt.Sprintf("invite:%d", id))
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

// sendApprovalInviteEmail sends the just-created invite's link. Reuses the
// session-share invite's SMTP settings/air-gap guard verbatim (see
// shareEmailEnabled's doc comment) — the requirement is identical and this
// avoids a second config surface for what is, operationally, the same kind
// of outbound system email.
func (s *Server) sendApprovalInviteEmail(ctx context.Context, inv store.ApprovalInvite, ar *store.AccessRequest, token string) error {
	link := strings.TrimRight(s.portalURL, "/") + "/approve.html?token=" + token
	target := ar.Reason
	if t, err := s.store.GetTarget(ctx, ar.TargetID); err == nil {
		target = t.Name
	}
	subject := "A PAMv1 access request needs your decision"
	body := fmt.Sprintf(`<html><body style="font-family:sans-serif;background:#050705;color:#eaffea;padding:24px">
<p><b>%s</b> is requesting access to <b>%s</b>.</p>
<p>Reason: %s</p>
<p><a href="%s" style="color:#4be0e0">Review and decide</a></p>
<p>This link expires in %d hours and can only be used once.</p>
</body></html>`,
		html.EscapeString(ar.Requester), html.EscapeString(target), html.EscapeString(ar.Reason),
		html.EscapeString(link), int(s.approvalInviteTTL/time.Hour))
	return alert.SendDirect(s.shareSMTPAddr, s.shareSMTPFrom, inv.Email, s.shareSMTPUser, s.shareSMTPPass, subject, body, nil, "")
}

// --- unauthenticated redemption surface (reached from the emailed link's
// approve.html page, NOT from the authenticated portal) ---

type approvalPreviewOut struct {
	Requester string `json:"requester"`
	Target    string `json:"target"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at"`
}

// previewApprovalInvite is GET /api/approval/preview/{token}: a
// safe, non-consuming lookup the redemption page loads immediately, so it
// can show what is being decided before asking for a decision. Never
// consumes the token — a mail client's link-prefetcher visiting this URL
// learns nothing sensitive it could not already infer from the email body,
// and triggers no state change at all.
func (s *Server) previewApprovalInvite(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	inv, err := s.store.GetApprovalInviteByTokenHash(r.Context(), auth.TokenHash(token))
	if err != nil {
		s.authFailed(w, r, "approval-link", "invalid, expired, revoked, or already-used invite link")
		return
	}
	ar, err := s.store.GetAccessRequest(r.Context(), inv.AccessRequestID)
	if err != nil {
		storeError(w, err)
		return
	}
	target := "(deleted target)"
	if t, err := s.store.GetTarget(r.Context(), ar.TargetID); err == nil {
		target = t.Name
	}
	writeJSON(w, http.StatusOK, approvalPreviewOut{
		Requester: ar.Requester, Target: target, Reason: ar.Reason,
		ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
	})
}

type approvalRedeemIn struct {
	Decision string `json:"decision"` // approved | denied
}

// redeemApprovalInvite is POST /api/approval/redeem/{token}: the
// single-use, state-changing call the redemption page fires only once a
// human clicks Approve or Deny. Atomically consumes the token, then decides
// the underlying access request through the exact same decideAccessRequest
// every authenticated approve/deny call uses, with a synthetic
// "magiclink:<email>" actor — a form no authenticated principal's actor
// string can ever take, so a requester who also holds CapApprove cannot
// self-approve through their own emailed link (decideAccessRequest's
// four-eyes check still applies to it, unchanged).
func (s *Server) redeemApprovalInvite(w http.ResponseWriter, r *http.Request) {
	var in approvalRedeemIn
	if !readJSON(w, r, &in) {
		return
	}
	switch in.Decision {
	case "approved", "denied":
	default:
		writeError(w, http.StatusUnprocessableEntity, "decision must be approved or denied")
		return
	}
	token := r.PathValue("token")
	inv, err := s.store.ConsumeApprovalInviteByTokenHash(r.Context(), auth.TokenHash(token), time.Now())
	if err != nil {
		s.authFailed(w, r, "approval-link", "invalid, expired, revoked, or already-used invite link")
		return
	}
	actor := "magiclink:" + inv.Email
	ok := s.decideAccessRequest(w, r, inv.AccessRequestID, in.Decision, actor)
	if ok {
		// Best-effort: the invite is already consumed either way, and the
		// underlying decision has already been written and responded to —
		// this only affects what the invite's OWN record shows a later
		// viewer (e.g. listApprovalInvites), not the access request itself.
		_ = s.store.RecordApprovalInviteDecision(r.Context(), inv.ID, in.Decision)
	}
}
