package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/store"
)

// --- access-request approval workflow (4-eyes) ---

type accessRequestIn struct {
	TargetID int64  `json:"target_id"`
	Reason   string `json:"reason"`
	Ticket   string `json:"ticket"`
	// Phase 21: multi-tier chains + scheduled windows. Approvals asks for more
	// than the configured minimum distinct approvers; NotBefore/NotAfter schedule
	// a maintenance window (the approval is only active between them).
	Approvals int        `json:"approvals,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	NotAfter  *time.Time `json:"not_after,omitempty"`
	// OneTime (Phase 26) asks for a single-use approval: the first privileged
	// use it admits consumes it. PAM_ACCESS_ONE_TIME forces it on every request.
	OneTime bool `json:"one_time,omitempty"`
}

// createAccessRequest files a request to connect to a target. The requester is
// the caller; approval must come from a different principal (see approve/deny).
func (s *Server) createAccessRequest(w http.ResponseWriter, r *http.Request) {
	var in accessRequestIn
	if !readJSON(w, r, &in) {
		return
	}
	if _, err := s.store.GetTarget(r.Context(), in.TargetID); err != nil {
		storeError(w, err)
		return
	}
	// Mandatory reason code (Phase 21), when configured.
	if s.requireReason && in.Reason == "" {
		writeError(w, http.StatusUnprocessableEntity, "a reason is required for access requests")
		return
	}
	// ITSM / ticketing gate (Phase 20): require and/or validate a change ticket
	// before the request is created; the ticket is recorded in the audit trail.
	if s.requireTicket && in.Ticket == "" {
		writeError(w, http.StatusUnprocessableEntity, "a change/incident ticket is required for access requests")
		return
	}
	if in.Ticket != "" && s.ticketValidator.Enabled() {
		if err := s.ticketValidator.Validate(r.Context(), in.Ticket); err != nil {
			s.audit(r.Context(), "access.ticket_rejected", fmt.Sprintf("target:%d ticket:%q reason:%v", in.TargetID, in.Ticket, err))
			writeError(w, http.StatusUnprocessableEntity, "ticket rejected: "+err.Error())
			return
		}
	}
	// Multi-tier chains + scheduled window (Phase 21). RequiredApprovals is the
	// larger of the request's ask and the configured default (at least 1). The
	// window defaults to now → now+approvalWindow; a scheduled request supplies
	// not_before / not_after.
	required := s.approvalsRequired
	if in.Approvals > required {
		required = in.Approvals
	}
	// The safe's dual-control floor (Phase 58) raises the bar for every target
	// in it, so a requester cannot ask for fewer approvers than the safe demands.
	floor, ferr := s.approvalFloorForTarget(r.Context(), in.TargetID)
	if ferr != nil {
		storeError(w, ferr)
		return
	}
	if floor > required {
		required = floor
	}
	if required < 1 {
		required = 1
	}
	expires := time.Now().Add(s.rt().approvalWindow).UTC()
	if in.NotAfter != nil {
		expires = in.NotAfter.UTC()
	}
	ar := store.AccessRequest{
		Requester:         actorFrom(r.Context()),
		TargetID:          in.TargetID,
		Reason:            in.Reason,
		Status:            "pending",
		ExpiresAt:         expires,
		Ticket:            in.Ticket,
		RequiredApprovals: required,
		NotBefore:         in.NotBefore,
		OneTime:           in.OneTime || s.oneTimeAccess,
	}
	if err := s.store.CreateAccessRequest(r.Context(), &ar); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "access.request", fmt.Sprintf("request:%d target:%d reason:%q ticket:%q approvals_required:%d one_time:%t", ar.ID, ar.TargetID, ar.Reason, ar.Ticket, ar.RequiredApprovals, ar.OneTime))
	writeJSON(w, http.StatusCreated, ar)
}

// listAccessRequests lists requests, optionally filtered by ?status=.
func (s *Server) listAccessRequests(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", "pending", "approved", "denied":
	default:
		writeError(w, http.StatusUnprocessableEntity, "status must be pending, approved or denied")
		return
	}
	limit, after := listWindow(r)
	reqs, err := s.store.ListAccessRequests(r.Context(), status, limit, after)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, reqs)
}

// approveAccessRequest approves the access request named in the {id} path value.
func (s *Server) approveAccessRequest(w http.ResponseWriter, r *http.Request) {
	s.decideAccessRequest(w, r, "approved")
}

// denyAccessRequest denies the access request named in the {id} path value.
func (s *Server) denyAccessRequest(w http.ResponseWriter, r *http.Request) {
	s.decideAccessRequest(w, r, "denied")
}

// decideAccessRequest records an approver's decision, enforcing the 4-eyes rule
// (the approver must differ from the requester) and that only pending requests
// can be decided.
func (s *Server) decideAccessRequest(w http.ResponseWriter, r *http.Request, decision string) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	ar, err := s.store.GetAccessRequest(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	approver := actorFrom(r.Context())
	if ar.Requester == approver {
		s.audit(r.Context(), "access.decision_denied", fmt.Sprintf("request:%d reason:self-approval", ar.ID))
		writeError(w, http.StatusForbidden, "four-eyes: you cannot decide your own access request")
		return
	}
	if ar.Status != "pending" {
		writeError(w, http.StatusConflict, "request already "+ar.Status)
		return
	}

	// A single deny is final.
	if decision == "denied" {
		if err := s.store.DecideAccessRequest(r.Context(), ar.ID, "denied", approver, time.Now()); err != nil {
			storeError(w, err)
			return
		}
		s.notifyDecision(r, "access.deny", approver, ar)
		ar.Status = "denied"
		ar.Approver = approver
		writeJSON(w, http.StatusOK, ar)
		return
	}

	// Approve: accumulate DISTINCT approvers (Phase 21 multi-tier chains). The
	// request is granted only once RequiredApprovals of them have approved.
	approvers := splitApprovers(ar.ApprovedBy)
	for _, a := range approvers {
		if strings.EqualFold(a, approver) {
			writeError(w, http.StatusConflict, "you have already approved this request")
			return
		}
	}
	approvers = append(approvers, approver)
	required := ar.RequiredApprovals
	if required < 1 {
		required = 1
	}
	// The safe's dual-control floor is re-read HERE, not just trusted from the
	// number stamped on the request at creation (Phase 58). A floor that only
	// applied at request time would be trivially bypassable: file the request
	// while the target sits outside the safe (or while the floor is lower), and
	// collect the old number of approvals afterwards. Re-reading means raising a
	// safe's floor immediately binds every request still in flight.
	if floor, ferr := s.approvalFloorForTarget(r.Context(), ar.TargetID); ferr != nil {
		storeError(w, ferr)
		return
	} else if floor > required {
		required = floor
	}
	joined := strings.Join(approvers, ",")
	if len(approvers) >= required {
		now := time.Now()
		if err := s.store.SetApprovalState(r.Context(), ar.ID, joined, "approved", approver, &now); err != nil {
			storeError(w, err)
			return
		}
		s.audit(r.Context(), "access.approve", fmt.Sprintf("request:%d requester:%s target:%d approvers:%d/%d", ar.ID, ar.Requester, ar.TargetID, len(approvers), required))
		s.notifyDecision(r, "access.approve", approver, ar)
		ar.Status = "approved"
		ar.Approver = approver
	} else {
		if err := s.store.SetApprovalState(r.Context(), ar.ID, joined, "pending", "", nil); err != nil {
			storeError(w, err)
			return
		}
		s.audit(r.Context(), "access.approve_partial", fmt.Sprintf("request:%d target:%d approver:%s approvals:%d/%d", ar.ID, ar.TargetID, approver, len(approvers), required))
	}
	ar.ApprovedBy = joined
	writeJSON(w, http.StatusOK, ar)
}

// splitApprovers parses a comma-joined approver set into a trimmed, non-empty
// slice.
func splitApprovers(s string) []string {
	var out []string
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// notifyDecision audits nothing (the caller audits) but fires the real-time
// alert for a final approve/deny decision.
func (s *Server) notifyDecision(r *http.Request, action, approver string, ar *store.AccessRequest) {
	if action == "access.deny" {
		s.audit(r.Context(), "access.deny", fmt.Sprintf("request:%d requester:%s target:%d", ar.ID, ar.Requester, ar.TargetID))
	}
	s.alerter.Notify(r.Context(), alert.Event{
		Type: action, Actor: approver,
		Detail: fmt.Sprintf("request:%d requester:%s target:%d", ar.ID, ar.Requester, ar.TargetID),
		Remote: r.RemoteAddr, Time: time.Now(),
	})
}

// --- enforcement ---

// approvalFloorForTarget returns the minimum distinct approvers the target's
// safe demands (0 = none). It loads the target, so a caller holding only an id
// — the approval-decision path — can apply the same policy the connect gates
// do. A missing target is not an error here: the request outlives its target,
// and refusing to decide a request whose target was deleted would leave it
// stuck pending forever; the connect gate is what enforces access anyway.
func (s *Server) approvalFloorForTarget(ctx context.Context, targetID int64) (int, error) {
	t, err := s.store.GetTarget(ctx, targetID)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	p, err := s.approvalPolicyFor(ctx, t)
	if err != nil {
		return 0, err
	}
	return p.MinApprovers, nil
}

// approvalPolicyFor returns the approval requirement binding a target: the
// global OT policy, the target's own flag, and — since Phase 58 — the policy of
// the safe it belongs to, whichever is strictest. The error is a store failure
// reading that safe; the returned policy is fail-closed (Required) so a caller
// that mishandles the error still denies.
func (s *Server) approvalPolicyFor(ctx context.Context, t *store.Target) (store.ApprovalPolicy, error) {
	return store.EffectiveApprovalPolicy(ctx, s.store, t, s.rt().approvalRequired)
}

// requireApprovalFor reports whether connecting to target needs an approved
// access request. An error reading the safe policy is reported as "required" —
// unknown policy is never treated as no policy.
func (s *Server) requireApprovalFor(ctx context.Context, t *store.Target) (bool, error) {
	p, err := s.approvalPolicyFor(ctx, t)
	return p.Required, err
}

// enforceApproval reports whether the caller may perform a privileged use of
// target (connect, WinRM run, reveal, checkout, broker tool call) under the
// approval policy. Break-glass bypasses (emergency access is already loud).
// This is a USE, not a status check: a single-use approval that admits the
// caller is consumed here (audited access.consumed) and admits nothing further
// — status-only checks must call HasActiveApproval instead.
func (s *Server) enforceApproval(ctx context.Context, t *store.Target) (bool, error) {
	required, err := s.requireApprovalFor(ctx, t)
	if err != nil {
		return false, err
	}
	if !required {
		return true, nil
	}
	if principalFrom(ctx).BreakGlass {
		return true, nil
	}
	ok, consumedID, err := s.store.ConsumeApproval(ctx, actorFrom(ctx), t.ID, time.Now())
	if err != nil {
		return false, err
	}
	if consumedID != 0 {
		s.audit(ctx, "access.consumed", fmt.Sprintf("request:%d target:%s", consumedID, t.Name))
	}
	return ok, nil
}
