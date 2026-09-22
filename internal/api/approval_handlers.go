package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/auditfmt"
	"github.com/morandeirachema/pamv1/internal/auth"
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
	// RecurDays (Phase 120) makes this request, once approved, the anchor of a
	// recurring series: every RecurDays a fresh request is auto-filed with the
	// same requester/target/reason, needing its own approval every time. Zero
	// is a one-off, matching every request before this field existed.
	RecurDays int `json:"recur_days,omitempty"`
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
		if err := s.ticketValidator.Validate(r.Context(), in.Ticket, actorFrom(r.Context())); err != nil {
			s.audit(r.Context(), "access.ticket_rejected", fmt.Sprintf("target:%d ticket:%q reason:%v", in.TargetID, in.Ticket, err))
			writeError(w, http.StatusUnprocessableEntity, "ticket rejected: "+err.Error())
			return
		}
	}
	if in.RecurDays < 0 || in.RecurDays > maxRecurDays {
		writeError(w, http.StatusUnprocessableEntity,
			fmt.Sprintf("recur_days must be between 0 (one-off) and %d", maxRecurDays))
		return
	}
	// Multi-tier chains + scheduled window (Phase 21). RequiredApprovals is the
	// larger of the request's ask and the configured default (at least 1). The
	// window defaults to now → now+approvalWindow; a scheduled request supplies
	// not_before / not_after.
	required := s.approvalsRequired
	if in.Approvals > required {
		required = in.Approvals
	}
	// An ordered chain with a "manager" tier (Phase 256) needs the requester
	// to HAVE one; refusing here, with the reason, beats a request that waits
	// forever for an approval nobody can give.
	if tiers, terr := s.approvalTiersForTarget(r.Context(), in.TargetID); terr != nil {
		storeError(w, terr)
		return
	} else if store.HasManagerTier(tiers) {
		if u, uerr := s.store.GetUserByUsername(r.Context(), actorFrom(r.Context())); uerr != nil || u.Manager == "" {
			writeError(w, http.StatusUnprocessableEntity, "this target's approval chain requires your direct manager's approval, and your identity has no manager set")
			return
		}
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
		RecurDays:         in.RecurDays,
	}
	if err := s.store.CreateAccessRequest(r.Context(), &ar); err != nil {
		storeError(w, err)
		return
	}
	detail := fmt.Sprintf("request:%d target:%d reason:%q ticket:%q approvals_required:%d one_time:%t", ar.ID, ar.TargetID, ar.Reason, ar.Ticket, ar.RequiredApprovals, ar.OneTime)
	if ar.RecurDays > 0 {
		detail += fmt.Sprintf(" recur_days:%d", ar.RecurDays)
	}
	s.audit(r.Context(), "access.request", detail)
	writeJSON(w, http.StatusCreated, ar)
}

// scopedApprovalTargets returns the targets p may decide access requests for
// through safe membership alone (Phase 246): every target in a safe where a
// live membership naming p carries the approve permission. It is one
// subject-indexed read — the same GrantsForSubjects the reach view uses — so
// the decision and the console's "am I an approver anywhere" agree.
func (s *Server) scopedApprovalTargets(ctx context.Context, p *auth.Principal) (map[int64]bool, error) {
	grants, err := s.store.GrantsForSubjects(ctx, auth.GrantSubjects(p))
	if err != nil {
		return nil, err
	}
	out := map[int64]bool{}
	for _, g := range store.LiveSubjectGrants(grants, time.Now()) {
		if g.Via == store.GrantViaSafe && store.GrantPermits(g.Permissions, store.SafePermApprove) {
			out[g.TargetID] = true
		}
	}
	return out, nil
}

// mayDecideRequest reports whether p may decide an access request for
// targetID: the global approve capability, or a live approve membership of
// the target's safe. Four-eyes and the dual-control floor are applied by
// decideAccessRequest either way — a scoped approver is an approver, not an
// exemption.
func (s *Server) mayDecideRequest(ctx context.Context, p *auth.Principal, targetID int64) (bool, error) {
	if p.Can(auth.CapApprove) {
		return true, nil
	}
	scope, err := s.scopedApprovalTargets(ctx, p)
	if err != nil {
		return false, err
	}
	return scope[targetID], nil
}

// qualifiesForCurrentTier reports whether p satisfies the tier this request
// is waiting on (Phase 256). A chain naming "manager" or "user=<name>" IS
// the grant of that one decision right: the requester's manager, or the named
// identity, decides the request at their tier without holding the general
// approve capability — CyberArk's confirmer is not an approver. A request
// with no chain, or a complete one, qualifies nobody this way.
func (s *Server) qualifiesForCurrentTier(ctx context.Context, p *auth.Principal, ar *store.AccessRequest) (bool, error) {
	tiers, err := s.approvalTiersForTarget(ctx, ar.TargetID)
	if err != nil || len(tiers) == 0 {
		return false, err
	}
	// Someone who already approved reached a tier once and keeps the standing
	// to reach the handler — which answers "already approved" (409), the
	// contract every earlier approval path has — rather than a refusal that
	// reads as if they never could.
	for _, a := range splitApprovers(ar.ApprovedBy) {
		if strings.EqualFold(a, p.Name) {
			return true, nil
		}
	}
	q := s.tierQualifier(ctx, ar)
	_, cur, complete := store.TierProgress(tiers, splitApprovers(ar.ApprovedBy), q)
	if complete {
		return false, nil
	}
	return q(p.Name, tiers[cur]), nil
}

// mayDecideRequestFor is mayDecideRequest with the request in hand, so the
// tier path (Phase 256) can be read too.
func (s *Server) mayDecideRequestFor(ctx context.Context, p *auth.Principal, ar *store.AccessRequest) (bool, error) {
	if ok, err := s.mayDecideRequest(ctx, p, ar.TargetID); err != nil || ok {
		return ok, err
	}
	return s.qualifiesForCurrentTier(ctx, p, ar)
}

// requireDecider is the approve/deny routes' authorization since Phase 246,
// which moved them off a CapApprove-only middleware so a scoped approver can
// reach them. A caller with no approval right anywhere is refused as the
// middleware refused them — before any request is looked up, so the route
// discloses nothing about which request ids exist — and one whose right does
// not cover this request's target is refused with the decision vocabulary.
func (s *Server) requireDecider(w http.ResponseWriter, r *http.Request, id int64) bool {
	p := principalFrom(r.Context())
	if p.Can(auth.CapApprove) {
		return true
	}
	scope, err := s.scopedApprovalTargets(r.Context(), p)
	if err != nil {
		storeError(w, err)
		return false
	}
	refuseGeneric := func() bool {
		s.audit(r.Context(), "authz.denied", r.Method+" "+r.URL.Path+" role:"+string(p.Role))
		writeError(w, http.StatusForbidden, "your role does not permit this action")
		return false
	}
	ar, err := s.store.GetAccessRequest(r.Context(), id)
	if err != nil {
		// A caller with no approval right anywhere learns nothing about which
		// ids exist: the refusal is the same one they get for a real id they
		// may not decide.
		if len(scope) == 0 {
			return refuseGeneric()
		}
		storeError(w, err)
		return false
	}
	if scope[ar.TargetID] {
		return true
	}
	// The tier path (Phase 256): the request's current tier may name this
	// caller — the requester's manager, a named identity — who then decides
	// it without the general capability.
	if ok, qerr := s.qualifiesForCurrentTier(r.Context(), p, ar); qerr != nil {
		storeError(w, qerr)
		return false
	} else if ok {
		return true
	}
	if len(scope) == 0 {
		return refuseGeneric()
	}
	s.audit(r.Context(), "access.decision_denied", fmt.Sprintf("request:%d target:%d reason:not-an-approver", ar.ID, ar.TargetID))
	writeError(w, http.StatusForbidden, "you may not decide access requests for this target")
	return false
}

// listAccessRequests lists requests, optionally filtered by ?status=. A caller
// holding CapApprove sees every request; a scoped approver (Phase 246) sees
// only the requests for targets they may decide; anyone else is refused.
func (s *Server) listAccessRequests(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", "pending", "approved", "denied":
	default:
		writeError(w, http.StatusUnprocessableEntity, "status must be pending, approved or denied")
		return
	}
	p := principalFrom(r.Context())
	limit, after := listWindow(r)
	if p.Can(auth.CapApprove) {
		reqs, err := s.store.ListAccessRequests(r.Context(), status, limit, after)
		if err != nil {
			storeError(w, err)
			return
		}
		s.decorateTiers(r.Context(), reqs)
		writeJSON(w, http.StatusOK, reqs)
		return
	}
	scope, err := s.scopedApprovalTargets(r.Context(), p)
	if err != nil {
		storeError(w, err)
		return
	}
	// A caller with no scope may still be the one a request's current tier
	// names (Phase 256); the refusal for a caller with no right at all comes
	// after the filter, once that is known.
	// The window is applied AFTER the filter, so a page is never short just
	// because other safes' requests fell inside it — a short page is how the
	// console's cursor drain knows it has reached the end.
	all, err := s.store.ListAccessRequests(r.Context(), status, 0, after)
	if err != nil {
		storeError(w, err)
		return
	}
	out := make([]store.AccessRequest, 0)
	for _, ar := range all {
		visible := scope[ar.TargetID]
		if !visible {
			if ok, qerr := s.qualifiesForCurrentTier(r.Context(), p, &ar); qerr != nil {
				storeError(w, qerr)
				return
			} else if ok {
				visible = true
			}
		}
		if visible {
			out = append(out, ar)
			s.decorateTiers(r.Context(), out[len(out)-1:])
			if len(out) == limit {
				break
			}
		}
	}
	if len(scope) == 0 && len(out) == 0 {
		s.audit(r.Context(), "authz.denied", r.Method+" "+r.URL.Path+" role:"+string(p.Role))
		writeError(w, http.StatusForbidden, "your role does not permit this action")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// approveAccessRequest approves the access request named in the {id} path value.
func (s *Server) approveAccessRequest(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if !s.requireDecider(w, r, id) {
		return
	}
	in, ok := s.readDecision(w, r)
	if !ok {
		return
	}
	s.decideAccessRequestWith(w, r, id, "approved", actorFrom(r.Context()), in)
}

// approvalDecisionIn is the optional body of an approve, deny or cancel (Phase 274):
// the approver's comment (required when PAM_APPROVAL_COMMENT_REQUIRED) and,
// on an approve, the duration granted in minutes — capped at what the
// request asked for, never extending it.
type approvalDecisionIn struct {
	Comment     string `json:"comment"`
	DurationMin int    `json:"duration_min"`
}

// readDecision reads the optional decision body: absent is the zero value
// (the pre-274 call shape), present must parse and satisfy the comment
// policy.
func (s *Server) readDecision(w http.ResponseWriter, r *http.Request) (approvalDecisionIn, bool) {
	var in approvalDecisionIn
	if r.ContentLength != 0 {
		if !readJSON(w, r, &in) {
			return in, false
		}
	}
	in.Comment = strings.TrimSpace(in.Comment)
	if len(in.Comment) > 500 {
		writeError(w, http.StatusUnprocessableEntity, "comment is limited to 500 characters")
		return in, false
	}
	if s.approvalCommentRequired && in.Comment == "" {
		writeError(w, http.StatusUnprocessableEntity, "a comment is required on every decision (PAM_APPROVAL_COMMENT_REQUIRED)")
		return in, false
	}
	if in.DurationMin < 0 {
		writeError(w, http.StatusUnprocessableEntity, "duration_min must be positive")
		return in, false
	}
	return in, true
}

// commentDetail renders a comment for an audit row, quoted (it is free text).
func commentDetail(c string) string {
	if c == "" {
		return ""
	}
	return " comment:" + auditfmt.Value(c, 200)
}

// cancelAccessRequest ends an APPROVED request before its window closes
// (Phase 274): the request moves to "cancelled", every live session the
// requester holds on that target is cut, and the trail records who, why and
// how many sessions ended. Four-eyes as for a decision: the requester cannot
// cancel their own approval (they can simply stop using it); a comment is
// always required here, because a cancel that ends someone's session must
// say why.
func (s *Server) cancelAccessRequest(w http.ResponseWriter, r *http.Request) {
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
		s.audit(r.Context(), "access.decision_denied", fmt.Sprintf("request:%d reason:self-cancel", ar.ID))
		writeError(w, http.StatusForbidden, "four-eyes: you cannot cancel your own approved request")
		return
	}
	in, ok := s.readDecision(w, r)
	if !ok {
		return
	}
	if in.Comment == "" {
		writeError(w, http.StatusUnprocessableEntity, "a comment is required to cancel an approved request")
		return
	}
	if ar.Status != "approved" {
		writeError(w, http.StatusConflict, "only an approved request can be cancelled (this one is "+ar.Status+")")
		return
	}
	if err := s.store.CancelAccessRequest(r.Context(), ar.ID, approver, time.Now()); err != nil {
		storeError(w, err)
		return
	}
	_ = s.store.NoteAccessRequest(r.Context(), ar.ID, approver, "cancelled: "+in.Comment)
	killed := 0
	target, terr := s.store.GetTarget(r.Context(), ar.TargetID)
	if terr == nil && s.sessions != nil {
		killed = s.sessions.KillByActorTarget(ar.Requester, target.Name)
	}
	s.audit(r.Context(), "access.cancel", fmt.Sprintf("request:%d requester:%s target:%d sessions_killed:%d", ar.ID, ar.Requester, ar.TargetID, killed)+commentDetail(in.Comment))
	s.alerter.Notify(r.Context(), alert.Event{Type: "access.cancel", Actor: approver,
		Detail: fmt.Sprintf("request:%d requester:%s target:%d sessions_killed:%d", ar.ID, ar.Requester, ar.TargetID, killed), Remote: r.RemoteAddr, Time: time.Now()})
	ar.Status = "cancelled"
	ar.Approver = approver
	writeJSON(w, http.StatusOK, ar)
}

// SweepApprovalTimeouts runs the approval-timeout sweep once, as of now, and
// reports how many pending requests expired — what the scheduler calls
// every tick, exposed so a test (or an operator's one-off) can run it.
func (s *Server) SweepApprovalTimeouts(ctx context.Context, now time.Time) int {
	return s.expirePendingAccessRequests(ctx, now)
}

// expirePendingAccessRequests is the approval-timeout sweep (Phase 274): a
// pending request nobody decided within ApprovalTimeout becomes "expired",
// each one audited and alerted, so a request does not sit open for days
// waiting for an approver who never saw it. Returns how many expired.
func (s *Server) expirePendingAccessRequests(ctx context.Context, now time.Time) int {
	if s.approvalTimeout <= 0 {
		return 0
	}
	expired, err := s.store.ExpirePendingAccessRequests(ctx, now.Add(-s.approvalTimeout))
	if err != nil {
		s.log.Error("approval timeout sweep", "err", err)
		return 0
	}
	for _, ar := range expired {
		s.auditAs(ctx, "system", "access.expired", fmt.Sprintf("request:%d requester:%s target:%d timeout_min:%d", ar.ID, ar.Requester, ar.TargetID, int(s.approvalTimeout.Minutes())))
		s.alerter.Notify(ctx, alert.Event{Type: "access.expired", Actor: "system",
			Detail: fmt.Sprintf("request:%d requester:%s target:%d", ar.ID, ar.Requester, ar.TargetID), Time: now})
	}
	return len(expired)
}

// denyAccessRequest denies the access request named in the {id} path value.
func (s *Server) denyAccessRequest(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if !s.requireDecider(w, r, id) {
		return
	}
	in, ok := s.readDecision(w, r)
	if !ok {
		return
	}
	s.decideAccessRequestWith(w, r, id, "denied", actorFrom(r.Context()), in)
}

// decideAccessRequest records approver's decision on the access request id,
// enforcing the 4-eyes rule (approver must differ from the requester) and
// that only pending requests can be decided. id and approver are explicit
// parameters — not derived from the URL/request context internally — so the
// magic-link redemption path (Phase 137) can call this with an access
// request id read from an already-consumed ApprovalInvite and a synthetic
// "magiclink:<email>" approver, an actor form no authenticated principal
// can ever present, sharing this exact four-eyes check rather than
// reimplementing it. Returns whether the decision was actually recorded
// (false on every refusal/error path, which has already written its own
// response) — the magic-link redemption handler uses this to know whether
// to record an outcome on the invite, since the underlying request may
// already have been decided by someone else between invite creation and
// redemption.
func (s *Server) decideAccessRequest(w http.ResponseWriter, r *http.Request, id int64, decision, approver string) bool {
	return s.decideAccessRequestWith(w, r, id, decision, approver, approvalDecisionIn{})
}

// decideAccessRequestWith is decideAccessRequest with the Phase 274 body:
// the comment is noted on the request and written to the audit row, and a
// granted duration shortens the approved window.
func (s *Server) decideAccessRequestWith(w http.ResponseWriter, r *http.Request, id int64, decision, approver string, in approvalDecisionIn) bool {
	ar, err := s.store.GetAccessRequest(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return false
	}
	if ar.Requester == approver {
		s.audit(r.Context(), "access.decision_denied", fmt.Sprintf("request:%d reason:self-approval", ar.ID))
		writeError(w, http.StatusForbidden, "four-eyes: you cannot decide your own access request")
		return false
	}
	if ar.Status != "pending" {
		writeError(w, http.StatusConflict, "request already "+ar.Status)
		return false
	}

	// A single deny is final.
	if decision == "denied" {
		if err := s.store.DecideAccessRequest(r.Context(), ar.ID, "denied", approver, time.Now()); err != nil {
			storeError(w, err)
			return false
		}
		if in.Comment != "" {
			_ = s.store.NoteAccessRequest(r.Context(), ar.ID, approver, "denied: "+in.Comment)
			s.audit(r.Context(), "access.comment", fmt.Sprintf("request:%d approver:%s", ar.ID, approver)+commentDetail(in.Comment))
		}
		s.notifyDecision(r, "access.deny", approver, ar)
		ar.Status = "denied"
		ar.Approver = approver
		writeJSON(w, http.StatusOK, ar)
		return true
	}

	// Approve: accumulate DISTINCT approvers (Phase 21 multi-tier chains). The
	// request is granted only once RequiredApprovals of them have approved.
	approvers := splitApprovers(ar.ApprovedBy)
	for _, a := range approvers {
		if strings.EqualFold(a, approver) {
			writeError(w, http.StatusConflict, "you have already approved this request")
			return false
		}
	}
	// An ordered chain (Phase 256): this approval counts only if the approver
	// qualifies for the CURRENT tier — the first unsatisfied level. Refused
	// otherwise, and not recorded, so a level-2 approver cannot pre-approve
	// past level 1. The chain is re-read from the policy in force, as the
	// dual-control floor is below, so a chain raised while a request waits
	// binds it at the next approval.
	tiers, terr := s.approvalTiersForTarget(r.Context(), ar.TargetID)
	if terr != nil {
		storeError(w, terr)
		return false
	}
	qualifies := s.tierQualifier(r.Context(), ar)
	if len(tiers) > 0 {
		if _, cur, _ := store.TierProgress(tiers, approvers, qualifies); cur < len(tiers) && !qualifies(approver, tiers[cur]) {
			s.audit(r.Context(), "access.decision_denied", fmt.Sprintf("request:%d approver:%s reason:not-in-current-tier tier:%d", ar.ID, approver, cur+1))
			writeError(w, http.StatusForbidden, "this request is waiting on tier "+strconv.Itoa(cur+1)+" ("+tiers[cur].String()+"), which you do not satisfy")
			return false
		}
	}
	approvedAs := appendApprovedAs(ar, len(approvers), principalFrom(r.Context()))
	approvers = append(approvers, approver)
	required := ar.RequiredApprovals
	if required < 1 {
		required = 1
	}
	chainComplete := true
	if len(tiers) > 0 {
		ar.Tiers, _, chainComplete = store.TierProgress(tiers, approvers, qualifies)
	}
	// The safe's dual-control floor is re-read HERE, not just trusted from the
	// number stamped on the request at creation (Phase 58). A floor that only
	// applied at request time would be trivially bypassable: file the request
	// while the target sits outside the safe (or while the floor is lower), and
	// collect the old number of approvals afterwards. Re-reading means raising a
	// safe's floor immediately binds every request still in flight.
	if floor, ferr := s.approvalFloorForTarget(r.Context(), ar.TargetID); ferr != nil {
		storeError(w, ferr)
		return false
	} else if floor > required {
		required = floor
	}
	joined := strings.Join(approvers, ",")
	if in.Comment != "" {
		_ = s.store.NoteAccessRequest(r.Context(), ar.ID, approver, "approved: "+in.Comment)
	}
	if chainComplete && len(approvers) >= required {
		now := time.Now()
		if err := s.store.SetApprovalState(r.Context(), ar.ID, joined, approvedAs, "approved", approver, &now); err != nil {
			storeError(w, err)
			return false
		}
		// The approver's duration (Phase 274) shortens the window the request
		// asked for; it can never extend it — the request is the ceiling.
		granted := ""
		if in.DurationMin > 0 {
			until := now.Add(time.Duration(in.DurationMin) * time.Minute).UTC()
			if until.Before(ar.ExpiresAt) {
				if err := s.store.ShortenAccessRequest(r.Context(), ar.ID, until); err != nil {
					storeError(w, err)
					return false
				}
				ar.ExpiresAt = until
				granted = " granted_until:" + until.Format(time.RFC3339)
			}
		}
		s.audit(r.Context(), "access.approve", fmt.Sprintf("request:%d requester:%s target:%d approvers:%d/%d", ar.ID, ar.Requester, ar.TargetID, len(approvers), required)+granted+commentDetail(in.Comment))
		s.notifyDecision(r, "access.approve", approver, ar)
		ar.Status = "approved"
		ar.Approver = approver
		// A recurring anchor's clock starts on APPROVAL, not on the original
		// request (Phase 120) — an approval that takes days to arrive must not
		// make the first recurrence fire immediately the moment it lands.
		if ar.RecurDays > 0 {
			next := now.UTC().AddDate(0, 0, ar.RecurDays)
			if err := s.store.SetAccessRequestNextRun(r.Context(), ar.ID, next); err != nil {
				storeError(w, err)
				return false
			}
			ar.NextRunAt = &next
		}
	} else {
		if err := s.store.SetApprovalState(r.Context(), ar.ID, joined, approvedAs, "pending", "", nil); err != nil {
			storeError(w, err)
			return false
		}
		s.audit(r.Context(), "access.approve_partial", fmt.Sprintf("request:%d target:%d approver:%s approvals:%d/%d", ar.ID, ar.TargetID, approver, len(approvers), required)+commentDetail(in.Comment))
	}
	ar.ApprovedBy, ar.ApprovedAs = joined, approvedAs
	writeJSON(w, http.StatusOK, ar)
	return true
}

// stopAccessRequestRecurrence ends a recurring anchor's series — the stop
// button an operator reaches for first when a periodic access need ends, so
// it has to just work (Phase 120, mirroring closeCampaign's role for
// campaigns). Idempotent: stopping an already one-off request, or one that
// was never approved, succeeds either way — the caller's intent ("this
// should not recur any more") is already satisfied. Gated the same as an
// approve/deny decision: ending a series is the same class of call as making
// one.
func (s *Server) stopAccessRequestRecurrence(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	ar, err := s.store.GetAccessRequest(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	if err := s.store.StopAccessRequestRecurrence(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "access.recurrence_stopped", fmt.Sprintf("request:%d target:%d", ar.ID, ar.TargetID))
	ar.RecurDays, ar.NextRunAt = 0, nil
	writeJSON(w, http.StatusOK, ar)
}

// approvalTiersForTarget is the ordered approval chain in force for a target
// (Phase 256): its own, else its safe's, else none — parsed, and fail-closed
// on an unparsable stored chain (impossible through the API).
func (s *Server) approvalTiersForTarget(ctx context.Context, targetID int64) ([]store.ApprovalTier, error) {
	t, err := s.store.GetTarget(ctx, targetID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p, err := s.approvalPolicyFor(ctx, t)
	if err != nil {
		return nil, err
	}
	tiers, perr := store.ParseApprovalTiers(p.Tiers)
	if perr != nil {
		return nil, fmt.Errorf("target %d carries an unreadable approval chain: %w", targetID, perr)
	}
	return tiers, nil
}

// tierQualifier answers whether an approver satisfies a tier for a request
// filed by requester: the requester's own manager for a manager tier, the
// named identity for a user tier, and — for a role tier — an identity
// holding that built-in role or custom profile, read from the user row or,
// for a directory identity with no row that is the caller itself, from the
// principal in hand. A PAST approver with no row is read from what the
// request recorded when they approved (AccessRequest.ApprovedAs, Phase 264):
// without it such an approver satisfied a tier in the response to their own
// approval and never again, and the chain could not complete.
func (s *Server) tierQualifier(ctx context.Context, ar *store.AccessRequest) func(approver string, tier store.ApprovalTier) bool {
	p := principalFrom(ctx)
	requester := ar.Requester
	heldAt := approvedAsByApprover(ar)
	return func(approver string, tier store.ApprovalTier) bool {
		switch tier.Kind {
		case store.TierManager:
			u, err := s.store.GetUserByUsername(ctx, requester)
			return err == nil && u.Manager != "" && strings.EqualFold(u.Manager, approver)
		case store.TierUser:
			return strings.EqualFold(tier.Name, approver)
		case store.TierRole:
			if u, err := s.store.GetUserByUsername(ctx, approver); err == nil {
				return u.Role == tier.Name
			}
			if p != nil && strings.EqualFold(p.Name, approver) {
				return auth.SubjectMatches(p, "role", tier.Name)
			}
			for _, role := range heldAt[strings.ToLower(approver)] {
				if role == tier.Name {
					return true
				}
			}
		}
		return false
	}
}

// approvedAsByApprover reads a request's role snapshots: approver (lower-cased)
// → the roles recorded when they approved. Approvals from before Phase 264
// have none and are simply absent.
func approvedAsByApprover(ar *store.AccessRequest) map[string][]string {
	names, held := splitApprovers(ar.ApprovedBy), strings.Split(ar.ApprovedAs, ",")
	out := map[string][]string{}
	for i, n := range names {
		if i < len(held) && held[i] != "" {
			out[strings.ToLower(n)] = strings.Split(held[i], "|")
		}
	}
	return out
}

// appendApprovedAs extends a request's role snapshots for one more approver,
// keeping the list parallel to approvers (legacy approvals pad as empty).
func appendApprovedAs(ar *store.AccessRequest, priorApprovers int, p *auth.Principal) string {
	held := strings.Split(ar.ApprovedAs, ",")
	if ar.ApprovedAs == "" {
		held = nil
	}
	for len(held) < priorApprovers {
		held = append(held, "")
	}
	var roles []string
	if p != nil {
		for _, r := range p.RoleNames() {
			if r != "" && !strings.ContainsAny(r, ",|") {
				roles = append(roles, r)
			}
		}
	}
	return strings.Join(append(held[:priorApprovers], strings.Join(roles, "|")), ",")
}

// decorateTiers fills in each request's chain progress when its target has
// one, for approvers and the console; a target with no chain leaves the
// field absent.
func (s *Server) decorateTiers(ctx context.Context, reqs []store.AccessRequest) {
	for i := range reqs {
		tiers, err := s.approvalTiersForTarget(ctx, reqs[i].TargetID)
		if err != nil || len(tiers) == 0 {
			continue
		}
		reqs[i].Tiers, _, _ = store.TierProgress(tiers, splitApprovers(reqs[i].ApprovedBy), s.tierQualifier(ctx, &reqs[i]))
	}
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
	claim, err := s.claimApproval(ctx, actorFrom(ctx), t)
	if err != nil {
		return false, err
	}
	return claim.OK, nil
}

// claimApproval runs the shared use-time approval gate for target and audits
// its outcome: a burned single-use approval (access.consumed) and a ticket that
// no longer validates (access.ticket_revoked — the ITSM said no, or could not
// be reached, at the moment access was used rather than when it was requested).
// Callers still decide what a refusal means for their protocol.
func (s *Server) claimApproval(ctx context.Context, actor string, t *store.Target) (store.ApprovalClaim, error) {
	claim, err := store.ClaimApproval(ctx, s.store, s.ticketRechecker(), actor, t.ID, time.Now())
	if err != nil {
		return claim, err
	}
	if claim.ConsumedID != 0 {
		s.audit(ctx, "access.consumed", fmt.Sprintf("request:%d target:%s", claim.ConsumedID, t.Name))
	}
	if claim.TicketErr != nil {
		s.audit(ctx, "access.ticket_revoked",
			fmt.Sprintf("target:%s ticket:%q reason:%v", t.Name, claim.Ticket, claim.TicketErr))
	}
	return claim, nil
}

// ticketRechecker returns the validator to re-check tickets with at use time,
// or nil when the re-check is off. Returning nil (rather than a disabled
// validator) is what keeps the gate free of an extra store read and an ITSM
// round trip on every connect in the default configuration.
func (s *Server) ticketRechecker() store.TicketChecker {
	if !s.revalidateTicket || !s.ticketValidator.Enabled() {
		return nil
	}
	return s.ticketValidator
}
