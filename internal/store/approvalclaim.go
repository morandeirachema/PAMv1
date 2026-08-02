package store

// approvalclaim.go answers the second half of the approval question in one
// place: **may this specific use go ahead, right now?**
//
// `EffectiveApprovalPolicy` (Phase 58) decides whether a target needs an
// approved access request. This decides whether the request that would admit
// the caller is still good at the moment they use it — which is not the same
// question, because time passes between the two.
//
// The gap it closes (Phase 60): the ITSM ticket attached to an access request
// was validated exactly once, when the request was FILED. An approval is valid
// for `PAM_APPROVAL_WINDOW_MIN`, and a scheduled request may sit for days
// waiting for its maintenance window — so a change ticket that is cancelled,
// closed or rejected in the meantime still admitted the session it was supposed
// to authorize. "No privileged access without an approved change ticket" has to
// mean at the moment of access, or it means at the moment of paperwork.
//
// Like the policy fold, this lives here because both `api` and `proxy` reach
// `internal/store` and both enforce this gate — the API (reveal, checkout,
// WinRM run, broker tools), the in-portal viewer, and the SSH, PostgreSQL and
// SQL Server proxies. Five sites re-implementing a use-time check is the
// Phase 38 lesson waiting to happen again.

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ApprovalClaimStore is the slice of the store ClaimApproval needs.
type ApprovalClaimStore interface {
	ActiveApproval(ctx context.Context, requester string, targetID int64, now time.Time) (*AccessRequest, error)
	ConsumeApproval(ctx context.Context, requester string, targetID int64, now time.Time) (ok bool, consumedID int64, err error)
}

// TicketChecker re-checks an ITSM ticket reference. *ticket.Validator satisfies
// it; store deliberately depends on this one-method view rather than importing
// the package, the same way `recording` takes a two-method view of the vault.
type TicketChecker interface {
	Validate(ctx context.Context, ticket string) error
}

// ticketRecheckTimeout bounds the ITSM call made on the connect path. The
// validator has its own client timeout, but this gate runs inside an SSH or
// database handshake the operator is waiting on, so a slow ITSM must fail
// rather than hold the handshake open.
const ticketRecheckTimeout = 5 * time.Second

// ApprovalClaim is the outcome of a use-time approval check.
type ApprovalClaim struct {
	// OK is the only field a caller must honour: false means refuse.
	OK bool
	// ConsumedID names the single-use approval this claim burned (0 when a
	// standing approval admitted the use, or when nothing was consumed).
	ConsumedID int64
	// Ticket is the ITSM reference on the admitting request, if it carries one.
	Ticket string
	// TicketErr is set when the ticket was re-checked and did not pass — the
	// reason to put in the audit trail. A refusal with TicketErr set is a
	// policy refusal, not a missing approval.
	TicketErr error
}

// ClaimApproval performs the use-time approval gate: it finds the approval that
// would admit requester, re-validates its ITSM ticket when a checker is
// configured, and only then consumes it.
//
// ORDER MATTERS. The re-check happens BEFORE the consume, so a single-use
// approval is not burned by a connection that policy then refuses — an operator
// whose ITSM is briefly unreachable keeps the approval they were granted. The
// cost is a small race: with two approvals for the same requester and target,
// the one whose ticket is checked is the one this same selection order would
// consume, but a concurrent connection could take it in between. That trade is
// deliberate — the alternative burns approvals on failures.
//
// FAIL-CLOSED. A ticket that cannot be confirmed is refused, whether the ITSM
// rejected it or simply could not be reached: an unreachable ITSM means the
// gate cannot do its job, and a gate that opens when it cannot do its job is
// not a gate. Deployments that cannot accept that leave the re-check off
// (`PAM_TICKET_REVALIDATE`), where this behaves exactly as it did before.
func ClaimApproval(ctx context.Context, st ApprovalClaimStore, tc TicketChecker, requester string, targetID int64, now time.Time) (ApprovalClaim, error) {
	if st == nil {
		return ApprovalClaim{}, errors.New("store: ClaimApproval needs a store")
	}
	if tc != nil {
		ar, err := st.ActiveApproval(ctx, requester, targetID, now)
		if err != nil {
			return ApprovalClaim{}, fmt.Errorf("store: reading the admitting approval: %w", err)
		}
		if ar != nil && ar.Ticket != "" {
			rctx, cancel := context.WithTimeout(ctx, ticketRecheckTimeout)
			err := tc.Validate(rctx, ar.Ticket)
			cancel()
			if err != nil {
				return ApprovalClaim{Ticket: ar.Ticket, TicketErr: err}, nil
			}
		}
	}
	ok, consumedID, err := st.ConsumeApproval(ctx, requester, targetID, now)
	if err != nil {
		return ApprovalClaim{}, err
	}
	return ApprovalClaim{OK: ok, ConsumedID: consumedID}, nil
}
