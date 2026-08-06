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
	ActiveApprovals(ctx context.Context, requester string, targetID int64, now time.Time, limit int) ([]AccessRequest, error)
	ConsumeApproval(ctx context.Context, requester string, targetID int64, now time.Time) (ok bool, consumedID int64, err error)
	ConsumeApprovalByID(ctx context.Context, id int64, requester string, targetID int64, now time.Time) (ok bool, err error)
}

// TicketChecker re-checks an ITSM ticket reference. *ticket.Validator satisfies
// it; store deliberately depends on this one-method view rather than importing
// the package, the same way `recording` takes a two-method view of the vault.
type TicketChecker interface {
	Validate(ctx context.Context, ticket string) error
}

// ticketRecheckTimeout bounds the ITSM calls made on the connect path. The
// validator has its own client timeout, but this gate runs inside an SSH or
// database handshake the operator is waiting on, so a slow ITSM must fail
// rather than hold the handshake open. It is a budget for the WHOLE claim, not
// per candidate: walking several approvals must not multiply the wait an
// operator sees.
const ticketRecheckTimeout = 5 * time.Second

// maxApprovalCandidates caps how many approvals one claim will consider. A
// requester normally has one live approval for a target; several is unusual and
// dozens is a sign of something else wrong. The cap keeps the worst case — an
// ITSM round trip per candidate — bounded, and the shared deadline above stops
// it dead regardless.
const maxApprovalCandidates = 8

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

// ClaimApproval performs the use-time approval gate: it walks the approvals
// that could admit requester, re-validates each one's ITSM ticket when a
// checker is configured, and consumes THE ONE IT JUST CHECKED.
//
// ORDER MATTERS. The re-check happens BEFORE the consume, so a single-use
// approval is not burned by a connection that policy then refuses — an operator
// whose ITSM is briefly unreachable keeps the approval they were granted.
//
// IT MUST BE THE SAME APPROVAL (Phase 60a). Phase 60 peeked at the front-runner
// and then called ConsumeApproval, which picked its own. Two connections racing
// each validated the same good ticket, and the second one's consume took the
// approval BEHIND it — whose change ticket had been cancelled and was never put
// to the ITSM at all. The gate opened on a ticket it had not checked. Claiming
// the inspected approval by id closes that: ConsumeApprovalByID either burns
// the approval whose ticket just passed or reports that somebody else got there
// first, in which case the loop moves to the next candidate and checks that
// one's ticket properly.
//
// A REFUSED CANDIDATE IS NOT A REFUSED USE. Walking the list also fixes the
// mirror-image bug: one approval with a cancelled ticket used to shadow every
// valid approval behind it, permanently, because the fold refused before
// consuming and so could never clear it — a third party who got a change
// cancelled could lock an operator out for the rest of the window. A candidate
// that fails is skipped, not fatal; the use is refused only when NO candidate
// passes, and the reason reported is the last one's.
//
// FAIL-CLOSED. A ticket that cannot be confirmed is refused, whether the ITSM
// rejected it or simply could not be reached: an unreachable ITSM means the
// gate cannot do its job, and a gate that opens when it cannot do its job is
// not a gate. The whole walk shares one `ticketRecheckTimeout` budget, so an
// ITSM that hangs refuses instead of holding a handshake open per candidate.
// Deployments that cannot accept that leave the re-check off
// (`PAM_TICKET_REVALIDATE`), where this behaves exactly as it did before.
func ClaimApproval(ctx context.Context, st ApprovalClaimStore, tc TicketChecker, requester string, targetID int64, now time.Time) (ApprovalClaim, error) {
	if st == nil {
		return ApprovalClaim{}, errors.New("store: ClaimApproval needs a store")
	}
	if tc == nil {
		// No re-check configured: there is nothing to inspect first, so the
		// store's own selection is the claim, exactly as before Phase 60.
		ok, consumedID, err := st.ConsumeApproval(ctx, requester, targetID, now)
		if err != nil {
			return ApprovalClaim{}, err
		}
		return ApprovalClaim{OK: ok, ConsumedID: consumedID}, nil
	}
	cands, err := st.ActiveApprovals(ctx, requester, targetID, now, maxApprovalCandidates)
	if err != nil {
		return ApprovalClaim{}, fmt.Errorf("store: reading the admitting approvals: %w", err)
	}
	rctx, cancel := context.WithTimeout(ctx, ticketRecheckTimeout)
	defer cancel()
	var lastTicket string
	var lastErr error
	for _, ar := range cands {
		// An approval with no ticket was never gated by one, so there is nothing
		// to re-check; it admits as it always did.
		if ar.Ticket != "" {
			if err := tc.Validate(rctx, ar.Ticket); err != nil {
				lastTicket, lastErr = ar.Ticket, err
				continue
			}
		}
		ok, err := st.ConsumeApprovalByID(ctx, ar.ID, requester, targetID, now)
		if err != nil {
			return ApprovalClaim{}, err
		}
		if !ok {
			continue // somebody else claimed it between the read and here
		}
		// A standing approval is not burned, so it reports no consumed id — the
		// caller's audit line is about a single-use approval being spent.
		consumed := ar.ID
		if !ar.OneTime {
			consumed = 0
		}
		return ApprovalClaim{OK: true, ConsumedID: consumed, Ticket: ar.Ticket}, nil
	}
	return ApprovalClaim{Ticket: lastTicket, TicketErr: lastErr}, nil
}
