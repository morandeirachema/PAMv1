package store_test

// approvalclaim_candidates_test.go covers Phase 60a: the use-time gate must
// consume THE APPROVAL WHOSE TICKET IT CHECKED.
//
// Phase 60 inspected the front-runner and then called ConsumeApproval, which
// made its own selection. Two things followed. Two connections racing each
// validated the same good ticket, and the second one's consume took the
// approval BEHIND it — whose change had been cancelled and whose ticket was
// never put to the ITSM at all, so the gate opened on a ticket it had not
// checked. And in the other direction, a single approval with a cancelled
// ticket shadowed every valid approval behind it forever, because the fold
// refused before consuming and so could never clear it: anyone who could get a
// change cancelled could lock an operator out for the rest of their window.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// recordingChecker fails the tickets named in `bad`, records every ticket it
// was asked about and the deadline it was asked under, and can be made slow
// enough to hold a claim open while another one runs.
type recordingChecker struct {
	mu        sync.Mutex
	bad       map[string]bool
	seen      []string
	deadlines []time.Time
	delay     time.Duration
}

// Validate answers for one ticket, the way an ITSM connector would.
func (c *recordingChecker) Validate(ctx context.Context, ticket string) error {
	c.mu.Lock()
	c.seen = append(c.seen, ticket)
	if dl, ok := ctx.Deadline(); ok {
		c.deadlines = append(c.deadlines, dl)
	}
	bad, delay := c.bad[ticket], c.delay
	c.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if bad {
		return fmt.Errorf("change %s is cancelled", ticket)
	}
	return nil
}

// asked returns the tickets the checker was given, in order.
func (c *recordingChecker) asked() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.seen...)
}

// approve seeds an approved access request straight into the store.
func approve(t *testing.T, st store.Store, targetID int64, ticket string, oneTime bool) *store.AccessRequest {
	t.Helper()
	ar := &store.AccessRequest{
		Requester: "alice", TargetID: targetID, Status: "approved",
		ExpiresAt: time.Now().Add(time.Hour), Ticket: ticket, OneTime: oneTime,
	}
	if err := st.CreateAccessRequest(context.Background(), ar); err != nil {
		t.Fatal(err)
	}
	return ar
}

// seedTarget creates the target the approvals are for.
func seedTarget(t *testing.T, st store.Store) *store.Target {
	t.Helper()
	tgt := &store.Target{Name: "prod-db", Host: "h", Port: 22, Protocol: "ssh"}
	if err := st.CreateTarget(context.Background(), tgt); err != nil {
		t.Fatal(err)
	}
	return tgt
}

// TestClaimApprovalNeverAdmitsOnAnUncheckedTicket is the finding itself, run
// against the real store rather than a fake. Two single-use approvals are
// live: one on an open change, one on a cancelled change. Two connections race
// for them, and the ITSM is slow enough that both are inside the gate at once.
//
// Exactly one may be admitted, and it must be the one whose ticket passed. The
// cancelled approval must survive unburned — admitting on it was the bug, and
// silently burning it would be its own small injustice.
func TestClaimApprovalNeverAdmitsOnAnUncheckedTicket(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	tgt := seedTarget(t, st)
	good := approve(t, st, tgt.ID, "CHG-OPEN", true)
	bad := approve(t, st, tgt.ID, "CHG-CANCELLED", true)
	tc := &recordingChecker{bad: map[string]bool{"CHG-CANCELLED": true}, delay: 40 * time.Millisecond}

	var wg sync.WaitGroup
	claims := make([]store.ApprovalClaim, 2)
	errs := make([]error, 2)
	for i := range claims {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			claims[i], errs[i] = store.ClaimApproval(ctx, st, tc, "alice", tgt.ID, time.Now())
		}(i)
	}
	wg.Wait()

	admitted := 0
	for i, c := range claims {
		if errs[i] != nil {
			t.Fatalf("claim %d: %v", i, errs[i])
		}
		if c.OK {
			admitted++
			if c.ConsumedID != good.ID {
				t.Fatalf("admitted on approval %d, but only %d had a valid ticket", c.ConsumedID, good.ID)
			}
		}
	}
	if admitted != 1 {
		t.Fatalf("%d of 2 connections admitted; exactly one approval had a valid ticket", admitted)
	}
	if g, _ := st.GetAccessRequest(ctx, bad.ID); g.ConsumedAt != nil {
		t.Fatal("the cancelled-change approval was consumed — the gate acted on a ticket it refused")
	}
	// The refused connection reached the cancelled ticket and put it to the
	// ITSM, rather than being admitted without asking.
	var sawCancelled bool
	for _, tk := range tc.asked() {
		if tk == "CHG-CANCELLED" {
			sawCancelled = true
		}
	}
	if !sawCancelled {
		t.Fatalf("the cancelled ticket was never checked: asked about %v", tc.asked())
	}
}

// TestClaimApprovalSkipsAPoisonedApproval proves the mirror-image bug is gone:
// one cancelled change no longer shadows a perfectly good approval behind it.
// The operator holds two approvals; one of the changes is cancelled; they get
// in on the other, and the poisoned one is left alone rather than burned to
// clear the way.
func TestClaimApprovalSkipsAPoisonedApproval(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	tgt := seedTarget(t, st)
	bad := approve(t, st, tgt.ID, "CHG-CANCELLED", true) // lower id: tried first
	good := approve(t, st, tgt.ID, "CHG-OPEN", true)     //
	tc := &recordingChecker{bad: map[string]bool{"CHG-CANCELLED": true}}

	claim, err := store.ClaimApproval(ctx, st, tc, "alice", tgt.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !claim.OK {
		t.Fatalf("a cancelled change must not block a valid approval: refused with %v", claim.TicketErr)
	}
	if claim.ConsumedID != good.ID {
		t.Fatalf("consumed approval %d, want the one with the open change (%d)", claim.ConsumedID, good.ID)
	}
	if g, _ := st.GetAccessRequest(ctx, bad.ID); g.ConsumedAt != nil {
		t.Fatal("the approval whose ticket was refused must survive")
	}
	if got := tc.asked(); len(got) != 2 || got[0] != "CHG-CANCELLED" || got[1] != "CHG-OPEN" {
		t.Fatalf("both tickets must be put to the ITSM, in order: %v", got)
	}
}

// TestClaimApprovalRefusesWhenEveryCandidateFails proves skipping is not
// softening: if no live approval has a ticket the ITSM still accepts, the use
// is refused, nothing is burned, and the reason handed to the audit trail is a
// real one.
func TestClaimApprovalRefusesWhenEveryCandidateFails(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	tgt := seedTarget(t, st)
	first := approve(t, st, tgt.ID, "CHG-A", true)
	second := approve(t, st, tgt.ID, "CHG-B", true)
	tc := &recordingChecker{bad: map[string]bool{"CHG-A": true, "CHG-B": true}}

	claim, err := store.ClaimApproval(ctx, st, tc, "alice", tgt.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if claim.OK {
		t.Fatal("no valid ticket must mean no access")
	}
	if claim.TicketErr == nil || claim.Ticket == "" {
		t.Fatalf("the refusal must name a ticket and a reason: %+v", claim)
	}
	for _, ar := range []*store.AccessRequest{first, second} {
		if g, _ := st.GetAccessRequest(ctx, ar.ID); g.ConsumedAt != nil {
			t.Fatalf("approval %d was burned by a refused use", ar.ID)
		}
	}
}

// TestClaimApprovalMovesOnWhenItLosesTheRace covers the seam directly: the
// approval the gate inspected is gone by the time it tries to claim it. It
// must fall through to the next candidate and check THAT one's ticket, not
// give up and not admit on an unchecked one.
func TestClaimApprovalMovesOnWhenItLosesTheRace(t *testing.T) {
	f := &claimFake{
		candidates: []store.AccessRequest{
			{ID: 1, Ticket: "CHG-A", OneTime: true},
			{ID: 2, Ticket: "CHG-B", OneTime: true},
		},
		taken: map[int64]bool{1: true}, // somebody else got there first
	}
	tc := &recordingChecker{}
	claim, err := store.ClaimApproval(context.Background(), f, tc, "alice", 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !claim.OK || claim.ConsumedID != 2 {
		t.Fatalf("want the second approval claimed, got ok=%v id=%d", claim.OK, claim.ConsumedID)
	}
	if got := tc.asked(); len(got) != 2 || got[1] != "CHG-B" {
		t.Fatalf("the second candidate's own ticket must be checked: %v", got)
	}
}

// TestClaimApprovalBoundsTheWalk proves the walk cannot become a way to hold a
// handshake open: the store read is capped, and every ITSM call in one claim
// shares a single deadline rather than getting a fresh one each.
func TestClaimApprovalBoundsTheWalk(t *testing.T) {
	var cands []store.AccessRequest
	for i := 1; i <= 50; i++ {
		cands = append(cands, store.AccessRequest{ID: int64(i), Ticket: fmt.Sprintf("CHG-%d", i), OneTime: true})
	}
	f := &claimFake{candidates: cands}
	tc := &recordingChecker{bad: map[string]bool{}}
	for _, c := range cands {
		tc.bad[c.Ticket] = true // refuse everything, so the walk runs to the end
	}

	if _, err := store.ClaimApproval(context.Background(), f, tc, "alice", 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if f.limit <= 0 || f.limit > 16 {
		t.Fatalf("the candidate read must be capped, got limit=%d", f.limit)
	}
	if n := len(tc.asked()); n != f.limit {
		t.Fatalf("checked %d tickets for a claim capped at %d", n, f.limit)
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	for i, dl := range tc.deadlines {
		if !dl.Equal(tc.deadlines[0]) {
			t.Fatalf("call %d got its own deadline (%v vs %v); the budget must span the claim", i, dl, tc.deadlines[0])
		}
	}
}

// TestClaimApprovalHungITSMFailsClosed proves the shared budget is enforced and
// not merely passed along: an ITSM that never answers refuses the use, once,
// rather than multiplying its timeout by the number of candidates.
func TestClaimApprovalHungITSMFailsClosed(t *testing.T) {
	f := &claimFake{candidates: []store.AccessRequest{
		{ID: 1, Ticket: "CHG-A", OneTime: true},
		{ID: 2, Ticket: "CHG-B", OneTime: true},
	}}
	tc := &recordingChecker{bad: map[string]bool{}, delay: time.Hour}

	start := time.Now()
	claim, err := store.ClaimApproval(context.Background(), f, tc, "alice", 1, time.Now())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if claim.OK {
		t.Fatal("an ITSM that never answers must refuse")
	}
	if !errors.Is(claim.TicketErr, context.DeadlineExceeded) {
		t.Fatalf("the refusal must say the check timed out, got %v", claim.TicketErr)
	}
	if len(f.consumed) != 0 {
		t.Fatalf("nothing may be burned by a timed-out claim: %v", f.consumed)
	}
	// One budget for the whole walk: two candidates must not cost two timeouts.
	if elapsed > 8*time.Second {
		t.Fatalf("the claim took %v; the re-check budget must span the walk", elapsed)
	}
}
