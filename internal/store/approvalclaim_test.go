package store_test

// approvalclaim_test.go covers the use-time approval fold in isolation: the
// order it does things in, and what it does when the ITSM says no. The
// end-to-end proof that every gate calls it lives in the api and proxy tests.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// claimFake is a stand-in for the store, recording which approvals were
// actually consumed. `taken` names approvals a concurrent use has already
// claimed, so a claim by id fails the way a lost race does.
type claimFake struct {
	candidates []store.AccessRequest
	consumed   []int64
	taken      map[int64]bool
	limit      int
	activeErr,
	consumeErr error
}

// oneCandidate builds a fake holding a single admitting approval.
func oneCandidate(ar *store.AccessRequest) *claimFake {
	f := &claimFake{}
	if ar != nil {
		f.candidates = []store.AccessRequest{*ar}
	}
	return f
}

func (f *claimFake) ActiveApprovals(_ context.Context, _ string, _ int64, _ time.Time, limit int) ([]store.AccessRequest, error) {
	if f.activeErr != nil {
		return nil, f.activeErr
	}
	f.limit = limit
	out := f.candidates
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *claimFake) ConsumeApproval(_ context.Context, _ string, _ int64, _ time.Time) (bool, int64, error) {
	if f.consumeErr != nil {
		return false, 0, f.consumeErr
	}
	if len(f.candidates) == 0 {
		return false, 0, nil
	}
	ar := f.candidates[0]
	f.consumed = append(f.consumed, ar.ID)
	if ar.OneTime {
		return true, ar.ID, nil
	}
	return true, 0, nil
}

func (f *claimFake) ConsumeApprovalByID(_ context.Context, id int64, _ string, _ int64, _ time.Time) (bool, error) {
	if f.consumeErr != nil {
		return false, f.consumeErr
	}
	if f.taken[id] {
		return false, nil
	}
	for _, ar := range f.candidates {
		if ar.ID != id {
			continue
		}
		if ar.OneTime {
			if f.taken == nil {
				f.taken = map[int64]bool{}
			}
			f.taken[id] = true
		}
		f.consumed = append(f.consumed, id)
		return true, nil
	}
	return false, nil
}

// checkFn adapts a function to store.TicketChecker.
type checkFn func(ctx context.Context, ticket string) error

func (f checkFn) Validate(ctx context.Context, ticket, _ string) error { return f(ctx, ticket) }

// TestClaimApprovalRefusesWithoutBurning is the point of the whole fold: when
// the ITSM no longer accepts the ticket, the use is refused AND the single-use
// approval survives. Burning it would punish the operator for their ticketing
// system's answer — they would have to obtain a fresh approval to retry
// something they were already granted.
func TestClaimApprovalRefusesWithoutBurning(t *testing.T) {
	f := oneCandidate(&store.AccessRequest{ID: 7, Ticket: "CHG1001", OneTime: true})
	rejected := errors.New("ticket CHG1001 was rejected by the ITSM system (status 404)")
	checked := ""

	claim, err := store.ClaimApproval(context.Background(), f,
		checkFn(func(_ context.Context, tk string) error { checked = tk; return rejected }),
		"alice", 1, time.Now())
	if err != nil {
		t.Fatalf("a refused ticket is a policy answer, not an error: %v", err)
	}
	if claim.OK {
		t.Fatal("a ticket the ITSM rejects must refuse the use")
	}
	if !errors.Is(claim.TicketErr, rejected) {
		t.Fatalf("the refusal must carry the ITSM's reason, got %v", claim.TicketErr)
	}
	if claim.Ticket != "CHG1001" || checked != "CHG1001" {
		t.Fatalf("the admitting request's ticket must be the one checked: checked=%q claim=%q", checked, claim.Ticket)
	}
	if len(f.consumed) != 0 {
		t.Fatal("a refused use must not consume the approval")
	}
}

// TestClaimApprovalUnreachableITSMFailsClosed proves an ITSM that cannot be
// reached refuses rather than admits. A gate that opens when it cannot do its
// job is not a gate — deployments that cannot accept that leave the re-check
// off entirely.
func TestClaimApprovalUnreachableITSMFailsClosed(t *testing.T) {
	f := oneCandidate(&store.AccessRequest{ID: 7, Ticket: "CHG1001"})
	claim, err := store.ClaimApproval(context.Background(), f,
		checkFn(func(context.Context, string) error {
			return errors.New("ticket validation request failed: connection refused")
		}),
		"alice", 1, time.Now())
	if err != nil || claim.OK {
		t.Fatalf("an unreachable ITSM must refuse: ok=%v err=%v", claim.OK, err)
	}
	if len(f.consumed) != 0 {
		t.Fatal("a refused use must not consume the approval")
	}
}

// TestClaimApprovalPassesAndConsumes covers the happy paths: a valid ticket, a
// request with no ticket at all, and a deployment with the re-check off. All
// three consume exactly as before Phase 60.
func TestClaimApprovalPassesAndConsumes(t *testing.T) {
	valid := checkFn(func(context.Context, string) error { return nil })

	for _, tc := range []struct {
		name    string
		active  *store.AccessRequest
		checker store.TicketChecker
		wantID  int64
	}{
		{"valid ticket", &store.AccessRequest{ID: 7, Ticket: "CHG1001", OneTime: true}, valid, 7},
		{"request without a ticket", &store.AccessRequest{ID: 8, OneTime: true}, valid, 8},
		{"recheck disabled", &store.AccessRequest{ID: 9, Ticket: "CHG1001", OneTime: true}, nil, 9},
		{"standing approval", &store.AccessRequest{ID: 10, Ticket: "CHG1001"}, valid, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := oneCandidate(tc.active)
			claim, err := store.ClaimApproval(context.Background(), f, tc.checker, "alice", 1, time.Now())
			if err != nil || !claim.OK {
				t.Fatalf("want admitted, got ok=%v err=%v", claim.OK, err)
			}
			if claim.ConsumedID != tc.wantID {
				t.Fatalf("consumed id = %d, want %d", claim.ConsumedID, tc.wantID)
			}
			if len(f.consumed) != 1 {
				t.Fatalf("the approval must be claimed exactly once, got %v", f.consumed)
			}
			if claim.TicketErr != nil {
				t.Fatalf("unexpected ticket error: %v", claim.TicketErr)
			}
		})
	}
}

// TestClaimApprovalStoreErrorsFailClosed proves neither store read can admit a
// use by failing: the caller gets an error and no claim.
func TestClaimApprovalStoreErrorsFailClosed(t *testing.T) {
	boom := errors.New("database is down")
	valid := checkFn(func(context.Context, string) error { return nil })

	f := &claimFake{activeErr: boom}
	if claim, err := store.ClaimApproval(context.Background(), f, valid, "alice", 1, time.Now()); err == nil || claim.OK {
		t.Fatalf("an unreadable approval must not admit: ok=%v err=%v", claim.OK, err)
	}
	f = oneCandidate(&store.AccessRequest{ID: 7})
	f.consumeErr = boom
	if claim, err := store.ClaimApproval(context.Background(), f, valid, "alice", 1, time.Now()); err == nil || claim.OK {
		t.Fatalf("a failed consume must not admit: ok=%v err=%v", claim.OK, err)
	}
	if _, err := store.ClaimApproval(context.Background(), nil, valid, "alice", 1, time.Now()); err == nil {
		t.Fatal("a nil store must be an error, not an admission")
	}
}

// TestClaimApprovalNoApprovalStillRefuses proves the fold does not accidentally
// admit when there is nothing to admit — the peek returning nil must not be
// read as "nothing to check, therefore fine".
func TestClaimApprovalNoApprovalStillRefuses(t *testing.T) {
	f := &claimFake{}
	claim, err := store.ClaimApproval(context.Background(), f,
		checkFn(func(context.Context, string) error { return nil }), "alice", 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if claim.OK {
		t.Fatal("no approval must refuse")
	}
}
