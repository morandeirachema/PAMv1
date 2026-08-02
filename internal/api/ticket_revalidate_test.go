package api_test

// ticket_revalidate_test.go proves the Phase 60 gate end to end: an ITSM ticket
// that was valid when the access request was FILED, and is no longer valid when
// the access is USED, does not admit the use. The whole point of "no privileged
// access without an approved change ticket" is that it holds at the moment of
// access — an approval window is an hour by default and a scheduled request can
// wait days, which is plenty of time for a change to be cancelled.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/ticket"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// flippableITSM is a fake ITSM whose verdict can be changed mid-test, the way a
// change record is cancelled while an approval is still live. It also counts
// calls, so a test can prove the re-check happens at use time and not only at
// request time.
type flippableITSM struct {
	*httptest.Server
	valid atomic.Bool
	calls atomic.Int32
}

func newFlippableITSM(t *testing.T) *flippableITSM {
	t.Helper()
	f := &flippableITSM{}
	f.valid.Store(true)
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.calls.Add(1)
		if f.valid.Load() && b["ticket"] == "CHG1234" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound) // the change was cancelled
	}))
	t.Cleanup(f.Close)
	return f
}

// approvedTicketedRequest files a ticketed request as alice and has bob approve
// it, returning the request id.
func approvedTicketedRequest(t *testing.T, srv *httptest.Server, targetID int64, alice, bob string, oneTime bool) int64 {
	t.Helper()
	status, data := do(t, srv, http.MethodPost, "/api/access-requests", alice, map[string]any{
		"target_id": targetID, "reason": "patch window", "ticket": "CHG1234", "one_time": oneTime,
	})
	if status != http.StatusCreated {
		t.Fatalf("file request: %d %s", status, data)
	}
	id := int64(jsonMap(t, data)["id"].(float64))
	if status, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", id), bob, nil); status != http.StatusOK {
		t.Fatalf("approve: %d %s", status, data)
	}
	return id
}

// TestTicketRevalidatedAtUseTime is the phase in one test: the same approval
// admits a WinRM run while the change is open, and stops admitting it the
// moment the ITSM cancels the change — with nothing about the approval itself
// having changed.
func TestTicketRevalidatedAtUseTime(t *testing.T) {
	itsm := newFlippableITSM(t)
	tv, err := ticket.New(`^CHG[0-9]{3,}$`, itsm.URL)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	srv, st := newTestServerOpts(t, nil, api.Options{
		WinRM: fake, TicketValidator: tv, RequireTicket: true, RevalidateTicket: true,
	})
	targetID := seedApprovalTarget(t, srv, true)
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")
	run := fmt.Sprintf("/api/targets/%d/winrm", targetID)

	approvedTicketedRequest(t, srv, targetID, alice, bob, false)

	// While the change is open, the approval admits the use.
	if status, data := do(t, srv, http.MethodPost, run, alice, map[string]any{"command": "whoami"}); status != http.StatusOK {
		t.Fatalf("use with a valid ticket: want 200, got %d %s", status, data)
	}
	beforeFlip := itsm.calls.Load()
	if beforeFlip < 2 {
		t.Fatalf("the ITSM must be consulted at USE time as well as at request time, saw %d calls", beforeFlip)
	}

	// The change is cancelled. Nothing about the approval changes.
	itsm.valid.Store(false)

	if status, _ := do(t, srv, http.MethodPost, run, alice, map[string]any{"command": "whoami"}); status != http.StatusForbidden {
		t.Fatalf("use with a cancelled ticket: want 403, got %d", status)
	}
	auditHas(t, st, "access.ticket_revoked", "CHG1234")

	// The approval itself is untouched: re-opening the change re-admits it,
	// which is what proves the refusal came from the ticket and not from the
	// approval having been spent or revoked.
	itsm.valid.Store(true)
	if status, data := do(t, srv, http.MethodPost, run, alice, map[string]any{"command": "whoami"}); status != http.StatusOK {
		t.Fatalf("use after the change was re-opened: want 200, got %d %s", status, data)
	}
}

// TestTicketRevalidationDoesNotBurnOneTimeApproval proves a refusal at the ITSM
// does not spend a single-use approval. Burning it would mean an operator whose
// ITSM had a bad minute has to go back through four-eyes for access they were
// already granted.
func TestTicketRevalidationDoesNotBurnOneTimeApproval(t *testing.T) {
	itsm := newFlippableITSM(t)
	tv, err := ticket.New(`^CHG[0-9]{3,}$`, itsm.URL)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	srv, st := newTestServerOpts(t, nil, api.Options{
		WinRM: fake, TicketValidator: tv, RequireTicket: true, RevalidateTicket: true,
	})
	targetID := seedApprovalTarget(t, srv, true)
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")
	run := fmt.Sprintf("/api/targets/%d/winrm", targetID)

	reqID := approvedTicketedRequest(t, srv, targetID, alice, bob, true) // single-use

	// The ITSM is unreachable/rejecting when the operator tries to use it.
	itsm.valid.Store(false)
	if status, _ := do(t, srv, http.MethodPost, run, alice, map[string]any{"command": "whoami"}); status != http.StatusForbidden {
		t.Fatalf("use with a cancelled ticket: want 403, got %d", status)
	}
	// The single-use approval must still be unconsumed.
	ar, err := st.GetAccessRequest(t.Context(), reqID)
	if err != nil || ar == nil {
		t.Fatalf("reading the request back: %+v err %v", ar, err)
	}
	if ar.ConsumedAt != nil {
		t.Fatal("a use refused by the ticket gate must not spend the single-use approval")
	}

	// With the change open again, the approval admits exactly one use, as ever.
	itsm.valid.Store(true)
	if status, data := do(t, srv, http.MethodPost, run, alice, map[string]any{"command": "whoami"}); status != http.StatusOK {
		t.Fatalf("first use: want 200, got %d %s", status, data)
	}
	if status, _ := do(t, srv, http.MethodPost, run, alice, map[string]any{"command": "whoami"}); status != http.StatusForbidden {
		t.Fatalf("second use of a single-use approval: want 403, got %d", status)
	}
	if ar, _ := st.GetAccessRequest(t.Context(), reqID); ar == nil || ar.ConsumedAt == nil {
		t.Fatal("the admitted use must still consume the single-use approval")
	}
}

// TestTicketRevalidationOffIsUnchanged proves the default configuration behaves
// exactly as it did before Phase 60: the ticket is checked when the request is
// filed and never again, so a cancelled change still admits the use. This is
// the documented trade-off, and it should fail loudly if it ever changes by
// accident rather than by decision.
func TestTicketRevalidationOffIsUnchanged(t *testing.T) {
	itsm := newFlippableITSM(t)
	tv, err := ticket.New(`^CHG[0-9]{3,}$`, itsm.URL)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	srv, _ := newTestServerOpts(t, nil, api.Options{
		WinRM: fake, TicketValidator: tv, RequireTicket: true, // RevalidateTicket left off
	})
	targetID := seedApprovalTarget(t, srv, true)
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")
	run := fmt.Sprintf("/api/targets/%d/winrm", targetID)

	approvedTicketedRequest(t, srv, targetID, alice, bob, false)
	atRequestTime := itsm.calls.Load()

	itsm.valid.Store(false)
	if status, data := do(t, srv, http.MethodPost, run, alice, map[string]any{"command": "whoami"}); status != http.StatusOK {
		t.Fatalf("with the re-check off the use must still be admitted: %d %s", status, data)
	}
	if itsm.calls.Load() != atRequestTime {
		t.Fatal("with the re-check off, using access must not call the ITSM at all")
	}
}

// TestTicketRevalidationIgnoresRequestsWithoutTickets proves a deployment that
// validates tickets but does not require them still admits an approval that
// carries none: there is nothing to re-check, and inventing a refusal would gate
// access on a control the admin did not ask for.
func TestTicketRevalidationIgnoresRequestsWithoutTickets(t *testing.T) {
	itsm := newFlippableITSM(t)
	itsm.valid.Store(false) // the ITSM rejects everything it is asked about
	tv, err := ticket.New("", itsm.URL)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	srv, _ := newTestServerOpts(t, nil, api.Options{
		WinRM: fake, TicketValidator: tv, RevalidateTicket: true, // RequireTicket off
	})
	targetID := seedApprovalTarget(t, srv, true)
	alice := seedUser(t, srv, "alice", "user")
	bob := seedUser(t, srv, "bob", "approver")

	status, data := do(t, srv, http.MethodPost, "/api/access-requests", alice, map[string]any{
		"target_id": targetID, "reason": "no ticket here",
	})
	if status != http.StatusCreated {
		t.Fatalf("file request: %d %s", status, data)
	}
	id := int64(jsonMap(t, data)["id"].(float64))
	if status, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", id), bob, nil); status != http.StatusOK {
		t.Fatalf("approve: %d", status)
	}
	run := fmt.Sprintf("/api/targets/%d/winrm", targetID)
	if status, data := do(t, srv, http.MethodPost, run, alice, map[string]any{"command": "whoami"}); status != http.StatusOK {
		t.Fatalf("a ticketless approval must still admit: %d %s", status, data)
	}
	if itsm.calls.Load() != 0 {
		t.Fatalf("nothing should have been asked of the ITSM, saw %d calls", itsm.calls.Load())
	}
}
