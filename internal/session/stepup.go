package session

import (
	"context"
	"sync"
	"time"
)

// StepUp coordinates in-session step-up approvals (Phase 30): when a session
// proxy meets a sensitive action it pauses and Awaits a supervisor's live
// decision — the session stays open, unlike a kill. A supervisor (watching the
// session) resolves it with Decide. It is shared between the proxy (which Awaits)
// and the API (which Decides), like the live Hub.
//
// The paused statement blocks in THIS replica's memory, so the coordinator alone
// is replica-local. Phase 56 closes that: StartBus (stepupbus.go) attaches the
// store, after which every pause is mirrored into a shared, TTL-bounded
// inventory (so PendingCluster lists the whole cluster) and a sealed decision
// published on any replica is applied by the one hosting the pause.
type StepUp struct {
	mu      sync.Mutex
	pending map[string]*pendingStepUp // keyed by session id: at most one at a time

	// Cross-replica machinery (Phase 56), attached once by StartBus and nil in a
	// deployment (or test) that never wires it — every path below degrades to the
	// replica-local behavior when st is nil.
	st      StepUpStore
	sealer  *liveSealer
	replica string
	audit   func(ctx context.Context, action, detail string)
}

// pendingStepUp is one paused action awaiting a decision.
type pendingStepUp struct {
	sessionID string
	actor     string
	statement string
	requested time.Time
	expires   time.Time
	decided   chan bool
}

// PendingStepUp is a supervisor-facing view of a paused action. It is also the
// row shape of the shared cluster inventory (StepUpStore) — with one twist: on
// the store surface Statement carries the SEALED form (base64 of an AES-GCM
// envelope under the cluster bus key, livecrypto.go), never the SQL itself. The
// session layer seals before Put and opens after List, so a database observer
// sees ciphertext and a fabricated row fails to open and is never shown to a
// supervisor. Everywhere else — the API response, local Pending — Statement is
// the plaintext statement the supervisor must read to decide.
type PendingStepUp struct {
	SessionID string    `json:"session_id"`
	Actor     string    `json:"actor"`
	Statement string    `json:"statement"`
	Requested time.Time `json:"requested_at"`
	// Expires is when the pause times out and the statement is refused. In the
	// shared inventory it is stamped by the store's own clock (the single-clock
	// rule of LiveStore), which is also what filters expired rows out of listings.
	Expires time.Time `json:"expires_at"`
	// Replica names the replica hosting the paused session — the one whose memory
	// holds the blocked statement, and the one that will apply a decision.
	Replica string `json:"replica,omitempty"`
}

// NewStepUp returns an empty step-up coordinator.
func NewStepUp() *StepUp { return &StepUp{pending: map[string]*pendingStepUp{}} }

// Await registers a pending step-up for a session and blocks until a supervisor
// Decides, or timeout/ctx fires (either of which is a denial — fail closed).
// Only one step-up per session at a time; a second concurrent Await is denied.
// A nil StepUp denies immediately (feature disabled).
func (s *StepUp) Await(ctx context.Context, sessionID, actor, statement string, timeout time.Duration) bool {
	if s == nil {
		return false
	}
	now := time.Now().UTC()
	entry := &pendingStepUp{sessionID: sessionID, actor: actor, statement: statement,
		requested: now, expires: now.Add(timeout), decided: make(chan bool, 1)}
	s.mu.Lock()
	if _, exists := s.pending[sessionID]; exists {
		s.mu.Unlock()
		return false
	}
	s.pending[sessionID] = entry
	s.mu.Unlock()

	// Mirror the pause into the shared cluster inventory (best-effort: the pause
	// itself lives in this replica's memory and works without the row; a failed
	// write only keeps remote supervisors from seeing it). If a decision claimed
	// the entry while the row was being written, the row is already a ghost —
	// delete it rather than leave it listed until its TTL.
	s.putRow(entry, timeout)
	s.mu.Lock()
	claimed := s.pending[sessionID] != entry
	s.mu.Unlock()
	if claimed {
		s.deleteRow(sessionID)
	}

	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case ok := <-entry.decided:
		return ok // a Decide claimed the entry (removed it) and delivered the decision
	case <-t.C:
	case <-ctx.Done():
	}
	// Timeout / cancellation: try to claim (remove) our own entry. Removal from the
	// map is the single atomic claim point — whoever removes it wins, so Await and a
	// concurrent Decide can never both report success on the same step-up.
	s.mu.Lock()
	if s.pending[sessionID] == entry {
		delete(s.pending, sessionID)
		s.mu.Unlock()
		s.deleteRow(sessionID)
		return false // we claimed the timeout; a later Decide finds nothing and fails
	}
	s.mu.Unlock()
	// A Decide claimed it first; honor the decision it delivered into our channel.
	select {
	case ok := <-entry.decided:
		return ok
	case <-time.After(100 * time.Millisecond):
		return false // decision never arrived; fail closed
	}
}

// Decide resolves a session's pending step-up (approve/deny) with no
// separation-of-duties check. Use DecideBy for anything reachable by a human;
// this exists for tests and for callers that have already established who is
// deciding.
func (s *StepUp) Decide(sessionID string, approve bool) bool {
	ok, _ := s.DecideBy(sessionID, approve, "")
	return ok
}

// DecideBy resolves a session's pending step-up on behalf of decider. It claims
// the pending entry by removing it from the map under the lock — the same atomic
// point Await's timeout path contends for — so exactly one of the two wins.
//
// It returns (false, true) when decider is the very operator whose session is
// paused. A step-up exists to put a second person in the loop before a sensitive
// statement runs; letting the operator approve their own turns the pause into a
// confirmation prompt, which is worse than no gate at all because the audit trail
// then records an approval that never happened. Every other decision point in
// pamv1 — access requests, vendor grants, broker approvals, access certification
// — already refuses self-approval; this one did not.
//
// The check happens under the same lock as the claim, so a concurrent decision
// cannot slip a self-approval through between a lookup and a claim.
func (s *StepUp) DecideBy(sessionID string, approve bool, decider string) (ok, selfApproval bool) {
	if s == nil {
		return false, false
	}
	s.mu.Lock()
	p, found := s.pending[sessionID]
	if found && decider != "" && p.actor == decider {
		s.mu.Unlock()
		return false, true // leave it pending for someone else to decide
	}
	if found {
		delete(s.pending, sessionID)
	}
	s.mu.Unlock()
	if !found {
		return false, false
	}
	s.deleteRow(sessionID) // the claim is done; drop the shared-inventory mirror
	p.decided <- approve   // buffered (cap 1); the waiting Await receives it
	return true, false
}

// Pending lists the sessions awaiting a step-up decision on THIS replica (for a
// supervisor). PendingCluster (stepupbus.go) is the cluster-wide view.
func (s *StepUp) Pending() []PendingStepUp {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PendingStepUp, 0, len(s.pending))
	for _, p := range s.pending {
		out = append(out, PendingStepUp{SessionID: p.sessionID, Actor: p.actor, Statement: p.statement,
			Requested: p.requested, Expires: p.expires, Replica: s.replica})
	}
	return out
}
