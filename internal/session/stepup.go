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
type StepUp struct {
	mu      sync.Mutex
	pending map[string]*pendingStepUp // keyed by session id: at most one at a time
}

// pendingStepUp is one paused action awaiting a decision.
type pendingStepUp struct {
	sessionID string
	actor     string
	statement string
	requested time.Time
	decided   chan bool
}

// PendingStepUp is a supervisor-facing view of a paused action.
type PendingStepUp struct {
	SessionID string    `json:"session_id"`
	Actor     string    `json:"actor"`
	Statement string    `json:"statement"`
	Requested time.Time `json:"requested_at"`
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
	entry := &pendingStepUp{sessionID: sessionID, actor: actor, statement: statement, requested: time.Now().UTC(), decided: make(chan bool, 1)}
	s.mu.Lock()
	if _, exists := s.pending[sessionID]; exists {
		s.mu.Unlock()
		return false
	}
	s.pending[sessionID] = entry
	s.mu.Unlock()

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

// Decide resolves a session's pending step-up (approve/deny). It claims the
// pending entry by removing it from the map under the lock — the same atomic
// point Await's timeout path contends for — so exactly one of the two wins.
// Returns false if no step-up is pending (or one was already claimed/decided).
func (s *StepUp) Decide(sessionID string, approve bool) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	p, ok := s.pending[sessionID]
	if ok {
		delete(s.pending, sessionID)
	}
	s.mu.Unlock()
	if !ok {
		return false
	}
	p.decided <- approve // buffered (cap 1); the waiting Await receives it
	return true
}

// Pending lists the sessions awaiting a step-up decision (for a supervisor).
func (s *StepUp) Pending() []PendingStepUp {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PendingStepUp, 0, len(s.pending))
	for _, p := range s.pending {
		out = append(out, PendingStepUp{SessionID: p.sessionID, Actor: p.actor, Statement: p.statement, Requested: p.requested})
	}
	return out
}
