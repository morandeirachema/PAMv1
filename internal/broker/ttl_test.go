package broker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/policy"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// ttlEngine parks tool "t" for approval with the given per-rule ttl_seconds
// (0 = the rule sets none, so the deployment's TTL stands alone).
func ttlEngine(t *testing.T, seconds int) *policy.Engine {
	t.Helper()
	rule := "rules:\n  - id: p\n    tool: t\n    effect: require_approval\n    approvers: [ops]\n"
	if seconds > 0 {
		rule += "    ttl_seconds: " + itoa(seconds) + "\n"
	}
	e, err := policy.Load(strings.NewReader(rule))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// itoa avoids pulling strconv in for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for ; n > 0; n /= 10 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
	}
	return string(digits)
}

// TestRuleTTLBoundsTheApprovalWindow is Phase 171's central assertion: a rule's
// ttl_seconds now really shortens how long a parked call can be decided and how
// long its single-use resume token can be spent.
//
// Until this phase the field was parsed into Decision.TTL and read by nothing:
// a rule advertising a 60-second grant got PAM_BROKER_TOKEN_TTL_MIN's 15
// minutes, and the shipped example policy marketed exactly that setting. A dead
// field that reads like a control is worse than an absent one.
func TestRuleTTLBoundsTheApprovalWindow(t *testing.T) {
	st := memstore.New()
	chain := newTestChain(t, st)
	reg := NewRegistry()
	ran := false
	reg.Register(recordingTool{ran: &ran})
	// A 30-minute deployment TTL, so the rule's 60 seconds is unambiguously the
	// binding constraint rather than a coincidence of the default.
	b := New(ttlEngine(t, 60), reg, chain).WithApproval(st, alert.Noop{}, 30*time.Minute)

	out := b.ProcessCall(context.Background(), &agentid.Identity{AgentName: "bot"}, Call{Tool: "t"})
	if out.Status != StatusPendingApproval {
		t.Fatalf("status = %q, want pending_approval", out.Status)
	}
	// The deadline is reported, because an agent told only "pending" cannot tell
	// a decision worth waiting for from one that can no longer happen.
	if out.ExpiresAt.IsZero() || time.Until(out.ExpiresAt) > 90*time.Second {
		t.Fatalf("expires_at = %v, want ~60s out (the rule's window, not the deployment's 30m)", out.ExpiresAt)
	}
	if pending := b.PendingApprovals(); len(pending) != 1 || pending[0].ExpiresAt.IsZero() {
		t.Fatalf("the approver queue must carry the deadline: %+v", pending)
	}

	// The resume token exists and was minted from the SAME deadline value the
	// outcome reports (park computes one `expires` and uses it for both), so the
	// reported window and the enforced one cannot drift apart.
	if out.ResumeToken == "" || out.jti == "" {
		t.Fatal("a parked call under an approval rule should carry a resume token")
	}
	if _, err := st.PeekBrokerToken(context.Background(), out.jti, "bot"); err != nil {
		t.Fatalf("the minted token should be peekable inside its window: %v", err)
	}

	// Two minutes on — well inside the deployment's 30 minutes, well past the
	// rule's 60 seconds — the call is swept, terminal and unexecuted.
	if n := len(b.SweepExpiredParked(context.Background(), time.Now().Add(2*time.Minute))); n != 1 {
		t.Fatalf("sweep evicted %d, want 1: the rule's ttl_seconds must bound the window", n)
	}
	got, ok := b.Lookup(out.CallID)
	if !ok || got.Status != StatusFailed {
		t.Fatalf("swept outcome = %+v ok=%v, want terminal failed", got, ok)
	}
	if ran {
		t.Fatal("a swept call must never execute")
	}
}

// TestRuleTTLCannotExceedTheDeploymentTTL pins the direction of the narrowing: a
// policy file may shorten the deployment's window, never lengthen it. A policy
// is edited far more often, and by more people, than a deployment's
// configuration — if a line of YAML could out-rank PAM_BROKER_TOKEN_TTL_MIN, the
// deployment-wide bound would be advisory.
func TestRuleTTLCannotExceedTheDeploymentTTL(t *testing.T) {
	st := memstore.New()
	b := New(ttlEngine(t, 3600), NewRegistry(), newTestChain(t, st)).
		WithApproval(st, alert.Noop{}, time.Minute)

	out := b.ProcessCall(context.Background(), &agentid.Identity{AgentName: "bot"}, Call{Tool: "t"})
	if out.Status != StatusPendingApproval {
		t.Fatalf("status = %q, want pending_approval", out.Status)
	}
	if time.Until(out.ExpiresAt) > 2*time.Minute {
		t.Fatalf("expires_at = %v: a rule must not extend the deployment's 1-minute window", out.ExpiresAt)
	}
	if n := len(b.SweepExpiredParked(context.Background(), time.Now().Add(90*time.Second))); n != 1 {
		t.Fatalf("sweep evicted %d, want 1: the deployment TTL still binds", n)
	}
}

// TestNoRuleTTLKeepsTheDeploymentWindow proves the unchanged path: a rule that
// sets no ttl_seconds behaves exactly as every rule did before this phase.
func TestNoRuleTTLKeepsTheDeploymentWindow(t *testing.T) {
	st := memstore.New()
	b := New(ttlEngine(t, 0), NewRegistry(), newTestChain(t, st)).
		WithApproval(st, alert.Noop{}, 10*time.Minute)

	out := b.ProcessCall(context.Background(), &agentid.Identity{AgentName: "bot"}, Call{Tool: "t"})
	if d := time.Until(out.ExpiresAt); d < 9*time.Minute || d > 10*time.Minute+time.Second {
		t.Fatalf("expires_at = %v, want the deployment's 10-minute window", out.ExpiresAt)
	}
	if n := len(b.SweepExpiredParked(context.Background(), time.Now().Add(5*time.Minute))); n != 0 {
		t.Fatalf("a call inside its window must survive the sweep, evicted %d", n)
	}
}
