package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/policy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// failAppendStore wraps a real memstore but makes broker-audit appends fail, so a
// test can simulate the audit chain being unavailable.
type failAppendStore struct{ *memstore.Memstore }

func (failAppendStore) AppendBrokerAuditLinked(context.Context, func(*store.BrokerAuditEvent) store.BrokerAuditEvent) (store.BrokerAuditEvent, error) {
	return store.BrokerAuditEvent{}, errors.New("audit store unavailable")
}

// recordingTool notes whether Execute ran.
type recordingTool struct{ ran *bool }

func (recordingTool) Name() string                   { return "t" }
func (recordingTool) Description() string            { return "test tool" }
func (recordingTool) InputSchema() map[string]string { return nil }
func (recordingTool) Capability() auth.Capability    { return auth.CapCallTool }
func (t recordingTool) Execute(context.Context, *auth.Principal, Args) (Result, error) {
	*t.ran = true
	return Result{Data: map[string]any{"ok": true}}, nil
}

func newTestChain(t *testing.T, st store.Store) *auditchain.Chain {
	t.Helper()
	key := make([]byte, auditchain.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := auditchain.New(context.Background(), key, priv, st)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func allowEngine(t *testing.T) *policy.Engine {
	t.Helper()
	e, err := policy.Load(strings.NewReader("rules:\n  - id: a\n    tool: t\n    effect: allow\n"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// TestProcessCallFailsClosedWhenAuditUnavailable proves a side-effecting call is
// NOT executed if its pre-execution audit record cannot be written to the chain —
// an executed action must never be missing from the authoritative log.
func TestProcessCallFailsClosedWhenAuditUnavailable(t *testing.T) {
	chain := newTestChain(t, failAppendStore{memstore.New()})
	reg := NewRegistry()
	ran := false
	reg.Register(recordingTool{ran: &ran})
	b := New(allowEngine(t), reg, chain)

	out := b.ProcessCall(context.Background(), &agentid.Identity{AgentName: "bot"}, Call{Tool: "t"})
	if out.Status != StatusFailed {
		t.Fatalf("status = %q, want failed when the audit chain is unavailable", out.Status)
	}
	if ran {
		t.Fatal("tool executed despite the audit chain being unavailable — must fail closed")
	}
}

// TestProcessCallExecutesWhenAuditWorks is the positive control: with a working
// chain the same allow rule runs the tool.
func TestProcessCallExecutesWhenAuditWorks(t *testing.T) {
	chain := newTestChain(t, memstore.New())
	reg := NewRegistry()
	ran := false
	reg.Register(recordingTool{ran: &ran})
	b := New(allowEngine(t), reg, chain)

	out := b.ProcessCall(context.Background(), &agentid.Identity{AgentName: "bot"}, Call{Tool: "t"})
	if out.Status != StatusExecuted || !ran {
		t.Fatalf("status=%q ran=%v, want executed/true", out.Status, ran)
	}
}

// parkEngine is a policy whose only rule parks tool "t" for human approval.
func parkEngine(t *testing.T) *policy.Engine {
	t.Helper()
	e, err := policy.Load(strings.NewReader("rules:\n  - id: p\n    tool: t\n    effect: require_approval\n    approvers: [ops]\n"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// TestSweepExpiredParked proves an abandoned parked call is evicted once it
// outlives the resume-token TTL: the agent polling its status sees a terminal
// failed outcome (not an eternal pending), the approval queue empties, and a
// call still inside the TTL survives the sweep.
func TestSweepExpiredParked(t *testing.T) {
	chain := newTestChain(t, memstore.New())
	reg := NewRegistry()
	ran := false
	reg.Register(recordingTool{ran: &ran})
	b := New(parkEngine(t), reg, chain)

	out := b.ProcessCall(context.Background(), &agentid.Identity{AgentName: "bot"}, Call{Tool: "t"})
	if out.Status != StatusPendingApproval {
		t.Fatalf("status = %q, want pending_approval", out.Status)
	}
	if n := len(b.PendingApprovals()); n != 1 {
		t.Fatalf("parked = %d, want 1", n)
	}

	// Inside the TTL nothing is evicted.
	if n := b.SweepExpiredParked(context.Background(), time.Now()); n != 0 {
		t.Fatalf("early sweep evicted %d, want 0", n)
	}
	// Past the TTL the call is evicted, terminal, and audited.
	if n := b.SweepExpiredParked(context.Background(), time.Now().Add(16*time.Minute)); n != 1 {
		t.Fatalf("sweep evicted %d, want 1", n)
	}
	if n := len(b.PendingApprovals()); n != 0 {
		t.Fatalf("parked after sweep = %d, want 0", n)
	}
	got, ok := b.Lookup(out.CallID)
	if !ok || got.Status != StatusFailed || !strings.Contains(got.Reason, "expired") {
		t.Fatalf("swept outcome = %+v ok=%v, want a terminal failed outcome naming expiry", got, ok)
	}
	if ran {
		t.Fatal("a swept call must never execute")
	}
}

// privilegedTool is a tool whose capability an agent identity never holds.
// Agents resolve to auth.RoleAgent, which carries CapCallTool and nothing else,
// so this stands in for "a tool the policy YAML says yes to and the RBAC model
// says no to".
type privilegedTool struct{ ran *bool }

func (privilegedTool) Name() string                   { return "t" }
func (privilegedTool) Description() string            { return "a tool agents may not call" }
func (privilegedTool) InputSchema() map[string]string { return nil }
func (privilegedTool) Capability() auth.Capability    { return auth.CapManageUsers }
func (t privilegedTool) Execute(context.Context, *auth.Principal, Args) (Result, error) {
	*t.ran = true
	return Result{Data: map[string]any{"ok": true}}, nil
}

// TestCapabilityBackstopDeniesWhatPolicyAllows proves the claim in
// docs/AGENT-THREAT-MODEL.md that "the capability backstop requires the agent
// principal to actually hold the tool's capability, so policy YAML is never the
// sole gate".
//
// Until this test existed, no policy had ever said `allow` for a tool whose
// capability the principal lacked — so the backstop's deny branch had never run
// on either path, and the claim that authorization does not rest on the YAML
// alone was unbacked. It matters most in the case the threat model is written
// for: a policy file that is wrong, whether by mistake or by tampering.
func TestCapabilityBackstopDeniesWhatPolicyAllows(t *testing.T) {
	// Path 1: the immediate allow path (ProcessCall).
	t.Run("immediate allow", func(t *testing.T) {
		chain := newTestChain(t, memstore.New())
		reg := NewRegistry()
		ran := false
		reg.Register(privilegedTool{ran: &ran})
		b := New(allowEngine(t), reg, chain)

		out := b.ProcessCall(context.Background(), &agentid.Identity{AgentName: "bot"}, Call{Tool: "t"})
		if out.Status != StatusDenied {
			t.Fatalf("status = %q, want denied — the policy said allow but the principal lacks the capability", out.Status)
		}
		if ran {
			t.Fatal("the tool executed on the strength of the policy file alone; the capability backstop is not a backstop")
		}
	})

	// Path 2: the post-approval path (Decide). A human approving a parked call
	// must not be able to grant a capability the agent does not hold.
	t.Run("after human approval", func(t *testing.T) {
		chain := newTestChain(t, memstore.New())
		reg := NewRegistry()
		ran := false
		reg.Register(privilegedTool{ran: &ran})
		b := New(parkEngine(t), reg, chain)

		id := &agentid.Identity{AgentName: "bot", KeyID: 1}
		parked := b.ProcessCall(context.Background(), id, Call{Tool: "t"})
		if parked.Status != StatusPendingApproval {
			t.Fatalf("expected the call to park, got %q", parked.Status)
		}
		out, ok, err := b.Decide(context.Background(), parked.CallID, Approver{Name: "human", IsAdmin: true}, true)
		if err != nil {
			t.Fatalf("Decide: %v", err)
		}
		if !ok {
			t.Fatal("Decide did not find the parked call")
		}
		if out.Status != StatusDenied {
			t.Fatalf("status = %q, want denied — a human approval must not confer a capability the agent lacks", out.Status)
		}
		if ran {
			t.Fatal("the tool executed after approval despite the agent lacking its capability")
		}
	})
}

// TestWithdrawRejectsForeignRequester proves a parked call can only be withdrawn
// by the agent that asked for it.
//
// docs/AGENT-THREAT-MODEL.md justifies withdrawal needing no approver on the
// grounds that "you may always cancel what you asked for" — a statement whose
// entire safety rests on the identity match. Nothing had ever proved that agent
// B cannot withdraw agent A's parked call, so the premise was assumed rather
// than tested. Without the match, withdrawal is a denial-of-service one agent
// can inflict on another's pending work.
func TestWithdrawRejectsForeignRequester(t *testing.T) {
	chain := newTestChain(t, memstore.New())
	reg := NewRegistry()
	ran := false
	reg.Register(recordingTool{ran: &ran})
	b := New(parkEngine(t), reg, chain)

	owner := &agentid.Identity{AgentName: "bot-a", KeyID: 1}
	parked := b.ProcessCall(context.Background(), owner, Call{Tool: "t"})
	if parked.Status != StatusPendingApproval {
		t.Fatalf("expected the call to park, got %q", parked.Status)
	}

	// A different agent — deliberately sharing the NAME, since agent names are
	// documented as non-unique — must not be able to withdraw it.
	stranger := &agentid.Identity{AgentName: "bot-a", KeyID: 2}
	if _, ok := b.Withdraw(context.Background(), parked.CallID, stranger); ok {
		t.Fatal("a different agent withdrew someone else's parked call; withdrawal is only safe because the identity must match")
	}
	if len(b.PendingApprovals()) != 1 {
		t.Fatalf("the call is no longer parked after a refused withdrawal: %d pending", len(b.PendingApprovals()))
	}

	// A nil requester must not withdraw either.
	if _, ok := b.Withdraw(context.Background(), parked.CallID, nil); ok {
		t.Fatal("a nil requester withdrew a parked call")
	}

	// The real requester still can — the control must not have broken the feature.
	if _, ok := b.Withdraw(context.Background(), parked.CallID, owner); !ok {
		t.Fatal("the requesting agent could not withdraw its own call")
	}
	if len(b.PendingApprovals()) != 0 {
		t.Fatal("the call survived its own requester's withdrawal")
	}
}

// TestSameAgentIdentityMatching pins the comparison Withdraw depends on, and in
// particular its weakest path.
//
// When both identities carry a static-key row id the match is by id, which is
// exact. When either lacks one — which is the case for every SVID-authenticated
// identity, i.e. the intended production posture — it falls back to a
// case-folded NAME comparison, and names are explicitly not unique. That
// fallback is the path real deployments take, so it is the one most worth
// holding still.
func TestSameAgentIdentityMatching(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b *agentid.Identity
		want bool
	}{
		{"nil a", nil, &agentid.Identity{AgentName: "x"}, false},
		{"nil b", &agentid.Identity{AgentName: "x"}, nil, false},
		{"both nil", nil, nil, false},
		{"same key id", &agentid.Identity{AgentName: "a", KeyID: 7}, &agentid.Identity{AgentName: "b", KeyID: 7}, true},
		{"different key id, same name", &agentid.Identity{AgentName: "a", KeyID: 1}, &agentid.Identity{AgentName: "a", KeyID: 2}, false},
		{"no key ids, same name", &agentid.Identity{AgentName: "svc"}, &agentid.Identity{AgentName: "svc"}, true},
		{"no key ids, case-folded name", &agentid.Identity{AgentName: "SVC"}, &agentid.Identity{AgentName: "svc"}, true},
		{"no key ids, different name", &agentid.Identity{AgentName: "svc"}, &agentid.Identity{AgentName: "other"}, false},
		{"one key id, same name", &agentid.Identity{AgentName: "svc", KeyID: 3}, &agentid.Identity{AgentName: "svc"}, true},
	} {
		if got := sameAgent(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: sameAgent = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestDecideFailsClosedWhenAuditUnavailable is the missing twin of
// TestProcessCallFailsClosedWhenAuditUnavailable. Both paths can reach a
// side-effecting execution, so both must refuse when the tamper-evident chain
// cannot record the intent — an action that happens without an audit entry is
// exactly what this system exists to prevent. Only the immediate path was
// covered; the post-approval path, which is the one a human has just said yes
// to, was not.
func TestDecideFailsClosedWhenAuditUnavailable(t *testing.T) {
	st := failAppendStore{memstore.New()}
	// Build the chain against a working store so parking succeeds, then swap in
	// the failing one — the interesting moment is the audit going down between
	// the call being parked and a human approving it.
	chain := newTestChain(t, memstore.New())
	reg := NewRegistry()
	ran := false
	reg.Register(recordingTool{ran: &ran})
	b := New(parkEngine(t), reg, chain)

	id := &agentid.Identity{AgentName: "bot", KeyID: 1}
	parked := b.ProcessCall(context.Background(), id, Call{Tool: "t"})
	if parked.Status != StatusPendingApproval {
		t.Fatalf("expected the call to park, got %q", parked.Status)
	}

	// The chain now cannot append.
	b.chain = newTestChain(t, st)

	out, ok, err := b.Decide(context.Background(), parked.CallID, Approver{Name: "human", IsAdmin: true}, true)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !ok {
		t.Fatal("Decide did not find the parked call")
	}
	if out.Status == StatusExecuted {
		t.Fatal("an approved call executed while the audit chain was unavailable — the post-approval path must fail closed like the immediate one")
	}
	if ran {
		t.Fatal("the tool ran with no durable record that it was going to")
	}
}
