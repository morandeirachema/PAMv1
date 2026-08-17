// Package broker is the AI-agent access broker's decision loop, shared by the
// REST and MCP transports. It resolves a policy decision for a tool call and its
// arguments, and on allow executes the tool server-side (which injects the target
// credential just-in-time), returning ONLY the result to the agent — the agent
// never holds a credential. Every outcome is written to the hash-chained audit.
package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/auditfmt"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/policy"
	"github.com/morandeirachema/pamv1/internal/store"
)

// Status is a tool-call outcome. Callers key on this, not the HTTP status code.
type Status string

const (
	StatusExecuted        Status = "executed"
	StatusPendingApproval Status = "pending_approval"
	StatusDenied          Status = "denied"
	StatusFailed          Status = "failed"
)

// terminal reports whether the status is a final outcome (not awaiting a human).
func (s Status) terminal() bool {
	return s == StatusExecuted || s == StatusDenied || s == StatusFailed
}

// The audit action names for a tool call's lifecycle, spelled once here and used
// by BOTH trails — the hash-chained broker audit and the primary audit trail the
// SIEM export and the risk engine read.
//
// They are constants, not concatenations, for a reason that has bitten this
// project twice: `internal/ocsf` classifies actions by exact name, and a name no
// code can emit is a classification that can never fire while reading to a SIEM
// author as coverage. `broker.tool_call.denied` sat in that map from Phase 27 to
// Phase 161 matching nothing, because the only place it was ever written was the
// chain — the primary trail got a flat `broker.tool_call` with the outcome buried
// in the detail text. Naming them here makes the literals greppable, which is
// what the guard test in internal/ocsf now checks.
const (
	ActionToolCallRequested = "broker.tool_call.requested"
	ActionToolCallExecuted  = "broker.tool_call.executed"
	ActionToolCallPending   = "broker.tool_call.pending_approval"
	ActionToolCallDenied    = "broker.tool_call.denied"
	ActionToolCallFailed    = "broker.tool_call.failed"
	ActionToolCallWithdrawn = "broker.tool_call.withdrawn"
	ActionToolCallResumed   = "broker.tool_call.resumed"
)

// ActionFor returns the audit action name for a call outcome's status.
//
// An unrecognised status still yields a well-formed name rather than an empty or
// wrong one: recording a status pamv1 does not know about as "failed" would be a
// lie in the authoritative log, so the name is built from the status itself and
// simply goes unclassified.
func ActionFor(s Status) string {
	switch s {
	case StatusExecuted:
		return ActionToolCallExecuted
	case StatusPendingApproval:
		return ActionToolCallPending
	case StatusDenied:
		return ActionToolCallDenied
	case StatusFailed:
		return ActionToolCallFailed
	}
	return "broker.tool_call." + string(s)
}

// Args are a tool call's arguments (decoded from JSON).
type Args = map[string]any

// Result is a tool's output. For exec/rotate/list tools it never carries
// credential material — the plaintext lives only inside Execute. Sensitive marks
// a result that DOES carry a secret (only reveal_credential), so the broker
// delivers it exactly once and never retains it in the in-memory poll cache.
type Result struct {
	Data      map[string]any
	Sensitive bool
}

// Tool is one brokered operation wrapping a pamv1 action.
type Tool interface {
	Name() string
	Description() string
	InputSchema() map[string]string // field -> "string|int|bool" (validation + MCP tools/list)
	Capability() auth.Capability
	Execute(ctx context.Context, p *auth.Principal, args Args) (Result, error)
}

// Registry holds the available tools by name.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{tools: map[string]Tool{}} }

// Register adds a tool (last registration for a name wins).
func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name()] = t
}

// Get returns the tool with the given name.
func (r *Registry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// List returns the tools sorted by name (for MCP tools/list).
func (r *Registry) List() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Call is a tool-call request from an agent.
type Call struct {
	// SessionID is the agent's own run/conversation identifier, and Client is its
	// self-declared software and model ("claude-code/2.1 (some-model-id)").
	//
	// Both are DECLARED BY THE CALLER and neither is verified, so neither may ever
	// influence a decision — they exist so an investigator can reconstruct one
	// agent run out of a trail that otherwise records each tool call as an
	// unrelated event. That is the whole point: a human session has a session
	// recording tying its actions together, and until Phase 161 an agent run had
	// nothing. They are quoted and bounded before reaching the trail (see
	// runFields), because an unverified string that reaches an audit detail is
	// exactly how a `key:value` record gets forged.
	SessionID string
	Client    string
	Tool      string
	Args      Args
}

// Outcome is the terminal (or pending) result of a tool call.
type Outcome struct {
	CallID string `json:"call_id"`
	// Tool is the tool this call asked for. Carried on the outcome so a status
	// poll and the audit written when a parked call is finally collected can name
	// it: by then the parked call itself has been consumed and is gone.
	Tool string `json:"tool,omitempty"`
	// SessionID echoes back the caller's own run identifier (Call.SessionID). An
	// agent that fires several tool calls concurrently, or collects a parked one
	// much later, gets its correlation key back with the answer instead of having
	// to remember which call id belonged to which run.
	SessionID   string         `json:"session_id,omitempty"`
	Status      Status         `json:"status"`
	Result      map[string]any `json:"result,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	RuleID      string         `json:"rule_id,omitempty"`
	Scope       string         `json:"scope,omitempty"`
	ApprovalID  string         `json:"approval_id,omitempty"`
	ResumeToken string         `json:"resume_token,omitempty"` // single-use ticket to collect a post-approval result

	// jti is the SHA-256 of the resume token — the id its `broker_tokens` row is
	// keyed by. It is unexported, so it never reaches the agent through JSON; it
	// travels with the remembered outcome purely so the park event and the later
	// resume event can be joined to the same token in the trail. Recording it is
	// safe: it is the token's HASH, so it identifies the ticket without being
	// spendable.
	jti string
}

const (
	maxRemembered = 4096 // bound on the in-memory outcome/poll cache
	maxParked     = 1024 // bound on simultaneously-pending approvals (DoS guard)
)

// TokenStore mints and spends the single-use resume tokens for parked calls.
// The store implements it; it is an interface so the broker stays transport- and
// storage-agnostic.
type TokenStore interface {
	CreateBrokerToken(ctx context.Context, t *store.BrokerToken) error
	ConsumeBrokerToken(ctx context.Context, jti string) (callID string, err error)
	PeekBrokerToken(ctx context.Context, jti string) (callID string, err error)
}

// parkedCall is a require_approval tool call awaiting a human decision. It holds
// the requesting agent identity and arguments so the broker can execute it
// server-side (JIT) once approved. approvers is the rule's approver-group set:
// separation of duties requires the deciding human to belong to one of them.
type parkedCall struct {
	callID    string
	id        *agentid.Identity
	call      Call
	scope     string
	ruleID    string
	reason    string
	approvers []string
	requested time.Time
	// jti is the SHA-256 of this call's single-use resume token (see Outcome.jti).
	// Held so the events written when the call is decided, withdrawn or collected
	// name the same ticket the park event named.
	jti string
}

// PendingApproval is an approver-facing view of a parked call (no credential).
type PendingApproval struct {
	CallID     string    `json:"call_id"`
	Tool       string    `json:"tool"`
	Args       Args      `json:"args"`
	Agent      string    `json:"agent"`
	OnBehalfOf string    `json:"on_behalf_of,omitempty"`
	Scope      string    `json:"scope,omitempty"`
	RuleID     string    `json:"rule_id,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Approvers  []string  `json:"approvers,omitempty"` // groups permitted to decide (SoD)
	Requested  time.Time `json:"requested_at"`
}

// Approver identifies the human deciding a parked call, for separation of duties
// (Phase 27). Groups is the decider's membership set (see auth.Principal.
// ApproverGroups): their name plus role names. IsAdmin marks a built-in
// administrator, who may approve any group (the superuser, as everywhere else).
type Approver struct {
	Name    string
	Groups  []string
	IsAdmin bool
}

// ErrNotApprover is returned by Decide when the deciding human is not a member of
// any of the rule's approver groups (separation of duties). The parked call is
// left intact so an authorized approver can still decide it.
var ErrNotApprover = errors.New("broker: not a member of the rule's approver group")

// Broker runs the shared policy loop.
type Broker struct {
	engine   *policy.Engine
	registry *Registry
	chain    *auditchain.Chain
	log      *slog.Logger

	tokens      TokenStore
	notifier    alert.Notifier
	tokenTTL    time.Duration
	maxArgBytes int
	revalidate  func(ctx context.Context, id *agentid.Identity) bool // agent still valid?

	mu     sync.Mutex
	calls  map[string]Outcome     // call_id -> latest outcome (in-memory)
	order  []string               // insertion order, for bounded eviction
	parked map[string]*parkedCall // call_id -> parked approval-pending call
}

// New builds a Broker over a policy engine, tool registry, and audit chain.
func New(engine *policy.Engine, reg *Registry, chain *auditchain.Chain) *Broker {
	return &Broker{
		engine: engine, registry: reg, chain: chain,
		log: logging.Component("broker"), notifier: alert.Noop{}, tokenTTL: 15 * time.Minute,
		calls: map[string]Outcome{}, parked: map[string]*parkedCall{},
	}
}

// WithApproval wires the approval flow: single-use resume tokens (tokenTTL
// lifetime) and an alerter notified when a call is parked. Called by main when
// the broker is enabled; without it, require_approval calls still park and can be
// decided, but no resume token is minted.
func (b *Broker) WithApproval(tokens TokenStore, notifier alert.Notifier, tokenTTL time.Duration) *Broker {
	b.tokens = tokens
	if notifier != nil {
		b.notifier = notifier
	}
	if tokenTTL > 0 {
		b.tokenTTL = tokenTTL
	}
	return b
}

// WithRevalidator sets a hook the broker calls at approval time to confirm the
// requesting agent identity is still valid (its static key not revoked/disabled,
// its SVID not expired). A parked call whose agent was revoked while awaiting a
// human decision is refused instead of executed.
func (b *Broker) WithRevalidator(fn func(ctx context.Context, id *agentid.Identity) bool) *Broker {
	b.revalidate = fn
	return b
}

// WithArgCap sets the maximum serialized size (bytes) of a tool call's arguments;
// 0 disables the cap. A hostile or accidental oversized argument is rejected
// before policy evaluation.
func (b *Broker) WithArgCap(n int) *Broker {
	b.maxArgBytes = n
	return b
}

type approvedKey struct{}

// WithApproved marks a context as carrying a human approval for the current tool
// call, so a tool's target-level approval gate treats it as satisfied (the
// approver just provided four-eyes for this exact call).
func WithApproved(ctx context.Context) context.Context {
	return context.WithValue(ctx, approvedKey{}, true)
}

// Approved reports whether the context carries a human approval (see WithApproved).
func Approved(ctx context.Context) bool {
	v, _ := ctx.Value(approvedKey{}).(bool)
	return v
}

// Tools returns the registered tools (for MCP tools/list).
func (b *Broker) Tools() []Tool { return b.registry.List() }

// ProcessCall evaluates policy and, on allow, executes the tool server-side,
// returning only the result. Deny and (for now) require_approval are terminal
// here; the approval decision + resume flow lands in a later increment.
func (b *Broker) ProcessCall(ctx context.Context, id *agentid.Identity, c Call) Outcome {
	out := Outcome{CallID: newCallID(), SessionID: c.SessionID, Tool: c.Tool}

	// Reject an oversized argument set before doing any work — the cap bounds both
	// audit-row bloat and a hostile payload. Recorded as a failure, still audited.
	if b.maxArgBytes > 0 {
		if raw, _ := json.Marshal(c.Args); len(raw) > b.maxArgBytes {
			out.Status, out.Reason = StatusFailed, fmt.Sprintf("arguments exceed %d-byte limit", b.maxArgBytes)
			b.remember(out)
			if err := b.chainEvent(ctx, id, c, ActionToolCallFailed, out, out.Reason); err != nil {
				b.log.Error("broker audit chain append failed", "call", out.CallID, "err", err)
			}
			return out
		}
	}

	// Policy decides first: deny and require_approval need no tool, and an unknown
	// tool with no matching rule is denied by default (fail-closed), never run.
	d := b.engine.Evaluate(c.Tool, c.Args)
	out.RuleID, out.Scope, out.Reason = d.RuleID, d.Scope, d.Reason
	var sensitive bool // the executed result carries a secret (reveal_credential)
	switch d.Effect {
	case policy.EffectDeny:
		out.Status = StatusDenied
	case policy.EffectRequireApproval:
		out.Status = StatusPendingApproval
		out.ApprovalID = out.CallID
		b.park(ctx, id, c, d.Approvers, &out)
	case policy.EffectAllow:
		tool, ok := b.registry.Get(c.Tool)
		if !ok {
			out.Status, out.Reason = StatusFailed, "unknown tool: "+c.Tool
			break
		}
		// Capability backstop: the principal must hold the tool's capability, so
		// authorization never rests on the policy YAML alone.
		if !id.Principal().Can(tool.Capability()) {
			out.Status, out.Reason = StatusDenied, "principal lacks the capability for this tool"
			break
		}
		// Record the intent in the tamper-evident chain BEFORE running a
		// side-effecting action, so an executed action can never be missing from
		// the authoritative log. If the chain is unavailable, refuse to run (fail
		// closed) rather than execute unauditably.
		if err := b.chainEvent(ctx, id, c, ActionToolCallRequested, out, ""); err != nil {
			b.log.Error("broker audit chain unavailable; refusing tool call", "call", out.CallID, "err", err)
			out.Status, out.Reason = StatusFailed, "audit log unavailable; call refused"
			break
		}
		res, err := tool.Execute(ctx, id.Principal(), c.Args)
		if err != nil {
			out.Status, out.Reason = StatusFailed, err.Error()
		} else {
			out.Status, out.Result, sensitive = StatusExecuted, res.Data, res.Sensitive
		}
	default:
		out.Status, out.Reason = StatusFailed, "policy returned no effect"
	}

	// A secret-bearing immediate result is delivered once in the returned outcome
	// but never retained in the poll cache — there is no resume token for an
	// allow (non-parked) call, so it can never be collected again.
	stored := out
	if sensitive {
		stored.Result = nil
	}
	b.remember(stored)
	// Record the terminal outcome (best-effort: for a side-effecting call the
	// "requested" event above already durably captured it in the chain).
	if err := b.chainEvent(ctx, id, c, ActionFor(out.Status), out, out.Reason); err != nil {
		b.log.Error("broker audit chain append failed", "call", out.CallID, "err", err)
	}
	return out
}

// park stores an approval-pending call, notifies an approver, and (when a token
// store is wired) mints a single-use resume token returned in out.ResumeToken.
// approvers is the rule's approver-group set, enforced at decision time (SoD).
func (b *Broker) park(ctx context.Context, id *agentid.Identity, c Call, approvers []string, out *Outcome) {
	b.mu.Lock()
	full := len(b.parked) >= maxParked
	if !full {
		b.parked[out.CallID] = &parkedCall{callID: out.CallID, id: id, call: c, scope: out.Scope, ruleID: out.RuleID, reason: out.Reason, approvers: approvers, requested: time.Now().UTC()}
	}
	b.mu.Unlock()
	// Fail closed rather than let unbounded pending approvals exhaust memory.
	if full {
		out.Status, out.Reason, out.ApprovalID = StatusFailed, "too many pending approvals; try again later", ""
		b.log.Warn("broker parked-approval cap reached; refusing new require_approval call", "cap", maxParked)
		return
	}

	if b.tokens != nil {
		token := newOpaqueToken()
		bt := store.BrokerToken{JTI: hashToken(token), CallID: out.CallID, ExpiresAt: time.Now().Add(b.tokenTTL).UTC()}
		if err := b.tokens.CreateBrokerToken(ctx, &bt); err != nil {
			b.log.Error("broker resume token mint failed", "call", out.CallID, "err", err)
		} else {
			out.ResumeToken, out.jti = token, bt.JTI
			// The parked call was inserted before the token existed, so stamp it now.
			// Under the lock: a human approver may already be deciding this call.
			b.mu.Lock()
			if pc, ok := b.parked[out.CallID]; ok {
				pc.jti = bt.JTI
			}
			b.mu.Unlock()
		}
	}
	b.notifier.Notify(ctx, alert.Event{
		Type:   "broker.approval.pending",
		Actor:  id.AgentName,
		Detail: fmt.Sprintf("agent %q requests %s (call %s, rule %s)", id.AgentName, c.Tool, out.CallID, out.RuleID),
		Time:   time.Now().UTC(),
	})
}

// PendingApprovals lists the parked calls awaiting a human decision.
func (b *Broker) PendingApprovals() []PendingApproval {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]PendingApproval, 0, len(b.parked))
	for callID, p := range b.parked {
		out = append(out, PendingApproval{
			CallID: callID, Tool: p.call.Tool, Args: p.call.Args,
			Agent: p.id.AgentName, OnBehalfOf: p.id.OnBehalfOf, Scope: p.scope,
			RuleID: p.ruleID, Reason: p.reason, Approvers: p.approvers, Requested: p.requested,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Requested.Before(out[j].Requested) })
	return out
}

// Decide resolves a parked approval: on approve the broker executes the tool
// server-side (JIT credential injection) and stores the terminal result; on
// reject the call becomes denied. Either way the decision is recorded in the
// tamper-evident chain attributed to the human approver. Separation of duties
// (Phase 27): the approver must belong to one of the rule's approver groups, or
// be an administrator — otherwise the call is left parked and (ErrNotApprover) is
// returned. Unknown/expired call -> ok=false.
func (b *Broker) Decide(ctx context.Context, callID string, approver Approver, approve bool) (Outcome, bool, error) {
	b.mu.Lock()
	p, ok := b.parked[callID]
	if !ok {
		b.mu.Unlock()
		return Outcome{}, false, nil
	}
	// SoD check BEFORE consuming the parked call, so a refusal leaves it decidable
	// by an authorized approver rather than silently discarding it.
	if !approverPermitted(approver, p.approvers) {
		b.mu.Unlock()
		refused := Outcome{CallID: callID, SessionID: p.call.SessionID, Tool: p.call.Tool, RuleID: p.ruleID, Scope: p.scope}
		b.chainApproval(ctx, p, approver.Name, "broker.approval.refused", refused)
		b.log.Warn("broker approval refused: approver not in rule's group",
			"call", callID, "approver", approver.Name, "required", strings.Join(p.approvers, ","))
		return Outcome{}, true, ErrNotApprover
	}
	delete(b.parked, callID)
	b.mu.Unlock()

	out := Outcome{CallID: callID, SessionID: p.call.SessionID, Tool: p.call.Tool, RuleID: p.ruleID, Scope: p.scope, jti: p.jti}
	if !approve {
		out.Status, out.Reason = StatusDenied, "rejected by "+approver.Name
		b.chainApproval(ctx, p, approver.Name, "broker.approval.denied", out)
		b.remember(out)
		return out, true, nil
	}

	b.chainApproval(ctx, p, approver.Name, "broker.approval.granted", out)
	tool, exists := b.registry.Get(p.call.Tool)
	if !exists {
		out.Status, out.Reason = StatusFailed, "unknown tool: "+p.call.Tool
		b.remember(out)
		_ = b.chainEvent(ctx, p.id, p.call, ActionToolCallFailed, out, out.Reason)
		return out, true, nil
	}
	// Capability backstop: the principal must hold the tool's capability (auth is
	// the single source of truth; policy is not the only gate).
	if !p.id.Principal().Can(tool.Capability()) {
		out.Status, out.Reason = StatusDenied, "principal lacks the capability for this tool"
		b.remember(out)
		_ = b.chainEvent(ctx, p.id, p.call, ActionToolCallDenied, out, out.Reason)
		return out, true, nil
	}
	// Re-check the agent is still valid: a call parked before its key was revoked
	// (or its SVID expired) must not execute just because a human approved it.
	if b.revalidate != nil && !b.revalidate(ctx, p.id) {
		out.Status, out.Reason = StatusDenied, "agent identity is no longer valid (revoked or expired)"
		b.remember(out)
		_ = b.chainEvent(ctx, p.id, p.call, ActionToolCallDenied, out, out.Reason)
		return out, true, nil
	}
	// Record intent before the side effect, fail closed if the chain is down.
	if err := b.chainEvent(ctx, p.id, p.call, ActionToolCallRequested, out, ""); err != nil {
		out.Status, out.Reason = StatusFailed, "audit log unavailable; call refused"
		b.remember(out)
		return out, true, nil
	}
	// The human approval satisfies any target-level four-eyes gate for this call.
	res, err := tool.Execute(WithApproved(ctx), p.id.Principal(), p.call.Args)
	if err != nil {
		out.Status, out.Reason = StatusFailed, err.Error()
	} else {
		out.Status, out.Result = StatusExecuted, res.Data
	}
	b.remember(out) // full outcome — the agent collects it once via the resume token
	if err := b.chainEvent(ctx, p.id, p.call, ActionFor(out.Status), out, out.Reason); err != nil {
		b.log.Error("broker audit chain append failed", "call", out.CallID, "err", err)
	}
	// The approver receives the decision status, never a secret-bearing result; a
	// Sensitive result (reveal_credential) is delivered only to the requesting
	// agent, once, through the single-use resume token.
	if res.Sensitive {
		out.Result = nil
	}
	return out, true, nil
}

// approverPermitted reports whether a decider may resolve a parked call under
// separation of duties: an administrator always may (the superuser, as
// everywhere), a rule that named no approver group admits anyone, otherwise the
// decider must share a group with the rule's approver set (case-insensitive).
func approverPermitted(a Approver, required []string) bool {
	if a.IsAdmin || len(required) == 0 {
		return true
	}
	for _, want := range required {
		for _, have := range a.Groups {
			if strings.EqualFold(want, have) {
				return true
			}
		}
	}
	return false
}

// Withdraw denies a parked call at the request of its OWN requester (Phase 27:
// MCP elicitation — the running user declined the confirmation). It needs no
// approver and does not satisfy four-eyes: it only lets the party that asked for
// the action take it back, so a still-parked call an out-of-band approver never
// saw is cleaned up. The requester identity must match the parked call's agent —
// by static-key row id when both have one (agent names are not unique), else by
// name. Returns ok=false for an unknown call or an identity mismatch.
func (b *Broker) Withdraw(ctx context.Context, callID string, requester *agentid.Identity) (Outcome, bool) {
	b.mu.Lock()
	p, ok := b.parked[callID]
	if !ok || !sameAgent(p.id, requester) {
		b.mu.Unlock()
		return Outcome{}, false
	}
	delete(b.parked, callID)
	b.mu.Unlock()
	out := Outcome{CallID: callID, SessionID: p.call.SessionID, Tool: p.call.Tool, RuleID: p.ruleID, Scope: p.scope, jti: p.jti, Status: StatusDenied, Reason: "withdrawn by requester"}
	b.remember(out)
	if err := b.chainEvent(ctx, p.id, p.call, ActionToolCallWithdrawn, out, out.Reason); err != nil {
		b.log.Error("broker withdraw audit append failed", "call", callID, "err", err)
	}
	return out, true
}

// sameAgent reports whether two identities are the same agent: by static-key row
// id when both carry one (names are not unique), otherwise by case-folded name.
func sameAgent(a, b *agentid.Identity) bool {
	if a == nil || b == nil {
		return false
	}
	if a.KeyID > 0 && b.KeyID > 0 {
		return a.KeyID == b.KeyID
	}
	return strings.EqualFold(a.AgentName, b.AgentName)
}

// ApprovalOwner returns the accountable owner (on-behalf-of) of a parked call, so
// the operator layer can refuse a self-approval (owner approving their own agent).
func (b *Broker) ApprovalOwner(callID string) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.parked[callID]
	if !ok {
		return "", false
	}
	return p.id.OnBehalfOf, true
}

// SweepExpiredParked drops parked approvals older than the resume-token TTL (the
// token they'd resume with has expired anyway), so an abandoned backlog can't
// permanently hold the parked cap. Each swept call is recorded as a terminal
// failed outcome (so an agent polling its status sees a resolution instead of an
// eternal pending) and appended to the tamper-evident chain (so the trail shows
// how the parked call ended). Returns the number evicted.
func (b *Broker) SweepExpiredParked(ctx context.Context, now time.Time) int {
	b.mu.Lock()
	var expired []*parkedCall
	for id, p := range b.parked {
		if now.Sub(p.requested) > b.tokenTTL {
			expired = append(expired, p)
			delete(b.parked, id)
		}
	}
	b.mu.Unlock()
	for _, p := range expired {
		out := Outcome{CallID: p.callID, RuleID: p.ruleID, Scope: p.scope, Status: StatusFailed, Reason: "approval expired before a decision"}
		b.remember(out)
		if err := b.chainEvent(ctx, p.id, p.call, ActionToolCallFailed, out, out.Reason); err != nil {
			b.log.Error("broker sweep audit append failed", "call", p.callID, "err", err)
		}
	}
	return len(expired)
}

// Resume spends a single-use token and returns the stored outcome for its bound
// call, so an agent collects a post-approval result exactly once. It peeks the
// token first, verifies it unlocks the expected call (wantCallID; "" skips the
// check for transports without a path id), and refuses to spend it while the call
// is still pending (so an early resume — or a wrong path id — can't burn the
// ticket before the result exists); the token is consumed only once a terminal
// outcome is actually returned. A mismatched, used, expired, unknown token, or a
// still-pending call yields ok=false. A collected Sensitive result is then
// stripped from the cache so the secret does not linger past its single delivery.
func (b *Broker) Resume(ctx context.Context, id *agentid.Identity, token, wantCallID string) (Outcome, bool) {
	if b.tokens == nil {
		return Outcome{}, false
	}
	jti := hashToken(token)
	callID, err := b.tokens.PeekBrokerToken(ctx, jti)
	if err != nil {
		return Outcome{}, false
	}
	if wantCallID != "" && callID != wantCallID {
		return Outcome{}, false // token does not unlock this path's call — never spend it
	}
	out, ok := b.Lookup(callID)
	if !ok || !out.Status.terminal() {
		return Outcome{}, false // don't spend the token before the call is collectable
	}
	if _, err := b.tokens.ConsumeBrokerToken(ctx, jti); err != nil {
		return Outcome{}, false // lost the single-use race
	}
	b.stripSensitive(callID)
	// Record the collection in the tamper-evident chain, not only in the primary
	// trail. The chain is the authoritative record, and until Phase 161 it ended
	// at the approval decision: the moment the agent actually TOOK the result —
	// which for reveal_credential is the moment a secret left pamv1 — appeared
	// nowhere in it. The event names the token by its id, so it joins to the park
	// event that minted it and to the broker_tokens row that was spent.
	out.jti = jti
	if err := b.chainEvent(ctx, id, Call{SessionID: out.SessionID, Tool: out.Tool}, ActionToolCallResumed, out, ""); err != nil {
		b.log.Error("broker resume audit append failed", "call", callID, "err", err)
	}
	return out, true
}

// stripSensitive clears a collected call's result from the in-memory cache, so a
// secret-bearing (reveal_credential) result delivered once via Resume does not
// linger in b.calls until eviction. The status/metadata are kept.
func (b *Broker) stripSensitive(callID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if o, ok := b.calls[callID]; ok && o.Result != nil {
		o.Result = nil
		b.calls[callID] = o
	}
}

// Lookup returns the latest known outcome for a call id.
func (b *Broker) Lookup(callID string) (Outcome, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	o, ok := b.calls[callID]
	return o, ok
}

// remember stores the outcome, evicting the oldest when over the cap.
func (b *Broker) remember(out Outcome) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.calls[out.CallID]; !exists {
		b.order = append(b.order, out.CallID)
		if len(b.order) > maxRemembered {
			delete(b.calls, b.order[0])
			b.order = b.order[1:]
		}
	}
	b.calls[out.CallID] = out
}

// chainEvent appends one broker audit event (a pre-execution "requested" record
// or a terminal outcome) to the tamper-evident chain and returns any error so the
// caller can fail closed. The request arguments (never a credential — the broker
// injects that) are recorded so the trail shows what was asked.
func (b *Broker) chainEvent(ctx context.Context, id *agentid.Identity, c Call, action string, out Outcome, reason string) error {
	detail := fmt.Sprintf("tool:%s call:%s rule:%s%s args:%s", c.Tool, out.CallID, out.RuleID, runFields(c, out), argsSummary(c.Args))
	if reason != "" {
		detail += " reason:" + reason
	}
	_, err := b.chain.Append(ctx, store.BrokerAuditEvent{
		Actor:      id.AgentName,
		OnBehalfOf: id.OnBehalfOf,
		ActorChain: chainJSON(id.ActorChain),
		Action:     action,
		Detail:     detail,
		Scope:      out.Scope,
	})
	return err
}

// runFields renders the correlation fields that let an investigator reassemble
// one agent run: the caller's declared run id, its declared client/model, and the
// resume token's id when the call was parked for approval.
//
// Each is emitted only when present, so an event about a call that declared
// nothing is not padded with empty keys. The two caller-declared values go
// through auditfmt.Field — quoted and bounded — because they are unverified text
// from the agent, and an unquoted value in a `key:value` detail lets whoever
// controls it invent fields (a session id of `x actor:admin` would otherwise read
// as a second, forged key). The jti is a hex hash pamv1 computed itself, so it
// needs no quoting.
func runFields(c Call, out Outcome) string {
	var b strings.Builder
	if c.SessionID != "" {
		b.WriteString(" session:" + auditfmt.Field(c.SessionID, maxRunFieldBytes))
	}
	if c.Client != "" {
		b.WriteString(" client:" + auditfmt.Field(c.Client, maxRunFieldBytes))
	}
	if out.jti != "" {
		b.WriteString(" jti:" + out.jti)
	}
	return b.String()
}

// maxRunFieldBytes bounds each caller-declared correlation value. Generous enough
// for a UUID, a model name or a client version string, and far too small to make
// the audit trail a place to store data.
const maxRunFieldBytes = 128

// argsSummary renders the call arguments as compact JSON, capped so a large or
// hostile argument can't bloat an audit row.
func argsSummary(args Args) string {
	b, err := json.Marshal(args)
	if err != nil {
		return "{}"
	}
	const cap = 512
	if len(b) > cap {
		return string(b[:cap]) + "…"
	}
	return string(b)
}

// chainJSON renders a delegation actor chain as a JSON array ("" when empty).
func chainJSON(chain []string) string {
	if len(chain) == 0 {
		return ""
	}
	b, _ := json.Marshal(chain)
	return string(b)
}

// newCallID returns an opaque, unguessable call identifier.
func newCallID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "call_" + hex.EncodeToString(b[:])
}

// newOpaqueToken returns a high-entropy resume token (the secret handed to the
// agent); only its hash is stored.
func newOpaqueToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return "brt_" + hex.EncodeToString(b[:])
}

// hashToken returns the hex SHA-256 of a resume token, used as its stored JTI so
// the plaintext token is never persisted. It delegates to auth.TokenHash, the
// single definition shared by every token-hashing site.
func hashToken(token string) string { return auth.TokenHash(token) }

// chainApproval records a human approval decision in the tamper-evident chain,
// attributed to the approver, over the agent's parked call.
func (b *Broker) chainApproval(ctx context.Context, p *parkedCall, approver, action string, out Outcome) {
	if _, err := b.chain.Append(ctx, store.BrokerAuditEvent{
		Actor:      approver,
		OnBehalfOf: p.id.AgentName,
		ActorChain: chainJSON(p.id.ActorChain),
		Action:     action,
		Detail:     fmt.Sprintf("tool:%s call:%s rule:%s%s args:%s", p.call.Tool, out.CallID, out.RuleID, runFields(p.call, out), argsSummary(p.call.Args)),
		Scope:      out.Scope,
	}); err != nil {
		b.log.Error("broker approval audit append failed", "call", out.CallID, "err", err)
	}
}
