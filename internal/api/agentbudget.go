package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/store"
)

// budgetWindow is how far back a spent-call count reaches.
//
// A ROLLING 24 hours, not a calendar day, and the difference is the point. A
// calendar reset hands every agent a predictable instant at which its quota
// refills, which is exactly when an agent (or whoever is driving it) would queue
// the work it could not do before — and it forces PAMv1 to pick a timezone for
// something that has nothing to do with anyone's working day. A rolling window
// needs no reset job, no timezone, and no midnight.
const budgetWindow = 24 * time.Hour

// budgetStatus is what an agent has spent and what it is allowed.
type budgetStatus struct {
	// Limit is the cap actually in force: the agent's own budget when it has
	// one, otherwise the server default.
	Limit int
	// Unlimited is true when no cap applies at all. It is a separate field
	// rather than "Limit == 0" because zero has two different meanings depending
	// on where it came from: an unset SERVER DEFAULT of 0 means "no budgets
	// configured, let everything through", while an agent whose own budget is
	// explicitly 0 is a deliberate hard stop — that agent may make no calls at
	// all. Collapsing the two would turn the strictest setting in the feature
	// into the most permissive one, which is the failure a reviewer would find
	// last and an operator would find first.
	Unlimited bool
	// PerAgent is the agent's own setting, nil when it inherits the default.
	PerAgent *int
	Used     int
}

// exhausted reports whether the agent has spent its allowance.
func (b budgetStatus) exhausted() bool { return !b.Unlimited && b.Used >= b.Limit }

// agentBudget resolves what an agent identity has spent in the rolling window
// and what it is allowed to spend.
//
// An SVID-authenticated agent has no key row and therefore no per-agent budget —
// it inherits the server default. That is a real gap and it is stated here
// rather than hidden: the fix is per-identity budgets keyed on the SPIFFE ID,
// the same shape Phase 159's quarantine used to cover both identity kinds, and
// it is not built yet.
func (s *Server) agentBudget(ctx context.Context, id *agentid.Identity) (budgetStatus, error) {
	st := budgetStatus{Limit: s.brokerBudgetPerDay, Unlimited: s.brokerBudgetPerDay <= 0}
	if id.KeyID > 0 {
		key, err := s.store.GetAgentKey(ctx, id.KeyID)
		if err != nil {
			return st, err
		}
		if key.BudgetPerDay != nil {
			// An explicit per-agent value is always a limit — including 0, which
			// is how an operator says "this agent may make no calls at all"
			// without deleting it and losing its history.
			st.PerAgent, st.Limit, st.Unlimited = key.BudgetPerDay, *key.BudgetPerDay, false
		}
	}
	// Nothing to count when nothing is limited: an unlimited agent should not pay
	// for a query on every call. Neither should a hard-stopped one — the answer
	// cannot depend on the count.
	if st.Unlimited || st.Limit == 0 {
		return st, nil
	}
	used, err := s.store.CountAgentToolCallsSince(ctx, id.AgentName, time.Now().Add(-budgetWindow))
	if err != nil {
		return st, err
	}
	st.Used = used
	return st, nil
}

// refuseOverBudget reports whether the call must be refused, having already
// written the refusal to the audit trail when it must.
//
// A store failure refuses the call (fail closed). That looks harsh for a
// resource control until you notice what the count is read FROM: the audit
// trail. If it cannot be read, the call could not have been recorded either, and
// the broker already refuses to execute anything it cannot audit — so failing
// closed here costs nothing that was not already lost, and executing "just this
// once, unmeasured" is precisely what a budget exists to prevent.
func (s *Server) refuseOverBudget(w http.ResponseWriter, r *http.Request, id *agentid.Identity, tool string) (bool, *agentSpend) {
	refusal, spend := s.budgetRefusal(r.Context(), id, tool)
	if refusal == nil {
		return false, spend
	}
	writeJSON(w, http.StatusOK, *refusal)
	return true, nil
}

// agentSpend is the budget reservation one call holds (Phase 219): the row
// ReserveAgentCall wrote at the instant the gate decided. nil when nothing was
// limited, so nothing was reserved. The caller settles it with settleSpend once
// the outcome is known.
type agentSpend struct{ id int64 }

// budgetRefusal returns the outcome to hand back when an agent may not spend
// another call — or nil, together with the reservation the call now holds —
// when it may. It is transport-agnostic so the REST and MCP paths share one
// decision: a budget enforced on only one of them is not a budget, and the MCP
// transport is the one an agent framework actually speaks.
//
// Two layers, in order. The audit-trail counts first (Phase 167's budget, Phase
// 209's ceiling): they are the numbers an operator reads, they refuse with those
// numbers, and they cover the window before this replica's ledger has seen a
// call — after an upgrade, or a call audited by a path that did not reserve.
// Then the reservation (Phase 219): a count followed by a call is a
// check-then-act, and two calls arriving together each read the same count,
// both passed, and the limit over-ran by the width of the burst. The
// reservation is the compare-and-spend the counts cannot be, made under the
// store's own serialisation, so exactly the allowed number of a burst get
// through. Both layers refuse under the same audit actions with the same
// detail fields; an investigator cannot tell which one fired, and does not
// need to.
func (s *Server) budgetRefusal(ctx context.Context, id *agentid.Identity, tool string) (*broker.Outcome, *agentSpend) {
	agentLimit := -1 // no daily budget applies
	if s.brokerBudgetPerDay > 0 || id.KeyID > 0 {
		st, err := s.agentBudget(ctx, id)
		if err != nil {
			return s.refuseBudgetUnevaluable(ctx, id, tool, err), nil
		}
		if st.exhausted() {
			return s.refuseBudgetExhausted(ctx, id, tool, st.Used, st.Limit), nil
		}
		if !st.Unlimited {
			agentLimit = st.Limit
		}
	}
	// The per-TOKEN ceiling (Phase 209) is a second, independent limit and is
	// checked here rather than at the REST call site, because the MCP transport
	// calls THIS function directly. It is also why the branch above does not
	// return early when no daily budget applies: an SVID has no key row, so
	// `id.KeyID == 0` is the normal case for exactly the identity kind the
	// ceiling exists for, and returning nil there would have made it inert.
	//
	// Order is deliberate: the daily budget is the coarser, longer-lived
	// statement about an agent, so an agent that is out of budget for the day
	// is told that rather than told about one of its tokens.
	if refusal := s.tokenCeilingRefusal(ctx, id, tool); refusal != nil {
		return refusal, nil
	}
	return s.reserveCall(ctx, id, tool, agentLimit)
}

// reserveCall is the atomic half of the gate: it writes the call's reservation
// against the limits the trail counts just found room under, and turns a refused
// reservation into the same outcome the counts would have produced.
//
// When nothing is limited — no daily budget, and no ceiling or no token to key
// one on — nothing is reserved and the store is not touched: an unlimited agent
// should not pay for a ledger row on every call.
func (s *Server) reserveCall(ctx context.Context, id *agentid.Identity, tool string, agentLimit int) (*broker.Outcome, *agentSpend) {
	tokenLimit := 0
	if id.TokenID != "" {
		tokenLimit = s.brokerMaxCallsPerToken
	}
	if agentLimit < 0 && tokenLimit <= 0 {
		return nil, nil
	}
	now := time.Now()
	res, err := s.store.ReserveAgentCall(ctx, id.AgentName, id.TokenID, now, now.Add(-budgetWindow), agentLimit, tokenLimit)
	if err != nil {
		return s.refuseBudgetUnevaluable(ctx, id, tool, err), nil
	}
	switch res.Refused {
	case store.ReservationRefusedBudget:
		return s.refuseBudgetExhausted(ctx, id, tool, res.AgentUsed, agentLimit), nil
	case store.ReservationRefusedToken:
		return s.refuseTokenExhausted(ctx, id, tool, res.TokenUsed, tokenLimit), nil
	}
	return nil, &agentSpend{id: res.ID}
}

// settleSpend resolves a call's reservation once its outcome is known: kept
// when the call did work, released when it did not, and carried by the parked
// call until an approver, the requester or the sweep ends it. A denial or a
// failure must give the slot back, or the budget would charge for refusals —
// which its interface doc says it must never do.
func (s *Server) settleSpend(ctx context.Context, spend *agentSpend, out broker.Outcome) {
	if spend == nil {
		return
	}
	switch out.Status {
	case broker.StatusExecuted:
		return // spent
	case broker.StatusPendingApproval:
		s.parkedSpends.Store(out.CallID, spend.id)
		return
	}
	s.releaseSpend(ctx, spend.id)
}

// settleParkedSpend resolves the reservation a parked call has been holding
// since it was requested: kept if the approval executed it, released otherwise
// (denied, withdrawn, or expired unapproved). A call this replica never parked
// holds nothing here, which is also the case for a parked call lost to a
// restart — its reservation then stands until it ages out of the window, the
// fail-closed direction.
func (s *Server) settleParkedSpend(ctx context.Context, callID string, executed bool) {
	v, ok := s.parkedSpends.LoadAndDelete(callID)
	if !ok || executed {
		return
	}
	s.releaseSpend(ctx, v.(int64))
}

// releaseSpend gives a reservation back. A failure is logged and otherwise
// left alone: the slot then stays spent until it ages out of the window, which
// under-serves the agent rather than over-serving it.
func (s *Server) releaseSpend(ctx context.Context, id int64) {
	if err := s.store.ReleaseAgentCallReservation(ctx, id); err != nil {
		s.log.Warn("agent call reservation release failed; the slot stays spent until it ages out (fail closed)",
			"reservation", id, "err", err)
	}
}

// refuseBudgetUnevaluable is the fail-closed outcome for a budget that could
// not be read. That looks harsh for a resource control until you notice what
// the count is read FROM: the audit trail. If it cannot be read, the call could
// not have been recorded either, and the broker already refuses to execute
// anything it cannot audit — so failing closed here costs nothing that was not
// already lost, and executing "just this once, unmeasured" is precisely what a
// budget exists to prevent. The reservation ledger is held to the same rule.
func (s *Server) refuseBudgetUnevaluable(ctx context.Context, id *agentid.Identity, tool string, err error) *broker.Outcome {
	s.log.Error("agent budget check failed; refusing the call (fail closed)", "agent", id.AgentName, "err", err)
	_ = s.auditAs(ctx, id.AgentName, "agent.budget_check_failed",
		"agent:"+auditField(id.AgentName, 200)+" tool:"+auditField(tool, 64))
	return &broker.Outcome{
		Status: broker.StatusFailed,
		Reason: "budget could not be evaluated; call refused",
	}
}

// refuseBudgetExhausted audits and returns the daily-budget refusal. Its own
// action, not only a denial: "this agent hit its ceiling" is a fact an operator
// wants to see and alert on directly, and it is the signal that a budget is set
// too low as often as it is the signal that an agent is running away. Both the
// trail count and the reservation refuse through here, so the record is the
// same whichever fired.
func (s *Server) refuseBudgetExhausted(ctx context.Context, id *agentid.Identity, tool string, used, limit int) *broker.Outcome {
	_ = s.auditAs(ctx, id.AgentName, "agent.budget_exhausted",
		fmt.Sprintf("agent:%s tool:%s used:%d limit:%d window:24h",
			auditField(id.AgentName, 200), auditField(tool, 64), used, limit))
	return &broker.Outcome{
		Status: broker.StatusDenied,
		Reason: fmt.Sprintf("daily budget exhausted: %d of %d calls used in the last 24h", used, limit),
	}
}

type budgetIn struct {
	// BudgetPerDay is a pointer so that an explicit null (clear it, inherit the
	// server default) is distinguishable from an omitted field and from 0, which
	// is a deliberate hard stop meaning "this agent may make no calls at all".
	BudgetPerDay *int `json:"budget_per_day"`
}

// maxAgentBudget bounds an accepted budget. High enough that no real workload
// meets it, low enough that a fat-fingered value cannot become an integer that
// misbehaves elsewhere.
const maxAgentBudget = 10_000_000

// setAgentBudget sets or clears one agent identity's daily call budget.
func (s *Server) setAgentBudget(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in budgetIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.BudgetPerDay != nil && (*in.BudgetPerDay < 0 || *in.BudgetPerDay > maxAgentBudget) {
		writeError(w, http.StatusUnprocessableEntity,
			fmt.Sprintf("budget_per_day must be between 0 and %d, or null to inherit the server default", maxAgentBudget))
		return
	}
	key, err := s.store.GetAgentKey(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	if err := s.store.SetAgentKeyBudget(r.Context(), id, in.BudgetPerDay); err != nil {
		storeError(w, err)
		return
	}
	detail := fmt.Sprintf("agent:%s id:%d", auditField(key.Name, 200), id)
	if in.BudgetPerDay == nil {
		detail += " budget:default"
	} else {
		detail += fmt.Sprintf(" budget:%d", *in.BudgetPerDay)
	}
	s.audit(r.Context(), "agent.budget_set", detail)
	w.WriteHeader(http.StatusNoContent)
}

// agentWithBudget is one agent identity plus its live budget usage, which is
// what the console's agent screen lists.
type agentWithBudget struct {
	store.AgentKey
	BudgetUsedToday int `json:"budget_used_today"`
	// BudgetLimitEffective is the limit actually in force — the agent's own when
	// set, otherwise the server default. Zero means unlimited.
	BudgetLimitEffective int `json:"budget_limit_effective"`
	// OwnerKnown reports whether this key's owner matches a PAMv1 user (Phase
	// 175). False means the offboarding cascade — which matches owners by
	// username string — can never reach this agent, usually because of a typo.
	OwnerKnown bool `json:"owner_known"`
}
