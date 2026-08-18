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
// the work it could not do before — and it forces pamv1 to pick a timezone for
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
func (s *Server) refuseOverBudget(w http.ResponseWriter, r *http.Request, id *agentid.Identity, tool string) bool {
	refusal := s.budgetRefusal(r.Context(), id, tool)
	if refusal == nil {
		return false
	}
	writeJSON(w, http.StatusOK, *refusal)
	return true
}

// budgetRefusal returns the outcome to hand back when an agent may not spend
// another call, or nil when it may. It is transport-agnostic so the REST and MCP
// paths share one decision — a budget enforced on only one of them is not a
// budget, and the MCP transport is the one an agent framework actually speaks.
func (s *Server) budgetRefusal(ctx context.Context, id *agentid.Identity, tool string) *broker.Outcome {
	if s.brokerBudgetPerDay <= 0 && id.KeyID == 0 {
		return nil // nothing configured and no per-agent setting is possible
	}
	st, err := s.agentBudget(ctx, id)
	if err != nil {
		s.log.Error("agent budget check failed; refusing the call (fail closed)", "agent", id.AgentName, "err", err)
		_ = s.auditAs(ctx, id.AgentName, "agent.budget_check_failed",
			"agent:"+auditField(id.AgentName, 200)+" tool:"+auditField(tool, 64))
		return &broker.Outcome{
			Status: broker.StatusFailed,
			Reason: "budget could not be evaluated; call refused",
		}
	}
	if !st.exhausted() {
		return nil
	}
	// Audited under its own action, not only as a denial: "this agent hit its
	// ceiling" is a fact an operator wants to see and alert on directly, and it
	// is the signal that a budget is set too low as often as it is the signal
	// that an agent is running away.
	_ = s.auditAs(ctx, id.AgentName, "agent.budget_exhausted",
		fmt.Sprintf("agent:%s tool:%s used:%d limit:%d window:24h",
			auditField(id.AgentName, 200), auditField(tool, 64), st.Used, st.Limit))
	return &broker.Outcome{
		Status: broker.StatusDenied,
		Reason: fmt.Sprintf("daily budget exhausted: %d of %d calls used in the last 24h", st.Used, st.Limit),
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
}
