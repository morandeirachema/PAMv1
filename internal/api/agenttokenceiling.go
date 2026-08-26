package api

// agenttokenceiling.go bounds what may be done with ONE token (Phase 209).
//
// The gap this closes, and the correction it carries. The roadmap listed this as
// "no ceiling on a single *run* — calls or targets touched under one
// `session:`". Building it that way would have been wrong, and the codebase
// already said so: `broker.Call.SessionID` is DECLARED BY THE CALLER and its doc
// comment states plainly that it "may never influence a decision". A ceiling
// keyed on `session:` is escaped by sending a different string — by the exact
// party it constrains. It would be a lint, not a control.
//
// So the ceiling is keyed on the presented token's `jti`, which the ISSUER
// chooses: PAMv1 itself for a delegated token. An agent cannot mint itself a
// fresh allowance without going back through the exchange, and that path is
// audited, depth-capped, `may_act`-gated and — since Phase 206 — able to require
// proof of possession.
//
// WHAT IT IS FOR. The per-minute rate limit bounds a burst; the per-day budget
// bounds a total. Neither bounds the thing an operator actually worries about
// with a delegated credential: that ONE token, handed to one sub-agent for one
// task, quietly does two hundred things. A per-token ceiling makes the blast
// radius of a single credential a number an operator sets rather than a
// consequence of how long the token happens to live.
//
// WHAT IT IS NOT. It is not a substitute for the daily budget and does not
// replace it: both are evaluated, and the stricter one wins by simply being
// checked first-to-fire. And it cannot apply to a static agent key, which
// carries no token id at all — that identity kind's ceiling is the per-day
// budget on its own key row, which is why an empty `jti` is answered
// "unlimited" rather than "refuse".

import (
	"context"
	"fmt"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/store"
)

// tokenCeilingRefusal returns the outcome to hand back when a token has spent
// its ceiling, or nil when the call may proceed.
//
// It is transport-agnostic for the same reason budgetRefusal is: a ceiling
// enforced on REST but not on MCP is not a ceiling, and MCP is the transport an
// agent framework actually speaks.
//
// Fail-closed on a store error, matching the budget beside it. An unevaluable
// ceiling must never read as "no ceiling" — that is the direction in which a
// database hiccup silently removes a control.
func (s *Server) tokenCeilingRefusal(ctx context.Context, id *agentid.Identity, tool string) *broker.Outcome {
	if s.brokerMaxCallsPerToken <= 0 {
		return nil // not configured
	}
	if id.TokenID == "" {
		// A static agent key, or an SVID whose issuer stamped no `jti`. Neither
		// can be counted, and both are left to the per-day budget. Stated here
		// rather than silently skipped, because "this control does not cover
		// that identity kind" is exactly what an operator must not have to
		// discover by experiment — the ADMIN-GUIDE says the same thing.
		return nil
	}
	used, err := s.store.CountAgentCallsForTokenSince(ctx, id.AgentName, id.TokenID, time.Now().Add(-budgetWindow))
	if err != nil {
		s.log.Error("agent token ceiling check failed; refusing the call (fail closed)",
			"agent", id.AgentName, "err", err)
		_ = s.auditAs(ctx, id.AgentName, "agent.token_budget_check_failed",
			"agent:"+auditField(id.AgentName, 200)+" tool:"+auditField(tool, 64))
		return &broker.Outcome{
			Status: broker.StatusFailed,
			Reason: "token ceiling could not be evaluated; call refused",
		}
	}
	if used < s.brokerMaxCallsPerToken {
		return nil
	}
	// Its own action rather than a generic denial, for the same reason
	// `agent.budget_exhausted` has one: "this token hit its ceiling" is a fact an
	// operator alerts on directly, and it reads as a runaway sub-agent as often
	// as it reads as a ceiling set too low. The `svid_jti:` field is written
	// through the same helper the count searches for, so an investigator can join
	// this record to the calls that spent it and to the mint that issued it.
	_ = s.auditAs(ctx, id.AgentName, "agent.token_budget_exhausted",
		fmt.Sprintf("agent:%s tool:%s used:%d limit:%d window:24h%s",
			auditField(id.AgentName, 200), auditField(tool, 64),
			used, s.brokerMaxCallsPerToken, store.AgentTokenAuditField(id.TokenID)))
	return &broker.Outcome{
		Status: broker.StatusDenied,
		Reason: fmt.Sprintf("this token has spent its ceiling: %d of %d calls. A new token starts a new ceiling.",
			used, s.brokerMaxCallsPerToken),
	}
}
