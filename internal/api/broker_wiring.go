package api

import (
	"context"
	"fmt"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/ratelimit"
)

// setupBroker constructs the AI-agent access broker when a policy engine is
// supplied (Phase 13). It builds the tamper-evident audit chain, the tool
// registry, and the agent-key verifier. A nil policy leaves the broker disabled.
func (s *Server) setupBroker(opts Options) error {
	if opts.BrokerPolicy == nil {
		return nil
	}
	chain, err := auditchain.New(context.Background(), opts.BrokerAuditKey, opts.BrokerAuditSignKey, s.store)
	if err != nil {
		return fmt.Errorf("api: broker audit chain: %w", err)
	}
	chain.WithRotation(opts.BrokerAuditSignPrevKeys...).WithCheckpointEvery(opts.BrokerCheckpointEvery)
	reg := broker.NewRegistry()
	s.registerBrokerTools(reg)
	s.auditChain = chain
	s.broker = broker.New(opts.BrokerPolicy, reg, chain).
		WithApproval(s.store, s.alerter, opts.BrokerTokenTTL).
		WithArgCap(opts.BrokerMaxArgBytes).
		WithResultCap(opts.BrokerMaxResultBytes).
		WithRevalidator(s.revalidateAgent)
	s.brokerLimiter = ratelimit.New(opts.BrokerRatePerMin)
	s.brokerBudgetPerDay = opts.BrokerBudgetPerDay
	s.brokerRequireEnrolledSVID = opts.BrokerRequireEnrolledSVID
	s.mcpSessions = newMCPSessionRegistry()
	// Static agent keys are always accepted; a SPIFFE SVID verifier, when
	// configured, is tried alongside them (Phase 13d).
	verifier := agentid.MultiVerifier{agentid.NewStaticVerifier(s.store)}
	if opts.BrokerSVIDVerifier != nil {
		verifier = append(verifier, opts.BrokerSVIDVerifier)
	}
	s.agentVerifier = verifier
	// Token exchange (Phase 57): the minter takes the SAME composed verifier the
	// ingress uses, so an actor may present a trust-domain SVID or a token this
	// broker minted earlier — which is what makes a second delegation link
	// possible without a privileged second verification path.
	if len(opts.BrokerTokenSignKey) > 0 {
		x, xerr := agentid.NewExchanger(agentid.ExchangerConfig{
			SignKey:  opts.BrokerTokenSignKey,
			Audience: opts.BrokerAudience,
			TTL:      opts.BrokerExchangeTTL,
			MaxDepth: opts.BrokerMaxDelegation,
			Verifier: verifier,
		})
		if xerr != nil {
			return fmt.Errorf("api: broker token exchange: %w", xerr)
		}
		s.exchanger = x
		s.log.Info("agent broker mints delegated SVIDs (RFC 8693)", "kid", x.KeyID(), "ttl", opts.BrokerExchangeTTL)
	}
	s.log.Info("agent access broker enabled", "tools", len(reg.List()), "policy_rules", opts.BrokerPolicy.Rules())
	return nil
}

// revalidateAgent reports whether a parked call's agent identity is still valid at
// approval time: it must not be quarantined, its credential must not have
// expired, and a static agent key must not have been revoked or disabled since
// the call was parked.
//
// The quarantine check is deliberately FIRST and unconditional, because it is the
// only one of the three that covers every identity kind. The key checks below it
// are gated on KeyID > 0, and an SVID identity has KeyID == 0 — so for a
// SPIFFE deployment (the intended production posture) those checks are no-ops and
// the token's own expiry was the only thing that could ever stop a parked call.
// Quarantining the subject is what gives an incident responder a same-second stop
// for an attested agent, at the two moments an agent's identity is consulted:
// ingress (agentAuth) and approval-time revalidation (here). Without this half, a
// call parked before the quarantine would still execute after it.
//
// It is the same chain-following check the ingress gate runs
// (quarantinedSubject): a call parked by a sub-agent must stop when the root it
// acts for is quarantined, which is precisely the call a responder is racing —
// one already waiting for a human to press approve.
func (s *Server) revalidateAgent(ctx context.Context, id *agentid.Identity) bool {
	hit, err := s.quarantinedSubject(ctx, id)
	if err != nil || hit != "" {
		if err != nil {
			s.log.Error("agent quarantine re-check failed; refusing the parked call (fail closed)",
				"agent", id.AgentName, "err", err)
		} else if hit != id.AgentName {
			s.log.Warn("parked call refused: an actor in its delegation chain is quarantined",
				"agent", id.AgentName, "subject", hit)
		}
		return false
	}
	if !id.ExpiresAt.IsZero() && time.Now().After(id.ExpiresAt) {
		return false
	}
	if id.KeyID > 0 {
		k, err := s.store.GetAgentKey(ctx, id.KeyID)
		if err != nil || !k.Active(time.Now()) {
			return false
		}
	}
	return true
}
