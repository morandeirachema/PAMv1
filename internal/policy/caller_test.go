package policy

import (
	"strings"
	"testing"
)

// mustEngine loads a policy that is expected to be valid.
func mustEngine(t *testing.T, src string) *Engine {
	t.Helper()
	e, err := Load(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Load: %v\npolicy:\n%s", err, src)
	}
	return e
}

// TestRulePrincipalSide is Phase 173's headline: a rule can finally say WHO it
// applies to, so one `allow` for a dangerous tool no longer enables it for every
// agent in the deployment.
//
// Until this phase `Rule` had no agent field at all. An operator who wanted
// "only the rotation bot may reveal a credential" had no way to write it —
// CyberArk (principal×resource pairs), Teleport (per-role `mcp.tools`) and
// StrongDM (per-agent-per-destination) all model the principal side, and this
// package's own sudoers analogy was incomplete: sudoers has a user column.
func TestRulePrincipalSide(t *testing.T) {
	e := mustEngine(t, `
rules:
  - id: only-rotator-reveals
    tool: reveal_credential
    agents: [rotation-bot]
    effect: allow
  - id: everyone-lists
    tool: list_targets
    effect: allow
`)
	rotator := Caller{Agent: "rotation-bot"}
	other := Caller{Agent: "planner-bot"}

	if d := e.Evaluate(rotator, "reveal_credential", nil); d.Effect != EffectAllow || d.RuleID != "only-rotator-reveals" {
		t.Fatalf("the named agent should match its rule: %+v", d)
	}
	// The whole point: the same rule must not cover a different agent, which
	// then falls through to the implicit default deny.
	if d := e.Evaluate(other, "reveal_credential", nil); d.Effect != EffectDeny || d.RuleID != "implicit-default-deny" {
		t.Fatalf("an unnamed agent must fall through to the default deny: %+v", d)
	}
	// A rule with no agents list still matches everyone — every policy written
	// before this phase behaves exactly as it did.
	for _, c := range []Caller{rotator, other} {
		if d := e.Evaluate(c, "list_targets", nil); d.Effect != EffectAllow {
			t.Fatalf("a rule with no principal side must match every agent: %+v", d)
		}
	}
}

// TestNotAgentsExcludesTheWholeChain pins the asymmetry between the two
// principal-side lists, which is deliberate: `agents` (which grants) matches the
// presenter only, while `not_agents` (which excludes) matches any identity the
// call can be attributed to. An exclusion that looked only at the presenter
// would be escaped by delegating one hop — the exact gap Phase 169 closed in
// quarantine.
func TestNotAgentsExcludesTheWholeChain(t *testing.T) {
	e := mustEngine(t, `
rules:
  - id: exec-except-quarantined-lineage
    tool: ssh_exec
    not_agents: ["spiffe://corp/sa/planner"]
    effect: allow
`)
	// The excluded identity itself.
	if d := e.Evaluate(Caller{Agent: "spiffe://corp/sa/planner", SPIFFEID: "spiffe://corp/sa/planner"}, "ssh_exec", nil); d.Effect != EffectDeny {
		t.Fatalf("the excluded agent must not match: %+v", d)
	}
	// A sub-agent it delegated to: a different presenter, same lineage.
	delegated := Caller{
		Agent:      "spiffe://corp/sa/worker",
		SPIFFEID:   "spiffe://corp/sa/worker",
		OnBehalfOf: "spiffe://corp/sa/planner",
		Chain:      []string{"spiffe://corp/sa/worker", "spiffe://corp/sa/planner"},
	}
	if d := e.Evaluate(delegated, "ssh_exec", nil); d.Effect != EffectDeny {
		t.Fatalf("a call delegated FROM an excluded agent must not match either: %+v", d)
	}
	// An unrelated agent is unaffected.
	if d := e.Evaluate(Caller{Agent: "spiffe://corp/sa/other", SPIFFEID: "spiffe://corp/sa/other"}, "ssh_exec", nil); d.Effect != EffectAllow {
		t.Fatalf("an unrelated agent should still match: %+v", d)
	}
}

// TestCallerConditions exercises the reserved `caller.*` namespace: identity
// facts a rule can match on that the agent cannot assert for itself.
func TestCallerConditions(t *testing.T) {
	e := mustEngine(t, `
rules:
  - id: no-reveal-through-delegation
    tool: reveal_credential
    when: { caller.delegation_depth: { gte: 1 } }
    effect: deny
    reason: a delegated token may not reveal a secret
  - id: reveal-attested-only
    tool: reveal_credential
    when: { caller.identity_kind: spiffe }
    effect: allow
  - id: exec-for-one-owner
    tool: ssh_exec
    when: { caller.on_behalf_of: alice }
    effect: allow
  - id: static-keys-list-only
    tool: list_targets
    when: { caller.spiffe_id: { present: false } }
    effect: allow
`)
	svid := Caller{Agent: "spiffe://corp/sa/planner", SPIFFEID: "spiffe://corp/sa/planner",
		OnBehalfOf: "spiffe://corp/sa/planner", Chain: []string{"spiffe://corp/sa/planner"}}
	delegated := Caller{Agent: "spiffe://corp/sa/worker", SPIFFEID: "spiffe://corp/sa/worker",
		OnBehalfOf: "spiffe://corp/sa/planner",
		Chain:      []string{"spiffe://corp/sa/worker", "spiffe://corp/sa/planner"}}
	staticKey := Caller{Agent: "deploy-bot", OnBehalfOf: "alice"}

	// An undelegated SVID is depth 0 — a one-element chain is the agent itself,
	// not a hop — so it reaches the allow rule below the delegation guard.
	if d := e.Evaluate(svid, "reveal_credential", nil); d.Effect != EffectAllow {
		t.Fatalf("an undelegated attested agent should be allowed: %+v", d)
	}
	if d := e.Evaluate(delegated, "reveal_credential", nil); d.Effect != EffectDeny || d.RuleID != "no-reveal-through-delegation" {
		t.Fatalf("a delegated call must hit the delegation guard: %+v", d)
	}
	// identity_kind separates the two authentication paths.
	if d := e.Evaluate(staticKey, "reveal_credential", nil); d.Effect != EffectDeny || d.RuleID != "implicit-default-deny" {
		t.Fatalf("a static key must not match an spiffe-only rule: %+v", d)
	}
	// on_behalf_of is the accountable party — a human for a static key.
	if d := e.Evaluate(staticKey, "ssh_exec", nil); d.Effect != EffectAllow {
		t.Fatalf("owner-scoped rule should match: %+v", d)
	}
	if d := e.Evaluate(svid, "ssh_exec", nil); d.Effect != EffectDeny {
		t.Fatalf("a different accountable party must not match: %+v", d)
	}
	// present:false on spiffe_id is how a rule says "a static key".
	if d := e.Evaluate(staticKey, "list_targets", nil); d.Effect != EffectAllow {
		t.Fatalf("static key should match the present:false rule: %+v", d)
	}
	if d := e.Evaluate(svid, "list_targets", nil); d.Effect != EffectDeny {
		t.Fatalf("an attested agent must not match caller.spiffe_id present:false: %+v", d)
	}
}

// TestCallerAttributesCannotBeForgedByArguments is the property that makes the
// namespace worth having. Every value a `caller.*` condition reads comes from
// the broker's authentication; an argument by the same name is a different
// lookup entirely and can never satisfy it.
//
// Without this split, "match on the identity" would mean "match on a string the
// agent chose to send" — which is how the research described every
// identity-shaped condition that was expressible before this phase.
func TestCallerAttributesCannotBeForgedByArguments(t *testing.T) {
	e := mustEngine(t, `
rules:
  - id: only-rotator
    tool: reveal_credential
    when: { caller.agent: rotation-bot }
    effect: allow
`)
	impostor := Caller{Agent: "planner-bot"}
	forged := map[string]any{
		"caller.agent": "rotation-bot",
		"agent":        "rotation-bot",
		"caller":       map[string]any{"agent": "rotation-bot"},
	}
	if d := e.Evaluate(impostor, "reveal_credential", forged); d.Effect != EffectDeny {
		t.Fatalf("an argument must never satisfy a caller.* condition: %+v", d)
	}
	// And the real thing still matches, with the same arguments present.
	if d := e.Evaluate(Caller{Agent: "rotation-bot"}, "reveal_credential", forged); d.Effect != EffectAllow {
		t.Fatalf("the verified caller should match: %+v", d)
	}
}

// TestUnknownCallerAttributeIsRefusedAtLoad keeps the batch's recurring lesson:
// a condition naming an attribute that does not exist would simply never match,
// which reads as a control while behaving as an absence. It is a load error, as
// a misplaced ttl_seconds is (Phase 171).
func TestUnknownCallerAttributeIsRefusedAtLoad(t *testing.T) {
	_, err := Load(strings.NewReader(
		"rules:\n  - id: r\n    tool: t\n    when: { caller.owner: alice }\n    effect: allow\n"))
	if err == nil || !strings.Contains(err.Error(), "unknown caller attribute") {
		t.Fatalf("want an unknown-attribute error, got %v", err)
	}
	if _, err := Load(strings.NewReader(
		"rules:\n  - id: r\n    tool: t\n    agents: [\"\"]\n    effect: allow\n")); err == nil ||
		!strings.Contains(err.Error(), "empty agent identity") {
		t.Fatalf("want an empty-identity error, got %v", err)
	}
}
