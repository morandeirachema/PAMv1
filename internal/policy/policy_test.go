package policy

import (
	"strings"
	"testing"
	"time"
)

// mustLoad parses YAML or fails the test.
func mustLoad(t *testing.T, y string) *Engine {
	t.Helper()
	e, err := Load(strings.NewReader(y))
	if err != nil {
		t.Fatalf("Load: %v\npolicy:\n%s", err, y)
	}
	return e
}

// TestEvaluate covers the operators, AND logic, first-match ordering, implicit
// deny, match-all (missing tool), and scope templating (success + fail-closed).
func TestEvaluate(t *testing.T) {
	const p = `
rules:
  - id: no-delete
    tool: delete_repo
    effect: deny
    reason: destructive
  - id: read-free
    tool: get_repo
    effect: allow
    scope: "repo:{repo}:read"
  - id: merge-safe
    tool: merge_pr
    when: { args.base: { in: [develop, staging] } }
    effect: allow
    scope: "repo:{repo}:write"
  - id: merge-human
    tool: merge_pr
    effect: require_approval
    approvers: [platform-team]
    scope: "repo:{repo}:write"
    ttl_seconds: 60
  - id: block-prod-repo
    tool: tag
    when: { args.repo: { not_in: [acme/payments] } }
    effect: allow
    scope: "repo:{repo}:tag"
  - id: global-audit-note
    effect: allow
`
	e := mustLoad(t, p)

	tests := []struct {
		name       string
		tool       string
		args       map[string]any
		wantRule   string
		wantEffect Effect
		wantScope  string
		wantTTL    time.Duration
	}{
		{"deny wins", "delete_repo", map[string]any{"repo": "acme/x"}, "no-delete", EffectDeny, "", 0},
		{"read renders scope", "get_repo", map[string]any{"repo": "acme/x"}, "read-free", EffectAllow, "repo:acme/x:read", 0},
		{"in matches safe branch", "merge_pr", map[string]any{"repo": "acme/x", "base": "develop"}, "merge-safe", EffectAllow, "repo:acme/x:write", 0},
		{"first-match falls through to approval", "merge_pr", map[string]any{"repo": "acme/x", "base": "main"}, "merge-human", EffectRequireApproval, "repo:acme/x:write", 60 * time.Second},
		{"not_in allows non-blocked", "tag", map[string]any{"repo": "acme/site"}, "block-prod-repo", EffectAllow, "repo:acme/site:tag", 0},
		{"missing tool rule matches all", "anything", map[string]any{}, "global-audit-note", EffectAllow, "", 0},
		{"scope template failure denies", "get_repo", map[string]any{}, "read-free", EffectDeny, "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Evaluate(Caller{}, tc.tool, tc.args)
			if d.RuleID != tc.wantRule || d.Effect != tc.wantEffect {
				t.Fatalf("got rule=%q effect=%q, want rule=%q effect=%q", d.RuleID, d.Effect, tc.wantRule, tc.wantEffect)
			}
			if d.Scope != tc.wantScope {
				t.Errorf("scope = %q, want %q", d.Scope, tc.wantScope)
			}
			if d.TTL != tc.wantTTL {
				t.Errorf("ttl = %v, want %v", d.TTL, tc.wantTTL)
			}
		})
	}
}

// TestImplicitDeny proves a call matching no rule is denied by default.
func TestImplicitDeny(t *testing.T) {
	e := mustLoad(t, "rules:\n  - id: only-reads\n    tool: get_repo\n    effect: allow\n")
	d := e.Evaluate(Caller{}, "delete_repo", map[string]any{"repo": "x"})
	if d.Effect != EffectDeny || d.RuleID != "implicit-default-deny" {
		t.Fatalf("want implicit deny, got %+v", d)
	}
}

// TestConditionOperators exercises each operator's presence/absence behavior.
func TestConditionOperators(t *testing.T) {
	e := mustLoad(t, `
rules:
  - id: eq
    tool: t_eq
    when: { args.b: main }
    effect: allow
  - id: not
    tool: t_not
    when: { args.b: { not: main } }
    effect: allow
  - id: num
    tool: t_num
    when: { args.n: "10000000" }
    effect: allow
`)
	cases := []struct {
		tool string
		args map[string]any
		want Effect
	}{
		{"t_eq", map[string]any{"b": "main"}, EffectAllow},
		{"t_eq", map[string]any{"b": "dev"}, EffectDeny},
		{"t_eq", map[string]any{}, EffectDeny},             // absent → eq fails
		{"t_not", map[string]any{"b": "dev"}, EffectAllow}, // present and differs → not matches
		// Absent used to satisfy `not` ("differs or absent"). It no longer does:
		// every value operator requires the argument, so a rule naming an argument
		// can never be satisfied by omitting that argument. See
		// TestNegativeOperatorsRequirePresence for why that mattered.
		{"t_not", map[string]any{}, EffectDeny},            // absent → not fails (fail-closed)
		{"t_not", map[string]any{"b": "main"}, EffectDeny}, // equal → not fails
		// JSON numbers arrive as float64; a large integer must render "10000000",
		// not "1e+07", or the eq would silently never match.
		{"t_num", map[string]any{"n": float64(10000000)}, EffectAllow},
		{"t_num", map[string]any{"n": float64(9999999)}, EffectDeny},
	}
	for _, c := range cases {
		if got := e.Evaluate(Caller{}, c.tool, c.args).Effect; got != c.want {
			t.Errorf("%s %v: effect=%q want %q", c.tool, c.args, got, c.want)
		}
	}
}

// TestLoadErrors proves the loader is fail-loud on malformed policy.
func TestLoadErrors(t *testing.T) {
	bad := map[string]string{
		"unknown key":          "rules:\n  - id: x\n    tool: t\n    effect: allow\n    bogus: 1\n",
		"unknown operator":     "rules:\n  - id: x\n    tool: t\n    when: { args.b: { regex: '.*' } }\n    effect: allow\n",
		"typo beside valid op": "rules:\n  - id: x\n    tool: t\n    when: { args.b: { not: y, reggex: '.*' } }\n    effect: allow\n",
		// `present` joins the same two fail-loud rules as every other operator:
		// exactly one operator per condition, and no unknown keys. A misspelled
		// "presnt" must not be silently ignored — a condition that decodes to
		// nothing would match nothing and quietly change the rule's meaning.
		"present plus another op": "rules:\n  - id: x\n    tool: t\n    when: { args.b: { present: true, not: x } }\n    effect: allow\n",
		"present typo":            "rules:\n  - id: x\n    tool: t\n    when: { args.b: { presnt: true } }\n    effect: allow\n",
		"no id":                   "rules:\n  - tool: t\n    effect: allow\n",
		"invalid effect":          "rules:\n  - id: x\n    tool: t\n    effect: maybe\n",
		"approval no approvers":   "rules:\n  - id: x\n    tool: t\n    effect: require_approval\n",
		"empty":                   "rules: []\n",
	}
	for name, y := range bad {
		if _, err := Load(strings.NewReader(y)); err == nil {
			t.Errorf("%s: expected a load error, got nil", name)
		}
	}
}

// TestNumericComparators proves the gte/gt/lte/lt operators compare argument
// values numerically and fail closed on absent or non-numeric values (Phase 30).
func TestNumericComparators(t *testing.T) {
	rules := `
rules:
  - id: big-refund-approval
    tool: refund
    when:
      args.amount: { gte: 5000 }
    effect: require_approval
    approvers: [finance]
  - id: small-refund-allow
    tool: refund
    effect: allow
`
	eng, err := Load(strings.NewReader(rules))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// >= 5000 requires approval; below is allowed; a non-numeric amount does not
	// satisfy the gte rule and falls through to allow (fail-closed on the comparator).
	cases := []struct {
		amount any
		want   Effect
	}{
		{5000, EffectRequireApproval},
		{9999.5, EffectRequireApproval},
		{4999, EffectAllow},
		{"not-a-number", EffectAllow},
		{nil, EffectAllow},
	}
	for _, c := range cases {
		args := map[string]any{}
		if c.amount != nil {
			args["amount"] = c.amount
		}
		if got := eng.Evaluate(Caller{}, "refund", args).Effect; got != c.want {
			t.Errorf("amount=%v: effect=%s, want %s", c.amount, got, c.want)
		}
	}
}

// TestNumericComparatorRejectsMultipleOps proves a condition with two operators
// is rejected at load (fail-loud).
func TestNumericComparatorRejectsMultipleOps(t *testing.T) {
	rules := "rules:\n  - id: bad\n    tool: t\n    when:\n      args.x: { gte: 1, lt: 9 }\n    effect: allow\n"
	if _, err := Load(strings.NewReader(rules)); err == nil {
		t.Fatal("a condition with two operators must fail to load")
	}
}

// TestUnknownOperatorRejected proves a typo'd operator is rejected fail-loud.
func TestUnknownOperatorRejected(t *testing.T) {
	rules := "rules:\n  - id: bad\n    tool: t\n    when:\n      args.x: { gee: 1 }\n    effect: allow\n"
	if _, err := Load(strings.NewReader(rules)); err == nil {
		t.Fatal("an unknown operator must fail to load")
	}
}

// TestNegativeOperatorsRequirePresence is the regression test for the
// "bypass by omission" that `not` and `not_in` used to allow.
//
// The scenario, in full, because it is the whole point of the test. The broker
// exposes a list_credentials tool whose `target` argument is OPTIONAL: pass a
// target name and you get that target's credential metadata, pass nothing and
// you get EVERY credential in the system. An operator who wants an agent to use
// the tool but never to see the two crown-jewel safes writes the guard that
// reads like English:
//
//	when: { args.target: { not_in: [vault-prod, hsm-root] } }
//
// Under the old semantics ("absent or not in the block-list") an agent defeated
// that by sending no `target` at all: absent counted as "not in the block-list",
// the allow rule matched, and the unfiltered call returned everything — vault-prod
// and hsm-root included. The rule that was supposed to restrict the agent was
// bypassed by sending LESS data than the honest call.
//
// So: an omitted argument must NOT satisfy `not_in` (or `not`). The call falls
// through to the implicit default deny instead.
func TestNegativeOperatorsRequirePresence(t *testing.T) {
	e := mustLoad(t, `
rules:
  - id: no-listing-the-vault-safe
    tool: list_credentials
    when:
      args.target: { not_in: [vault-prod, hsm-root] }
    effect: allow
  - id: no-revealing-the-vault-safe
    tool: reveal_credential
    when:
      args.target: { not: vault-prod }
    effect: allow
`)
	cases := []struct {
		name string
		tool string
		args map[string]any
		want Effect
	}{
		{
			name: "not_in: omitting target no longer matches the guard",
			tool: "list_credentials",
			args: map[string]any{}, // the exploit: the unfiltered, list-everything call
			want: EffectDeny,
		},
		{
			name: "not_in: a blocked target is still refused",
			tool: "list_credentials",
			args: map[string]any{"target": "vault-prod"},
			want: EffectDeny,
		},
		{
			name: "not_in: an ordinary target is still allowed",
			tool: "list_credentials",
			args: map[string]any{"target": "lab-win-01"},
			want: EffectAllow,
		},
		{
			name: "not: omitting target no longer matches the guard",
			tool: "reveal_credential",
			args: map[string]any{},
			want: EffectDeny,
		},
		{
			name: "not: the named target is still refused",
			tool: "reveal_credential",
			args: map[string]any{"target": "vault-prod"},
			want: EffectDeny,
		},
		{
			name: "not: another target is still allowed",
			tool: "reveal_credential",
			args: map[string]any{"target": "lab-win-01"},
			want: EffectAllow,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := e.Evaluate(Caller{}, c.tool, c.args)
			if d.Effect != c.want {
				t.Fatalf("args=%v: effect=%s (rule %q), want %s", c.args, d.Effect, d.RuleID, c.want)
			}
			if c.want == EffectDeny && len(c.args) == 0 && d.RuleID != "implicit-default-deny" {
				t.Errorf("the omitted-argument call should fall through to the implicit deny, "+
					"but rule %q matched it", d.RuleID)
			}
		})
	}
}

// TestPositiveOperatorsUnchangedByPresenceFix pins that requiring presence for
// the negative operators did not disturb the operators that already required it.
// eq/in/gte are re-checked here on purpose: this is the "no accidental change"
// half of the same change.
func TestPositiveOperatorsUnchangedByPresenceFix(t *testing.T) {
	e := mustLoad(t, `
rules:
  - id: eq-rule
    tool: t_eq
    when: { args.b: main }
    effect: allow
  - id: in-rule
    tool: t_in
    when: { args.b: { in: [develop, staging] } }
    effect: allow
  - id: gte-rule
    tool: t_gte
    when: { args.amount: { gte: 5000 } }
    effect: allow
`)
	cases := []struct {
		tool string
		args map[string]any
		want Effect
	}{
		{"t_eq", map[string]any{"b": "main"}, EffectAllow},
		{"t_eq", map[string]any{"b": "dev"}, EffectDeny},
		{"t_eq", map[string]any{}, EffectDeny}, // absent → still fails
		{"t_in", map[string]any{"b": "staging"}, EffectAllow},
		{"t_in", map[string]any{"b": "main"}, EffectDeny},
		{"t_in", map[string]any{}, EffectDeny}, // absent → still fails
		{"t_gte", map[string]any{"amount": float64(5000)}, EffectAllow},
		{"t_gte", map[string]any{"amount": float64(4999)}, EffectDeny},
		{"t_gte", map[string]any{}, EffectDeny},                         // absent → still fails
		{"t_gte", map[string]any{"amount": "not-a-number"}, EffectDeny}, // non-numeric → still fails
	}
	for _, c := range cases {
		if got := e.Evaluate(Caller{}, c.tool, c.args).Effect; got != c.want {
			t.Errorf("%s %v: effect=%s, want %s", c.tool, c.args, got, c.want)
		}
	}
}

// TestPresentOperator covers the operator that restores what requiring presence
// took away: the ability to talk about whether an argument was supplied at all.
//
// The `present: false` half is the practical one — it is how an operator writes
// "the unscoped, list-everything form of this call is not allowed", which is a
// direct, readable statement of the very bypass the presence change closes.
//
// The edge that is easy to get wrong, and is pinned explicitly below: presence
// means the argument was SUPPLIED, not that it is non-empty. `target: ""` is
// present, so it matches `present: true` and does NOT match `present: false`.
func TestPresentOperator(t *testing.T) {
	e := mustLoad(t, `
rules:
  # Deny the unscoped call outright: no target argument means "list everything".
  - id: no-unscoped-listing
    tool: list_credentials
    when:
      args.target: { present: false }
    effect: deny
    reason: unscoped listing
  # A scoped call is fine, whatever the target is.
  - id: scoped-listing-ok
    tool: list_credentials
    when:
      args.target: { present: true }
    effect: allow
`)
	cases := []struct {
		name     string
		args     map[string]any
		wantRule string
		want     Effect
	}{
		{"absent matches present:false", map[string]any{}, "no-unscoped-listing", EffectDeny},
		{"supplied matches present:true", map[string]any{"target": "lab-win-01"}, "scoped-listing-ok", EffectAllow},
		// An empty string was SUPPLIED, so it is present: the deny rule must not
		// claim it and the allow rule must.
		{"empty string is present, not absent", map[string]any{"target": ""}, "scoped-listing-ok", EffectAllow},
		// A JSON null likewise arrives as a key in the args map, so it is present.
		{"explicit null is present", map[string]any{"target": nil}, "scoped-listing-ok", EffectAllow},
		// A different argument being supplied says nothing about `target`.
		{"another argument does not stand in", map[string]any{"other": "x"}, "no-unscoped-listing", EffectDeny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := e.Evaluate(Caller{}, "list_credentials", c.args)
			if d.RuleID != c.wantRule || d.Effect != c.want {
				t.Fatalf("args=%v: rule=%q effect=%s, want rule=%q effect=%s",
					c.args, d.RuleID, d.Effect, c.wantRule, c.want)
			}
		})
	}
}

// TestPresentOperatorCombinesWithOthers proves `present` is an ordinary
// condition: several conditions on one rule still AND together, so an operator
// can require one argument and forbid another in the same rule.
func TestPresentOperatorCombinesWithOthers(t *testing.T) {
	e := mustLoad(t, `
rules:
  - id: scoped-exec-only
    tool: ssh_exec
    when:
      args.target: { in: [lab-01, lab-02] }
      args.all_hosts: { present: false }
    effect: allow
`)
	cases := []struct {
		args map[string]any
		want Effect
	}{
		{map[string]any{"target": "lab-01"}, EffectAllow},
		{map[string]any{"target": "lab-01", "all_hosts": true}, EffectDeny},
		{map[string]any{"target": "lab-01", "all_hosts": false}, EffectDeny}, // supplied at all is enough
		{map[string]any{"all_hosts": nil}, EffectDeny},
	}
	for _, c := range cases {
		if got := e.Evaluate(Caller{}, "ssh_exec", c.args).Effect; got != c.want {
			t.Errorf("args=%v: effect=%s, want %s", c.args, got, c.want)
		}
	}
}

// TestMayEverAllow pins the question a LISTING asks, which is not the question a
// call asks: could any arguments get this caller an allow for this tool?
//
// It exists because MCP tools/list handed every agent the whole registry, so an
// agent permitted only ssh_exec was still told winrm_exec and reveal_credential
// exist. The reasoning has to follow Evaluate's first-match-wins order, and the
// interesting cases are the conditional ones: a conditional DENY might not fire,
// so a later allow still counts; an unconditional deny is final.
func TestMayEverAllow(t *testing.T) {
	const rules = `
rules:
  - id: planner-ssh
    tool: ssh_exec
    agents: [planner]
    effect: allow
  - id: nobody-reveals-prod
    tool: reveal_credential
    when:
      target: {in: [prod-db]}
    effect: deny
  - id: reveal-otherwise
    tool: reveal_credential
    agents: [planner]
    effect: require_approval
    approvers: [secops]
  - id: winrm-never
    tool: winrm_exec
    effect: deny
`
	e, err := Load(strings.NewReader(rules))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	planner := Caller{Agent: "planner"}
	other := Caller{Agent: "other"}

	for _, tc := range []struct {
		name   string
		caller Caller
		tool   string
		want   bool
	}{
		{"the tool its own rule names", planner, "ssh_exec", true},
		{"another agent gets nothing from that rule", other, "ssh_exec", false},
		{"a conditional deny does not settle it — a later rule may allow", planner, "reveal_credential", true},
		{"…and that later rule is agent-scoped, so others still get nothing", other, "reveal_credential", false},
		{"an UNCONDITIONAL deny is final", planner, "winrm_exec", false},
		{"a tool no rule mentions is the implicit default deny", planner, "k8s_get", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := e.MayEverAllow(tc.caller, tc.tool); got != tc.want {
				t.Errorf("MayEverAllow(%q, %q) = %v, want %v", tc.caller.Agent, tc.tool, got, tc.want)
			}
		})
	}

	// The filter must never be more permissive than Evaluate: anything Evaluate
	// actually allows must have been listable.
	for _, tool := range []string{"ssh_exec", "reveal_credential", "winrm_exec", "k8s_get"} {
		for _, c := range []Caller{planner, other} {
			d := e.Evaluate(c, tool, map[string]any{"target": "staging"})
			if d.Effect != EffectDeny && !e.MayEverAllow(c, tool) {
				t.Errorf("%s/%s: Evaluate says %q but the listing would hide it", c.Agent, tool, d.Effect)
			}
		}
	}
}
