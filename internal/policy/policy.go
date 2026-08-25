// Package policy is the agent-access-broker decision engine. It matches a tool
// call and its arguments against an ordered rule set (sudoers-style) and returns
// allow / deny / require_approval. First matching rule wins; no match is an
// implicit deny (fail-closed). Conditions match the argument value only —
// there is deliberately no regex, OR, or nesting (numeric comparison arrived in
// Phase 30). Every value operator requires the argument to be present, including
// the negative `not`/`not_in`, so a rule can never be defeated by omitting the
// argument it names; `present: true|false` is the one operator that speaks about
// presence itself. See Condition for why that matters.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Effect is a rule outcome.
type Effect string

const (
	EffectAllow           Effect = "allow"
	EffectDeny            Effect = "deny"
	EffectRequireApproval Effect = "require_approval"
)

// Condition is a single argument matcher. Exactly one field is set (enforced at
// load time via UnmarshalYAML). Every condition on a rule must hold (AND). The
// gte/gt/lte/lt operators compare the argument value NUMERICALLY (Phase 30), for
// amount-based rules like "require approval when args.amount >= 5000".
//
// EVERY value operator requires the argument to be PRESENT. That includes the
// negative ones, `not` and `not_in`, and it is a deliberate break with their
// original behaviour ("differs OR absent"), because the old rule handed an agent
// a bypass by omission. Concretely: the broker's list_credentials tool takes an
// OPTIONAL `target` argument and, when it is omitted, lists EVERY credential's
// metadata. An operator writing the natural guard
//
//	when: { args.target: { not_in: [vault-prod, hsm-root] } }
//
// used to get the exact opposite of what they wrote — an agent that simply sent
// no `target` at all satisfied "absent, therefore not in the block-list", matched
// the allow rule, and listed everything including the two named targets. A
// control that reads as a restriction and is defeated by sending LESS data is
// the worst shape a security control can have, so absence now fails the match
// and the call falls through to the next rule (ultimately the implicit deny).
//
// Because that makes "the argument must be absent" inexpressible — the engine
// has no OR — the `present` operator says it directly: `{ present: true }` holds
// only when the argument was supplied, `{ present: false }` only when it was
// not. `{ present: false }` is how an operator writes "the unscoped,
// list-everything form of this call is not allowed". Note that presence is about
// the argument being SUPPLIED, not about it being non-empty: an argument sent as
// the empty string is present.
type Condition struct {
	Eq      *string  // args.field: value        (equality; matches only when present)
	Not     *string  // args.field: { not: X }   (present AND differs)
	In      []string // args.field: { in: [...] }(present and in the allow-list)
	NotIn   []string // args.field: { not_in: [...] } (present AND not in the block-list)
	Present *bool    // args.field: { present: true|false } (argument supplied / not supplied)
	Gte     *float64 // args.field: { gte: N }   (present, numeric, and >= N)
	Gt      *float64 // args.field: { gt: N }    (present, numeric, and >  N)
	Lte     *float64 // args.field: { lte: N }   (present, numeric, and <= N)
	Lt      *float64 // args.field: { lt: N }    (present, numeric, and <  N)
}

// UnmarshalYAML accepts either a scalar (equality) or a one-key mapping with
// not/in/not_in/present/gte/gt/lte/lt, and rejects anything else (e.g. an unknown
// operator) fail-loud. In Go terms this is the yaml.v3 hook for a custom type:
// the library hands us the raw parsed node and we decide what a Condition may
// look like, the way a Python __init__ that validates its kwargs would.
func (c *Condition) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		s := value.Value
		c.Eq = &s
		return nil
	case yaml.MappingNode:
		// Reject unknown operator keys fail-loud: a typo (e.g. "reggex") paired with
		// a valid operator would otherwise load silently and enforce only the
		// accidental clause. value.Decode ignores unknown keys, so check them here.
		for i := 0; i+1 < len(value.Content); i += 2 {
			switch value.Content[i].Value {
			case "not", "in", "not_in", "present", "gte", "gt", "lte", "lt":
			default:
				return fmt.Errorf("policy: unknown condition operator %q (want not|in|not_in|present|gte|gt|lte|lt)", value.Content[i].Value)
			}
		}
		var m struct {
			Not     *string  `yaml:"not"`
			In      []string `yaml:"in"`
			NotIn   []string `yaml:"not_in"`
			Present *bool    `yaml:"present"`
			Gte     *float64 `yaml:"gte"`
			Gt      *float64 `yaml:"gt"`
			Lte     *float64 `yaml:"lte"`
			Lt      *float64 `yaml:"lt"`
		}
		if err := value.Decode(&m); err != nil {
			return err
		}
		set := 0
		if m.Not != nil {
			c.Not = m.Not
			set++
		}
		if m.In != nil {
			c.In = m.In
			set++
		}
		if m.NotIn != nil {
			c.NotIn = m.NotIn
			set++
		}
		if m.Present != nil {
			c.Present = m.Present
			set++
		}
		if m.Gte != nil {
			c.Gte = m.Gte
			set++
		}
		if m.Gt != nil {
			c.Gt = m.Gt
			set++
		}
		if m.Lte != nil {
			c.Lte = m.Lte
			set++
		}
		if m.Lt != nil {
			c.Lt = m.Lt
			set++
		}
		if set != 1 {
			return fmt.Errorf("policy: a condition must have exactly one of not/in/not_in/present/gte/gt/lte/lt")
		}
		return nil
	default:
		return fmt.Errorf("policy: condition must be a value or a {not|in|not_in|present|gte|gt|lte|lt} map")
	}
}

// match reports whether the condition holds for the argument value (val,
// present). `present` is the second return value of a Go map lookup — it says
// the caller SUPPLIED the argument, not that the argument is non-empty, so an
// argument sent as "" is present.
//
// Every value operator fails closed on an absent argument. For eq/in and the
// numeric comparators (gte/gt/lte/lt) that was always true; for the negative
// operators `not` and `not_in` it is a deliberate change of semantics that
// closes a bypass by omission. They used to read `!present || …`, i.e. an absent
// argument satisfied them on its own, so a rule like
//
//   - id: no-listing-the-vault-safe
//     tool: list_credentials
//     effect: allow
//     when: { args.target: { not_in: [vault-prod, hsm-root] } }
//
// was defeated by calling list_credentials with NO `target` at all: absent
// counted as "not in the block-list", the allow rule matched, and because that
// tool's `target` filter is optional the agent got the metadata of every
// credential in the system — including vault-prod and hsm-root, the two the rule
// was written to protect. Requiring presence means the omitted-argument call now
// falls through this rule to whatever comes next, and to the implicit deny if
// nothing does.
//
// The `present` operator is the way back to the expressiveness that removes:
// `{ present: false }` matches ONLY the absent case, which is how you say "the
// unscoped, list-everything form of this call is not allowed"; `{ present: true }`
// matches whenever the argument was supplied, whatever its value.
func (c Condition) match(val string, present bool) bool {
	switch {
	case c.Eq != nil:
		return present && val == *c.Eq
	case c.Not != nil:
		return present && val != *c.Not
	case c.In != nil:
		return present && slices.Contains(c.In, val)
	case c.NotIn != nil:
		return present && !slices.Contains(c.NotIn, val)
	case c.Present != nil:
		return present == *c.Present
	case c.Gte != nil:
		n, ok := numeric(val, present)
		return ok && n >= *c.Gte
	case c.Gt != nil:
		n, ok := numeric(val, present)
		return ok && n > *c.Gt
	case c.Lte != nil:
		n, ok := numeric(val, present)
		return ok && n <= *c.Lte
	case c.Lt != nil:
		n, ok := numeric(val, present)
		return ok && n < *c.Lt
	}
	return false
}

// numeric parses a present argument value as a float; ok=false when absent or
// non-numeric.
func numeric(val string, present bool) (float64, bool) {
	if !present {
		return 0, false
	}
	n, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// Caller is the VERIFIED identity behind a tool call, as the broker's
// authentication established it — never anything the agent asserted in its
// arguments (Phase 173).
//
// Until this phase the engine's whole input was `(tool, args)`. The verified
// identity sat one line above the Evaluate call in the broker and was never
// passed, with two consequences an operator could not work around:
//
//   - **A rule had no principal side.** One `allow` for `reveal_credential`
//     enabled it for EVERY agent, because a rule could only speak about the tool
//     and its arguments. Three separate vendors model this the other way round
//     (CyberArk's principal×resource pairs, Teleport's per-role `mcp.tools`,
//     StrongDM's per-agent-per-destination), and the package's own sudoers
//     analogy was incomplete: sudoers HAS a user column.
//   - **Anything identity-shaped a rule matched was self-asserted.** A condition
//     could only read `args`, so a rule keyed on "which agent is this" was
//     really keyed on a string the agent chose to send.
//
// Chain is the RFC 8693 delegation chain, innermost..outermost (empty for a
// static agent key). Every field here comes from the authenticated identity.
type Caller struct {
	Agent      string   // presenter: the agent-key name, or the full SPIFFE ID
	SPIFFEID   string   // "" for a static agent key
	OnBehalfOf string   // accountable party: a human owner (key) or the outermost SPIFFE ID
	Chain      []string // delegation chain, innermost..outermost; empty for a static key
}

// callerFields are the reserved `caller.*` attributes a condition may read. They
// are listed once, here, so Load can refuse a rule naming one that does not
// exist rather than silently never matching — the failure mode this whole batch
// keeps closing.
//
//   - caller.agent            the presenting identity (key name or SPIFFE ID)
//   - caller.spiffe_id        the SPIFFE ID, absent for a static key
//   - caller.on_behalf_of     the accountable party
//   - caller.delegation_depth number of delegation hops: 0 for an undelegated call
//   - caller.identity_kind    "spiffe" or "key"
var callerFields = []string{"agent", "spiffe_id", "on_behalf_of", "delegation_depth", "identity_kind"}

// attr returns one caller.* attribute and whether it is PRESENT, using the same
// present/absent distinction an argument has: an empty value reads as absent, so
// `caller.spiffe_id: { present: false }` is how a rule says "a static agent key,
// not an attested workload". delegation_depth and identity_kind always have a
// value, so they are always present.
func (c Caller) attr(field string) (string, bool) {
	switch field {
	case "agent":
		return c.Agent, c.Agent != ""
	case "spiffe_id":
		return c.SPIFFEID, c.SPIFFEID != ""
	case "on_behalf_of":
		return c.OnBehalfOf, c.OnBehalfOf != ""
	case "delegation_depth":
		return strconv.Itoa(c.delegationDepth()), true
	case "identity_kind":
		if c.SPIFFEID != "" {
			return "spiffe", true
		}
		return "key", true
	}
	return "", false
}

// delegationDepth is the number of delegation HOPS, not the chain length: an
// SVID that was never exchanged carries a one-element chain (itself) and is
// depth 0, exactly like a static key, so `caller.delegation_depth: { gte: 1 }`
// means "this call came through a delegated token" for both identity kinds.
func (c Caller) delegationDepth() int {
	if len(c.Chain) < 2 {
		return 0
	}
	return len(c.Chain) - 1
}

// identities lists every identity this call can be attributed to: the presenter,
// its delegation chain, and the accountable party. Used by `not_agents`, which
// excludes on ANY of them — an exclusion that only looked at the presenter would
// be escaped by delegating one hop, the same gap Phase 169 closed in quarantine.
func (c Caller) identities() []string {
	out := make([]string, 0, len(c.Chain)+2)
	for _, id := range append([]string{c.Agent, c.OnBehalfOf}, c.Chain...) {
		if id != "" && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// Rule is one policy entry. A missing Tool matches every tool (global rule).
//
// Two fields need their exact power stated, because both once read stronger than
// they were (Phase 171):
//
//   - Scope is a TEMPLATE RENDERED INTO THE AUDIT RECORD, not an execution
//     constraint. It cannot narrow what a call does — the call's arguments are
//     already fixed and the broker executes exactly those. What it does do is
//     assert presence: a template naming {target} fails to render when the call
//     has no `target` argument, and a render failure is a DENY. So it is a label
//     with a fail-closed required-argument check attached, and describing it as
//     "a scoped grant" oversells it.
//   - TTLSeconds bounds how long a require_approval call stays decidable and its
//     resume token stays spendable. It may only NARROW the deployment-wide
//     PAM_BROKER_TOKEN_TTL_MIN, never extend it. On any other effect it bounds
//     nothing — an allow executes immediately and a deny is already over — so
//     Load REFUSES it there rather than accepting a setting that does nothing.
type Rule struct {
	ID   string               `yaml:"id"`
	Tool string               `yaml:"tool"`
	When map[string]Condition `yaml:"when"`
	// Agents restricts a rule to the listed presenting identities (agent-key
	// names or full SPIFFE IDs); empty matches every agent, so every rule
	// written before Phase 173 behaves exactly as it did. It matches the
	// PRESENTER only: a call delegated FROM a listed agent is presented by the
	// delegate, which is a different identity and needs its own rule. That is
	// the narrowing direction, and narrowing is the safe default for the side
	// of a rule that grants.
	Agents []string `yaml:"agents"`
	// NotAgents excludes identities from a rule. Unlike Agents it matches ANY
	// identity the call can be attributed to — presenter, delegation chain, or
	// accountable party — because an exclusion that looked only at the presenter
	// would be escaped by delegating one hop. Both directions narrow.
	NotAgents  []string `yaml:"not_agents"`
	Effect     Effect   `yaml:"effect"`
	Approvers  []string `yaml:"approvers"`
	Scope      string   `yaml:"scope"`
	TTLSeconds int      `yaml:"ttl_seconds"`
	Reason     string   `yaml:"reason"`
}

// matchesCaller reports whether this rule's principal side admits the caller.
//
// Both lists short-circuit when empty, which is the ordinary case: Evaluate runs
// this for every rule on every tool call, and c.identities() allocates. A rule
// set that uses neither list — every rule written before Phase 173 — costs two
// length checks.
func (r Rule) matchesCaller(c Caller) bool {
	if len(r.Agents) > 0 && !slices.Contains(r.Agents, c.Agent) {
		return false
	}
	if len(r.NotAgents) == 0 {
		return true
	}
	for _, id := range c.identities() {
		if slices.Contains(r.NotAgents, id) {
			return false
		}
	}
	return true
}

// Decision is the engine's verdict for a tool call.
//
// TTL is the matched rule's ttl_seconds, zero when it sets none; the broker
// narrows its own token TTL with it when parking the call (Broker.effectiveTTL).
// Scope is the rendered audit label — see Rule for what each of the two can and
// cannot do.
type Decision struct {
	RuleID    string
	Effect    Effect
	Scope     string
	TTL       time.Duration
	Approvers []string
	Reason    string
}

// Engine holds an ordered, validated rule set.
type Engine struct {
	rules []Rule
}

type policyFile struct {
	Rules []Rule `yaml:"rules"`
}

// Load parses a YAML policy from r, rejecting unknown keys (fail-loud) and
// validating that every rule has an id and a known effect.
func Load(r io.Reader) (*Engine, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var f policyFile
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	if len(f.Rules) == 0 {
		return nil, fmt.Errorf("policy: no rules defined")
	}
	for i := range f.Rules {
		r := &f.Rules[i]
		if r.ID == "" {
			return nil, fmt.Errorf("policy: rule at index %d has no id", i)
		}
		switch r.Effect {
		case EffectAllow, EffectDeny, EffectRequireApproval:
		default:
			return nil, fmt.Errorf("policy: rule %q has invalid effect %q", r.ID, r.Effect)
		}
		if r.Effect == EffectRequireApproval && len(r.Approvers) == 0 {
			return nil, fmt.Errorf("policy: rule %q requires approval but lists no approvers", r.ID)
		}
		// ttl_seconds bounds an APPROVAL WINDOW. On an allow rule there is no
		// window — the call runs and returns in the same request — and on a deny
		// there is nothing to bound at all, so a value there has never meant
		// anything. Refusing it at load is the point of this phase: the field was
		// parsed and ignored everywhere for six phases, and a setting that reads
		// like a control while doing nothing is worse than no setting. A negative
		// value is refused for the same reason rather than silently clamped.
		for field := range r.When {
			name, isCaller := strings.CutPrefix(field, "caller.")
			if isCaller && !slices.Contains(callerFields, name) {
				return nil, fmt.Errorf(
					"policy: rule %q matches on unknown caller attribute %q; valid ones are caller.%s",
					r.ID, field, strings.Join(callerFields, ", caller."))
			}
		}
		for _, list := range [][]string{r.Agents, r.NotAgents} {
			for _, id := range list {
				if strings.TrimSpace(id) == "" {
					return nil, fmt.Errorf("policy: rule %q lists an empty agent identity", r.ID)
				}
			}
		}
		switch {
		case r.TTLSeconds < 0:
			return nil, fmt.Errorf("policy: rule %q has a negative ttl_seconds", r.ID)
		case r.TTLSeconds > 0 && r.Effect != EffectRequireApproval:
			return nil, fmt.Errorf(
				"policy: rule %q sets ttl_seconds on an %q rule, where it bounds nothing; "+
					"ttl_seconds limits how long a require_approval call stays decidable", r.ID, r.Effect)
		}
	}
	return &Engine{rules: f.Rules}, nil
}

// LoadFile reads and parses a policy file from path.
func LoadFile(path string) (*Engine, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured broker policy file path
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	return Load(bytes.NewReader(data))
}

// Rules returns the number of loaded rules (for startup logging).
func (e *Engine) Rules() int { return len(e.rules) }

// Evaluate returns the decision for a tool call by the given verified caller. It
// scans rules top-to-bottom, returning the first whose principal side, tool and
// conditions all match; a scope-template failure on a matched rule is a deny, and
// no match at all is the implicit default deny.
//
// The caller is passed rather than inferred (Phase 173): before it, the engine
// saw only the tool and its arguments, so a rule could not say WHO it applied to
// and any identity a condition matched was one the agent had asserted itself.
func (e *Engine) Evaluate(caller Caller, tool string, args map[string]any) Decision {
	for _, r := range e.rules {
		if r.Tool != "" && r.Tool != tool {
			continue
		}
		if !r.matchesCaller(caller) {
			continue
		}
		if !matchAll(r.When, args, caller) {
			continue
		}
		scope, ok := renderScope(r.Scope, args)
		if !ok {
			return Decision{RuleID: r.ID, Effect: EffectDeny, Reason: "scope template failed: missing argument"}
		}
		return Decision{
			RuleID:    r.ID,
			Effect:    r.Effect,
			Scope:     scope,
			TTL:       time.Duration(r.TTLSeconds) * time.Second,
			Approvers: r.Approvers,
			Reason:    r.Reason,
		}
	}
	return Decision{RuleID: "implicit-default-deny", Effect: EffectDeny, Reason: "no rule matched"}
}

// MayEverAllow reports whether ANY set of arguments could get this caller an
// allow (or an approval) for this tool. It is the question a listing asks, where
// Evaluate answers the question a call asks.
//
// It exists because MCP `tools/list` handed every agent the whole registry: an
// agent permitted only `ssh_exec` was still told `winrm_exec` and
// `reveal_credential` exist. Policy refused the call, but the listing had already
// described the surface — the same disclosure Phase 189 closed for target
// listings, where the answer was to show an agent only what it can reach.
//
// The reasoning follows Evaluate's own order, first match wins:
//
//   - a rule that does not name this tool, or whose principal side excludes this
//     caller, can never fire — skip it;
//   - a rule with NO conditions always fires for this caller and tool, so its
//     effect is final: allow or require_approval means yes, deny means no;
//   - a rule WITH conditions only might fire. If it could allow, that is enough
//     to say yes. If it would deny, a later rule may still allow, so keep looking.
//
// Nothing matching is the implicit default deny, and therefore no.
//
// Deliberately conservative in the DISCLOSURE direction, not the access one: it
// never widens what a call may do — Evaluate alone decides that — so a tool shown
// here can still be refused, while a tool hidden here can still be called by name
// if an agent already knows it. Hiding is advisory; the point is to stop handing
// out a map.
func (e *Engine) MayEverAllow(caller Caller, tool string) bool {
	for _, r := range e.rules {
		if r.Tool != "" && r.Tool != tool {
			continue
		}
		if !r.matchesCaller(caller) {
			continue
		}
		if len(r.When) == 0 {
			return r.Effect != EffectDeny
		}
		if r.Effect != EffectDeny {
			return true
		}
	}
	return false
}

// matchAll reports whether every condition in when holds (AND logic).
//
// A `caller.` prefix reads the VERIFIED identity; anything else reads the call's
// arguments (with an optional, historical `args.` prefix). The split is absolute
// and that is the point: an agent cannot satisfy `caller.agent` by sending an
// argument named "caller.agent", because a caller.* key never reaches the
// argument map at all. Load has already refused any unknown caller.* field, so
// the lookup here cannot silently never match.
func matchAll(when map[string]Condition, args map[string]any, caller Caller) bool {
	for field, cond := range when {
		var val string
		var present bool
		if name, isCaller := strings.CutPrefix(field, "caller."); isCaller {
			val, present = caller.attr(name)
		} else {
			raw, ok := args[strings.TrimPrefix(field, "args.")]
			val, present = stringify(raw), ok
		}
		if !cond.match(val, present) {
			return false
		}
	}
	return true
}

var scopeVar = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

// renderScope substitutes {arg} placeholders in tmpl from args. It returns
// ok=false if any referenced argument is absent (the caller treats that as deny).
func renderScope(tmpl string, args map[string]any) (string, bool) {
	if tmpl == "" {
		return "", true
	}
	ok := true
	out := scopeVar.ReplaceAllStringFunc(tmpl, func(m string) string {
		name := m[1 : len(m)-1]
		v, present := args[name]
		if !present {
			ok = false
			return m
		}
		return stringify(v)
	})
	return out, ok
}

// stringify renders an argument value (from JSON: string/number/bool) as the
// string the policy compares against.
func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		// JSON numbers decode to float64; format in plain decimal so an integer
		// argument like 10000000 matches the policy's "10000000" and not the
		// "%v"/%g rendering "1e+07" (which would silently never match).
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	default:
		return fmt.Sprintf("%v", t)
	}
}
