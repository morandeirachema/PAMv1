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

// Rule is one policy entry. A missing Tool matches every tool (global rule).
type Rule struct {
	ID         string               `yaml:"id"`
	Tool       string               `yaml:"tool"`
	When       map[string]Condition `yaml:"when"`
	Effect     Effect               `yaml:"effect"`
	Approvers  []string             `yaml:"approvers"`
	Scope      string               `yaml:"scope"`
	TTLSeconds int                  `yaml:"ttl_seconds"`
	Reason     string               `yaml:"reason"`
}

// Decision is the engine's verdict for a tool call.
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

// Evaluate returns the decision for a tool call. It scans rules top-to-bottom,
// returning the first whose tool and conditions match; a scope-template failure
// on a matched rule is a deny, and no match at all is the implicit default deny.
func (e *Engine) Evaluate(tool string, args map[string]any) Decision {
	for _, r := range e.rules {
		if r.Tool != "" && r.Tool != tool {
			continue
		}
		if !matchAll(r.When, args) {
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

// matchAll reports whether every condition in when holds for args (AND logic).
func matchAll(when map[string]Condition, args map[string]any) bool {
	for field, cond := range when {
		key := strings.TrimPrefix(field, "args.")
		val, present := args[key]
		if !cond.match(stringify(val), present) {
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
