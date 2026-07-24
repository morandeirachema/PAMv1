// Package blast is a read-only identity blast-radius / CIEM engine (Phase 31,
// pam-research Solution-04). It evaluates *effective* permissions and follows
// privilege-escalation paths across a normalized, provider-agnostic identity
// graph, so a reviewer can answer "if this identity is compromised, what can it
// actually reach?" — the honest, in-process core. Live cloud ingestion (boto3,
// Okta, GitHub, Workspace APIs) is the external part and is deliberately out of
// scope: the engine consumes a normalized graph that an ingester produces.
//
// iam.go is the AWS IAM effective-permission evaluator. It implements the real
// AWS policy-evaluation order — an explicit Deny anywhere wins, an SCP is a
// ceiling, a permission boundary is a ceiling, then an identity Allow grants —
// and models a condition it cannot evaluate as UNCERTAIN rather than guessing.
// "An edge means a permission that really holds."
package blast

import "strings"

// Effect is a policy statement's effect.
type Effect string

const (
	Allow Effect = "Allow"
	Deny  Effect = "Deny"
)

// Statement is one IAM policy statement (a minimal, honest subset: actions,
// resources, effect, and whether it carries a condition we cannot evaluate).
type Statement struct {
	Effect       Effect   `json:"effect"`
	Actions      []string `json:"actions"`   // e.g. ["s3:GetObject", "sts:AssumeRole"] or ["*"]
	Resources    []string `json:"resources"` // ARNs or ["*"]; matched with '*'/'?' wildcards
	HasCondition bool     `json:"has_condition"`
}

// Policy is a named set of statements (an identity policy, an SCP, or a boundary).
type Policy struct {
	Name       string      `json:"name"`
	Statements []Statement `json:"statements"`
}

// Decision is the evaluator's verdict for (action, resource).
type Decision int

const (
	// Denied: an explicit Deny matched, or nothing allowed (implicit deny), or a
	// ceiling (SCP / boundary) did not permit the action.
	Denied Decision = iota
	// Allowed: an identity Allow matched and every ceiling permitted it, with no
	// blocking condition.
	Allowed
	// Uncertain: the action would be allowed but a condition we cannot evaluate
	// gates it (or the only matching allow at a ceiling was conditional), so we
	// neither assert nor deny it — a reviewer must check.
	Uncertain
)

// String renders a Decision.
func (d Decision) String() string {
	switch d {
	case Allowed:
		return "allow"
	case Uncertain:
		return "uncertain"
	default:
		return "deny"
	}
}

// Evaluation is the full result of an effective-permission check.
type Evaluation struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
}

// Evaluator holds an AWS principal's effective-permission inputs: its identity
// policies, an optional org SCP set (a ceiling), and an optional permission
// boundary (a ceiling). Empty ceilings impose no limit.
type Evaluator struct {
	Identity []Policy `json:"identity"`
	SCPs     []Policy `json:"scps"`
	Boundary []Policy `json:"boundary"`
}

// Evaluate returns the effective decision for (action, resource) following AWS
// policy-evaluation order:
//  1. an explicit Deny in ANY policy (identity, SCP, or boundary) → deny;
//  2. every present ceiling (SCPs, boundary) must allow it, else → deny;
//  3. an identity Allow must match, else → implicit deny;
//  4. if the only thing that would allow it is conditional (a condition we can't
//     evaluate), the result is UNCERTAIN, not a hard allow.
func (e Evaluator) Evaluate(action, resource string) Evaluation {
	// 1. Explicit deny anywhere is final.
	for _, set := range [][]Policy{e.Identity, e.SCPs, e.Boundary} {
		if st, matched := matchEffect(set, Deny, action, resource); matched {
			if st.HasCondition {
				// A conditional deny might not apply — flag rather than assert allow/deny.
				return Evaluation{Uncertain, "a conditional explicit Deny may apply"}
			}
			return Evaluation{Denied, "explicit Deny"}
		}
	}
	uncertain := false
	// 2. Ceilings: an SCP set and a boundary each cap the permission.
	if len(e.SCPs) > 0 {
		st, ok := matchEffect(e.SCPs, Allow, action, resource)
		if !ok {
			return Evaluation{Denied, "not permitted by the SCP ceiling"}
		}
		uncertain = uncertain || st.HasCondition
	}
	if len(e.Boundary) > 0 {
		st, ok := matchEffect(e.Boundary, Allow, action, resource)
		if !ok {
			return Evaluation{Denied, "not permitted by the permission boundary"}
		}
		uncertain = uncertain || st.HasCondition
	}
	// 3. Identity allow.
	st, ok := matchEffect(e.Identity, Allow, action, resource)
	if !ok {
		return Evaluation{Denied, "no identity Allow matched (implicit deny)"}
	}
	uncertain = uncertain || st.HasCondition
	if uncertain {
		return Evaluation{Uncertain, "allowed only subject to a condition that cannot be evaluated"}
	}
	return Evaluation{Allowed, "identity Allow, permitted by all ceilings"}
}

// matchEffect returns the first statement in policies with the given effect whose
// action AND resource patterns both match, and whether one matched.
func matchEffect(policies []Policy, effect Effect, action, resource string) (Statement, bool) {
	for _, p := range policies {
		for _, st := range p.Statements {
			if st.Effect != effect {
				continue
			}
			if anyMatch(st.Actions, action) && anyMatch(st.Resources, resource) {
				return st, true
			}
		}
	}
	return Statement{}, false
}

// anyMatch reports whether any pattern in pats matches s (case-insensitive for
// actions/ARNs, with '*' and '?' wildcards — the IAM matching semantics).
func anyMatch(pats []string, s string) bool {
	for _, p := range pats {
		if wildcardMatch(strings.ToLower(p), strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// wildcardMatch reports whether pattern (with '*' = any run, '?' = any one char)
// matches s in full. Iterative two-pointer glob with backtracking — no regex, so
// a hostile pattern can't cause catastrophic backtracking.
func wildcardMatch(pattern, s string) bool {
	var si, pi, star, mark int
	star = -1
	for si < len(s) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]) {
			si++
			pi++
		} else if pi < len(pattern) && pattern[pi] == '*' {
			star = pi
			mark = si
			pi++
		} else if star != -1 {
			pi = star + 1
			mark++
			si = mark
		} else {
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
