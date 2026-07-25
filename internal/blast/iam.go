// Package blast is a read-only identity blast-radius / CIEM engine (Phase 31,
// pam-research Solution-04, https://github.com/morandeirachema/pam-research). It
// evaluates *effective* permissions and follows privilege-escalation paths across
// a normalized, provider-agnostic identity graph, so a reviewer can answer "if
// this identity is compromised, what can it actually reach?" — the honest,
// in-process core. Live cloud ingestion (AWS boto3
// [GetAccountAuthorizationDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html),
// [Okta](https://developer.okta.com/docs/reference/),
// [GitHub](https://docs.github.com/en/rest), and
// [Google Workspace Admin](https://developers.google.com/admin-sdk) APIs) is the
// external part and is deliberately out of scope: the engine consumes a
// normalized graph that an ingester produces.
//
// iam.go is the AWS IAM effective-permission evaluator, implementing the real AWS
// policy-evaluation order (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
// — an unconditional explicit Deny anywhere wins, an SCP is a ceiling, a
// permission boundary is a ceiling, then an identity Allow grants — and models a
// condition it cannot evaluate (or a conditional Deny) as UNCERTAIN rather than
// guessing. "An edge means a permission that really holds."
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
	// 1. Explicit deny: an UNCONDITIONAL deny anywhere is final. Scan every deny
	// statement across all policy sets (not just the first match) — a conditional
	// deny that appears before an unconditional one must not short-circuit the
	// stronger, definite deny.
	condDeny := false
	for _, set := range [][]Policy{e.Identity, e.SCPs, e.Boundary} {
		for _, st := range denyMatches(set, action, resource) {
			if st.HasCondition {
				condDeny = true
			} else {
				return Evaluation{Denied, "explicit Deny"}
			}
		}
	}
	uncertain := condDeny
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
	// 3. Identity allow. With no allow the action is denied (implicit) regardless of
	// any conditional deny above.
	st, ok := matchEffect(e.Identity, Allow, action, resource)
	if !ok {
		return Evaluation{Denied, "no identity Allow matched (implicit deny)"}
	}
	uncertain = uncertain || st.HasCondition
	if uncertain {
		return Evaluation{Uncertain, "allowed only subject to a condition (or conditional deny) that cannot be evaluated"}
	}
	return Evaluation{Allowed, "identity Allow, permitted by all ceilings"}
}

// denyMatches returns every Deny statement in policies whose action AND resource
// match (so the caller can distinguish an unconditional from a conditional deny).
func denyMatches(policies []Policy, action, resource string) []Statement {
	var out []Statement
	for _, p := range policies {
		for _, st := range p.Statements {
			if st.Effect == Deny && matchAction(st.Actions, action) && matchResource(st.Resources, resource) {
				out = append(out, st)
			}
		}
	}
	return out
}

// matchEffect returns the first statement in policies with the given effect whose
// action AND resource patterns both match, and whether one matched.
func matchEffect(policies []Policy, effect Effect, action, resource string) (Statement, bool) {
	for _, p := range policies {
		for _, st := range p.Statements {
			if st.Effect != effect {
				continue
			}
			if matchAction(st.Actions, action) && matchResource(st.Resources, resource) {
				return st, true
			}
		}
	}
	return Statement{}, false
}

// matchAction reports whether any pattern matches the action. Action matching is
// case-INSENSITIVE in IAM (e.g. s3:GetObject == s3:getobject).
func matchAction(pats []string, action string) bool {
	action = strings.ToLower(action)
	for _, p := range pats {
		if wildcardMatch(strings.ToLower(p), action) {
			return true
		}
	}
	return false
}

// matchResource reports whether any pattern matches the resource. Resource (ARN)
// matching is case-SENSITIVE in IAM (an S3 object key is case-significant), so a
// wrong-case pattern must not match — that would over- or under-state reach.
func matchResource(pats []string, resource string) bool {
	for _, p := range pats {
		if wildcardMatch(p, resource) {
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
