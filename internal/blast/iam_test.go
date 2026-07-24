package blast

import "testing"

// pol is a tiny helper to build a one-statement policy.
func pol(effect Effect, actions, resources []string, cond bool) Policy {
	return Policy{Statements: []Statement{{Effect: effect, Actions: actions, Resources: resources, HasCondition: cond}}}
}

// TestEvaluateOrder proves the AWS evaluation order: explicit deny wins, an SCP
// and a permission boundary each cap, an identity allow grants, and no match is
// an implicit deny.
func TestEvaluateOrder(t *testing.T) {
	star := []string{"*"}

	// Explicit deny beats an allow.
	e := Evaluator{Identity: []Policy{pol(Allow, star, star, false), pol(Deny, []string{"s3:*"}, star, false)}}
	if got := e.Evaluate("s3:GetObject", "arn:aws:s3:::bucket/obj"); got.Decision != Denied {
		t.Fatalf("explicit deny: %s (%s)", got.Decision, got.Reason)
	}

	// Identity allow with no ceiling → allow.
	e = Evaluator{Identity: []Policy{pol(Allow, []string{"s3:GetObject"}, star, false)}}
	if got := e.Evaluate("s3:GetObject", "arn:aws:s3:::b/o"); got.Decision != Allowed {
		t.Fatalf("identity allow: %s", got.Decision)
	}
	// No matching allow → implicit deny.
	if got := e.Evaluate("s3:PutObject", "arn:aws:s3:::b/o"); got.Decision != Denied {
		t.Fatalf("implicit deny: %s", got.Decision)
	}

	// An SCP ceiling that does not allow the action → deny even with identity allow.
	e = Evaluator{
		Identity: []Policy{pol(Allow, star, star, false)},
		SCPs:     []Policy{pol(Allow, []string{"s3:*"}, star, false)},
	}
	if got := e.Evaluate("iam:CreateUser", "*"); got.Decision != Denied {
		t.Fatalf("SCP ceiling: %s (%s)", got.Decision, got.Reason)
	}
	if got := e.Evaluate("s3:GetObject", "*"); got.Decision != Allowed {
		t.Fatalf("within SCP ceiling: %s", got.Decision)
	}

	// A permission boundary caps the same way.
	e = Evaluator{
		Identity: []Policy{pol(Allow, star, star, false)},
		Boundary: []Policy{pol(Allow, []string{"ec2:Describe*"}, star, false)},
	}
	if got := e.Evaluate("ec2:TerminateInstances", "*"); got.Decision != Denied {
		t.Fatalf("boundary ceiling: %s", got.Decision)
	}
	if got := e.Evaluate("ec2:DescribeInstances", "*"); got.Decision != Allowed {
		t.Fatalf("within boundary: %s", got.Decision)
	}
}

// TestEvaluateUncertain proves a conditional allow yields UNCERTAIN, not a hard
// allow — the engine never asserts a permission it cannot fully evaluate.
func TestEvaluateUncertain(t *testing.T) {
	e := Evaluator{Identity: []Policy{pol(Allow, []string{"s3:*"}, []string{"*"}, true)}}
	if got := e.Evaluate("s3:GetObject", "arn:aws:s3:::b/o"); got.Decision != Uncertain {
		t.Fatalf("conditional allow: %s (%s), want uncertain", got.Decision, got.Reason)
	}
}

// TestWildcardMatch covers the glob semantics (prefix, suffix, single-char, and
// full-string anchoring) used for action/resource matching.
func TestWildcardMatch(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"s3:*", "s3:getobject", true},
		{"*", "anything", true},
		{"ec2:describe*", "ec2:describeinstances", true},
		{"ec2:describe*", "ec2:terminateinstances", false},
		{"arn:aws:s3:::b/?", "arn:aws:s3:::b/o", true},
		{"iam:createuser", "iam:createrole", false},
		{"a*b", "axxb", true},
		{"a*b", "axxc", false},
	}
	for _, c := range cases {
		if got := wildcardMatch(c.pat, c.s); got != c.want {
			t.Errorf("wildcardMatch(%q,%q)=%v, want %v", c.pat, c.s, got, c.want)
		}
	}
}
