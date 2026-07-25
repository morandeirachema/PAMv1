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

// TestConditionalDenyDoesNotHideUnconditionalDeny proves a conditional Deny does
// not short-circuit to Uncertain when an unconditional Deny also matches, and that
// a conditional Deny with no Allow at all is a definite Deny.
func TestConditionalDenyDoesNotHideUnconditionalDeny(t *testing.T) {
	star := []string{"*"}
	// Conditional deny + unconditional deny both match → definite Deny.
	e := Evaluator{Identity: []Policy{
		pol(Allow, star, star, false),
		pol(Deny, []string{"s3:*"}, star, true),          // conditional deny (appears first)
		pol(Deny, []string{"s3:GetObject"}, star, false), // unconditional deny
	}}
	if got := e.Evaluate("s3:GetObject", "arn:aws:s3:::b/o"); got.Decision != Denied {
		t.Fatalf("unconditional deny must win over an earlier conditional deny: %s (%s)", got.Decision, got.Reason)
	}
	// A conditional deny with NO allow anywhere is a definite (implicit) Deny.
	e = Evaluator{Identity: []Policy{pol(Deny, []string{"s3:*"}, star, true)}}
	if got := e.Evaluate("s3:GetObject", "arn:aws:s3:::b/o"); got.Decision != Denied {
		t.Fatalf("conditional deny with no allow must be denied, not uncertain: %s", got.Decision)
	}
	// A conditional deny WITH an allow is uncertain (the deny might apply).
	e = Evaluator{Identity: []Policy{pol(Allow, star, star, false), pol(Deny, []string{"s3:*"}, star, true)}}
	if got := e.Evaluate("s3:GetObject", "arn:aws:s3:::b/o"); got.Decision != Uncertain {
		t.Fatalf("conditional deny over an allow must be uncertain: %s", got.Decision)
	}
}

// TestResourceMatchingIsCaseSensitive proves actions match case-insensitively but
// resource ARNs match case-sensitively (an S3 key is case-significant).
func TestResourceMatchingIsCaseSensitive(t *testing.T) {
	// Action case-insensitive: an "s3:getobject" pattern matches "s3:GetObject".
	e := Evaluator{Identity: []Policy{pol(Allow, []string{"s3:getobject"}, []string{"arn:aws:s3:::b/o"}, false)}}
	if got := e.Evaluate("s3:GetObject", "arn:aws:s3:::b/o"); got.Decision != Allowed {
		t.Fatalf("action matching must be case-insensitive: %s", got.Decision)
	}
	// Resource case-sensitive: a Deny on ".../Secret" must NOT match ".../secret".
	e = Evaluator{Identity: []Policy{
		pol(Allow, []string{"s3:*"}, []string{"arn:aws:s3:::b/*"}, false),
		pol(Deny, []string{"s3:*"}, []string{"arn:aws:s3:::b/Secret"}, false),
	}}
	if got := e.Evaluate("s3:GetObject", "arn:aws:s3:::b/secret"); got.Decision != Allowed {
		t.Fatalf("a Deny on b/Secret must not match b/secret (case-sensitive): %s", got.Decision)
	}
	if got := e.Evaluate("s3:GetObject", "arn:aws:s3:::b/Secret"); got.Decision != Denied {
		t.Fatalf("the Deny must match the exact-case b/Secret: %s", got.Decision)
	}
}
