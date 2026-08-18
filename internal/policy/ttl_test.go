package policy

import (
	"strings"
	"testing"
	"time"
)

// TestTTLIsRefusedWhereItBoundsNothing pins Phase 171's load-time validation.
//
// `ttl_seconds` was parsed into Decision.TTL and read by no non-test caller for
// six phases, and the shipped example policy advertised it on an `allow` rule as
// "a scoped, short-lived grant" — teaching operators to rely on a field that did
// nothing at all. Now it bounds a real approval window, which also means there
// are effects it cannot bound: an allow executes and returns in one request, and
// a deny is over before it starts. Setting it there is refused when the policy
// loads rather than accepted and ignored.
func TestTTLIsRefusedWhereItBoundsNothing(t *testing.T) {
	for _, tc := range []struct{ name, policy, want string }{
		{
			"on an allow rule",
			"rules:\n  - id: r\n    tool: t\n    effect: allow\n    ttl_seconds: 60\n",
			"bounds nothing",
		},
		{
			"on a deny rule",
			"rules:\n  - id: r\n    tool: t\n    effect: deny\n    ttl_seconds: 60\n",
			"bounds nothing",
		},
		{
			"negative",
			"rules:\n  - id: r\n    tool: t\n    effect: require_approval\n    approvers: [team]\n    ttl_seconds: -1\n",
			"negative ttl_seconds",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(tc.policy))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load: want an error containing %q, got %v", tc.want, err)
			}
		})
	}

	// Where it does bound something, it loads and reaches the decision.
	e, err := Load(strings.NewReader(
		"rules:\n  - id: r\n    tool: t\n    effect: require_approval\n    approvers: [team]\n    ttl_seconds: 90\n"))
	if err != nil {
		t.Fatalf("a ttl on a require_approval rule must load: %v", err)
	}
	if d := e.Evaluate(Caller{}, "t", nil); d.TTL != 90*time.Second {
		t.Fatalf("decision ttl = %v, want 90s", d.TTL)
	}
}
