package proxy

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// dbProxyGates is every identifier that constitutes POLICY on a database
// session: who may connect, whether an approval is needed and spent, whether the
// session is recorded, and the fail-closed audit that must precede the upstream
// dial.
//
// The list is written out rather than derived, so adding a gate to one proxy and
// not the other is a decision somebody has to make in this file instead of an
// omission nobody notices.
var dbProxyGates = []string{
	// Authorization
	"CanConnectTarget",
	"EffectiveTargetGrants",
	"EffectiveApprovalPolicy",
	"claimApproval",
	// Identity-time refusals the HTTP middleware also makes
	"EnrollOnly",
	"TunnelOnly",
	"BreakGlass",
	"noteBreakGlass",
	// Abuse and resource limits
	"authLimiter",
	"Register",
	// Recording and in-session control
	"requireRec",
	"blockedStatement",
	"stepUpRefused",
	// Evidence before the upstream leg
	"appendAuditErr",
}

// TestDBProxiesEnforceTheSameGates keeps the PostgreSQL and SQL Server proxies
// from drifting apart on policy.
//
// The two are ~1,000 lines each and deliberately line-for-line siblings, so that
// "anything that differs is the transport, never the policy". That is a good
// decision and a fragile one: it means every policy fix must be made twice, and
// nothing but care stops the second one being forgotten. This is the thing that
// stops it — the repo's own history is full of one path missing a gate its
// siblings enforced (the tunnel-scoped token at three listeners, the app-secret
// grant that skipped gateCredentialAccess, the broker's reveal that skipped
// four-eyes), and the cost of finding those late is what this test buys down.
//
// It is deliberately a source-level check. A behavioural test would need a live
// SQL Server, which is exactly the infrastructure this repo does not pretend to
// have — and the failure being guarded is textual: a gate that was never typed
// into one of the two files.
func TestDBProxiesEnforceTheSameGates(t *testing.T) {
	pg := readProxySource(t, "dbproxy.go")
	ms := readProxySource(t, "mssqlproxy.go")

	for _, gate := range dbProxyGates {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(gate) + `\b`)
		inPG, inMS := re.MatchString(pg), re.MatchString(ms)
		switch {
		case inPG && inMS:
			// Both enforce it: the invariant holds for this gate.
		case inPG:
			t.Errorf("policy drift: dbproxy.go references %q and mssqlproxy.go does not.\n"+
				"The two proxies are siblings on purpose so that anything differing between them is the\n"+
				"transport and never the policy. Either add the gate to the SQL Server path, or if it\n"+
				"genuinely does not apply there, remove it from dbProxyGates with a comment saying why.", gate)
		case inMS:
			t.Errorf("policy drift: mssqlproxy.go references %q and dbproxy.go does not. See the note above.", gate)
		default:
			// Neither has it. The gate was renamed or removed and this list was not
			// updated — which would otherwise leave the test checking a dead name
			// forever and reporting green while it tested nothing.
			t.Errorf("%q appears in neither proxy: the gate was renamed or removed and dbProxyGates is stale.\n"+
				"A list of names nothing matches is a test that cannot fail.", gate)
		}
	}
}

// readProxySource reads one proxy's source with its comments stripped, so a gate
// merely *mentioned* in a comment cannot stand in for one that is enforced.
func readProxySource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(b), "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//") {
			continue
		}
		code.WriteString(line)
		code.WriteByte('\n')
	}
	return code.String()
}
