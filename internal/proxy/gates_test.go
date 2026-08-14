package proxy

// gates_test.go replaces the old source-level "do the DB proxies mention the
// same 14 gate identifiers" drift alarm with something stronger for the gates
// that were unified: it drives each admission gate's DENIAL through the one
// shared admit() and asserts the typed outcome and the audits admit() itself
// emits. Because all three proxies (SSH, PostgreSQL, SQL Server) now route their
// admission decision through this single function, exercising it once proves the
// gate for every proxy — a behavioural check where the old one was textual.
//
// The gates that admit() does NOT own — the per-connection rate limiter, the
// session registration, the fail-closed recording, and the per-statement
// command-control/step-up pipeline invoked from each DB proxy's relay — are
// still duplicated across dbproxy.go and mssqlproxy.go, so TestDBRelayGatesStay-
// InSync below keeps the narrower source-level drift check for exactly those.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/posture"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

const (
	gatesTestUser   = "root"
	gatesTestSecret = "s3cr3t-from-the-vault"
)

// testEnv is a fresh gates + backing store + a seeded ssh target "web-01" with a
// password credential, built per case so cases cannot contaminate one another.
type testEnv struct {
	g      *gates
	st     store.Store
	v      *vault.Vault
	target *store.Target
	cred   *store.Credential
}

// newTestEnv builds a testEnv: an in-memory store, a real vault, and one ssh
// target whose credential's secret is vaulted the same way the API path does it
// (insert to assign the ID, then encrypt bound to that ID).
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	st := memstore.New()
	key, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	target := &store.Target{Name: "web-01", Host: "127.0.0.1", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	cred := &store.Credential{TargetID: target.ID, Username: gatesTestUser, SecretType: "password"}
	if err := st.CreateCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	enc, err := v.Encrypt(ctx, gatesTestSecret, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateCredentialSecretEnc(ctx, cred.ID, enc); err != nil {
		t.Fatal(err)
	}
	return &testEnv{
		g: &gates{
			store: st,
			vault: v,
			log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		st:     st,
		v:      v,
		target: target,
		cred:   cred,
	}
}

// baseReq is the SSH-shaped admit request every case starts from: it resolves
// "web-01", brokers ssh, decrypts a normal (non-ssh_ca) credential and audits a
// session.start. Cases override individual fields to exercise one gate.
func baseReq(p *auth.Principal) admitRequest {
	return admitRequest{
		principal:   p,
		targetName:  "web-01",
		proxyable:   func(t *store.Target) bool { return t.Protocol == "ssh" },
		skipDecrypt: func(c *store.Credential) bool { return c.SecretType == "ssh_ca" },
		startAudit: func(t *store.Target, c *store.Credential) (string, string) {
			return "session.start", "target:" + t.Name + " cred_user:" + c.Username
		},
	}
}

// user is a connect-capable non-admin principal; auditor cannot connect.
func gatesUser(name string) *auth.Principal { return &auth.Principal{Name: name, Role: auth.RoleUser} }

// failingAuditGates wraps a Store and fails AppendAudit for one action, so a
// case can prove admit() fails closed when the session-start evidence cannot be
// written. (The proxy_test package has its own copy; this is the package-proxy
// twin, since an internal test cannot import an external test helper.)
type failingAuditGates struct {
	store.Store
	failAction string
}

// AppendAudit refuses the configured action and passes every other one through.
func (f *failingAuditGates) AppendAudit(ctx context.Context, e *store.AuditEvent) error {
	if e.Action == f.failAction {
		return errors.New("audit store down")
	}
	return f.Store.AppendAudit(ctx, e)
}

// TestAdmitDeniesEachGate drives one denial (or the two OK paths) per gate
// through the shared admit() and checks the typed outcome, the specific gate,
// and the audits admit() owns. This is the behavioural successor to the old
// grep-based parity alarm: it proves the unified gates actually refuse, for
// every proxy at once, because every proxy calls this same function.
func TestAdmitDeniesEachGate(t *testing.T) {
	cases := []struct {
		name       string
		build      func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest)
		wantKind   admitKind
		wantGate   admitGate
		wantAudits []string // audit actions admit() must have written
		wantSecret bool     // admitOK: expect the vaulted secret back
	}{
		{
			name: "tunnel-only token",
			build: func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest) {
				p := gatesUser("alice")
				p.TunnelOnly = true
				return p, baseReq(p)
			},
			wantKind: admitDenied, wantGate: gateTunnelOnly,
		},
		{
			name: "mfa enrollment pending",
			build: func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest) {
				p := gatesUser("alice")
				p.EnrollOnly = true
				return p, baseReq(p)
			},
			wantKind: admitDenied, wantGate: gateEnrollOnly,
		},
		{
			name: "role lacks CapConnect",
			build: func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest) {
				p := &auth.Principal{Name: "otto", Role: auth.RoleAuditor}
				return p, baseReq(p)
			},
			wantKind: admitDenied, wantGate: gateRoleConnect,
		},
		{
			name: "device posture check fails",
			build: func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest) {
				fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusForbidden)
				}))
				t.Cleanup(fail.Close)
				env.g.posture = posture.NewAttestor(fail.URL)
				p := gatesUser("alice")
				return p, baseReq(p)
			},
			wantKind: admitDenied, wantGate: gatePosture,
		},
		{
			name: "break-glass bypasses the posture gate",
			build: func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest) {
				fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusForbidden)
				}))
				t.Cleanup(fail.Close)
				env.g.posture = posture.NewAttestor(fail.URL)
				p := gatesUser("alice")
				p.BreakGlass = true
				return p, baseReq(p)
			},
			wantKind: admitOK, wantGate: gateNone, wantSecret: true,
			wantAudits: []string{"session.start"},
		},
		{
			name: "target does not resolve",
			build: func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest) {
				p := gatesUser("alice")
				req := baseReq(p)
				req.targetName = "nosuch"
				return p, req
			},
			wantKind: admitDenied, wantGate: gateResolve,
		},
		{
			name: "exact-protocol mismatch (DB proxies)",
			build: func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest) {
				p := gatesUser("alice")
				req := baseReq(p)
				req.proxyable = nil             // DB proxies use expectProtocol, not proxyable
				req.expectProtocol = "postgres" // the target is ssh
				return p, req
			},
			wantKind: admitDenied, wantGate: gateProtocolMatch,
		},
		{
			name: "protocol not on the allowlist",
			build: func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest) {
				env.g.allowedProto = map[string]bool{"winrm": true} // ssh excluded
				p := gatesUser("alice")
				return p, baseReq(p)
			},
			wantKind: admitDenied, wantGate: gateProtocolAllowed,
		},
		{
			name: "per-target policy denies an ungranted user",
			build: func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest) {
				// A grant for someone else makes the grant set non-empty, so an
				// unmatched non-admin is refused (default-deny once grants exist).
				if err := env.st.CreateTargetGrant(context.Background(),
					&store.TargetGrant{TargetID: env.target.ID, SubjectType: "user", Subject: "bob"}); err != nil {
					t.Fatal(err)
				}
				p := gatesUser("alice")
				return p, baseReq(p)
			},
			wantKind: admitDenied, wantGate: gateTargetPolicy,
		},
		{
			name: "approval required but none granted",
			build: func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest) {
				env.g.requireApprv = true
				p := gatesUser("alice")
				return p, baseReq(p)
			},
			wantKind: admitDenied, wantGate: gateApproval,
			// admit owns the (byte-identical) access.denied for an approval refusal.
			wantAudits: []string{"access.denied"},
		},
		{
			name: "break-glass bypasses the approval gate",
			build: func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest) {
				env.g.requireApprv = true
				p := gatesUser("alice")
				p.BreakGlass = true
				return p, baseReq(p)
			},
			wantKind: admitOK, wantGate: gateNone, wantSecret: true,
			wantAudits: []string{"session.start"},
		},
		{
			name: "concurrent-session cap reached",
			build: func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest) {
				reg := session.NewRegistry()
				reg.SetLimits(1, 0) // one live session per actor
				reg.Register(session.Info{Actor: "alice", Target: "other"}, func() {})
				env.g.sessions = reg
				p := gatesUser("alice")
				return p, baseReq(p)
			},
			wantKind: admitSessionLimited, wantGate: gateSessionLimit,
		},
		{
			name: "session-start audit cannot be written",
			build: func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest) {
				env.g.store = &failingAuditGates{Store: env.st, failAction: "session.start"}
				p := gatesUser("alice")
				return p, baseReq(p)
			},
			wantKind: admitAuditUnavailable, wantGate: gateAudit,
		},
		{
			name: "credential decryption fails",
			build: func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest) {
				// Corrupt the stored ciphertext so JIT decryption fails.
				if err := env.st.UpdateCredentialSecretEnc(context.Background(), env.cred.ID, "v2:not-a-valid-envelope"); err != nil {
					t.Fatal(err)
				}
				p := gatesUser("alice")
				return p, baseReq(p)
			},
			wantKind: admitDecryptFailed, wantGate: gateDecrypt,
			// admit owns the (byte-identical) credential.decrypt_failed audit;
			// session.start still lands first (evidence before decryption).
			wantAudits: []string{"session.start", "credential.decrypt_failed"},
		},
		{
			name: "all gates pass",
			build: func(t *testing.T, env *testEnv) (*auth.Principal, admitRequest) {
				p := gatesUser("alice")
				return p, baseReq(p)
			},
			wantKind: admitOK, wantGate: gateNone, wantSecret: true,
			wantAudits: []string{"session.start"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t)
			p, req := tc.build(t, env)
			res := env.g.admit(context.Background(), req)

			if res.outcome != tc.wantKind {
				t.Fatalf("outcome = %d, want %d", res.outcome, tc.wantKind)
			}
			if res.gate != tc.wantGate {
				t.Fatalf("gate = %d, want %d", res.gate, tc.wantGate)
			}
			if tc.wantSecret && res.secret != gatesTestSecret {
				t.Fatalf("secret = %q, want the vaulted secret", res.secret)
			}
			if !tc.wantSecret && res.secret != "" {
				t.Fatalf("secret leaked on a refused/secretless session: %q", res.secret)
			}
			// Every audit admit() wrote goes to env.g.store, which for one case is
			// the failing wrapper — read through the underlying memstore.
			events, err := env.st.ListAudit(context.Background(), 100)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.wantAudits {
				if !hasAuditAction(events, want) {
					t.Fatalf("missing audit %q; got %v", want, auditActions(events))
				}
			}
			_ = p
		})
	}
}

// hasAuditAction reports whether any event has the given action.
func hasAuditAction(events []store.AuditEvent, action string) bool {
	for _, e := range events {
		if e.Action == action {
			return true
		}
	}
	return false
}

// auditActions lists the action of every event, for a readable failure message.
func auditActions(events []store.AuditEvent) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Action)
	}
	return out
}

// dbRelayGates are the policy invocations the two DB proxies still hold
// SEPARATELY — the ones admit() does NOT unify. admit() folded the admission
// gates into one function, but each DB proxy keeps its own pre-auth rate limit,
// its own session registration, its own fail-closed recording, its own
// break-glass note, and its own per-statement command-control/step-up calls in
// relay. Those are the remaining copy-paste surface, so this narrow source-level
// check stays to stop one drifting from the other.
var dbRelayGates = []string{
	"authLimiter",         // pre-auth online-guessing throttle
	"noteBreakGlass",      // emergency-access signal raised per proxy
	"Register",            // live-session registration (kill/monitor)
	"requireRec",          // fail-closed session recording
	"sqlBlockedStatement", // per-statement command control (relay)
	"sqlStepUpRefused",    // per-statement in-session step-up (relay)
}

// TestDBRelayGatesStayInSync keeps the PostgreSQL and SQL Server proxies from
// drifting on the gates admit() does NOT own. It is the slimmed successor to the
// old 14-identifier alarm: the admission gates moved into the shared admit()
// (covered behaviourally by TestAdmitDeniesEachGate), leaving only these relay/
// connection gates duplicated between the two files.
func TestDBRelayGatesStayInSync(t *testing.T) {
	pg := readProxyCode(t, "dbproxy.go")
	ms := readProxyCode(t, "mssqlproxy.go")
	for _, gate := range dbRelayGates {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(gate) + `\b`)
		inPG, inMS := re.MatchString(pg), re.MatchString(ms)
		switch {
		case inPG && inMS:
			// Both invoke it: the invariant holds for this gate.
		case inPG:
			t.Errorf("policy drift: dbproxy.go references %q and mssqlproxy.go does not. "+
				"Add it to the SQL Server path, or drop it from dbRelayGates with a reason.", gate)
		case inMS:
			t.Errorf("policy drift: mssqlproxy.go references %q and dbproxy.go does not. See the note above.", gate)
		default:
			t.Errorf("%q appears in neither DB proxy: the gate was renamed or removed and dbRelayGates is stale.", gate)
		}
	}
}

// readProxyCode reads one proxy's source with comment lines stripped, so a gate
// merely mentioned in a comment cannot stand in for one that is enforced.
func readProxyCode(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code.WriteString(line)
		code.WriteByte('\n')
	}
	return code.String()
}
