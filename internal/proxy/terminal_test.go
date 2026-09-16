package proxy

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// termProxy builds a *Proxy over the gate env's store so authenticate — a
// method on the proxy, not on the gates — can be called directly.
func termProxy(t *testing.T, env *testEnv) *Proxy {
	t.Helper()
	key, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := auth.NewResolver(env.st, "term-bootstrap-key", "")
	if err != nil {
		t.Fatal(err)
	}
	pem, err := GenerateHostKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := HostKeyFromPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	px, err := New(env.st, v, resolver, Config{HostKey: signer, RecordingDir: t.TempDir(), DialTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return px
}

// auditSaw reports whether an audit row with action and a detail substring exists.
func auditSaw(t *testing.T, st store.Store, action, detail string) bool {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == action && strings.Contains(e.Detail, detail) {
			return true
		}
	}
	return false
}

// fakeConnMeta is the ssh.ConnMetadata the password callback sees, with the
// two fields the terminal rules read: where the connection came from, and
// the client-version string.
type fakeConnMeta struct {
	user, version string
	remote        net.Addr
}

func (f fakeConnMeta) User() string          { return f.user }
func (f fakeConnMeta) SessionID() []byte     { return []byte("sid") }
func (f fakeConnMeta) ClientVersion() []byte { return []byte(f.version) }
func (f fakeConnMeta) ServerVersion() []byte { return []byte("SSH-2.0-pamv1") }
func (f fakeConnMeta) RemoteAddr() net.Addr  { return f.remote }
func (f fakeConnMeta) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222}
}

// TestTerminalTokenOnlyOverLoopback proves the proxy's one rule for a
// browser-terminal token (Phase 254): it authenticates only from the loopback
// interface — the API server's own dial — and is refused from anywhere else
// exactly as a viewer token is, with its own audit reason. It also proves the
// browser's address is carried through the client-version string.
func TestTerminalTokenOnlyOverLoopback(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	px := termProxy(t, env)
	future := time.Now().Add(time.Hour)
	tok := "term-token"
	if err := env.st.CreateUser(ctx, &store.User{Username: "alice", Role: "user", TokenHash: auth.TokenHash("alice-real-key")}); err != nil {
		t.Fatal(err)
	}
	if err := env.st.CreateSession(ctx, &store.Session{Username: "alice", Role: "user", Scope: auth.SessionScopeTerminal,
		TokenHash: auth.TokenHash(tok), ExpiresAt: future, TargetID: &env.target.ID}); err != nil {
		t.Fatal(err)
	}
	login := gatesTestUser + "@" + env.target.Name

	// From the network: refused, audited with the terminal reason.
	outside := fakeConnMeta{user: login, version: auth.TerminalClientVersion("203.0.113.9"), remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000}}
	if _, err := px.authenticate(outside, []byte(tok)); err == nil {
		t.Fatal("a terminal token from a non-loopback address must be refused")
	}
	if !auditSaw(t, env.st, "session.denied", "reason:terminal-token-off-loopback") {
		t.Fatal("the off-loopback refusal must be audited with its own reason")
	}

	// From loopback: accepted, and the browser's address (from the version
	// string) is stashed for handleConn as the session's remote.
	inside := fakeConnMeta{user: login, version: auth.TerminalClientVersion("198.51.100.7"), remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001}}
	perms, err := px.authenticate(inside, []byte(tok))
	if err != nil {
		t.Fatalf("a terminal token over loopback must authenticate: %v", err)
	}
	if got := perms.Extensions["terminal_remote"]; got != "198.51.100.7" {
		t.Errorf("terminal_remote = %q, want the browser address from the client version", got)
	}
	// A version string that is not ours carries nothing.
	plain := fakeConnMeta{user: login, version: "SSH-2.0-OpenSSH_9.6", remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40002}}
	if err := env.st.CreateSession(ctx, &store.Session{Username: "alice", Role: "user", Scope: auth.SessionScopeTerminal,
		TokenHash: auth.TokenHash("term-token-2"), ExpiresAt: future, TargetID: &env.target.ID}); err != nil {
		t.Fatal(err)
	}
	perms, err = px.authenticate(plain, []byte("term-token-2"))
	if err != nil {
		t.Fatalf("loopback with a plain client version still authenticates: %v", err)
	}
	if perms.Extensions["terminal_remote"] != "" {
		t.Errorf("a non-terminal client version must not set a remote, got %q", perms.Extensions["terminal_remote"])
	}
}

// TestAdmitTerminalTokenBoundToTarget proves the admission gate refuses a
// terminal token presented for any target but the one it was minted for, at
// its own gate — a token replayed against a second target opens nothing.
func TestAdmitTerminalTokenBoundToTarget(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	other := &store.Target{Name: "other-01", Host: "127.0.0.1", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := env.st.CreateTarget(ctx, other); err != nil {
		t.Fatal(err)
	}
	p := gatesUser("alice")
	p.TerminalOnly, p.TerminalTarget = true, other.ID // minted for other-01
	req := baseReq(p)
	req.serving = auth.ScopeTerminal
	res := env.g.admit(ctx, req) // ...presented for env.target
	if res.outcome != admitDenied || res.gate != gateTerminalTarget {
		t.Fatalf("outcome %d gate %d, want denied at gateTerminalTarget", res.outcome, res.gate)
	}
	// Bound to THIS target, and served as the terminal: admitted.
	p.TerminalTarget = env.target.ID
	req = baseReq(p)
	req.serving = auth.ScopeTerminal
	if res := env.g.admit(ctx, req); res.outcome != admitOK {
		t.Fatalf("outcome %d gate %d, want admitOK for the bound target", res.outcome, res.gate)
	}
	// Not served as the terminal (a door that does not declare it): refused
	// at the scope gates, before any target is even resolved.
	req = baseReq(p)
	if res := env.g.admit(ctx, req); res.outcome != admitDenied || res.gate == gateTerminalTarget || res.gate == gateNone {
		t.Fatalf("outcome %d gate %d, want refused at the scope gates", res.outcome, res.gate)
	}
}
