package proxy_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// seedScopedSession stores a session of the given scope for an ADMIN and returns
// its bearer token. Admin on purpose: the audit's exploit needed a role holding
// both CapRevealSecret (to mint an extension token) and CapConnect, and among the
// built-in roles only admin holds both — so this is the realistic victim.
func seedScopedSession(t *testing.T, st store.Store, scope string) string {
	t.Helper()
	token := "scoped-" + scope + "-token-4c1e0b"
	sum := sha256.Sum256([]byte(token))
	if err := st.CreateSession(context.Background(), &store.Session{
		Username: "alice", Role: "admin", Scope: scope,
		TokenHash: hex.EncodeToString(sum[:]), ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	return token
}

// TestSSHProxyRefusesExtensionToken is the regression test for the 2026-08-26
// audit's finding H-1. The browser-extension scope (Phase 147) was documented as
// "refused everywhere except reveal" and was refused by the HTTP middleware — but
// the SSH proxy's admit() checked TunnelOnly, EnrollOnly and MFAPending by hand
// and had never been told about the fourth field. So a token lifted from an
// endpoint's local storage, the exact threat the scope was built for, worked as
// an SSH password for 24 hours. The scope test now has one implementation
// (auth.Principal.MayOpenSession) and this proves the proxy uses it.
func TestSSHProxyRefusesExtensionToken(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	host, port := startUpstream(t, "root", upstreamSecret, "")
	seedTarget(t, st, v, host, port)
	token := seedScopedSession(t, st, auth.SessionScopeExtension)
	addr := startProxy(t, st, v, t.TempDir())

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "root@web-01",
		Auth:            []ssh.AuthMethod{ssh.Password(token)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		client.Close()
		t.Fatal("a browser-extension token opened an SSH session")
	}
	if !hasAuditReason(t, st, "session.denied", "reason:extension-scoped-token") {
		t.Fatal("the refusal was not audited as session.denied … reason:extension-scoped-token")
	}
}

// TestDBProxyRefusesExtensionToken proves the same for the PostgreSQL proxy,
// which resolves its own principal and reaches admit() by a different path.
func TestDBProxyRefusesExtensionToken(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	fake := startFakePostgres(t, upstreamSecret)
	seedPGTarget(t, st, v, fake.addr)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	token := seedScopedSession(t, st, auth.SessionScopeExtension)
	dbx, err := proxy.NewDB(st, v, resolver, proxy.DBConfig{RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveDBProxy(t, dbx)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "dbuser@pg-01", "database": "appdb"},
	})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := fe.Receive(); err != nil {
		t.Fatal(err)
	}
	fe.Send(&pgproto3.PasswordMessage{Password: token})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	msg, err := fe.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if _, refused := msg.(*pgproto3.ErrorResponse); !refused {
		t.Fatalf("a browser-extension token was admitted to the DB proxy; first reply was %T", msg)
	}
	if !hasAuditReason(t, st, "db.session.denied", "reason:extension-scoped-token") {
		t.Fatal("the refusal was not audited as db.session.denied … reason:extension-scoped-token")
	}
}

// TestMayOpenSessionEnumeratesEveryScope is the structural half: the predicate
// must refuse EVERY narrow scope for a proxy, and exactly one for the tunnel.
// A table over the scopes, rather than a sample, so a scope added to Principal
// without being added to NarrowScope shows up as a ScopeNone that opens sessions.
func TestMayOpenSessionEnumeratesEveryScope(t *testing.T) {
	for _, tc := range []struct {
		name      string
		p         auth.Principal
		proxyOK   bool
		tunnelOK  bool
		wantScope auth.SessionScope
	}{
		{"full session", auth.Principal{}, true, true, auth.ScopeNone},
		{"enroll-only", auth.Principal{EnrollOnly: true}, false, false, auth.ScopeEnrollOnly},
		{"mfa-pending", auth.Principal{MFAPending: true}, false, false, auth.ScopeMFAPending},
		{"tunnel-only", auth.Principal{TunnelOnly: true}, false, true, auth.ScopeTunnelOnly},
		{"extension-only", auth.Principal{ExtensionOnly: true}, false, false, auth.ScopeExtensionOnly},
	} {
		if got := tc.p.NarrowScope(); got != tc.wantScope {
			t.Errorf("%s: NarrowScope = %v, want %v", tc.name, got, tc.wantScope)
		}
		if got := tc.p.MayOpenSession(auth.ScopeNone); got != tc.proxyOK {
			t.Errorf("%s: MayOpenSession(proxy) = %v, want %v", tc.name, got, tc.proxyOK)
		}
		if got := tc.p.MayOpenSession(auth.ScopeTunnelOnly); got != tc.tunnelOK {
			t.Errorf("%s: MayOpenSession(tunnel) = %v, want %v", tc.name, got, tc.tunnelOK)
		}
	}
}
