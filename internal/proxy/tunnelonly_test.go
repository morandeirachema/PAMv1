package proxy_test

// A tunnel-scoped token (auth.SessionScopeRDP / SessionScopeVNC) exists so the
// in-portal graphical viewers can authenticate a WebSocket, which browsers cannot
// give a header. It therefore travels in a URL and lands in reverse-proxy and
// access logs, and the whole point of auth.Principal.TunnelOnly is that such a
// copy is useless anywhere else.
//
// It was enforced only in the HTTP middleware. The three session proxies resolve
// the SAME token through the SAME resolver and never checked the flag, so a
// 60-second viewer token — which carries no target binding — could be pasted as
// the SSH/PostgreSQL/SQL Server password to open a full privileged session on ANY
// target its owner may reach, for as long as that session lived. These tests pin
// the refusal on all three, and prove the upstream is never dialled.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// seedViewerToken creates a live login session with a viewer (tunnel-only) scope
// for a connect-capable user, and returns the bearer token.
func seedViewerToken(t *testing.T, st store.Store, scope string) string {
	t.Helper()
	token := "viewer-token-" + scope + "-7f3a91"
	sum := sha256.Sum256([]byte(token))
	if err := st.CreateSession(context.Background(), &store.Session{
		Username: "alice", Role: "user", Scope: scope,
		TokenHash: hex.EncodeToString(sum[:]), ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	return token
}

// hasAuditReason reports whether any audit event's detail mentions reason.
func hasAuditReason(t *testing.T, st store.Store, action, reason string) bool {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == action && strings.Contains(e.Detail, reason) {
			return true
		}
	}
	return false
}

// TestSSHProxyRefusesTunnelOnlyToken proves an RDP viewer token cannot open an
// SSH session, and that the refusal is audited.
//
// The target is seeded and a real upstream sshd is running, so the ONLY reason the
// connection can fail is the token's scope — and because the refusal happens in
// the password callback, the upstream is never dialled at all.
func TestSSHProxyRefusesTunnelOnlyToken(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	host, port := startUpstream(t, "root", upstreamSecret, "")
	seedTarget(t, st, v, host, port)

	token := seedViewerToken(t, st, auth.SessionScopeRDP)
	addr := startProxy(t, st, v, t.TempDir())

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "root@web-01",
		Auth:            []ssh.AuthMethod{ssh.Password(token)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		client.Close()
		t.Fatal("a tunnel-only viewer token opened an SSH session")
	}
	if !hasAuditReason(t, st, "session.denied", "reason:tunnel-only-token") {
		t.Fatal("the refusal was not audited as session.denied … reason:tunnel-only-token")
	}
}

// TestDBProxyRefusesTunnelOnlyToken proves the same for the PostgreSQL proxy,
// using a VNC-scoped token so both viewer scopes are covered across the suite.
func TestDBProxyRefusesTunnelOnlyToken(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	fake := startFakePostgres(t, upstreamSecret)
	seedPGTarget(t, st, v, fake.addr)

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	token := seedViewerToken(t, st, auth.SessionScopeVNC)

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
	_ = fe.Flush()
	if _, err := fe.Receive(); err != nil { // cleartext password request
		t.Fatal(err)
	}
	fe.Send(&pgproto3.PasswordMessage{Password: token})
	_ = fe.Flush()

	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("expected an ErrorResponse, got transport error: %v", err)
	}
	if _, ok := msg.(*pgproto3.ErrorResponse); !ok {
		t.Fatalf("expected ErrorResponse for a tunnel-only token, got %T", msg)
	}
	if fake.password() != "" {
		t.Fatal("the upstream was contacted for a tunnel-only token")
	}
	if !hasAuditReason(t, st, "db.session.denied", "reason:tunnel-only-token") {
		t.Fatal("the refusal was not audited as db.session.denied … reason:tunnel-only-token")
	}
}

// TestDBProxyBreakGlassIsAuditedAndAlerted proves that opening a session with the
// emergency key through a session proxy raises the break-glass signal.
//
// Before this, the proxies consulted principal.BreakGlass only to SKIP the
// four-eyes approval gate. Nothing else happened: no breakglass.access audit
// event, no alert and no metric — so the one path that deliberately bypasses
// approval was also the quietest, while the same key against GET /api/me produced
// all three. The hook stands in for main's wiring to the alerter and the
// Prometheus counter.
func TestDBProxyBreakGlassIsAuditedAndAlerted(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	fake := startFakePostgres(t, upstreamSecret)
	seedPGTarget(t, st, v, fake.addr)

	const emergencyKey = "the-sealed-emergency-key"
	sum := sha256.Sum256([]byte(emergencyKey))
	resolver, err := auth.NewResolver(st, proxyAPIKey, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}

	signalled := make(chan string, 1)
	dbx, err := proxy.NewDB(st, v, resolver, proxy.DBConfig{
		RecordingDir: t.TempDir(),
		DialTimeout:  5 * time.Second,
		OnBreakGlass: func(_ context.Context, actor, detail string) {
			select {
			case signalled <- actor + " " + detail:
			default:
			}
		},
	})
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
	_ = fe.Flush()
	if _, err := fe.Receive(); err != nil {
		t.Fatal(err)
	}
	fe.Send(&pgproto3.PasswordMessage{Password: emergencyKey})
	_ = fe.Flush()

	select {
	case got := <-signalled:
		if !strings.Contains(got, "break-glass") {
			t.Fatalf("break-glass signal names actor %q, want the break-glass principal", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("opening a session with the emergency key raised no break-glass signal")
	}

	// The audit event is the durable half, and it must name the action the SIEM
	// forwarder and the risk engine look for.
	deadline := time.Now().Add(5 * time.Second)
	for !hasAuditReason(t, st, "breakglass.access", "postgres login:") {
		if time.Now().After(deadline) {
			t.Fatal("no breakglass.access audit event for an emergency-key database session")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
