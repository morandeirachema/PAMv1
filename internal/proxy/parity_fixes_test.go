package proxy_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// failingAuditStore wraps a Store and fails AppendAudit for one action name,
// so a test can prove a path fails closed when its audit write cannot land.
type failingAuditStore struct {
	store.Store
	failAction string
}

// AppendAudit refuses the configured action and passes every other one through.
func (f *failingAuditStore) AppendAudit(ctx context.Context, e *store.AuditEvent) error {
	if e.Action == f.failAction {
		return errors.New("audit store down")
	}
	return f.Store.AppendAudit(ctx, e)
}

// TestWinRMRunAuditFailClosed proves the proxy's WinRM command loop withholds
// command output when the winrm.run audit cannot be written — the same
// fail-closed contract the REST WinRM endpoint has always enforced: nobody
// acts on output that the system of record never accounted for. The command
// itself has already run on the target; what fails closed is the evidence
// reaching the operator.
func TestWinRMRunAuditFailClosed(t *testing.T) {
	mem := memstore.New()
	st := &failingAuditStore{Store: mem, failAction: "winrm.run"}
	v := mustVault(t)
	seedWinRMTarget(t, st, v)
	runner := &fakeWinRMRunner{out: "contoso\\Administrator\r\n"}

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		WinRMRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, "win-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}
	io.WriteString(stdin, "whoami\r\nexit\r\n")
	data, _ := io.ReadAll(stdout)
	_ = sess.Wait()

	got := string(data)
	if runner.lastCmd != "whoami" {
		t.Fatalf("winrm ran %q, want whoami", runner.lastCmd)
	}
	if strings.Contains(got, "contoso\\Administrator") {
		t.Fatalf("output delivered despite a failed winrm.run audit: %q", got)
	}
	if !strings.Contains(got, "output withheld") {
		t.Fatalf("operator not told the output was withheld: %q", got)
	}
}

// TestDBProxyDenyBoundsHostileLogin proves an attacker-chosen PostgreSQL
// startup username cannot restructure the audit trail. The startup packet's
// user parameter is arbitrary bytes; every denial row must carry it bounded
// and quoted (auditField), so an embedded newline or a forged `key:value` pair
// survives only as escaped text inside one quoted field — the guarantee the
// SQL Server listener already had, now pinned for its PostgreSQL sibling.
func TestDBProxyDenyBoundsHostileLogin(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	dbx, err := proxy.NewDB(st, v, resolver, proxy.DBConfig{RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveDBProxy(t, dbx)

	// A newline to break the row, a forged pair to invent a field, and 300
	// bytes of padding to bloat it. The target does not exist, so the deny
	// path interpolates this login into db.session.denied.
	hostile := "eve@nosuch\nactor:admin action:break-glass.used " + strings.Repeat("A", 300)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": hostile, "database": "appdb"},
	})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	msg, err := fe.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := msg.(*pgproto3.AuthenticationCleartextPassword); !ok {
		t.Fatalf("expected cleartext-password request, got %T", msg)
	}
	fe.Send(&pgproto3.PasswordMessage{Password: proxyAPIKey})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, ok := (mustReceive(t, fe)).(*pgproto3.ErrorResponse); !ok {
		t.Fatal("hostile login against a missing target should be denied")
	}

	events, err := st.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var denied string
	for _, e := range events {
		// No audit row anywhere may carry the raw newline the client sent.
		if strings.ContainsAny(e.Detail, "\n\r") {
			t.Fatalf("audit detail carries a raw newline: %q", e.Detail)
		}
		if e.Action == "db.session.denied" {
			denied = e.Detail
		}
	}
	if denied == "" {
		t.Fatalf("no db.session.denied audit row: %+v", events)
	}
	// The forged pair survives only inside the quoted login value, never as a
	// free-standing field the trail would read as real.
	if !strings.Contains(denied, "login:") {
		t.Fatalf("db.session.denied row has no bounded login field: %q", denied)
	}
	if strings.Contains(denied, " actor:admin action:break-glass.used") {
		t.Fatalf("forged key:value pair escaped the quoted login field: %q", denied)
	}
}

// mustReceive reads the next backend message, failing the test on a transport
// error. It exists so a test that expects a specific message type can assert on
// the result without repeating the error check.
func mustReceive(t *testing.T, fe *pgproto3.Frontend) pgproto3.BackendMessage {
	t.Helper()
	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("frontend receive: %v", err)
	}
	return msg
}
