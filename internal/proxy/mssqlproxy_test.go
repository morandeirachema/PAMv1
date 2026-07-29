package proxy_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/cmdguard"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/tds"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// fakeMSSQL is a minimal in-process SQL Server that accepts ONLY wantPass. It
// records the credentials and the login fields it was handed plus the requests
// it received, and answers each one with a bare DONE. It stands in for a real
// SQL Server, so a passing test proves the proxy authenticated the upstream
// with the vaulted secret — never the operator's PAM key.
type fakeMSSQL struct {
	addr string

	mu       sync.Mutex
	user     string
	pass     string
	login    *tds.Login7
	requests []string
	reached  int
}

// startFakeMSSQL launches the fake upstream on an ephemeral port.
func startFakeMSSQL(t *testing.T, wantPass string) *fakeMSSQL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeMSSQL{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn, wantPass)
		}
	}()
	return f
}

// serve handles one upstream connection: PRELOGIN (declining encryption, which
// keeps the fixture free of certificate plumbing), LOGIN7 accepting only
// wantPass, then a request loop answering each with DONE.
func (f *fakeMSSQL) serve(conn net.Conn, wantPass string) {
	defer conn.Close()
	c := tds.NewConn(conn)

	typ, _, _, err := c.ReadMessage(1 << 20)
	if err != nil || typ != tds.PacketPreLogin {
		return
	}
	resp := tds.NewPreLogin()
	resp.Set(tds.PreLoginVersion, []byte{16, 0, 0, 0, 0, 0})
	resp.Set(tds.PreLoginEncryption, []byte{tds.EncryptNotSup})
	if err := c.WriteMessage(tds.PacketPreLogin, 0, resp.Encode()); err != nil {
		return
	}

	typ, _, payload, err := c.ReadMessage(1 << 20)
	if err != nil || typ != tds.PacketLogin7 {
		return
	}
	login, err := tds.ParseLogin7(payload)
	if err != nil {
		return
	}
	f.mu.Lock()
	f.user, f.pass, f.login = login.UserName, login.Password, login
	f.reached++
	f.mu.Unlock()

	if login.Password != wantPass {
		// Exactly what a real server sends for a bad login.
		_ = c.WriteMessage(tds.PacketTabularResult, 0,
			tds.Refusal(18456, 14, "Login failed for user.", tds.PacketLogin7, true))
		return
	}
	ack := []byte{tds.TokenLoginAck, 0x04, 0x00, 1, 2, 3, 4}
	ack = append(ack, tds.DoneToken{Token: tds.TokenDone}.Encode(true)...)
	if err := c.WriteMessage(tds.PacketTabularResult, 0, ack); err != nil {
		return
	}

	for {
		typ, _, data, err := c.ReadMessage(1 << 20)
		if err != nil {
			return
		}
		var req tds.Request
		switch typ {
		case tds.PacketSQLBatch:
			req, _ = tds.ParseSQLBatch(data)
		case tds.PacketRPC:
			req, _ = tds.ParseRPC(data)
		default:
			continue
		}
		f.mu.Lock()
		f.requests = append(f.requests, req.AuditText)
		f.mu.Unlock()
		if err := c.WriteMessage(tds.PacketTabularResult, 0, tds.DoneToken{Token: tds.TokenDone}.Encode(true)); err != nil {
			return
		}
	}
}

// password reports the password the upstream was handed ("" if never reached).
func (f *fakeMSSQL) password() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pass
}

// username reports the username the upstream was handed.
func (f *fakeMSSQL) username() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.user
}

// gotRequests returns the requests the upstream actually executed.
func (f *fakeMSSQL) gotRequests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

// loginFields returns the LOGIN7 the upstream received.
func (f *fakeMSSQL) loginFields() *tds.Login7 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.login
}

// mssqlClient is a minimal TDS client: PRELOGIN, LOGIN7 with the operator's PAM
// key, then batches and RPCs. It is deliberately hand-rolled rather than a
// driver, so the tests depend on no new module.
type mssqlClient struct {
	conn net.Conn
	c    *tds.Conn
}

// dialMSSQLProxy connects to the proxy and completes the handshake, returning
// the client and the last login response body.
func dialMSSQLProxy(t *testing.T, addr, login, password, database string) (*mssqlClient, []byte, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, nil, err
	}
	t.Cleanup(func() { conn.Close() })
	c := tds.NewConn(conn)

	pre := tds.NewPreLogin()
	pre.Set(tds.PreLoginVersion, []byte{16, 0, 0, 0, 0, 0})
	pre.Set(tds.PreLoginEncryption, []byte{tds.EncryptNotSup})
	if err := c.WriteMessage(tds.PacketPreLogin, 0, pre.Encode()); err != nil {
		return nil, nil, err
	}
	if _, _, _, err := c.ReadMessage(1 << 20); err != nil {
		return nil, nil, err
	}

	l := &tds.Login7{
		TDSVersion: tds.VersionTDS74, PacketSize: 4096,
		UserName: login, Password: password, Database: database,
		HostName: "workstation", AppName: "pamv1-test", CltIntName: "ODBC", Language: "us_english",
	}
	if err := c.WriteMessage(tds.PacketLogin7, 0, l.Encode()); err != nil {
		return nil, nil, err
	}
	_, _, resp, err := c.ReadMessage(1 << 20)
	if err != nil {
		return nil, nil, err
	}
	if res := tds.WalkLoginResponse(resp, true); !res.OK {
		return nil, resp, errors.New("login refused: " + res.ServerError)
	}
	return &mssqlClient{conn: conn, c: c}, resp, nil
}

// batch sends a SQLBatch and reads one response message.
func (m *mssqlClient) batch(sql string) ([]byte, error) {
	body := allHeadersBlock()
	body = append(body, ucs2(sql)...)
	if err := m.c.WriteMessage(tds.PacketSQLBatch, 0, body); err != nil {
		return nil, err
	}
	_, _, resp, err := m.c.ReadMessage(1 << 20)
	return resp, err
}

// rpcExecuteSQL sends sp_executesql carrying sql as its first parameter — the
// shape every parameterised driver uses.
func (m *mssqlClient) rpcExecuteSQL(sql string) ([]byte, error) {
	body := allHeadersBlock()
	body = append(body, 0xff, 0xff, byte(tds.ProcExecuteSQL), 0x00, 0x00, 0x00)
	param := []byte{0x05}
	param = append(param, ucs2("@stmt")...)
	param = append(param, 0x00, 0xE7, 0x40, 0x1f, 0x09, 0x04, 0xd0, 0x00, 0x34)
	v := ucs2(sql)
	param = append(param, byte(len(v)&0xff), byte(len(v)>>8))
	param = append(param, v...)
	body = append(body, param...)
	if err := m.c.WriteMessage(tds.PacketRPC, 0, body); err != nil {
		return nil, err
	}
	_, _, resp, err := m.c.ReadMessage(1 << 20)
	return resp, err
}

// allHeadersBlock builds the 22-byte ALL_HEADERS prefix.
func allHeadersBlock() []byte {
	b := make([]byte, 22)
	b[0] = 22
	b[4] = 18
	b[8] = 2
	b[18] = 1
	return b
}

// ucs2 encodes s as UTF-16LE for the hand-built requests.
func ucs2(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// respHasError reports whether a relayed response carries an ERROR token, and
// returns its message.
func respHasError(b []byte) (string, bool) {
	if len(b) == 0 || b[0] != tds.TokenError {
		return "", false
	}
	if len(b) < 11 {
		return "", true
	}
	n := int(b[9]) | int(b[10])<<8
	if 11+n*2 > len(b) {
		return "", true
	}
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteRune(rune(int(b[11+i*2]) | int(b[12+i*2])<<8))
	}
	return sb.String(), true
}

// serveMSSQLProxy runs the proxy on an ephemeral port for the test's lifetime.
func serveMSSQLProxy(t *testing.T, mx *proxy.MSSQLProxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = mx.Serve(ctx, ln)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ln.Addr().String()
}

// seedMSSQLTarget creates a "sql-01" mssql target pointing at addr, plus a
// vaulted password credential (sql_svc / upstreamSecret).
func seedMSSQLTarget(t *testing.T, st store.Store, v *vault.Vault, addr string) {
	t.Helper()
	ctx := context.Background()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	target := &store.Target{Name: "sql-01", Host: host, Port: port, OSType: "windows", Protocol: "mssql"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	cred := &store.Credential{TargetID: target.ID, Username: "sql_svc", SecretType: "password"}
	if err := st.CreateCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	enc, err := v.Encrypt(ctx, upstreamSecret, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateCredentialSecretEnc(ctx, cred.ID, enc); err != nil {
		t.Fatal(err)
	}
}

// newMSSQLProxy builds a proxy over st/v with cfg's zero values filled in.
func newMSSQLProxy(t *testing.T, st store.Store, v *vault.Vault, cfg proxy.MSSQLConfig) *proxy.MSSQLProxy {
	t.Helper()
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RecordingDir == "" {
		cfg.RecordingDir = t.TempDir()
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	mx, err := proxy.NewMSSQL(st, v, resolver, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return mx
}

// TestMSSQLProxyJITInjection is the phase's central claim: the operator
// authenticates with their PAM key, yet the upstream — which accepts ONLY the
// vaulted secret — runs the statement. A pass proves the operator never held
// the database password, and that the statement was audited.
func TestMSSQLProxyJITInjection(t *testing.T) {
	st, v := memstore.New(), mustVault(t)
	fake := startFakeMSSQL(t, upstreamSecret)
	seedMSSQLTarget(t, st, v, fake.addr)
	addr := serveMSSQLProxy(t, newMSSQLProxy(t, st, v, proxy.MSSQLConfig{}))

	cli, _, err := dialMSSQLProxy(t, addr, "sql_svc@sql-01", proxyAPIKey, "orders")
	if err != nil {
		t.Fatalf("login through the proxy: %v", err)
	}
	if _, err := cli.batch("SELECT 1"); err != nil {
		t.Fatalf("batch: %v", err)
	}

	if got := fake.password(); got != upstreamSecret {
		t.Fatalf("upstream got password %q, want the vaulted %q", got, upstreamSecret)
	}
	if got := fake.username(); got != "sql_svc" {
		t.Fatalf("upstream got username %q, want sql_svc", got)
	}
	if reqs := fake.gotRequests(); len(reqs) != 1 || reqs[0] != "SELECT 1" {
		t.Fatalf("upstream requests = %v", reqs)
	}

	events, err := st.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var sawStart, sawQuery bool
	for _, e := range events {
		if e.Action == "db.session.start" && strings.Contains(e.Detail, "via:mssql") {
			sawStart = true
		}
		if e.Action == "db.query" && strings.Contains(e.Detail, "SELECT 1") && strings.Contains(e.Detail, "via:mssql") {
			sawQuery = true
		}
	}
	if !sawStart || !sawQuery {
		t.Fatalf("audit missing session start (%v) or query (%v)", sawStart, sawQuery)
	}
}

// TestMSSQLProxyWrongKeyRejected proves a bad PAM key is refused BEFORE the
// upstream is contacted — so a failed authentication never causes the vaulted
// secret to be decrypted or a connection to the database to be made.
func TestMSSQLProxyWrongKeyRejected(t *testing.T) {
	st, v := memstore.New(), mustVault(t)
	fake := startFakeMSSQL(t, upstreamSecret)
	seedMSSQLTarget(t, st, v, fake.addr)
	addr := serveMSSQLProxy(t, newMSSQLProxy(t, st, v, proxy.MSSQLConfig{}))

	if _, _, err := dialMSSQLProxy(t, addr, "sql_svc@sql-01", "not-the-pam-key", "orders"); err == nil {
		t.Fatal("a wrong PAM key was accepted")
	}
	if got := fake.password(); got != "" {
		t.Fatalf("the upstream was contacted despite a failed login (password %q)", got)
	}
}

// TestMSSQLProxyKeepsClientLoginFields proves the LOGIN7 rewrite replaces the
// credentials and nothing else: the client's own hostname, application name,
// database and language reach the server, so it behaves as it would without a
// broker in between.
func TestMSSQLProxyKeepsClientLoginFields(t *testing.T) {
	st, v := memstore.New(), mustVault(t)
	fake := startFakeMSSQL(t, upstreamSecret)
	seedMSSQLTarget(t, st, v, fake.addr)
	addr := serveMSSQLProxy(t, newMSSQLProxy(t, st, v, proxy.MSSQLConfig{}))

	if _, _, err := dialMSSQLProxy(t, addr, "sql_svc@sql-01", proxyAPIKey, "orders"); err != nil {
		t.Fatalf("login: %v", err)
	}
	l := fake.loginFields()
	if l == nil {
		t.Fatal("the upstream never received a login")
	}
	if l.HostName != "workstation" || l.AppName != "pamv1-test" || l.Database != "orders" || l.Language != "us_english" {
		t.Fatalf("client login fields were not forwarded: %+v", l)
	}
	if l.IntegratedSecurity() {
		t.Fatal("fIntSecurity reached the upstream login")
	}
}

// TestMSSQLProxyCommandBlocked proves command control reaches the TDS path: a
// denied statement is refused with an error token, never reaches the upstream,
// is audited — and the SESSION SURVIVES, so the next statement still runs.
func TestMSSQLProxyCommandBlocked(t *testing.T) {
	st, v := memstore.New(), mustVault(t)
	fake := startFakeMSSQL(t, upstreamSecret)
	seedMSSQLTarget(t, st, v, fake.addr)
	guard, err := cmdguard.New([]string{`(?i)drop\s+table`})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveMSSQLProxy(t, newMSSQLProxy(t, st, v, proxy.MSSQLConfig{CommandGuard: guard}))

	cli, _, err := dialMSSQLProxy(t, addr, "sql_svc@sql-01", proxyAPIKey, "orders")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp, err := cli.batch("DROP TABLE accounts")
	if err != nil {
		t.Fatalf("blocked batch: %v", err)
	}
	if msg, isErr := respHasError(resp); !isErr || !strings.Contains(msg, "blocked by policy") {
		t.Fatalf("blocked statement response = %q (error=%v)", msg, isErr)
	}
	// The session stays usable.
	if _, err := cli.batch("SELECT 1"); err != nil {
		t.Fatalf("the session did not survive a refusal: %v", err)
	}
	reqs := fake.gotRequests()
	for _, r := range reqs {
		if strings.Contains(r, "DROP TABLE") {
			t.Fatalf("a blocked statement reached the upstream: %v", reqs)
		}
	}
	if len(reqs) != 1 || reqs[0] != "SELECT 1" {
		t.Fatalf("upstream requests = %v, want only the allowed one", reqs)
	}

	events, _ := st.ListAudit(context.Background(), 100)
	blocked := false
	for _, e := range events {
		if e.Action == "command.blocked" && strings.Contains(e.Detail, "via:mssql") {
			blocked = true
		}
	}
	if !blocked {
		t.Fatal("no command.blocked audit event for the refused statement")
	}
}

// TestMSSQLProxyBlockedRPC proves the guard sees through sp_executesql — the
// shape every parameterised driver sends. A proc-name-only implementation
// would pass every other test in this file and fail this one, letting a denied
// statement through as an RPC parameter.
func TestMSSQLProxyBlockedRPC(t *testing.T) {
	st, v := memstore.New(), mustVault(t)
	fake := startFakeMSSQL(t, upstreamSecret)
	seedMSSQLTarget(t, st, v, fake.addr)
	guard, err := cmdguard.New([]string{`(?i)drop\s+table`})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveMSSQLProxy(t, newMSSQLProxy(t, st, v, proxy.MSSQLConfig{CommandGuard: guard}))

	cli, _, err := dialMSSQLProxy(t, addr, "sql_svc@sql-01", proxyAPIKey, "orders")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp, err := cli.rpcExecuteSQL("DROP TABLE payments")
	if err != nil {
		t.Fatalf("blocked rpc: %v", err)
	}
	if msg, isErr := respHasError(resp); !isErr || !strings.Contains(msg, "blocked by policy") {
		t.Fatalf("blocked RPC response = %q (error=%v)", msg, isErr)
	}
	for _, r := range fake.gotRequests() {
		if strings.Contains(r, "DROP TABLE") {
			t.Fatal("a blocked statement reached the upstream through sp_executesql")
		}
	}

	// An allowed RPC still runs, and its SQL — not just the proc name — is audited.
	if _, err := cli.rpcExecuteSQL("SELECT name FROM sys.tables"); err != nil {
		t.Fatalf("allowed rpc: %v", err)
	}
	events, _ := st.ListAudit(context.Background(), 100)
	sawSQL := false
	for _, e := range events {
		if e.Action == "db.query" && strings.Contains(e.Detail, "sys.tables") {
			sawSQL = true
		}
	}
	if !sawSQL {
		t.Fatal("an RPC's SQL text was not audited (only the procedure name would be a fig leaf)")
	}
}

// TestMSSQLProxyRecordsSession proves the session is recorded and the artifact's
// hash is written to the audit trail, like every other brokered session.
func TestMSSQLProxyRecordsSession(t *testing.T) {
	st, v := memstore.New(), mustVault(t)
	fake := startFakeMSSQL(t, upstreamSecret)
	seedMSSQLTarget(t, st, v, fake.addr)
	dir := t.TempDir()
	addr := serveMSSQLProxy(t, newMSSQLProxy(t, st, v, proxy.MSSQLConfig{RecordingDir: dir}))

	cli, _, err := dialMSSQLProxy(t, addr, "sql_svc@sql-01", proxyAPIKey, "orders")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := cli.batch("SELECT 42"); err != nil {
		t.Fatal(err)
	}
	cli.conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		events, _ := st.ListAudit(context.Background(), 100)
		for _, e := range events {
			if e.Action == "session.record" && strings.Contains(e.Detail, "proto:mssql") && strings.Contains(e.Detail, "sha256:") {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no session.record audit event with a hash for the mssql session")
}

// TestMSSQLProxyRequireRecordingRefuses proves PAM_REQUIRE_RECORDING covers
// this path: with recording impossible, the session is refused rather than run
// unrecorded.
func TestMSSQLProxyRequireRecordingRefuses(t *testing.T) {
	st, v := memstore.New(), mustVault(t)
	fake := startFakeMSSQL(t, upstreamSecret)
	seedMSSQLTarget(t, st, v, fake.addr)
	// A recording directory that genuinely cannot be created: a path UNDER a
	// regular file, so MkdirAll fails with ENOTDIR.
	blocker := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(blocker, "recordings")
	addr := serveMSSQLProxy(t, newMSSQLProxy(t, st, v, proxy.MSSQLConfig{
		RecordingDir: bad, RequireRecording: true,
	}))

	cli, _, err := dialMSSQLProxy(t, addr, "sql_svc@sql-01", proxyAPIKey, "orders")
	if err == nil {
		// The upstream login has already happened by the time the recording is
		// set up, so the refusal arrives as an error token on the next read
		// rather than as a transport failure. What must hold is the security
		// property: no statement is ever executed on the target.
		resp, berr := cli.batch("SELECT 1")
		if berr == nil {
			if msg, isErr := respHasError(resp); !isErr || !strings.Contains(msg, "recording") {
				t.Fatalf("an unrecordable session answered %q instead of refusing", msg)
			}
		}
	}
	if reqs := fake.gotRequests(); len(reqs) != 0 {
		t.Fatalf("an unrecordable session ran %v on the target", reqs)
	}
	events, _ := st.ListAudit(context.Background(), 100)
	sawFail := false
	for _, e := range events {
		if e.Action == "session.record_failed" && strings.Contains(e.Detail, "proto:mssql") {
			sawFail = true
		}
	}
	if !sawFail {
		t.Fatal("the recording failure was not audited")
	}
}

// TestMSSQLProxyLiveMonitor proves a supervisor can watch a SQL Server session
// as it happens, exactly as for SSH and PostgreSQL.
func TestMSSQLProxyLiveMonitor(t *testing.T) {
	st, v := memstore.New(), mustVault(t)
	fake := startFakeMSSQL(t, upstreamSecret)
	seedMSSQLTarget(t, st, v, fake.addr)
	reg, hub := session.NewRegistry(), session.NewHub()
	reg.AttachHub(hub)
	addr := serveMSSQLProxy(t, newMSSQLProxy(t, st, v, proxy.MSSQLConfig{Sessions: reg, Live: hub}))

	cli, _, err := dialMSSQLProxy(t, addr, "sql_svc@sql-01", proxyAPIKey, "orders")
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	var sid string
	for i := 0; i < 200 && sid == ""; i++ {
		if ls := reg.List(); len(ls) > 0 {
			if ls[0].Protocol != "mssql" {
				t.Fatalf("registered protocol = %q, want mssql", ls[0].Protocol)
			}
			sid = ls[0].ID
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if sid == "" {
		t.Fatal("the mssql session was not registered")
	}
	frames, cancel := hub.Subscribe(sid)
	defer cancel()

	if _, err := cli.batch("SELECT watched"); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(3 * time.Second)
	for {
		select {
		case b, open := <-frames:
			if !open {
				t.Fatal("the session ended before its statement streamed")
			}
			if strings.Contains(string(b), "SELECT watched") {
				return
			}
		case <-deadline:
			t.Fatal("the statement never reached the live hub")
		}
	}
}

// TestMSSQLProxySessionKill proves a live SQL Server session is killable from
// the registry, like every other brokered session.
func TestMSSQLProxySessionKill(t *testing.T) {
	st, v := memstore.New(), mustVault(t)
	fake := startFakeMSSQL(t, upstreamSecret)
	seedMSSQLTarget(t, st, v, fake.addr)
	reg := session.NewRegistry()
	addr := serveMSSQLProxy(t, newMSSQLProxy(t, st, v, proxy.MSSQLConfig{Sessions: reg}))

	cli, _, err := dialMSSQLProxy(t, addr, "sql_svc@sql-01", proxyAPIKey, "orders")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	var sid string
	for i := 0; i < 200 && sid == ""; i++ {
		if ls := reg.List(); len(ls) > 0 {
			sid = ls[0].ID
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if sid == "" {
		t.Fatal("session not registered")
	}
	if !reg.Kill(sid) {
		t.Fatal("Kill reported no such session")
	}
	_ = cli.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := cli.batch("SELECT 1"); err == nil {
		t.Fatal("the session survived a kill")
	}
}

// TestMSSQLProxyNonMSSQLTargetDenied proves a target of another protocol cannot
// be reached through this listener — the gate is checked before any decrypt.
func TestMSSQLProxyNonMSSQLTargetDenied(t *testing.T) {
	st, v := memstore.New(), mustVault(t)
	fake := startFakeMSSQL(t, upstreamSecret)
	seedMSSQLTarget(t, st, v, fake.addr)
	// Re-label the seeded target as postgres.
	ctx := context.Background()
	tg, err := st.GetTarget(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	tg.Protocol = "postgres"
	if err := st.UpdateTarget(ctx, tg); err != nil {
		t.Fatal(err)
	}
	addr := serveMSSQLProxy(t, newMSSQLProxy(t, st, v, proxy.MSSQLConfig{}))

	if _, _, err := dialMSSQLProxy(t, addr, "sql_svc@sql-01", proxyAPIKey, "orders"); err == nil {
		t.Fatal("a postgres target was reachable through the mssql listener")
	}
	if fake.password() != "" {
		t.Fatal("the upstream was contacted for a wrong-protocol target")
	}
}

// TestMSSQLProxyIntegratedAuthRefused proves a Windows/SSPI login gets a clear
// refusal rather than a corrupted upstream login.
func TestMSSQLProxyIntegratedAuthRefused(t *testing.T) {
	st, v := memstore.New(), mustVault(t)
	fake := startFakeMSSQL(t, upstreamSecret)
	seedMSSQLTarget(t, st, v, fake.addr)
	addr := serveMSSQLProxy(t, newMSSQLProxy(t, st, v, proxy.MSSQLConfig{}))

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := tds.NewConn(conn)
	pre := tds.NewPreLogin()
	pre.Set(tds.PreLoginEncryption, []byte{tds.EncryptNotSup})
	if err := c.WriteMessage(tds.PacketPreLogin, 0, pre.Encode()); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := c.ReadMessage(1 << 20); err != nil {
		t.Fatal(err)
	}
	l := &tds.Login7{TDSVersion: tds.VersionTDS74, PacketSize: 4096, OptionFlags2: 0x80}
	if err := c.WriteMessage(tds.PacketLogin7, 0, l.Encode()); err != nil {
		t.Fatal(err)
	}
	_, _, resp, err := c.ReadMessage(1 << 20)
	if err != nil {
		t.Fatalf("no refusal was sent: %v", err)
	}
	msg, isErr := respHasError(resp)
	if !isErr || !strings.Contains(msg, "SQL authentication") {
		t.Fatalf("integrated auth refusal = %q (error=%v)", msg, isErr)
	}
	if fake.password() != "" {
		t.Fatal("the upstream was contacted for an integrated-auth login")
	}
}

// TestMSSQLProxyLargeStatementSpansPackets proves a statement larger than one
// TDS packet is reassembled, audited whole and forwarded intact — the
// multi-packet path ordinary tests never reach.
func TestMSSQLProxyLargeStatementSpansPackets(t *testing.T) {
	st, v := memstore.New(), mustVault(t)
	fake := startFakeMSSQL(t, upstreamSecret)
	seedMSSQLTarget(t, st, v, fake.addr)
	addr := serveMSSQLProxy(t, newMSSQLProxy(t, st, v, proxy.MSSQLConfig{}))

	cli, _, err := dialMSSQLProxy(t, addr, "sql_svc@sql-01", proxyAPIKey, "orders")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	// 4096-byte packets: this statement needs several.
	long := "SELECT '" + strings.Repeat("x", 12000) + "'"
	if _, err := cli.batch(long); err != nil {
		t.Fatalf("large batch: %v", err)
	}
	reqs := fake.gotRequests()
	if len(reqs) != 1 || reqs[0] != long {
		got := ""
		if len(reqs) > 0 {
			got = reqs[0][:min(60, len(reqs[0]))] + "..."
		}
		t.Fatalf("the upstream received %d requests, first %q — reassembly or re-framing is wrong", len(reqs), got)
	}
}

// TestMSSQLProxyEnrollOnlyRejected proves a principal with MFA enrollment
// pending cannot open a session through this listener either.
func TestMSSQLProxyEnrollOnlyRejected(t *testing.T) {
	st, v := memstore.New(), mustVault(t)
	fake := startFakeMSSQL(t, upstreamSecret)
	seedMSSQLTarget(t, st, v, fake.addr)

	// An enrollment-only login session for a connect-capable user: MFA setup is
	// pending, so the principal may not open sessions on any listener.
	const enrollToken = "enroll-session-token-mssql"
	sum := sha256.Sum256([]byte(enrollToken))
	if err := st.CreateSession(context.Background(), &store.Session{
		Username: "alice", Role: "user", Scope: auth.SessionScopeEnroll,
		TokenHash: hex.EncodeToString(sum[:]), ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	addr := serveMSSQLProxy(t, newMSSQLProxy(t, st, v, proxy.MSSQLConfig{}))

	if _, _, err := dialMSSQLProxy(t, addr, "sql_svc@sql-01", enrollToken, "orders"); err == nil {
		t.Fatal("an enrollment-only principal opened a session")
	}
	if fake.password() != "" {
		t.Fatal("the upstream was contacted for an enrollment-only principal")
	}
}
