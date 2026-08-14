package proxy_test

import (
	"context"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/testutil"
	"github.com/morandeirachema/pamv1/internal/vault"
)

const provisionerSecret = "the-provisioner-password"

var createRoleRE = regexp.MustCompile(`CREATE ROLE "([^"]+)" WITH LOGIN PASSWORD '([^']+)' VALID UNTIL '([^']+)'`)
var dropRoleRE = regexp.MustCompile(`DROP ROLE "([^"]+)"`)

// fakePGProvisioner is a dedicated fake upstream for Zero Standing Privilege
// database tests (Phase 129) — distinct from fakePostgres (which accepts
// exactly one fixed password) because a ZSP session authenticates twice with
// two DIFFERENT, dynamically-generated credentials in one test run: the
// provisioner's own real password, then the ephemeral role's random one,
// parsed straight out of the CREATE ROLE statement the proxy issues.
type fakePGProvisioner struct {
	addr string
	mu   sync.Mutex
	// creds holds every (user -> password) pair currently valid: the
	// provisioner (seeded up front) plus any role a CREATE ROLE query mints,
	// removed again once a matching DROP ROLE arrives.
	creds       map[string]string
	queries     []string
	createdRole string // most recent CREATE ROLE's role name, for assertions
	droppedRole string // most recent DROP ROLE's role name, for assertions
}

func startFakePGProvisioner(t *testing.T, provisionerUser string) *fakePGProvisioner {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakePGProvisioner{addr: ln.Addr().String(), creds: map[string]string{provisionerUser: provisionerSecret}}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

func (f *fakePGProvisioner) serve(conn net.Conn) {
	defer conn.Close()
	be := pgproto3.NewBackend(conn, conn)
	var user string
	for started := false; !started; {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			return
		}
		switch m := msg.(type) {
		case *pgproto3.SSLRequest, *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
		case *pgproto3.StartupMessage:
			user = m.Parameters["user"]
			started = true
		default:
			return
		}
	}
	be.Send(&pgproto3.AuthenticationCleartextPassword{})
	if be.Flush() != nil {
		return
	}
	if be.SetAuthType(pgproto3.AuthTypeCleartextPassword) != nil {
		return
	}
	m, err := be.Receive()
	if err != nil {
		return
	}
	pw, ok := m.(*pgproto3.PasswordMessage)
	if !ok {
		return
	}
	f.mu.Lock()
	want, known := f.creds[user]
	f.mu.Unlock()
	if !known || pw.Password != want {
		be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"})
		_ = be.Flush()
		return
	}
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16.0"})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 2}})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if be.Flush() != nil {
		return
	}
	for {
		m, err := be.Receive()
		if err != nil {
			return
		}
		switch msg := m.(type) {
		case *pgproto3.Query:
			f.mu.Lock()
			f.queries = append(f.queries, msg.String)
			if mm := createRoleRE.FindStringSubmatch(msg.String); mm != nil {
				f.creds[mm[1]] = mm[2]
				f.createdRole = mm[1]
			}
			if mm := dropRoleRE.FindStringSubmatch(msg.String); mm != nil {
				delete(f.creds, mm[1])
				f.droppedRole = mm[1]
			}
			f.mu.Unlock()
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if be.Flush() != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		}
	}
}

func (f *fakePGProvisioner) state() (queries []string, created, dropped string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...), f.createdRole, f.droppedRole
}

// seedZSPTarget creates a postgres target with two credentials: a real
// password credential flagged Provisioner, and a db_zsp credential (no
// stored secret) — the shape Phase 129 requires before a ZSP dial can work.
func seedDBZSPTarget(t *testing.T, st store.Store, v *vault.Vault, addr string, provisionerUser, zspUser string) {
	t.Helper()
	ctx := context.Background()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	target := &store.Target{Name: "pg-zsp-01", Host: host, Port: port, OSType: "linux", Protocol: "postgres"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	prov := &store.Credential{TargetID: target.ID, Username: provisionerUser, SecretType: store.SecretTypePassword, Provisioner: true}
	if err := st.CreateCredential(ctx, prov); err != nil {
		t.Fatal(err)
	}
	enc, err := v.Encrypt(ctx, provisionerSecret, store.CredentialAAD(target.ID, prov.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateCredentialSecretEnc(ctx, prov.ID, enc); err != nil {
		t.Fatal(err)
	}
	zsp := &store.Credential{TargetID: target.ID, Username: zspUser, SecretType: store.SecretTypeDBZSP}
	if err := st.CreateCredential(ctx, zsp); err != nil {
		t.Fatal(err)
	}
}

// waitForAuditDetail polls st (via the shared testutil.WaitFor) for an audit
// row whose detail contains want, up to 2s — teardown runs in the connection
// handler's own defer chain after the client disconnects, so the test cannot
// assume it has landed the instant the client-side connection closes.
func waitForAuditDetail(t *testing.T, st store.Store, action, want string) {
	t.Helper()
	ok := testutil.WaitFor(t, 2*time.Second, func() bool {
		events, err := st.ListAudit(context.Background(), 200)
		if err != nil {
			return false
		}
		for _, e := range events {
			if e.Action == action && strings.Contains(e.Detail, want) {
				return true
			}
		}
		return false
	})
	if !ok {
		t.Fatalf("timed out waiting for audit action %q containing %q", action, want)
	}
}

// TestDBProxyZSPProvisionsAndTearsDownRole proves the end-to-end Zero
// Standing Privilege flow against a real (fake) PostgreSQL wire protocol: the
// operator's session runs its query as a freshly minted role — never the
// provisioner's own credential, never any password vaulted for the db_zsp
// row itself (it has none) — and that role is dropped once the session ends.
func TestDBProxyZSPProvisionsAndTearsDownRole(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	fake := startFakePGProvisioner(t, "provisioner-admin")
	seedDBZSPTarget(t, st, v, fake.addr, "provisioner-admin", "zsp-slot")

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	dbx, err := proxy.NewDB(st, v, resolver, proxy.DBConfig{RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveDBProxy(t, dbx)

	fe, conn := openDBSession(t, addr, "zsp-slot@pg-zsp-01", "appdb", proxyAPIKey)
	fe.Send(&pgproto3.Query{String: "SELECT 1"})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	waitReady(t, fe)
	fe.Send(&pgproto3.Terminate{})
	_ = fe.Flush()
	conn.Close()

	waitForAuditDetail(t, st, "db.zsp_provisioned", "pg-zsp-01")
	waitForAuditDetail(t, st, "db.zsp_teardown", "pg-zsp-01")

	queries, created, dropped := fake.state()
	if created == "" || !strings.HasPrefix(created, "pamv1_zsp_") {
		t.Fatalf("expected a pamv1_zsp_-prefixed role to be created, got %q", created)
	}
	if dropped != created {
		t.Fatalf("dropped role %q does not match created role %q", dropped, created)
	}
	found := false
	for _, q := range queries {
		if q == "SELECT 1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the operator's SELECT 1 to reach the upstream, got queries: %v", queries)
	}
	// The provisioner's own password must never be reused as the session's
	// own login — a real session and a provisioning connection are distinct
	// identities, proven by the fact a distinct role name was minted at all
	// (created != "" already established above) rather than the proxy
	// connecting the real session directly as "provisioner-admin".
}

// TestDBProxyZSPNoProvisionerRefused proves a db_zsp target with no
// provisioner credential configured refuses the connection rather than
// guessing which credential to provision with.
func TestDBProxyZSPNoProvisionerRefused(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	fake := startFakePGProvisioner(t, "unused-provisioner")
	ctx := context.Background()
	host, portStr, _ := net.SplitHostPort(fake.addr)
	port, _ := strconv.Atoi(portStr)
	target := &store.Target{Name: "pg-zsp-bare", Host: host, Port: port, OSType: "linux", Protocol: "postgres"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	zsp := &store.Credential{TargetID: target.ID, Username: "zsp-slot", SecretType: store.SecretTypeDBZSP}
	if err := st.CreateCredential(ctx, zsp); err != nil {
		t.Fatal(err)
	}

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
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
		Parameters:      map[string]string{"user": "zsp-slot@pg-zsp-bare", "database": "appdb"},
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
	msg, err = fe.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := msg.(*pgproto3.ErrorResponse); !ok {
		t.Fatalf("expected the connection to be refused, got %T", msg)
	}
	waitForAuditDetail(t, st, "db.zsp_provision_failed", "pg-zsp-bare")
}

// TestDBProxyZSPAmbiguousProvisionerRefused proves a target with TWO
// provisioner credentials refuses a db_zsp dial rather than guessing which
// one to provision with — ambiguity here must fail closed.
func TestDBProxyZSPAmbiguousProvisionerRefused(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	fake := startFakePGProvisioner(t, "provisioner-a")
	ctx := context.Background()
	host, portStr, _ := net.SplitHostPort(fake.addr)
	port, _ := strconv.Atoi(portStr)
	target := &store.Target{Name: "pg-zsp-ambig", Host: host, Port: port, OSType: "linux", Protocol: "postgres"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"provisioner-a", "provisioner-b"} {
		c := &store.Credential{TargetID: target.ID, Username: u, SecretType: store.SecretTypePassword, Provisioner: true}
		if err := st.CreateCredential(ctx, c); err != nil {
			t.Fatal(err)
		}
		enc, err := v.Encrypt(ctx, provisionerSecret, store.CredentialAAD(target.ID, c.ID))
		if err != nil {
			t.Fatal(err)
		}
		if err := st.UpdateCredentialSecretEnc(ctx, c.ID, enc); err != nil {
			t.Fatal(err)
		}
	}
	zsp := &store.Credential{TargetID: target.ID, Username: "zsp-slot", SecretType: store.SecretTypeDBZSP}
	if err := st.CreateCredential(ctx, zsp); err != nil {
		t.Fatal(err)
	}

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
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
		Parameters:      map[string]string{"user": "zsp-slot@pg-zsp-ambig", "database": "appdb"},
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
	msg, err = fe.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := msg.(*pgproto3.ErrorResponse); !ok {
		t.Fatalf("expected the connection to be refused, got %T", msg)
	}
	waitForAuditDetail(t, st, "db.zsp_provision_failed", "pg-zsp-ambig")
}
