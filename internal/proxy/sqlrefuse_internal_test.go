package proxy

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/tds"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// sqlRefusalCase is one row of the contract both SQL listeners keep when
// admit() refuses a session: what the operator's client is told, and what the
// trail records. It is written from the refusal tables as they stood when
// this test was added, not from either implementation's current code, so a
// change to a message, a code or an audit row fails here first.
type sqlRefusalCase struct {
	name   string
	gate   admitGate
	reason string
	// pgCode is the PostgreSQL SQLSTATE; SQL Server sends every refusal as a
	// login-failed error (18456, class 14).
	pgCode string
	msg    string
	// msMsg is the SQL Server message where it differs from msg.
	msMsg string
	// audit is the one db.session.denied detail the refusal writes, with
	// %VIA% standing for each listener's tag ("" on PostgreSQL, " via:mssql"
	// on SQL Server); "" means the refusal writes no audit row of its own
	// (admit() already wrote what it owns, or the gate is a fail-closed check).
	audit string
	// unhandled marks a gate neither listener maps: logged as an error.
	unhandled bool
}

const (
	sqlRefusalActor = "alice"
	sqlRefusalLogin = "dbuser@db-01"
	sqlLoginField   = `login:"dbuser@db-01"`
)

var sqlRefusalCases = []sqlRefusalCase{
	{name: "tunnel-only token", gate: gateTunnelOnly, pgCode: "28000",
		msg:   "PAMv1: this token may only be used by the in-portal viewer",
		audit: sqlLoginField + " reason:tunnel-only-token"},
	{name: "enrollment pending", gate: gateEnrollOnly, pgCode: "28000",
		msg:   "PAMv1: complete MFA enrollment first",
		audit: sqlLoginField + " reason:mfa-enrollment-incomplete"},
	{name: "extension token", gate: gateExtensionOnly, pgCode: "28000",
		msg:   "PAMv1: a browser-extension token cannot open a database session",
		audit: sqlLoginField + " reason:extension-scoped-token"},
	{name: "webauthn pending", gate: gateMFAPending, pgCode: "28000",
		msg:   "PAMv1: complete WebAuthn sign-in first",
		audit: sqlLoginField + " reason:mfa-webauthn-pending"},
	{name: "role may not connect", gate: gateRoleConnect, pgCode: "28000",
		msg:   "PAMv1: your role may not open sessions",
		audit: sqlLoginField + "%VIA% reason:your role may not open sessions"},
	{name: "ip allowlist", gate: gateIPAllowlist, pgCode: "28000",
		msg:   "PAMv1: this account may not connect from this network",
		audit: sqlLoginField + "%VIA% reason:this account may not connect from this network"},
	{name: "device posture", gate: gatePosture, pgCode: "28000",
		msg:   "PAMv1: your device failed its posture check",
		audit: sqlLoginField + "%VIA% reason:your device failed its posture check"},
	{name: "on call", gate: gateOnCall, pgCode: "28000",
		msg:   "PAMv1: you are not currently on call",
		audit: sqlLoginField + "%VIA% reason:you are not currently on call"},
	{name: "unresolved target", gate: gateResolve, reason: "unknown target \"db-01\"", pgCode: "28000",
		msg:   "PAMv1: unknown target \"db-01\"",
		audit: sqlLoginField + "%VIA% reason:unknown target \"db-01\""},
	{name: "wrong protocol", gate: gateProtocolMatch, pgCode: "28000",
		msg: "PAMv1: target is not a postgres target", msMsg: "PAMv1: target is not a mssql target",
		audit: sqlLoginField + "%VIA% reason:target is not a %PROTO% target"},
	{name: "protocol not allowed", gate: gateProtocolAllowed, pgCode: "28000",
		msg:   "PAMv1: protocol not allowed by policy",
		audit: sqlLoginField + "%VIA% reason:protocol not allowed by policy"},
	{name: "grants lookup failed", gate: gateTargetGrants, pgCode: "58000",
		msg: "PAMv1: authorization check failed"},
	{name: "not authorized for the target", gate: gateTargetPolicy, pgCode: "28000",
		msg:   "PAMv1: not authorized for this target",
		audit: sqlLoginField + "%VIA% reason:not authorized for this target"},
	{name: "session-mfa check failed", gate: gateSessionMFACheck, pgCode: "58000",
		msg: "PAMv1: authorization check failed"},
	{name: "session-mfa required", gate: gateSessionMFA, reason: auth.ReasonSessionMFARequired, pgCode: "28000",
		msg:   "PAMv1: this target requires a second factor for every session — mint a ticket (POST /api/session-mfa) and use it as the password",
		audit: "target:db-01 reason:" + auth.ReasonSessionMFARequired},
	{name: "session-mfa ticket used", gate: gateSessionMFA, reason: auth.ReasonSessionMFATicketUsed, pgCode: "28000",
		msg:   "PAMv1: this session-MFA ticket has already been used",
		audit: "target:db-01 reason:" + auth.ReasonSessionMFATicketUsed},
	{name: "approval policy failed", gate: gateApprovalPolicy, pgCode: "58000",
		msg: "PAMv1: approval check failed"},
	{name: "approval claim failed", gate: gateApprovalClaim, pgCode: "58000",
		msg: "PAMv1: approval check failed"},
	{name: "no approval", gate: gateApproval, reason: "approval-required", pgCode: "28000",
		msg: "PAMv1: connection requires an approved access request"},
	{name: "vendor check failed", gate: gateVendorCheck, pgCode: "58000",
		msg: "PAMv1: authorization check failed"},
	{name: "vendor contract", gate: gateVendor, pgCode: "28000",
		msg: "PAMv1: vendor access requires an approved, in-window contract grant"},
	{name: "session limit", gate: gateSessionLimit, pgCode: "53300",
		msg:   "PAMv1: too many concurrent sessions",
		audit: "target:db-01 reason:session-limit"},
	{name: "audit unavailable", gate: gateAudit, pgCode: "58000",
		msg: "PAMv1: audit log unavailable; session refused"},
	{name: "decrypt failed", gate: gateDecrypt, pgCode: "58000",
		msg: "PAMv1: credential unavailable"},
	{name: "ssh-only gate", gate: gateProtocolProxyable, pgCode: "58000",
		msg: "PAMv1: authorization check failed", unhandled: true},
	{name: "terminal token gate", gate: gateTerminalTarget, pgCode: "58000",
		msg: "PAMv1: authorization check failed", unhandled: true},
}

// TestSQLRefusalContract drives every admit() gate through each SQL
// listener's refuse and checks the whole contract: the wire refusal (the
// PostgreSQL SQLSTATE and message; the SQL Server login-failed token, byte
// for byte), the db.session.denied row or its absence, and the error log for
// a gate neither listener maps. Before it, most of these rows had no test on
// either listener.
func TestSQLRefusalContract(t *testing.T) {
	covered := map[admitGate]bool{}
	for _, c := range sqlRefusalCases {
		covered[c.gate] = true
	}
	for g := gateTunnelOnly; g <= gateTerminalTarget; g++ {
		if !covered[g] {
			t.Errorf("gate %d has no row in sqlRefusalCases: a gate added to admit() needs its SQL refusal pinned here", g)
		}
	}

	for _, c := range sqlRefusalCases {
		t.Run("postgres/"+c.name, func(t *testing.T) {
			st, logs, d := newRefusalDBProxy(t)
			srv, cli := net.Pipe()
			defer cli.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer srv.Close()
				d.refuse(context.Background(), pgproto3.NewBackend(srv, srv), c.result(), sqlRefusalActor, sqlRefusalLogin)
			}()
			_ = cli.SetReadDeadline(time.Now().Add(5 * time.Second))
			msg, err := pgproto3.NewFrontend(cli, cli).Receive()
			if err != nil {
				t.Fatalf("no refusal on the wire: %v", err)
			}
			er, ok := msg.(*pgproto3.ErrorResponse)
			if !ok {
				t.Fatalf("got %T, want an ErrorResponse", msg)
			}
			if er.Severity != "FATAL" || er.Code != c.pgCode || er.Message != c.msg {
				t.Fatalf("wire: %s %s %q, want FATAL %s %q", er.Severity, er.Code, er.Message, c.pgCode, c.msg)
			}
			<-done
			c.checkAudit(t, st, "", "postgres")
			c.checkUnhandled(t, logs, "unhandled admit refusal on the PostgreSQL proxy")
		})
		for _, tds72 := range []bool{true, false} {
			name := "mssql/" + c.name
			if !tds72 {
				name += "/pre-tds72"
			}
			t.Run(name, func(t *testing.T) {
				st, logs, m := newRefusalMSSQLProxy(t)
				srv, cli := net.Pipe()
				defer cli.Close()
				done := make(chan struct{})
				go func() {
					defer close(done)
					defer srv.Close()
					m.refuse(context.Background(), tds.NewConn(srv), c.result(), sqlRefusalActor, sqlRefusalLogin, tds72)
				}()
				_ = cli.SetReadDeadline(time.Now().Add(5 * time.Second))
				typ, _, data, err := tds.NewConn(cli).ReadMessage(1 << 20)
				if err != nil {
					t.Fatalf("no refusal on the wire: %v", err)
				}
				msg := c.msg
				if c.msMsg != "" {
					msg = c.msMsg
				}
				want := tds.Refusal(mssqlErrLoginFailed, 14, msg, tds.PacketLogin7, tds72)
				if typ != tds.PacketTabularResult || !bytes.Equal(data, want) {
					t.Fatalf("wire: type %d, %q; want type %d, login-failed %q", typ, tds.WalkLoginResponse(data, tds72).ServerError, tds.PacketTabularResult, msg)
				}
				<-done
				c.checkAudit(t, st, " via:mssql", "mssql")
				c.checkUnhandled(t, logs, "unhandled admit refusal on the SQL Server proxy")
			})
		}
	}
}

func (c sqlRefusalCase) result() admitResult {
	return admitResult{gate: c.gate, reason: c.reason, target: &store.Target{Name: "db-01"}}
}

// checkAudit asserts the refusal wrote exactly the expected db.session.denied
// row, or none, and nothing else.
func (c sqlRefusalCase) checkAudit(t *testing.T, st store.Store, via, proto string) {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range events {
		got = append(got, e.Actor+" "+e.Action+" "+e.Detail)
	}
	var want []string
	if c.audit != "" {
		detail := strings.ReplaceAll(strings.ReplaceAll(c.audit, "%VIA%", via), "%PROTO%", proto)
		want = []string{sqlRefusalActor + " db.session.denied " + detail}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// checkUnhandled asserts the error log a gate neither listener maps leaves,
// and that a mapped gate leaves none.
func (c sqlRefusalCase) checkUnhandled(t *testing.T, logs *bytes.Buffer, msg string) {
	t.Helper()
	logged := strings.Contains(logs.String(), "level=ERROR msg=\""+msg+"\"")
	if logged != c.unhandled {
		t.Fatalf("unhandled-gate error log present=%v, want %v:\n%s", logged, c.unhandled, logs)
	}
}

// refusalDeps is the store, vault, resolver and captured log a refusal test
// listener needs; refuse touches nothing else.
func refusalDeps(t *testing.T) (store.Store, *vault.Vault, *auth.Resolver, *bytes.Buffer, *slog.Logger) {
	t.Helper()
	st := memstore.New()
	key, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := auth.NewResolver(st, "refusal-test-bootstrap-key", "")
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	return st, v, resolver, &logs, slog.New(slog.NewTextHandler(&logs, nil))
}

func newRefusalDBProxy(t *testing.T) (store.Store, *bytes.Buffer, *DBProxy) {
	t.Helper()
	st, v, resolver, logs, log := refusalDeps(t)
	d, err := NewDB(st, v, resolver, DBConfig{RecordingDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	d.log = log
	return st, logs, d
}

func newRefusalMSSQLProxy(t *testing.T) (store.Store, *bytes.Buffer, *MSSQLProxy) {
	t.Helper()
	st, v, resolver, logs, log := refusalDeps(t)
	m, err := NewMSSQL(st, v, resolver, MSSQLConfig{RecordingDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	m.log = log
	return st, logs, m
}
