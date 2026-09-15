package proxy_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/mfa"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// mfaUser seeds a local user with a bearer token and, when withTOTP, a
// confirmed TOTP factor sealed exactly as POST /api/mfa/enroll seals one.
func mfaUser(t *testing.T, st store.Store, v *vault.Vault, name string, withTOTP bool) (token, secret string) {
	t.Helper()
	ctx := context.Background()
	token = name + "-token"
	if err := st.CreateUser(ctx, &store.User{Username: name, Role: "user", TokenHash: auth.TokenHash(token)}); err != nil {
		t.Fatal(err)
	}
	if !withTOTP {
		return token, ""
	}
	secret, err := mfa.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := v.Encrypt(ctx, secret, store.MFAAAD(name))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertMFAEnrollment(ctx, &store.MFAEnrollment{Username: name, SecretEnc: enc, Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	return token, secret
}

// mintTicket writes the ticket row POST /api/session-mfa writes once a factor
// is verified: a session with the ticket scope, bound to targetID.
func mintTicket(t *testing.T, st store.Store, user string, targetID int64) string {
	t.Helper()
	tok := fmt.Sprintf("ticket-%s-%d-%d", user, targetID, time.Now().UnixNano())
	if err := st.CreateSession(context.Background(), &store.Session{Username: user, Role: "user", Scope: auth.SessionScopeSessionMFA,
		TokenHash: auth.TokenHash(tok), ExpiresAt: time.Now().Add(2 * time.Minute), TargetID: &targetID}); err != nil {
		t.Fatal(err)
	}
	return tok
}

// targetIDNamed returns the id of the target called name.
func targetIDNamed(t *testing.T, st store.Store, name string) int64 {
	t.Helper()
	ts, err := st.ListTargets(context.Background(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tg := range ts {
		if tg.Name == name {
			return tg.ID
		}
	}
	t.Fatalf("no target %q", name)
	return 0
}

// seedNamedTarget is seedTarget under another name.
func seedNamedTarget(t *testing.T, st store.Store, v *vault.Vault, name, host string, port int) *store.Target {
	t.Helper()
	ctx := context.Background()
	target := &store.Target{Name: name, Host: host, Port: port, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	cred := &store.Credential{TargetID: target.ID, Username: upstreamUser, SecretType: "password"}
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
	return target
}

// dialMFA authenticates with password and answers any keyboard-interactive
// prompt with code, reporting how many prompts the proxy sent.
func dialMFA(t *testing.T, addr, login, password, code string) (*ssh.Client, int, error) {
	t.Helper()
	prompts := 0
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: login,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				prompts += len(questions)
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = code
				}
				return answers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	return client, prompts, err
}

// waitAuditDetail waits for an audit row whose action is action and whose
// detail contains want — the proxies write refusal rows on their own
// goroutine, so a test that looks immediately can race them.
func waitAuditDetail(t *testing.T, st store.Store, action, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		events, err := st.ListAudit(context.Background(), 500)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if e.Action == action && strings.Contains(e.Detail, want) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no audit row %s containing %q", action, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestSessionMFAProxy proves per-session MFA (Phase 244) end to end through the
// SSH proxy, against a real upstream sshd that accepts ONLY the vaulted
// password: a target that requires it prompts for a one-time code after the
// operator's token and admits only a right, unspent one; a ticket minted after
// a factor works as the password exactly once and only for its own target; an
// operator with no one-time-code factor is not prompted and is refused unless
// they bring a ticket; break-glass bypasses while the bootstrap key does not;
// and a target that does not require it is untouched.
func TestSessionMFAProxy(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	ctx := context.Background()
	guarded := seedTarget(t, st, v, host, port) // web-01
	guarded.RequireSessionMFA = true
	if err := st.UpdateTarget(ctx, guarded); err != nil {
		t.Fatal(err)
	}
	open := seedNamedTarget(t, st, v, "web-02", host, port)

	bg := sha256.Sum256([]byte("emergency-key"))
	resolver, err := auth.NewResolver(st, proxyAPIKey, hex.EncodeToString(bg[:]))
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	aliceTok, secret := mfaUser(t, st, v, "alice", true)
	bobTok, _ := mfaUser(t, st, v, "bob", false)

	run := func(client *ssh.Client, why string) {
		t.Helper()
		defer client.Close()
		sess, err := client.NewSession()
		if err != nil {
			t.Fatalf("%s: session refused: %v", why, err)
		}
		defer sess.Close()
		if out, err := sess.Output("run"); err != nil || string(out) != targetOutput {
			t.Fatalf("%s: output %q err %v", why, out, err)
		}
	}
	refused := func(client *ssh.Client, why string) {
		t.Helper()
		defer client.Close()
		if sess, err := client.NewSession(); err == nil {
			sess.Close()
			t.Fatalf("%s: a session must not open", why)
		}
	}

	// 1. The right code, answered at the prompt, reaches the real target.
	code, err := mfa.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client, prompts, err := dialMFA(t, addr, upstreamUser+"@web-01", aliceTok, code)
	if err != nil {
		t.Fatalf("alice with the right code: %v", err)
	}
	if prompts != 1 {
		t.Fatalf("alice was prompted %d times, want once", prompts)
	}
	run(client, "alice with the right code")
	waitAuditDetail(t, st, "session.mfa_verified", "target:web-01 factor:totp path:ssh")

	// 2. The same code again is a replay, and 3. a wrong code is wrong: both
	// fail authentication itself, and the failure is on the record.
	if c, _, err := dialMFA(t, addr, upstreamUser+"@web-01", aliceTok, code); err == nil {
		c.Close()
		t.Fatal("a replayed one-time code was accepted")
	}
	if c, _, err := dialMFA(t, addr, upstreamUser+"@web-01", aliceTok, "not-a-code"); err == nil {
		c.Close()
		t.Fatal("a wrong one-time code was accepted")
	}
	waitAuditDetail(t, st, "session.mfa_failed", "web-01")

	// 4. bob has no one-time-code factor: he is not prompted for one he could
	// not answer, and the session gate refuses him.
	client, prompts, err = dialMFA(t, addr, upstreamUser+"@web-01", bobTok, "unused")
	if err != nil {
		t.Fatalf("bob's token still authenticates the transport: %v", err)
	}
	if prompts != 0 {
		t.Fatal("bob was prompted for a factor he has not enrolled")
	}
	refused(client, "bob with no factor")
	waitAuditDetail(t, st, "session.denied", "target:web-01 reason:session-mfa-required")

	// 5. A ticket for web-01 is the factor: no prompt, one session, then dead.
	ticket := mintTicket(t, st, "bob", guarded.ID)
	client, prompts, err = dialMFA(t, addr, upstreamUser+"@web-01", ticket, "unused")
	if err != nil {
		t.Fatalf("bob with a ticket: %v", err)
	}
	if prompts != 0 {
		t.Fatal("a ticket holder was prompted")
	}
	run(client, "bob with a ticket")
	waitAuditDetail(t, st, "session.mfa_verified", "target:web-01 factor:ticket path:ssh")
	if c, _, err := dialMFA(t, addr, upstreamUser+"@web-01", ticket, "unused"); err == nil {
		c.Close()
		t.Fatal("a spent ticket authenticated again")
	}

	// 6. A ticket for web-02 shown at web-01 is refused — and burned with it.
	other := mintTicket(t, st, "bob", open.ID)
	client, _, err = dialMFA(t, addr, upstreamUser+"@web-01", other, "unused")
	if err != nil {
		t.Fatalf("dial with another target's ticket: %v", err)
	}
	refused(client, "a ticket for another target")
	waitAuditDetail(t, st, "session.denied", "target:web-01 reason:session-mfa-ticket-target")
	if c, _, err := dialMFA(t, addr, upstreamUser+"@web-02", other, "unused"); err == nil {
		c.Close()
		t.Fatal("a ticket shown to the wrong target must be burned")
	}

	// 7. The policy is the target's own: bob's plain token opens web-02.
	client, _, err = dialMFA(t, addr, upstreamUser+"@web-02", bobTok, "unused")
	if err != nil {
		t.Fatalf("bob on web-02: %v", err)
	}
	run(client, "bob on a target that does not require it")

	// 8. Break-glass bypasses; the bootstrap key, which has no factor, does not.
	client, prompts, err = dialMFA(t, addr, upstreamUser+"@web-01", "emergency-key", "unused")
	if err != nil {
		t.Fatalf("break-glass: %v", err)
	}
	if prompts != 0 {
		t.Fatal("break-glass was prompted")
	}
	run(client, "break-glass")
	client, _, err = dialMFA(t, addr, upstreamUser+"@web-01", proxyAPIKey, "unused")
	if err != nil {
		t.Fatalf("bootstrap key: %v", err)
	}
	refused(client, "the bootstrap key has no second factor")
}

// pgLoginError authenticates to the database proxy and returns the refusal
// message, failing the test if a session opens instead.
func pgLoginError(t *testing.T, addr, user, password string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{"user": user, "database": "appdb"}})
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
	fe.Send(&pgproto3.PasswordMessage{Password: password})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	for {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			return m.Message
		case *pgproto3.ReadyForQuery:
			t.Fatal("the session opened")
		}
	}
}

// TestSessionMFADBProxy proves the PostgreSQL proxy honours PAM_SESSION_MFA
// (Phase 244): the wire protocol has no second prompt, so a token alone is
// refused before the upstream is touched, and a ticket is the password — once.
func TestSessionMFADBProxy(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	fake := startFakePostgres(t, upstreamSecret)
	seedPGTarget(t, st, v, fake.addr)
	auditOnFailure(t, st)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	dbx, err := proxy.NewDB(st, v, resolver, proxy.DBConfig{RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second, SessionMFA: true})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveDBProxy(t, dbx)
	bobTok, _ := mfaUser(t, st, v, "bob", false)

	if msg := pgLoginError(t, addr, "dbuser@pg-01", bobTok); !strings.Contains(msg, "second factor") {
		t.Fatalf("token alone: refusal %q", msg)
	}
	if got := fake.password(); got != "" {
		t.Fatalf("the upstream was contacted for a refused session (password %q)", got)
	}
	waitAuditDetail(t, st, "db.session.denied", "target:pg-01 reason:session-mfa-required")

	ticket := mintTicket(t, st, "bob", targetIDNamed(t, st, "pg-01"))
	fe, conn := openDBSession(t, addr, "dbuser@pg-01", "appdb", ticket)
	fe.Send(&pgproto3.Query{String: "SELECT 1"})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	waitReady(t, fe)
	fe.Send(&pgproto3.Terminate{})
	_ = fe.Flush()
	conn.Close()
	if got := fake.password(); got != upstreamSecret {
		t.Fatalf("upstream password %q; the vaulted secret was not injected", got)
	}
	waitAuditDetail(t, st, "session.mfa_verified", "target:pg-01 factor:ticket path:postgres")
	if msg := pgLoginError(t, addr, "dbuser@pg-01", ticket); !strings.Contains(msg, "authentication failed") {
		t.Fatalf("a spent ticket: refusal %q", msg)
	}
}

// TestSessionMFAMSSQLProxy proves the SQL Server proxy takes the same gate:
// a token alone never reaches the upstream, a ticket logs in.
func TestSessionMFAMSSQLProxy(t *testing.T) {
	st, v := memstore.New(), mustVault(t)
	fake := startFakeMSSQL(t, upstreamSecret)
	seedMSSQLTarget(t, st, v, fake.addr)
	addr := serveMSSQLProxy(t, newMSSQLProxy(t, st, v, proxy.MSSQLConfig{SessionMFA: true}))
	bobTok, _ := mfaUser(t, st, v, "bob", false)

	if _, _, err := dialMSSQLProxy(t, addr, "sql_svc@sql-01", bobTok, "orders"); err == nil {
		t.Fatal("a token alone logged in to a target that requires session MFA")
	}
	if got := fake.password(); got != "" {
		t.Fatalf("the upstream was contacted for a refused session (password %q)", got)
	}
	waitAuditDetail(t, st, "db.session.denied", "target:sql-01 reason:session-mfa-required")

	ticket := mintTicket(t, st, "bob", targetIDNamed(t, st, "sql-01"))
	cli, _, err := dialMSSQLProxy(t, addr, "sql_svc@sql-01", ticket, "orders")
	if err != nil {
		t.Fatalf("login with a ticket: %v", err)
	}
	if _, err := cli.batch("SELECT 1"); err != nil {
		t.Fatalf("batch: %v", err)
	}
	if got := fake.password(); got != upstreamSecret {
		t.Fatalf("upstream got password %q, want the vaulted secret", got)
	}
}
