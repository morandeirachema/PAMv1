package proxy

// dbproxy.go extends the session-broker chokepoint to databases. It speaks the
// PostgreSQL frontend/backend wire protocol: an operator points psql (or any
// libpq client) at the proxy with user "<dbcred>@<target>" and their PAM key as
// the password; the proxy authenticates them, runs every authorization gate the
// SSH proxy runs, decrypts the target's DB credential just-in-time, dials the
// real PostgreSQL injecting that secret, and brokers the wire protocol —
// auditing each SQL statement and recording the session. The operator never
// sees the database credential (same invariant as the SSH/WinRM paths).

import (
	"context"
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- MD5 is mandated by the PostgreSQL MD5 auth wire protocol
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"golang.org/x/crypto/pbkdf2"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/cmdguard"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/posture"
	"github.com/morandeirachema/pamv1/internal/ratelimit"
	"github.com/morandeirachema/pamv1/internal/recording"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// DBConfig configures the PostgreSQL session proxy.
type DBConfig struct {
	Addr            string            // listen address, e.g. ":5433"; "off" disables it
	RecordingDir    string            // where session recordings are written
	Sessions        *session.Registry // live-session registry (optional)
	RequireApproval bool              // global 4-eyes/OT gate (per-target also applies)
	// RequireTargetGrant refuses a session to a target with NO grants at all
	// (PAM_REQUIRE_TARGET_GRANT, Phase 203).
	RequireTargetGrant bool
	// TicketCheck re-validates the admitting request's ITSM ticket at connect
	// time rather than at request time (PAM_TICKET_REVALIDATE, Phase 60).
	TicketCheck store.TicketChecker
	// PostureAttestor (optional) validates a user's live device posture on
	// every connect (Phase 133); nil disables posture checking.
	PostureAttestor  *posture.Attestor
	AllowedProtocols []string // protocol allowlist (must include "postgres")
	RequireRecording bool     // refuse a session that cannot be recorded
	DialTimeout      time.Duration
	// ClientTLS, when set, offers TLS on the operator-facing leg (responds 'S' to
	// an SSLRequest). When nil the proxy responds 'N' and the operator's PAM key
	// travels in cleartext — logged loudly at startup, terminate TLS at the ingress.
	ClientTLS *tls.Config
	// OnSessionEnd forces post-session credential rotation, like the SSH proxy.
	OnSessionEnd func(credentialID int64)

	// OnBreakGlass mirrors proxy.Config.OnBreakGlass: the emergency-access signal
	// this listener must raise itself, since it resolves its own principal.
	OnBreakGlass func(ctx context.Context, actor, detail string)
	// EncryptRecordings seals recordings at rest (PAM_RECORDING_ENCRYPT).
	EncryptRecordings bool
	// OpaqueRecordingNames names recording files by timestamp + random hex
	// (PAM_RECORDING_OPAQUE_NAMES, Phase 48).
	OpaqueRecordingNames bool
	// CommandGuard blocks SQL statements matching its deny patterns (Phase 16).
	CommandGuard *cmdguard.Guard
	// CommandAllowGuard (Phase 131), once set, narrows every command-control
	// path to ONLY commands it matches; deny still wins. nil = deny-only.
	CommandAllowGuard *cmdguard.Guard
	// Live receives each recorded statement keyed by session id, so a supervisor
	// can watch the session live (Phase 16).
	Live *session.Hub
	// AuthRatePerMin throttles operator authentication attempts per source IP per
	// minute, limiting online guessing of the PAM key (0 disables).
	AuthRatePerMin int
	// UpstreamTLS, when non-nil, VERIFIES the upstream PostgreSQL server's TLS
	// certificate on the target leg (RootCAs / ServerName). nil keeps the legacy
	// trust-any-with-warning behavior for the upstream connection.
	UpstreamTLS *tls.Config
	// MaxRecordingBytes caps a session recording's output (0 = unlimited).
	MaxRecordingBytes int64
	// StepUpGuard marks SQL statements that require an in-session supervisor
	// approval (Phase 30); nil disables step-up. StepUp coordinates the pause +
	// decision (shared with the API), and StepUpTTL bounds how long a paused
	// statement waits before it is denied (default 2m).
	StepUpGuard *cmdguard.Guard
	StepUp      *session.StepUp
	StepUpTTL   time.Duration
}

// DBProxy brokers PostgreSQL sessions with just-in-time credential injection.
type DBProxy struct {
	listener // shared accept/drain lifecycle: log, store, conns, bg, onSessionEnd, ln, Addr, audit

	vault        *vault.Vault
	recKey       recording.KeyWrapper
	opaqueNames  bool
	resolver     *auth.Resolver
	recordingDir string
	sessions     *session.Registry
	requireApprv bool
	ungated      auth.UngatedDefault
	ticketCheck  store.TicketChecker
	posture      *posture.Attestor
	onBreakGlass func(ctx context.Context, actor, detail string)
	allowedProto map[string]bool
	requireRec   bool
	dialTimeout  time.Duration
	clientTLS    *tls.Config
	guard        *cmdguard.Guard
	allowGuard   *cmdguard.Guard
	live         *session.Hub
	chain        *recordChain
	authLimiter  *ratelimit.Limiter
	upstreamTLS  *tls.Config
	maxRecBytes  int64
	stepupGuard  *cmdguard.Guard
	stepup       *session.StepUp
	stepupTTL    time.Duration
	gate         *gates // the shared admission-gate sequence (gates.go)
	// pol is the protocol-independent per-statement policy shared with the SQL
	// Server proxy (see sqlproxy.go), built once at construction.
	pol sqlPolicy
}

// NewDB constructs a DBProxy from the store, vault, auth resolver and cfg. It
// requires a resolver, defaults RecordingDir and DialTimeout, and warns loudly
// when the operator-facing leg is unencrypted (no ClientTLS).
func NewDB(st store.Store, v *vault.Vault, resolver *auth.Resolver, cfg DBConfig) (*DBProxy, error) {
	if resolver == nil {
		return nil, errors.New("dbproxy: resolver is required")
	}
	if cfg.RecordingDir == "" {
		cfg.RecordingDir = "recordings"
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	d := &DBProxy{
		listener: listener{
			log:          logging.Component("dbproxy"),
			store:        st,
			component:    "dbproxy",
			onSessionEnd: cfg.OnSessionEnd,
			conns:        make(map[net.Conn]struct{}),
		},
		vault:        v,
		recKey:       recKeyFor(cfg.EncryptRecordings, v),
		opaqueNames:  cfg.OpaqueRecordingNames,
		resolver:     resolver,
		recordingDir: cfg.RecordingDir,
		sessions:     cfg.Sessions,
		requireApprv: cfg.RequireApproval,
		ungated:      ungatedDefault(cfg.RequireTargetGrant),
		ticketCheck:  cfg.TicketCheck,
		posture:      cfg.PostureAttestor,
		onBreakGlass: cfg.OnBreakGlass,
		allowedProto: protocolSet(cfg.AllowedProtocols),
		requireRec:   cfg.RequireRecording,
		dialTimeout:  cfg.DialTimeout,
		clientTLS:    cfg.ClientTLS,
		guard:        cfg.CommandGuard,
		allowGuard:   cfg.CommandAllowGuard,
		live:         cfg.Live,
		chain:        newRecordChain(cfg.RecordingDir),
		authLimiter:  ratelimit.New(cfg.AuthRatePerMin),
		upstreamTLS:  cfg.UpstreamTLS,
		maxRecBytes:  cfg.MaxRecordingBytes,
		stepupGuard:  cfg.StepUpGuard,
		stepup:       cfg.StepUp,
		stepupTTL:    cfg.StepUpTTL,
	}
	if d.stepupTTL <= 0 {
		d.stepupTTL = 2 * time.Minute
	}
	d.gate = &gates{
		store:        st,
		vault:        v,
		log:          d.log,
		allowedProto: d.allowedProto,
		requireApprv: d.requireApprv,
		ungated:      d.ungated,
		ticketCheck:  d.ticketCheck,
		sessions:     d.sessions,
		posture:      d.posture,
	}
	d.pol = sqlPolicy{
		guard:       d.guard,
		allowGuard:  d.allowGuard,
		stepupGuard: d.stepupGuard,
		stepup:      d.stepup,
		stepupTTL:   d.stepupTTL,
		live:        d.live,
		prompt:      "psql> ",
		via:         "postgres",
		viaInQuery:  false, // PostgreSQL omits the via tag from db.query/step-up/deny details
	}
	if d.clientTLS == nil {
		d.log.Warn("database proxy operator leg is NOT encrypted (set PAM_TLS_CERT/KEY or terminate TLS at the ingress)")
	}
	if d.upstreamTLS == nil {
		d.log.Warn("upstream PostgreSQL TLS is NOT verified (set PAM_DB_UPSTREAM_CA or PAM_DB_UPSTREAM_TLS_VERIFY to pin it)")
	}
	return d, nil
}

// ListenAndServe binds addr and serves until ctx is cancelled.
func (d *DBProxy) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return d.Serve(ctx, ln)
}

// Serve accepts connections until ctx is cancelled, then closes the listener and
// force-closes active connections so the drain is bounded. The accept/drain
// lifecycle lives in the embedded listener; this only logs the PostgreSQL
// startup line and dispatches handleConn.
func (d *DBProxy) Serve(ctx context.Context, ln net.Listener) error {
	d.log.Info("database proxy listening", "addr", ln.Addr().String(), "protocol", "postgres")
	return d.serve(ctx, ln, d.handleConn, "db proxy accept error; retrying", "db-connection")
}

// handleConn brokers one PostgreSQL connection end to end: startup + SSL
// negotiation, operator authentication, the authorization gates, JIT credential
// injection into the upstream, and the audited/recorded message relay.
func (d *DBProxy) handleConn(ctx context.Context, nConn net.Conn) {
	defer recoverPanicLog(d.log, "db-session")
	remote := nConn.RemoteAddr().String()
	conn := nConn
	defer func() { conn.Close() }()

	// Bound the pre-authentication exchange, for the same reason the SSH proxy
	// does: until a peer authenticates it holds a connection slot and a goroutine
	// for free, and the startup/TLS/password sequence will otherwise wait forever
	// on a client that connects and says nothing. Cleared once authenticated,
	// because a real database session is legitimately idle between queries.
	_ = nConn.SetDeadline(time.Now().Add(handshakeTimeout))

	// --- Startup / SSL negotiation ---
	backend := newBoundedBackend(conn, pgPreAuthMaxBody)
	var startup *pgproto3.StartupMessage
	for startup == nil {
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return
		}
		switch msg := msg.(type) {
		case *pgproto3.SSLRequest:
			if d.clientTLS != nil {
				if _, err := conn.Write([]byte{'S'}); err != nil {
					return
				}
				tconn := tls.Server(conn, d.clientTLS)
				if err := tconn.HandshakeContext(ctx); err != nil {
					return
				}
				conn = tconn
				backend = newBoundedBackend(conn, pgPreAuthMaxBody) // re-frame over TLS
			} else if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
		case *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
		case *pgproto3.StartupMessage:
			startup = msg
		default:
			return
		}
	}

	login := startup.Parameters["user"]
	database := startup.Parameters["database"]
	if database == "" {
		database = login // libpq defaults dbname to the user
	}

	// --- Authenticate the operator: cleartext password = their PAM key ---
	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := backend.Flush(); err != nil {
		return
	}
	if err := backend.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
		return
	}
	// Throttle BEFORE reading the password, not after. Until the 2026-08-26
	// audit this check sat below the Receive, so a peer that was already
	// rate-limited could still make the proxy read (and, before the body bound
	// above, allocate for) one more message per connection. The limiter's job is
	// to stop an abusive source from costing us anything; that only holds if it
	// runs before the first thing the source can make us do.
	if !d.authLimiter.Allow(remoteHost(nConn.RemoteAddr())) {
		// Log but do NOT append — see the SSH proxy's authenticate for why: the
		// preceding failures are the signal, and appending per attempt under a
		// flood turns the system of record into the amplifier.
		d.log.Warn("db authentication rate limited", "login", auditField(login, 64), "remote", remote)
		d.fail(backend, "28P01", "pamv1: too many attempts; try again shortly")
		return
	}
	pmsg, err := backend.Receive()
	if err != nil {
		return
	}
	pw, ok := pmsg.(*pgproto3.PasswordMessage)
	if !ok {
		d.fail(backend, "28000", "pamv1: password expected")
		return
	}
	// Past the password the peer will send real queries, which are legitimately
	// larger than a credential — so the bound is widened here, and only here.
	backend.SetMaxBodyLen(pgSessionMaxBody)
	principal, err := d.resolver.Resolve(ctx, pw.Password)
	if err != nil {
		d.log.Warn("db authentication failed", "login", auditField(login, 64), "remote", remote)
		d.audit(ctx, auditField(login, 64), "proxy.auth_failed", "proto:postgres remote:"+remote)
		d.fail(backend, "28P01", "pamv1: authentication failed")
		return
	}
	actor := principal.Name
	// Authenticated: lift the pre-authentication deadline. Note this clears it on
	// nConn, the connection the deadline was set on — `conn` may now be a TLS
	// wrapper around it, and setting a deadline on the wrapper would not undo one
	// set on the socket beneath.
	_ = nConn.SetDeadline(time.Time{})

	// --- Authorization gates ---
	// Break-glass is noted here (it is not itself a gate): every entry point that
	// resolves its own principal must raise the emergency-access signal. It runs
	// just before admit — admit's first gate (tunnel-only) can never fire for a
	// break-glass principal, since the two token types are mutually exclusive, so
	// the pre-admit position is behaviour-identical to the old post-tunnel one.
	d.noteBreakGlass(ctx, principal, "postgres login:"+auditField(login, 64))

	// The shared admission sequence (gates.go, admit) runs every gate — tunnel-only
	// and enrollment refusals, role CapConnect, target/credential resolution, the
	// exact-protocol match, the protocol allowlist, per-target grants, the approval
	// and vendor-contract gates, the concurrent cap and the fail-closed
	// session-start audit — and decrypts just-in-time only if all pass. refuse()
	// maps whatever it returns to PostgreSQL's own refusal wording.
	credUser, targetName := splitLogin(login)
	res := d.gate.admit(ctx, admitRequest{
		principal:      principal,
		targetName:     targetName,
		credUser:       credUser,
		remoteAddr:     remote,
		expectProtocol: "postgres",
		skipDecrypt:    func(c *store.Credential) bool { return c.IsZSP() },
		startAudit: func(t *store.Target, c *store.Credential) (string, string) {
			return "db.session.start", fmt.Sprintf("target:%s db:%s cred_user:%s", t.Name, auditValueDB(database), c.Username)
		},
	})
	if res.outcome != admitOK {
		d.refuse(ctx, backend, res, actor, login)
		return
	}
	target, cred, secret := res.target, res.cred, res.secret

	// Zero Standing Privilege (Phase 129): a db_zsp credential carries no
	// stored secret (secret is "" here, per skipDecrypt above) — provision a
	// fresh, ephemeral role via the target's provisioner credential and dial
	// AS that role instead of the db_zsp row's own (unusable) username.
	dialUser, dialSecret := cred.Username, secret
	var provisioner *store.Credential
	var provisionerSecret, ephemeralUser string
	if cred.IsZSP() {
		var perr error
		provisioner, perr = findProvisioner(ctx, d.store, target.ID)
		if perr == nil {
			provisionerSecret, perr = jitDecrypt(ctx, d.vault, target, provisioner)
		}
		if perr == nil {
			ephemeralUser, dialSecret, perr = d.provisionPGRole(ctx, target, provisioner, provisionerSecret)
		}
		if perr != nil {
			d.audit(ctx, actor, "db.zsp_provision_failed", fmt.Sprintf("target:%s error:%v", target.Name, perr))
			d.fail(backend, "08006", "pamv1: zero standing privilege provisioning failed")
			return
		}
		dialUser = ephemeralUser
		d.audit(ctx, actor, "db.zsp_provisioned", fmt.Sprintf("target:%s role:%s", target.Name, ephemeralUser))
		// Registered immediately, not folded into the later session-lifecycle
		// defer below: several early-return paths between here and that defer
		// (a failed dial, a required-recording refusal) would otherwise leak
		// the just-created role for the rest of its VALID UNTIL window.
		defer d.teardownPGRole(context.WithoutCancel(ctx), actor, target, provisioner, provisionerSecret, ephemeralUser)
	}

	up, err := d.dialUpstream(ctx, target, dialUser, dialSecret, database)
	if err != nil {
		d.log.Error("upstream database connection failed", "actor", actor, "target", target.Name, "err", err)
		d.audit(ctx, actor, "db.session.error", fmt.Sprintf("target:%s db:%s error:%v", target.Name, auditValueDB(database), err))
		d.fail(backend, "08006", "pamv1: upstream connection failed")
		return
	}
	defer up.conn.Close()

	// Tell the operator's client authentication succeeded; the upstream's
	// ParameterStatus/BackendKeyData/ReadyForQuery flow through the relay.
	backend.Send(&pgproto3.AuthenticationOk{})
	if err := backend.Flush(); err != nil {
		return
	}

	d.log.Info("db session started", "actor", actor, "target", target.Name, "db", database, "cred_user", cred.Username, "remote", remote)

	var rec *Recording
	if r, rerr := newRecording(context.Background(), d.recordingDir, recording.Title(d.opaqueNames, time.Now(), "pgsql-"+target.Name, actor), time.Now(), d.maxRecBytes, d.recKey); rerr == nil {
		rec = r
	} else {
		d.audit(ctx, actor, "session.record_failed", "proto:postgres target:"+target.Name+" err:"+rerr.Error())
		if d.requireRec {
			d.fail(backend, "58000", "pamv1: session recording unavailable")
			return
		}
	}

	var sid string
	if d.sessions != nil {
		sid = d.sessions.Register(session.Info{
			Actor: actor, Target: target.Name, Protocol: "postgres", Remote: remote, Started: time.Now(),
		}, func() { conn.Close(); up.conn.Close() })
		defer d.sessions.Remove(sid)
		d.live.Publish(sid, watermarkBanner(actor, target.Name))
	}
	defer func() {
		if rec != nil {
			path, sum, n := rec.Close()
			chainHash := d.chain.append(sum)
			d.auditClosing(ctx, actor, "session.record",
				fmt.Sprintf("proto:postgres target:%s file:%s sha256:%s bytes:%d chain:%s", target.Name, filepath.Base(path), sum, n, chainHash))
		}
		d.log.Info("db session ended", "actor", actor, "target", target.Name)
		d.auditClosing(ctx, actor, "db.session.end", "target:"+target.Name)
		d.fireSessionEnd(cred.ID)
	}()

	d.relay(ctx, backend, up.fe, conn, up.conn, actor, target, rec, sid)
}

// upstreamPG is an authenticated connection to the real PostgreSQL server.
type upstreamPG struct {
	conn net.Conn
	fe   *pgproto3.Frontend
}

// dialUpstream connects to the target PostgreSQL, negotiates optional TLS, sends
// the startup message for credUser/database and completes authentication with
// the vaulted secret (cleartext, MD5 or SCRAM-SHA-256).
func (d *DBProxy) dialUpstream(ctx context.Context, target *store.Target, user, secret, database string) (*upstreamPG, error) {
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	dialer := net.Dialer{Timeout: d.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	// Bound everything up to a completed upstream login. net.Dialer.Timeout covers
	// only the TCP connect, so a target that accepted the connection and then went
	// silent — mid-TLS, or mid-authentication — parked this goroutine forever
	// holding the just-decrypted plaintext credential, in the window between the
	// session cap and Register where nothing counts, lists or kills it. The
	// deadline is cleared once the session is established, so a healthy long-lived
	// session is never cut.
	if derr := conn.SetDeadline(time.Now().Add(d.dialTimeout)); derr != nil {
		conn.Close()
		return nil, derr
	}
	tconn, err := d.maybeUpstreamTLS(conn, target.Host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream tls: %w", err)
	}
	conn = tconn
	fe := pgproto3.NewFrontend(conn, conn)
	// The upstream is a configured target, but its TLS default is trust-any, so
	// a corrupted or impersonated server sending a bogus length must not be able
	// to make this proxy allocate for it either.
	fe.SetMaxBodyLen(pgSessionMaxBody)
	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": user, "database": database},
	})
	if err := fe.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := pgAuthUpstream(fe, user, secret); err != nil {
		conn.Close()
		return nil, err
	}
	// Authenticated: clear the handshake deadline so the session itself is not
	// bounded by it.
	if derr := conn.SetDeadline(time.Time{}); derr != nil {
		conn.Close()
		return nil, derr
	}
	return &upstreamPG{conn: conn, fe: fe}, nil
}

// relay brokers messages both ways until either side closes. Client→upstream
// Query/Parse statements are audited and recorded; everything else passes
// through so result sets, prepared statements and COPY still work.
func (d *DBProxy) relay(ctx context.Context, backend *pgproto3.Backend, fe *pgproto3.Frontend, clientConn, upConn net.Conn, actor string, target *store.Target, rec *Recording, sid string) {
	// A per-connection context so a paused step-up (which blocks on a supervisor's
	// decision) is released when either peer disconnects, instead of parking until
	// the step-up TTL elapses.
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var once sync.Once
	stop := func() { cancel(); clientConn.Close(); upConn.Close() }
	// The client-facing backend is written by BOTH directions — the upstream→
	// client relay and a policy refusal on the client→upstream side — so every
	// write goes through this mutex; pgproto3.Backend is not concurrency-safe.
	var bmu sync.Mutex
	sendClient := func(msgs ...pgproto3.BackendMessage) error {
		bmu.Lock()
		defer bmu.Unlock()
		for _, m := range msgs {
			backend.Send(m)
		}
		return backend.Flush()
	}
	// cl adapts the mutex-guarded sendClient to the shared per-statement pipeline's
	// sqlClient interface (see sqlproxy.go).
	cl := pgSQLClient{send: sendClient}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // client → upstream
		defer wg.Done()
		defer once.Do(stop)
		defer recoverPanicLog(d.log, "db-c2u")
		for {
			msg, err := backend.Receive()
			if err != nil {
				return
			}
			switch m := msg.(type) {
			case *pgproto3.Query:
				if sqlBlockedStatement(ctx, &d.listener, &d.pol, cl, actor, target, m.String, false) {
					continue // refused by policy; session stays usable
				}
				if sqlStepUpRefused(relayCtx, &d.listener, &d.pol, cl, actor, target, m.String, sid, false) {
					continue // paused for a supervisor and denied/timed out; session stays usable
				}
				if sqlRecordQuery(ctx, &d.listener, &d.pol, rec, actor, target, m.String, sid) {
					return // recording cap reached: end the session rather than run it unrecorded
				}
			case *pgproto3.Parse:
				if sqlBlockedStatement(ctx, &d.listener, &d.pol, cl, actor, target, m.Query, true) {
					return // fail-closed: end the extended-protocol session
				}
				// Step-up covers the extended protocol too, so a client can't dodge a
				// supervisor by sending a guarded statement as Parse+Bind+Execute.
				if sqlStepUpRefused(relayCtx, &d.listener, &d.pol, cl, actor, target, m.Query, sid, true) {
					return // denied/timed out: fail-closed, end the extended-protocol session
				}
				if sqlRecordQuery(ctx, &d.listener, &d.pol, rec, actor, target, m.Query, sid) {
					return
				}
			case *pgproto3.FunctionCall:
				// The deprecated fast-path call carries no SQL text, so it can't be
				// command-filtered — but audit it so it can't silently evade the
				// per-statement trail the Query/Parse paths provide.
				if sqlRecordQuery(ctx, &d.listener, &d.pol, rec, actor, target, fmt.Sprintf("[fastpath function_call oid=%d]", m.Function), sid) {
					return
				}
			case *pgproto3.Terminate:
				fe.Send(msg)
				_ = fe.Flush()
				return
			}
			fe.Send(msg)
			if err := fe.Flush(); err != nil {
				return
			}
		}
	}()
	go func() { // upstream → client
		defer wg.Done()
		defer once.Do(stop)
		defer recoverPanicLog(d.log, "db-u2c")
		for {
			msg, err := fe.Receive()
			if err != nil {
				return
			}
			if err := sendClient(msg); err != nil {
				return
			}
		}
	}()
	wg.Wait()
}

// pgSQLClient adapts the mutex-guarded client writer to the shared per-statement
// pipeline's sqlClient interface (see sqlproxy.go). It encodes a refusal in the
// PostgreSQL frontend/backend protocol: a graceful ERROR + a fresh
// ReadyForQuery keeps the session usable, while a FATAL error (the
// extended-protocol case) leaves the caller to end the session. SQLSTATE 42501
// is "insufficient_privilege", the closest standard code for a policy refusal.
type pgSQLClient struct {
	send func(...pgproto3.BackendMessage) error
}

// refuse sends an ERROR ErrorResponse followed by a fresh ReadyForQuery, so the
// operator's client reports the refusal and the session stays usable.
func (c pgSQLClient) refuse(msg string) {
	_ = c.send(
		&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42501", Message: msg},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
}

// refuseFatal sends a FATAL ErrorResponse with no ReadyForQuery, the
// extended-protocol (Parse) case where answering gracefully would desync the
// Parse/Bind/Execute stream; the caller ends the session afterwards.
func (c pgSQLClient) refuseFatal(msg string) {
	_ = c.send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "42501", Message: msg})
}

// Message-body bounds for the PostgreSQL wire protocol, in octets.
//
// pgproto3's default is NO bound ("if maxBodyLen is 0, then no maximum is
// enforced"), and that default was live here from Phase 15 until the 2026-08-26
// audit: an unauthenticated peer could complete the 10 000-byte-bounded startup
// exchange and then, in the password message that follows, declare a ~2 GiB body.
// Receive() allocated it and blocked for the whole handshake timeout — and the
// rate limiter runs AFTER that read, so it never saw the connection. A handful of
// such connections OOM-killed the process and every session it hosted.
//
// Two bounds rather than one, because the two phases carry different traffic:
//
//   - pgPreAuthMaxBody covers the one message an unauthenticated peer may send
//     after startup — a password. 64 KiB is orders of magnitude above any real
//     credential and small enough that a flood of them is bounded by connection
//     count, not by what each connection can make us allocate.
//   - pgSessionMaxBody covers authenticated traffic: query text, bind parameters,
//     COPY data. 64 MiB is generous for a brokered session and still refuses the
//     pathological lengths a corrupted peer can encode in a 4-byte field.
//
// Both apply to the upstream Frontend as well, because the upstream's TLS
// default is trust-any and a server that sends a bogus length is the failure
// mode SetMaxBodyLen exists for on that side.
const (
	pgPreAuthMaxBody = 64 << 10
	pgSessionMaxBody = 64 << 20
)

// newBoundedBackend constructs a pgproto3.Backend with a message-body bound
// already set, so the bound cannot be forgotten at a construction site the way
// it was at every construction site before the audit.
func newBoundedBackend(conn net.Conn, maxBody int) *pgproto3.Backend {
	b := pgproto3.NewBackend(conn, conn)
	b.SetMaxBodyLen(maxBody)
	return b
}

// fail sends a FATAL ErrorResponse to the operator's client.
func (d *DBProxy) fail(backend *pgproto3.Backend, code, msg string) {
	backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: code, Message: msg})
	_ = backend.Flush()
}

// deny audits a refused session and reports it to the client. login is the
// operator-supplied startup username — attacker-controlled bytes — so it is
// bounded and quoted (auditField) before it reaches a log line or an audit
// row, exactly as the SSH and SQL Server listeners bound it.
func (d *DBProxy) deny(ctx context.Context, backend *pgproto3.Backend, actor, login, reason string) {
	d.log.Warn("db session denied", "actor", actor, "login", auditField(login, 64), "reason", reason)
	sqlDeny(ctx, &d.listener, &d.pol, actor, login, reason, func(msg string) { d.fail(backend, "28000", msg) })
}

// refuse maps an admit() refusal to PostgreSQL's wire refusal and audit,
// preserving the exact SQLSTATE codes, audit action names and details each gate
// has always used. admit already emitted the audits identical across all three
// proxies (access.denied for the approval and vendor denials, and
// credential.decrypt_failed) and the shared check-failed error logs; this adds
// only what is specific to the PostgreSQL transport. gateProtocolProxyable is
// an SSH-only gate and never occurs here (this proxy sets no proxyable hook).
func (d *DBProxy) refuse(ctx context.Context, backend *pgproto3.Backend, res admitResult, actor, login string) {
	switch res.gate {
	case gateTunnelOnly:
		// Audited here (with the short reason slug shared by the SSH proxy and the
		// HTTP authz middleware) and failed directly — NOT via deny(), which would
		// audit a second, differently-worded db.session.denied row for the same
		// refusal.
		d.audit(ctx, actor, "db.session.denied", "login:"+auditField(login, 64)+" reason:tunnel-only-token")
		d.fail(backend, "28000", "pamv1: this token may only be used by the in-portal viewer")
	case gateEnrollOnly:
		d.audit(ctx, actor, "db.session.denied", "login:"+auditField(login, 64)+" reason:mfa-enrollment-incomplete")
		d.fail(backend, "28000", "pamv1: complete MFA enrollment first")
	case gateExtensionOnly:
		d.audit(ctx, actor, "db.session.denied", "login:"+auditField(login, 64)+" reason:extension-scoped-token")
		d.fail(backend, "28000", "pamv1: a browser-extension token cannot open a database session")
	case gateMFAPending:
		d.audit(ctx, actor, "db.session.denied", "login:"+auditField(login, 64)+" reason:mfa-webauthn-pending")
		d.fail(backend, "28000", "pamv1: complete WebAuthn sign-in first")
	case gateRoleConnect:
		d.deny(ctx, backend, actor, login, "your role may not open sessions")
	case gateIPAllowlist:
		d.deny(ctx, backend, actor, login, "this account may not connect from this network")
	case gatePosture:
		d.deny(ctx, backend, actor, login, "your device failed its posture check")
	case gateResolve:
		d.deny(ctx, backend, actor, login, res.reason)
	case gateProtocolMatch:
		d.deny(ctx, backend, actor, login, "target is not a postgres target")
	case gateProtocolAllowed:
		d.deny(ctx, backend, actor, login, "protocol not allowed by policy")
	case gateTargetGrants:
		// admit logged "target grants lookup failed"; fail closed on the wire.
		d.fail(backend, "58000", "pamv1: authorization check failed")
	case gateTargetPolicy:
		d.deny(ctx, backend, actor, login, "not authorized for this target")
	case gateApprovalPolicy, gateApprovalClaim:
		// admit logged the specific approval error; fail closed on the wire.
		d.fail(backend, "58000", "pamv1: approval check failed")
	case gateApproval:
		// admit already audited access.denied with the reason.
		d.fail(backend, "28000", "pamv1: connection requires an approved access request")
	case gateVendorCheck:
		// admit logged "vendor gate check failed"; fail closed on the wire.
		d.fail(backend, "58000", "pamv1: authorization check failed")
	case gateVendor:
		// admit already audited access.denied reason:vendor-contract.
		d.fail(backend, "28000", "pamv1: vendor access requires an approved, in-window contract grant")
	case gateSessionLimit:
		d.audit(ctx, actor, "db.session.denied", "target:"+res.target.Name+" reason:session-limit")
		d.fail(backend, "53300", "pamv1: too many concurrent sessions")
	case gateAudit:
		// admit's fail-closed db.session.start write did not land; refuse.
		d.fail(backend, "58000", "pamv1: audit log unavailable; session refused")
	case gateDecrypt:
		// admit already audited credential.decrypt_failed and logged the error.
		d.fail(backend, "58000", "pamv1: credential unavailable")
	default:
		d.log.Error("unhandled admit refusal on the PostgreSQL proxy", "gate", int(res.gate), "actor", actor)
		d.fail(backend, "58000", "pamv1: authorization check failed")
	}
}

// maybeUpstreamTLS offers SSL to the upstream PostgreSQL. If the server accepts
// ('S') the connection is wrapped in TLS; if it declines ('N') the plaintext
// connection continues.
//
// When an upstream TLS config is set (PAM_DB_UPSTREAM_CA / PAM_DB_UPSTREAM_TLS_VERIFY)
// the server certificate is VERIFIED (fail-closed) so the JIT-injected DB
// credential cannot be harvested by a MITM impersonating the target. When it is
// unset the connection falls back to the legacy trust-any-with-warning posture
// (a warning is logged at startup), mirroring the SSH proxy's unpinned host-key
// behavior — but a verified config removes that gap entirely for the DB leg.
func (d *DBProxy) maybeUpstreamTLS(conn net.Conn, host string) (net.Conn, error) {
	// SSLRequest: int32 length 8, int32 request code 80877103.
	if _, err := conn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}); err != nil {
		return nil, err
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	if resp[0] != 'S' {
		// Upstream declined TLS. If verification was demanded, refuse rather than
		// silently sending the vaulted credential over a plaintext link.
		if d.upstreamTLS != nil {
			return nil, errors.New("upstream declined TLS but PAM_DB_UPSTREAM verification is required")
		}
		return conn, nil
	}
	var cfg *tls.Config
	if d.upstreamTLS != nil {
		cfg = d.upstreamTLS.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
	} else {
		cfg = &tls.Config{ServerName: host, InsecureSkipVerify: true} // #nosec G402 -- legacy trust-any fallback; verify via PAM_DB_UPSTREAM_CA / _TLS_VERIFY
	}
	tconn := tls.Client(conn, cfg)
	if err := tconn.Handshake(); err != nil {
		return nil, err
	}
	return tconn, nil
}

// pgAuthUpstream completes the frontend side of PostgreSQL authentication with
// the vaulted secret, supporting trust, cleartext, MD5 and SCRAM-SHA-256.
func pgAuthUpstream(fe *pgproto3.Frontend, user, password string) error {
	for {
		msg, err := fe.Receive()
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationOk:
			return nil
		case *pgproto3.AuthenticationCleartextPassword:
			fe.Send(&pgproto3.PasswordMessage{Password: password})
			if err := fe.Flush(); err != nil {
				return err
			}
		case *pgproto3.AuthenticationMD5Password:
			fe.Send(&pgproto3.PasswordMessage{Password: md5Password(user, password, m.Salt)})
			if err := fe.Flush(); err != nil {
				return err
			}
		case *pgproto3.AuthenticationSASL:
			if err := scramAuth(fe, password, m.AuthMechanisms); err != nil {
				return err
			}
		case *pgproto3.ErrorResponse:
			return fmt.Errorf("upstream rejected authentication: %s", m.Message)
		default:
			// NoticeResponse / ParameterStatus before auth completes: ignore.
		}
	}
}

// md5Password builds the "md5"-prefixed hash libpq sends for MD5 authentication:
// md5( md5(password+user) + salt ).
func md5Password(user, password string, salt [4]byte) string {
	inner := md5.Sum([]byte(password + user))                                  // #nosec G401 -- MD5 is mandated by the PostgreSQL MD5 auth protocol
	outer := md5.Sum(append([]byte(hex.EncodeToString(inner[:])), salt[:]...)) // #nosec G401 -- MD5 is mandated by the PostgreSQL MD5 auth protocol
	return "md5" + hex.EncodeToString(outer[:])
}

// scramAuth performs the client side of SCRAM-SHA-256 (RFC 5802) against the
// upstream, proving knowledge of the vaulted password without sending it.
func scramAuth(fe *pgproto3.Frontend, password string, mechanisms []string) error {
	supported := false
	for _, m := range mechanisms {
		if m == "SCRAM-SHA-256" {
			supported = true
		}
	}
	if !supported {
		return fmt.Errorf("no supported SASL mechanism offered: %v", mechanisms)
	}
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	clientNonce := base64.StdEncoding.EncodeToString(raw)
	clientFirstBare := "n=,r=" + clientNonce
	fe.Send(&pgproto3.SASLInitialResponse{AuthMechanism: "SCRAM-SHA-256", Data: []byte("n,," + clientFirstBare)})
	if err := fe.Flush(); err != nil {
		return err
	}

	msg, err := fe.Receive()
	if err != nil {
		return err
	}
	cont, ok := msg.(*pgproto3.AuthenticationSASLContinue)
	if !ok {
		return fmt.Errorf("expected SASLContinue, got %T", msg)
	}
	serverFirst := string(cont.Data)
	attrs := parseSCRAM(serverFirst)
	serverNonce := attrs["r"]
	if !strings.HasPrefix(serverNonce, clientNonce) {
		return errors.New("scram: server nonce does not extend client nonce")
	}
	salt, err := base64.StdEncoding.DecodeString(attrs["s"])
	if err != nil {
		return fmt.Errorf("scram salt: %w", err)
	}
	iters, err := strconv.Atoi(attrs["i"])
	if err != nil {
		return fmt.Errorf("scram iterations: %w", err)
	}

	saltedPassword := pbkdf2.Key([]byte(password), salt, iters, sha256.Size, sha256.New)
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	clientFinalBare := "c=biws,r=" + serverNonce
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalBare
	clientSig := hmacSHA256(storedKey[:], []byte(authMessage))
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSig[i]
	}
	fe.Send(&pgproto3.SASLResponse{Data: []byte(clientFinalBare + ",p=" + base64.StdEncoding.EncodeToString(proof))})
	if err := fe.Flush(); err != nil {
		return err
	}

	msg, err = fe.Receive()
	if err != nil {
		return err
	}
	if e, isErr := msg.(*pgproto3.ErrorResponse); isErr {
		return fmt.Errorf("scram rejected: %s", e.Message)
	}
	final, ok := msg.(*pgproto3.AuthenticationSASLFinal)
	if !ok {
		return fmt.Errorf("expected SASLFinal, got %T", msg)
	}
	// Verify the server signature (SCRAM mutual authentication): recompute the
	// expected ServerSignature and constant-time compare it with the server's
	// v=… value. Skipping this — as the proxy previously did — forfeits mutual auth
	// and lets a MITM/impostor upstream complete the handshake without proving it
	// knows the password.
	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
	expectedSig := hmacSHA256(serverKey, []byte(authMessage))
	gotSig, err := base64.StdEncoding.DecodeString(parseSCRAM(string(final.Data))["v"])
	if err != nil {
		return fmt.Errorf("scram server signature: %w", err)
	}
	if !hmac.Equal(gotSig, expectedSig) {
		return errors.New("scram: server signature mismatch (possible MITM upstream)")
	}
	return nil // AuthenticationOk follows and is consumed by the caller's loop
}

// parseSCRAM parses a SCRAM "k=v,k=v,..." message into a map.
func parseSCRAM(s string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(s, ",") {
		if k, v, ok := strings.Cut(part, "="); ok {
			out[k] = v
		}
	}
	return out
}

// hmacSHA256 returns HMAC-SHA-256(key, msg).
func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// --- shared with the SSH proxy (proxy.go) ---

// lookupTargetCred resolves a target by name and a matching credential (by
// username, or the first credential when credUser is empty) WITHOUT decrypting
// the secret, so every authorization gate can run before any plaintext exists.
func lookupTargetCred(ctx context.Context, st store.Store, targetName, credUser string) (*store.Target, *store.Credential, error) {
	if targetName == "" {
		return nil, nil, errors.New("no target specified")
	}
	targets, err := st.ListTargets(ctx, 0, 0)
	if err != nil {
		return nil, nil, errors.New("target lookup failed")
	}
	var target *store.Target
	for i := range targets {
		if targets[i].Name == targetName {
			target = &targets[i]
			break
		}
	}
	if target == nil {
		return nil, nil, fmt.Errorf("unknown target %q", targetName)
	}
	creds, err := st.ListCredentials(ctx, target.ID, 0, 0)
	if err != nil {
		return nil, nil, errors.New("credential lookup failed")
	}
	var cred *store.Credential
	for i := range creds {
		if credUser == "" || creds[i].Username == credUser {
			cred = &creds[i]
			break
		}
	}
	if cred == nil {
		return nil, nil, fmt.Errorf("no matching credential for target %q", targetName)
	}
	return target, cred, nil
}

// jitDecrypt performs the just-in-time decryption of a credential's secret. It
// must be called only after every authorization gate has passed.
func jitDecrypt(ctx context.Context, v *vault.Vault, target *store.Target, cred *store.Credential) (string, error) {
	secret, err := v.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		return "", errors.New("credential decryption failed")
	}
	return secret, nil
}

// appendAudit writes an audit event, logging (not failing) on a store error.
func appendAudit(ctx context.Context, st store.Store, log *slog.Logger, actor, action, detail string) {
	_ = appendAuditErr(ctx, st, log, actor, action, detail)
}

// appendAuditErr is appendAudit that returns the store error, so a session that
// must be audited before a secret is injected upstream can fail closed on it.
func appendAuditErr(ctx context.Context, st store.Store, log *slog.Logger, actor, action, detail string) error {
	e := store.AuditEvent{Actor: actor, Action: action, Detail: detail}
	err := st.AppendAudit(ctx, &e)
	if err != nil {
		log.Error("audit append failed", "action", action, "err", err)
	}
	return err
}

// recoverPanicLog logs and swallows a panic in a per-connection or per-session
// goroutine so one malformed session cannot crash the whole proxy.
func recoverPanicLog(log *slog.Logger, where string) {
	if r := recover(); r != nil {
		log.Error("proxy: recovered from panic", "where", where, "panic", r, "stack", string(debug.Stack()))
	}
}

// noteBreakGlass raises the emergency-access signal for this listener; see the
// shared implementation in proxy.go.
func (d *DBProxy) noteBreakGlass(ctx context.Context, principal *auth.Principal, detail string) {
	noteBreakGlass(ctx, d.store, d.log, d.onBreakGlass, principal, detail)
}
