package proxy

// mssqlproxy.go brokers Microsoft SQL Server sessions, the TDS sibling of
// dbproxy.go's PostgreSQL broker. An operator points sqlcmd (or any TDS client)
// at the proxy with user "<dbcred>@<target>" and their PAM key as the password;
// the proxy authenticates them, runs every authorization gate the SSH and
// PostgreSQL proxies run, decrypts the target's SQL login just-in-time, dials
// the real SQL Server injecting that credential into the LOGIN7 it forwards,
// and brokers the wire protocol — auditing each statement and recording the
// session. The operator never learns the database password.
//
// The gate ORDER is deliberately identical to dbproxy.handleConn, so the two
// can be diffed: anything that differs is the transport, never the policy.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/cmdguard"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/ratelimit"
	"github.com/morandeirachema/pamv1/internal/recording"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/tds"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// maxTDSMessage bounds a reassembled client request. A statement larger than
// this is refused rather than buffered: the cap exists so a peer that never
// ends its message cannot grow the heap without limit.
const maxTDSMessage = 16 << 20

// maxHandshakeMessage bounds the PRELOGIN and LOGIN7 reads, which happen before
// anything is authenticated. MS-TDS caps a LOGIN7 stream at 128K-1 bytes, so a
// larger one is malformed — and pre-auth connections are the cheapest thing for
// an attacker to open.
const maxHandshakeMessage = 128 << 10

// SQL Server error numbers used for refusals. 18456 is the number every client
// renders as "Login failed"; 50000 is the user-defined range, which is what an
// in-session policy refusal is.
const (
	mssqlErrLoginFailed uint32 = 18456
	mssqlErrPolicy      uint32 = 50000
)

// MSSQLConfig configures the SQL Server session proxy. It mirrors DBConfig
// field for field — the two listeners share every policy knob, so an operator
// never has to reason about one database proxy being configured differently
// from the other.
type MSSQLConfig struct {
	Addr             string            // listen address, e.g. ":1433"; "off" disables it
	RecordingDir     string            // where session recordings are written
	Sessions         *session.Registry // live-session registry (optional)
	RequireApproval  bool              // global 4-eyes/OT gate (per-target also applies)
	AllowedProtocols []string          // protocol allowlist (must include "mssql")
	RequireRecording bool              // refuse a session that cannot be recorded
	DialTimeout      time.Duration
	// ClientTLS, when set, offers TLS on the operator-facing leg. TDS carries
	// the handshake inside its own packets (see internal/tds). When nil the
	// proxy advertises "encryption not supported" and the operator's PAM key
	// travels in cleartext — logged loudly at startup, and refused outright by
	// modern clients, which default to requiring encryption.
	ClientTLS *tls.Config
	// OnSessionEnd forces post-session credential rotation, like the SSH proxy.
	OnSessionEnd func(credentialID int64)

	// OnBreakGlass mirrors proxy.Config.OnBreakGlass: the emergency-access signal
	// this listener must raise itself, since it resolves its own principal.
	OnBreakGlass func(ctx context.Context, actor, detail string)
	// EncryptRecordings seals recordings at rest (PAM_RECORDING_ENCRYPT).
	EncryptRecordings bool
	// OpaqueRecordingNames names recording files by timestamp + random hex.
	OpaqueRecordingNames bool
	// CommandGuard blocks statements matching its deny patterns (Phase 16).
	CommandGuard *cmdguard.Guard
	// Live receives each recorded statement keyed by session id.
	Live *session.Hub
	// AuthRatePerMin throttles operator authentication attempts per source IP.
	AuthRatePerMin int
	// UpstreamTLS, when non-nil, VERIFIES the upstream server's certificate on
	// the target leg. nil keeps the trust-any-with-warning behavior.
	UpstreamTLS *tls.Config
	// MaxRecordingBytes caps a session recording's output (0 = unlimited).
	MaxRecordingBytes int64
	// StepUpGuard marks statements that require an in-session supervisor
	// approval (Phase 30); nil disables step-up.
	StepUpGuard *cmdguard.Guard
	StepUp      *session.StepUp
	StepUpTTL   time.Duration
}

// MSSQLProxy brokers SQL Server sessions with just-in-time credential injection.
type MSSQLProxy struct {
	store        store.Store
	vault        *vault.Vault
	recKey       recording.KeyWrapper
	opaqueNames  bool
	resolver     *auth.Resolver
	log          *slog.Logger
	recordingDir string
	sessions     *session.Registry
	requireApprv bool
	onBreakGlass func(ctx context.Context, actor, detail string)
	allowedProto map[string]bool
	requireRec   bool
	dialTimeout  time.Duration
	clientTLS    *tls.Config
	onSessionEnd func(int64)
	guard        *cmdguard.Guard
	live         *session.Hub
	chain        *recordChain
	authLimiter  *ratelimit.Limiter
	upstreamTLS  *tls.Config
	maxRecBytes  int64
	stepupGuard  *cmdguard.Guard
	stepup       *session.StepUp
	stepupTTL    time.Duration

	bg sync.WaitGroup // background tasks (post-session rotation) drained on shutdown

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closing bool
}

// NewMSSQL constructs an MSSQLProxy from the store, vault, auth resolver and
// cfg, with the same requirements and startup warnings as NewDB.
func NewMSSQL(st store.Store, v *vault.Vault, resolver *auth.Resolver, cfg MSSQLConfig) (*MSSQLProxy, error) {
	if resolver == nil {
		return nil, errors.New("mssqlproxy: resolver is required")
	}
	if cfg.RecordingDir == "" {
		cfg.RecordingDir = "recordings"
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	m := &MSSQLProxy{
		store:        st,
		vault:        v,
		recKey:       recKeyFor(cfg.EncryptRecordings, v),
		opaqueNames:  cfg.OpaqueRecordingNames,
		resolver:     resolver,
		log:          logging.Component("mssqlproxy"),
		recordingDir: cfg.RecordingDir,
		sessions:     cfg.Sessions,
		requireApprv: cfg.RequireApproval,
		onBreakGlass: cfg.OnBreakGlass,
		allowedProto: protocolSet(cfg.AllowedProtocols),
		requireRec:   cfg.RequireRecording,
		dialTimeout:  cfg.DialTimeout,
		clientTLS:    cfg.ClientTLS,
		onSessionEnd: cfg.OnSessionEnd,
		guard:        cfg.CommandGuard,
		live:         cfg.Live,
		chain:        newRecordChain(cfg.RecordingDir),
		authLimiter:  ratelimit.New(cfg.AuthRatePerMin),
		upstreamTLS:  cfg.UpstreamTLS,
		maxRecBytes:  cfg.MaxRecordingBytes,
		stepupGuard:  cfg.StepUpGuard,
		stepup:       cfg.StepUp,
		stepupTTL:    cfg.StepUpTTL,
		conns:        make(map[net.Conn]struct{}),
	}
	if m.stepupTTL <= 0 {
		m.stepupTTL = 2 * time.Minute
	}
	if m.clientTLS == nil {
		m.log.Warn("SQL Server proxy operator leg is NOT encrypted (set PAM_TLS_CERT/KEY); modern TDS clients require encryption and will refuse to connect")
	}
	if m.upstreamTLS == nil {
		m.log.Warn("upstream SQL Server TLS is NOT verified (set PAM_DB_UPSTREAM_CA or PAM_DB_UPSTREAM_TLS_VERIFY to pin it)")
	}
	return m, nil
}

// ListenAndServe binds addr and serves until ctx is cancelled.
func (m *MSSQLProxy) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return m.Serve(ctx, ln)
}

// Serve accepts connections until ctx is cancelled, then closes the listener
// and force-closes active connections so the drain is bounded.
func (m *MSSQLProxy) Serve(ctx context.Context, ln net.Listener) error {
	m.mu.Lock()
	m.closing = false
	m.mu.Unlock()

	go func() {
		<-ctx.Done()
		ln.Close()
		m.closeActiveConns()
	}()

	m.log.Info("database proxy listening", "addr", ln.Addr().String(), "protocol", "mssql")
	var wg sync.WaitGroup
	var tempDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				m.bg.Wait()
				return nil
			}
			//lint:ignore SA1019 Temporary() is the only portable transient-accept signal; matches net/http's Serve backoff
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > time.Second {
					tempDelay = time.Second
				}
				m.log.Warn("mssql proxy accept error; retrying", "err", err, "retry_in", tempDelay)
				select {
				case <-time.After(tempDelay):
				case <-ctx.Done():
					wg.Wait()
					m.bg.Wait()
					return nil
				}
				continue
			}
			return err
		}
		tempDelay = 0
		m.trackConn(conn)
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer m.untrackConn(c)
			defer recoverPanicLog(m.log, "mssql-connection")
			m.handleConn(ctx, c)
		}(conn)
	}
}

// trackConn records an accepted connection so shutdown can force-close it.
func (m *MSSQLProxy) trackConn(c net.Conn) {
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		c.Close()
		return
	}
	m.conns[c] = struct{}{}
	m.mu.Unlock()
}

// untrackConn drops a connection once its handler returns.
func (m *MSSQLProxy) untrackConn(c net.Conn) {
	m.mu.Lock()
	delete(m.conns, c)
	m.mu.Unlock()
}

// closeActiveConns force-closes every tracked connection to bound the drain.
func (m *MSSQLProxy) closeActiveConns() {
	m.mu.Lock()
	m.closing = true
	conns := make([]net.Conn, 0, len(m.conns))
	for c := range m.conns {
		conns = append(conns, c)
	}
	m.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// fireSessionEnd runs the post-session rotation callback as a tracked
// background task (drained on shutdown).
func (m *MSSQLProxy) fireSessionEnd(credID int64) {
	if m.onSessionEnd == nil {
		return
	}
	m.bg.Add(1)
	go func() {
		defer m.bg.Done()
		m.onSessionEnd(credID)
	}()
}

// audit appends an audit event, defaulting an empty actor to "mssqlproxy".
func (m *MSSQLProxy) audit(ctx context.Context, actor, action, detail string) {
	if actor == "" {
		actor = "mssqlproxy"
	}
	appendAudit(ctx, m.store, m.log, actor, action, detail)
}

// auditClosing writes a teardown audit event that must survive graceful
// shutdown (detached from a cancelled ctx, bounded so a hung store cannot
// stall the drain).
func (m *MSSQLProxy) auditClosing(ctx context.Context, actor, action, detail string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	m.audit(ctx, actor, action, detail)
}

// handleConn brokers one SQL Server connection end to end: PRELOGIN + optional
// TLS, LOGIN7 parsing, operator authentication, the authorization gates, JIT
// credential injection into the upstream login, and the audited/recorded relay.
func (m *MSSQLProxy) handleConn(ctx context.Context, nConn net.Conn) {
	defer recoverPanicLog(m.log, "mssql-session")
	remote := nConn.RemoteAddr().String()
	conn := nConn
	defer func() { conn.Close() }()

	// Bound the pre-authentication exchange for the same reason the SSH and
	// PostgreSQL proxies do: until a peer authenticates it holds a connection
	// slot and a goroutine for free. Cleared once authenticated, because a real
	// database session is legitimately idle between queries.
	_ = nConn.SetDeadline(time.Now().Add(handshakeTimeout))

	// --- PRELOGIN ---
	c := tds.NewConn(conn)
	typ, _, payload, err := c.ReadMessage(maxHandshakeMessage)
	if err != nil {
		return
	}
	if typ != tds.PacketPreLogin {
		// TDS 8.0 "strict" encryption opens with a raw TLS handshake (0x16)
		// instead of a PRELOGIN packet. Say so rather than hanging: an
		// unexplained stall is the worst failure mode for an operator.
		if typ == 0x16 {
			m.log.Warn("TDS 8.0 strict encryption is not supported; use Encrypt=Mandatory", "remote", remote)
		}
		return
	}
	clientPre, err := tds.ParsePreLogin(payload)
	if err != nil {
		return
	}
	encrypted, err := m.serverPreLogin(c, conn, clientPre)
	if err != nil {
		return
	}
	if encrypted != nil {
		conn = encrypted
		c = tds.NewConn(conn) // re-frame over TLS
	}

	// --- LOGIN7 ---
	typ, _, payload, err = c.ReadMessage(maxHandshakeMessage)
	if err != nil || typ != tds.PacketLogin7 {
		return
	}
	login, err := tds.ParseLogin7(payload)
	if err != nil {
		return
	}
	c.SetPacketSize(int(login.PacketSize))
	tds72 := login.TDS72OrLater()
	if login.IntegratedSecurity() {
		// Brokering means swapping the operator's PAM key for a vaulted SQL
		// login; Windows authentication cannot express that.
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: use SQL authentication (integrated/Windows auth is not brokered)", tds72)
		return
	}

	loginName := login.UserName
	// Throttle online guessing of the PAM key before any resolve work.
	if !m.authLimiter.Allow(remoteHost(nConn.RemoteAddr())) {
		// Log but do NOT append — as in the SSH and DB proxies: the preceding
		// failures are the signal, and appending per attempt under a flood turns
		// the system of record into the amplifier.
		m.log.Warn("mssql authentication rate limited", "login", auditField(loginName, 64), "remote", remote)
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: too many attempts; try again shortly", tds72)
		return
	}
	principal, err := m.resolver.Resolve(ctx, login.Password)
	if err != nil {
		m.log.Warn("mssql authentication failed", "login", auditField(loginName, 64), "remote", remote)
		m.audit(ctx, auditField(loginName, 64), "proxy.auth_failed", "proto:mssql remote:"+remote)
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: authentication failed", tds72)
		return
	}
	actor := principal.Name
	// Authenticated: lift the pre-authentication deadline. Note this clears it
	// on nConn, the connection the deadline was set on — conn may now be a TLS
	// wrapper around it.
	_ = nConn.SetDeadline(time.Time{})

	// --- Authorization gates (identical order to dbproxy; decrypt only after all pass) ---
	if principal.TunnelOnly {
		m.audit(ctx, actor, "db.session.denied", "login:"+auditField(loginName, 64)+" reason:tunnel-only-token")
		m.deny(ctx, c, actor, loginName, "this token may only be used by the in-portal viewer", tds72)
		return
	}
	m.noteBreakGlass(ctx, principal, "mssql login:"+auditField(loginName, 64))
	if principal.EnrollOnly {
		m.audit(ctx, actor, "db.session.denied", "login:"+auditField(loginName, 64)+" reason:mfa-enrollment-incomplete")
		m.deny(ctx, c, actor, loginName, "complete MFA enrollment first", tds72)
		return
	}
	if !principal.Can(auth.CapConnect) {
		m.deny(ctx, c, actor, loginName, "your role may not open sessions", tds72)
		return
	}
	credUser, targetName := splitLogin(loginName)
	target, cred, err := lookupTargetCred(ctx, m.store, targetName, credUser)
	if err != nil {
		m.deny(ctx, c, actor, loginName, err.Error(), tds72)
		return
	}
	if target.Protocol != "mssql" {
		m.deny(ctx, c, actor, loginName, "target is not a mssql target", tds72)
		return
	}
	if m.allowedProto != nil && !m.allowedProto[target.Protocol] {
		m.deny(ctx, c, actor, loginName, "protocol not allowed by policy", tds72)
		return
	}
	grants, err := m.store.EffectiveTargetGrants(ctx, target.ID)
	if err != nil {
		m.log.Error("target grants lookup failed", "target", target.Name, "err", err)
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: authorization check failed", tds72)
		return
	}
	if !auth.CanConnectTarget(principal, grants, target.SafeID != nil) {
		m.deny(ctx, c, actor, loginName, "not authorized for this target", tds72)
		return
	}
	// Consume-on-connect (Phase 26): a single-use approval is burned by the
	// connection it admits and cannot authorize a second session.
	if (m.requireApprv || target.RequireApproval) && !principal.BreakGlass {
		approved, consumedID, aerr := m.store.ConsumeApproval(ctx, actor, target.ID, time.Now())
		if aerr != nil {
			m.log.Error("approval check failed", "target", target.Name, "err", aerr)
			m.fail(c, mssqlErrLoginFailed, 14, "pamv1: approval check failed", tds72)
			return
		}
		if !approved {
			m.audit(ctx, actor, "access.denied", "target:"+target.Name+" reason:approval-required")
			m.fail(c, mssqlErrLoginFailed, 14, "pamv1: connection requires an approved access request", tds72)
			return
		}
		if consumedID != 0 {
			m.audit(ctx, actor, "access.consumed", fmt.Sprintf("request:%d target:%s", consumedID, target.Name))
		}
	}

	// Vendor contract gate (Phase 29).
	if isVendor, allowed, verr := m.store.VendorSessionAllowed(ctx, actor, target.Name, cred.Username, time.Now()); verr != nil {
		m.log.Error("vendor gate check failed", "target", target.Name, "err", verr)
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: authorization check failed", tds72)
		return
	} else if isVendor && !allowed {
		m.audit(ctx, actor, "access.denied", "target:"+target.Name+" reason:vendor-contract")
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: vendor access requires an approved, in-window contract grant", tds72)
		return
	}

	// Concurrent-session cap: refuse before decrypting any secret.
	if m.sessions != nil && !m.sessions.AllowNew(actor) {
		m.audit(ctx, actor, "db.session.denied", "target:"+target.Name+" reason:session-limit")
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: too many concurrent sessions", tds72)
		return
	}

	database := login.Database
	// Fail closed: durably audit the session before any secret is decrypted or
	// injected upstream.
	if err := appendAuditErr(ctx, m.store, m.log, actor, "db.session.start",
		fmt.Sprintf("target:%s db:%s cred_user:%s via:mssql", target.Name, database, cred.Username)); err != nil {
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: audit log unavailable; session refused", tds72)
		return
	}

	// Every gate passed — decrypt just-in-time. Plaintext exists only from here.
	secret, err := jitDecrypt(ctx, m.vault, target, cred)
	if err != nil {
		m.log.Error("credential decryption failed", "actor", actor, "target", target.Name, "err", err)
		m.audit(ctx, actor, "credential.decrypt_failed", "target:"+target.Name+" cred_user:"+cred.Username+" op:connect")
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: credential unavailable", tds72)
		return
	}

	up, loginResp, err := m.dialUpstream(ctx, target, cred.Username, secret, login)
	if err != nil {
		m.log.Error("upstream database connection failed", "actor", actor, "target", target.Name, "err", err)
		m.audit(ctx, actor, "db.session.error", fmt.Sprintf("target:%s db:%s via:mssql error:%v", target.Name, database, err))
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: upstream connection failed", tds72)
		return
	}
	defer up.conn.Close()

	// A server-imposed packet size (ENVCHANGE type 4) is relayed to the client
	// below, so the CLIENT-facing framer has to adopt it as well — otherwise the
	// proxy keeps writing packets larger than the size the client just accepted,
	// and the client aborts mid-session.
	if up.negotiated > 0 {
		c.SetPacketSize(up.negotiated)
	}
	// Relay the upstream's login response verbatim, so LOGINACK, collation and
	// the database ENVCHANGE all reach the client intact.
	if err := c.WriteMessage(tds.PacketTabularResult, 0, loginResp); err != nil {
		return
	}

	m.log.Info("db session started", "actor", actor, "target", target.Name, "db", database,
		"cred_user", cred.Username, "remote", remote, "protocol", "mssql")

	var rec *Recording
	if r, rerr := newRecording(context.Background(), m.recordingDir,
		recording.Title(m.opaqueNames, time.Now(), "mssql-"+target.Name, actor), time.Now(), m.maxRecBytes, m.recKey); rerr == nil {
		rec = r
	} else {
		m.audit(ctx, actor, "session.record_failed", "proto:mssql target:"+target.Name+" err:"+rerr.Error())
		if m.requireRec {
			m.fail(c, mssqlErrLoginFailed, 14, "pamv1: session recording unavailable", tds72)
			return
		}
	}

	var sid string
	if m.sessions != nil {
		sid = m.sessions.Register(session.Info{
			Actor: actor, Target: target.Name, Protocol: "mssql", Remote: remote, Started: time.Now(),
		}, func() { conn.Close(); up.conn.Close() })
		defer m.sessions.Remove(sid)
	}
	defer func() {
		if rec != nil {
			path, sum, n := rec.Close()
			chainHash := m.chain.append(sum)
			m.auditClosing(ctx, actor, "session.record",
				fmt.Sprintf("proto:mssql target:%s file:%s sha256:%s bytes:%d chain:%s", target.Name, filepath.Base(path), sum, n, chainHash))
		}
		m.log.Info("db session ended", "actor", actor, "target", target.Name, "protocol", "mssql")
		m.auditClosing(ctx, actor, "db.session.end", "target:"+target.Name+" via:mssql")
		m.fireSessionEnd(cred.ID)
	}()

	m.relay(ctx, c, up, conn, actor, target, rec, sid, tds72)
}

// serverPreLogin answers the client's PRELOGIN and, when TLS is configured,
// completes the TDS-framed handshake. It returns the encrypted connection, or
// nil when the session stays in cleartext.
//
// The proxy never selects TDS's "encrypt the login packet only" mode: that mode
// reverts to plaintext mid-stream, which is precisely where silent-downgrade
// bugs live. With ClientTLS set it advertises ENCRYPT_ON (whole session);
// without it, ENCRYPT_NOT_SUP — and a client that demanded encryption
// terminates the connection itself with a clear message.
func (m *MSSQLProxy) serverPreLogin(c *tds.Conn, conn net.Conn, client *tds.PreLogin) (net.Conn, error) {
	enc := tds.EncryptNotSup
	if m.clientTLS != nil {
		enc = tds.EncryptOn
	} else if want := client.Encryption(); want == tds.EncryptOn || want == tds.EncryptReq {
		m.log.Warn("client requested TDS encryption but the proxy has no certificate (set PAM_TLS_CERT/KEY)")
	}

	resp := tds.NewPreLogin()
	resp.Set(tds.PreLoginVersion, []byte{16, 0, 0, 0, 0, 0})
	resp.Set(tds.PreLoginEncryption, []byte{enc})
	resp.Set(tds.PreLoginInstOpt, []byte{0x00})
	// MARS off: multiplexed sessions would carry SMP headers the request parser
	// never sees, so per-statement audit and command control would silently go
	// blind. FEDAUTHREQUIRED is deliberately omitted — its presence is what
	// tells a client federated auth is on offer.
	resp.Set(tds.PreLoginMARS, []byte{0x00})
	if err := c.WriteMessage(tds.PacketPreLogin, 0, resp.Encode()); err != nil {
		return nil, err
	}
	if enc != tds.EncryptOn {
		return nil, nil
	}
	return tds.ServerHandshake(conn, m.clientTLS)
}

// upstreamMSSQL is an authenticated connection to the real SQL Server.
type upstreamMSSQL struct {
	conn net.Conn
	c    *tds.Conn
	// negotiated is a server-imposed packet size (ENVCHANGE type 4), or 0.
	negotiated int
}

// dialUpstream connects to the target, negotiates TLS, and completes the login
// with the vaulted credential injected into the client's own LOGIN7 — every
// other field (hostname, application name, database, language, feature
// extensions, negotiated version and packet size) is forwarded untouched, so
// the server answers the client the way it would without a broker in between.
func (m *MSSQLProxy) dialUpstream(ctx context.Context, target *store.Target, user, secret string, clientLogin *tds.Login7) (*upstreamMSSQL, []byte, error) {
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	dialer := net.Dialer{Timeout: m.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	// Bound everything up to a completed upstream login. net.Dialer.Timeout covers
	// only the TCP connect, so a target that accepted the connection and then went
	// silent — mid-TLS, or mid-authentication — parked this goroutine forever
	// holding the just-decrypted plaintext credential, in the window between the
	// session cap and Register where nothing counts, lists or kills it. The
	// deadline is cleared once the session is established, so a healthy long-lived
	// session is never cut.
	if derr := conn.SetDeadline(time.Now().Add(m.dialTimeout)); derr != nil {
		conn.Close()
		return nil, nil, derr
	}
	c := tds.NewConn(conn)

	// PRELOGIN: ask for whole-session encryption. The vaulted credential is
	// about to cross this leg, and TDS password "obfuscation" is a keyless
	// nibble swap — it protects nothing.
	req := tds.NewPreLogin()
	req.Set(tds.PreLoginVersion, []byte{16, 0, 0, 0, 0, 0})
	req.Set(tds.PreLoginEncryption, []byte{tds.EncryptOn})
	req.Set(tds.PreLoginInstOpt, []byte{0x00})
	req.Set(tds.PreLoginThreadID, []byte{0, 0, 0, 0})
	req.Set(tds.PreLoginMARS, []byte{0x00})
	if err := c.WriteMessage(tds.PacketPreLogin, 0, req.Encode()); err != nil {
		conn.Close()
		return nil, nil, err
	}
	_, _, payload, err := c.ReadMessage(maxTDSMessage)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	serverPre, err := tds.ParsePreLogin(payload)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if serverPre.Encryption() == tds.EncryptOn || serverPre.Encryption() == tds.EncryptReq {
		cfg := m.upstreamTLS
		if cfg == nil {
			// No verification configured: keep the documented trust-any posture
			// (warned at startup), matching the PostgreSQL leg and the SSH
			// proxy's unpinned host-key behavior.
			cfg = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // #nosec G402 -- documented fallback; PAM_DB_UPSTREAM_CA/_TLS_VERIFY makes it fail-closed
		} else {
			cfg = cfg.Clone()
			if cfg.ServerName == "" {
				cfg.ServerName = target.Host
			}
		}
		tconn, terr := tds.ClientHandshake(conn, cfg)
		if terr != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("upstream tls: %w", terr)
		}
		conn = tconn
		c = tds.NewConn(conn)
	} else {
		// The server declined encryption. Refuse: the next thing on this wire
		// would be the vaulted credential under TDS's keyless nibble-swap
		// "obfuscation", which protects nothing. Every supported SQL Server
		// offers encryption (self-signed by default), so a refusal here is a
		// misconfigured or impersonated server, not a normal deployment.
		conn.Close()
		return nil, nil, errors.New("upstream declined TLS: refusing to send the vaulted credential over a plaintext link")
	}
	c.SetPacketSize(int(clientLogin.PacketSize))

	// The injection itself: the client's login with its credentials replaced.
	upLogin := *clientLogin
	upLogin.UserName = user
	upLogin.Password = secret
	upLogin.OptionFlags2 &^= 0x80 // SQL authentication, never SSPI
	upLogin.SSPI = nil
	// A federated-authentication token in the feature extension would make the
	// server authenticate the OPERATOR's own identity while the session is
	// audited as the vaulted account — and the spec forbids fIntSecurity
	// alongside it, so the integrated-auth refusal can never catch it. Strip it
	// the same way, keeping the client's other negotiated features.
	if len(upLogin.FeatureExt) > 0 {
		upLogin.FeatureExt = tds.StripFeatures(upLogin.FeatureExt, map[byte]bool{tds.FeatureFedAuth: true})
	}
	body, err := upLogin.Encode()
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if err := c.WriteMessage(tds.PacketLogin7, 0, body); err != nil {
		conn.Close()
		return nil, nil, err
	}
	_, _, resp, err := c.ReadMessage(maxTDSMessage)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	res := tds.WalkLoginResponse(resp, clientLogin.TDS72OrLater())
	if !res.OK {
		conn.Close()
		msg := res.ServerError
		if msg == "" {
			msg = "login rejected"
		}
		// The upstream's own text is logged and audited but never relayed
		// verbatim to the operator, matching dialUpstream on the PostgreSQL leg.
		return nil, nil, fmt.Errorf("upstream login failed: %s", msg)
	}
	// Logged in: clear the handshake deadline so the session itself is not bounded
	// by it.
	if derr := conn.SetDeadline(time.Time{}); derr != nil {
		conn.Close()
		return nil, nil, derr
	}
	up := &upstreamMSSQL{conn: conn, c: c}
	if res.PacketSize > 0 {
		c.SetPacketSize(res.PacketSize)
		up.negotiated = res.PacketSize
	}
	return up, resp, nil
}

// relay brokers messages both ways until either side closes. Client→upstream
// SQLBatch and RPC requests are audited, recorded and policy-checked; every
// other message type is forwarded verbatim, so bulk load, attention signals and
// transaction manager requests still work.
func (m *MSSQLProxy) relay(ctx context.Context, client *tds.Conn, up *upstreamMSSQL, clientConn net.Conn, actor string, target *store.Target, rec *Recording, sid string, tds72 bool) {
	// A per-connection context so a paused step-up is released when either peer
	// disconnects, instead of parking until the step-up TTL elapses.
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var once sync.Once
	stop := func() { cancel(); clientConn.Close(); up.conn.Close() }

	// The client-facing framer is written by BOTH directions — the upstream→
	// client relay and a policy refusal on the client→upstream side — so every
	// write goes through this mutex.
	var cmu sync.Mutex
	sendClient := func(typ byte, body []byte) error {
		cmu.Lock()
		defer cmu.Unlock()
		return client.WriteMessage(typ, 0, body)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // client → upstream
		defer wg.Done()
		defer once.Do(stop)
		defer recoverPanicLog(m.log, "mssql-c2u")
		for {
			typ, status, data, err := client.ReadMessage(maxTDSMessage)
			if err != nil {
				return
			}
			switch typ {
			case tds.PacketSQLBatch, tds.PacketRPC:
				reqs, perr := parseTDSRequest(typ, data)
				if perr != nil {
					// Unreadable. With a command guard configured this must be
					// refused: forwarding a statement the guard could not be
					// applied to is the bypass the guard exists to prevent.
					// Without one, audit it and forward, as the PostgreSQL
					// proxy does for a fast-path call it cannot filter.
					if m.guard != nil {
						m.audit(ctx, actor, "command.blocked",
							fmt.Sprintf("target:%s via:mssql pattern:unparsed-request sql:[unparsed %s]", target.Name, tdsKind(typ)))
						_ = sendClient(tds.PacketTabularResult, tds.Refusal(mssqlErrPolicy, 16,
							"pamv1: request could not be parsed for policy inspection", typ, tds72))
						continue
					}
					if m.recordStatement(ctx, rec, actor, target, "[unparsed "+tdsKind(typ)+" request]", sid) {
						return // recording cap reached: end the session, do not run it unrecorded
					}
					break
				}
				// Every call in the message is inspected, not just the first: an
				// RPC message may carry several, and auditing only the leading
				// one would let a benign call escort arbitrary statements.
				if m.refuseRequests(ctx, relayCtx, sendClient, actor, target, reqs, sid, typ, tds72) {
					continue // refused by policy; the session stays usable
				}
				capped := false
				for _, req := range reqs {
					if m.recordStatement(ctx, rec, actor, target, req.AuditText, sid) {
						capped = true
						break
					}
				}
				if capped {
					return
				}
			}
			// RESETCONNECTION and friends ride the first packet's status bits and
			// must survive re-framing, or connection pooling breaks silently.
			if err := up.c.WriteMessage(typ, status, data); err != nil {
				return
			}
		}
	}()
	go func() { // upstream → client
		defer wg.Done()
		defer once.Do(stop)
		defer recoverPanicLog(m.log, "mssql-u2c")
		for {
			typ, _, data, err := up.c.ReadMessage(maxTDSMessage)
			if err != nil {
				return
			}
			if err := sendClient(typ, data); err != nil {
				return
			}
		}
	}()
	wg.Wait()
}

// parseTDSRequest decodes a client message into the calls it carries. A
// SQLBatch is one; an RPC message may be several.
func parseTDSRequest(typ byte, data []byte) ([]tds.Request, error) {
	if typ == tds.PacketRPC {
		return tds.ParseRPC(data)
	}
	req, err := tds.ParseSQLBatch(data)
	if err != nil {
		return nil, err
	}
	return []tds.Request{req}, nil
}

// refuseRequests applies command control and step-up to every call in a message
// and reports whether the message was refused. A call whose text could not be
// recovered is refused when a guard is configured — an unreadable statement is
// exactly the shape a bypass takes, so it fails closed rather than through.
func (m *MSSQLProxy) refuseRequests(ctx, relayCtx context.Context, sendClient func(byte, []byte) error, actor string, target *store.Target, reqs []tds.Request, sid string, reqType byte, tds72 bool) bool {
	for _, req := range reqs {
		if !req.Recovered && m.guard != nil {
			m.audit(ctx, actor, "command.blocked",
				fmt.Sprintf("target:%s via:mssql pattern:unreadable-parameters sql:%s", target.Name, auditCmd(req.AuditText)))
			_ = sendClient(tds.PacketTabularResult, tds.Refusal(mssqlErrPolicy, 16,
				"pamv1: statement could not be read for policy inspection", reqType, tds72))
			return true
		}
		// Guard EVERY recovered character parameter, not only the one believed
		// to be the statement: which parameter carries SQL varies by procedure.
		for _, text := range req.GuardTexts() {
			if m.blockedStatement(ctx, sendClient, actor, target, text, reqType, tds72) {
				return true
			}
			if m.stepUpRefused(relayCtx, sendClient, actor, target, text, sid, reqType, tds72) {
				return true
			}
		}
		if len(req.GuardTexts()) == 0 {
			if m.blockedStatement(ctx, sendClient, actor, target, req.AuditText, reqType, tds72) {
				return true
			}
		}
	}
	return false
}

// tdsKind names a request type for an audit detail.
func tdsKind(typ byte) string {
	if typ == tds.PacketRPC {
		return "rpc"
	}
	return "batch"
}

// recordStatement audits and records a single statement, and publishes it to
// the live hub so a supervisor can watch the session. The audit action is the
// same `db.query` the PostgreSQL proxy uses — disambiguated by via:mssql —
// because the OCSF exporter and the analytics engine key off that vocabulary,
// and a fresh one would silently exclude every SQL Server session from SIEM
// export and risk scoring.
// It reports whether the recording size cap was reached, in which case the caller
// must END the session: Recording.Write latches errRecordingLimit, so a discarded
// error meant every statement past PAM_MAX_RECORDING_MB was dropped and the
// session continued UNRECORDED with no session.record_limit audit — the same
// defect as the PostgreSQL proxy, fixed with it.
func (m *MSSQLProxy) recordStatement(ctx context.Context, rec *Recording, actor string, target *store.Target, sql, sid string) (limitReached bool) {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" {
		return false
	}
	m.audit(ctx, actor, "db.query", "target:"+target.Name+" via:mssql sql:"+auditCmd(trimmed))
	line := []byte("mssql> " + trimmed + "\r\n")
	if rec != nil {
		if _, werr := rec.Write(line); werr != nil {
			if errors.Is(werr, errRecordingLimit) {
				m.audit(ctx, actor, "session.record_limit",
					"target:"+target.Name+" via:mssql reason:recording-size-cap")
				m.log.Warn("ending session: recording size cap reached", "target", target.Name, "actor", actor)
				return true
			}
			m.log.Error("session recording write failed", "target", target.Name, "err", werr)
		}
	}
	m.live.Publish(sid, line)
	return false
}

// stepUpRefused reports whether a statement matched the step-up guard and its
// supervisor decision was a denial (or timeout) — in which case the caller
// refuses the statement but keeps the session open.
func (m *MSSQLProxy) stepUpRefused(ctx context.Context, sendClient func(byte, []byte) error, actor string, target *store.Target, sql, sid string, reqType byte, tds72 bool) bool {
	if m.stepupGuard == nil || m.stepup == nil || sid == "" {
		return false
	}
	pat, match := m.stepupGuard.Blocked(sql)
	if !match {
		return false
	}
	m.audit(ctx, actor, "db.stepup_required", fmt.Sprintf("target:%s via:mssql pattern:%s sql:%s", target.Name, pat, auditCmd(sql)))
	if m.live != nil {
		m.live.Publish(sid, []byte("mssql> [step-up: awaiting supervisor approval] "+strings.TrimSpace(sql)+"\r\n"))
	}
	if m.stepup.Await(ctx, sid, actor, strings.TrimSpace(sql), m.stepupTTL) {
		m.audit(ctx, actor, "db.stepup_approved", fmt.Sprintf("target:%s via:mssql sql:%s", target.Name, auditCmd(sql)))
		return false // approved — the statement proceeds
	}
	m.audit(ctx, actor, "db.stepup_denied", fmt.Sprintf("target:%s via:mssql sql:%s", target.Name, auditCmd(sql)))
	_ = sendClient(tds.PacketTabularResult,
		tds.Refusal(mssqlErrPolicy, 16, "pamv1: statement requires supervisor approval (denied or timed out)", reqType, tds72))
	return true
}

// blockedStatement reports whether sql is blocked by command control. When it
// is, it audits command.blocked and sends the client an error token.
//
// The refused request is never forwarded, and with MARS disabled there is no
// pipelining, so the upstream cannot desync and the session always stays
// usable — there is no TDS analogue of the PostgreSQL extended-protocol
// fail-closed branch.
func (m *MSSQLProxy) blockedStatement(ctx context.Context, sendClient func(byte, []byte) error, actor string, target *store.Target, sql string, reqType byte, tds72 bool) bool {
	pat, blocked := m.guard.Blocked(sql)
	if !blocked {
		return false
	}
	m.audit(ctx, actor, "command.blocked", fmt.Sprintf("target:%s via:mssql pattern:%s sql:%s", target.Name, pat, auditCmd(sql)))
	_ = sendClient(tds.PacketTabularResult,
		tds.Refusal(mssqlErrPolicy, 16, "pamv1: command blocked by policy", reqType, tds72))
	return true
}

// fail sends an error token to the operator's client and ends the exchange.
func (m *MSSQLProxy) fail(c *tds.Conn, number uint32, class byte, msg string, tds72 bool) {
	_ = c.WriteMessage(tds.PacketTabularResult, 0, tds.Refusal(number, class, msg, tds.PacketLogin7, tds72))
}

// deny audits a refused session and reports it to the client.
func (m *MSSQLProxy) deny(ctx context.Context, c *tds.Conn, actor, login, reason string, tds72 bool) {
	m.log.Warn("db session denied", "actor", actor, "login", auditField(login, 64), "reason", reason, "protocol", "mssql")
	m.audit(ctx, actor, "db.session.denied", "login:"+auditField(login, 64)+" via:mssql reason:"+reason)
	m.fail(c, mssqlErrLoginFailed, 14, "pamv1: "+reason, tds72)
}

// noteBreakGlass raises the emergency-access signal for this listener; see the
// shared implementation in proxy.go.
func (m *MSSQLProxy) noteBreakGlass(ctx context.Context, principal *auth.Principal, detail string) {
	noteBreakGlass(ctx, m.store, m.log, m.onBreakGlass, principal, detail)
}
