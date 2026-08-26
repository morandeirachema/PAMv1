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
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/cmdguard"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/posture"
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
	Addr            string            // listen address, e.g. ":1433"; "off" disables it
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
	AllowedProtocols []string // protocol allowlist (must include "mssql")
	RequireRecording bool     // refuse a session that cannot be recorded
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
	// CommandAllowGuard (Phase 131), once set, narrows every command-control
	// path to ONLY commands it matches; deny still wins. nil = deny-only.
	CommandAllowGuard *cmdguard.Guard
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
	// pol is the protocol-independent per-statement policy shared with the
	// PostgreSQL proxy (see sqlproxy.go), built once at construction.
	pol sqlPolicy
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
		listener: listener{
			log:          logging.Component("mssqlproxy"),
			store:        st,
			component:    "mssqlproxy",
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
	if m.stepupTTL <= 0 {
		m.stepupTTL = 2 * time.Minute
	}
	m.gate = &gates{
		store:        st,
		vault:        v,
		log:          m.log,
		allowedProto: m.allowedProto,
		requireApprv: m.requireApprv,
		ungated:      m.ungated,
		ticketCheck:  m.ticketCheck,
		sessions:     m.sessions,
		posture:      m.posture,
	}
	m.pol = sqlPolicy{
		guard:       m.guard,
		allowGuard:  m.allowGuard,
		stepupGuard: m.stepupGuard,
		stepup:      m.stepup,
		stepupTTL:   m.stepupTTL,
		live:        m.live,
		prompt:      "mssql> ",
		via:         "mssql",
		viaInQuery:  true, // SQL Server tags db.query/step-up/deny details with via:mssql
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
// and force-closes active connections so the drain is bounded. The accept/drain
// lifecycle lives in the embedded listener; this only logs the SQL Server
// startup line and dispatches handleConn.
func (m *MSSQLProxy) Serve(ctx context.Context, ln net.Listener) error {
	m.log.Info("database proxy listening", "addr", ln.Addr().String(), "protocol", "mssql")
	return m.serve(ctx, ln, m.handleConn, "mssql proxy accept error; retrying", "mssql-connection")
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

	// Throttle BEFORE reading LOGIN7. The read is already bounded, so unlike the
	// PostgreSQL proxy there was no allocation hazard here — but the limiter's
	// job is to stop an abusive source from costing anything, and a peer that
	// is already rate-limited should not get to make us parse one more login.
	// Refused with a bare close rather than a TDS error: we have not read the
	// client's TDS version yet, so we cannot frame a reply it would understand.
	if !m.authLimiter.Allow(remoteHost(nConn.RemoteAddr())) {
		m.log.Warn("mssql authentication rate limited", "remote", remote)
		return
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

	// --- Authorization gates ---
	// Break-glass is noted here (it is not itself a gate): every entry point that
	// resolves its own principal must raise the emergency-access signal. It runs
	// just before admit — admit's first gate (tunnel-only) can never fire for a
	// break-glass principal, since the two token types are mutually exclusive, so
	// the pre-admit position is behaviour-identical to the old post-tunnel one.
	m.noteBreakGlass(ctx, principal, "mssql login:"+auditField(loginName, 64))

	database := login.Database
	// The shared admission sequence (gates.go, admit) runs every gate in the fixed
	// order — identical to the PostgreSQL proxy, since anything that differs between
	// the two is the transport, never the policy — and decrypts just-in-time only
	// if all pass. refuse() maps whatever it returns to SQL Server's own refusal.
	credUser, targetName := splitLogin(loginName)
	res := m.gate.admit(ctx, admitRequest{
		principal:      principal,
		targetName:     targetName,
		credUser:       credUser,
		remoteAddr:     remote,
		expectProtocol: "mssql",
		startAudit: func(t *store.Target, cr *store.Credential) (string, string) {
			return "db.session.start", fmt.Sprintf("target:%s db:%s cred_user:%s via:mssql", t.Name, database, cr.Username)
		},
	})
	if res.outcome != admitOK {
		m.refuse(ctx, c, res, actor, loginName, tds72)
		return
	}
	target, cred, secret := res.target, res.cred, res.secret

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
		m.live.Publish(sid, watermarkBanner(actor, target.Name))
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
					if sqlRecordQuery(ctx, &m.listener, &m.pol, rec, actor, target, "[unparsed "+tdsKind(typ)+" request]", sid) {
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
					if sqlRecordQuery(ctx, &m.listener, &m.pol, rec, actor, target, req.AuditText, sid) {
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
	// cl adapts this message's TDS framing (reqType/tds72 vary per message) to the
	// shared per-statement pipeline's sqlClient interface (see sqlproxy.go). TDS
	// refusals never end the session — with MARS off there is no pipelining to
	// desync — so the shared calls always pass extended=false.
	cl := mssqlSQLClient{send: sendClient, reqType: reqType, tds72: tds72}
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
			if sqlBlockedStatement(ctx, &m.listener, &m.pol, cl, actor, target, text, false) {
				return true
			}
			if sqlStepUpRefused(relayCtx, &m.listener, &m.pol, cl, actor, target, text, sid, false) {
				return true
			}
		}
		if len(req.GuardTexts()) == 0 {
			if sqlBlockedStatement(ctx, &m.listener, &m.pol, cl, actor, target, req.AuditText, false) {
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

// mssqlSQLClient adapts this message's TDS framing to the shared per-statement
// pipeline's sqlClient interface (see sqlproxy.go). A refused request is never
// forwarded, and with MARS disabled there is no pipelining, so the upstream
// cannot desync and the session always stays usable — there is no TDS analogue
// of the PostgreSQL extended-protocol fail-closed branch, so refuseFatal is
// never reached and behaves the same as refuse. reqType/tds72 come from the
// message being refused, so a fresh client is built per message.
//
// The shared db.query / command.blocked / db.stepup_* vocabulary is reused (tagged
// via:mssql) deliberately: the OCSF exporter and the analytics engine key off
// that vocabulary, and a fresh action name would silently exclude every SQL
// Server session from SIEM export and risk scoring.
type mssqlSQLClient struct {
	send    func(byte, []byte) error
	reqType byte
	tds72   bool
}

// refuse sends a TDS error token (user-defined number 50000, class 16), leaving
// the session usable.
func (c mssqlSQLClient) refuse(msg string) {
	_ = c.send(tds.PacketTabularResult, tds.Refusal(mssqlErrPolicy, 16, msg, c.reqType, c.tds72))
}

// refuseFatal has no distinct TDS encoding (no extended-protocol desync to
// guard against), so it refuses exactly as refuse does; the shared pipeline
// never asks the SQL Server proxy for a fatal refusal.
func (c mssqlSQLClient) refuseFatal(msg string) { c.refuse(msg) }

// fail sends an error token to the operator's client and ends the exchange.
func (m *MSSQLProxy) fail(c *tds.Conn, number uint32, class byte, msg string, tds72 bool) {
	_ = c.WriteMessage(tds.PacketTabularResult, 0, tds.Refusal(number, class, msg, tds.PacketLogin7, tds72))
}

// deny audits a refused session and reports it to the client.
func (m *MSSQLProxy) deny(ctx context.Context, c *tds.Conn, actor, login, reason string, tds72 bool) {
	m.log.Warn("db session denied", "actor", actor, "login", auditField(login, 64), "reason", reason, "protocol", "mssql")
	sqlDeny(ctx, &m.listener, &m.pol, actor, login, reason, func(msg string) { m.fail(c, mssqlErrLoginFailed, 14, msg, tds72) })
}

// refuse maps an admit() refusal to SQL Server's wire refusal and audit,
// preserving the exact error numbers/classes, audit action names and details
// each gate has always used — the transport twin of the PostgreSQL proxy's
// refuse. admit already emitted the audits identical across all three proxies
// (access.denied for the approval and vendor denials, and
// credential.decrypt_failed) and the shared check-failed error logs; this adds
// only what is specific to the TDS transport. gateProtocolProxyable is an
// SSH-only gate and never occurs here (this proxy sets no proxyable hook).
func (m *MSSQLProxy) refuse(ctx context.Context, c *tds.Conn, res admitResult, actor, login string, tds72 bool) {
	switch res.gate {
	case gateTunnelOnly:
		// Audited here (with the short reason slug shared by the SSH proxy and the
		// HTTP authz middleware) and failed directly — NOT via deny(), which would
		// audit a second, differently-worded db.session.denied row for the same
		// refusal.
		m.audit(ctx, actor, "db.session.denied", "login:"+auditField(login, 64)+" reason:tunnel-only-token")
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: this token may only be used by the in-portal viewer", tds72)
	case gateEnrollOnly:
		m.audit(ctx, actor, "db.session.denied", "login:"+auditField(login, 64)+" reason:mfa-enrollment-incomplete")
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: complete MFA enrollment first", tds72)
	case gateExtensionOnly:
		m.audit(ctx, actor, "db.session.denied", "login:"+auditField(login, 64)+" reason:extension-scoped-token")
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: a browser-extension token cannot open a database session", tds72)
	case gateMFAPending:
		m.audit(ctx, actor, "db.session.denied", "login:"+auditField(login, 64)+" reason:mfa-webauthn-pending")
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: complete WebAuthn sign-in first", tds72)
	case gateRoleConnect:
		m.deny(ctx, c, actor, login, "your role may not open sessions", tds72)
	case gateIPAllowlist:
		m.deny(ctx, c, actor, login, "this account may not connect from this network", tds72)
	case gatePosture:
		m.deny(ctx, c, actor, login, "your device failed its posture check", tds72)
	case gateResolve:
		m.deny(ctx, c, actor, login, res.reason, tds72)
	case gateProtocolMatch:
		m.deny(ctx, c, actor, login, "target is not a mssql target", tds72)
	case gateProtocolAllowed:
		m.deny(ctx, c, actor, login, "protocol not allowed by policy", tds72)
	case gateTargetGrants:
		// admit logged "target grants lookup failed"; fail closed on the wire.
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: authorization check failed", tds72)
	case gateTargetPolicy:
		m.deny(ctx, c, actor, login, "not authorized for this target", tds72)
	case gateApprovalPolicy, gateApprovalClaim:
		// admit logged the specific approval error; fail closed on the wire.
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: approval check failed", tds72)
	case gateApproval:
		// admit already audited access.denied with the reason.
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: connection requires an approved access request", tds72)
	case gateVendorCheck:
		// admit logged "vendor gate check failed"; fail closed on the wire.
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: authorization check failed", tds72)
	case gateVendor:
		// admit already audited access.denied reason:vendor-contract.
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: vendor access requires an approved, in-window contract grant", tds72)
	case gateSessionLimit:
		m.audit(ctx, actor, "db.session.denied", "target:"+res.target.Name+" reason:session-limit")
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: too many concurrent sessions", tds72)
	case gateAudit:
		// admit's fail-closed db.session.start write did not land; refuse.
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: audit log unavailable; session refused", tds72)
	case gateDecrypt:
		// admit already audited credential.decrypt_failed and logged the error.
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: credential unavailable", tds72)
	default:
		m.log.Error("unhandled admit refusal on the SQL Server proxy", "gate", int(res.gate), "actor", actor)
		m.fail(c, mssqlErrLoginFailed, 14, "pamv1: authorization check failed", tds72)
	}
}

// noteBreakGlass raises the emergency-access signal for this listener; see the
// shared implementation in proxy.go.
func (m *MSSQLProxy) noteBreakGlass(ctx context.Context, principal *auth.Principal, detail string) {
	noteBreakGlass(ctx, m.store, m.log, m.onBreakGlass, principal, detail)
}
