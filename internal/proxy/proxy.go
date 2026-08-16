// Package proxy is the pamv1 SSH session gateway. Operators connect to it
// instead of to targets directly; the proxy authenticates them, pulls the
// right credential from the vault and injects it just-in-time (JIT) into the
// upstream SSH connection — the operator never sees the secret. Every session
// is recorded and audited.
//
// Login convention (Phase 2, before the AD connector):
//
//	ssh -p 2222 <target-name>@pam-host                 # first credential of the target
//	ssh -p 2222 <cred-user>@<target-name>@pam-host     # a specific credential
//
// The SSH password presented to the proxy is the PAM API key; AD-backed user
// auth replaces this in Phase 3.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/morandeirachema/pamv1/internal/auditfmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/cmdguard"
	"github.com/morandeirachema/pamv1/internal/icap"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/posture"
	"github.com/morandeirachema/pamv1/internal/ratelimit"
	"github.com/morandeirachema/pamv1/internal/recording"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/sshca"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/vault"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

type Config struct {
	Addr         string     // listen address, e.g. ":2222"
	HostKey      ssh.Signer // proxy SSH host key
	RecordingDir string     // where session recordings are written
	DialTimeout  time.Duration
	Sessions     *session.Registry // live-session registry (optional)
	// RequireApproval gates every session behind an approved access request
	// (global OT policy); per-target Target.RequireApproval also applies.
	RequireApproval bool
	// UpstreamHostKey verifies the target's SSH host key (e.g. a known_hosts
	// callback). nil trusts any upstream key — insecure, and logged loudly.
	UpstreamHostKey ssh.HostKeyCallback
	// OnBreakGlass, if set, is called when a session is opened with the emergency
	// key. The proxies resolve their own principal outside the HTTP authz
	// middleware, so — like every such entry point — they must raise the
	// break-glass signal themselves; `main` points this at the alerter and the
	// Prometheus counter. Without it an emergency-key SSH/DB session bypassed the
	// approval gate leaving only a session.start row: no breakglass.access event,
	// no alert, no metric.
	OnBreakGlass func(ctx context.Context, actor, detail string)

	// OnSessionEnd, if set, is called with the credential ID when a proxied
	// session ends — used to force credential rotation after use. It runs in a
	// goroutine and must not block.
	OnSessionEnd func(credentialID int64)
	// AllowedProtocols, when non-empty, restricts which target protocols the proxy
	// will broker (the proxy only handles "ssh"; this lets an OT policy forbid it).
	AllowedProtocols []string
	// WinRMRunner, if set, lets the proxy broker an interactive command loop to
	// WinRM (Windows) targets; nil disables WinRM through the proxy.
	WinRMRunner winrm.Runner
	// Jump, if set, reaches SSH targets through an SSH bastion (for legacy
	// equipment only accessible via a jump host).
	Jump *JumpConfig
	// RequireRecording refuses a session when its recording cannot be created,
	// rather than proceeding unrecorded (fail-closed session auditing).
	RequireRecording bool
	// PortForward enables client-initiated direct-tcpip channels (ssh -L
	// style forwarding), scoped to the connected target's own host only —
	// see handleDirectTCPIP (Phase 141). The PAM_SSH_PORT_FORWARD default is
	// true (matching SFTPMode's default-allow posture: an operator already
	// fully authorized for this target loses nothing by also being able to
	// forward to it), resolved by internal/config before reaching here.
	// Forwarded bytes are opaque, so RequireRecording refuses forwarding
	// outright rather than attempting an unrecordable session, and
	// forwarding is always refused for an observer session or while
	// RequireSupervision is configured — neither has a mechanism to cover
	// it.
	PortForward bool
	// RequireSupervision refuses an interactive session to proceed until a
	// supervisor actively watches it (the live hub reports a subscriber) or
	// SupervisionTimeout elapses. Observer sessions and break-glass access are
	// exempt.
	RequireSupervision bool
	// SupervisionTimeout bounds the wait RequireSupervision imposes. Zero means
	// no grace period: a session is refused unless already watched.
	SupervisionTimeout time.Duration
	// EncryptRecordings seals session recordings at rest with a per-recording
	// data key wrapped by the vault KEK (PAM_RECORDING_ENCRYPT).
	EncryptRecordings bool
	// OpaqueRecordingNames names recording files by timestamp + random hex; the
	// target/actor metadata then lives only in the audited session.record event
	// (PAM_RECORDING_OPAQUE_NAMES, Phase 48).
	OpaqueRecordingNames bool
	// CommandGuard, when set, blocks commands matching its deny patterns on the
	// exec and WinRM paths (Phase 16 command control). nil disables it.
	CommandGuard *cmdguard.Guard
	// CommandAllowGuard (Phase 131), once set, narrows every command-control
	// path to ONLY commands it matches; deny still wins. nil = deny-only.
	CommandAllowGuard *cmdguard.Guard
	// Live, when set, receives a copy of every recorded output byte keyed by
	// session id, so a supervisor can watch a session live (Phase 16).
	Live *session.Hub
	// Shares is the input-sharing mux for session-sharing joins (Phase 116) —
	// the SAME instance passed to api.Options, since an external/vendor
	// invite is redeemed over HTTP, not SSH, and must reach this proxy's mux
	// through the shared object. nil disables session-sharing (every
	// interactive SSH session behaves exactly as before this phase).
	Shares *session.ShareRegistry
	// CA, when set, enables Zero Standing Privilege (Phase 22): for a credential
	// of type "ssh_ca" the proxy mints a short-lived SSH user certificate signed
	// by this authority and authenticates upstream with it — no standing secret is
	// stored for the account (the target trusts the CA via TrustedUserCAKeys).
	CA *sshca.CertAuthority
	// CertTTL is how long a minted ZSP certificate is valid (default 2m).
	CertTTL time.Duration
	// AuthRatePerMin throttles authentication attempts per source IP per minute,
	// limiting online guessing of the PAM key presented as the SSH password
	// (0 disables).
	AuthRatePerMin int
	// MaxRecordingBytes caps a single session recording's output (0 = unlimited);
	// a session that exceeds it is terminated rather than run unrecorded.
	MaxRecordingBytes int64
	// SFTPMode is the file-transfer policy for SFTP (an SSH subsystem) sessions:
	// SFTPAllow (default, forward + audit every operation), SFTPReadOnly (refuse
	// writes), or SFTPDeny (refuse the subsystem). An empty value means SFTPAllow.
	SFTPMode SFTPMode
	// SFTPPathGuard, when set, refuses any SFTP operation whose path matches one
	// of its deny patterns — in EVERY mode, including reads, since denying a path
	// that can still be downloaded protects nothing (PAM_SSH_SFTP_DENY_FILE,
	// Phase 51). It reuses the cmdguard engine so one regex-denylist semantic
	// covers commands and paths alike.
	SFTPPathGuard *cmdguard.Guard
	// SFTPCapture records the CONTENT of files moved over SFTP (Phase 59):
	// uploads, downloads, or all. Each transferred file becomes a chunk-log
	// artifact in the recording directory, sealed and hash-chained like a
	// session recording (PAM_SSH_SFTP_CAPTURE; off by default).
	SFTPCapture SFTPCaptureMode
	// TicketCheck, when set, re-validates the ITSM ticket on the access request
	// that admits a connection, at connect time rather than at request time
	// (PAM_TICKET_REVALIDATE, Phase 60). nil leaves the pre-Phase-60 behaviour.
	TicketCheck store.TicketChecker
	// PostureAttestor (optional) validates a user's live device posture on
	// every connect (Phase 133); nil disables posture checking.
	PostureAttestor *posture.Attestor
	// SFTPCaptureMaxBytes caps the captured bytes per file (0 = unlimited).
	// Beyond the cap the transfer is REFUSED, not merely unrecorded — the same
	// posture as the session-recording cap (PAM_SSH_SFTP_CAPTURE_MAX_MB).
	SFTPCaptureMaxBytes int64
	// ICAPClient (optional) submits each finalized SFTP transfer to an ICAP
	// RESPMOD service for AV/DLP scanning (Phase 143); nil disables it.
	// Detection only, not prevention — see sftpcapture.go's finalizeLocked
	// for why a whole-file scan cannot block a transfer before it lands.
	ICAPClient *icap.Client
	// EndpointAgents (optional, Phase 153) is the SHARED registry of connected
	// outbound-only endpoint agents — the same instance handed to api.Options,
	// since the API reports live status from it. nil disables the feature:
	// the "endpoint-agent:<name>" login is refused and a target bound to an
	// agent row is unreachable (never silently dialed direct).
	EndpointAgents *session.EndpointAgents
}

// JumpConfig configures reaching SSH targets through an SSH bastion.
type JumpConfig struct {
	Addr    string              // bastion host:port
	User    string              // bastion login
	KeyPEM  string              // bastion private key (OpenSSH PEM)
	HostKey ssh.HostKeyCallback // verifies the bastion's host key (nil = trust-any)
}

type Proxy struct {
	listener // shared accept/drain lifecycle: log, store, conns, bg, onSessionEnd, ln, Addr, audit

	vault        *vault.Vault
	recKey       recording.KeyWrapper // non-nil = seal recordings at rest
	opaqueNames  bool                 // name recordings by timestamp+hex, not target/actor
	resolver     *auth.Resolver
	sshCfg       *ssh.ServerConfig
	hostKey      ssh.Signer
	recordingDir string
	dialTimeout  time.Duration
	sessions     *session.Registry
	requireApprv bool
	upstreamHKCB ssh.HostKeyCallback
	onBreakGlass func(ctx context.Context, actor, detail string)
	allowedProto map[string]bool
	winrm        winrm.Runner
	upstreamDial func(addr string) (net.Conn, error)
	chain        *recordChain
	requireRec   bool
	requireSup   bool
	supTimeout   time.Duration
	portForward  bool
	guard        *cmdguard.Guard
	allowGuard   *cmdguard.Guard
	live         *session.Hub
	// shares is the SAME *session.ShareRegistry instance the API layer's
	// external/vendor redemption path uses (wired once in main.go, like
	// sessions/live) — an email+QR join is redeemed over HTTP, not SSH, so it
	// must reach this proxy's mux through the shared object, not a
	// proxy-private one the API could never see.
	shares      *session.ShareRegistry
	ca          *sshca.CertAuthority
	certTTL     time.Duration
	authLimiter *ratelimit.Limiter
	maxRecBytes int64
	sftpMode    SFTPMode
	sftpPaths   *cmdguard.Guard
	sftpCapture SFTPCaptureMode
	sftpCapMax  int64
	icapClient  *icap.Client
	ticketCheck store.TicketChecker
	posture     *posture.Attestor
	gate        *gates // the shared admission-gate sequence (gates.go)
	// endpointAgents is the shared live registry of connected endpoint agents
	// (Phase 153); nil = feature disabled.
	endpointAgents *session.EndpointAgents

	// pending carries the resolved *auth.Principal from authenticate (where the
	// SSH password is available) to handleConn (which runs the gates), keyed by a
	// per-connection token stashed in the SSH permissions. It exists so the real
	// principal reaches the gates — CanConnectTarget must see the actual roles and
	// capabilities, not a partial reconstruction that a future field could
	// silently outgrow. Entries are removed by handleConn (LoadAndDelete); a
	// stale-entry sweep in authenticate bounds the map against the rare
	// post-auth handshake failure where handleConn never runs to remove one.
	pending  sync.Map // token(string) -> pendingPrincipal
	princSeq atomic.Uint64
}

// pendingPrincipal is a principal awaiting handoff from authenticate to
// handleConn, stamped with its store time so a stale entry (one whose handshake
// failed after authentication) can be swept.
type pendingPrincipal struct {
	principal *auth.Principal
	at        time.Time
}

// New constructs a Proxy from the store, vault, auth resolver and cfg. It
// requires a HostKey and resolver, defaults RecordingDir and DialTimeout when
// unset, and warns loudly (falling back to InsecureIgnoreHostKey) when no
// upstream host-key callback is supplied.
func New(st store.Store, v *vault.Vault, resolver *auth.Resolver, cfg Config) (*Proxy, error) {
	if cfg.HostKey == nil {
		return nil, errors.New("proxy: HostKey is required")
	}
	if resolver == nil {
		return nil, errors.New("proxy: resolver is required")
	}
	if cfg.RecordingDir == "" {
		cfg.RecordingDir = "recordings"
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	p := &Proxy{
		listener: listener{
			log:          logging.Component("proxy"),
			store:        st,
			component:    "proxy",
			onSessionEnd: cfg.OnSessionEnd,
			conns:        make(map[net.Conn]struct{}),
		},
		vault:          v,
		recKey:         recKeyFor(cfg.EncryptRecordings, v),
		opaqueNames:    cfg.OpaqueRecordingNames,
		resolver:       resolver,
		hostKey:        cfg.HostKey,
		recordingDir:   cfg.RecordingDir,
		dialTimeout:    cfg.DialTimeout,
		sessions:       cfg.Sessions,
		requireApprv:   cfg.RequireApproval,
		upstreamHKCB:   cfg.UpstreamHostKey,
		onBreakGlass:   cfg.OnBreakGlass,
		allowedProto:   protocolSet(cfg.AllowedProtocols),
		winrm:          cfg.WinRMRunner,
		chain:          newRecordChain(cfg.RecordingDir),
		requireRec:     cfg.RequireRecording,
		requireSup:     cfg.RequireSupervision,
		portForward:    cfg.PortForward,
		supTimeout:     cfg.SupervisionTimeout,
		guard:          cfg.CommandGuard,
		allowGuard:     cfg.CommandAllowGuard,
		live:           cfg.Live,
		shares:         cfg.Shares,
		endpointAgents: cfg.EndpointAgents,
		ca:             cfg.CA,
		certTTL:        cfg.CertTTL,
		authLimiter:    ratelimit.New(cfg.AuthRatePerMin),
		maxRecBytes:    cfg.MaxRecordingBytes,
		sftpMode:       cfg.SFTPMode,
		sftpPaths:      cfg.SFTPPathGuard,
		sftpCapture:    cfg.SFTPCapture,
		sftpCapMax:     cfg.SFTPCaptureMaxBytes,
		icapClient:     cfg.ICAPClient,
		ticketCheck:    cfg.TicketCheck,
		posture:        cfg.PostureAttestor,
	}
	p.gate = &gates{
		store:        st,
		vault:        v,
		log:          p.log,
		allowedProto: p.allowedProto,
		requireApprv: p.requireApprv,
		ticketCheck:  p.ticketCheck,
		sessions:     p.sessions,
		posture:      p.posture,
	}
	if p.certTTL <= 0 {
		p.certTTL = 2 * time.Minute
	}
	if p.sftpMode == "" {
		p.sftpMode = SFTPAllow
	}
	if p.sftpCapture == "" {
		p.sftpCapture = SFTPCaptureOff
	}
	if p.upstreamHKCB == nil {
		p.log.Warn("upstream SSH host keys are NOT verified (set PAM_SSH_KNOWN_HOSTS to pin them)")
		p.upstreamHKCB = ssh.InsecureIgnoreHostKey() // #nosec G106 -- documented trust-any default; pin with PAM_SSH_KNOWN_HOSTS
	}
	if cfg.Jump != nil {
		dial, err := jumpDial(*cfg.Jump, cfg.DialTimeout)
		if err != nil {
			return nil, fmt.Errorf("proxy: jump host: %w", err)
		}
		p.upstreamDial = dial
		p.log.Info("SSH targets routed through a jump host", "jump", cfg.Jump.Addr)
	}
	p.sshCfg = &ssh.ServerConfig{PasswordCallback: p.authenticate}
	p.sshCfg.AddHostKey(cfg.HostKey)
	return p, nil
}

// recKeyFor returns the key wrapper to seal recordings with, or nil to keep
// writing them in the clear. A shared helper so both proxies express the same
// rule: encryption is opt-in, and impossible without a vault.
func recKeyFor(enabled bool, v *vault.Vault) recording.KeyWrapper {
	if !enabled || v == nil {
		return nil
	}
	return v
}

// authenticate resolves the SSH password (a PAM key or per-user token) into a
// Principal and stashes it with the requested target/credential in the
// connection permissions; the role check and target resolution happen after
// the handshake.
func (p *Proxy) authenticate(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	// Throttle online guessing of the PAM key before doing any resolve work.
	if !p.authLimiter.Allow(remoteHost(c.RemoteAddr())) {
		// Log but do NOT append. The failures that preceded the throttle are the
		// signal; writing one audit row per attempt under a flood makes the audit
		// trail the amplifier, and with the HMAC chain enabled the retention
		// worker deliberately refuses to prune those rows. This mirrors the API
		// middleware, which returns before auditing for exactly this reason.
		p.log.Warn("authentication rate limited", "login", auditField(c.User(), 64), "remote", c.RemoteAddr().String())
		return nil, fmt.Errorf("pamv1: too many attempts; try again shortly")
	}
	// An outbound-only endpoint agent (Phase 153) authenticates as
	// "endpoint-agent:<name>" with its own bearer key — a wholly separate
	// identity kind, resolved against endpoint_agents, never through the human
	// resolver below. Checked after the rate limit (an agent key is as
	// guessable as any other) and before anything else, since nothing that
	// follows — target parsing, principals, gates — applies to it.
	if name, ok := endpointAgentLogin(c.User()); ok {
		return p.authenticateEndpointAgent(c, name, password)
	}
	principal, err := p.resolver.Resolve(context.Background(), string(password))
	if err != nil {
		remote := c.RemoteAddr().String()
		p.log.Warn("authentication failed", "login", c.User(), "remote", remote)
		// Record failed proxy auth in the audit store (not just the log), so
		// credential-stuffing against the proxy is visible in the system-of-record.
		//
		// The login is quoted and bounded before it becomes the audit ACTOR: it is
		// unauthenticated, attacker-chosen, and limited only by the SSH packet
		// size, so raw it could carry newlines, forged `key:value` pairs, or a
		// quarter-megabyte of padding into a column the retention worker refuses
		// to prune when the HMAC chain is enabled.
		p.audit(context.Background(), auditField(c.User(), 64), "proxy.auth_failed", "remote:"+remote)
		return nil, fmt.Errorf("pamv1: authentication failed")
	}
	// A tunnel-scoped token (the in-portal RDP/VNC viewer) authenticates ONLY at
	// its viewer tunnel. It travels in a WebSocket URL — browsers cannot set
	// headers on a WS handshake — so a copy lifted from a reverse-proxy or access
	// log must not open a shell. The HTTP middleware refuses it; this is the same
	// refusal for the proxy, which resolves its own principal and would otherwise
	// accept it as a password for ANY target the owner may reach, for an
	// unbounded session, from a 60-second token.
	if principal.TunnelOnly {
		remote := c.RemoteAddr().String()
		p.log.Warn("tunnel-scoped token presented to the SSH proxy", "actor", principal.Name, "remote", remote)
		p.audit(context.Background(), principal.Name, "session.denied",
			"login:"+auditField(c.User(), 64)+" remote:"+remote+" reason:tunnel-only-token")
		return nil, fmt.Errorf("pamv1: authentication failed")
	}
	p.noteBreakGlass(context.Background(), principal, "ssh login:"+auditField(c.User(), 64)+" remote:"+c.RemoteAddr().String())

	// A session-share join (Phase 116): the ENTIRE username is "join:<token>",
	// not a "creduser@target" login — a join has no target of its own, the
	// already-approved invite names the session it attaches to. Checked before
	// the +observe/splitLogin parsing below, which does not apply here. The
	// joining principal authenticated with their OWN password above (the
	// resolver call is unconditional), so ext["principal"] is their real
	// identity, not a token-derived one — every action they take joined is
	// attributed to a real, accountable actor. An enroll-only principal
	// (MFA policy requires enrollment, not yet completed) is refused here,
	// same as it would be refused doing anything else privileged.
	if token, ok := strings.CutPrefix(c.User(), "join:"); ok {
		if principal.EnrollOnly {
			p.audit(context.Background(), principal.Name, "session.share_join_denied",
				"reason:enrollment-incomplete")
			return nil, fmt.Errorf("pamv1: authentication failed")
		}
		ext := map[string]string{
			"login":      c.User(),
			"principal":  principal.Name,
			"role":       string(principal.Role),
			"roles":      auth.JoinRoles(principal.Roles),
			"join_token": token,
		}
		if principal.Can(auth.CapConnect) {
			ext["can_connect"] = "true"
		}
		now := time.Now()
		token36 := strconv.FormatUint(p.princSeq.Add(1), 36)
		p.pending.Store(token36, pendingPrincipal{principal: principal, at: now})
		ext["princ"] = token36
		return &ssh.Permissions{Extensions: ext}, nil
	}

	// A "+observe" suffix requests a read-only (view-only) session: the operator
	// sees output but their keystrokes and exec requests are dropped.
	login := c.User()
	observe := false
	if rest, ok := strings.CutSuffix(login, "+observe"); ok {
		observe, login = true, rest
	}
	credUser, targetName := splitLogin(login)
	ext := map[string]string{
		"login":     c.User(),
		"principal": principal.Name,
		"role":      string(principal.Role),
		"roles":     auth.JoinRoles(principal.Roles),
		"target":    targetName,
		"cred_user": credUser,
	}
	if observe {
		ext["observe"] = "true"
	}
	if principal.EnrollOnly {
		ext["enroll_only"] = "true"
	}
	if principal.BreakGlass {
		ext["break_glass"] = "true"
	}
	// Resolve the connect capability now (a custom profile carries its own
	// capabilities that the role string alone cannot express downstream).
	if principal.Can(auth.CapConnect) {
		ext["can_connect"] = "true"
	}
	// Carry the REAL principal to handleConn (which runs the gates) rather than a
	// reconstruction: the SSH password is available only here, and CanConnectTarget
	// must see the actual roles/capabilities. The token is a per-connection map key;
	// handleConn removes the entry with LoadAndDelete once the handshake completes.
	//
	// Sweep stale entries first: handleConn consumes a token within one handshake
	// of it being stored, so any entry older than that is one whose NewServerConn
	// failed AFTER this callback succeeded (handleConn never ran to delete it).
	// Without this the map would grow without bound over such post-auth failures.
	now := time.Now()
	p.pending.Range(func(k, v any) bool {
		if pp, ok := v.(pendingPrincipal); ok && now.Sub(pp.at) > time.Minute {
			p.pending.Delete(k)
		}
		return true
	})
	token := strconv.FormatUint(p.princSeq.Add(1), 36)
	p.pending.Store(token, pendingPrincipal{principal: principal, at: now})
	ext["princ"] = token
	return &ssh.Permissions{Extensions: ext}, nil
}

// splitLogin parses "creduser@target" (rightmost @ separates the target) or
// bare "target". Target names never contain '@'.
func splitLogin(login string) (credUser, target string) {
	if i := strings.LastIndex(login, "@"); i >= 0 {
		return login[:i], login[i+1:]
	}
	return "", login
}

// ListenAndServe binds Config.Addr and serves until ctx is cancelled.
func (p *Proxy) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return p.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is cancelled. On cancellation it
// closes the listener and force-closes every active client connection, then
// waits for the in-flight handlers to return — so the drain is bounded (it does
// not wait for operators to voluntarily disconnect) and no handler goroutine
// outlives Serve. A fatal Accept error (not caused by cancellation) is returned
// promptly without waiting on active handlers. Exposed separately so tests can
// supply a 127.0.0.1:0 listener and read the address back. The accept/drain
// lifecycle lives in the embedded listener; this only logs the SSH-specific
// startup line (with the host-key fingerprint) and dispatches handleConn.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener) error {
	p.log.Info("ssh proxy listening",
		"addr", ln.Addr().String(),
		"hostkey_fp", ssh.FingerprintSHA256(p.hostKey.PublicKey()))
	return p.serve(ctx, ln, p.handleConn, "ssh proxy accept error; retrying", "connection")
}

// handshakeTimeout bounds the pre-authentication phase of a proxied connection:
// the SSH handshake, and the PostgreSQL startup/authentication exchange.
//
// 120 seconds, matching OpenSSH's LoginGraceTime, because this phase is NOT
// machine-speed. pamv1's documented flow has a human typing or pasting the API
// key at the password prompt — and OpenSSH re-prompts up to three times within
// one connection. An earlier value of 30s was measured cutting off a client
// whose operator took 32 seconds, with no message and no audit event, which
// looks exactly like a broken server.
//
// It still does the job it exists for: a peer that connects and says nothing
// cannot hold a connection slot, a goroutine and part of the PAM_MAX_SESSIONS
// budget indefinitely. The deadline is cleared the moment authentication
// succeeds, since an established session is legitimately idle for long stretches
// while an operator reads output.
const handshakeTimeout = 120 * time.Second

// handleConn completes the SSH handshake and runs every authorization gate in
// order (enrollment, role CapConnect, target/credential resolution, per-target
// grants and the approval gate) before dialing the upstream with the
// JIT-decrypted secret and proxying its session channels. Each denial and the
// session lifecycle are audited.
func (p *Proxy) handleConn(ctx context.Context, nConn net.Conn) {
	// Bound the handshake. Until it completes, an unauthenticated peer holds a
	// connection slot, a goroutine and (with PAM_MAX_SESSIONS) part of a finite
	// budget — and ssh.NewServerConn will wait indefinitely on a client that
	// connects and then says nothing. Cheap to open, free to hold, is the shape
	// of a resource-exhaustion problem, so it gets a deadline; a real handshake
	// finishes in milliseconds.
	//
	// The deadline is cleared immediately afterwards: an established session is
	// legitimately idle for long stretches while an operator reads output, and a
	// deadline that survived the handshake would cut working sessions off.
	_ = nConn.SetDeadline(time.Now().Add(handshakeTimeout))
	sconn, chans, reqs, err := ssh.NewServerConn(nConn, p.sshCfg)
	if err != nil {
		return // handshake/auth failure; nothing authenticated to audit
	}
	_ = nConn.SetDeadline(time.Time{})
	defer sconn.Close()

	ext := sconn.Permissions.Extensions
	// An endpoint agent's connection (Phase 153) is not a session: it carries
	// no principal, opens no channels of its own, and exists only to accept
	// the reverse-forward request and then hold still. It owns the global
	// request stream (which every operator connection discards below).
	if idStr := ext["endpoint_agent"]; idStr != "" {
		agentID, _ := strconv.ParseInt(idStr, 10, 64)
		targetID, _ := strconv.ParseInt(ext["endpoint_agent_target"], 10, 64)
		p.serveEndpointAgent(ctx, sconn, chans, reqs, agentID, targetID, ext["endpoint_agent_name"], sconn.RemoteAddr().String())
		return
	}
	go ssh.DiscardRequests(reqs)

	actor := ext["principal"]
	login := ext["login"]
	role := auth.Role(ext["role"])
	remote := sconn.RemoteAddr().String()
	p.log.Info("connection authenticated", "actor", actor, "role", string(role),
		"login", auditField(login, 64), "remote", remote)

	// The operator picked login at their client, so every use below is bounded
	// and quoted (auditField) before it reaches a log line or an audit row —
	// exactly as authenticate and the two SQL listeners bound it.

	// Every authorization gate now lives in the shared admission sequence
	// (gates.go, admit) so a gate cannot be fixed on one proxy and forgotten on
	// the others. admit runs the fixed order — enrollment, role CapConnect,
	// target/credential resolution, protocol allowlist, per-target grants,
	// approval, vendor contract, "can this gateway broker it", the concurrent
	// cap and the fail-closed session-start audit — and, only if all pass,
	// decrypts the secret just-in-time. It emits the audits that are identical on
	// all three proxies; refuse() below maps whatever it returns to the SSH
	// transport's own refusal wording.

	// Carry the REAL principal resolved in authenticate (where the SSH password
	// is available) through to the gates, rather than reconstructing a partial
	// one — CanConnectTarget must see the actual roles/capabilities. Fail closed
	// if it is somehow absent (it is stored on every successful authentication).
	principal, ok := p.loadPrincipal(ext["princ"])
	if !ok {
		p.log.Error("authenticated connection without a resolved principal", "actor", actor, "remote", remote)
		rejectAll(chans, ssh.Prohibited, "pamv1: internal authorization error")
		return
	}

	// A session-share join (Phase 116) dispatches here, BEFORE admit() runs —
	// deliberately: admit authorizes NEW access to a target (grants, approval,
	// protocol allowlist, JIT decrypt), and a join creates none of that. It
	// attaches to a session whose own admit() already ran when the primary
	// operator connected; reusing admit for this would be a category error,
	// checking authorization for access nobody is requesting.
	if token := ext["join_token"]; token != "" {
		p.handleJoinConn(ctx, chans, principal, token, remote)
		return
	}

	observe := ext["observe"] == "true"
	// viaAgent is set inside startAudit — the first point at which the target
	// is resolved — so the same lookup that stamps the session.start row also
	// decides how dialUpstream reaches the target (Phase 153).
	var viaAgent *store.EndpointAgent
	var agentErr error
	res := p.gate.admit(ctx, admitRequest{
		principal:  principal,
		targetName: ext["target"],
		credUser:   ext["cred_user"],
		remoteAddr: remote,
		// The SSH gateway brokers ssh always and winrm only with a runner
		// configured, so it has no single expected protocol; it uses proxyable
		// rather than expectProtocol (which the DB proxies use). serveWinRM
		// re-checks defensively.
		proxyable: func(t *store.Target) bool {
			return t.Protocol == "ssh" || (t.Protocol == "winrm" && p.winrm != nil)
		},
		// A Zero Standing Privilege ("ssh_ca") credential has no stored secret;
		// the proxy mints a short-lived certificate at dial time (dialUpstream)
		// instead, so admit must not try to decrypt one.
		skipDecrypt: func(c *store.Credential) bool { return c.IsZSP() },
		startAudit: func(t *store.Target, c *store.Credential) (string, string) {
			mode := "interactive"
			if observe {
				mode = "observer"
			}
			// The host is quoted rather than charset-validated: an IPv6 literal
			// legitimately contains colons, so `host:2001:db8::1:22` is ambiguous
			// even with nobody attacking it.
			detail := fmt.Sprintf("target:%s host:%s:%d cred_user:%s mode:%s", t.Name, auditField(t.Host, 255), t.Port, c.Username, mode)
			if t.Protocol != "ssh" {
				detail += " protocol:" + t.Protocol
			}
			// A target bound to an endpoint agent is reached through it, never
			// dialed — say so on the session.start row. A store error here fails
			// closed at dial time (viaAgent stays nil, agentErr is checked below).
			if a, err := p.endpointAgentFor(ctx, t.ID); err != nil {
				agentErr = err
			} else if a != nil {
				viaAgent = a
				detail += " via:endpoint-agent:" + a.Name
			}
			return "session.start", detail
		},
	})
	if res.outcome != admitOK {
		p.refuse(ctx, chans, res, actor, login, role, remote)
		return
	}
	target, cred, secret := res.target, res.cred, res.secret
	if agentErr != nil {
		p.log.Error("endpoint agent lookup failed", "actor", actor, "target", target.Name, "err", agentErr)
		p.audit(ctx, actor, "session.error", fmt.Sprintf("target:%s reason:endpoint-agent-lookup-failed", target.Name))
		rejectAll(chans, ssh.ConnectionFailed, "pamv1: upstream connection failed")
		return
	}
	// The endpoint-agent tunnel is an SSH-only path in v1 (the API refuses to
	// bind an agent to any other protocol); refuse rather than let a WinRM
	// target's agent row be silently ignored by a direct HTTP dial.
	if viaAgent != nil && target.Protocol != "ssh" {
		p.audit(ctx, actor, "session.error", fmt.Sprintf("target:%s reason:endpoint-agent-unsupported-protocol protocol:%s", target.Name, target.Protocol))
		rejectAll(chans, ssh.ConnectionFailed, "pamv1: endpoint agents reach SSH targets only")
		return
	}

	// Zero Standing Privilege but no CA configured: refuse where decryption would
	// otherwise have happened (after admit's fail-closed session.start audit).
	// admit left the secret empty for this credential type; dialUpstream needs the
	// CA to mint the certificate.
	if cred.IsZSP() && p.ca == nil {
		p.log.Error("zero-standing-privilege credential but no SSH CA configured", "actor", actor, "target", target.Name)
		p.audit(ctx, actor, "session.error",
			fmt.Sprintf("target:%s cred_user:%s reason:no-ssh-ca", target.Name, cred.Username))
		rejectAll(chans, ssh.ConnectionFailed, "pamv1: zero standing privilege is not configured on this server")
		return
	}

	observeMode := ext["observe"] == "true"

	// Non-SSH targets are brokered differently: WinRM targets get an interactive
	// command loop (if a runner is configured); anything else is refused.
	if target.Protocol != "ssh" {
		p.serveWinRM(ctx, sconn, chans, target, cred, secret, actor, remote, observeMode)
		return
	}

	upstream, err := p.dialUpstream(ctx, target, cred, secret, actor, viaAgent)
	if err != nil {
		p.log.Error("upstream connection failed", "actor", actor, "target", target.Name,
			"host", fmt.Sprintf("%s:%d", target.Host, target.Port), "err", err)
		p.audit(ctx, actor, "session.error",
			fmt.Sprintf("target:%s host:%s:%d error:%v", target.Name, auditField(target.Host, 255), target.Port, err))
		rejectAll(chans, ssh.ConnectionFailed, "pamv1: upstream connection failed")
		return
	}
	defer upstream.Close()

	mode := "interactive"
	if observe {
		mode = "observer"
	}
	p.log.Info("session started", "actor", actor, "target", target.Name,
		"host", fmt.Sprintf("%s:%d", target.Host, target.Port), "cred_user", cred.Username, "mode", mode)
	var sid string
	if p.sessions != nil {
		sid = p.sessions.Register(session.Info{
			Actor: actor, Target: target.Name, Protocol: "ssh", Remote: remote, Started: time.Now(),
		}, func() { sconn.Close() })
		defer p.sessions.Remove(sid)
		p.live.Publish(sid, watermarkBanner(actor, target.Name))
	}
	// The input-sharing mux (Phase 116) is opened unconditionally alongside
	// the session, whether or not anyone ever joins — matching how teeLive's
	// output tee is likewise paid on every session regardless of watchers.
	// p.shares is never nil (see New): a Proxy always has one, so every
	// interactive SSH session gets share-join capability, not just ones a
	// caller opted into.
	if sid != "" {
		p.shares.Open(sid)
		defer p.shares.Close(sid)
	}
	defer func() {
		p.log.Info("session ended", "actor", actor, "target", target.Name)
		p.auditClosing(ctx, actor, "session.end", "target:"+target.Name)
		// Force post-session credential rotation, if configured, so a secret
		// used in one session cannot be reused in the next.
		p.fireSessionEnd(cred.ID)
	}()

	var wg sync.WaitGroup
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			wg.Add(1)
			go func(nc ssh.NewChannel) {
				defer wg.Done()
				defer recoverPanicLog(p.log, "session")
				p.handleSession(ctx, nc, upstream, target, cred, actor, observe, principal.BreakGlass, sid)
			}(nc)
		case "direct-tcpip":
			// Phase 141: ssh -L style forwarding, scoped to the target's own
			// host only. None of observe/RequireSupervision/RequireRecording
			// have a mechanism that covers a raw forward, so each refuses it
			// outright rather than silently admitting an uncovered path.
			switch {
			case !p.portForward:
				nc.Reject(ssh.Prohibited, "pamv1: port forwarding is disabled by policy")
			case observe:
				nc.Reject(ssh.Prohibited, "pamv1: port forwarding is not available in an observer session")
			case p.requireSup:
				nc.Reject(ssh.Prohibited, "pamv1: port forwarding is unavailable when live supervision is required")
			case p.requireRec:
				nc.Reject(ssh.Prohibited, "pamv1: port forwarding is unavailable when session recording is required")
			default:
				wg.Add(1)
				go func(nc ssh.NewChannel) {
					defer wg.Done()
					defer recoverPanicLog(p.log, "forward")
					p.handleDirectTCPIP(ctx, nc, upstream, target, actor)
				}(nc)
			}
		default:
			nc.Reject(ssh.UnknownChannelType, "pamv1: only session channels are proxied")
		}
	}
	// The chans range ends when the client connection closes — the true
	// "client is gone" signal. Close the upstream now (before waiting) so any
	// session still blocked copying idle or wedged upstream output unblocks;
	// otherwise the deferred upstream.Close() below would sit behind this Wait.
	upstream.Close()
	wg.Wait()
}

// loadPrincipal retrieves (and removes) the *auth.Principal that authenticate
// stashed under token, so handleConn runs the gates against the REAL principal
// resolved from the SSH password rather than a partial reconstruction. Returns
// false when the token is unknown (which should not happen — a principal is
// stored on every successful authentication — and is treated as fail-closed).
func (p *Proxy) loadPrincipal(token string) (*auth.Principal, bool) {
	v, ok := p.pending.LoadAndDelete(token)
	if !ok {
		return nil, false
	}
	pp, ok := v.(pendingPrincipal)
	return pp.principal, ok
}

// refuse maps an admit() refusal to the SSH proxy's wire refusal and audit,
// preserving the exact action names, details and SSH rejection reasons each gate
// has always used. admit already emitted the audits identical across all three
// proxies (access.denied for the approval and vendor denials, and
// credential.decrypt_failed) and the shared check-failed error logs; this adds
// only the SSH-transport-specific wording. The switch is exhaustive over the
// gates reachable on the SSH path; gateTunnelOnly (refused at authentication)
// and gateProtocolMatch (a DB-only gate) fall to the fail-closed default.
func (p *Proxy) refuse(ctx context.Context, chans <-chan ssh.NewChannel, res admitResult, actor, login string, role auth.Role, remote string) {
	switch res.gate {
	case gateEnrollOnly:
		p.log.Warn("session denied: mfa enrollment incomplete", "actor", actor, "remote", remote)
		p.audit(ctx, actor, "session.denied", "login:"+auditField(login, 64)+" reason:mfa-enrollment-incomplete")
		rejectAll(chans, ssh.Prohibited, "pamv1: complete MFA enrollment first")
	case gateMFAPending:
		p.log.Warn("session denied: webauthn sign-in pending", "actor", actor, "remote", remote)
		p.audit(ctx, actor, "session.denied", "login:"+auditField(login, 64)+" reason:mfa-webauthn-pending")
		rejectAll(chans, ssh.Prohibited, "pamv1: complete WebAuthn sign-in first")
	case gateRoleConnect:
		p.log.Warn("session denied by role", "actor", actor, "role", string(role), "remote", remote)
		p.audit(ctx, actor, "session.denied",
			fmt.Sprintf("login:%s role:%s reason:role may not connect", auditField(login, 64), role))
		rejectAll(chans, ssh.Prohibited, "pamv1: your role may not open sessions")
	case gateIPAllowlist:
		p.log.Warn("session denied: source address not allowed", "actor", actor, "remote", remote)
		p.audit(ctx, actor, "session.denied", "login:"+auditField(login, 64)+" reason:source-ip-not-allowed")
		rejectAll(chans, ssh.Prohibited, "pamv1: this account may not connect from this network")
	case gatePosture:
		p.log.Warn("session denied: device posture check failed", "actor", actor, "remote", remote)
		p.audit(ctx, actor, "session.denied", "login:"+auditField(login, 64)+" reason:posture-check-failed")
		rejectAll(chans, ssh.Prohibited, "pamv1: your device failed its posture check")
	case gateResolve:
		p.log.Warn("session denied", "actor", actor, "login", auditField(login, 64), "reason", res.reason, "remote", remote)
		p.audit(ctx, actor, "session.denied", fmt.Sprintf("login:%s reason:%s", auditField(login, 64), res.reason))
		rejectAll(chans, ssh.Prohibited, "pamv1: "+res.reason)
	case gateProtocolAllowed:
		p.log.Warn("session denied: protocol not allowed", "actor", actor, "target", res.target.Name, "protocol", res.target.Protocol)
		p.audit(ctx, actor, "access.denied", "target:"+res.target.Name+" reason:protocol-not-allowed")
		rejectAll(chans, ssh.Prohibited, "pamv1: this protocol is not allowed by policy")
	case gateTargetGrants:
		// admit logged "target grants lookup failed"; fail closed on the wire.
		rejectAll(chans, ssh.Prohibited, "pamv1: authorization check failed")
	case gateTargetPolicy:
		p.log.Warn("session denied: target policy", "actor", actor, "target", res.target.Name, "remote", remote)
		p.audit(ctx, actor, "session.denied", "target:"+res.target.Name+" reason:target-policy")
		rejectAll(chans, ssh.Prohibited, "pamv1: not authorized for this target")
	case gateApprovalPolicy, gateApprovalClaim:
		// admit logged the specific approval error; fail closed on the wire.
		rejectAll(chans, ssh.Prohibited, "pamv1: approval check failed")
	case gateApproval:
		// admit already audited access.denied with the reason.
		p.log.Warn("session denied", "actor", actor, "target", res.target.Name, "remote", remote, "reason", res.reason)
		rejectAll(chans, ssh.Prohibited, "pamv1: connection requires an approved access request")
	case gateVendorCheck:
		// admit logged "vendor gate check failed"; fail closed on the wire.
		rejectAll(chans, ssh.Prohibited, "pamv1: authorization check failed")
	case gateVendor:
		// admit already audited access.denied reason:vendor-contract. access.denied,
		// not session.denied: the SQL listeners, the viewer tunnel and the REST
		// paths all record a vendor-contract refusal under access.denied, and the
		// OCSF exporter and risk analytics key off that vocabulary.
		p.log.Warn("session denied: vendor contract", "actor", actor, "target", res.target.Name, "remote", remote)
		rejectAll(chans, ssh.Prohibited, "pamv1: vendor access requires an approved, in-window contract grant")
	case gateProtocolProxyable:
		p.log.Warn("session denied: protocol not proxyable", "actor", actor, "target", res.target.Name, "protocol", res.target.Protocol)
		p.audit(ctx, actor, "session.denied", "target:"+res.target.Name+" reason:protocol-not-proxyable")
		rejectAll(chans, ssh.Prohibited, "pamv1: this target's protocol is not available through the proxy")
	case gateSessionLimit:
		p.log.Warn("session denied: concurrent-session limit", "actor", actor, "target", res.target.Name)
		p.audit(ctx, actor, "session.denied", "target:"+res.target.Name+" reason:session-limit")
		rejectAll(chans, ssh.Prohibited, "pamv1: too many concurrent sessions")
	case gateAudit:
		// admit's fail-closed session.start write did not land; refuse unaudited.
		rejectAll(chans, ssh.ConnectionFailed, "pamv1: audit log unavailable; session refused")
	case gateDecrypt:
		// admit already audited credential.decrypt_failed and logged the error.
		rejectAll(chans, ssh.ConnectionFailed, "pamv1: credential unavailable")
	default:
		p.log.Error("unhandled admit refusal on the SSH proxy", "gate", int(res.gate), "actor", actor, "remote", remote)
		rejectAll(chans, ssh.Prohibited, "pamv1: not authorized")
	}
}

// dialUpstream opens an SSH client to the target. For a Zero Standing Privilege
// ("ssh_ca") credential it mints a short-lived certificate just-in-time and
// authenticates with it (no standing secret); otherwise it authenticates with
// the decrypted secret as a parsed private key ("ssh_key") or a password. The
// upstream host key is checked via the configured callback. When via is
// non-nil the target is bound to an outbound-only endpoint agent (Phase 153):
// the raw stream is opened back through that agent's connection instead of
// dialing target.Host — direct and jump-host dialing are never attempted for
// such a target, so an offline agent is "unreachable", not "fall back".
func (p *Proxy) dialUpstream(ctx context.Context, target *store.Target, cred *store.Credential, secret, actor string, via *store.EndpointAgent) (*ssh.Client, error) {
	var authMethod ssh.AuthMethod
	switch cred.SecretType {
	case store.SecretTypeSSHCA:
		if p.ca == nil {
			return nil, errors.New("zero-standing-privilege credential but no SSH CA configured")
		}
		keyID := fmt.Sprintf("pamv1:%s@%s", actor, target.Name)
		certSigner, cert, err := p.ca.IssueUser(cred.Username, p.certTTL, keyID)
		if err != nil {
			return nil, fmt.Errorf("mint certificate: %w", err)
		}
		// Audit the issuance (serial + validity + key-id, never the private key), so
		// a minted certificate is accounted for even if the subsequent dial fails.
		p.audit(ctx, actor, "session.cert_issued",
			fmt.Sprintf("target:%s principal:%s serial:%d valid_before:%d key_id:%s",
				target.Name, cred.Username, cert.Serial, cert.ValidBefore, keyID))
		authMethod = ssh.PublicKeys(certSigner)
	case "ssh_key":
		signer, err := ssh.ParsePrivateKey([]byte(secret))
		if err != nil {
			return nil, fmt.Errorf("parse ssh key: %w", err)
		}
		authMethod = ssh.PublicKeys(signer)
	default:
		authMethod = ssh.Password(secret)
	}
	cfg := &ssh.ClientConfig{
		User:            cred.Username,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: p.upstreamHKCB,
		Timeout:         p.dialTimeout,
	}
	addr := fmt.Sprintf("%s:%d", target.Host, target.Port)
	// Route the raw TCP connection through the jump-host dialer when configured
	// (targets reachable only via a bastion); otherwise dial directly.
	//
	// The connection is dialled by hand even in the direct case, so a DEADLINE can
	// be set across the SSH handshake. ssh.ClientConfig.Timeout bounds only the TCP
	// connect (x/crypto documents it as such), so a target that completed the
	// three-way handshake and then went silent parked this goroutine forever —
	// holding the just-decrypted plaintext credential in memory, in the window
	// between the session cap check and Register, where it was counted by no cap,
	// listed by no GET /api/sessions and killable by nothing.
	dial := p.upstreamDial
	if dial == nil {
		dial = func(a string) (net.Conn, error) { return net.DialTimeout("tcp", a, p.dialTimeout) }
	}
	if via != nil {
		dial = func(string) (net.Conn, error) {
			c, err := p.endpointAgents.Dial(target.ID)
			if err != nil {
				return nil, fmt.Errorf("endpoint agent %q: %w", via.Name, err)
			}
			return c, nil
		}
	}
	conn, err := dial(addr)
	if err != nil {
		return nil, err
	}
	// A watchdog rather than SetDeadline: through a jump host this conn is an SSH
	// channel, which answers "deadline not supported". Closing the connection makes
	// the handshake fail, which works for both kinds. Stopped as soon as the
	// handshake returns, so it never cuts a healthy long-lived session.
	watchdog := time.AfterFunc(p.dialTimeout, func() { _ = conn.Close() })
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	watchdog.Stop()
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// jumpDial builds an upstream dialer that reaches the target through an SSH
// bastion: it opens a fresh bastion connection (public-key auth) per target dial
// and tunnels a direct-tcpip channel to the target. Closing the returned conn
// also closes the bastion connection.
func jumpDial(jc JumpConfig, timeout time.Duration) (func(addr string) (net.Conn, error), error) {
	if jc.Addr == "" || jc.User == "" || jc.KeyPEM == "" {
		return nil, errors.New("jump host requires an address, user and key")
	}
	signer, err := ssh.ParsePrivateKey([]byte(jc.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse jump key: %w", err)
	}
	hostCB := jc.HostKey
	if hostCB == nil {
		hostCB = ssh.InsecureIgnoreHostKey() // #nosec G106 -- documented trust-any default (jump host); pin with PAM_SSH_KNOWN_HOSTS
	}
	return func(addr string) (net.Conn, error) {
		bastion, err := ssh.Dial("tcp", jc.Addr, &ssh.ClientConfig{
			User:            jc.User,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: hostCB,
			Timeout:         timeout,
		})
		if err != nil {
			return nil, fmt.Errorf("jump host dial: %w", err)
		}
		conn, err := bastion.Dial("tcp", addr)
		if err != nil {
			bastion.Close()
			return nil, fmt.Errorf("jump to target: %w", err)
		}
		return &jumpConn{Conn: conn, bastion: bastion}, nil
	}, nil
}

// jumpConn wraps a tunneled connection so closing it also closes the bastion.
type jumpConn struct {
	net.Conn
	bastion *ssh.Client
}

// Close closes the tunneled connection and the underlying bastion connection.
func (j *jumpConn) Close() error {
	err := j.Conn.Close()
	j.bastion.Close()
	return err
}

// handleSession bridges one client session channel to a freshly opened upstream
// channel, forwarding channel requests and stdin/stdout/stderr both directions
// and tee'ing the target's output into an asciicast recording. On close the
// recording's SHA-256 and its position in the tamper-evident chain are audited.
func (p *Proxy) handleSession(ctx context.Context, nc ssh.NewChannel, upstream *ssh.Client, target *store.Target, cred *store.Credential, actor string, observe, breakGlass bool, sid string) {
	clientChan, clientReqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer clientChan.Close()

	// Session-sharing (Phase 116): register how a join running in a separate
	// goroutine/connection can reach THIS terminal with a Stderr banner —
	// there is no other path from handleJoinSession back to clientChan.
	if sid != "" {
		p.shares.SetNotifier(sid, func(msg string) { fmt.Fprintln(clientChan.Stderr(), msg) })
	}

	// Mandatory live supervision (Phase 112): refuse the channel — before the
	// upstream channel even opens, so nothing is relayed to the target — until
	// a supervisor is actively watching. An observer session already IS the
	// watching role, and break-glass exists precisely for when no supervisor
	// is reachable, so both are exempt. HasSubscribers is already true on the
	// common case (a supervisor attached before or immediately after this
	// channel opens, including cross-replica via Phase 55's relay), so this
	// only actually waits the first time a session goes unwatched.
	if p.requireSup && !observe && !breakGlass && !p.awaitSupervision(ctx, sid) {
		p.audit(ctx, actor, "session.unsupervised",
			fmt.Sprintf("target:%s cred_user:%s timeout:%s", target.Name, cred.Username, p.supTimeout))
		fmt.Fprintln(clientChan.Stderr(), "pamv1: no supervisor attached to watch this session; refused")
		return
	}

	upChan, upReqs, err := upstream.OpenChannel("session", nil)
	if err != nil {
		fmt.Fprintln(clientChan.Stderr(), "pamv1: could not open upstream session")
		return
	}
	defer upChan.Close()

	now := time.Now()
	title := recording.Title(p.opaqueNames, now, target.Name, actor)
	rec, err := newRecording(context.Background(), p.recordingDir, title, now, p.maxRecBytes, p.recKey)
	if err != nil {
		p.log.Error("recording setup failed", "actor", actor, "target", target.Name, "err", err)
		p.audit(ctx, actor, "session.record_failed",
			fmt.Sprintf("target:%s cred_user:%s error:%v", target.Name, cred.Username, err))
		if p.requireRec {
			// Through the live tee, not just stderr: a supervisor already watching
			// this registered session must see why it ends, not an empty stream.
			fmt.Fprintln(p.teeLive(clientChan.Stderr(), sid), "pamv1: session recording is unavailable; session refused")
			return
		}
	}

	// Forward channel requests both directions (pty-req, shell, exec,
	// window-change from the client; exit-status from upstream). In observer mode
	// the client→upstream pump refuses exec/subsystem, and operator keystrokes are
	// dropped — the session is view-only.
	// The client→upstream request pump is joined so its in-flight reply (notably
	// the exec/shell reply the client's Session.Start blocks on) is guaranteed to
	// reach clientChan before the deferred clientChan.Close() below tears it down.
	// Capture a non-interactive `ssh <target> "<cmd>"` into the recording + audit:
	// the command rides the exec request payload, not the tee'd channel data, so
	// without this it would appear in neither the .cast nor the audit trail.
	onExec := func(payload []byte) bool {
		var m struct{ Command string }
		_ = ssh.Unmarshal(payload, &m)
		pat, blocked := p.guard.Blocked(m.Command)
		if !blocked && p.allowGuard != nil && !p.allowGuard.Allowed(m.Command) {
			pat, blocked = "not-allowed", true
		}
		if blocked {
			if rec != nil {
				_, _ = io.WriteString(rec, "$ "+m.Command+"\r\npamv1: command blocked by policy\r\n")
			}
			p.audit(ctx, actor, "command.blocked", fmt.Sprintf("target:%s via:proxy pattern:%s cmd:%s", target.Name, pat, auditCmd(m.Command)))
			return false // do not forward the exec request upstream
		}
		if rec != nil {
			_, _ = io.WriteString(rec, "$ "+m.Command+"\r\n")
		}
		p.audit(ctx, actor, "ssh.exec", fmt.Sprintf("target:%s cred_user:%s via:proxy cmd:%s", target.Name, cred.Username, auditCmd(m.Command)))
		return true
	}
	// File-transfer control (Phase 32): SFTP rides an SSH "subsystem" channel. The
	// inspector parses that binary stream to audit each file operation and, in
	// read-only mode, refuse writes; onSubsystem gates the subsystem request itself
	// (deny mode refuses it, otherwise it activates the inspector for sftp).
	// Content capture (Phase 59), when enabled, additionally records the bytes of
	// every transferred file into per-file artifacts named after this session's
	// recording — created here so they share the title, the seal and the chain.
	sftpAudit := func(action, detail string) {
		p.audit(ctx, actor, action, fmt.Sprintf("target:%s cred_user:%s %s", target.Name, cred.Username, detail))
	}
	var capState *sftpCapture
	var respWatch *sftpRespWatcher
	if p.sftpCapture != SFTPCaptureOff && p.sftpMode != SFTPDeny && !observe {
		// The closing auditor is what writes each artifact's attestation: a
		// session drained by shutdown finalizes its open artifacts, and those
		// events must outlive the cancelled session context (the same reason
		// session.record uses it three lines below).
		sftpAuditClosing := func(action, detail string) {
			p.auditClosing(ctx, actor, action, fmt.Sprintf("target:%s cred_user:%s %s", target.Name, cred.Username, detail))
		}
		capState = newSFTPCapture(ctx, p.recordingDir, title, p.recKey, p.chain, p.sftpCapture, p.sftpCapMax, p.icapClient, sftpAudit, sftpAuditClosing)
		respWatch = &sftpRespWatcher{cap: capState}
	}
	insp := newSFTPInspector(p.sftpMode, p.sftpPaths, capState, sftpAudit)
	onSubsystem := func(payload []byte) bool {
		var m struct{ Name string }
		_ = ssh.Unmarshal(payload, &m)
		if m.Name != "sftp" {
			if p.sftpMode == SFTPDeny {
				p.audit(ctx, actor, "sftp.denied", fmt.Sprintf("target:%s cred_user:%s subsystem:%s", target.Name, cred.Username, m.Name))
				return false
			}
			p.audit(ctx, actor, "session.subsystem", fmt.Sprintf("target:%s cred_user:%s name:%s", target.Name, cred.Username, m.Name))
			return true
		}
		if p.sftpMode == SFTPDeny {
			if rec != nil {
				_, _ = io.WriteString(rec, "pamv1: SFTP is disabled by policy\r\n")
			}
			p.audit(ctx, actor, "sftp.denied", fmt.Sprintf("target:%s cred_user:%s", target.Name, cred.Username))
			return false
		}
		insp.activate()
		p.audit(ctx, actor, "sftp.session", fmt.Sprintf("target:%s cred_user:%s mode:%s", target.Name, cred.Username, p.sftpMode))
		return true
	}
	clientReqDone := make(chan struct{}) // stops the pump between requests
	var clientReqPump sync.WaitGroup
	clientReqPump.Add(1)
	go func() {
		defer clientReqPump.Done()
		if observe {
			pumpRequestsObserver(clientReqs, upChan, clientReqDone)
		} else {
			pumpRequests(clientReqs, upChan, clientReqDone, reqHooks{onExec: onExec, onSubsystem: onSubsystem})
		}
	}()
	var upReqDone sync.WaitGroup
	upReqDone.Add(1)
	go func() {
		defer upReqDone.Done()
		pumpRequests(upReqs, clientChan, nil, reqHooks{}) // exits when the upstream channel closes
	}()

	// Target stderr -> operator, also tee'd into the recording so the audited
	// hash covers stderr, not just stdout (Recording.Write is concurrency-safe).
	// The copy is joined before rec.Close() below: stdout hitting EOF (which ends
	// io.Copy(out, upChan)) does not mean stderr has drained, and a late write
	// into an already-closed Recording would vanish from the audited hash. The
	// upstream channel closing EOFs Stderr() too, so this never outlives stdout.
	var errOut io.Writer = clientChan.Stderr()
	if rec != nil {
		errOut = io.MultiWriter(clientChan.Stderr(), rec)
	}
	errOut = p.teeLive(errOut, sid)
	var errCopyDone sync.WaitGroup
	errCopyDone.Add(1)
	go func() {
		defer errCopyDone.Done()
		io.Copy(errOut, upChan.Stderr())
	}()
	// One serialized view of the operator's channel, shared by everything that
	// writes to it: the target-output copy below and the SFTP inspector's
	// refusals, which run on their own goroutine.
	clientOut := &syncWriter{w: clientChan}

	if observe {
		// Read-only: drop operator keystrokes; never touch the upstream channel.
		go io.Copy(io.Discard, clientChan)
	} else {
		// Session-share input mux (Phase 116): when sharing is active for this
		// session (sid != ""), the primary operator's own keystrokes are fed
		// into the mux — the SAME channel any attached view-control joiner's
		// keystrokes also feed — and pump reads from the mux instead of
		// clientChan directly. This is what lets a joiner's input reach the
		// target at all without a second goroutine writing upChan directly
		// (x/crypto/ssh forbids concurrent writes to one channel). With
		// sharing inactive (sid == "", e.g. the session registry is disabled)
		// this is a no-op indirection: keyIn stays clientChan, unchanged from
		// before this phase.
		var keyIn io.Reader = clientChan
		if sid != "" {
			go io.Copy(p.shares.Writer(sid), clientChan)
			keyIn = p.shares.Reader(sid)
		}
		go func() {
			// Operator keystrokes -> target. For an SFTP session the inspector parses
			// this leg to audit + gate file operations; for a shell/exec session it is
			// a transparent pass-through (the inspector stays inactive).
			if err := insp.pump(upChan, keyIn, clientOut); errors.Is(err, errSFTPCaptureAbort) {
				// Content capture failed the stream closed: tear the upstream
				// channel down fully so the session unwinds now, rather than
				// leave both sides waiting on packets that will never flow.
				upChan.Close()
				return
			}
			// Propagate a client stdin half-close (CHANNEL_EOF) upstream, but keep
			// the channel open so the command's remaining output and exit-status
			// still flow back. Full upstream teardown happens in handleConn when the
			// client connection actually closes.
			upChan.CloseWrite()
		}()
	}

	// Target output -> operator, tee'd into the recording and the live hub. This
	// writes through clientOut so it cannot overlap an SFTP refusal. With content
	// capture on, the same bytes are also framed as SFTP responses so HANDLE and
	// DATA packets can be attributed to files (the stream itself is forwarded
	// unchanged either way).
	var out io.Writer = clientOut
	if rec != nil {
		out = io.MultiWriter(clientOut, rec)
	}
	out = p.teeLive(out, sid)
	var cerr error
	if respWatch != nil {
		cerr = copyObserved(out, upChan, insp.enabled, respWatch)
	} else {
		_, cerr = io.Copy(out, upChan)
	}
	if errors.Is(cerr, errRecordingLimit) {
		p.audit(ctx, actor, "session.record_limit", "target:"+target.Name+" cred_user:"+cred.Username+" reason:recording-size-cap")
	}
	if errors.Is(cerr, errSFTPCaptureAbort) {
		upChan.Close() // fail closed: unwind the whole session (audited by the watcher)
	}
	upReqDone.Wait() // make sure exit-status reached the client

	// Upstream is done and exit-status is delivered; stop the client-request pump
	// and wait for it to park, so any reply it is mid-way through delivering
	// flushes to clientChan before the deferred clientChan.Close() runs.
	close(clientReqDone)
	clientReqPump.Wait()

	// Flush upstream stderr into the recording before hashing and closing it, so
	// the audited sha256 covers every stderr byte the session produced.
	errCopyDone.Wait()

	// Close out any capture artifacts the client never closed (or whose close
	// was deferred behind reads that will now never resolve): each is hashed,
	// chained and audited exactly like a cleanly closed one.
	if capState != nil {
		capState.finalizeAll()
	}

	if rec != nil {
		path, sum, n := rec.Close()
		chain := p.chain.append(sum)
		p.auditClosing(ctx, actor, "session.record",
			fmt.Sprintf("target:%s cred_user:%s file:%s bytes:%d sha256:%s chain:%s",
				target.Name, cred.Username, path, n, sum, chain))
	}
}

// directTCPIPExtra is the RFC 4254 §7.2 direct-tcpip channel-open payload a
// client sends to request forwarding (the wire shape behind `ssh -L`).
// Marshaled by an ssh.Client's own Dial when pamv1 acts as the client (see
// jumpDial); this is the mirror-image server-side decode, needed only since
// Phase 141 accepts a client-initiated direct-tcpip channel for the first
// time — every prior use of this shape in this codebase was outbound.
type directTCPIPExtra struct {
	DestAddr string
	DestPort uint32
	SrcAddr  string
	SrcPort  uint32
}

// sameHostAsTarget reports whether addr names the connected target's own
// host — an exact (case-insensitive) match, or a loopback literal
// (localhost/127.0.0.1/::1). The loopback case matters because
// handleDirectTCPIP dials out through upstream, the already-authenticated
// connection TO the target: "localhost" resolved from there is the target
// itself, and `ssh -L 5432:localhost:5432 op@target` — reaching a service
// bound only to loopback on the target box — is the single most common
// real-world use of this feature. The port is deliberately never compared
// against target.Port: that is the target's SSH port, not the port of
// whatever service the operator actually wants to reach on the same host.
func sameHostAsTarget(addr string, target *store.Target) bool {
	if strings.EqualFold(addr, target.Host) {
		return true
	}
	switch strings.ToLower(addr) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// handleDirectTCPIP admits a client-initiated direct-tcpip channel (Phase
// 141) ONLY to the connected target's own host, reusing the session's
// existing authorization rather than inventing a new "allowed destinations"
// concept — deliberately narrower than a real SSH server's forwarding,
// which would let the client reach anything the target's network position
// can. Forwarded bytes are opaque: no parser exists for arbitrary
// application data the way there is for exec/SQL, so the audit trail is
// connection-level only (destination, byte counts, duration), never
// content — the caller has already refused observe/RequireSupervision/
// RequireRecording sessions before this is reached.
func (p *Proxy) handleDirectTCPIP(ctx context.Context, nc ssh.NewChannel, upstream *ssh.Client, target *store.Target, actor string) {
	var d directTCPIPExtra
	if err := ssh.Unmarshal(nc.ExtraData(), &d); err != nil {
		nc.Reject(ssh.Prohibited, "pamv1: malformed forwarding request")
		return
	}
	dest := net.JoinHostPort(d.DestAddr, strconv.Itoa(int(d.DestPort)))
	if !sameHostAsTarget(d.DestAddr, target) {
		p.audit(ctx, actor, "forward.refused",
			fmt.Sprintf("target:%s dest:%s reason:not-same-host", target.Name, auditField(dest, 255)))
		nc.Reject(ssh.Prohibited, "pamv1: forwarding is only permitted to the connected target's own host")
		return
	}
	upConn, err := upstream.Dial("tcp", dest)
	if err != nil {
		p.audit(ctx, actor, "forward.refused",
			fmt.Sprintf("target:%s dest:%s reason:dial-failed", target.Name, auditField(dest, 255)))
		nc.Reject(ssh.ConnectionFailed, "pamv1: could not reach the forwarding destination")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		upConn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)

	started := time.Now()
	p.audit(ctx, actor, "forward.start", fmt.Sprintf("target:%s dest:%s", target.Name, auditField(dest, 255)))

	var bytesIn, bytesOut int64
	var pipes sync.WaitGroup
	pipes.Add(2)
	go func() {
		defer pipes.Done()
		n, _ := io.Copy(upConn, ch)
		atomic.AddInt64(&bytesIn, n)
		// A half-close, not a full Close: the other leg's goroutine may still
		// be delivering the destination's response, and tearing the whole
		// connection down here would truncate it.
		if cw, ok := upConn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			upConn.Close()
		}
	}()
	go func() {
		defer pipes.Done()
		n, _ := io.Copy(ch, upConn)
		atomic.AddInt64(&bytesOut, n)
		ch.CloseWrite()
	}()
	pipes.Wait()
	ch.Close()
	upConn.Close()

	p.auditClosing(ctx, actor, "forward.end", fmt.Sprintf("target:%s dest:%s bytes_in:%d bytes_out:%d duration:%s",
		target.Name, auditField(dest, 255), atomic.LoadInt64(&bytesIn), atomic.LoadInt64(&bytesOut), time.Since(started).Round(time.Second)))
}

// handleJoinConn attaches an approved, internal (named-pamv1-user) session-
// share redemption (Phase 116) to the session its invite names. It is
// dispatched from handleConn BEFORE admit() runs and never calls it: admit
// authorizes NEW access to a target, and a join creates none — it attaches to
// a session whose own admit() already ran when the primary operator
// connected. External/vendor invites (email + QR) are never redeemed here —
// they are redeemed over HTTP by a different handler entirely, since the
// recipient has no pamv1 login to present as an SSH password; an external
// invite's token presented to this login path is refused, not silently
// honored, so the "email address is the identity anchor" story for that path
// cannot be sidestepped by an insider who learns the token.
func (p *Proxy) handleJoinConn(ctx context.Context, chans <-chan ssh.NewChannel, principal *auth.Principal, token, remote string) {
	if p.live == nil {
		p.audit(ctx, principal.Name, "session.share_join_denied", "reason:live-monitoring-not-configured")
		rejectAll(chans, ssh.Prohibited, "pamv1: session sharing is not configured on this server")
		return
	}
	// Consume the token FIRST (atomically single-use), before any further
	// validation — a token that fails a later check (wrong invitee, no
	// CapConnect) is still burned, exactly like a single-use approval token
	// elsewhere in this codebase: a rejected redemption attempt must not
	// leave a still-valid token an attacker can keep retrying other things
	// against.
	inv, err := p.store.ConsumeSessionShareInviteByTokenHash(ctx, auth.TokenHash(token), time.Now())
	if err != nil {
		p.audit(ctx, principal.Name, "session.share_join_denied", "reason:invalid-expired-or-used-token")
		rejectAll(chans, ssh.Prohibited, "pamv1: this invite is invalid, expired or already used")
		return
	}
	if inv.Kind != "internal" {
		p.audit(ctx, principal.Name, "session.share_join_denied",
			fmt.Sprintf("invite:%d reason:wrong-redemption-path", inv.ID))
		rejectAll(chans, ssh.Prohibited, "pamv1: this invite must be redeemed via its emailed link")
		return
	}
	// The invite names WHO it was issued to; redeemed by a different pamv1
	// user than named, even with the right token, is refused — a leaked
	// token must not let a different user impersonate the invitee.
	if !strings.EqualFold(inv.Invitee, principal.Name) {
		p.audit(ctx, principal.Name, "session.share_join_denied",
			fmt.Sprintf("invite:%d reason:invitee-mismatch", inv.ID))
		rejectAll(chans, ssh.Prohibited, "pamv1: this invite was not issued to you")
		return
	}
	if inv.Mode == "view_control" && !principal.Can(auth.CapConnect) {
		p.audit(ctx, principal.Name, "session.share_join_denied",
			fmt.Sprintf("invite:%d reason:no-connect-capability", inv.ID))
		rejectAll(chans, ssh.Prohibited, "pamv1: view-control requires connect capability")
		return
	}
	if p.sessions == nil || !p.sessions.Exists(inv.SessionID) {
		p.audit(ctx, principal.Name, "session.share_join_denied",
			fmt.Sprintf("invite:%d session:%s reason:not-live", inv.ID, inv.SessionID))
		rejectAll(chans, ssh.Prohibited, "pamv1: this session is no longer live")
		return
	}

	joinID := strconv.FormatInt(inv.ID, 10)
	var wg sync.WaitGroup
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "pamv1: only session channels are proxied")
			continue
		}
		wg.Add(1)
		go func(nc ssh.NewChannel) {
			defer wg.Done()
			defer recoverPanicLog(p.log, "join")
			p.handleJoinSession(ctx, nc, principal.Name, remote, inv, joinID)
		}(nc)
	}
	wg.Wait()
}

// handleJoinSession bridges one join connection's channel to session sid's
// existing live stream: output via the same Hub.Subscribe every watcher uses
// (so a joiner sees exactly what a supervisor watching would, cross-replica
// transparent via Phase 55's relay), and — for view_control only — input via
// the SAME ShareRegistry mux the primary operator's own keystrokes feed.
// Unlike handleSession, this never opens an upstream channel: a join attaches
// to the primary's already-open PTY, it does not dial the target a second
// time.
func (p *Proxy) handleJoinSession(ctx context.Context, nc ssh.NewChannel, joinActor, remote string, inv *store.SessionShareInvite, joinID string) {
	clientChan, clientReqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer clientChan.Close()

	sid := inv.SessionID
	kicked := p.shares.Track(sid, joinID, joinActor, inv.Mode)
	defer p.shares.Untrack(sid, joinID)
	p.shares.Notify(sid, fmt.Sprintf("pamv1: %s joined this session (%s)", joinActor, inv.Mode))
	defer p.shares.Notify(sid, fmt.Sprintf("pamv1: %s left this session", joinActor))

	// Full trace of the connection: invite, session, mode and the redeeming
	// connection's own source address — matching session.start's own detail
	// shape one level up, best-effort like every other audit call in this
	// file (session.start/session.record/session.end included).
	p.audit(ctx, joinActor, "session.share_joined",
		fmt.Sprintf("invite:%d session:%s mode:%s remote:%s", inv.ID, sid, inv.Mode, remote))
	defer p.auditClosing(ctx, joinActor, "session.share_ended",
		fmt.Sprintf("invite:%d session:%s", inv.ID, sid))

	// Answer pty-req/shell/window-change LOCALLY (never forwarded — there is
	// no upstream channel here to forward to) and refuse exec/subsystem,
	// exactly like an observer session. SFTP is therefore unreachable to a
	// joiner as a direct, automatic consequence of that refusal, with no
	// special-case code needed.
	reqDone := make(chan struct{})
	var reqWG sync.WaitGroup
	reqWG.Add(1)
	go func() {
		defer reqWG.Done()
		answerJoinRequests(clientReqs, reqDone)
	}()
	defer func() { close(reqDone); reqWG.Wait() }()

	frames, cancel := p.live.Subscribe(sid)
	defer cancel()

	if inv.Mode == "view_control" {
		// This joiner's own keystrokes feed the SAME mux the primary's do —
		// any number of simultaneous view-control joiners is supported, since
		// the mux is a plain channel any number of senders can feed (Phase
		// 116's multi-parallel requirement).
		go io.Copy(p.shares.Writer(sid), clientChan)
	} else {
		go io.Copy(io.Discard, clientChan)
	}

	for {
		select {
		case b, ok := <-frames:
			if !ok {
				fmt.Fprintln(clientChan.Stderr(), "pamv1: session ended")
				return
			}
			if _, werr := clientChan.Write(b); werr != nil {
				return
			}
		case <-ctx.Done():
			return
		case <-kicked:
			fmt.Fprintln(clientChan.Stderr(), "pamv1: you have been removed from this session")
			return
		}
	}
}

// answerJoinRequests replies success to every channel request from in EXCEPT
// exec/subsystem (refused, matching pumpRequestsObserver's restriction — a
// join is never allowed to run a discrete command or open SFTP), without
// forwarding anything anywhere: a join has no upstream channel of its own, it
// is attached to the primary's already-open PTY, so pty-req/shell/
// window-change are answered locally so an ordinary SSH client blocked
// waiting for that reply does not hang.
func answerJoinRequests(in <-chan *ssh.Request, done <-chan struct{}) {
	for {
		select {
		case req, ok := <-in:
			if !ok {
				return
			}
			ok2 := req.Type != "exec" && req.Type != "subsystem"
			if req.WantReply {
				req.Reply(ok2, nil)
			}
		case <-done:
			return
		}
	}
}

// serveWinRM brokers an interactive command loop to a WinRM (Windows) target.
// The connection has already passed every gate (role, grants, approval, protocol
// allowlist). Each operator line is run as a separate WinRM command — this is a
// command loop, not a stateful PowerShell (working directory / variables do not
// persist across lines). Refuses cleanly when no WinRM runner is configured.
func (p *Proxy) serveWinRM(ctx context.Context, sconn *ssh.ServerConn, chans <-chan ssh.NewChannel, target *store.Target, cred *store.Credential, secret, actor, remote string, observe bool) {
	if target.Protocol != "winrm" || p.winrm == nil {
		p.log.Warn("session denied: protocol not proxyable", "actor", actor, "target", target.Name, "protocol", target.Protocol)
		p.audit(ctx, actor, "session.denied", "target:"+target.Name+" reason:protocol-not-proxyable")
		rejectAll(chans, ssh.Prohibited, "pamv1: this target's protocol is not available through the proxy")
		return
	}
	mode := "interactive"
	if observe {
		mode = "observer"
	}
	p.log.Info("winrm session started", "actor", actor, "target", target.Name, "mode", mode)
	// sid is hoisted out of the if so the command loop can tee output to the
	// live-monitoring hub under it — for a long time it was scoped inside,
	// which is why WinRM sessions were listable and killable but not watchable.
	var sid string
	if p.sessions != nil {
		sid = p.sessions.Register(session.Info{
			Actor: actor, Target: target.Name, Protocol: "winrm", Remote: remote, Started: time.Now(),
		}, func() { sconn.Close() })
		defer p.sessions.Remove(sid)
	}
	defer func() {
		p.log.Info("winrm session ended", "actor", actor, "target", target.Name)
		p.auditClosing(ctx, actor, "session.end", "target:"+target.Name+" protocol:winrm")
		p.fireSessionEnd(cred.ID)
	}()

	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "pamv1: only session channels are proxied")
			continue
		}
		p.handleWinRMSession(ctx, nc, target, cred, secret, actor, observe, sid)
	}
}

// handleWinRMSession answers channel requests for one WinRM session channel: it
// runs a "shell" as an interactive command loop and an "exec" as a single
// command, tee'ing output into an asciicast recording and — under sid — into
// the live-monitoring hub, so a supervisor can watch a WinRM session as it
// happens the way they can an SSH or PostgreSQL one.
func (p *Proxy) handleWinRMSession(ctx context.Context, nc ssh.NewChannel, target *store.Target, cred *store.Credential, secret, actor string, observe bool, sid string) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	now := time.Now()
	rec, err := newRecording(context.Background(), p.recordingDir, recording.Title(p.opaqueNames, now, target.Name, actor), now, p.maxRecBytes, p.recKey)
	if err != nil {
		p.log.Error("recording setup failed", "actor", actor, "target", target.Name, "err", err)
		p.audit(ctx, actor, "session.record_failed",
			fmt.Sprintf("target:%s cred_user:%s protocol:winrm error:%v", target.Name, cred.Username, err))
		if p.requireRec {
			// Through the live tee, not just the channel: a supervisor already
			// subscribed to this registered session must see why it ends, not an
			// empty stream.
			fmt.Fprintln(p.teeLive(ch, sid), "pamv1: session recording is unavailable; session refused")
			return
		}
	}
	defer func() {
		if rec != nil {
			path, sum, n := rec.Close()
			chain := p.chain.append(sum)
			p.auditClosing(ctx, actor, "session.record",
				fmt.Sprintf("target:%s cred_user:%s file:%s bytes:%d sha256:%s chain:%s", target.Name, cred.Username, path, n, sum, chain))
		}
	}()

	// One writer chain for the whole session, built here so the shell loop and
	// the per-command runner cannot drift apart: client channel + recording,
	// wrapped by the cap latch, tee'd to the live hub. Order matters — the
	// recording stays the byte-authority (the live tee never receives bytes the
	// recording refused), and the cap latch is what lets the Fprintf-style
	// writers below notice the recording cap at all.
	cw := &capWriter{w: recWriter(ch, rec)}
	out := p.teeLive(cw, sid)

	for req := range reqs {
		switch req.Type {
		case "pty-req", "env", "window-change":
			if req.WantReply {
				req.Reply(true, nil)
			}
		case "shell":
			if req.WantReply {
				req.Reply(true, nil)
			}
			p.winrmShellLoop(ctx, ch, out, cw, target, cred, secret, actor, observe, sid)
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{0}))
			return
		case "exec":
			if req.WantReply {
				req.Reply(true, nil)
			}
			var m struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &m)
			code := p.winrmRun(ctx, out, target, cred, secret, actor, observe, m.Command)
			p.winrmCapStop(ctx, cw, ch, sid, actor, target, cred)
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{uint32(code)}))
			return
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// winrmShellLoop reads operator lines and runs each as a WinRM command, printing
// a prompt and streaming output through out (client + recording + live hub;
// built once by handleWinRMSession). "exit"/"quit"/"logout" or EOF ends the
// session — and so does the recording size cap, which cw latches: a session the
// recording refuses does not keep running unrecorded.
func (p *Proxy) winrmShellLoop(ctx context.Context, ch ssh.Channel, out io.Writer, cw *capWriter, target *store.Target, cred *store.Credential, secret, actor string, observe bool, sid string) {
	fmt.Fprintf(out, "pamv1 WinRM shell for %s (each line is a separate command; type 'exit' to quit)\r\n", target.Name)
	prompt := "pamv1 " + target.Name + "> "
	scanner := bufio.NewScanner(ch)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	for {
		fmt.Fprint(out, prompt)
		// Checked once per loop turn, right after a write: catches a cap tripped
		// by the banner, the prompt, or the previous command's output.
		if p.winrmCapStop(ctx, cw, ch, sid, actor, target, cred) {
			return
		}
		if !scanner.Scan() {
			return
		}
		line := strings.TrimRight(scanner.Text(), "\r\n")
		switch strings.TrimSpace(line) {
		case "":
			fmt.Fprint(out, "\r\n")
			continue
		case "exit", "quit", "logout":
			fmt.Fprint(out, "\r\n")
			return
		}
		// winrmRun echoes the command into the recording itself.
		p.winrmRun(ctx, out, target, cred, secret, actor, observe, line)
	}
}

// winrmRun executes one WinRM command, durably audits it, and only then streams
// its output through out (client + recording + live hub), returning the remote
// exit code. If the audit store is unavailable the output is withheld — the
// fail-closed contract the REST WinRM endpoint has always had. In observer mode
// it refuses to run.
func (p *Proxy) winrmRun(ctx context.Context, out io.Writer, target *store.Target, cred *store.Credential, secret, actor string, observe bool, command string) int {
	// Echo the command into the recording (WinRM output doesn't echo the input the
	// way an interactive SSH shell does) so the .cast is a faithful record of what
	// was run — the non-repudiation guarantee.
	fmt.Fprintf(out, "%s\r\n", command)
	if observe {
		fmt.Fprint(out, "pamv1: read-only session, command ignored\r\n")
		p.audit(ctx, actor, "access.denied", "target:"+target.Name+" reason:observer-winrm cmd:"+auditCmd(command))
		return 1
	}
	pat, blocked := p.guard.Blocked(command)
	if !blocked && p.allowGuard != nil && !p.allowGuard.Allowed(command) {
		pat, blocked = "not-allowed", true
	}
	if blocked {
		fmt.Fprint(out, "pamv1: command blocked by policy\r\n")
		p.audit(ctx, actor, "command.blocked", fmt.Sprintf("target:%s via:proxy pattern:%s cmd:%s", target.Name, pat, auditCmd(command)))
		return 1
	}
	res, err := p.winrm.Run(ctx, target.Host, target.Port, cred.Username, secret, command)
	if err != nil {
		fmt.Fprintf(out, "pamv1: winrm error: %v\r\n", err)
		p.audit(ctx, actor, "winrm.error", fmt.Sprintf("target:%s via:proxy error:%v", target.Name, err))
		return 1
	}
	// Durable audit BEFORE the operator sees the output — the same withheld-result
	// contract as the REST WinRM endpoint (execWinRM): nobody acts on output that
	// the system of record never accounted for. The command has already run on the
	// target either way; what fails closed is the evidence reaching the operator.
	if aerr := appendAuditErr(ctx, p.store, p.log, actor, "winrm.run",
		fmt.Sprintf("target:%s cred_user:%s via:proxy exit:%d cmd:%s", target.Name, cred.Username, res.ExitCode, auditCmd(command))); aerr != nil {
		fmt.Fprint(out, "pamv1: audit log unavailable; output withheld\r\n")
		return 1
	}
	if res.Stdout != "" {
		io.WriteString(out, crlf(res.Stdout))
	}
	if res.Stderr != "" {
		io.WriteString(out, crlf(res.Stderr))
	}
	return res.ExitCode
}

// auditCmd renders a command for an audit detail, quoted and length-capped so a
// long or newline-bearing command can't bloat or break the audit row.
func auditCmd(command string) string { return auditField(command, 400) }

// auditField makes an untrusted string safe to place in an audit detail or actor:
// bounded in length and quoted, so embedded newlines, quotes and forged
// `key:value` pairs cannot restructure the record around it.
//
// Audit details are a space-separated `key:value` format read by humans and by
// the SIEM forwarder. Interpolating raw client input into one lets a caller
// invent fields — a login of `alice target:prod-db action:approved` reads as
// three legitimate keys. Every current consumer sanitizes on the way out, so
// this is defence for the raw column, which is the copy an investigator reads.
func auditField(s string, limit int) string { return auditfmt.Field(s, limit) }

// syncWriter serializes concurrent writes to one destination.
//
// It exists for the operator's SSH channel, which two goroutines write to at
// once: the session's main goroutine copying target output back, and the SFTP
// inspector answering a refusal with a status packet. x/crypto/ssh documents
// in-source that concurrent WriteExtended calls for the same extended code share
// a pooled buffer and are not safe, and beyond the data race the practical
// result is a status packet interleaved into a split read response — a corrupted
// SFTP stream on the client.
//
// The race was latent while refusals only happened in read-only mode. Phase 51's
// path denylist made them possible in the default allow mode too, where an
// ordinary `mget` over a mixed allowed/denied set triggers exactly this overlap.
// Sequential request/response tests never produce it.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// Write forwards to the wrapped writer while holding the lock.
func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// recWriter returns a writer that sends to the client channel and, when set, tees
// into the recording.
func recWriter(ch ssh.Channel, rec io.Writer) io.Writer {
	if rec == nil {
		return ch
	}
	return io.MultiWriter(ch, rec)
}

// capWriter forwards to w and latches an errRecordingLimit, so callers whose
// individual writes discard errors — the WinRM loop writes through fmt.Fprintf —
// still notice that the recording refused the bytes and can stop the session,
// which is the contract Recording.Write's cap exists for. (The SSH path gets the
// same signal for free: its io.Copy returns the error.)
type capWriter struct {
	w       io.Writer
	capped  bool
	audited bool
}

// Write forwards to the wrapped writer, remembering a recording-cap refusal.
func (c *capWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if errors.Is(err, errRecordingLimit) {
		c.capped = true
	}
	return n, err
}

// winrmCapStop reports whether the WinRM session's recording cap has tripped.
// The first time it has, the limit is audited (session.record_limit — the same
// event the SSH path emits), the operator is told on the raw channel, and the
// live watchers learn why their stream is about to end. The caller then ends
// the session: continuing would run it unrecorded, and an unrecorded privileged
// session is exactly what PAM_MAX_RECORDING_MB must never quietly allow.
func (p *Proxy) winrmCapStop(ctx context.Context, cw *capWriter, ch io.Writer, sid, actor string, target *store.Target, cred *store.Credential) bool {
	if cw == nil || !cw.capped {
		return false
	}
	if !cw.audited {
		cw.audited = true
		p.audit(ctx, actor, "session.record_limit", "target:"+target.Name+" cred_user:"+cred.Username+" reason:recording-size-cap")
		const notice = "pamv1: recording size limit reached; session closed\r\n"
		io.WriteString(ch, notice)
		p.live.Publish(sid, []byte(notice))
	}
	return true
}

// liveWriter publishes everything written to it to a live-session hub under a
// session id, so a supervisor can watch the session as it happens. Writes never
// fail (a slow watcher drops frames), so it is safe to tee into.
type liveWriter struct {
	hub *session.Hub
	id  string
}

// Write publishes p to the hub and reports it fully written.
func (w liveWriter) Write(p []byte) (int, error) {
	w.hub.Publish(w.id, p)
	return len(p), nil
}

// teeLive returns w plus a live tee to the hub when live monitoring is enabled
// for sid; otherwise it returns w unchanged.
func (p *Proxy) teeLive(w io.Writer, sid string) io.Writer {
	if p.live == nil || sid == "" {
		return w
	}
	return io.MultiWriter(w, liveWriter{hub: p.live, id: sid})
}

// supervisionPoll is how often awaitSupervision re-checks for a watcher. Short
// enough that a supervisor who just attached is noticed promptly, cheap enough
// (an in-memory map lookup, or the relay's already-maintained TTL flag on a
// remote replica) that polling it costs nothing worth avoiding with a proper
// wake-up channel.
const supervisionPoll = 500 * time.Millisecond

// awaitSupervision blocks until session sid has an attached watcher — locally
// or, via the Phase 55 relay, on another replica — or p.supTimeout elapses,
// whichever comes first. It returns false on timeout or context cancellation.
// A nil live hub (monitoring not wired) or an empty sid can never gain a
// watcher, so it fails fast rather than waiting out the full timeout for a
// condition that can never become true.
func (p *Proxy) awaitSupervision(ctx context.Context, sid string) bool {
	if p.live == nil || sid == "" {
		return false
	}
	if p.live.HasSubscribers(sid) {
		return true
	}
	deadline := time.NewTimer(p.supTimeout)
	defer deadline.Stop()
	poll := time.NewTicker(supervisionPoll)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return false
		case <-poll.C:
			if p.live.HasSubscribers(sid) {
				return true
			}
		}
	}
}

// crlf normalizes bare LF line endings to CRLF for terminal display.
func crlf(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

// reqHooks intercepts specific channel requests on the client→upstream leg. A nil
// hook forwards that request type unchanged; a hook returning false refuses the
// request (it is not sent upstream and the client is replied to with failure).
//
// This is where command control reaches an SSH session: the command in an
// `ssh target "cmd"` arrives as an "exec" request payload and never appears in
// the channel data the recording tees, so intercepting the request is the only
// place it is visible as a discrete command.
type reqHooks struct {
	onExec      func(payload []byte) bool // "exec" (a discrete `ssh target "cmd"`)
	onSubsystem func(payload []byte) bool // "subsystem" (notably sftp)
}

// pumpRequests forwards SSH channel requests from in to dst, relaying replies,
// until in closes or done fires.
//
// Closing done stops the pump only BETWEEN requests: one already dequeued is
// forwarded and its reply delivered before the pump returns, so a caller can
// join it and know an in-flight reply (the exec or shell reply, say) reached its
// channel before that channel is torn down. Without that guarantee an operator's
// client sees a truncated session rather than a clean exit. A nil done means
// "run until in closes".
//
// h's hooks are consulted before a request is forwarded, which is how a command
// is captured into the recording and the audit trail, and how command control
// vetoes one: a hook returning false means the request is not sent upstream and
// the client is answered with failure.
func pumpRequests(in <-chan *ssh.Request, dst ssh.Channel, done <-chan struct{}, h reqHooks) {
	for {
		select {
		case req, ok := <-in:
			if !ok {
				return
			}
			// A hook captures the request and reports whether to forward it; one
			// refused by policy is not sent upstream (reply false).
			if h.onExec != nil && req.Type == "exec" && !h.onExec(req.Payload) {
				if req.WantReply {
					req.Reply(false, nil)
				}
				continue
			}
			if h.onSubsystem != nil && req.Type == "subsystem" && !h.onSubsystem(req.Payload) {
				if req.WantReply {
					req.Reply(false, nil)
				}
				continue
			}
			okr, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(okr && err == nil, nil)
			}
		case <-done:
			return
		}
	}
}

// pumpRequestsObserver forwards channel requests like pumpRequests but refuses
// anything that would run a command (exec, subsystem), so a read-only session
// cannot execute — the operator may open a shell/pty and watch, nothing more.
func pumpRequestsObserver(in <-chan *ssh.Request, dst ssh.Channel, done <-chan struct{}) {
	for {
		select {
		case req, ok := <-in:
			if !ok {
				return
			}
			if req.Type == "exec" || req.Type == "subsystem" {
				if req.WantReply {
					req.Reply(false, nil)
				}
				continue
			}
			okr, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(okr && err == nil, nil)
			}
		case <-done:
			return
		}
	}
}

// protocolSet turns a protocol list into a lookup set; an empty list returns nil
// (meaning "allow all protocols").
func protocolSet(ps []string) map[string]bool {
	if len(ps) == 0 {
		return nil
	}
	m := make(map[string]bool, len(ps))
	for _, p := range ps {
		if p = strings.TrimSpace(p); p != "" {
			m[p] = true
		}
	}
	return m
}

// rejectAll rejects every channel the client opens with reason and msg, used to
// refuse a connection after authentication once a policy gate fails.
func rejectAll(chans <-chan ssh.NewChannel, reason ssh.RejectionReason, msg string) {
	for nc := range chans {
		nc.Reject(reason, msg)
	}
}

// noteBreakGlass raises the emergency-access signal for a principal resolved by a
// proxy. It is the proxies' twin of the API's Server.noteBreakGlass, and exists
// for the same stated reason: every entry point that resolves its own principal
// outside the HTTP authz middleware must raise this itself, or an emergency-key
// privileged session goes unnoticed.
//
// Before this, break-glass through the SSH, PostgreSQL or SQL Server proxy was
// used ONLY to skip the four-eyes approval gate. The single trace was a
// session.start row whose actor happened to read `break-glass` — no
// breakglass.access event, no webhook/syslog/email alert, and no
// pam_breakglass_access_total increment, even though the same key against
// GET /api/me produced all three.
//
// A nil principal or a non-break-glass one is a no-op, so callers can invoke it
// unconditionally right after Resolve.
func (p *Proxy) noteBreakGlass(ctx context.Context, principal *auth.Principal, detail string) {
	noteBreakGlass(ctx, p.store, p.log, p.onBreakGlass, principal, detail)
}

// noteBreakGlass raises the emergency-access signal for a principal resolved by a
// session proxy. It is the proxies' twin of the API's Server.noteBreakGlass and
// exists for the same stated reason: every entry point that resolves its own
// principal outside the HTTP authz middleware must raise this itself, or an
// emergency-key privileged session goes unnoticed.
//
// Before this, break-glass through the SSH, PostgreSQL or SQL Server proxy was
// consulted ONLY to skip the four-eyes approval gate. The single trace was a
// session.start row whose actor happened to read `break-glass` — no
// breakglass.access event, no webhook/syslog/email alert and no
// pam_breakglass_access_total increment, even though the same key presented to
// GET /api/me produced all three.
//
// A nil or non-break-glass principal is a no-op, so callers can invoke it
// unconditionally right after Resolve. Shared by all three proxies so the three
// cannot drift apart.
func noteBreakGlass(ctx context.Context, st store.Store, log *slog.Logger,
	hook func(ctx context.Context, actor, detail string), principal *auth.Principal, detail string) {
	if principal == nil || !principal.BreakGlass {
		return
	}
	log.Warn("BREAK-GLASS access via a session proxy", "actor", principal.Name, "detail", detail)
	appendAudit(ctx, st, log, principal.Name, "breakglass.access", detail)
	if hook != nil {
		hook(ctx, principal.Name, detail)
	}
}

// claimApproval runs the use-time approval gate for one connection and audits
// its outcome. All three proxies and the API call the same fold
// (store.ClaimApproval), so the connect-time ticket re-check cannot be present
// on some paths and missing on others — the Phase 38 lesson, applied to the
// gate rather than to command control.
//
// It returns the reason to put in the denial audit, so a caller only has to
// decide how its own protocol says no.
func claimApproval(ctx context.Context, st store.Store, tc store.TicketChecker, actor string, target *store.Target, audit func(action, detail string)) (ok bool, reason string, err error) {
	claim, err := store.ClaimApproval(ctx, st, tc, actor, target.ID, time.Now())
	if err != nil {
		return false, "", err
	}
	if claim.ConsumedID != 0 {
		audit("access.consumed", fmt.Sprintf("request:%d target:%s", claim.ConsumedID, target.Name))
	}
	if claim.TicketErr != nil {
		audit("access.ticket_revoked", fmt.Sprintf("target:%s ticket:%q reason:%v", target.Name, claim.Ticket, claim.TicketErr))
		return false, "ticket-not-valid", nil
	}
	if !claim.OK {
		return false, "approval-required", nil
	}
	return true, "", nil
}
