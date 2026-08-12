// Package api exposes the PAM REST API and the embedded portal.
package api

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/analytics"
	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/cmdguard"
	"github.com/morandeirachema/pamv1/internal/guacd"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/metrics"
	"github.com/morandeirachema/pamv1/internal/oidc"
	"github.com/morandeirachema/pamv1/internal/policy"
	"github.com/morandeirachema/pamv1/internal/ratelimit"
	"github.com/morandeirachema/pamv1/internal/recording"
	"github.com/morandeirachema/pamv1/internal/rotate"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/sshca"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/ticket"
	"github.com/morandeirachema/pamv1/internal/vault"
	"github.com/morandeirachema/pamv1/internal/vendor"
	"github.com/morandeirachema/pamv1/internal/web"
	"github.com/morandeirachema/pamv1/internal/winrm"
	"golang.org/x/crypto/ssh"
)

type ctxKey int

const (
	principalKey ctxKey = iota
	reqInfoKey
)

// withPrincipal returns a copy of ctx carrying the authenticated Principal.
func withPrincipal(ctx context.Context, p *auth.Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// principalFrom returns the Principal stored in ctx, or a fallback "unknown"
// principal when none is present.
func principalFrom(ctx context.Context) *auth.Principal {
	if p, ok := ctx.Value(principalKey).(*auth.Principal); ok {
		return p
	}
	return &auth.Principal{Name: "unknown"}
}

// actorFrom returns the name of the Principal in ctx, used for audit attribution.
func actorFrom(ctx context.Context) string {
	return principalFrom(ctx).Name
}

// reqInfo is a per-request holder the access-log middleware places in the
// context and the authz middleware fills with the resolved actor.
type reqInfo struct{ actor string }

// setActor records the resolved actor on the per-request reqInfo (if present),
// so the access-log middleware can log who made the request.
func setActor(ctx context.Context, actor string) {
	if ri, ok := ctx.Value(reqInfoKey).(*reqInfo); ok {
		ri.actor = actor
	}
}

// Options tunes server policy.
type Options struct {
	// MFARequired makes password login require a confirmed second factor: users
	// without one get an enrollment-only session until they set up MFA.
	MFARequired bool
	// WinRM runs commands on Windows targets; defaults to a real HTTPS client.
	WinRM winrm.Runner
	// BuildVersion and BuildCommit identify the running binary. They are exported
	// as the pam_build_info metric so an operator can answer "which build is
	// this?" from monitoring during an incident — previously unanswerable in-band.
	BuildVersion, BuildCommit string
	// RecordingDir is where session/command transcripts are written.
	RecordingDir string
	// CertRemindDays is how many days before a certification campaign's due date
	// its first reminder fires (PAM_CERT_REMIND_DAYS). 0 disables reminders.
	CertRemindDays int
	// RequireRecording refuses a session that cannot be recorded, matching what
	// PAM_REQUIRE_RECORDING already did for the SSH and PostgreSQL proxies. It
	// covers the two paths the flag never reached: the in-portal RDP viewer and
	// the REST WinRM endpoint.
	RequireRecording bool
	// OIDC (optional) enables the browser Authorization Code login flow.
	OIDC *oidc.Provider
	// OIDCRoleMap maps OIDC app-role/group claims to roles.
	OIDCRoleMap map[string]auth.Role
	// PortalURL is where the OIDC callback redirects (default "/").
	PortalURL string
	// GuacdAddr enables RDP brokering via an Apache Guacamole guacd daemon
	// (e.g. "127.0.0.1:4822"); empty disables RDP.
	GuacdAddr string
	// GuacdRecordingPath, if set, makes guacd record RDP sessions server-side
	// (a path on the guacd host).
	GuacdRecordingPath string
	// GuacdRDPSecurity sets the RDP security mode ("nla"/"tls"/"rdp"/…); empty
	// negotiates. GuacdIgnoreCert disables RDP server-cert verification (dev only).
	GuacdRDPSecurity string
	GuacdIgnoreCert  bool
	// RDPClipboard is the clipboard/drive policy for in-portal RDP sessions:
	// "allow" (default), "readonly" (block paste into the target), or "deny"
	// (clipboard off both ways). Drive redirection is always disabled.
	RDPClipboard string
	// AuthRatePerMin limits authentication attempts per client IP per minute
	// (0 disables rate limiting). It budgets the login endpoints and, on its own
	// window, the failed bearer-credential attempts on the REST, agent-broker and
	// application-secrets surfaces.
	AuthRatePerMin int
	// CommandGuard is the command denylist (PAM_COMMAND_DENY_FILE), the SAME
	// guard the session proxies enforce. The API owns two paths where a discrete
	// command is visible — the REST WinRM run and the broker's ssh_exec/winrm_exec
	// tools — and without it a pattern blocked for a human on the proxy would run
	// freely for an AI agent. A nil guard blocks nothing.
	CommandGuard *cmdguard.Guard
	// EncryptRecordings seals session recordings and WinRM transcripts at rest
	// with a per-recording data key wrapped by the vault KEK (PAM_RECORDING_ENCRYPT).
	// Playback detects the format per file, so recordings written before it was
	// turned on keep replaying.
	EncryptRecordings bool
	// RDPClipboardAudit records what crosses the RDP clipboard bridge (Phase 50):
	// "off" (default), "meta" (direction, mimetype, size, SHA-256) or "full"
	// (also the content — see the warning in clipboard.go).
	RDPClipboardAudit string
	// OpaqueRecordingNames names WinRM transcripts by timestamp + random hex; the
	// target/actor metadata then lives only in the audited winrm.run event
	// (PAM_RECORDING_OPAQUE_NAMES, Phase 48).
	OpaqueRecordingNames bool
	// TrustedProxyHops is how many trusted reverse-proxy hops sit in front of the
	// server; it selects the real client IP from X-Forwarded-For for rate limiting
	// (0 = use RemoteAddr directly).
	TrustedProxyHops int
	// RevealDisabled makes credential reveal break-glass-only (proxy is the norm).
	RevealDisabled bool
	// Sessions is the live-session registry (shared with the proxy).
	Sessions *session.Registry
	// Live is the live-session output hub (shared with the proxy) that backs the
	// GET /api/sessions/{id}/stream monitoring endpoint (Phase 16).
	Live *session.Hub
	// Cluster (optional) is the cross-replica live-monitoring coordinator
	// (Phase 55): GET /api/sessions lists cluster-wide and the stream endpoint
	// can watch a session hosted on another replica. nil = replica-local, the
	// pre-HA behavior.
	Cluster *session.Cluster
	// StepUp coordinates in-session step-up approvals with the DB proxy (Phase 30):
	// a supervisor decides a paused statement via POST /api/sessions/{id}/stepup.
	StepUp *session.StepUp
	// NOTE: there is deliberately no BreakGlassHashHex here. The hash lives once,
	// in auth.Resolver, and the quorum-unseal handler asks it. Two inputs for one
	// value is what let Phase 78's rotation reach the direct key path and not the
	// quorum path — and the test harness had already drifted the two apart
	// without anything noticing.
	// BreakGlassThreshold (M) enables M-of-N quorum unseal when >= 2.
	BreakGlassThreshold int
	// BreakGlassTTL is the lifetime of an unsealed break-glass session.
	BreakGlassTTL time.Duration
	// Alerter delivers real-time break-glass alerts (defaults to no-op).
	Alerter alert.Notifier
	// Rotators changes a credential's secret on the target, keyed by target
	// protocol ("ssh", "winrm"). Defaults are built from the SSH/WinRM connectors.
	Rotators map[string]rotate.Rotator
	// Verifiers checks a vaulted secret still authenticates, keyed by protocol.
	// Defaults are built from the SSH/WinRM connectors.
	Verifiers map[string]rotate.Verifier
	// RequireApproval, when true, gates every target's connect paths behind an
	// approved access request (global OT maintenance-window / 4-eyes policy).
	// Individual targets can also opt in via Target.RequireApproval.
	RequireApproval bool
	// ApprovalWindow is how long an approved access request stays valid
	// (default 60m).
	ApprovalWindow time.Duration
	// TicketValidator validates an ITSM change/incident ticket on access
	// requests (Phase 20); nil disables validation. RequireTicket makes a ticket
	// mandatory on every access request.
	TicketValidator *ticket.Validator
	RequireTicket   bool
	// RevalidateTicket re-checks the admitting request's ticket at the moment
	// access is USED, not only when it was requested (Phase 60). Off by
	// default: it puts an ITSM call on the connect path and refuses when the
	// ITSM cannot confirm the ticket.
	RevalidateTicket bool
	// ApprovalsRequired is the default number of distinct approvers an access
	// request needs (Phase 21 multi-tier chains; default 1). RequireReason
	// rejects an access request that carries no reason.
	ApprovalsRequired int
	RequireReason     bool
	// OneTimeAccess (Phase 26) makes every access request single-use: the first
	// privileged use its approval admits consumes it. A request may also opt in
	// individually via one_time.
	OneTimeAccess bool
	// CheckoutTTL is the lifetime of a credential checkout lease (default 30m).
	CheckoutTTL time.Duration
	// AirGap disables all outbound network calls (alert webhooks) for isolated
	// OT/air-gapped deployments.
	AirGap bool
	// DiscoveryDial overrides the TCP dialer used by the discovery scanner
	// (tests inject a dialer; nil uses the default net.Dialer).
	DiscoveryDial func(ctx context.Context, network, addr string) (net.Conn, error)
	// SSHHostKeyCallback pins the host key for the default SSH rotation/reconcile
	// connector (nil trusts any upstream key). Ignored if Rotators/Verifiers are
	// supplied explicitly.
	SSHHostKeyCallback ssh.HostKeyCallback
	// AllowedProtocols, when non-empty, restricts which target protocols may be
	// created and connected to (e.g. {"ssh","winrm"}); empty allows all.
	AllowedProtocols []string
	// Directory (optional) backs identity reconciliation: pamv1 revokes access for
	// users the directory reports as disabled. nil disables the reconcile endpoint.
	Directory auth.DirectorySource
	// Reconfigure (optional) rebuilds the hot-swappable RuntimeConfig from the
	// current stored configuration (Phase 12). When set, PUT/DELETE /api/config
	// take effect without a restart; nil keeps the startup snapshot (changes
	// apply on the next restart).
	Reconfigure func(context.Context) (*RuntimeConfig, error)
	// AuditSignKey (optional) signs primary-audit-chain checkpoints served by
	// GET /api/audit/head, so an auditor can detect tail truncation. nil disables
	// the endpoint.
	AuditSignKey ed25519.PrivateKey
	// BrokerPolicy (optional) enables the AI-agent access broker (Phase 13). When
	// non-nil the broker routes are served; BrokerAuditKey (32 bytes) and
	// BrokerAuditSignKey are then required for the tamper-evident audit chain.
	BrokerPolicy       *policy.Engine
	BrokerAuditKey     []byte
	BrokerAuditSignKey ed25519.PrivateKey
	// BrokerTokenTTL is how long a single-use approval resume token stays valid
	// (default 15m). BrokerMaxArgBytes caps a tool call's serialized arguments (0
	// = uncapped). BrokerRatePerMin rate-limits tool calls per agent (0 = off).
	BrokerTokenTTL    time.Duration
	BrokerMaxArgBytes int
	BrokerRatePerMin  int
	// BrokerCheckpointEvery emits a signed in-chain audit checkpoint every N broker
	// events (0 = off). BrokerAuditSignPrevKeys are rotated-out ed25519 public keys
	// still trusted to verify older checkpoints during a signing-key rotation
	// overlap (Phase 27).
	BrokerCheckpointEvery   int
	BrokerAuditSignPrevKeys []ed25519.PublicKey
	// BrokerSVIDVerifier (optional) accepts SPIFFE JWT-SVIDs in addition to static
	// agent keys (Phase 13d); nil = static keys only.
	BrokerSVIDVerifier agentid.Verifier
	// BrokerTokenSignKey (optional) enables the RFC 8693 token-exchange endpoint
	// (Phase 57): the ed25519 key the broker signs delegated JWT-SVIDs with. Nil
	// leaves POST /v1/token unmounted — pamv1 then verifies delegation without
	// issuing it, which is what Phases 13–56 did. BrokerExchangeTTL bounds an
	// issued token (it is additionally capped by the delegator's own expiry).
	BrokerTokenSignKey ed25519.PrivateKey
	BrokerExchangeTTL  time.Duration
	// BrokerAudience and BrokerMaxDelegation mirror what the SVID verifier was
	// built with, so a minted token carries the audience the ingress requires and
	// the same delegation-depth cap is applied at mint time, not only on the next
	// presentation.
	BrokerAudience      string
	BrokerMaxDelegation int
	// CA (optional) is the Zero Standing Privilege SSH certificate authority
	// (Phase 22). When set, GET /api/ca/ssh publishes its public key so operators
	// can install it in a target's TrustedUserCAKeys; nil disables ZSP. It also
	// backs operator-issued certificates (Phase 28), capped at SSHOperatorCertTTL.
	CA                 *sshca.CertAuthority
	SSHOperatorCertTTL time.Duration
	// VendorAttestor (optional) validates a vendor's live employment attestation
	// before a contract grant is approved (Phase 29); nil accepts every vendor.
	VendorAttestor *vendor.Attestor
	// Analytics (optional) enables privileged threat analytics (Phase 23): the
	// GET /api/analytics/risk endpoint and, when AnalyticsInterval > 0, a
	// background risk-scoring worker. nil disables both. AnalyticsWindow is how
	// far back each pass scores (default 60m); AnalyticsAutoKill terminates a
	// critical-risk actor's live sessions.
	Analytics         *analytics.Engine
	AnalyticsWindow   time.Duration
	AnalyticsAutoKill bool
	// AnalyticsBaseline is how far back to read history for the novelty signal
	// (0 disables it). AnalyticsAutoStepUp revokes a HIGH-risk actor's logins so
	// their next action re-authenticates — the rung below killing them.
	AnalyticsBaseline   time.Duration
	AnalyticsAutoStepUp bool
	// AppSecretsEnabled turns on the application-secrets API (Phase 24): the app
	// identity + secret-grant admin routes and the /v1/app-secrets fetch path.
	AppSecretsEnabled bool
}

type Server struct {
	store              store.Store
	vault              *vault.Vault
	resolver           *auth.Resolver
	winrm              winrm.Runner
	recordingDir       string
	certRemindDays     int
	requireRecording   bool
	portalURL          string
	guacdAddr          string
	guacdRecordingPath string
	guacdRDPSecurity   string
	guacdIgnoreCert    bool
	rdpClipboard       string
	authLimiter        *ratelimit.Limiter
	// keyFailLimiter throttles FAILED bearer-credential attempts (X-API-Key,
	// agent key, application key) per source IP. It is separate from
	// authLimiter — which throttles every call to the login endpoints — because
	// a legitimate API client makes many successful calls a minute and only its
	// failures may be counted. Same budget (PAM_AUTH_RATE_LIMIT), own window.
	keyFailLimiter     *ratelimit.Limiter
	cmdGuard           *cmdguard.Guard
	recKey             recording.KeyWrapper
	opaqueRecNames     bool
	rdpClipAudit       string
	trustedProxyHops   int
	sessions           *session.Registry
	live               *session.Hub
	cluster            *session.Cluster
	stepup             *session.StepUp
	bgThreshold        int
	bgTTL              time.Duration
	unseal             *unsealState
	alerter            alert.Notifier
	ticketValidator    *ticket.Validator
	requireTicket      bool
	revalidateTicket   bool
	approvalsRequired  int
	requireReason      bool
	oneTimeAccess      bool
	rotators           map[string]rotate.Rotator
	verifiers          map[string]rotate.Verifier
	sshConnector       rotate.SSHConnector // one-shot SSH exec for the broker's ssh_exec tool
	airGap             bool
	discoveryDial      func(ctx context.Context, network, addr string) (net.Conn, error)
	sshCA              *sshca.CertAuthority
	sshOperatorCertTTL time.Duration
	vendorAttestor     *vendor.Attestor
	analytics          *analytics.Engine
	analyticsWindow    time.Duration
	analyticsCooldown  time.Duration
	analyticsAutoKill  bool
	// analyticsBaseline is how far back to read history for the novelty signal
	// (0 = off). analyticsAutoStepUp requires an elevated actor to
	// re-authenticate rather than killing them (Phase 86).
	analyticsBaseline   time.Duration
	analyticsAutoStepUp bool
	analyticsMu         sync.Mutex
	analyticsAlerted    map[string]analyticsAlert // actor → last alert (score + time)
	appSecretsEnabled   bool
	metrics             *metrics.Metrics
	log                 *slog.Logger
	mux                 *http.ServeMux
	handler             http.Handler
	// rtc is the atomically-swappable snapshot of runtime-overridable settings
	// (identity backends + operational policy). PUT /api/config rebuilds it via
	// reconfigure without a restart (Phase 12). Read it through s.rt().
	rtc atomic.Pointer[runtimeConf]
	// reconfigure rebuilds the runtime snapshot from current stored config; nil
	// disables hot-swap (changes then apply on the next restart).
	reconfigure func(context.Context) (*RuntimeConfig, error)
	// auditSignKey signs primary-audit checkpoints (GET /api/audit/head); nil disables it.
	auditSignKey ed25519.PrivateKey
	// AI-agent access broker (Phase 13); nil unless a policy file is configured.
	broker        *broker.Broker
	agentVerifier agentid.Verifier
	// exchanger mints delegated JWT-SVIDs (Phase 57, RFC 8693); nil unless
	// PAM_BROKER_TOKEN_EXCHANGE is on, which also gates POST /v1/token.
	exchanger     *agentid.Exchanger
	auditChain    *auditchain.Chain
	brokerLimiter *ratelimit.Limiter  // per-agent tool-call rate limit (Phase 13)
	mcpSessions   *mcpSessionRegistry // open MCP SSE streams for elicitation (Phase 27)
}

// RuntimeConfig is the set of settings PUT /api/config can change without a
// server restart (Phase 12 hot-swap): the identity backends and operational
// policy. main builds it from the base env config plus stored overrides and
// hands the server a Reconfigure closure that reproduces it after each change.
// Transport/bootstrap settings (listeners, TLS, DB URL, KEK) are not here —
// they stay environment-only and require a restart.
type RuntimeConfig struct {
	Authn            auth.Authenticator
	Directory        auth.DirectorySource
	OIDC             *oidc.Provider
	OIDCRoleMap      map[string]auth.Role
	MFARequired      bool
	RevealDisabled   bool
	ApprovalRequired bool
	ApprovalWindow   time.Duration
	CheckoutTTL      time.Duration
	AllowedProtocols []string
}

// Metrics exposes the server's collector, so a background worker wired in main
// can record into the same series the /metrics endpoint serves.
func (s *Server) Metrics() *metrics.Metrics { return s.metrics }

// runtimeConf is the server's immutable in-memory copy of a RuntimeConfig,
// stored behind s.rtc (atomic.Pointer) so in-flight requests read a consistent
// snapshot while a swap is in progress.
type runtimeConf struct {
	authn            auth.Authenticator
	directory        auth.DirectorySource
	oidc             *oidc.Provider
	oidcRoleMap      map[string]auth.Role
	mfaRequired      bool
	revealDisabled   bool
	approvalRequired bool
	approvalWindow   time.Duration
	checkoutTTL      time.Duration
	allowedProtocols map[string]bool
}

// snapshot converts an externally-built RuntimeConfig into the internal
// immutable form, defaulting the approval window and checkout TTL exactly as New
// does so a hot swap never installs a zero duration.
func snapshot(rc RuntimeConfig) *runtimeConf {
	if rc.ApprovalWindow <= 0 {
		rc.ApprovalWindow = 60 * time.Minute
	}
	if rc.CheckoutTTL <= 0 {
		rc.CheckoutTTL = 30 * time.Minute
	}
	return &runtimeConf{
		authn:            rc.Authn,
		directory:        rc.Directory,
		oidc:             rc.OIDC,
		oidcRoleMap:      rc.OIDCRoleMap,
		mfaRequired:      rc.MFARequired,
		revealDisabled:   rc.RevealDisabled,
		approvalRequired: rc.ApprovalRequired,
		approvalWindow:   rc.ApprovalWindow,
		checkoutTTL:      rc.CheckoutTTL,
		allowedProtocols: protocolSet(rc.AllowedProtocols),
	}
}

// rt returns the current runtime configuration snapshot. Never nil after New.
func (s *Server) rt() *runtimeConf { return s.rtc.Load() }

// applyReconfigure rebuilds the runtime snapshot from the current stored config
// and installs it atomically, so identity backends and policy take effect
// without a restart. A nil reconfigure (e.g. in tests) leaves the running
// snapshot in place and the change applies on the next restart.
func (s *Server) applyReconfigure(ctx context.Context) error {
	if s.reconfigure == nil {
		return nil
	}
	rc, err := s.reconfigure(ctx)
	if err != nil {
		return err
	}
	s.rtc.Store(snapshot(*rc))
	return nil
}

// hotSwap reports whether runtime configuration changes take effect immediately
// (a reconfigure closure is wired) rather than on the next restart.
func (s *Server) hotSwap() bool { return s.reconfigure != nil }

// New builds the HTTP handler. The resolver authenticates the X-API-Key header
// into a Principal (bootstrap admin key, break-glass key, per-user token, or a
// login session). authn (optional) backs POST /api/login with a password
// identity source such as Active Directory; pass nil to disable password login.
func New(st store.Store, v *vault.Vault, resolver *auth.Resolver, authn auth.Authenticator, opts Options) (*Server, error) {
	if resolver == nil {
		return nil, errors.New("api: resolver is required")
	}
	runner := opts.WinRM
	if runner == nil {
		runner = winrm.Client{HTTPS: true}
	}
	portalURL := opts.PortalURL
	if portalURL == "" {
		portalURL = "/"
	}
	// NOTE: the break-glass hash is deliberately NOT copied onto the Server. It
	// lives once, in auth.Resolver, so a rotation reaches every consumer at the
	// same instant; see Resolver.MatchesBreakGlass.
	bgTTL := opts.BreakGlassTTL
	if bgTTL <= 0 {
		bgTTL = 15 * time.Minute
	}
	alerter := opts.Alerter
	if alerter == nil || opts.AirGap {
		// Air-gapped deployments must make no outbound calls; drop the webhook.
		alerter = alert.Noop{}
	}
	sshConn := rotate.SSHConnector{HostKeyCallback: opts.SSHHostKeyCallback}
	rotators := opts.Rotators
	if rotators == nil {
		rotators = map[string]rotate.Rotator{
			"ssh":   sshConn,
			"winrm": rotate.WinRMConnector{Runner: runner},
		}
	}
	verifiers := opts.Verifiers
	if verifiers == nil {
		verifiers = map[string]rotate.Verifier{
			"ssh":   sshConn,
			"winrm": rotate.WinRMConnector{Runner: runner},
		}
	}
	s := &Server{
		store:               st,
		vault:               v,
		resolver:            resolver,
		winrm:               runner,
		ticketValidator:     opts.TicketValidator,
		requireTicket:       opts.RequireTicket,
		revalidateTicket:    opts.RevalidateTicket,
		approvalsRequired:   opts.ApprovalsRequired,
		requireReason:       opts.RequireReason,
		oneTimeAccess:       opts.OneTimeAccess,
		recordingDir:        opts.RecordingDir,
		certRemindDays:      opts.CertRemindDays,
		requireRecording:    opts.RequireRecording,
		portalURL:           portalURL,
		guacdAddr:           opts.GuacdAddr,
		guacdRecordingPath:  opts.GuacdRecordingPath,
		guacdRDPSecurity:    opts.GuacdRDPSecurity,
		guacdIgnoreCert:     opts.GuacdIgnoreCert,
		rdpClipboard:        rdpClipboardMode(opts.RDPClipboard),
		authLimiter:         ratelimit.New(opts.AuthRatePerMin),
		keyFailLimiter:      ratelimit.New(opts.AuthRatePerMin),
		cmdGuard:            opts.CommandGuard,
		recKey:              apiRecKey(opts.EncryptRecordings, v),
		opaqueRecNames:      opts.OpaqueRecordingNames,
		rdpClipAudit:        guacd.NormalizeClipAudit(opts.RDPClipboardAudit),
		trustedProxyHops:    opts.TrustedProxyHops,
		sessions:            opts.Sessions,
		live:                opts.Live,
		cluster:             opts.Cluster,
		stepup:              opts.StepUp,
		bgThreshold:         opts.BreakGlassThreshold,
		bgTTL:               bgTTL,
		unseal:              newUnsealState(),
		alerter:             alerter,
		rotators:            rotators,
		verifiers:           verifiers,
		sshConnector:        sshConn,
		airGap:              opts.AirGap,
		discoveryDial:       opts.DiscoveryDial,
		reconfigure:         opts.Reconfigure,
		auditSignKey:        opts.AuditSignKey,
		sshCA:               opts.CA,
		sshOperatorCertTTL:  opts.SSHOperatorCertTTL,
		vendorAttestor:      opts.VendorAttestor,
		analytics:           opts.Analytics,
		analyticsWindow:     opts.AnalyticsWindow,
		analyticsAutoKill:   opts.AnalyticsAutoKill,
		analyticsBaseline:   opts.AnalyticsBaseline,
		analyticsAutoStepUp: opts.AnalyticsAutoStepUp,
		analyticsAlerted:    make(map[string]analyticsAlert),
		appSecretsEnabled:   opts.AppSecretsEnabled,
		metrics:             metrics.New(),
		log:                 logging.Component("api"),
		mux:                 http.NewServeMux(),
	}
	// The initial runtime snapshot comes from opts (built by main from the base
	// env config + stored overrides); PUT /api/config later swaps it via
	// applyReconfigure.
	s.rtc.Store(snapshot(RuntimeConfig{
		Authn:            authn,
		Directory:        opts.Directory,
		OIDC:             opts.OIDC,
		OIDCRoleMap:      opts.OIDCRoleMap,
		MFARequired:      opts.MFARequired,
		RevealDisabled:   opts.RevealDisabled,
		ApprovalRequired: opts.RequireApproval,
		ApprovalWindow:   opts.ApprovalWindow,
		CheckoutTTL:      opts.CheckoutTTL,
		AllowedProtocols: opts.AllowedProtocols,
	}))
	if s.analyticsWindow <= 0 {
		s.analyticsWindow = time.Hour
	}
	// A flagged actor is re-alerted (and, if critical, re-killed) once per cooldown
	// so a sustained or recurring incident isn't suppressed forever; the cooldown
	// tracks the scoring window.
	s.metrics.SetBuildInfo(opts.BuildVersion, opts.BuildCommit)
	s.analyticsCooldown = s.analyticsWindow
	if s.sessions != nil {
		s.metrics.SetActiveSessionsSource(func() int { return len(s.sessions.List()) })
	}
	if err := s.setupBroker(opts); err != nil {
		return nil, err
	}
	s.routes()
	s.handler = s.withAccessLog(s.withSecurityHeaders(s.mux))
	return s, nil
}

// ServeHTTP dispatches the request through the server's middleware chain and router.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// statusWriter captures the response status and byte count for the access log.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

// WriteHeader records the status code before writing it to the underlying writer.
func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Write proxies to the underlying writer, defaulting the status to 200 (as
// net/http does on an implicit write) and accumulating the byte count.
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// Flush forwards to the underlying writer so streaming handlers (the live
// session SSE endpoint) can push frames — the embedded http.ResponseWriter
// interface does not promote Flush on its own.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		if w.status == 0 {
			w.status = http.StatusOK
		}
		f.Flush()
	}
}

// Unwrap exposes the writer underneath, which is how http.ResponseController
// reaches capabilities this wrapper does not implement itself — SetWriteDeadline
// and SetReadDeadline today, whatever net/http adds tomorrow.
//
// Without it the wrapper is opaque: ResponseController stops at statusWriter,
// finds no deadline support, and returns ErrNotSupported. That is how the
// live-monitoring stream ended up capped at the server's 30s WriteTimeout even
// after the handler tried to clear it. The lesson is in the two methods below —
// Flush and Hijack are hand-forwarded, one per capability, each added after
// something broke. Unwrap generalises that instead of continuing to enumerate.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack forwards to the underlying writer so the WebSocket handler (the RDP
// tunnel) can take over the connection. The embedded http.ResponseWriter
// interface does not promote Hijack, so without this the access-log wrapper
// would fail every WebSocket upgrade with 501. The status is recorded as 101
// (Switching Protocols) for the log line.
func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	if w.status == 0 {
		w.status = http.StatusSwitchingProtocols
	}
	return hj.Hijack()
}

// withAccessLog logs one line per HTTP request (method, path, status, bytes,
// duration, actor, remote). Health probes are skipped to avoid noise.
func (s *Server) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip health/readiness/metrics probes: they are high-frequency and would
		// drown the access log and inflate the request counter (self-counting).
		switch r.URL.Path {
		case "/healthz", "/readyz", "/metrics":
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		ri := &reqInfo{}
		ctx := context.WithValue(r.Context(), reqInfoKey, ri)
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r.WithContext(ctx))
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		s.metrics.HTTPRequest(sw.status)
		s.log.Info("http request",
			"method", r.Method, "path", r.URL.Path, "status", sw.status,
			"bytes", sw.bytes, "dur_ms", time.Since(start).Milliseconds(),
			"actor", ri.actor, "remote", r.RemoteAddr)
	})
}

// routes registers every HTTP route on the server's mux.
func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.health)         // liveness
	s.mux.HandleFunc("GET /readyz", s.readyz)          // readiness (store reachable)
	s.mux.HandleFunc("GET /metrics", s.metricsHandler) // Prometheus exposition
	s.mux.HandleFunc("GET /{$}", web.Index)
	s.mux.HandleFunc("GET /static/guacamole-common.min.js", web.GuacamoleJS) // vendored RDP viewer client

	// Authentication endpoints are rate-limited per client IP.
	s.mux.Handle("POST /api/login", s.rateLimit(http.HandlerFunc(s.login))) // public: this IS authentication
	s.mux.Handle("POST /api/logout", s.authenticated(s.logout))
	s.mux.Handle("GET /api/auth/oidc/start", s.rateLimit(http.HandlerFunc(s.oidcStart)))
	s.mux.Handle("GET /api/auth/oidc/callback", s.rateLimit(http.HandlerFunc(s.oidcCallback)))
	s.mux.Handle("POST /api/breakglass/unseal", s.rateLimit(http.HandlerFunc(s.breakGlassUnseal)))

	// Identity of the caller (drives the portal's role-aware menu).
	s.mux.Handle("GET /api/me", s.authenticated(s.me))

	// Self-service MFA (any authenticated identity manages its own second factor).
	s.mux.Handle("GET /api/mfa", s.authenticated(s.mfaStatus))
	s.mux.Handle("POST /api/mfa/enroll", s.authenticated(s.mfaEnroll))
	s.mux.Handle("POST /api/mfa/verify", s.rateLimit(s.authenticated(s.mfaVerify)))
	s.mux.Handle("POST /api/mfa/recovery-codes", s.authenticated(s.mfaRecoveryCodes))
	s.mux.Handle("DELETE /api/mfa", s.authenticated(s.mfaDisable))

	s.mux.Handle("POST /api/targets", s.authz(auth.CapManageTargets, s.createTarget))
	s.mux.Handle("GET /api/targets", s.authz(auth.CapReadInventory, pagedList(s, s.store.ListTargets)))
	s.mux.Handle("GET /api/targets/{id}", s.authz(auth.CapReadInventory, s.getTarget))
	s.mux.Handle("PUT /api/targets/{id}", s.authz(auth.CapManageTargets, s.updateTarget))
	s.mux.Handle("DELETE /api/targets/{id}", s.authz(auth.CapManageTargets, s.deleteTarget))

	s.mux.Handle("POST /api/targets/{id}/grants", s.authz(auth.CapManageTargets, s.createTargetGrant))
	s.mux.Handle("GET /api/targets/{id}/grants", s.authz(auth.CapManageTargets, s.listTargetGrants))
	s.mux.Handle("DELETE /api/targets/{id}/grants/{gid}", s.authz(auth.CapManageTargets, s.deleteTargetGrant))
	s.mux.Handle("PUT /api/targets/{id}/safe", s.authz(auth.CapManageTargets, s.setTargetSafe))

	// Safes (Phase 17): named containers grouping targets with delegated members.
	// Membership management is open to inventory readers so a delegated can_manage
	// member can grant access to their own safe (canManageSafe enforces it).
	s.mux.Handle("POST /api/safes", s.authz(auth.CapManageTargets, s.createSafe))
	s.mux.Handle("GET /api/safes", s.authz(auth.CapReadInventory, pagedList(s, s.store.ListSafes)))
	s.mux.Handle("PUT /api/safes/{id}", s.authz(auth.CapManageTargets, s.updateSafe))
	s.mux.Handle("DELETE /api/safes/{id}", s.authz(auth.CapManageTargets, s.deleteSafe))
	s.mux.Handle("GET /api/safes/{id}/members", s.authz(auth.CapReadInventory, s.listSafeMembers))
	s.mux.Handle("POST /api/safes/{id}/members", s.authz(auth.CapReadInventory, s.addSafeMember))
	s.mux.Handle("DELETE /api/safes/{id}/members/{mid}", s.authz(auth.CapReadInventory, s.deleteSafeMember))

	s.mux.Handle("POST /api/targets/{id}/winrm", s.authz(auth.CapConnect, s.runWinRM))
	s.mux.Handle("POST /api/rdp-token", s.authz(auth.CapConnect, s.rdpToken)) // mint a short-lived WS token for the viewer
	s.mux.Handle("POST /api/vnc-token", s.authz(auth.CapConnect, s.vncToken)) // same, for the VNC viewer
	s.mux.HandleFunc("GET /api/targets/{id}/rdp", s.rdpTunnel)                // WebSocket; auths via query token
	s.mux.HandleFunc("GET /api/targets/{id}/vnc", s.vncTunnel)                // WebSocket; auths via query token

	// Zero Standing Privilege (Phase 22): publish the SSH CA public key so an
	// operator can install it in a target's TrustedUserCAKeys. 404 when ZSP is off.
	s.mux.Handle("GET /api/ca/ssh", s.authz(auth.CapReadInventory, s.sshCAPublicKey))
	// Operator-issued SSH certificates + KRL revocation (Phase 28).
	s.mux.Handle("POST /api/ca/ssh/challenge", s.authz(auth.CapConnect, s.sshCACertChallenge))
	s.mux.Handle("POST /api/ca/ssh/sign", s.authz(auth.CapConnect, s.signOperatorCert))
	s.mux.Handle("POST /api/ca/ssh/revoke", s.authz(auth.CapManageTargets, s.revokeOperatorCert))
	s.mux.Handle("GET /api/ca/ssh/krl", s.authz(auth.CapReadInventory, s.sshCAKRL))
	s.mux.Handle("GET /api/ca/ssh/certs", s.authz(auth.CapReadInventory, s.listSSHCertsHandler))

	s.mux.Handle("POST /api/credentials", s.authz(auth.CapManageCredentials, s.createCredential))
	s.mux.Handle("GET /api/credentials", s.authz(auth.CapReadInventory, s.listCredentials))
	s.mux.Handle("POST /api/credentials/{id}/reveal", s.authz(auth.CapRevealSecret, s.revealCredential))
	s.mux.Handle("POST /api/credentials/{id}/rotate", s.authz(auth.CapManageCredentials, s.rotateCredentialHandler))
	s.mux.Handle("POST /api/credentials/{id}/reconcile", s.authz(auth.CapManageCredentials, s.reconcileCredentialHandler))
	s.mux.Handle("GET /api/reconcile", s.authz(auth.CapManageCredentials, s.reconcileAllHandler))
	s.mux.Handle("POST /api/credentials/{id}/checkout", s.authz(auth.CapRevealSecret, s.checkoutCredential))
	s.mux.Handle("POST /api/credentials/{id}/checkin", s.authz(auth.CapRevealSecret, s.checkinCredential))
	s.mux.Handle("GET /api/checkouts", s.authz(auth.CapReadAudit, s.listCheckouts))
	s.mux.Handle("POST /api/discovery/scan", s.authz(auth.CapManageTargets, s.discoveryScan))
	s.mux.Handle("DELETE /api/credentials/{id}", s.authz(auth.CapManageCredentials, s.deleteCredential))

	// Dependent accounts (Phase 17): a credential's consumers, updated over WinRM
	// on rotation so it does not break production.
	s.mux.Handle("POST /api/credentials/{id}/dependencies", s.authz(auth.CapManageCredentials, s.createDependency))
	s.mux.Handle("GET /api/credentials/{id}/dependencies", s.authz(auth.CapReadInventory, s.listDependencies))
	s.mux.Handle("DELETE /api/credentials/{id}/dependencies/{did}", s.authz(auth.CapManageCredentials, s.deleteDependency))

	// Access-request approval workflow (4-eyes). A connect-capable user files a
	// request; an approver (a *different* principal) approves or denies it.
	s.mux.Handle("POST /api/access-requests", s.authz(auth.CapConnect, s.createAccessRequest))
	s.mux.Handle("GET /api/access-requests", s.authz(auth.CapApprove, s.listAccessRequests))
	s.mux.Handle("POST /api/access-requests/{id}/approve", s.authz(auth.CapApprove, s.approveAccessRequest))
	s.mux.Handle("POST /api/access-requests/{id}/deny", s.authz(auth.CapApprove, s.denyAccessRequest))

	s.mux.Handle("GET /api/audit", s.authz(auth.CapReadAudit, s.listAudit))
	s.mux.Handle("GET /api/audit/export", s.authz(auth.CapReadAudit, s.exportAudit))
	s.mux.Handle("GET /api/audit/ocsf", s.authz(auth.CapReadAudit, s.exportOCSF))
	s.mux.Handle("GET /api/audit/verify", s.authz(auth.CapReadAudit, s.verifyAudit))
	s.mux.Handle("GET /api/audit/head", s.authz(auth.CapReadAudit, s.auditHead))

	s.mux.Handle("GET /api/sessions", s.authz(auth.CapReadAudit, s.listSessions))
	s.mux.Handle("GET /api/sessions/{id}/stream", s.authz(auth.CapReadAudit, s.streamSession))
	s.mux.Handle("POST /api/blast/analyze", s.authz(auth.CapReadAudit, s.analyzeBlast))  // Phase 31 (CIEM)
	s.mux.Handle("GET /api/sessions/stepups", s.authz(auth.CapReadAudit, s.listStepUps)) // Phase 30
	// Listing paused statements is a monitoring read (CapReadAudit, the same gate as
	// the live stream); DECIDING one releases a statement the policy flagged, which
	// is an execution-authorizing act — CapApprove, so a read-only auditor cannot
	// grant it (Phase 39).
	s.mux.Handle("POST /api/sessions/{id}/stepup", s.authz(auth.CapApprove, s.decideStepUp)) // Phase 30
	s.mux.Handle("DELETE /api/sessions/{id}", s.authz(auth.CapManageTargets, s.killSession))

	// Session-recording playback (Phase 26): list stored recordings and serve one
	// for replay, hash-verified against the audit trail. Content search over
	// stored SSH recordings (Phase 110) is a literal route, not a path value,
	// so it takes precedence over {name} at the same segment without any
	// recording ever being named "search" (recordingNameRe would refuse it).
	s.mux.Handle("GET /api/recordings", s.authz(auth.CapReadAudit, s.listRecordings))
	s.mux.Handle("GET /api/recordings/search", s.authz(auth.CapReadAudit, s.searchRecordings))
	s.mux.Handle("GET /api/recordings/{name}", s.authz(auth.CapReadAudit, s.playRecording))

	// Privileged threat analytics (Phase 23): behavioral risk scores over the
	// audit trail. Read-only, so an auditor may review risk without changing state.
	if s.analytics != nil {
		s.mux.Handle("GET /api/analytics/risk", s.authz(auth.CapReadAudit, s.analyticsRisk))
	}

	// Application-secrets API (Phase 24, Tier-4): Conjur-style secret delivery for
	// non-agent applications, opt-in via PAM_APP_SECRETS_ENABLED. The fetch path
	// authenticates an application bearer key; the admin routes reuse human RBAC —
	// app identity CRUD needs CapManageUsers, and delegating a secret to an app
	// needs CapRevealSecret (you can only hand out a secret you could reveal).
	if s.appSecretsEnabled {
		s.mux.HandleFunc("GET /v1/app-secrets/{id}", s.appAuth(s.fetchAppSecret))
		s.mux.Handle("POST /v1/apps", s.authz(auth.CapManageUsers, s.createAppKey))
		s.mux.Handle("GET /v1/apps", s.authz(auth.CapManageUsers, s.listAppKeys))
		s.mux.Handle("DELETE /v1/apps/{id}", s.authz(auth.CapManageUsers, s.deleteAppKey))
		s.mux.Handle("GET /v1/apps/{id}/grants", s.authz(auth.CapManageUsers, s.listAppSecretGrants))
		s.mux.Handle("POST /v1/apps/{id}/grants", s.authz(auth.CapRevealSecret, s.grantAppSecret))
		s.mux.Handle("DELETE /v1/apps/{id}/grants/{gid}", s.authz(auth.CapRevealSecret, s.deleteAppSecretGrant))
	}

	s.mux.Handle("POST /api/users", s.authz(auth.CapManageUsers, s.createUser))
	s.mux.Handle("GET /api/users", s.authz(auth.CapManageUsers, pagedList(s, s.store.ListUsers)))
	s.mux.Handle("PUT /api/users/{id}", s.authz(auth.CapManageUsers, s.updateUser))
	s.mux.Handle("DELETE /api/users/{id}", s.authz(auth.CapManageUsers, s.deleteUser))
	s.mux.Handle("GET /api/login-sessions", s.authz(auth.CapManageUsers, s.listLoginSessions))
	s.mux.Handle("POST /api/login-sessions/revoke", s.authz(auth.CapManageUsers, s.revokeLoginSessions))
	s.mux.Handle("POST /api/identity/reconcile", s.authz(auth.CapManageUsers, s.reconcileIdentities))

	// Third-party vendor access gate (Phase 29).
	s.mux.Handle("POST /api/vendors", s.authz(auth.CapManageUsers, s.createVendor))
	s.mux.Handle("GET /api/vendors", s.authz(auth.CapReadInventory, pagedList(s, s.store.ListVendors)))
	s.mux.Handle("PUT /api/vendors/{id}", s.authz(auth.CapManageUsers, s.updateVendor))
	s.mux.Handle("POST /api/vendors/{id}/offboard", s.authz(auth.CapManageUsers, s.offboardVendor))
	s.mux.Handle("POST /api/vendors/{id}/grants", s.authz(auth.CapManageTargets, s.createVendorGrant))
	s.mux.Handle("GET /api/vendors/{id}/grants", s.authz(auth.CapReadInventory, s.listVendorGrants))
	s.mux.Handle("GET /api/vendors/{id}/evidence", s.authz(auth.CapReadAudit, s.vendorEvidence))
	s.mux.Handle("POST /api/vendor-grants/{gid}/approve", s.authz(auth.CapApprove, s.approveVendorGrant))
	s.mux.Handle("POST /api/vendor-grants/{gid}/revoke", s.authz(auth.CapManageTargets, s.revokeVendorGrant))

	// Access certification / attestation campaigns (Phase 19): a periodic review
	// of who has access to what; a revoke decision removes the underlying grant.
	s.mux.Handle("POST /api/campaigns", s.authz(auth.CapManageUsers, s.createCampaign))
	s.mux.Handle("GET /api/campaigns", s.authz(auth.CapReadAudit, s.listCampaigns))
	s.mux.Handle("GET /api/campaigns/{id}", s.authz(auth.CapReadAudit, s.getCampaign))
	// Certifying or revoking an item is a review decision, not user administration:
	// CapApprove lets a dedicated reviewer run the campaign without holding the
	// access-granting capability (Phase 39). Creating and closing a campaign stay
	// CapManageUsers.
	s.mux.Handle("POST /api/campaigns/{id}/items/{iid}/decision", s.authz(auth.CapApprove, s.decideCampaignItem))
	s.mux.Handle("POST /api/campaigns/{id}/close", s.authz(auth.CapManageUsers, s.closeCampaign))
	// Assignment is administration (who reviews what), so manage_users — the same
	// gate as creating the campaign. Deciding stays approve.
	s.mux.Handle("PUT /api/campaigns/{id}/items/{itemID}/reviewer", s.authz(auth.CapManageUsers, s.assignCampaignItem))
	// A reviewer's own queue across every open campaign.
	s.mux.Handle("GET /api/campaigns/mine", s.authz(auth.CapApprove, s.myReviewQueue))

	// Custom permission profiles (Phase 12): named capability sets for users.
	s.mux.Handle("POST /api/profiles", s.authz(auth.CapManageUsers, s.createProfile))
	s.mux.Handle("GET /api/profiles", s.authz(auth.CapManageUsers, s.listProfiles))
	s.mux.Handle("DELETE /api/profiles/{id}", s.authz(auth.CapManageUsers, s.deleteProfile))

	// System configuration overrides (Phase 12): DB-persisted PAM_* settings.
	s.mux.Handle("GET /api/config", s.authz(auth.CapManageUsers, s.listConfig))
	s.mux.Handle("GET /api/config/effective", s.authz(auth.CapManageUsers, s.effectiveConfig))
	s.mux.Handle("GET /api/config/iac", s.authz(auth.CapManageUsers, s.iacConfig))
	s.mux.Handle("PUT /api/config", s.authz(auth.CapManageUsers, s.putConfig))
	s.mux.Handle("DELETE /api/config/{key}", s.authz(auth.CapManageUsers, s.deleteConfig))

	// AI-agent access broker (Phase 13), served only when a policy is configured.
	// Agent-facing routes authenticate an agent bearer key/SVID; operator-facing
	// routes reuse the human RBAC capabilities.
	if s.broker != nil {
		s.mux.HandleFunc("POST /v1/tool-calls", s.agentAuth(s.processToolCall))
		s.mux.HandleFunc("GET /v1/tool-calls/{id}", s.agentAuth(s.getToolCall))
		s.mux.HandleFunc("POST /v1/tool-calls/{id}/resume", s.agentAuth(s.resumeToolCall))
		s.mux.HandleFunc("POST /mcp", s.agentAuth(s.serveMCP))
		s.mux.HandleFunc("GET /mcp", s.agentAuth(s.serveMCPStream)) // MCP SSE transport (Phase 27)
		s.mux.Handle("GET /v1/approvals", s.authz(auth.CapApprove, s.listBrokerApprovals))
		s.mux.Handle("POST /v1/approvals/{id}/decision", s.authz(auth.CapApprove, s.decideBrokerApproval))
		s.mux.Handle("POST /v1/agents", s.authz(auth.CapManageUsers, s.createAgentKey))
		s.mux.Handle("GET /v1/agents", s.authz(auth.CapManageUsers, s.listAgentKeys))
		s.mux.Handle("DELETE /v1/agents/{id}", s.authz(auth.CapManageUsers, s.deleteAgentKey))
		s.mux.Handle("GET /v1/audit", s.authz(auth.CapReadAudit, s.listBrokerAudit))
		s.mux.Handle("GET /v1/audit/verify", s.authz(auth.CapReadAudit, s.verifyBrokerAudit))
		s.mux.Handle("GET /v1/audit/head", s.authz(auth.CapReadAudit, s.brokerAuditHead))
		s.mux.Handle("GET /v1/audit/jwks", s.authz(auth.CapReadAudit, s.brokerAuditJWKS))
		// RFC 8693 token exchange (Phase 57). Mounted with the broker but 404s
		// unless a signing key was configured, like the app-secrets surface.
		s.mux.HandleFunc("POST /v1/token", s.agentAuth(s.exchangeToken))
		s.mux.Handle("GET /v1/token/jwks", s.authz(auth.CapReadAudit, s.tokenJWKS))
	}
}

// authz resolves the caller into a Principal and enforces that its role holds
// the required capability. Break-glass use is deliberately loud: every request
// made with the emergency key appends a "breakglass.access" audit event and
// logs a warning.
func (s *Server) authz(cap auth.Capability, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.resolver.Resolve(r.Context(), r.Header.Get("X-API-Key"))
		if err != nil {
			s.authFailed(w, r, "api", "invalid or missing API key")
			return
		}
		setActor(r.Context(), p.Name)
		ctx := withPrincipal(r.Context(), p)
		s.noteBreakGlass(ctx, p, r)
		if p.EnrollOnly {
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" reason:mfa-enrollment-incomplete")
			writeError(w, http.StatusForbidden, "complete MFA enrollment to continue")
			return
		}
		if p.TunnelOnly {
			// An RDP-tunnel token (minted for the WS URL) must not reach any API endpoint,
			// so a copy leaked from a proxy log cannot act or re-mint itself.
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" reason:tunnel-only-token")
			writeError(w, http.StatusForbidden, "this token is only valid for the RDP tunnel")
			return
		}
		if !p.Can(cap) {
			s.log.Warn("authorization denied", "actor", p.Name, "role", string(p.Role),
				"method", r.Method, "path", r.URL.Path)
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" role:"+string(p.Role))
			writeError(w, http.StatusForbidden, "your role does not permit this action")
			return
		}
		next(w, r.WithContext(ctx))
	})
}

// noteBreakGlass loudly records and alerts a break-glass access (the security
// invariant: break-glass use is always audited + alerted). Every entry point that
// resolves its own principal outside the authz middleware — e.g. the RDP tunnel —
// must call this, or an emergency-key privileged action would go unnoticed.
// NoteBreakGlassSignal raises the out-of-band half of the break-glass signal —
// the Prometheus counter and the alert — for an emergency-key session opened
// somewhere other than the HTTP surface.
//
// The session proxies resolve their own principal, so they must raise this
// themselves (see proxy.noteBreakGlass, which writes the audit event and calls
// this through proxy.Config.OnBreakGlass). The split is deliberate: the proxy owns
// the audit record, because it owns the actor-quoting and detail conventions for
// its own listener, while the alerter and the metrics registry live here.
func (s *Server) NoteBreakGlassSignal(ctx context.Context, actor, detail string) {
	s.metrics.BreakGlass()
	s.log.Warn("BREAK-GLASS access", "actor", actor, "detail", detail)
	s.alerter.Notify(ctx, alert.Event{
		Type: "breakglass.access", Actor: actor, Detail: detail, Time: time.Now(),
	})
}

// noteBreakGlass loudly records a request served under the emergency break-glass
// key: it bumps the break-glass metric, logs a warning, appends an audit event
// and fires an alert. It is a no-op for a normally-authenticated principal, so
// callers can invoke it unconditionally on every request.
func (s *Server) noteBreakGlass(ctx context.Context, p *auth.Principal, r *http.Request) {
	if !p.BreakGlass {
		return
	}
	s.metrics.BreakGlass()
	s.log.Warn("BREAK-GLASS access", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
	s.audit(ctx, "breakglass.access", r.Method+" "+r.URL.Path)
	s.alerter.Notify(ctx, alert.Event{
		Type: "breakglass.access", Actor: p.Name,
		Detail: r.Method + " " + r.URL.Path, Remote: r.RemoteAddr, Time: time.Now(),
	})
}

// authenticated resolves the caller into a Principal without a capability
// check (used by endpoints any signed-in identity may call, e.g. logout).
func (s *Server) authenticated(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.resolver.Resolve(r.Context(), r.Header.Get("X-API-Key"))
		if err != nil {
			s.authFailed(w, r, "api", "invalid or missing API key")
			return
		}
		setActor(r.Context(), p.Name)
		ctx := withPrincipal(r.Context(), p)
		// Break-glass use is always loudly audited + alerted — including on the
		// low-sensitivity endpoints any signed-in identity may call (/me, /logout,
		// /mfa/*), so an emergency-key holder never acts entirely unrecorded.
		s.noteBreakGlass(ctx, p, r)
		if p.TunnelOnly {
			writeError(w, http.StatusForbidden, "this token is only valid for the RDP tunnel")
			return
		}
		next(w, r.WithContext(ctx))
	})
}

// apiRecKey returns the key wrapper used to seal recordings, or nil to write
// them in the clear. Encryption is opt-in and impossible without a vault.
func apiRecKey(enabled bool, v *vault.Vault) recording.KeyWrapper {
	if !enabled || v == nil {
		return nil
	}
	return v
}

// audit appends an audit event attributed to the actor in ctx, bumps the audit
// (and, for rotations, rotation) metrics, and logs it. A store failure is logged
// but not returned to the caller (best-effort; use mustAudit for secret paths).
func (s *Server) audit(ctx context.Context, action, detail string) {
	_ = s.auditAs(ctx, actorFrom(ctx), action, detail)
}

// auditAs appends an audit event with an explicit actor, for events where the
// actor is not the authenticated principal in ctx — notably failed logins, whose
// actor is the attempted (unauthenticated) username. It returns the store error
// so secret-use paths can fail closed (see mustAudit); non-secret callers ignore
// it and remain best-effort.
func (s *Server) auditAs(ctx context.Context, actor, action, detail string) error {
	e := store.AuditEvent{Actor: actor, Action: action, Detail: detail}
	err := s.store.AppendAudit(ctx, &e)
	if err != nil {
		s.log.Error("audit append failed", "action", action, "err", err)
	}
	s.metrics.Audit()
	if action == "credential.rotate" {
		s.metrics.Rotation()
	}
	s.log.Info("audit", "actor", actor, "action", action, "detail", detail)
	return err
}

// mustAudit records a secret-use audit event FAIL-CLOSED: the durable audit must
// persist before the secret is delivered. If the append fails it writes a 503 and
// returns false, so the caller aborts without handing out an unaudited secret —
// upholding the invariant that every secret use appends an audit event. This is
// the audit analogue of PAM_REQUIRE_RECORDING for the proxy.
func (s *Server) mustAudit(w http.ResponseWriter, ctx context.Context, action, detail string) bool {
	return s.mustAuditAs(w, ctx, actorFrom(ctx), action, detail)
}

// mustAuditAs is mustAudit with an explicit actor (e.g. an application identity).
func (s *Server) mustAuditAs(w http.ResponseWriter, ctx context.Context, actor, action, detail string) bool {
	if err := s.auditAs(ctx, actor, action, detail); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit log unavailable; secret access denied")
		return false
	}
	return true
}

// recordingRequired reports whether this path must refuse to proceed because
// PAM_REQUIRE_RECORDING is set and no recording can be produced.
//
// The flag shipped enforcing exactly this for the SSH proxy, the WinRM proxy and
// the PostgreSQL proxy — but not for the two paths that reach a target through
// the HTTP server: the in-portal RDP viewer and the REST WinRM endpoint. An
// operator who set it believed every session was recorded, and the two newest
// ways to reach a machine were the two it did not cover. That is the worst shape
// for a security control: silently narrower than its name.
//
// The check runs BEFORE anything happens on the target, because "refuse the
// session" only means something while there is still a session to refuse. For
// WinRM in particular the transcript is written after the command returns, so a
// post-hoc check would report a failure the command had already caused.
func (s *Server) recordingRequired(dir string) bool {
	return s.requireRecording && dir == ""
}

// beginStream prepares w for an open-ended Server-Sent Events response and
// clears this connection's write deadline.
//
// The deadline is the part that matters. http.Server carries a global
// WriteTimeout (30s here) which is exactly right for a request/response API and
// exactly wrong for a stream: net/http arms it before the handler runs, so a
// live-monitoring session was cut off mid-frame after thirty seconds no matter
// how healthy it was. Verified rather than assumed — an SSE stream under a 1s
// WriteTimeout delivers one frame and then fails with i/o timeout, and clearing
// the deadline delivers all of them.
//
// http.ResponseController is the supported way to reach past the global setting
// for one connection (Go 1.20+). It returns an error only if the underlying
// connection does not support deadlines, which for a real server it does; the
// error is surfaced so a future transport change cannot silently reintroduce a
// half-hour cap.
//
// Note this applies to SSE only. A hijacked WebSocket — the RDP viewer — does
// NOT inherit the server's write deadline, which was also verified rather than
// assumed before deciding it needed no change.
func (s *Server) beginStream(w http.ResponseWriter) (*http.ResponseController, bool) {
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		s.log.Error("stream: cannot clear write deadline; the stream would be cut at the server WriteTimeout", "err", err)
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return nil, false
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering
	return rc, true
}

// health is the liveness probe: it always reports ok while the process serves.
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// protocolSet turns a protocol list into a lookup set; an empty list returns nil,
// meaning "allow all protocols".
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

// protocolAllowed reports whether a target using proto may be created or
// connected to under the configured allowlist (nil allowlist = all allowed).
func (s *Server) protocolAllowed(proto string) bool {
	allowed := s.rt().allowedProtocols
	return allowed == nil || allowed[proto]
}

// readyz reports readiness: the server is up AND its store backend is reachable.
// Kubernetes should gate traffic on this, and liveness on /healthz.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		s.log.Warn("readiness check failed", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready", "reason": "store unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// metricsHandler serves the Prometheus exposition. It is intentionally
// unauthenticated (like /healthz) and exposes only low-sensitivity counts;
// restrict it at the network/ingress layer.
func (s *Server) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.WritePrometheus(w)
}
