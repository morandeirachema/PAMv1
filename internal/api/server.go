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

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/analytics"
	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/banner"
	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/cmdguard"
	"github.com/morandeirachema/pamv1/internal/guacd"
	"github.com/morandeirachema/pamv1/internal/icap"
	"github.com/morandeirachema/pamv1/internal/k8s"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/metrics"
	"github.com/morandeirachema/pamv1/internal/oidc"
	"github.com/morandeirachema/pamv1/internal/oncall"
	"github.com/morandeirachema/pamv1/internal/policy"
	"github.com/morandeirachema/pamv1/internal/posture"
	"github.com/morandeirachema/pamv1/internal/probe"
	"github.com/morandeirachema/pamv1/internal/ratelimit"
	"github.com/morandeirachema/pamv1/internal/recording"
	"github.com/morandeirachema/pamv1/internal/rotate"
	"github.com/morandeirachema/pamv1/internal/saml"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/sshca"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/ticket"
	"github.com/morandeirachema/pamv1/internal/vault"
	"github.com/morandeirachema/pamv1/internal/vendor"
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
	// Banners (Phase 276): the login banner (served publicly by GET /api/banner
	// for the sign-on screen) and the session notice a desktop must
	// acknowledge before its token is minted.
	Banners *banner.Banners
	// RDPDrive / RDPPrinter / RDPAudio / RDPAudioIn (Phase 270) are the
	// deployment ceilings for the desktop redirections a target's or grant's
	// rights may enable; a redirection off here stays off everywhere.
	RDPDrive, RDPPrinter, RDPAudio, RDPAudioIn bool
	// RADIUS / RADIUSSecondFactor (Phase 269) seed the runtime config; see
	// RuntimeConfig for their meaning.
	RADIUS             *auth.RADIUSAuthenticator
	RADIUSSecondFactor bool
	// MFARequired makes password login require a confirmed second factor: users
	// without one get an enrollment-only session until they set up MFA.
	MFARequired bool
	// SessionMFA (PAM_SESSION_MFA, Phase 244) requires a fresh second factor for
	// every session a human opens and every secret or certificate handed to one;
	// per-target and per-safe flags also apply (store.EffectiveSessionMFA).
	SessionMFA bool
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
	// PasswordPolicy configures every generated password's length and per-class
	// minimums (Phase 120, PAM_PASSWORD_MIN_*). Restart-only, unlike checkout
	// TTL: a domain-wide complexity policy is an infrequent, deliberate change,
	// not something worth the hot-swap plumbing.
	PasswordPolicy rotate.PasswordPolicy
	// PasswordHistoryCount is how many of a credential's past rotation hashes
	// are checked to refuse reissuing a recently-used password
	// (PAM_PASSWORD_HISTORY_COUNT). 0 (the default) disables the check
	// entirely, including the write, so an unconfigured deployment pays no
	// extra query on every rotation.
	PasswordHistoryCount int
	// CredentialFileMaxKB (Phase 145, PAM_CREDENTIAL_FILE_MAX_KB) caps a
	// SecretTypeFile credential's content at creation — refused over the cap,
	// not truncated.
	CredentialFileMaxKB int
	// ExtensionTokenTTL (Phase 147, PAM_EXTENSION_TOKEN_TTL_HOURS) bounds how
	// long a browser-extension autofill token stays valid before its holder
	// must mint a new one from the portal. Deliberately hours-to-days, not
	// rdpTokenTTL's seconds: this token lives in the extension's own local
	// storage, not a URL, so it needs to survive more than one page load.
	ExtensionTokenTTL time.Duration
	// CheckoutMaxExtend (Phase 120) bounds how long a checkout lease may run in
	// total, measured from CheckedOutAt — the ceiling POST
	// /api/checkouts/{id}/extend enforces. Restart-only, like CertRemindDays:
	// an infrequent policy change, not one worth hot-swap plumbing.
	CheckoutMaxExtend time.Duration
	// RequireRecording refuses a session that cannot be recorded, matching what
	// PAM_REQUIRE_RECORDING already did for the SSH and PostgreSQL proxies. It
	// covers the two paths the flag never reached: the in-portal RDP viewer and
	// the REST WinRM endpoint.
	RequireRecording bool
	// OIDC (optional) enables the browser Authorization Code login flow.
	OIDC *oidc.Provider
	// WebAuthn (optional) enables FIDO2/WebAuthn as an alternate second factor
	// to TOTP. Unlike OIDC this is NOT part of RuntimeConfig — PAM_WEBAUTHN_RP_ID/
	// _RP_ORIGIN name a domain, and re-pointing that at runtime without a
	// restart is a migration event, not a routine policy change.
	WebAuthn *webauthn.WebAuthn
	// OIDCRoleMap maps OIDC app-role/group claims to roles.
	OIDCRoleMap map[string]auth.Role
	// SAML (optional, Phase 151) enables the SAML 2.0 SP-initiated browser login
	// flow — for IdPs with no OIDC endpoint (on-prem ADFS). Hot-swappable like
	// OIDC, since it is identity configuration, not transport.
	SAML *saml.Provider
	// SAMLRoleMap maps SAML group/role attribute values to roles.
	SAMLRoleMap map[string]auth.Role
	// PortalURL is where the OIDC callback redirects (default "/").
	PortalURL string
	// SSHProxyAddr is the loopback address the in-portal SSH terminal (Phase
	// 254) dials the session proxy on; empty disables the terminal. The API
	// server is an SSH CLIENT of the proxy on the operator's behalf, so every
	// gate, the recording and the registry apply unchanged. SSHProxyHostKey
	// pins the proxy's own host key for that dial.
	SSHProxyAddr    string
	SSHProxyHostKey ssh.PublicKey
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
	// CommandAllowGuard (Phase 131), once set, narrows every command-control
	// path to ONLY commands it matches; deny still wins. nil = deny-only.
	CommandAllowGuard *cmdguard.Guard
	// EncryptRecordings seals session recordings and WinRM transcripts at rest
	// with a per-recording data key wrapped by the vault KEK (PAM_RECORDING_ENCRYPT).
	// Playback detects the format per file, so recordings written before it was
	// turned on keep replaying.
	EncryptRecordings bool
	// MaxRecordingBytes caps the recording the portal writes of one graphical
	// session (Phase 258; PAM_MAX_RECORDING_MB, 0 = unlimited) — the session
	// ends at the cap, as an SSH session does.
	MaxRecordingBytes int64
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
	// RequireTargetGrant refuses a connection to a target that has NO grants at
	// all (PAM_REQUIRE_TARGET_GRANT, Phase 203). False — the default — keeps
	// PAMv1's historical behaviour, where an unrestricted target is reachable by
	// any connect-capable principal. The reachability review (menu 31) renders
	// exactly those targets in red, so an operator can see the blast radius
	// before turning this on.
	RequireTargetGrant bool
	// Sessions is the live-session registry (shared with the proxy).
	Sessions *session.Registry
	// Live is the live-session output hub (shared with the proxy) that backs the
	// GET /api/sessions/{id}/stream monitoring endpoint (Phase 16).
	Live *session.Hub
	// Shares is the live-session input mux (shared with the SSH proxy) backing
	// session-sharing (Phase 116): nil disables the feature's HTTP surface, same
	// convention as Live/Sessions being nil.
	Shares *session.ShareRegistry
	// ShareInviteTTL is how long an approved session-share invite stays
	// redeemable (Phase 116). Locked at 15 minutes by product decision — see
	// config.Config.ShareInviteTTL's doc comment.
	ShareInviteTTL time.Duration
	// ShareGuestSessionTTL bounds how long a web-redeemed external invite's
	// guest key stays valid once redeemed (Phase 116) — separate from, and
	// much longer than, ShareInviteTTL.
	ShareGuestSessionTTL time.Duration
	// ApprovalInviteTTL is how long a magic-link access-request approval
	// invite stays redeemable (Phase 137) — see config.Config.ApprovalInviteTTL's
	// doc comment.
	ApprovalInviteTTL time.Duration
	// SlackWebhookURL/SlackSigningSecret (Phase 234) enable chat-ops access-
	// request approval — see config.Config's doc comments on both. Empty
	// disables the notify route; the interactivity callback route stays
	// registered either way but always refuses without a signing secret to
	// verify against.
	SlackWebhookURL    string
	SlackSigningSecret string
	// ShareSMTP{Addr,From,User,Pass} are the SMTP settings session-share
	// invite emails send through (Phase 116) — reused verbatim from
	// PAM_ALERT_EMAIL_* by main.go, so enabling security-alert email also
	// enables external session-share invites with no second config surface.
	// Empty ShareSMTPAddr/ShareSMTPFrom disables external (email+QR) invites;
	// internal (named-pamv1-user) invites are unaffected either way.
	ShareSMTPAddr string
	ShareSMTPFrom string
	ShareSMTPUser string
	ShareSMTPPass string
	// DigestTo / DigestHour configure the daily report digest (Phase 277):
	// mailed to DigestTo through the ShareSMTP relay once a day at DigestHour
	// UTC by RunDigestWorker. Empty DigestTo disables it.
	DigestTo   []string
	DigestHour int
	// TelnetEnabled allows telnet targets (PAM_TELNET_ENABLED, Phase 279).
	TelnetEnabled bool
	// ICAP is the content scanner (PAM_ICAP_URL); ICAPDesktop says which
	// desktop transfers the viewer holds for it (Phase 280: off, files,
	// clipboard, all) and ICAPDesktopMaxBytes bounds one held transfer.
	ICAP                *icap.Client
	ICAPDesktop         string
	ICAPDesktopMaxBytes int
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
	// ApprovalTimeout (Phase 274) expires a pending request nobody decided
	// within it (0 = never); the scheduler sweeps. ApprovalCommentRequired
	// makes every approve/deny/cancel carry the approver's comment.
	ApprovalTimeout         time.Duration
	ApprovalCommentRequired bool
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
	// UserTokenTTL is the default lifetime of a per-user access token minted by
	// POST /api/users or POST /api/users/{id}/token (Phase 242; 0 = the token
	// never expires, PAMv1's behaviour before Phase 242). A request may name
	// its own token_ttl_hours instead.
	UserTokenTTL time.Duration
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
	// Directory (optional) backs identity reconciliation: PAMv1 revokes access for
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
	// BrokerMaxResultBytes caps how much of a tool's RESULT reaches the agent
	// (0 = unbounded). The stored transcript keeps the full output either way.
	BrokerMaxResultBytes int
	// BrokerBudgetPerDay is the default cumulative cap on brokered tool calls per
	// agent over a rolling 24 hours (0 = unlimited). A per-agent budget on the
	// key overrides it. A rate limit bounds bursts; this bounds the total.
	BrokerBudgetPerDay int
	// BrokerRequireEnrolledSVID refuses an SVID-authenticated agent whose SPIFFE
	// ID has no enrolled row in agent_identities (Phase 174). Off by default:
	// with it off PAMv1 records every identity it sees so the inventory builds
	// itself, and with it on the trust domain's word stops being sufficient on
	// its own.
	BrokerRequireEnrolledSVID bool
	// BrokerRequireKnownOwner refuses a broker approval when the calling agent's
	// owner is not a PAMv1 user, rather than auditing it as unverified (Phase
	// 176). Off by default.
	BrokerRequireKnownOwner bool
	// BrokerPostureRequired extends the posture webhook to agent identities
	// (Phase 180). Off by default; needs PostureAttestor to be configured too.
	BrokerPostureRequired bool
	// BrokerMaxCallsPerToken caps how many brokered calls may be spent while
	// presenting ONE token, keyed on its `jti` (Phase 209). 0 = off. It is a
	// separate control from BrokerBudgetPerDay, not a replacement: the budget
	// bounds an agent's day, this bounds a single credential's whole life.
	// Identities that carry no token id (static agent keys) are unaffected.
	BrokerMaxCallsPerToken int
	// DoubleLockMinLength raises the minimum DoubleLock password length above the
	// built-in floor (PAM_DOUBLELOCK_MIN_LENGTH). 0 uses the floor.
	DoubleLockMinLength int
	// BrokerRequirePoP refuses an SVID-authenticated agent whose token carries no
	// RFC 7800 `cnf` binding (Phase 206) — i.e. it makes sender-constrained
	// tokens mandatory rather than available. Off by default, because turning it
	// on breaks every unbound token a deployment already issued.
	//
	// It is scoped to SVIDs on purpose: a STATIC agent key has no claims and so
	// can carry no confirmation, and requiring one of it would not make it
	// sender-constrained — it would only turn that identity kind off by a side
	// door. The way to stop accepting bearer agent keys is to stop configuring
	// them.
	BrokerRequirePoP bool
	// BrokerPublicURL is the base URL agents address this broker at, e.g.
	// "https://pam.example.com". It is what an RFC 9449 proof's `htu` claim is
	// compared against; unset derives it from each request, which is wrong behind
	// a TLS-terminating proxy (the request arrives as plain http on an internal
	// name, while the client signed the external https one).
	BrokerPublicURL  string
	BrokerRatePerMin int
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
	// leaves POST /v1/token unmounted — PAMv1 then verifies delegation without
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
	// PostureAttestor (optional) validates a user's live device posture on
	// every authenticated call and every session connect (Phase 133); nil
	// disables posture checking.
	PostureAttestor *posture.Attestor
	// OnCallAttestor (optional) validates a user is currently on call on
	// every authenticated call and every session connect (Phase 232); nil
	// disables on-call checking.
	OnCallAttestor *oncall.Attestor
	// DeviceHeader (optional) names the HTTP header a trusted reverse proxy
	// injects with the terminated client certificate's fingerprint
	// (Phase 133); empty disables device-identity checking entirely.
	DeviceHeader string
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
	// ScimEnabled turns on the SCIM 2.0 provisioning API (Phase 149): the SCIM
	// key admin routes and the /scim/v2/Users surface.
	ScimEnabled bool
	// SessionForensics (Phase 157) turns on post-session forensic
	// reconstruction: after an interactive SSH session ends, PAMv1 runs one
	// fixed, read-only command over that target's own vaulted credential to
	// pull the TARGET's kernel audit record of what actually executed during
	// the session window, and stores it beside the recording. Off by default —
	// it runs an extra command on the target after every session, which a site
	// must consent to. SessionForensicsMaxEvents caps the events an artifact
	// carries (0 = the package default), SessionForensicsTimeout bounds the
	// whole collection.
	SessionForensics          bool
	SessionForensicsMaxEvents int
	SessionForensicsTimeout   time.Duration
	// K8s (Phase 155) is the TEMPLATE for every brokered Kubernetes call: TLS
	// trust (PAM_K8S_CA_FILE / PAM_K8S_INSECURE_SKIP_VERIFY) and the request
	// bounds. Server and Token are filled per operation — the API server URL
	// comes from the target row, the bearer token from the vault, decrypted
	// just-in-time and discarded with the client.
	K8s k8s.Config
	// EndpointAgents (Phase 153) is the SHARED live registry of connected
	// outbound-only endpoint agents — the same instance the SSH proxy
	// registers into — so GET /api/endpoint-agents can report connectivity and
	// a revoke can drop the live tunnel. nil disables the feature (routes not
	// registered).
	EndpointAgents *session.EndpointAgents
	// ProbeHub (Phase 266) is the SHARED live registry of connected session
	// probes — the same instance the proxy serves. nil = probes disabled: the
	// probe routes are not registered and a probe-kind agent cannot be created.
	ProbeHub *probe.Hub
}

type Server struct {
	store                                      store.Store
	vault                                      *vault.Vault
	resolver                                   *auth.Resolver
	winrm                                      winrm.Runner
	recordingDir                               string
	webAuthn                                   *webauthn.WebAuthn
	certRemindDays                             int
	passwordPolicy                             rotate.PasswordPolicy
	passwordHistoryCount                       int
	credentialFileMaxKB                        int
	extensionTokenTTL                          time.Duration
	checkoutMaxExtend                          time.Duration
	requireRecording                           bool
	portalURL                                  string
	guacdAddr                                  string
	sshProxyAddr                               string
	sshProxyHostKey                            ssh.PublicKey
	guacdRecordingPath                         string
	guacdRDPSecurity                           string
	guacdIgnoreCert                            bool
	banners                                    *banner.Banners
	approvalTimeout                            time.Duration
	approvalCommentRequired                    bool
	rdpDrive, rdpPrinter, rdpAudio, rdpAudioIn bool
	rdpClipboard                               string
	authLimiter                                *ratelimit.Limiter
	// keyFailLimiter throttles FAILED bearer-credential attempts (X-API-Key,
	// agent key, application key) per source IP. It is separate from
	// authLimiter — which throttles every call to the login endpoints — because
	// a legitimate API client makes many successful calls a minute and only its
	// failures may be counted. Same budget (PAM_AUTH_RATE_LIMIT), own window.
	keyFailLimiter    *ratelimit.Limiter
	cmdGuard          *cmdguard.Guard
	cmdAllowGuard     *cmdguard.Guard
	recKey            recording.KeyWrapper
	opaqueRecNames    bool
	maxRecordingBytes int64
	// viewerJoins maps a live graphical session's registry id to what a
	// watcher needs to join it read-only (Phase 258). Replica-local, like the
	// guacd connection it names.
	viewerJoins        sync.Map
	rdpClipAudit       string
	trustedProxyHops   int
	sessions           *session.Registry
	live               *session.Hub
	shares             *session.ShareRegistry
	shareInviteTTL     time.Duration
	shareGuestTTL      time.Duration
	approvalInviteTTL  time.Duration
	slackWebhookURL    string
	slackSigningSecret string
	userTokenTTL       time.Duration
	sessionMFA         bool
	shareSMTPAddr      string
	shareSMTPFrom      string
	shareSMTPUser      string
	shareSMTPPass      string
	digest             digestState
	telnetEnabled      bool
	icap               *icap.Client
	icapDesktop        string
	icapDesktopMax     int
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
	postureAttestor    *posture.Attestor
	oncallAttestor     *oncall.Attestor
	deviceHeader       string
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
	scimEnabled         bool
	endpointAgents      *session.EndpointAgents
	probeHub            *probe.Hub
	k8sConfig           k8s.Config
	forensics           bool
	forensicsMaxEvents  int
	forensicsTimeout    time.Duration
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
	brokerLimiter *ratelimit.Limiter // per-agent tool-call rate limit (Phase 13)
	// brokerBudgetPerDay is the default cumulative per-agent call budget over a
	// rolling 24h (0 = unlimited); a per-agent value on the key overrides it.
	brokerBudgetPerDay int
	// brokerRequireEnrolledSVID refuses an SVID whose SPIFFE ID has no enrolled
	// row (Phase 174). Read on the agent authentication path.
	brokerRequireEnrolledSVID bool
	// brokerRequireKnownOwner refuses an approval whose agent owner matches no
	// PAMv1 user (Phase 176). Read on the approval-decision path.
	brokerRequireKnownOwner bool
	// brokerPostureRequired asks the posture webhook about the calling agent
	// (Phase 180). Read on the agent authentication path.
	brokerPostureRequired bool
	// brokerRequirePoP makes an RFC 7800 binding mandatory for SVID-authenticated
	// agents (Phase 206); brokerPublicURL is the origin a proof's `htu` is
	// checked against ("" = derive it from the request). popChecker verifies the
	// proofs and remembers them so none is accepted twice; nil unless the broker
	// is enabled.
	// brokerMaxCallsPerToken caps calls spent under one token's `jti` (Phase
	// 209); 0 = off. Read on the same path as the daily budget.
	brokerMaxCallsPerToken int
	// parkedSpends maps a parked call's id to the budget reservation it holds
	// (Phase 219), so the reservation can be settled when the call ends without
	// executing — denied by the approver, withdrawn, or expired. Parked calls
	// live in this replica's broker memory, and so does this.
	parkedSpends sync.Map
	// doubleLockMin is the configured minimum DoubleLock password length (H-3);
	// the effective minimum is never below the built-in floor.
	doubleLockMin    int
	brokerRequirePoP bool
	brokerPublicURL  string
	popChecker       *agentid.ProofChecker
	// svidSeen damps the inventory's last-seen writes to one per identity per
	// sightingInterval (Phase 176). Keyed by SPIFFE ID; values are time.Time.
	svidSeen sync.Map
	// svidSeenN counts svidSeen's entries so the damper can be bounded; it is a
	// hint, not a ledger — a racy over- or under-count only shifts when the map
	// is dropped, never what the damper decides.
	svidSeenN   atomic.Int64
	mcpSessions *mcpSessionRegistry // open MCP SSE streams for elicitation (Phase 27)
}

// RuntimeConfig is the set of settings PUT /api/config can change without a
// server restart (Phase 12 hot-swap): the identity backends and operational
// policy. main builds it from the base env config plus stored overrides and
// hands the server a Reconfigure closure that reproduces it after each change.
// Transport/bootstrap settings (listeners, TLS, DB URL, KEK) are not here —
// they stay environment-only and require a restart.
type RuntimeConfig struct {
	Authn     auth.Authenticator
	Directory auth.DirectorySource
	// RADIUS (Phase 269) is the RADIUS authenticator when one is configured.
	// In login mode it is ALSO inside Authn's chain, and is kept here so the
	// login handler can finish an Access-Challenge (Continue); in second-factor
	// mode (RADIUSSecondFactor) it is not in the chain and verifies the code a
	// directory-authenticated user typed.
	RADIUS             *auth.RADIUSAuthenticator
	RADIUSSecondFactor bool
	OIDC               *oidc.Provider
	OIDCRoleMap        map[string]auth.Role
	SAML               *saml.Provider
	SAMLRoleMap        map[string]auth.Role
	MFARequired        bool
	RevealDisabled     bool
	// RequireTargetGrant refuses a connection to a target with NO grants at all
	// (PAM_REQUIRE_TARGET_GRANT, Phase 203). False keeps the historical default.
	RequireTargetGrant bool
	ApprovalRequired   bool
	ApprovalWindow     time.Duration
	CheckoutTTL        time.Duration
	AllowedProtocols   []string
}

// Metrics exposes the server's collector, so a background worker wired in main
// can record into the same series the /metrics endpoint serves.
func (s *Server) Metrics() *metrics.Metrics { return s.metrics }

// runtimeConf is the server's immutable in-memory copy of a RuntimeConfig,
// stored behind s.rtc (atomic.Pointer) so in-flight requests read a consistent
// snapshot while a swap is in progress.
type runtimeConf struct {
	authn              auth.Authenticator
	directory          auth.DirectorySource
	radius             *auth.RADIUSAuthenticator
	radiusSecondFactor bool
	oidc               *oidc.Provider
	oidcRoleMap        map[string]auth.Role
	saml               *saml.Provider
	samlRoleMap        map[string]auth.Role
	mfaRequired        bool
	revealDisabled     bool
	// ungated is what a target with NO grants means here (Phase 203):
	// auth.UngatedOpen (anyone connect-capable reaches it — the historical
	// default) or auth.UngatedDeny under PAM_REQUIRE_TARGET_GRANT.
	ungated          auth.UngatedDefault
	approvalRequired bool
	approvalWindow   time.Duration
	checkoutTTL      time.Duration
	allowedProtocols map[string]bool
}

// ungatedDefault maps the deployment's boolean to the policy the authorization
// layer takes, so the mapping lives in exactly one place.
func ungatedDefault(requireGrant bool) auth.UngatedDefault {
	if requireGrant {
		return auth.UngatedDeny
	}
	return auth.UngatedOpen
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
		authn:              rc.Authn,
		radius:             rc.RADIUS,
		radiusSecondFactor: rc.RADIUSSecondFactor,
		directory:          rc.Directory,
		oidc:               rc.OIDC,
		oidcRoleMap:        rc.OIDCRoleMap,
		saml:               rc.SAML,
		samlRoleMap:        rc.SAMLRoleMap,
		mfaRequired:        rc.MFARequired,
		revealDisabled:     rc.RevealDisabled,
		ungated:            ungatedDefault(rc.RequireTargetGrant),
		approvalRequired:   rc.ApprovalRequired,
		approvalWindow:     rc.ApprovalWindow,
		checkoutTTL:        rc.CheckoutTTL,
		allowedProtocols:   protocolSet(rc.AllowedProtocols),
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
		store:                st,
		vault:                v,
		resolver:             resolver,
		winrm:                runner,
		ticketValidator:      opts.TicketValidator,
		requireTicket:        opts.RequireTicket,
		revalidateTicket:     opts.RevalidateTicket,
		approvalsRequired:    opts.ApprovalsRequired,
		requireReason:        opts.RequireReason,
		oneTimeAccess:        opts.OneTimeAccess,
		recordingDir:         opts.RecordingDir,
		webAuthn:             opts.WebAuthn,
		certRemindDays:       opts.CertRemindDays,
		passwordPolicy:       opts.PasswordPolicy,
		passwordHistoryCount: opts.PasswordHistoryCount,
		credentialFileMaxKB:  opts.CredentialFileMaxKB,
		extensionTokenTTL:    opts.ExtensionTokenTTL,
		checkoutMaxExtend:    opts.CheckoutMaxExtend,
		requireRecording:     opts.RequireRecording,
		portalURL:            portalURL,
		guacdAddr:            opts.GuacdAddr,
		sshProxyAddr:         opts.SSHProxyAddr,
		sshProxyHostKey:      opts.SSHProxyHostKey,
		doubleLockMin:        opts.DoubleLockMinLength,
		guacdRecordingPath:   opts.GuacdRecordingPath,
		guacdRDPSecurity:     opts.GuacdRDPSecurity,
		guacdIgnoreCert:      opts.GuacdIgnoreCert,
		banners:              opts.Banners,
		approvalTimeout:      opts.ApprovalTimeout, approvalCommentRequired: opts.ApprovalCommentRequired,
		rdpDrive: opts.RDPDrive, rdpPrinter: opts.RDPPrinter, rdpAudio: opts.RDPAudio, rdpAudioIn: opts.RDPAudioIn,
		rdpClipboard:        rdpClipboardMode(opts.RDPClipboard),
		authLimiter:         ratelimit.New(opts.AuthRatePerMin),
		keyFailLimiter:      ratelimit.New(opts.AuthRatePerMin),
		cmdGuard:            opts.CommandGuard,
		cmdAllowGuard:       opts.CommandAllowGuard,
		recKey:              apiRecKey(opts.EncryptRecordings, v),
		opaqueRecNames:      opts.OpaqueRecordingNames,
		maxRecordingBytes:   opts.MaxRecordingBytes,
		rdpClipAudit:        guacd.NormalizeClipAudit(opts.RDPClipboardAudit),
		trustedProxyHops:    opts.TrustedProxyHops,
		sessions:            opts.Sessions,
		live:                opts.Live,
		shares:              opts.Shares,
		shareInviteTTL:      opts.ShareInviteTTL,
		approvalInviteTTL:   opts.ApprovalInviteTTL,
		slackWebhookURL:     opts.SlackWebhookURL,
		slackSigningSecret:  opts.SlackSigningSecret,
		userTokenTTL:        opts.UserTokenTTL,
		sessionMFA:          opts.SessionMFA,
		shareGuestTTL:       opts.ShareGuestSessionTTL,
		shareSMTPAddr:       opts.ShareSMTPAddr,
		shareSMTPFrom:       opts.ShareSMTPFrom,
		shareSMTPUser:       opts.ShareSMTPUser,
		shareSMTPPass:       opts.ShareSMTPPass,
		digest:              digestState{to: opts.DigestTo, hour: opts.DigestHour},
		telnetEnabled:       opts.TelnetEnabled,
		icap:                opts.ICAP,
		icapDesktop:         opts.ICAPDesktop,
		icapDesktopMax:      opts.ICAPDesktopMaxBytes,
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
		postureAttestor:     opts.PostureAttestor,
		oncallAttestor:      opts.OnCallAttestor,
		deviceHeader:        opts.DeviceHeader,
		analytics:           opts.Analytics,
		analyticsWindow:     opts.AnalyticsWindow,
		analyticsAutoKill:   opts.AnalyticsAutoKill,
		analyticsBaseline:   opts.AnalyticsBaseline,
		analyticsAutoStepUp: opts.AnalyticsAutoStepUp,
		analyticsAlerted:    make(map[string]analyticsAlert),
		appSecretsEnabled:   opts.AppSecretsEnabled,
		scimEnabled:         opts.ScimEnabled,
		endpointAgents:      opts.EndpointAgents,
		probeHub:            opts.ProbeHub,
		k8sConfig:           opts.K8s,
		forensics:           opts.SessionForensics,
		forensicsMaxEvents:  opts.SessionForensicsMaxEvents,
		forensicsTimeout:    opts.SessionForensicsTimeout,
		metrics:             metrics.New(),
		log:                 logging.Component("api"),
		mux:                 http.NewServeMux(),
	}
	// The initial runtime snapshot comes from opts (built by main from the base
	// env config + stored overrides); PUT /api/config later swaps it via
	// applyReconfigure.
	s.rtc.Store(snapshot(RuntimeConfig{
		Authn:              authn,
		Directory:          opts.Directory,
		OIDC:               opts.OIDC,
		OIDCRoleMap:        opts.OIDCRoleMap,
		SAML:               opts.SAML,
		SAMLRoleMap:        opts.SAMLRoleMap,
		MFARequired:        opts.MFARequired,
		RADIUS:             opts.RADIUS,
		RADIUSSecondFactor: opts.RADIUSSecondFactor,
		RevealDisabled:     opts.RevealDisabled,
		ApprovalRequired:   opts.RequireApproval,
		ApprovalWindow:     opts.ApprovalWindow,
		CheckoutTTL:        opts.CheckoutTTL,
		AllowedProtocols:   opts.AllowedProtocols,
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

// authz resolves the caller into a Principal and enforces that its role holds
// the required capability. Break-glass use is deliberately loud: every request
// made with the emergency key appends a "breakglass.access" audit event and
// logs a warning.
func (s *Server) authz(cap auth.Capability, next http.HandlerFunc) http.Handler {
	return s.authzCore(cap, false, next)
}

// authzExtOK is authz's twin for the one route a browser-extension token
// (auth.SessionScopeExtension, Phase 147) may reach — currently only
// revealCredential. It runs every check authz does, in the same order,
// except it does not blanket-refuse ExtensionOnly: Can(cap) below still
// gates it normally, since a minted extension token inherits the minting
// user's own role/capabilities (issueSessionTTL), so a principal who could
// never reveal a secret still cannot via this route either.
func (s *Server) authzExtOK(cap auth.Capability, next http.HandlerFunc) http.Handler {
	return s.authzCore(cap, true, next)
}

// authzCore is authz and authzExtOK's shared body; allowExtension is the one
// difference between them. Keeping it in one place is deliberate — two
// near-identical copies of this checklist is exactly how a future gate added
// to one and not the other goes unnoticed.
func (s *Server) authzCore(cap auth.Capability, allowExtension bool, next http.HandlerFunc) http.Handler {
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
		if p.MFAPending {
			// A password-verified, WebAuthn-pending token is narrower than
			// EnrollOnly: it exists only to finish one specific login ceremony
			// (see mfaPendingOnly), so it must not reach any ordinary API route.
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" reason:mfa-webauthn-pending")
			writeError(w, http.StatusForbidden, "complete WebAuthn sign-in to continue")
			return
		}
		if p.TunnelOnly {
			// An RDP-tunnel token (minted for the WS URL) must not reach any API endpoint,
			// so a copy leaked from a proxy log cannot act or re-mint itself.
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" reason:tunnel-only-token")
			writeError(w, http.StatusForbidden, "this token is only valid for the RDP tunnel")
			return
		}
		if p.TerminalOnly {
			// A browser-terminal token (Phase 254) travels in a WebSocket URL
			// the same way, and is refused here for the same reason.
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" reason:terminal-only-token")
			writeError(w, http.StatusForbidden, "this token is only valid for the SSH terminal")
			return
		}
		if p.WatchOnly {
			// A watch token (Phase 258) travels in a WebSocket URL too.
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" reason:watch-only-token")
			writeError(w, http.StatusForbidden, "this token is only valid for watching a session")
			return
		}
		if p.SessionMFATicket {
			// A session-MFA ticket (Phase 244) opens one session and nothing
			// else. As an API key it could mint its own successor, so it is
			// refused on every route — the REST access paths take it in its
			// own header, beside the caller's real key.
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" reason:session-mfa-ticket")
			writeError(w, http.StatusForbidden, "a session-MFA ticket opens one session; it is not an API key")
			return
		}
		if p.ExtensionOnly && !allowExtension {
			// A browser-extension token reaching any route but the one it was
			// minted for (see authzExtOK) — refused the same way a leaked
			// RDP-tunnel token is, so a copy pulled from extension storage is
			// useless anywhere else in the API.
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" reason:extension-token-scope")
			writeError(w, http.StatusForbidden, "this token is only valid for the extension reveal endpoint")
			return
		}
		// Source IP allowlist (Phase 118), enrolled device (Phase 133) and live
		// posture (Phase 133), in that order, as one function shared with the
		// viewer tunnel — see sourceGates for why it is one.
		if reason, msg := s.sourceGates(ctx, p, r); reason != "" {
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" reason:"+reason)
			writeError(w, http.StatusForbidden, msg)
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

// sourceGates runs the four per-request principal gates that sit between the
// scope test and the capability test — the source-IP allowlist (Phase 118),
// the enrolled device fingerprint and live posture (Phase 133), and on-call
// attestation (Phase 232) — and returns the audit reason slug and the
// refusal message of the first that trips, or "" when all pass. Break-glass
// bypasses all four, as it does every other gate: emergency access is
// already loud on its own.
//
// One function because two doors need it: the authz middleware, and the
// RDP/VNC viewer tunnel, which resolves its own principal from a query-string
// token and, until the 2026-08-27 audit, ran none of these — a tunnel token
// minted from inside a user's allowlist opened the desktop from anywhere it
// was relayed to. That is the "self-resolving entry point with a shorter
// checklist" shape the 2026-08-26 audit's H-1/H-2 had; a gate added here
// lands on both doors at once, and the session proxies run the same checks in
// admit() (gates 5-7).
func (s *Server) sourceGates(ctx context.Context, p *auth.Principal, r *http.Request) (reason, msg string) {
	if p.BreakGlass {
		return "", ""
	}
	if !auth.IPAllowed(p.IPAllowlist, s.clientIP(r)) {
		return "source-ip-not-allowed", "your account may not connect from this network"
	}
	// s.deviceHeader empty (the default) skips this entirely — the header, if
	// present, is never even read.
	if s.deviceHeader != "" && p.DeviceFingerprint != "" && r.Header.Get(s.deviceHeader) != p.DeviceFingerprint {
		return "device-not-trusted", "this device is not enrolled for your account"
	}
	// Re-checked on every authenticated call, not just at connect, since
	// posture — unlike vendor employment — can change mid-session. A
	// nil/unconfigured attestor always passes.
	if s.postureAttestor.Enabled() {
		if err := s.postureAttestor.Attest(ctx, p.Name); err != nil {
			return "posture-check-failed", "your device failed its posture check"
		}
	}
	// On-call attestation (Phase 232): same shape as posture above, re-checked
	// on every authenticated call since shift status can change mid-session.
	if s.oncallAttestor.Enabled() {
		if err := s.oncallAttestor.Attest(ctx, p.Name); err != nil {
			return "oncall-check-failed", "you are not currently on call"
		}
	}
	return "", ""
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
		// A narrow-scope token reaching an authenticated-only route is refused,
		// AND recorded (2026-08-26 audit, F-8): authzCore audits every equivalent
		// refusal, and a leaked scoped token probing /me left no trace here. The
		// reason slug matches the one the proxies and the tunnel use for the same
		// scope, so the trail reads consistently wherever the refusal happened.
		// A narrow-scope token reaching an authenticated-only route is refused,
		// AND recorded (2026-08-26 audit, F-8): a leaked scoped token probing /me
		// left no trace here, unlike authzCore. EnrollOnly is deliberately NOT in
		// this set — an enrollment session must still reach /api/mfa/* to finish
		// setup, exactly as before; only the three fully-out-of-scope tokens are
		// refused. The reason slugs match the proxies' and the tunnel's.
		reason, msg := "", ""
		switch p.NarrowScope() {
		case auth.ScopeTunnelOnly:
			reason, msg = "tunnel-only-token", "this token is only valid for the RDP tunnel"
		case auth.ScopeMFAPending:
			reason, msg = "mfa-webauthn-pending", "complete WebAuthn sign-in to continue"
		case auth.ScopeExtensionOnly:
			reason, msg = "extension-scoped-token", "this token is only valid for the extension reveal endpoint"
		case auth.ScopeSessionMFA:
			reason, msg = "session-mfa-ticket", "a session-MFA ticket opens one session; it is not an API key"
		case auth.ScopeTerminal:
			reason, msg = "terminal-only-token", "this token is only valid for the SSH terminal"
		case auth.ScopeWatch:
			reason, msg = "watch-only-token", "this token is only valid for watching a session"
		}
		if reason != "" {
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" reason:"+reason)
			writeError(w, http.StatusForbidden, msg)
			return
		}
		// The source gates too (2026-08-27 audit): Phase 118 promised a local
		// user's token is IP-restricted "on every authenticated call", and this
		// middleware — /me, /logout and the MFA enrollment routes — had never run
		// them, so a token used from outside its allowlist could still enroll a
		// second factor. Same function as authz and the viewer tunnel.
		if reason, msg := s.sourceGates(ctx, p, r); reason != "" {
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" reason:"+reason)
			writeError(w, http.StatusForbidden, msg)
			return
		}
		next(w, r.WithContext(ctx))
	})
}

// mfaPendingOnly wraps the two routes that finish a WebAuthn login ceremony
// (POST /api/webauthn/login/begin and .../finish). It is the mirror image of
// authenticated: where authenticated refuses MFAPending, this refuses
// everyone EXCEPT MFAPending — a fully-authenticated principal has no reason
// to be starting a *pending* login, and letting one through here would let an
// already-logged-in user register an assertion against someone else's
// in-flight login state.
func (s *Server) mfaPendingOnly(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.resolver.Resolve(r.Context(), r.Header.Get("X-API-Key"))
		if err != nil {
			s.authFailed(w, r, "api", "invalid or missing API key")
			return
		}
		if !p.MFAPending {
			writeError(w, http.StatusForbidden, "no WebAuthn sign-in is pending")
			return
		}
		setActor(r.Context(), p.Name)
		next(w, r.WithContext(withPrincipal(r.Context(), p)))
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
