// Package config loads server configuration from PAM_* environment variables.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr  string
	DatabaseURL string
	MasterKey   string
	APIKey      string
	// BreakGlassKeyHash is the hex SHA-256 of the sealed emergency key
	// (optional; empty disables the break-glass path). Only the hash lives
	// in config so the plaintext key can be kept sealed offline.
	BreakGlassKeyHash string

	// SSHAddr is the session-proxy listen address; "off" disables it.
	SSHAddr string
	// DBAddr is the PostgreSQL session-proxy listen address; "off" disables it
	// (Phase 15). Operators reach postgres targets with psql through this port.
	DBAddr string
	// MSSQLAddr is the SQL Server (TDS) session-proxy listen address; "off"
	// disables it (Phase 53). Operators reach mssql targets with sqlcmd or any
	// TDS client through this port. Both database proxies share every policy
	// knob — TLS, upstream verification, command control, step-up, recording —
	// so an operator never has to reason about one being configured differently
	// from the other.
	MSSQLAddr string
	// SSHHostKeyPath persists the proxy host key; empty = ephemeral key.
	SSHHostKeyPath string
	// SSHCAKeyPath persists the Zero Standing Privilege SSH certificate-authority
	// key (Phase 22). When set, "ssh_ca" credentials are served by minting a
	// short-lived user certificate just-in-time instead of injecting a stored
	// secret. Empty = ZSP disabled. SSHCertTTL is the minted certificate's
	// validity (a small window, since it is minted fresh per session).
	SSHCAKeyPath string
	SSHCertTTL   time.Duration
	// SSHOperatorCertTTL caps an operator-issued SSH certificate (Phase 28): pamv1
	// signs an operator's own public key for direct target access. Longer than the
	// per-session ZSP TTL (an operator uses it interactively) but still short.
	SSHOperatorCertTTL time.Duration
	// SSHKnownHosts pins upstream target host keys (an OpenSSH known_hosts file).
	// Empty = trust any upstream key (insecure; logged loudly).
	SSHKnownHosts string
	// SSHSFTPMode is the file-transfer policy for SFTP sessions through the proxy:
	// "allow" (default — forward + audit every operation), "readonly" (refuse
	// writes/deletes/renames), or "deny" (refuse the SFTP subsystem entirely).
	SSHSFTPMode string
	// SSHSFTPDenyFile is a file of regular expressions (one per line, '#'
	// comments) matched against every SFTP path. A matching path is refused in
	// EVERY mode, reads included — denying a path an operator can still download
	// protects nothing (Phase 51). Empty disables the path policy.
	SSHSFTPDenyFile string
	// SSHSFTPCapture records the CONTENT of files moved over SFTP (Phase 59):
	// "off" (default), "uploads", "downloads", or "all". Each transferred file
	// becomes a chunk-log artifact stored with the session recordings, sealed
	// when PAM_RECORDING_ENCRYPT is on and hash-chained like a recording. While
	// enabled, an SFTP stream that cannot be parsed is refused (fail closed) —
	// capture is a containment control, not best-effort visibility.
	SSHSFTPCapture string
	// SSHSFTPCaptureMaxMB caps the captured bytes per transferred file
	// (0 = unlimited). Beyond the cap the transfer is REFUSED, not merely
	// unrecorded, mirroring the session-recording cap's posture — which makes
	// it double as a transfer size limit when capture is on.
	SSHSFTPCaptureMaxMB int
	// ICAPURL (Phase 143), when set, submits each finalized SFTP transfer to
	// an ICAP RESPMOD service (icap://host[:port]/service) for AV/DLP
	// scanning — detection only; see docs/ADMIN-GUIDE.md for why a whole-file
	// scan cannot block a transfer already in flight. Requires
	// PAM_SSH_SFTP_CAPTURE to be enabled and PAM_SSH_SFTP_CAPTURE_MAX_MB to
	// be set (validated below): the scan needs a complete captured file, and
	// a deployment that turns on scanning without bounding file size would
	// buffer an unbounded amount of memory per open transfer.
	ICAPURL string
	// SSHJump* route SSH targets through an SSH bastion (for legacy equipment only
	// reachable via a jump host). Empty SSHJumpHost disables it.
	SSHJumpHost string
	SSHJumpUser string
	SSHJumpKey  string // path to the bastion private key (PEM)
	// RecordingDir is where session recordings are written.
	RecordingDir string

	// LogLevel is debug|info|warn|error (default info).
	LogLevel string
	// LogFormat is json|text (default json).
	LogFormat string

	// TLSCert/TLSKey enable native HTTPS on the listen address when both are set.
	TLSCert string
	TLSKey  string
	// AuthRatePerMin limits auth attempts per client IP per minute (0 disables).
	// It budgets both every call to the login endpoints and — on its own window —
	// the FAILED bearer-credential attempts on the REST, agent-broker and
	// application-secrets surfaces (Phase 37).
	AuthRatePerMin int
	// TrustedProxyHops is the number of trusted reverse-proxy hops in front of the
	// API. 0 (default) keys the rate limiter on RemoteAddr; >0 takes the client IP
	// from the last N X-Forwarded-For entries (the hops YOU control), so per-IP
	// throttling still works behind a TLS-terminating proxy without trusting a
	// spoofable header end-to-end.
	TrustedProxyHops int
	// ProxyAuthRatePerMin limits failed authentication attempts per client IP per
	// minute on the SSH (:2222) and PostgreSQL (:5433) proxies, throttling online
	// guessing of the operator-chosen PAM_API_KEY (0 disables).
	ProxyAuthRatePerMin int
	// RequireHTTPS refuses to start the API/portal over plaintext HTTP when native
	// TLS (TLSCert/TLSKey) is not configured — fail-closed transport. Leave false
	// only when TLS is terminated by a trusted reverse proxy or for local demos.
	RequireHTTPS bool
	// RequireDBClientTLS refuses to start the PostgreSQL session proxy without TLS
	// on the operator-facing leg (TLSCert/TLSKey), so the operator's PAM key is
	// never sent to the DB proxy in cleartext.
	RequireDBClientTLS bool
	// DBUpstreamCA is a PEM CA bundle used to VERIFY the upstream PostgreSQL
	// server's TLS certificate on the database proxy's target leg. DBUpstreamTLSVerify
	// verifies against the system roots instead. Either enables fail-closed upstream
	// TLS so the JIT-injected DB credential can't be harvested by a MITM; unset
	// keeps the legacy trust-any-with-warning behavior.
	DBUpstreamCA        string
	DBUpstreamTLSVerify bool
	// AuditHMACKey, when set (base64 of 32 bytes), turns on tamper-evident
	// chaining of the PRIMARY audit trail: each event is HMAC-linked to the
	// previous one, so editing/reordering/deleting any event is detectable via
	// GET /api/audit/verify. Unset leaves the plain (unchained) audit table.
	AuditHMACKey string
	// AuditSignSeed, when set (base64 of 32 bytes) alongside AuditHMACKey, is an
	// ed25519 seed for signing audit-chain checkpoints (GET /api/audit/head). An
	// auditor stores a signed head and later detects TAIL TRUNCATION (which the
	// HMAC chain alone cannot catch). Unset disables the checkpoint endpoint.
	AuditSignSeed string
	// AuditForwardAddr, when set (host:port), streams every audit event to a SIEM
	// collector as it is written. AuditForwardProto is "udp" (default), "tcp" or
	// "tls" (syslog over TLS, RFC 5425 — certificate verification is always on);
	// AuditForwardFormat is "rfc5424" (default), "cef" or "leef";
	// AuditForwardCA optionally pins the collector's CA (PEM bundle path) for the
	// tls transport (empty = system roots); AuditForwardIntervalSec is the
	// polling cadence (default 10). Empty AuditForwardAddr disables it.
	AuditForwardAddr        string
	AuditForwardProto       string
	AuditForwardFormat      string
	AuditForwardCA          string
	AuditForwardIntervalSec int
	// RevealDisabled makes credential reveal break-glass-only.
	RevealDisabled bool

	// BreakGlassThreshold (M) enables M-of-N quorum unseal; BreakGlassShares (N)
	// is used by -split-key; BreakGlassTTL is the unsealed session lifetime.
	BreakGlassThreshold int
	BreakGlassShares    int
	BreakGlassTTL       time.Duration
	// AlertWebhook receives real-time break-glass alerts (JSON POST). AlertSyslog
	// ("udp://host:port" or "tcp://…") and the AlertEmail* fields add syslog and
	// SMTP alert channels; any combination fans out.
	AlertWebhook   string
	AlertSyslog    string
	AlertEmailSMTP string
	AlertEmailFrom string
	AlertEmailTo   string // comma-separated
	AlertEmailUser string
	AlertEmailPass string

	// MFARequired makes password login require a confirmed second factor —
	// TOTP or WebAuthn, whichever the user has confirmed.
	MFARequired bool

	// WebAuthnRPID/WebAuthnRPOrigin configure FIDO2/WebAuthn as an alternate
	// second factor to TOTP. Presence enables it, the same idiom OIDC uses —
	// there is no separate boolean flag. RPID is the effective domain (e.g.
	// "pam.example.com", no scheme/port); RPOrigin is the fully-qualified
	// origin browsers will present it as (e.g. "https://pam.example.com").
	// Both are read once at startup: a domain migration is an operational
	// event, not something to hot-reload like OIDC's config.
	WebAuthnRPID     string
	WebAuthnRPOrigin string

	// RotateInterval enables the background credential-lifecycle worker (reconcile
	// + max-age rotation); 0 disables it. RotateMaxAge rotates password
	// credentials older than this (0 = reconcile/report only).
	RotateInterval time.Duration
	RotateMaxAge   time.Duration
	// RotateAfterSession forces credential rotation when a proxied SSH session
	// ends, so a secret used in one session cannot be reused in the next.
	RotateAfterSession bool

	// RequireRecording refuses a proxied session when its recording cannot be
	// created, rather than proceeding unrecorded (fail-closed session auditing).
	RequireRecording bool
	// SSHPortForward enables client-initiated direct-tcpip channels (ssh -L
	// style forwarding) on the SSH proxy, scoped to the connected target's
	// own host only (Phase 141). Default true, matching SSHSFTPMode's
	// default-allow posture — an operator already fully authorized for a
	// target loses nothing by also being able to forward to it. Forwarding
	// is refused regardless of this setting for an observer session, or
	// while RequireSupervision/RequireRecording are configured: neither has
	// a mechanism that covers a raw, unrecordable byte stream.
	SSHPortForward bool
	// RequireSupervision refuses an interactive SSH session to proceed until a
	// supervisor actively watches it (GET /api/sessions/{id}/stream) or
	// SupervisionTimeout elapses — after-the-fact review isn't enough for a
	// deployment that sets it. Observer sessions and break-glass access are
	// exempt: an observer session already is the watching role, and an
	// emergency key exists precisely for when no supervisor is reachable.
	RequireSupervision bool
	// SupervisionTimeout bounds how long an interactive session waits for a
	// supervisor to attach before it is refused.
	SupervisionTimeout time.Duration
	// MaxSessionsPerUser / MaxSessionsTotal cap concurrent live proxied sessions
	// per actor and across all actors (0 = unlimited), bounding resource use from
	// a single (or compromised) identity. Per-replica in an HA deployment.
	MaxSessionsPerUser int
	MaxSessionsTotal   int
	// EncryptRecordings seals session recordings and WinRM transcripts at rest,
	// with a per-recording AES-256-GCM data key wrapped by the configured KEK.
	// Opt-in: it changes the on-disk format, so a plain `.cast` can no longer be
	// replayed with asciinema directly (replay through the portal instead).
	// Playback detects the format per file, so existing recordings keep working.
	EncryptRecordings bool
	// OpaqueRecordingNames names recording files by timestamp + random hex
	// instead of target + actor (Phase 48). Sealing (above) protects the
	// CONTENT; the file NAME still told anyone with volume, backup or snapshot
	// access who accessed which system, when. With this on, that metadata lives
	// only in the audited session.record / winrm.run events (which name the
	// file, the target and the actor), where reading it requires read_audit.
	// The console joins the two, so its listing still shows target and actor.
	OpaqueRecordingNames bool
	// MaxRecordingMB caps a single session recording's output in megabytes
	// (0 = unlimited); a session that exceeds it is terminated rather than run
	// unrecorded, so one runaway session can't fill the recording disk.
	MaxRecordingMB int
	// Retention (Phase 36): RecordingRetentionDays prunes recording files older
	// than N days; AuditRetentionDays deletes audit rows older than N days (skipped
	// when the tamper-evident chain is on). RetentionIntervalHours is the sweep
	// cadence. 0 days = keep forever.
	RecordingRetentionDays int
	AuditRetentionDays     int
	RetentionIntervalHours int
	// RetentionArchiveDir, when set, turns pruning into archive-then-prune
	// (Phase 49): aged audit rows are exported as digest-stamped JSON Lines and
	// aged recordings are MOVED into this directory — meant to be write-once
	// storage — and the delete runs only if that archive succeeded. Empty keeps
	// the plain delete-on-expiry behavior.
	RetentionArchiveDir string

	// OT hardening (Phase 8). RequireApproval gates every target's connect paths
	// behind an approved access request (4-eyes / maintenance window).
	// ApprovalWindow is how long an approval stays valid. AirGap disables all
	// outbound network calls (alert webhooks) for isolated deployments.
	RequireApproval bool
	ApprovalWindow  time.Duration
	AirGap          bool
	// ITSM / ticketing gate (Phase 20). RequireTicket makes an access request
	// carry a change/incident ticket; TicketPattern is a regex it must match and
	// TicketValidateURL is a webhook the ITSM system answers 2xx for a valid ticket.
	RequireTicket bool
	// RevalidateTicket re-checks the admitting access request's ITSM ticket at
	// the moment access is USED (connect, reveal, checkout, WinRM run, broker
	// tool), not only when the request was filed (Phase 60). Off by default: it
	// puts an ITSM call on the connect path, and it REFUSES when the ticket
	// cannot be confirmed — including when the ITSM is unreachable.
	RevalidateTicket  bool
	TicketPattern     string
	TicketValidateURL string
	// TicketProvider selects the ITSM connector: "webhook" (the default when a
	// URL is set), "servicenow" or "jira". The first-class connectors check the
	// ticket's STATE, its change WINDOW and whether it names the operator —
	// none of which a 2xx webhook can express (Phase 84).
	TicketProvider      string
	TicketURL           string
	TicketUser          string
	TicketToken         string
	TicketStates        []string
	TicketActorFields   []string
	TicketRequireWindow bool
	TicketBindActor     bool
	// Approval workflow (Phase 21). ApprovalsRequired is the default number of
	// distinct approvers an access request needs (multi-tier chains); a request
	// may ask for more. RequireReason rejects an access request with no reason.
	ApprovalsRequired int
	RequireReason     bool
	// OneTimeAccess (Phase 26) makes every access request single-use: the first
	// privileged use its approval admits consumes it. Individual requests can
	// also opt in per-request regardless of this default.
	OneTimeAccess bool
	// VendorAttestURL (Phase 29) is a webhook the vendor-management system answers
	// 2xx for a currently-employed vendor; checked when a contract grant is
	// approved. Empty disables attestation (grants approve without it).
	VendorAttestURL string
	// VendorSweepInterval runs a background sweep that cuts a vendor's live
	// sessions once their contract window closes or they are offboarded (0 = off).
	VendorSweepInterval time.Duration
	// PostureAttestURL (Phase 133) is a webhook the deployment's EDR/posture
	// system answers 2xx for a currently healthy device; checked on every
	// connect (session-proxy admit() and the REST authz middleware), not just
	// once at approval, since posture — unlike vendor employment — can change
	// between one connection and the next. Empty disables posture checking.
	PostureAttestURL string
	// DeviceHeader (Phase 133) is the name of an HTTP header a trusted
	// reverse proxy injects with the terminated client certificate's
	// fingerprint (the common nginx/Envoy mTLS-terminated-upstream pattern).
	// Empty (the default) disables device-identity checking entirely — the
	// header, if present, is never read. When set, a principal whose
	// enrolled store.User.DeviceFingerprint is non-empty must present a
	// matching value in this header to act; a principal with no enrolled
	// fingerprint is unaffected. pamv1 trusts whatever value arrives in this
	// header verbatim, so it must be deployed behind a reverse proxy that
	// performs real mTLS termination and strips any client-supplied value —
	// setting this without that proxy in place lets a caller self-assert any
	// device identity.
	DeviceHeader string
	// CheckoutTTL is the lifetime of a credential checkout lease.
	CheckoutTTL time.Duration
	// CheckoutMaxExtend (Phase 120, PAM_CHECKOUT_MAX_EXTEND_MIN, default 240)
	// is the longest a checkout lease may run in total, measured from
	// CheckedOutAt — the ceiling POST /api/checkouts/{id}/extend enforces, so
	// "extend" can push ExpiresAt out but never past a bound the holder
	// checked out under.
	CheckoutMaxExtend time.Duration
	// ShareInviteTTL (Phase 116) is how long an approved session-share invite
	// stays redeemable — 15 minutes by explicit product decision, not a
	// tunable default to casually raise: short enough that an intercepted
	// email (the external/vendor path) is a narrow window.
	ShareInviteTTL time.Duration
	// ShareGuestSessionTTL (Phase 116) bounds how long a web-redeemed external
	// invite's guest key stays valid, separate from (and much longer than)
	// ShareInviteTTL — the invite link itself is single-use and short-lived,
	// but once redeemed the guest's browser needs to keep streaming/typing for
	// the rest of the viewing, which the 15-minute window is not meant to cap.
	ShareGuestSessionTTL time.Duration
	// ApprovalInviteTTL (Phase 137) is how long a magic-link access-request
	// approval invite stays redeemable. Deliberately much longer than
	// ShareInviteTTL's 15 minutes: this is a decision link an approver may
	// not open for hours, closer in profile to a password-reset link than to
	// a live-session join link — 24 hours by default.
	ApprovalInviteTTL time.Duration
	// AllowedProtocols restricts which target protocols may be created and
	// connected to (comma-separated, e.g. "ssh,winrm"); empty = all allowed. Used
	// in OT zones to forbid protocols like RDP.
	AllowedProtocols string
	// CommandDenyFile is a file of regular expressions (one per line, '#'
	// comments) that block matching commands on the exec/WinRM/SQL paths
	// (Phase 16 command control). Empty disables command control.
	CommandDenyFile string
	// CommandAllowFile (Phase 131) is a file of regular expressions, same
	// format as CommandDenyFile, that — once set — narrows every command-
	// control path to ONLY the listed commands; deny still wins when both
	// would match. Empty leaves every path deny-only, unchanged from before
	// this existed.
	CommandAllowFile string
	// DBStepUpFile (Phase 30) is a file of regex patterns; a matching PostgreSQL
	// statement pauses for a supervisor's live approval before it runs.
	// DBStepUpTTL bounds how long a paused statement waits before it is denied.
	DBStepUpFile string
	DBStepUpTTL  time.Duration

	// Privileged threat analytics (Phase 23). AnalyticsInterval enables the
	// background risk-scoring worker (0 disables it; the read-only risk endpoint
	// stays available). AnalyticsWindow is how far back each scoring pass looks.
	// AnalyticsAutoKill terminates a critical-risk actor's live sessions.
	// AnalyticsBusinessStart/End bound business hours for the off-hours signal,
	// interpreted in AnalyticsTimezone (an IANA name; empty = UTC, matching the
	// UTC audit timestamps).
	AnalyticsInterval      time.Duration
	AnalyticsWindow        time.Duration
	AnalyticsAutoKill      bool
	AnalyticsBaselineDays  int
	AnalyticsAutoStepUp    bool
	AnalyticsBusinessStart int
	AnalyticsBusinessEnd   int
	AnalyticsTimezone      string

	// AppSecretsEnabled turns on the application-secrets API (Phase 24, Tier-4):
	// a Conjur-style path where a non-agent application retrieves the specific
	// secrets it has been granted with a bearer key. Opt-in (default off) because
	// it delivers plaintext secrets to machines — front it with TLS.
	AppSecretsEnabled bool

	// ScimEnabled turns on the SCIM 2.0 provisioning API (Phase 149):
	// /scim/v2/Users, authenticated by a narrowly-scoped bearer key (never a
	// human's own capability set), for push-based IdP user lifecycle —
	// create, deactivate, reactivate — as the real-time complement to the
	// existing pull-based POST /api/identity/reconcile. Opt-in (default
	// off): most deployments have no SCIM-speaking IdP, and this is a new
	// unauthenticated-until-bearer-key-checked surface not worth exposing
	// by default.
	ScimEnabled bool

	// SessionForensics turns on post-session forensic reconstruction (Phase
	// 157): after an interactive SSH session ends, pamv1 runs ONE fixed,
	// read-only command over that target's own vaulted credential to pull the
	// TARGET's kernel audit record (auditd) of what actually executed during
	// the session window, and stores it beside the recording — the only way a
	// PROXY can answer "what really ran" for a PTY it deliberately never
	// parses. Off by default: it runs an extra command on every target after
	// every session, which a site must consent to, and it needs the credential
	// to be able to read the target's audit log.
	SessionForensics bool
	// SessionForensicsMaxEvents caps the execs one artifact carries (a cap that
	// bites is reported as truncation, never silently), and
	// SessionForensicsTimeoutSec bounds the whole post-session collection.
	SessionForensicsMaxEvents  int
	SessionForensicsTimeoutSec int

	// K8sCAFile is a PEM CA bundle used to VERIFY a Kubernetes API server's TLS
	// certificate on the brokered-operation leg (Phase 155). Unset verifies
	// against the system roots, which is right for a managed cluster with a
	// publicly-rooted endpoint and wrong for the usual private cluster CA — so
	// most on-prem deployments set this. Several clusters' CAs may be
	// concatenated into one bundle. K8sInsecureSkipVerify disables verification
	// entirely (kind/minikube demos): the bearer token would then be handed to
	// whoever answers, so it is a loud, deliberate opt-in and never a default.
	K8sCAFile             string
	K8sInsecureSkipVerify bool
	// K8sTimeoutSec bounds one brokered Kubernetes request end to end, and
	// K8sMaxResponseKB caps the response body — over it the operation fails
	// closed rather than returning a truncated object or log.
	K8sTimeoutSec    int
	K8sMaxResponseKB int

	// EndpointAgentsEnabled turns on outbound-only endpoint agents (Phase 153,
	// BeyondTrust "Jump Client"-style): the SSH listener accepts the
	// "endpoint-agent:<name>" login (an agent's own bearer key, never a
	// human's), holds the reverse tunnel it requests, and reaches the bound
	// target through it; /api/endpoint-agents manages the agents. Opt-in
	// (default off), the same posture as PAM_SCIM_ENABLED: a new bearer-key
	// identity on a public listener is not worth accepting by default in a
	// deployment with no NAT'd endpoints to reach.
	EndpointAgentsEnabled bool

	// Broker (Phase 13, AI-agent access broker). Setting BrokerPolicyFile enables
	// the broker. The audit key + seed may be set explicitly — that is also how a
	// signing-key rotation is driven — and when left unset each is generated under
	// shared custody: sealed by the KEK into the store's key_material, converged
	// on by every replica, and re-wrapped by -rotate-kek like every other key.
	BrokerPolicyFile    string        // PAM_BROKER_POLICY_FILE — YAML policy rules; enables the broker
	BrokerAuditKey      string        // PAM_BROKER_AUDIT_KEY — base64 32-byte HMAC chain key (unset = shared custody)
	BrokerAuditSignSeed string        // PAM_BROKER_AUDIT_SIGN_SEED — base64 32-byte ed25519 seed (unset = shared custody)
	BrokerTokenTTL      time.Duration // PAM_BROKER_TOKEN_TTL_MIN — approval resume-token lifetime (default 15m)
	// CertRemindDays is how many days before a certification campaign's due date
	// the first reminder fires (PAM_CERT_REMIND_DAYS, default 7; 0 disables
	// reminders entirely). After the first, a campaign with pending items is
	// nudged daily until it is closed or emptied.
	CertRemindDays int
	// PasswordMinLength and PasswordMin{Lower,Upper,Digit,Symbol} configure
	// every generated password's shape (Phase 120, PAM_PASSWORD_MIN_LENGTH/
	// _LOWER/_UPPER/_DIGIT/_SYMBOL). Defaults (24, 1, 1, 1, 1) reproduce the
	// hardcoded policy every password had before this field existed, so an
	// unconfigured deployment generates byte-for-byte-equivalent passwords.
	PasswordMinLength                                                       int
	PasswordMinLower, PasswordMinUpper, PasswordMinDigit, PasswordMinSymbol int
	// PasswordHistoryCount is how many of a credential's past rotation hashes
	// are checked to refuse reissuing a recently-used password
	// (PAM_PASSWORD_HISTORY_COUNT, default 0 = off).
	PasswordHistoryCount int
	// CredentialFileMaxKB caps a SecretTypeFile credential's (base64) content
	// at creation (Phase 145, PAM_CREDENTIAL_FILE_MAX_KB). Refused over the
	// cap, not truncated — the same posture PAM_SSH_SFTP_CAPTURE_MAX_MB
	// already established — because a credential is not general object
	// storage, only somewhere small like a cert bundle or a license key
	// belongs. Unlike the SFTP cap, this one is never "unlimited": a new
	// storage class defaults to a sane ceiling from day one rather than
	// opening one up that has to be dialed back later.
	CredentialFileMaxKB int
	// ExtensionTokenTTLHours bounds how long a browser-extension autofill
	// token (Phase 147, PAM_EXTENSION_TOKEN_TTL_HOURS) stays valid before its
	// holder must mint a new one from the portal. Default 24h: long enough to
	// survive a workday of page loads without asking a user to re-mint
	// constantly, short enough that a token pulled from a compromised
	// endpoint's local storage has a bounded, forensically legible window.
	ExtensionTokenTTLHours int
	// ConjurRefreshMin is how often, in minutes, the refreshable bootstrap
	// secrets are re-read from Conjur (0 = off, the default). Only the secrets
	// that can be adopted by a running server are refreshed; see internal/conjur.
	ConjurRefreshMin  int
	BrokerMaxArgBytes int // PAM_BROKER_MAX_ARG_BYTES — cap on a tool call's serialized args (0 = off)
	// BrokerMaxResultBytes — PAM_BROKER_MAX_RESULT_BYTES — cap on how much of a
	// tool's RESULT travels back to the agent (0 = off). The durable transcript
	// still holds the full output; this bounds the copy that reaches the model's
	// context, which is both a cost and a prompt-injection surface.
	BrokerMaxResultBytes int
	// BrokerBudgetPerDay — PAM_BROKER_BUDGET_PER_DAY — default cumulative cap on
	// brokered tool calls per agent over a ROLLING 24 hours (0 = unlimited). A
	// per-agent budget on the key overrides it. The rate limit bounds bursts;
	// this bounds the total, which a rate limit cannot express: 60/minute is
	// still 86,400 privileged calls a day that nobody chose.
	BrokerBudgetPerDay int
	BrokerRatePerMin   int // PAM_BROKER_RATE_PER_MIN — per-agent tool-call rate limit (0 = off)
	// Audit-chain checkpoints + signing-key rotation (Phase 27).
	BrokerCheckpointEvery int    // PAM_BROKER_AUDIT_CHECKPOINT_EVERY — emit a signed in-chain checkpoint every N events (0 = off)
	BrokerAuditSignPrev   string // PAM_BROKER_AUDIT_SIGN_PREV — comma-separated base64 ed25519 PUBLIC keys still trusted after a signing-key rotation (overlap window)
	// SPIFFE JWT-SVID agent identity (Phase 13d). Setting the JWKS path enables it.
	BrokerTrustDomainJWKS string // PAM_BROKER_TRUST_DOMAIN_JWKS — file with the trust-domain JWKS
	BrokerTrustDomain     string // PAM_BROKER_TRUST_DOMAIN — SPIFFE trust domain host (e.g. example.org)
	BrokerAudience        string // PAM_BROKER_AUDIENCE — required SVID audience
	BrokerMaxDelegation   int    // PAM_BROKER_MAX_DELEGATION_DEPTH — RFC 8693 act-chain cap (default 1)
	// RequireTargetGrant — PAM_REQUIRE_TARGET_GRANT — refuse a connection to a
	// target that has NO grants at all: no direct grant, and not in a safe with
	// members.
	//
	// FALSE IS THE DEFAULT, and it is pamv1's historical behaviour: a target
	// nobody has restricted is reachable by every connect-capable principal,
	// human or agent. That is an estate-wide default rather than a decision
	// anyone made about a particular system, which is why the reachability review
	// (menu 31, GET /api/access/reach) renders those targets in red — they are
	// the finding, not the happy path.
	//
	// Turning it on is a real change for an existing estate, so it is opt-in
	// rather than flipped underneath anyone: read the review first, see how many
	// targets are reachable for reason "open", grant them deliberately, then set
	// this. Admins still bypass (an explicit decision about a role), and a
	// safe-scoped target was already default-deny.
	RequireTargetGrant bool
	// BrokerRequireEnrolledSVID — PAM_BROKER_REQUIRE_ENROLLED_SVID — refuse an
	// SVID whose SPIFFE ID has not been enrolled in agent_identities (Phase 174).
	// Off by default, because turning it on is a policy decision about the trust
	// domain: with it off, any workload the trust domain vouches for may call and
	// pamv1 records that it did; with it on, the trust domain's word is necessary
	// but no longer sufficient, and somebody has to have claimed the identity
	// first. Static agent keys are unaffected — pamv1 issued those itself.
	BrokerRequireEnrolledSVID bool
	// BrokerRequireKnownOwner — PAM_BROKER_REQUIRE_KNOWN_OWNER — refuse a broker
	// approval when the calling agent's owner matches no pamv1 user (Phase 176).
	// Off by default: a team address is a legitimate owner, and an owner that is
	// merely unrecognised is audited rather than blocked. On, the deployment is
	// saying that four-eyes it cannot verify is four-eyes it will not accept.
	BrokerRequireKnownOwner bool
	// BrokerMaxCallsPerToken — PAM_BROKER_MAX_CALLS_PER_TOKEN — cap how many
	// brokered calls may be spent while presenting ONE token, keyed on its `jti`
	// (Phase 209). 0 = off. Separate from BrokerBudgetPerDay rather than a
	// replacement: the budget bounds an agent's day, this bounds one
	// credential's whole life. A static agent key carries no token id and is
	// unaffected — its ceiling is the per-day budget on its own row.
	BrokerMaxCallsPerToken int
	// BrokerRequirePoP — PAM_BROKER_REQUIRE_POP — refuse an SVID-authenticated
	// agent whose token is not key-bound (RFC 7800 `cnf`, Phase 206), making
	// sender-constrained tokens mandatory instead of merely available. Off by
	// default: turning it on refuses every unbound token already in circulation.
	// Static agent keys carry no claims and are exempt by construction.
	BrokerRequirePoP bool
	// BrokerPublicURL — PAM_BROKER_PUBLIC_URL — the base URL agents address the
	// broker at (e.g. https://pam.example.com), used to check an RFC 9449 proof's
	// `htu` claim. Unset derives it per request, which is wrong behind a
	// TLS-terminating proxy. Must be an absolute http(s) URL with no path.
	BrokerPublicURL string
	// BrokerPostureRequired — PAM_BROKER_POSTURE_REQUIRED — also ask the posture
	// webhook about AGENT identities, not only human operators (Phase 180).
	// Separate from PAM_POSTURE_ATTEST_URL on purpose: a deployment that has been
	// attesting laptops has a webhook that knows laptops, and pointing agent
	// names at it unannounced would refuse every brokered call. Off by default;
	// when on, an unanswerable posture check refuses the call, like everywhere
	// else posture is enforced.
	BrokerPostureRequired bool

	// Token exchange (Phase 57): the MINTING half of delegation. Off by default —
	// issuing delegated identities is a privilege an operator opts into, separate
	// from merely verifying SVIDs.
	BrokerTokenExchange bool          // PAM_BROKER_TOKEN_EXCHANGE — enable POST /v1/token (RFC 8693)
	BrokerExchangeTTL   time.Duration // PAM_BROKER_EXCHANGE_TTL_MIN — delegated-token lifetime (default 5m)
	BrokerTokenSignSeed string        // PAM_BROKER_TOKEN_SIGN_SEED — base64 32-byte ed25519 seed (unset = shared custody)

	// WinRMHTTPS uses HTTPS (5986) for WinRM; WinRMInsecure skips TLS verify (dev).
	WinRMHTTPS    bool
	WinRMInsecure bool
	// WinRMNTLM selects NTLMv2 auth (required by most AD-joined hosts).
	WinRMNTLM bool
	// ProxyWinRM enables an interactive WinRM command loop through the SSH proxy
	// (ssh <cred>@<winrm-target>@pam). Opt-in — off by default.
	ProxyWinRM bool
	// GuacdAddr enables RDP brokering via an Apache Guacamole guacd daemon.
	GuacdAddr string
	// GuacdRecordingPath makes guacd record RDP sessions server-side.
	GuacdRecordingPath string
	// GuacdRDPSecurity sets the RDP security mode ("nla", "tls", "rdp", …); empty
	// lets guacd negotiate. GuacdIgnoreCert disables RDP server-cert verification
	// (dev only — default false verifies the certificate).
	GuacdRDPSecurity string
	GuacdIgnoreCert  bool
	// RDPClipboard is the in-portal RDP clipboard policy: "allow" (default),
	// "readonly" (block paste into the target — no clipboard injection), or "deny"
	// (clipboard off both ways). Drive redirection is always disabled.
	RDPClipboard string
	// RDPClipboardAudit records what crosses that bridge (Phase 50): "off"
	// (default), "meta" (direction, mimetype, byte count, SHA-256) or "full"
	// (also the content, truncated). Content auditing is opt-in on purpose: a
	// privileged desktop's clipboard routinely carries a password an operator
	// just copied, and the audit trail is readable by every auditor.
	RDPClipboardAudit string

	// KEKProvider selects the vault Key Encryption Key backend:
	// "local" (default, dev/test — uses MasterKey) or "vault-transit".
	KEKProvider string
	// Transit* configure the HashiCorp Vault Transit KEK (production).
	TransitAddr  string
	TransitToken string
	TransitKey   string
	// AWS* configure the AWS KMS KEK (production).
	AWSKMSKeyID string
	AWSRegion   string
	// PKCS11* configure the on-prem HSM KEK (only in builds tagged "pkcs11").
	PKCS11Module     string
	PKCS11Pin        string
	PKCS11KeyLabel   string
	PKCS11TokenLabel string

	// LDAP* configure Active Directory / LDAP login. Empty LDAPURL disables it.
	LDAPURL                string
	LDAPBindDN             string
	LDAPBindPassword       string
	LDAPBaseDN             string
	LDAPUserFilter         string
	LDAPInsecureSkipVerify bool
	LDAPGroupAdmin         string
	LDAPGroupUser          string
	LDAPGroupAuditor       string
	LDAPGroupApprover      string

	// Entra* configure Microsoft Entra ID (Azure AD) login. Empty tenant disables it.
	EntraTenantID      string
	EntraClientID      string
	EntraClientSecret  string
	EntraScope         string
	EntraAuthorityHost string
	EntraRoleAdmin     string
	EntraRoleUser      string
	EntraRoleAuditor   string
	EntraRoleApprover  string

	// OIDC* configure the browser Authorization Code login flow. Empty issuer disables it.
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	OIDCScopes       string // space-separated; default "openid profile"
	OIDCAuthURL      string // optional; discovered from issuer if empty
	OIDCTokenURL     string
	OIDCJWKSURL      string
	OIDCRoleAdmin    string
	OIDCRoleUser     string
	OIDCRoleAuditor  string
	OIDCRoleApprover string
	PortalURL        string

	// SAML* configure the SAML 2.0 SP-initiated browser login flow (Phase 151),
	// for IdPs with no OIDC endpoint (on-prem ADFS, or a SAML-only Okta/
	// OneLogin/Entra application). Empty SP URL disables it — the same
	// presence-enables idiom as OIDCIssuer. Exactly one of the two IdP-metadata
	// sources must be set when enabled. The two *_FILE settings are env/IaC-only
	// (not hot-swappable): a stored override must never be able to point the
	// server at an arbitrary file on its own host.
	SAMLSPURL           string // pamv1's public base URL, e.g. https://pam.example.com
	SAMLSPEntityID      string // optional; defaults to <SP URL>/api/auth/saml/metadata
	SAMLIDPMetadataURL  string // fetched once at build (and on hot-swap)
	SAMLIDPMetadataFile string // or the metadata document on disk (air-gapped sites)
	SAMLSPKeyFile       string // optional PEM RSA key: signs AuthnRequests, decrypts assertions
	SAMLSPCertFile      string // its certificate; published in the SP metadata
	SAMLNameAttr        string // optional assertion attribute for the username (default NameID)
	SAMLGroupAttr       string // optional comma-separated group attribute names (default: the common set)
	SAMLRoleAdmin       string
	SAMLRoleUser        string
	SAMLRoleAuditor     string
	SAMLRoleApprover    string
}

// Load reads configuration from the PAM_* environment variables, applying
// defaults, and returns an error if a required variable (API key, database URL,
// or the master key when the local KEK provider is used) is missing.
// commaList splits a comma-separated setting into trimmed, non-empty entries.
func commaList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// weakAPIKeyAllowed reports the PAM_ALLOW_WEAK_API_KEY escape hatch. Read here
// rather than through Load's `boolean` closure so the rule is usable from the
// refresh path too.
func weakAPIKeyAllowed() bool {
	v, err := strconv.ParseBool(strings.TrimSpace(os.Getenv("PAM_ALLOW_WEAK_API_KEY")))
	return err == nil && v
}

// MinAPIKeyLen is the floor for the bootstrap key.
const MinAPIKeyLen = 16

// ValidateBootstrapAPIKey reports why key is unfit to be PAM_API_KEY.
//
// It is exported because the runtime secret refresh (Phase 78) adopts a new
// bootstrap key without going through Load, and originally applied ANY non-empty
// value — so a running server could accept a three-character admin key that the
// same binary would refuse to start with, and the next restart CrashLooped on the
// error the running process had walked past. One rule, both paths (Phase 80).
func ValidateBootstrapAPIKey(key, databaseURL string) error {
	if key == "" {
		return errors.New("PAM_API_KEY is required")
	}
	if len(key) < MinAPIKeyLen && databaseURL != "memory" && !weakAPIKeyAllowed() {
		// The bootstrap key is presented as the SSH/DB proxy password and grants
		// admin; the proxies now throttle guessing, but a real (non-demo)
		// deployment must not run on a short, human-chosen key. The in-memory demo
		// store and an explicit PAM_ALLOW_WEAK_API_KEY escape hatch are exempt so
		// the quickstart keeps working.
		return fmt.Errorf("PAM_API_KEY must be at least %d characters (set PAM_ALLOW_WEAK_API_KEY=true to override, e.g. for demos)", MinAPIKeyLen)
	}
	return nil
}

// Load reads the full configuration from PAM_* environment variables into a
// Config, validating as it goes. It accumulates every problem rather than
// stopping at the first, so a misconfigured deployment surfaces all of its
// errors in one startup failure. A security toggle with a garbage value fails
// loud here rather than defaulting to a fail-open state.
// maxCallsPerToken bounds what PAM_BROKER_MAX_CALLS_PER_TOKEN may be set to. A
// ceiling far above any real task is indistinguishable from none while still
// reading to an operator as a control, which is the shape this validator refuses
// elsewhere too.
const maxCallsPerToken = 100_000

func Load() (*Config, error) {
	var errs []string
	// boolean parses a strict bool (true/false/1/0/t/f/…) and records an error for
	// any other value rather than silently falling back — a garbage value on a
	// security toggle (MFA, recording, air-gap) must fail loud, not fail open.
	boolean := func(key string, def bool) bool {
		v := os.Getenv(key)
		if v == "" {
			return def
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: invalid boolean %q (use true or false)", key, v))
			return def
		}
		return b
	}
	// integer parses an int and records an error for a non-integer value instead
	// of silently disabling the feature it configures.
	integer := func(key string, def int) int {
		v := os.Getenv(key)
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: invalid integer %q", key, v))
			return def
		}
		return n
	}
	cfg := &Config{
		ListenAddr:              getenv("PAM_LISTEN_ADDR", ":8080"),
		DatabaseURL:             os.Getenv("PAM_DATABASE_URL"),
		MasterKey:               os.Getenv("PAM_MASTER_KEY"),
		APIKey:                  os.Getenv("PAM_API_KEY"),
		BreakGlassKeyHash:       os.Getenv("PAM_BREAK_GLASS_KEY_HASH"),
		SSHAddr:                 getenv("PAM_SSH_ADDR", ":2222"),
		DBAddr:                  getenv("PAM_DB_ADDR", "off"),
		MSSQLAddr:               getenv("PAM_MSSQL_ADDR", "off"),
		SSHHostKeyPath:          os.Getenv("PAM_SSH_HOST_KEY"),
		SSHCAKeyPath:            os.Getenv("PAM_SSH_CA_KEY"),
		SSHCertTTL:              time.Duration(integer("PAM_SSH_CERT_TTL_MIN", 2)) * time.Minute,
		SSHOperatorCertTTL:      time.Duration(integer("PAM_SSH_OPERATOR_CERT_TTL_MIN", 10)) * time.Minute,
		SSHKnownHosts:           os.Getenv("PAM_SSH_KNOWN_HOSTS"),
		SSHSFTPMode:             strings.ToLower(getenv("PAM_SSH_SFTP", "allow")),
		SSHSFTPCapture:          strings.ToLower(getenv("PAM_SSH_SFTP_CAPTURE", "off")),
		SSHSFTPCaptureMaxMB:     integer("PAM_SSH_SFTP_CAPTURE_MAX_MB", 0),
		ICAPURL:                 getenv("PAM_ICAP_URL", ""),
		SSHJumpHost:             os.Getenv("PAM_SSH_JUMP_HOST"),
		SSHJumpUser:             os.Getenv("PAM_SSH_JUMP_USER"),
		SSHJumpKey:              os.Getenv("PAM_SSH_JUMP_KEY"),
		RecordingDir:            getenv("PAM_RECORDING_DIR", "recordings"),
		LogLevel:                getenv("PAM_LOG_LEVEL", "info"),
		LogFormat:               getenv("PAM_LOG_FORMAT", "json"),
		TLSCert:                 os.Getenv("PAM_TLS_CERT"),
		TLSKey:                  os.Getenv("PAM_TLS_KEY"),
		AuthRatePerMin:          integer("PAM_AUTH_RATE_LIMIT", 20),
		TrustedProxyHops:        integer("PAM_TRUSTED_PROXY_HOPS", 0),
		ProxyAuthRatePerMin:     integer("PAM_PROXY_AUTH_RATE_LIMIT", 10),
		RequireHTTPS:            boolean("PAM_REQUIRE_HTTPS", false),
		RequireDBClientTLS:      boolean("PAM_REQUIRE_DB_CLIENT_TLS", false),
		DBUpstreamCA:            os.Getenv("PAM_DB_UPSTREAM_CA"),
		DBUpstreamTLSVerify:     boolean("PAM_DB_UPSTREAM_TLS_VERIFY", false),
		AuditHMACKey:            os.Getenv("PAM_AUDIT_HMAC_KEY"),
		AuditForwardAddr:        os.Getenv("PAM_AUDIT_FORWARD_ADDR"),
		AuditForwardProto:       strings.ToLower(getenv("PAM_AUDIT_FORWARD_PROTO", "udp")),
		AuditForwardFormat:      strings.ToLower(getenv("PAM_AUDIT_FORWARD_FORMAT", "rfc5424")),
		AuditForwardCA:          os.Getenv("PAM_AUDIT_FORWARD_CA"),
		AuditForwardIntervalSec: integer("PAM_AUDIT_FORWARD_INTERVAL_SEC", 10),
		AuditSignSeed:           os.Getenv("PAM_AUDIT_SIGN_SEED"),
		RevealDisabled:          boolean("PAM_REVEAL_DISABLED", false),
		BreakGlassThreshold:     integer("PAM_BREAK_GLASS_THRESHOLD", 0),
		BreakGlassShares:        integer("PAM_BREAK_GLASS_SHARES", 5),
		BreakGlassTTL:           time.Duration(integer("PAM_BREAK_GLASS_TTL_MIN", 15)) * time.Minute,
		AlertWebhook:            os.Getenv("PAM_ALERT_WEBHOOK"),
		AlertSyslog:             os.Getenv("PAM_ALERT_SYSLOG"),
		AlertEmailSMTP:          os.Getenv("PAM_ALERT_EMAIL_SMTP"),
		AlertEmailFrom:          os.Getenv("PAM_ALERT_EMAIL_FROM"),
		AlertEmailTo:            os.Getenv("PAM_ALERT_EMAIL_TO"),
		AlertEmailUser:          os.Getenv("PAM_ALERT_EMAIL_USER"),
		AlertEmailPass:          os.Getenv("PAM_ALERT_EMAIL_PASS"),
		MFARequired:             boolean("PAM_MFA_REQUIRED", false),
		WebAuthnRPID:            os.Getenv("PAM_WEBAUTHN_RP_ID"),
		WebAuthnRPOrigin:        os.Getenv("PAM_WEBAUTHN_RP_ORIGIN"),
		RotateInterval:          time.Duration(integer("PAM_ROTATE_INTERVAL_MIN", 0)) * time.Minute,
		RotateMaxAge:            time.Duration(integer("PAM_ROTATE_MAX_AGE_HOURS", 0)) * time.Hour,
		RotateAfterSession:      boolean("PAM_ROTATE_AFTER_SESSION", false),
		RequireRecording:        boolean("PAM_REQUIRE_RECORDING", false),
		SSHPortForward:          boolean("PAM_SSH_PORT_FORWARD", true),
		RequireSupervision:      boolean("PAM_REQUIRE_LIVE_SUPERVISION", false),
		SupervisionTimeout:      time.Duration(integer("PAM_LIVE_SUPERVISION_TIMEOUT_SEC", 120)) * time.Second,
		MaxSessionsPerUser:      integer("PAM_MAX_SESSIONS_PER_USER", 0),
		MaxSessionsTotal:        integer("PAM_MAX_SESSIONS_TOTAL", 0),
		EncryptRecordings:       boolean("PAM_RECORDING_ENCRYPT", false),
		OpaqueRecordingNames:    boolean("PAM_RECORDING_OPAQUE_NAMES", false),
		RDPClipboardAudit:       strings.ToLower(getenv("PAM_RDP_CLIPBOARD_AUDIT", "off")),
		MaxRecordingMB:          integer("PAM_MAX_RECORDING_MB", 0),
		RecordingRetentionDays:  integer("PAM_RECORDING_RETENTION_DAYS", 0),
		AuditRetentionDays:      integer("PAM_AUDIT_RETENTION_DAYS", 0),
		RetentionIntervalHours:  integer("PAM_RETENTION_INTERVAL_HOURS", 24),
		RetentionArchiveDir:     os.Getenv("PAM_RETENTION_ARCHIVE_DIR"),
		RequireApproval:         boolean("PAM_REQUIRE_APPROVAL", false),
		ApprovalWindow:          time.Duration(integer("PAM_APPROVAL_WINDOW_MIN", 60)) * time.Minute,
		RequireTicket:           boolean("PAM_REQUIRE_TICKET", false),
		RevalidateTicket:        boolean("PAM_TICKET_REVALIDATE", false),
		TicketPattern:           os.Getenv("PAM_TICKET_PATTERN"),
		TicketValidateURL:       os.Getenv("PAM_TICKET_VALIDATE_URL"),
		TicketProvider:          strings.ToLower(strings.TrimSpace(os.Getenv("PAM_TICKET_PROVIDER"))),
		TicketURL:               os.Getenv("PAM_TICKET_URL"),
		TicketUser:              os.Getenv("PAM_TICKET_USER"),
		TicketToken:             os.Getenv("PAM_TICKET_TOKEN"),
		TicketStates:            commaList(os.Getenv("PAM_TICKET_STATES")),
		TicketActorFields:       commaList(os.Getenv("PAM_TICKET_ACTOR_FIELDS")),
		TicketRequireWindow:     boolean("PAM_TICKET_REQUIRE_WINDOW", true),
		// Binding the ticket to the person is the point of a first-class
		// connector, so it is ON by default. Off, a ticket number works as a
		// shared password.
		TicketBindActor:      boolean("PAM_TICKET_BIND_ACTOR", true),
		ApprovalsRequired:    integer("PAM_APPROVALS_REQUIRED", 1),
		RequireReason:        boolean("PAM_REQUIRE_REASON", false),
		OneTimeAccess:        boolean("PAM_ACCESS_ONE_TIME", false),
		VendorAttestURL:      getenv("PAM_VENDOR_ATTEST_URL", ""),
		VendorSweepInterval:  time.Duration(integer("PAM_VENDOR_SWEEP_INTERVAL_MIN", 0)) * time.Minute,
		PostureAttestURL:     getenv("PAM_POSTURE_ATTEST_URL", ""),
		DeviceHeader:         getenv("PAM_DEVICE_HEADER", ""),
		AirGap:               boolean("PAM_OT_AIRGAP", false),
		CheckoutTTL:          time.Duration(integer("PAM_CHECKOUT_TTL_MIN", 30)) * time.Minute,
		CheckoutMaxExtend:    time.Duration(integer("PAM_CHECKOUT_MAX_EXTEND_MIN", 240)) * time.Minute,
		ShareInviteTTL:       time.Duration(integer("PAM_SESSION_SHARE_INVITE_TTL_SEC", 900)) * time.Second,
		ApprovalInviteTTL:    time.Duration(integer("PAM_APPROVAL_INVITE_TTL_MIN", 1440)) * time.Minute,
		ShareGuestSessionTTL: time.Duration(integer("PAM_SESSION_SHARE_GUEST_TTL_MIN", 240)) * time.Minute,
		AllowedProtocols:     os.Getenv("PAM_ALLOWED_PROTOCOLS"),
		CommandDenyFile:      os.Getenv("PAM_COMMAND_DENY_FILE"),
		CommandAllowFile:     os.Getenv("PAM_COMMAND_ALLOW_FILE"),
		SSHSFTPDenyFile:      os.Getenv("PAM_SSH_SFTP_DENY_FILE"),
		DBStepUpFile:         os.Getenv("PAM_DB_STEPUP_FILE"),
		DBStepUpTTL:          time.Duration(integer("PAM_DB_STEPUP_TTL_SEC", 120)) * time.Second,

		AnalyticsInterval: time.Duration(integer("PAM_ANALYTICS_INTERVAL_MIN", 0)) * time.Minute,
		AnalyticsWindow:   time.Duration(integer("PAM_ANALYTICS_WINDOW_MIN", 60)) * time.Minute,
		AnalyticsAutoKill: boolean("PAM_ANALYTICS_AUTO_KILL", false),
		// 30 days of history for the novelty signal. On by default because a
		// nil baseline simply removes the signal — it never produces a false
		// positive — and because the first-run alert storm it might have caused
		// is already prevented by only scoring actors that HAVE history.
		AnalyticsBaselineDays:      integer("PAM_ANALYTICS_BASELINE_DAYS", 30),
		AnalyticsAutoStepUp:        boolean("PAM_ANALYTICS_AUTO_STEPUP", false),
		AnalyticsBusinessStart:     integer("PAM_ANALYTICS_BUSINESS_START", 7),
		AnalyticsBusinessEnd:       integer("PAM_ANALYTICS_BUSINESS_END", 20),
		AnalyticsTimezone:          os.Getenv("PAM_ANALYTICS_TIMEZONE"),
		AppSecretsEnabled:          boolean("PAM_APP_SECRETS_ENABLED", false),
		ScimEnabled:                boolean("PAM_SCIM_ENABLED", false),
		EndpointAgentsEnabled:      boolean("PAM_ENDPOINT_AGENTS_ENABLED", false),
		SessionForensics:           boolean("PAM_SESSION_FORENSICS", false),
		SessionForensicsMaxEvents:  integer("PAM_SESSION_FORENSICS_MAX_EVENTS", 500),
		SessionForensicsTimeoutSec: integer("PAM_SESSION_FORENSICS_TIMEOUT_SEC", 30),
		K8sCAFile:                  os.Getenv("PAM_K8S_CA_FILE"),
		K8sInsecureSkipVerify:      boolean("PAM_K8S_INSECURE_SKIP_VERIFY", false),
		K8sTimeoutSec:              integer("PAM_K8S_TIMEOUT_SEC", 30),
		K8sMaxResponseKB:           integer("PAM_K8S_MAX_RESPONSE_KB", 1024),
		BrokerPolicyFile:           os.Getenv("PAM_BROKER_POLICY_FILE"),
		BrokerAuditKey:             os.Getenv("PAM_BROKER_AUDIT_KEY"),
		BrokerAuditSignSeed:        os.Getenv("PAM_BROKER_AUDIT_SIGN_SEED"),
		BrokerTokenTTL:             time.Duration(integer("PAM_BROKER_TOKEN_TTL_MIN", 15)) * time.Minute,
		CertRemindDays:             integer("PAM_CERT_REMIND_DAYS", 7),
		PasswordMinLength:          integer("PAM_PASSWORD_MIN_LENGTH", 24),
		PasswordMinLower:           integer("PAM_PASSWORD_MIN_LOWER", 1),
		PasswordMinUpper:           integer("PAM_PASSWORD_MIN_UPPER", 1),
		PasswordMinDigit:           integer("PAM_PASSWORD_MIN_DIGIT", 1),
		PasswordMinSymbol:          integer("PAM_PASSWORD_MIN_SYMBOL", 1),
		PasswordHistoryCount:       integer("PAM_PASSWORD_HISTORY_COUNT", 0),
		CredentialFileMaxKB:        integer("PAM_CREDENTIAL_FILE_MAX_KB", 1024),
		ExtensionTokenTTLHours:     integer("PAM_EXTENSION_TOKEN_TTL_HOURS", 24),
		ConjurRefreshMin:           integer("PAM_CONJUR_REFRESH_MIN", 0),
		BrokerMaxArgBytes:          integer("PAM_BROKER_MAX_ARG_BYTES", 16384),
		BrokerMaxResultBytes:       integer("PAM_BROKER_MAX_RESULT_BYTES", 65536),
		BrokerBudgetPerDay:         integer("PAM_BROKER_BUDGET_PER_DAY", 0),
		RequireTargetGrant:         boolean("PAM_REQUIRE_TARGET_GRANT", false),
		BrokerRequireEnrolledSVID:  boolean("PAM_BROKER_REQUIRE_ENROLLED_SVID", false),
		BrokerRequireKnownOwner:    boolean("PAM_BROKER_REQUIRE_KNOWN_OWNER", false),
		BrokerPostureRequired:      boolean("PAM_BROKER_POSTURE_REQUIRED", false),
		BrokerRequirePoP:           boolean("PAM_BROKER_REQUIRE_POP", false),
		BrokerMaxCallsPerToken:     integer("PAM_BROKER_MAX_CALLS_PER_TOKEN", 0),
		BrokerPublicURL:            strings.TrimRight(strings.TrimSpace(os.Getenv("PAM_BROKER_PUBLIC_URL")), "/"),
		BrokerRatePerMin:           integer("PAM_BROKER_RATE_PER_MIN", 0),
		BrokerCheckpointEvery:      integer("PAM_BROKER_AUDIT_CHECKPOINT_EVERY", 0),
		BrokerAuditSignPrev:        getenv("PAM_BROKER_AUDIT_SIGN_PREV", ""),

		BrokerTrustDomainJWKS: os.Getenv("PAM_BROKER_TRUST_DOMAIN_JWKS"),
		BrokerTrustDomain:     os.Getenv("PAM_BROKER_TRUST_DOMAIN"),
		BrokerAudience:        os.Getenv("PAM_BROKER_AUDIENCE"),
		BrokerMaxDelegation:   integer("PAM_BROKER_MAX_DELEGATION_DEPTH", 1),
		BrokerTokenExchange:   boolean("PAM_BROKER_TOKEN_EXCHANGE", false),
		BrokerExchangeTTL:     time.Duration(integer("PAM_BROKER_EXCHANGE_TTL_MIN", 5)) * time.Minute,
		BrokerTokenSignSeed:   os.Getenv("PAM_BROKER_TOKEN_SIGN_SEED"),
		WinRMHTTPS:            boolean("PAM_WINRM_HTTPS", true), // default HTTPS
		WinRMInsecure:         boolean("PAM_WINRM_INSECURE_SKIP_VERIFY", false),
		WinRMNTLM:             os.Getenv("PAM_WINRM_AUTH") == "ntlm",
		ProxyWinRM:            boolean("PAM_PROXY_WINRM", false),
		GuacdAddr:             os.Getenv("PAM_GUACD_ADDR"),
		GuacdRecordingPath:    os.Getenv("PAM_GUACD_RECORDING_PATH"),
		GuacdRDPSecurity:      os.Getenv("PAM_GUACD_RDP_SECURITY"),
		GuacdIgnoreCert:       boolean("PAM_GUACD_IGNORE_CERT", false),
		RDPClipboard:          strings.ToLower(getenv("PAM_RDP_CLIPBOARD", "allow")),
		KEKProvider:           getenv("PAM_KEK_PROVIDER", "local"),
		TransitAddr:           os.Getenv("PAM_KEK_TRANSIT_ADDR"),
		TransitToken:          os.Getenv("PAM_KEK_TRANSIT_TOKEN"),
		TransitKey:            os.Getenv("PAM_KEK_TRANSIT_KEY"),
		AWSKMSKeyID:           os.Getenv("PAM_KEK_AWS_KEY_ID"),
		AWSRegion:             os.Getenv("PAM_KEK_AWS_REGION"),
		PKCS11Module:          os.Getenv("PAM_KEK_PKCS11_MODULE"),
		PKCS11Pin:             os.Getenv("PAM_KEK_PKCS11_PIN"),
		PKCS11KeyLabel:        os.Getenv("PAM_KEK_PKCS11_KEY_LABEL"),
		PKCS11TokenLabel:      os.Getenv("PAM_KEK_PKCS11_TOKEN_LABEL"),

		LDAPURL:                os.Getenv("PAM_LDAP_URL"),
		LDAPBindDN:             os.Getenv("PAM_LDAP_BIND_DN"),
		LDAPBindPassword:       os.Getenv("PAM_LDAP_BIND_PASSWORD"),
		LDAPBaseDN:             os.Getenv("PAM_LDAP_BASE_DN"),
		LDAPUserFilter:         os.Getenv("PAM_LDAP_USER_FILTER"),
		LDAPInsecureSkipVerify: boolean("PAM_LDAP_INSECURE_SKIP_VERIFY", false),
		LDAPGroupAdmin:         os.Getenv("PAM_LDAP_GROUP_ADMIN"),
		LDAPGroupUser:          os.Getenv("PAM_LDAP_GROUP_USER"),
		LDAPGroupAuditor:       os.Getenv("PAM_LDAP_GROUP_AUDITOR"),
		LDAPGroupApprover:      os.Getenv("PAM_LDAP_GROUP_APPROVER"),

		EntraTenantID:      os.Getenv("PAM_ENTRA_TENANT_ID"),
		EntraClientID:      os.Getenv("PAM_ENTRA_CLIENT_ID"),
		EntraClientSecret:  os.Getenv("PAM_ENTRA_CLIENT_SECRET"),
		EntraScope:         os.Getenv("PAM_ENTRA_SCOPE"),
		EntraAuthorityHost: os.Getenv("PAM_ENTRA_AUTHORITY_HOST"),
		EntraRoleAdmin:     os.Getenv("PAM_ENTRA_ROLE_ADMIN"),
		EntraRoleUser:      os.Getenv("PAM_ENTRA_ROLE_USER"),
		EntraRoleAuditor:   os.Getenv("PAM_ENTRA_ROLE_AUDITOR"),
		EntraRoleApprover:  os.Getenv("PAM_ENTRA_ROLE_APPROVER"),

		OIDCIssuer:       os.Getenv("PAM_OIDC_ISSUER"),
		OIDCClientID:     os.Getenv("PAM_OIDC_CLIENT_ID"),
		OIDCClientSecret: os.Getenv("PAM_OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:  os.Getenv("PAM_OIDC_REDIRECT_URL"),
		OIDCScopes:       os.Getenv("PAM_OIDC_SCOPES"),
		OIDCAuthURL:      os.Getenv("PAM_OIDC_AUTH_URL"),
		OIDCTokenURL:     os.Getenv("PAM_OIDC_TOKEN_URL"),
		OIDCJWKSURL:      os.Getenv("PAM_OIDC_JWKS_URL"),
		OIDCRoleAdmin:    os.Getenv("PAM_OIDC_ROLE_ADMIN"),
		OIDCRoleUser:     os.Getenv("PAM_OIDC_ROLE_USER"),
		OIDCRoleAuditor:  os.Getenv("PAM_OIDC_ROLE_AUDITOR"),
		OIDCRoleApprover: os.Getenv("PAM_OIDC_ROLE_APPROVER"),
		PortalURL:        os.Getenv("PAM_PORTAL_URL"),

		SAMLSPURL:           os.Getenv("PAM_SAML_SP_URL"),
		SAMLSPEntityID:      os.Getenv("PAM_SAML_SP_ENTITY_ID"),
		SAMLIDPMetadataURL:  os.Getenv("PAM_SAML_IDP_METADATA_URL"),
		SAMLIDPMetadataFile: os.Getenv("PAM_SAML_IDP_METADATA_FILE"),
		SAMLSPKeyFile:       os.Getenv("PAM_SAML_SP_KEY_FILE"),
		SAMLSPCertFile:      os.Getenv("PAM_SAML_SP_CERT_FILE"),
		SAMLNameAttr:        os.Getenv("PAM_SAML_NAME_ATTR"),
		SAMLGroupAttr:       os.Getenv("PAM_SAML_GROUP_ATTR"),
		SAMLRoleAdmin:       os.Getenv("PAM_SAML_ROLE_ADMIN"),
		SAMLRoleUser:        os.Getenv("PAM_SAML_ROLE_USER"),
		SAMLRoleAuditor:     os.Getenv("PAM_SAML_ROLE_AUDITOR"),
		SAMLRoleApprover:    os.Getenv("PAM_SAML_ROLE_APPROVER"),
	}
	// Normalize the disable sentinel so "off"/"OFF"/"Off" all disable the proxy.
	if strings.EqualFold(cfg.SSHAddr, "off") {
		cfg.SSHAddr = "off"
	}
	if strings.EqualFold(cfg.DBAddr, "off") {
		cfg.DBAddr = "off"
	}
	if strings.EqualFold(cfg.MSSQLAddr, "off") {
		cfg.MSSQLAddr = "off"
	}

	// MasterKey is required only for the local KEK provider; a KMS-backed
	// provider (e.g. vault-transit) holds the key material instead. The KEK
	// factory validates provider-specific settings at startup.
	if cfg.KEKProvider == "local" && cfg.MasterKey == "" {
		errs = append(errs, "PAM_MASTER_KEY is required for the local KEK (generate one with: pam-server -genkey), or set PAM_KEK_PROVIDER")
	}
	if cfg.APIKey == "" {
		errs = append(errs, "PAM_API_KEY is required")
	} else if err := ValidateBootstrapAPIKey(cfg.APIKey, cfg.DatabaseURL); err != nil {
		// The bootstrap key is presented as the SSH/DB proxy password and grants
		// admin; the proxies now throttle guessing, but a real (non-demo) deployment
		// must not run on a short, human-chosen key. The in-memory demo store and an
		// explicit PAM_ALLOW_WEAK_API_KEY escape hatch are exempt so the quickstart
		// keeps working.
		errs = append(errs, err.Error())
	}
	if cfg.DatabaseURL == "" {
		errs = append(errs, `PAM_DATABASE_URL is required (postgres://... or "memory" for an ephemeral demo)`)
	}
	// TLS must be all-or-nothing: one of cert/key set without the other would
	// silently downgrade the control plane to plaintext HTTP.
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		errs = append(errs, "PAM_TLS_CERT and PAM_TLS_KEY must both be set (HTTPS) or both empty (HTTP)")
	}
	// Break-glass quorum needs a threshold of at least 2; 1 or a negative value
	// would pass startup yet leave the M-of-N unseal path permanently disabled.
	if cfg.BreakGlassThreshold != 0 && (cfg.BreakGlassThreshold < 2 || cfg.BreakGlassThreshold > 255) {
		errs = append(errs, "PAM_BREAK_GLASS_THRESHOLD must be 0 (disabled) or between 2 and 255")
	}
	if cfg.BreakGlassThreshold >= 2 && cfg.BreakGlassShares < cfg.BreakGlassThreshold {
		errs = append(errs, "PAM_BREAK_GLASS_SHARES must be >= PAM_BREAK_GLASS_THRESHOLD")
	}
	// The broker's audit-chain keys are deliberately NOT required here: when unset
	// they are generated under shared custody at startup (sealed by the KEK in
	// key_material), so the verifiable log always has a key — the fail-loud check
	// on an explicitly-set malformed value lives in cmd/pam-server's buildBroker.
	// SPIFFE SVID identity needs its trust domain and audience to verify a subject
	// and reject cross-audience token replay; a JWKS file with neither would accept
	// any well-formed token in any trust domain.
	// Token exchange mints delegated identities, which only exist inside the SVID
	// world: the delegator must be SVID-authenticated and the minted token's actor
	// chain is verified against the trust domain. Enabling it without that is a
	// configuration that could never issue anything — fail loud rather than serve
	// an endpoint that refuses every request.
	if cfg.BrokerTokenExchange && cfg.BrokerTrustDomainJWKS == "" {
		errs = append(errs, "PAM_BROKER_TOKEN_EXCHANGE needs PAM_BROKER_TRUST_DOMAIN_JWKS: only an SVID-authenticated agent can delegate")
	}
	if cfg.BrokerTokenExchange && cfg.BrokerPolicyFile == "" {
		errs = append(errs, "PAM_BROKER_TOKEN_EXCHANGE needs the agent broker enabled (PAM_BROKER_POLICY_FILE)")
	}
	if cfg.BrokerTrustDomainJWKS != "" && (cfg.BrokerTrustDomain == "" || cfg.BrokerAudience == "") {
		errs = append(errs, "PAM_BROKER_TRUST_DOMAIN and PAM_BROKER_AUDIENCE are required when PAM_BROKER_TRUST_DOMAIN_JWKS is set")
	}
	// A control that is ON but cannot act is the failure this batch keeps
	// closing, one level up: not a dead field in the code, but a live field in
	// the CONFIGURATION whose prerequisite is absent. Each of these reads to an
	// operator as "the agents are gated", and each does nothing at all without
	// the thing it gates on — so each fails the startup loudly rather than
	// serving a deployment that believes it is stricter than it is.
	if cfg.BrokerRequireEnrolledSVID && cfg.BrokerTrustDomainJWKS == "" {
		errs = append(errs, "PAM_BROKER_REQUIRE_ENROLLED_SVID needs PAM_BROKER_TRUST_DOMAIN_JWKS: without it no agent authenticates with an SVID, so there is no enrollment to require")
	}
	if cfg.BrokerPostureRequired && cfg.PostureAttestURL == "" {
		errs = append(errs, "PAM_BROKER_POSTURE_REQUIRED needs PAM_POSTURE_ATTEST_URL: there is no posture system to ask")
	}
	// Same shape again for proof of possession (Phase 206): it constrains
	// SVID-authenticated agents, so without an SVID verifier it is a refusal that
	// can never fire — and an operator reading it would believe the agent fleet
	// was sender-constrained when nothing was.
	if cfg.BrokerRequirePoP && cfg.BrokerTrustDomainJWKS == "" {
		errs = append(errs, "PAM_BROKER_REQUIRE_POP needs PAM_BROKER_TRUST_DOMAIN_JWKS: without it no agent authenticates with an SVID, so there is no token that could carry a key binding")
	}
	// A ceiling must be a sane positive number. Negative is meaningless, and a
	// value far above any real task is indistinguishable from no ceiling while
	// reading to an operator as one — the shape this validator already refuses
	// elsewhere.
	if cfg.BrokerMaxCallsPerToken < 0 || cfg.BrokerMaxCallsPerToken > maxCallsPerToken {
		errs = append(errs, "PAM_BROKER_MAX_CALLS_PER_TOKEN must be between 0 (off) and 100000")
	}
	// The origin a proof is checked against must be an ORIGIN. A value with a
	// path, a query or a missing scheme would silently never match any request,
	// refusing every bound agent with nothing in the config to point at.
	if cfg.BrokerPublicURL != "" {
		u, err := url.Parse(cfg.BrokerPublicURL)
		switch {
		case err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https"):
			errs = append(errs, fmt.Sprintf("PAM_BROKER_PUBLIC_URL %q must be an absolute http(s) URL, e.g. https://pam.example.com", cfg.BrokerPublicURL))
		case u.Path != "" || u.RawQuery != "" || u.Fragment != "":
			errs = append(errs, fmt.Sprintf("PAM_BROKER_PUBLIC_URL %q must be a bare origin with no path, query or fragment", cfg.BrokerPublicURL))
		}
	}
	// The broker's own knobs, checked as a group so a future one is covered by
	// adding a line here rather than by remembering to. Numeric caps are
	// harmless when the broker is off; these three are refusals, and a refusal
	// that cannot happen is worth failing over.
	if cfg.BrokerPolicyFile == "" {
		for _, k := range []struct {
			name string
			set  bool
		}{
			{"PAM_BROKER_REQUIRE_KNOWN_OWNER", cfg.BrokerRequireKnownOwner},
			{"PAM_BROKER_REQUIRE_ENROLLED_SVID", cfg.BrokerRequireEnrolledSVID},
			{"PAM_BROKER_POSTURE_REQUIRED", cfg.BrokerPostureRequired},
			{"PAM_BROKER_REQUIRE_POP", cfg.BrokerRequirePoP},
			{"PAM_BROKER_MAX_CALLS_PER_TOKEN", cfg.BrokerMaxCallsPerToken > 0},
			// Added by the 2026-08-26 audit (T-4): four documents claimed this
			// knob "fails the startup loudly" without its prerequisite, and it
			// did not — only its URL shape was checked.
			{"PAM_BROKER_PUBLIC_URL", cfg.BrokerPublicURL != ""},
		} {
			if k.set {
				errs = append(errs, k.name+" needs the agent broker enabled (PAM_BROKER_POLICY_FILE)")
			}
		}
	}
	// Business-hours bounds must be a valid, non-empty window (the off-hours risk
	// signal is otherwise meaningless or inverted).
	if cfg.AnalyticsBusinessStart < 0 || cfg.AnalyticsBusinessEnd > 24 ||
		cfg.AnalyticsBusinessStart >= cfg.AnalyticsBusinessEnd {
		errs = append(errs, "PAM_ANALYTICS_BUSINESS_START/_END must satisfy 0 <= START < END <= 24")
	}
	// A bad timezone name must fail loud, not silently fall back to UTC and score
	// the off-hours signal in the wrong zone.
	if cfg.AnalyticsTimezone != "" {
		if _, err := time.LoadLocation(cfg.AnalyticsTimezone); err != nil {
			errs = append(errs, fmt.Sprintf("PAM_ANALYTICS_TIMEZONE %q is not a valid IANA timezone", cfg.AnalyticsTimezone))
		}
	}
	// A Zero Standing Privilege certificate must have a positive, short lifetime; a
	// zero/negative TTL would mint an already-expired certificate, and an overly
	// long one silently becomes a standing credential (defeating the point of ZSP).
	if cfg.SSHCAKeyPath != "" && cfg.SSHCertTTL <= 0 {
		errs = append(errs, "PAM_SSH_CERT_TTL_MIN must be >= 1 when PAM_SSH_CA_KEY is set")
	}
	if cfg.SSHCAKeyPath != "" && cfg.SSHCertTTL > 24*time.Hour {
		errs = append(errs, "PAM_SSH_CERT_TTL_MIN must be <= 1440 (24h) to keep ZSP certificates short-lived")
	}
	// SFTP file-transfer policy is a fixed enum; a typo must fail loud, not silently
	// fall back to the permissive default.
	switch cfg.SSHSFTPMode {
	case "allow", "readonly", "deny":
	default:
		errs = append(errs, fmt.Sprintf("PAM_SSH_SFTP must be one of allow, readonly, deny (got %q)", cfg.SSHSFTPMode))
	}
	// SFTP content capture is a fixed enum too: a typo must not silently record
	// nothing while the operator believes every transfer leaves evidence.
	switch cfg.SSHSFTPCapture {
	case "off", "uploads", "downloads", "all":
	default:
		errs = append(errs, fmt.Sprintf("PAM_SSH_SFTP_CAPTURE must be one of off, uploads, downloads, all (got %q)", cfg.SSHSFTPCapture))
	}
	// A year of history is plenty and bounds the audit read this performs on
	// every pass; negative is a fat-finger.
	if cfg.AnalyticsBaselineDays < 0 || cfg.AnalyticsBaselineDays > 366 {
		errs = append(errs, "PAM_ANALYTICS_BASELINE_DAYS must be between 0 (off) and 366")
	}
	// A refresh faster than a minute hammers Conjur for values that change
	// rarely; slower than a day is not a refresh.
	if cfg.ConjurRefreshMin < 0 || cfg.ConjurRefreshMin > 1440 {
		errs = append(errs, "PAM_CONJUR_REFRESH_MIN must be between 0 (off) and 1440")
	}
	// A reminder cadence outside a year is a typo, not a schedule. Unbounded, a
	// fat-fingered value silently means "remind immediately, every day, forever",
	// because a due date already inside the window clamps to now.
	if cfg.CertRemindDays < 0 || cfg.CertRemindDays > 366 {
		errs = append(errs, "PAM_CERT_REMIND_DAYS must be between 0 (reminders off) and 366")
	}
	// Each class minimum must be at least 1, not 0: every password generated by
	// this project has always contained at least one of each of the four
	// classes, as an unconditional guarantee, not a policy some deployment can
	// opt out of. (0 is not "disable this class" — it would just silently fall
	// back to the built-in default of 1 inside rotate.PasswordPolicy.Normalized,
	// which is confusing enough to refuse outright at config load instead.)
	if cfg.PasswordMinLength < 12 || cfg.PasswordMinLength > 256 {
		errs = append(errs, "PAM_PASSWORD_MIN_LENGTH must be between 12 and 256")
	}
	if cfg.PasswordMinLower < 1 || cfg.PasswordMinLower > 64 {
		errs = append(errs, "PAM_PASSWORD_MIN_LOWER must be between 1 and 64")
	}
	if cfg.PasswordMinUpper < 1 || cfg.PasswordMinUpper > 64 {
		errs = append(errs, "PAM_PASSWORD_MIN_UPPER must be between 1 and 64")
	}
	if cfg.PasswordMinDigit < 1 || cfg.PasswordMinDigit > 64 {
		errs = append(errs, "PAM_PASSWORD_MIN_DIGIT must be between 1 and 64")
	}
	if cfg.PasswordMinSymbol < 1 || cfg.PasswordMinSymbol > 64 {
		errs = append(errs, "PAM_PASSWORD_MIN_SYMBOL must be between 1 and 64")
	}
	if cfg.PasswordHistoryCount < 0 || cfg.PasswordHistoryCount > 50 {
		errs = append(errs, "PAM_PASSWORD_HISTORY_COUNT must be between 0 (off) and 50")
	}
	// No "0 = unlimited" escape hatch here, unlike the SFTP capture cap: this
	// caps a brand-new storage class rather than tightening an existing one,
	// so it starts bounded rather than opening unbounded and needing to be
	// dialed back later. The 10 MB ceiling is generous for a cert bundle or a
	// short document and still nowhere near "general file storage."
	if cfg.CredentialFileMaxKB < 1 || cfg.CredentialFileMaxKB > 10240 {
		errs = append(errs, "PAM_CREDENTIAL_FILE_MAX_KB must be between 1 and 10240")
	}
	// A 30-day ceiling is generous for "set it up once, use it for weeks" —
	// unlike the checkout-extension ceiling above, this token is meant to
	// outlive a single task, but it is still a bearer credential sitting in
	// an endpoint's local storage, so it does not get to be truly unbounded.
	if cfg.ExtensionTokenTTLHours < 1 || cfg.ExtensionTokenTTLHours > 720 {
		errs = append(errs, "PAM_EXTENSION_TOKEN_TTL_HOURS must be between 1 and 720")
	}
	// A checkout is meant to stay time-boxed even when extended, so the ceiling
	// itself is bounded — a week is generous for any legitimate maintenance
	// window and still far short of "standing access with extra steps."
	if cfg.CheckoutMaxExtend < time.Minute || cfg.CheckoutMaxExtend > 7*24*time.Hour {
		errs = append(errs, "PAM_CHECKOUT_MAX_EXTEND_MIN must be between 1 and 10080 (7 days)")
	}
	// Bounded at both ends: negative is a fat-finger, and a value large enough
	// to overflow the int64 byte count it becomes would wrap into a negative
	// cap — which reads as "unlimited" at one comparison and refuses everything
	// at another. 1 PiB is far above any real per-file transfer.
	if cfg.SSHSFTPCaptureMaxMB < 0 || cfg.SSHSFTPCaptureMaxMB > 1<<30 {
		errs = append(errs, "PAM_SSH_SFTP_CAPTURE_MAX_MB must be between 0 (unlimited) and 1073741824")
	}
	// ICAP scanning needs a COMPLETE captured file to submit, so it is
	// meaningless without capture on, and a deployment that enabled it
	// without also bounding file size would buffer an unbounded amount of
	// memory per open transfer (the same buffer capture's own disk artifact
	// is bounded by, mirrored in memory) — both must fail loud at startup
	// rather than silently scan nothing, or silently have no size ceiling.
	if cfg.ICAPURL != "" {
		if cfg.SSHSFTPCapture == "off" {
			errs = append(errs, "PAM_ICAP_URL requires PAM_SSH_SFTP_CAPTURE to be uploads, downloads, or all")
		}
		if cfg.SSHSFTPCaptureMaxMB <= 0 {
			errs = append(errs, "PAM_ICAP_URL requires PAM_SSH_SFTP_CAPTURE_MAX_MB to be set (> 0), so the in-memory scan buffer is bounded")
		}
		// A light, stdlib-only shape check: this package deliberately imports
		// no other internal/ package (it is the dependency root every other
		// package's config comes from), so it cannot call internal/icap.
		// NewClient directly. The strict parse — the same one NewClient
		// itself performs — runs again where the client actually gets built;
		// this exists so a malformed URL fails at startup, not on the first
		// file transfer.
		if u, err := url.Parse(cfg.ICAPURL); err != nil || u.Scheme != "icap" || u.Hostname() == "" || strings.TrimPrefix(u.Path, "/") == "" {
			errs = append(errs, fmt.Sprintf("PAM_ICAP_URL must look like icap://host[:port]/service (got %q)", cfg.ICAPURL))
		}
	}
	// RDP clipboard policy is the same fixed enum.
	switch cfg.RDPClipboard {
	case "allow", "readonly", "deny":
	default:
		errs = append(errs, fmt.Sprintf("PAM_RDP_CLIPBOARD must be one of allow, readonly, deny (got %q)", cfg.RDPClipboard))
	}
	// Clipboard auditing is a fixed enum too. A typo must fail loud rather than
	// silently fall back to "off" — an operator who asked for clipboard evidence
	// and got none would not find out until they needed it.
	switch cfg.RDPClipboardAudit {
	case "off", "meta", "full":
	default:
		errs = append(errs, fmt.Sprintf("PAM_RDP_CLIPBOARD_AUDIT must be one of off, meta, full (got %q)", cfg.RDPClipboardAudit))
	}
	// Retention windows are "0 = keep forever"; a negative value is a fat-finger
	// that must fail loud rather than silently delete or disable.
	if cfg.RecordingRetentionDays < 0 || cfg.AuditRetentionDays < 0 || cfg.RetentionIntervalHours < 1 {
		errs = append(errs, "PAM_RECORDING_RETENTION_DAYS / PAM_AUDIT_RETENTION_DAYS must be >= 0 and PAM_RETENTION_INTERVAL_HOURS >= 1")
	}
	// SIEM audit forwarding: validate the transport and format only when enabled,
	// fail-loud on a typo rather than silently not forwarding.
	if cfg.AuditForwardAddr != "" {
		if cfg.AuditForwardProto != "udp" && cfg.AuditForwardProto != "tcp" && cfg.AuditForwardProto != "tls" {
			errs = append(errs, fmt.Sprintf("PAM_AUDIT_FORWARD_PROTO must be udp, tcp or tls (got %q)", cfg.AuditForwardProto))
		}
		if cfg.AuditForwardFormat != "rfc5424" && cfg.AuditForwardFormat != "cef" && cfg.AuditForwardFormat != "leef" {
			errs = append(errs, fmt.Sprintf("PAM_AUDIT_FORWARD_FORMAT must be rfc5424, cef or leef (got %q)", cfg.AuditForwardFormat))
		}
		// A pinned CA only means something on the TLS transport — a typo'd proto
		// must not silently drop the pinning.
		if cfg.AuditForwardCA != "" && cfg.AuditForwardProto != "tls" {
			errs = append(errs, "PAM_AUDIT_FORWARD_CA requires PAM_AUDIT_FORWARD_PROTO=tls")
		}
		if cfg.AuditForwardIntervalSec < 1 {
			errs = append(errs, "PAM_AUDIT_FORWARD_INTERVAL_SEC must be >= 1")
		}
	}
	// Rate limits are "0 = off"; a negative value must fail loud rather than
	// silently disable throttling (a fat-fingered minus turning off brute-force
	// protection).
	if cfg.AuthRatePerMin < 0 {
		errs = append(errs, "PAM_AUTH_RATE_LIMIT must be >= 0 (0 disables)")
	}
	if cfg.MaxSessionsPerUser < 0 || cfg.MaxSessionsTotal < 0 || cfg.MaxRecordingMB < 0 {
		errs = append(errs, "PAM_MAX_SESSIONS_PER_USER / PAM_MAX_SESSIONS_TOTAL / PAM_MAX_RECORDING_MB must be >= 0 (0 disables)")
	}
	if cfg.BrokerRatePerMin < 0 || cfg.BrokerMaxArgBytes < 0 || cfg.BrokerMaxResultBytes < 0 || cfg.BrokerBudgetPerDay < 0 {
		errs = append(errs, "PAM_BROKER_RATE_PER_MIN, PAM_BROKER_MAX_ARG_BYTES, PAM_BROKER_MAX_RESULT_BYTES and PAM_BROKER_BUDGET_PER_DAY must be >= 0")
	}
	// Email alerting is all-or-nothing: a partial config silently drops the
	// detective break-glass alert channel while the operator believes it is armed.
	emailSet := 0
	for _, v := range []string{cfg.AlertEmailSMTP, cfg.AlertEmailFrom, cfg.AlertEmailTo} {
		if v != "" {
			emailSet++
		}
	}
	if emailSet != 0 && emailSet != 3 {
		errs = append(errs, "PAM_ALERT_EMAIL_SMTP, PAM_ALERT_EMAIL_FROM and PAM_ALERT_EMAIL_TO must all be set together (or all empty)")
	}
	errs = append(errs, airGapConflicts(cfg)...)
	if len(errs) > 0 {
		return nil, fmt.Errorf("config: %s", strings.Join(errs, "; "))
	}
	return cfg, nil
}

// airGapConflicts reports the integrations that would still reach the network
// while PAM_OT_AIRGAP is set.
//
// The flag's name is a promise, and for a long time the code kept only a small
// part of it: it was consulted in exactly one place — choosing the alerter — so
// the ITSM webhook, the vendor-attestation webhook, the SIEM forwarder, Conjur
// sourcing, a cloud KEK and a cloud identity provider all still made outbound
// calls. An operator sets this flag precisely because they cannot afford egress,
// so a flag that silences alerts and nothing else is worse than no flag: it
// manufactures confidence.
//
// The rule is default-deny with an explicit, per-variable escape hatch, because
// "air-gapped" rarely means "no network" — it usually means "nothing leaves this
// enclave". Several of these integrations can legitimately point at something
// inside the enclave (a local Conjur, an in-DMZ SIEM collector, a self-hosted
// Keycloak), and refusing those outright would push operators to turn the flag
// off, which is the opposite of what it is for. So:
//
//   - Anything that CANNOT be inside an enclave is refused outright: an AWS KMS
//     KEK and a Microsoft Entra tenant are somebody else's cloud by definition.
//   - Anything endpoint-shaped is refused unless the operator names it in
//     PAM_OT_AIRGAP_ALLOW, certifying that it resolves inside the enclave.
//
// The result is that egress is impossible by accident and possible on purpose,
// and the list of exceptions is written down in the deployment rather than
// living in somebody's head.
func airGapConflicts(cfg *Config) []string {
	if !cfg.AirGap {
		return nil
	}
	allowed := map[string]bool{}
	for _, name := range strings.Split(os.Getenv("PAM_OT_AIRGAP_ALLOW"), ",") {
		if n := strings.TrimSpace(name); n != "" {
			allowed[strings.ToUpper(n)] = true
		}
	}

	var errs []string
	// Endpoint-shaped: allowed if declared internal.
	for _, c := range []struct{ name, value string }{
		{"PAM_TICKET_VALIDATE_URL", cfg.TicketValidateURL},
		{"PAM_VENDOR_ATTEST_URL", cfg.VendorAttestURL},
		{"PAM_POSTURE_ATTEST_URL", cfg.PostureAttestURL},
		{"PAM_ICAP_URL", cfg.ICAPURL},
		{"PAM_AUDIT_FORWARD_ADDR", cfg.AuditForwardAddr},
		{"PAM_OIDC_ISSUER", cfg.OIDCIssuer},
		{"PAM_SAML_IDP_METADATA_URL", cfg.SAMLIDPMetadataURL},
		{"PAM_CONJUR_URL", os.Getenv("PAM_CONJUR_URL")},
		{"PAM_ALERT_WEBHOOK", cfg.AlertWebhook},
	} {
		if c.value != "" && !allowed[c.name] {
			errs = append(errs, fmt.Sprintf(
				"PAM_OT_AIRGAP is set but %s would make outbound calls; unset it, or add %s to PAM_OT_AIRGAP_ALLOW to certify that it resolves inside the enclave",
				c.name, c.name))
		}
	}
	// Inherently external: no escape hatch, because there is no version of these
	// that lives inside an air-gapped enclave.
	if cfg.KEKProvider == "aws-kms" {
		errs = append(errs, "PAM_OT_AIRGAP is set but PAM_KEK_PROVIDER=aws-kms requires reaching AWS; use local, pkcs11 (an on-prem HSM) or an in-enclave vault-transit")
	}
	if cfg.EntraTenantID != "" {
		errs = append(errs, "PAM_OT_AIRGAP is set but PAM_ENTRA_TENANT_ID requires reaching Microsoft Entra; use LDAP against an in-enclave directory instead")
	}
	return errs
}

// getenv returns the environment variable key, or def when it is unset or empty.
func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
