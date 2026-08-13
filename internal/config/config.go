// Package config loads server configuration from PAM_* environment variables.
package config

import (
	"errors"
	"fmt"
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

	// MFARequired makes password login require a confirmed TOTP second factor.
	MFARequired bool

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
	// CheckoutTTL is the lifetime of a credential checkout lease.
	CheckoutTTL time.Duration
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
	// AllowedProtocols restricts which target protocols may be created and
	// connected to (comma-separated, e.g. "ssh,winrm"); empty = all allowed. Used
	// in OT zones to forbid protocols like RDP.
	AllowedProtocols string
	// CommandDenyFile is a file of regular expressions (one per line, '#'
	// comments) that block matching commands on the exec/WinRM/SQL paths
	// (Phase 16 command control). Empty disables command control.
	CommandDenyFile string
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
	// ConjurRefreshMin is how often, in minutes, the refreshable bootstrap
	// secrets are re-read from Conjur (0 = off, the default). Only the secrets
	// that can be adopted by a running server are refreshed; see internal/conjur.
	ConjurRefreshMin  int
	BrokerMaxArgBytes int // PAM_BROKER_MAX_ARG_BYTES — cap on a tool call's serialized args (0 = off)
	BrokerRatePerMin  int // PAM_BROKER_RATE_PER_MIN — per-agent tool-call rate limit (0 = off)
	// Audit-chain checkpoints + signing-key rotation (Phase 27).
	BrokerCheckpointEvery int    // PAM_BROKER_AUDIT_CHECKPOINT_EVERY — emit a signed in-chain checkpoint every N events (0 = off)
	BrokerAuditSignPrev   string // PAM_BROKER_AUDIT_SIGN_PREV — comma-separated base64 ed25519 PUBLIC keys still trusted after a signing-key rotation (overlap window)
	// SPIFFE JWT-SVID agent identity (Phase 13d). Setting the JWKS path enables it.
	BrokerTrustDomainJWKS string // PAM_BROKER_TRUST_DOMAIN_JWKS — file with the trust-domain JWKS
	BrokerTrustDomain     string // PAM_BROKER_TRUST_DOMAIN — SPIFFE trust domain host (e.g. example.org)
	BrokerAudience        string // PAM_BROKER_AUDIENCE — required SVID audience
	BrokerMaxDelegation   int    // PAM_BROKER_MAX_DELEGATION_DEPTH — RFC 8693 act-chain cap (default 1)

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
		RotateInterval:          time.Duration(integer("PAM_ROTATE_INTERVAL_MIN", 0)) * time.Minute,
		RotateMaxAge:            time.Duration(integer("PAM_ROTATE_MAX_AGE_HOURS", 0)) * time.Hour,
		RotateAfterSession:      boolean("PAM_ROTATE_AFTER_SESSION", false),
		RequireRecording:        boolean("PAM_REQUIRE_RECORDING", false),
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
		AirGap:               boolean("PAM_OT_AIRGAP", false),
		CheckoutTTL:          time.Duration(integer("PAM_CHECKOUT_TTL_MIN", 30)) * time.Minute,
		ShareInviteTTL:       time.Duration(integer("PAM_SESSION_SHARE_INVITE_TTL_SEC", 900)) * time.Second,
		ShareGuestSessionTTL: time.Duration(integer("PAM_SESSION_SHARE_GUEST_TTL_MIN", 240)) * time.Minute,
		AllowedProtocols:     os.Getenv("PAM_ALLOWED_PROTOCOLS"),
		CommandDenyFile:      os.Getenv("PAM_COMMAND_DENY_FILE"),
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
		AnalyticsBaselineDays:  integer("PAM_ANALYTICS_BASELINE_DAYS", 30),
		AnalyticsAutoStepUp:    boolean("PAM_ANALYTICS_AUTO_STEPUP", false),
		AnalyticsBusinessStart: integer("PAM_ANALYTICS_BUSINESS_START", 7),
		AnalyticsBusinessEnd:   integer("PAM_ANALYTICS_BUSINESS_END", 20),
		AnalyticsTimezone:      os.Getenv("PAM_ANALYTICS_TIMEZONE"),
		AppSecretsEnabled:      boolean("PAM_APP_SECRETS_ENABLED", false),
		BrokerPolicyFile:       os.Getenv("PAM_BROKER_POLICY_FILE"),
		BrokerAuditKey:         os.Getenv("PAM_BROKER_AUDIT_KEY"),
		BrokerAuditSignSeed:    os.Getenv("PAM_BROKER_AUDIT_SIGN_SEED"),
		BrokerTokenTTL:         time.Duration(integer("PAM_BROKER_TOKEN_TTL_MIN", 15)) * time.Minute,
		CertRemindDays:         integer("PAM_CERT_REMIND_DAYS", 7),
		ConjurRefreshMin:       integer("PAM_CONJUR_REFRESH_MIN", 0),
		BrokerMaxArgBytes:      integer("PAM_BROKER_MAX_ARG_BYTES", 16384),
		BrokerRatePerMin:       integer("PAM_BROKER_RATE_PER_MIN", 0),
		BrokerCheckpointEvery:  integer("PAM_BROKER_AUDIT_CHECKPOINT_EVERY", 0),
		BrokerAuditSignPrev:    getenv("PAM_BROKER_AUDIT_SIGN_PREV", ""),

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
	// Bounded at both ends: negative is a fat-finger, and a value large enough
	// to overflow the int64 byte count it becomes would wrap into a negative
	// cap — which reads as "unlimited" at one comparison and refuses everything
	// at another. 1 PiB is far above any real per-file transfer.
	if cfg.SSHSFTPCaptureMaxMB < 0 || cfg.SSHSFTPCaptureMaxMB > 1<<30 {
		errs = append(errs, "PAM_SSH_SFTP_CAPTURE_MAX_MB must be between 0 (unlimited) and 1073741824")
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
	if cfg.BrokerRatePerMin < 0 || cfg.BrokerMaxArgBytes < 0 {
		errs = append(errs, "PAM_BROKER_RATE_PER_MIN and PAM_BROKER_MAX_ARG_BYTES must be >= 0")
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
		{"PAM_AUDIT_FORWARD_ADDR", cfg.AuditForwardAddr},
		{"PAM_OIDC_ISSUER", cfg.OIDCIssuer},
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
