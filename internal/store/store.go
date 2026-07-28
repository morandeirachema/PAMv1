// Package store defines the persistence contract for the PAM inventory,
// vaulted credentials and the audit trail. The production implementation
// is PostgreSQL (pgstore); memstore backs tests and ephemeral demos.
package store

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/morandeirachema/pamv1/internal/session"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: already exists")
)

// CredentialAAD is the additional-authenticated-data string that binds a
// vaulted secret to its owning target AND its specific credential row, so a
// ciphertext copied onto another credential (even on the same target) fails to
// decrypt. The API, the session proxy and the rotation/maintenance paths must
// all use the same value or decryption fails. Because it needs the credential's
// ID, a newly created credential is inserted first (to assign the ID) and its
// secret encrypted and stored in a second step.
func CredentialAAD(targetID, credentialID int64) string {
	return fmt.Sprintf("target:%d/cred:%d", targetID, credentialID)
}

// Paging bounds for ListAudit. They live here, not in an implementation, because
// they are part of the interface's contract: a caller must be able to reason
// about how many events it will get back without knowing which store it holds.
const (
	// DefaultAuditPage is returned when a caller passes a non-positive limit.
	DefaultAuditPage = 100
	// MaxAuditPage bounds a single read so one call cannot pull an unbounded
	// slice of the audit table into memory. A caller needing more must page with
	// AuditSince.
	MaxAuditPage = 5000
)

// ClampAuditLimit applies the ListAudit limit contract. Both store
// implementations call it rather than each writing the rule out, because the
// bug it fixes was precisely the two of them writing it out differently.
func ClampAuditLimit(limit int) int {
	switch {
	case limit <= 0:
		return DefaultAuditPage
	case limit > MaxAuditPage:
		return MaxAuditPage
	default:
		return limit
	}
}

// KeyMaterialAAD binds a vault-encrypted long-lived key to its name, so a host
// key envelope cannot be swapped in as the CA key (Phase 42).
func KeyMaterialAAD(name string) string { return "keymaterial:" + name }

// KeyMaterial is one named long-lived key held in shared custody (Phase 42): the
// SSH proxy host key and the Zero Standing Privilege CA key. Value is the vault
// envelope of the PEM — never the PEM itself — so the database holds nothing
// usable on its own.
type KeyMaterial struct {
	Name  string `json:"name"`
	Value string `json:"-"` // vault envelope; never serialized
}

// MFAAAD binds a vaulted TOTP secret to its owning user.
func MFAAAD(username string) string {
	return "mfa:" + username
}

// ConfigAAD binds a vault-encrypted configuration setting (e.g. an LDAP bind
// password or an OIDC client secret) to its key.
func ConfigAAD(key string) string {
	return "config:" + key
}

// Target is a machine reachable through the PAM (a future proxy session
// connects to it injecting a vaulted credential just-in-time).
type Target struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	OSType   string `json:"os_type"`  // linux | windows
	Protocol string `json:"protocol"` // ssh | winrm | rdp
	// RequireApproval gates connections behind an approved access request
	// (4-eyes / maintenance-window control, used in OT deployments).
	RequireApproval bool `json:"require_approval"`
	// SafeID, when set, places the target in a safe (Phase 17): safe members may
	// connect to every target in the safe. nil means the target is not in a safe.
	SafeID    *int64    `json:"safe_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Campaign is an access-certification (attestation) campaign: a point-in-time
// review of who has access to what, so a reviewer certifies or revokes each
// grant (Phase 19 — a SOX / ISO 27001 / NIS2 access-review control).
type Campaign struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	DueAt     *time.Time `json:"due_at,omitempty"`
	Status    string     `json:"status"` // open | closed
	ClosedAt  *time.Time `json:"closed_at,omitempty"`
}

// CampaignItem is one access grant under review in a campaign. RefID points at
// the underlying grant so a "revoke" decision can delete it. GrantedBy is the
// grant's creator, snapshotted at campaign creation (Phase 46) so the four-eyes
// check — the grantor may not CERTIFY their own grant — needs no live lookup
// and survives the grant's deletion; empty when the creator was never recorded.
type CampaignItem struct {
	ID          int64      `json:"id"`
	CampaignID  int64      `json:"campaign_id"`
	Kind        string     `json:"kind"`   // target_grant | safe_member
	RefID       int64      `json:"ref_id"` // id of the underlying grant/member
	SubjectType string     `json:"subject_type"`
	Subject     string     `json:"subject"`
	Detail      string     `json:"detail"` // human-readable ("grant on target web-01")
	GrantedBy   string     `json:"granted_by,omitempty"`
	Decision    string     `json:"decision"` // pending | certified | revoked
	DecidedBy   string     `json:"decided_by,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
}

// CredentialDependency declares a consumer of a credential — a Windows Service,
// Scheduled Task or IIS App Pool that logs on with the account — so that when
// the credential is rotated, pamv1 also updates the consumer over WinRM and the
// rotation does not break production (Phase 17).
type CredentialDependency struct {
	ID           int64  `json:"id"`
	CredentialID int64  `json:"credential_id"`
	Kind         string `json:"kind"` // windows_service | scheduled_task | iis_apppool
	Host         string `json:"host"` // WinRM-reachable host running the consumer
	Port         int    `json:"port"` // WinRM port (0 → 5985)
	Name         string `json:"name"` // service / task / app-pool name
}

// Safe is a named container that groups targets and delegates who may access
// them (Phase 17). Membership is an additional grant path alongside per-target
// grants: a member of a target's safe may connect to it.
type Safe struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// SafeMember authorizes a subject (a user or a role) on a safe. CanManage marks
// a delegated safe administrator (may add/remove members of that safe).
// CreatedBy records who added the member (Phase 46, four-eyes on certification);
// empty on rows that predate the recording.
type SafeMember struct {
	ID          int64  `json:"id"`
	SafeID      int64  `json:"safe_id"`
	SubjectType string `json:"subject_type"` // user | role
	Subject     string `json:"subject"`
	CanManage   bool   `json:"can_manage"`
	CreatedBy   string `json:"created_by,omitempty"`
}

// AccessRequest is a user's request to connect to a target, subject to approval
// by a different principal (4-eyes). When a target (or global OT policy) requires
// approval, connect paths admit only a requester with an approved, unexpired
// request. Statuses: pending | approved | denied.
type AccessRequest struct {
	ID        int64      `json:"id"`
	Requester string     `json:"requester"`
	TargetID  int64      `json:"target_id"`
	Reason    string     `json:"reason"`
	Status    string     `json:"status"`
	Approver  string     `json:"approver,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
	// Ticket is an optional ITSM change/incident reference (Phase 20). When
	// ticket validation is configured it is validated before the request is
	// created, and it is recorded in the audit trail.
	Ticket string `json:"ticket,omitempty"`
	// RequiredApprovals is how many DISTINCT approvers must approve before the
	// request is granted (Phase 21 multi-tier chains; default 1). ApprovedBy is
	// the comma-joined set of approvers so far. NotBefore, when set, delays when
	// an approved request becomes active (a scheduled maintenance window).
	RequiredApprovals int        `json:"required_approvals,omitempty"`
	ApprovedBy        string     `json:"approved_by,omitempty"`
	NotBefore         *time.Time `json:"not_before,omitempty"`
	// OneTime marks a single-use approval (Phase 26): the first privileged use
	// it admits (a proxy/RDP connect, a WinRM run, a reveal or checkout, a
	// broker tool call) consumes it — ConsumedAt is stamped and the approval
	// admits nothing further. A consumed approval is not "active" anywhere.
	OneTime    bool       `json:"one_time,omitempty"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}

// Credential is a privileged account on a Target. SecretEnc is always an
// encrypted vault token — plaintext never touches the store or the JSON
// encoder (note the "-" tag).
type Credential struct {
	ID         int64      `json:"id"`
	TargetID   int64      `json:"target_id"`
	Username   string     `json:"username"`
	SecretType string     `json:"secret_type"` // password | ssh_key
	SecretEnc  string     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	RotatedAt  *time.Time `json:"rotated_at,omitempty"`
}

// TargetGrant authorizes a subject (a specific user, or a whole role) to connect
// to a target. A target with no grants is open to any connect-capable principal;
// once it has grants, only matching subjects (plus admins) may connect.
// CreatedBy records the principal who created the grant (Phase 46) so a
// certification review can refuse the grantor attesting to their own grant;
// empty on rows that predate the recording. EffectiveTargetGrants (an
// authorization-only view) does not populate it.
type TargetGrant struct {
	ID          int64  `json:"id"`
	TargetID    int64  `json:"target_id"`
	SubjectType string `json:"subject_type"` // user | role
	Subject     string `json:"subject"`
	CreatedBy   string `json:"created_by,omitempty"`
}

// Checkout is an exclusive, time-boxed lease on a credential. While a checkout
// is active no other holder may check the same credential out; on check-in the
// credential is rotated so the password the holder saw can no longer be used.
type Checkout struct {
	ID           int64      `json:"id"`
	CredentialID int64      `json:"credential_id"`
	TargetID     int64      `json:"target_id"`
	Holder       string     `json:"holder"`
	Reason       string     `json:"reason"`
	CheckedOutAt time.Time  `json:"checked_out_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	ReturnedAt   *time.Time `json:"returned_at,omitempty"`
}

type AuditEvent struct {
	ID     int64     `json:"id"`
	TS     time.Time `json:"ts"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
	// PrevHash and HMAC form the optional tamper-evident hash chain over the
	// primary audit trail, activated when an audit HMAC key is configured
	// (EnableAuditChain). HMAC = HMAC-SHA256(key, prev_hash || canonical(event)),
	// so editing, reordering, or deleting any event breaks the chain from that
	// point. PrevHash is derivable (the previous row's HMAC) and not exposed; both
	// are nil when the chain is not enabled.
	PrevHash []byte `json:"-"`
	HMAC     []byte `json:"hmac,omitempty"`
}

// AuditCanonical serializes the integrity-relevant fields of an audit event
// (actor, action, detail) into a stable, length-prefixed byte string. The
// timestamp and id are excluded — like the broker chain — so a clock skew or an
// id gap can't spuriously break verification; ordering is captured by the chain.
func AuditCanonical(e *AuditEvent) []byte {
	var b bytes.Buffer
	for _, s := range []string{e.Actor, e.Action, e.Detail} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		b.Write(n[:])
		b.WriteString(s)
	}
	return b.Bytes()
}

// AuditMAC computes an event's chain HMAC over prev || canonical(event).
func AuditMAC(key, prev []byte, e *AuditEvent) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(prev)
	m.Write(AuditCanonical(e))
	return m.Sum(nil)
}

// User is a local identity with a role. The access token is stored only as a
// hex SHA-256 (TokenHash, never serialized); the plaintext token is shown to
// the admin exactly once, at creation.
type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"` // admin | user | auditor | approver
	TokenHash string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

// AgentKey is an AI-agent identity for the access broker: a bearer key whose
// SHA-256 hash is stored, granting only the ability to request brokered tool
// calls (never a credential). Owner is the accountable human/service recorded in
// every audit entry the agent produces.
type AgentKey struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Owner     string    `json:"owner"`
	TokenHash string    `json:"-"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
}

// AppKey is a non-human application identity for the application-secrets API
// (Phase 24, Tier-4 Conjur-style secret delivery): a bearer key whose SHA-256
// hash is stored, letting an application retrieve only the specific secrets it
// has been explicitly granted — nothing else. Owner is the accountable
// human/team recorded in the audit trail.
type AppKey struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Owner     string    `json:"owner"`
	TokenHash string    `json:"-"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
}

// Vendor is a third-party (external) identity whose access is governed by
// time-boxed contract grants (Phase 29). Username links to a users row (the
// vendor's login). A disabled vendor is offboarded — every grant is revoked and
// live sessions are cut.
type Vendor struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Org       string    `json:"org"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
}

// VendorGrant is a customer-approved, time-boxed authorization for a vendor to
// log in as Principal on a target. The vendor may connect only while
// Status=="approved", RevokedAt is nil, and now is within [NotBefore, NotAfter].
// Approver is the customer principal who approved it (never the vendor — four
// eyes).
type VendorGrant struct {
	ID         int64      `json:"id"`
	VendorID   int64      `json:"vendor_id"`
	TargetID   int64      `json:"target_id"`
	Principal  string     `json:"principal"`
	Status     string     `json:"status"` // pending | approved | revoked
	NotBefore  *time.Time `json:"not_before,omitempty"`
	NotAfter   time.Time  `json:"not_after"`
	Approver   string     `json:"approver,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// SSHCert records an operator-issued SSH certificate (Phase 28): pamv1 signed the
// operator's own public key into a short-lived cert scoped to a target account.
// The row is the revocation handle — a KRL revoking Serial is published so a
// target's sshd cuts the cert off before ValidBefore. RevokedAt is nil until
// revoked.
type SSHCert struct {
	ID int64 `json:"id"`
	// Serial serializes as a JSON STRING (`,string`), not a number. It is seeded
	// from a nanosecond clock, so its value is far above 2^53 — the largest
	// integer JavaScript's number type represents exactly. As a JSON number it
	// arrived in the console rounded, and a rounded serial revokes nothing: the
	// KRL would name a certificate that does not exist while the real one stayed
	// valid until expiry. The /sign response already returned a string for this
	// reason; this listing did not, which is why the console's revoke option
	// could not revoke a real certificate.
	Serial      int64      `json:"serial,string"`
	KeyID       string     `json:"key_id"`
	Principal   string     `json:"principal"`
	Actor       string     `json:"actor"`
	IssuedAt    time.Time  `json:"issued_at"`
	ValidBefore *time.Time `json:"valid_before,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RevokedBy   string     `json:"revoked_by,omitempty"`
}

// AppSecretGrant authorizes an application (AppKey) to retrieve one specific
// credential's secret through the application-secrets API. Access is
// default-deny: an app may fetch only the credentials it has an explicit grant
// for.
type AppSecretGrant struct {
	ID           int64     `json:"id"`
	AppID        int64     `json:"app_id"`
	CredentialID int64     `json:"credential_id"`
	CreatedAt    time.Time `json:"created_at"`
}

// BrokerToken is a short-lived, single-use ticket the broker mints when a tool
// call is parked for approval (Phase 13). The agent presents its opaque token to
// resume and collect the post-approval result exactly once; the stored JTI is the
// token's SHA-256 hash, bound to the parked call and an expiry.
type BrokerToken struct {
	JTI       string     `json:"-"` // SHA-256 hex of the opaque token
	CallID    string     `json:"call_id"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
}

// Profile is a named, custom capability set (Phase 12) assignable to users as an
// alternative to the four built-in roles. Capabilities holds the stable
// capability names defined in internal/auth.
type Profile struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Capabilities []string  `json:"capabilities"`
	CreatedAt    time.Time `json:"created_at"`
}

// Setting is a persisted configuration override (Phase 12): a PAM_* key whose
// value takes precedence over the environment for the identity backends, SSO,
// and operational policy. Secret values (bind passwords, client secrets) are
// stored vault-encrypted (Value is a "v2:" token, Secret is true).
type Setting struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	Secret    bool      `json:"secret"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BrokerAuditEvent is one entry in the broker's tamper-evident, keyed-HMAC
// hash-chained audit log (separate from the general audit_events trail). Each
// row's HMAC covers the previous row's HMAC, so any edit or truncation breaks
// the chain. The broker is the sole writer, so rows chain in id order.
type BrokerAuditEvent struct {
	ID         int64     `json:"id"`
	TS         time.Time `json:"ts"`
	Actor      string    `json:"actor"`        // agent name
	OnBehalfOf string    `json:"on_behalf_of"` // accountable owner / SVID on_behalf_of
	ActorChain string    `json:"actor_chain"`  // JSON array of the delegation actor chain
	Action     string    `json:"action"`
	Detail     string    `json:"detail"`
	Scope      string    `json:"scope"`
	PrevHash   []byte    `json:"-"`    // previous row's HMAC (chain link); derivable, not exposed
	HMAC       []byte    `json:"hmac"` // HMAC-SHA256(key, prev_hash || canonical(event))
}

// Session is a short-lived bearer token issued after a password login (e.g.
// Active Directory). Only the token's hex SHA-256 is stored (never serialized).
type Session struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	// Roles is the comma-separated set of directory-matched roles for a multi-group
	// login (empty for a single role), so the resolved principal gets their union.
	Roles     string    `json:"roles,omitempty"`
	Scope     string    `json:"scope"` // "" (full) | "enroll" (MFA enrollment only)
	TokenHash string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MFAEnrollment is a user's TOTP second factor. SecretEnc is the vault-encrypted
// TOTP secret (never serialized); Confirmed is set once the user proves they can
// generate a valid code.
type MFAEnrollment struct {
	Username  string    `json:"username"`
	SecretEnc string    `json:"-"`
	Confirmed bool      `json:"confirmed"`
	CreatedAt time.Time `json:"created_at"`
	// LastTOTPStep is the highest TOTP time-step counter accepted for this user,
	// used to reject a code replayed within the skew window.
	LastTOTPStep int64 `json:"-"`
}

// List-cursor semantics (Phase 44). Every top-level inventory list read takes a
// (limit, afterID) window: rows are returned in ascending id order, starting
// strictly after afterID, at most limit rows when limit > 0. limit <= 0 means
// "no cap" — reserved for in-process sweeps (rotation, reconciliation, the
// vendor sweeper); the HTTP handlers always pass a clamped limit so an
// authenticated client can never pull an unbounded result set. afterID <= 0
// starts from the beginning. Child lists scoped to one parent (a target's
// grants, a safe's members) stay unwindowed — they are bounded by their parent.

type Store interface {
	// CreateTarget inserts a target, populating its ID and CreatedAt.
	CreateTarget(ctx context.Context, t *Target) error
	// ListTargets returns targets in the (limit, afterID) window, id-ascending.
	ListTargets(ctx context.Context, limit int, afterID int64) ([]Target, error)
	// GetTarget returns one target by ID, or ErrNotFound.
	GetTarget(ctx context.Context, id int64) (*Target, error)
	// UpdateTarget replaces the editable fields (Name, Host, Port, OSType,
	// Protocol, RequireApproval) of the target with t.ID, refreshing t's SafeID
	// and CreatedAt from the stored row. It deliberately does NOT touch the safe
	// assignment (AssignTargetSafe owns that). ErrNotFound if the target is
	// missing, ErrConflict if the new name is taken — so fixing a host or port
	// no longer means delete + recreate, which cascades away the target's
	// credentials, grants, dependencies and safe assignment.
	UpdateTarget(ctx context.Context, t *Target) error
	// DeleteTarget removes a target (cascading to its dependents), or ErrNotFound.
	DeleteTarget(ctx context.Context, id int64) error

	// CreateCredential inserts a credential for a target, or ErrNotFound if the target is missing.
	CreateCredential(ctx context.Context, c *Credential) error
	// ListCredentials returns credentials for one target (or all when targetID
	// is 0) in the (limit, afterID) window, id-ascending.
	ListCredentials(ctx context.Context, targetID int64, limit int, afterID int64) ([]Credential, error)
	// GetCredential returns one credential by ID, or ErrNotFound.
	GetCredential(ctx context.Context, id int64) (*Credential, error)
	// UpdateCredentialSecretEnc replaces a credential's encrypted secret (used
	// by vault key rotation). It deliberately does NOT touch rotated_at — a KEK
	// re-wrap is not a credential rotation.
	UpdateCredentialSecretEnc(ctx context.Context, id int64, secretEnc string) error
	// RotateCredentialSecret replaces the encrypted secret AND stamps rotated_at
	// (used by the credential-lifecycle rotation, where the secret on the target
	// actually changed).
	RotateCredentialSecret(ctx context.Context, id int64, secretEnc string, rotatedAt time.Time) error
	// DeleteCredential removes a credential by ID, or ErrNotFound.
	DeleteCredential(ctx context.Context, id int64) error

	// CreateTargetGrant adds an authorization grant to a target.
	CreateTargetGrant(ctx context.Context, g *TargetGrant) error
	// ListTargetGrants returns the grants for a target.
	ListTargetGrants(ctx context.Context, targetID int64) ([]TargetGrant, error)
	// DeleteTargetGrant removes a grant by ID, or ErrNotFound.
	DeleteTargetGrant(ctx context.Context, id int64) error
	// EffectiveTargetGrants returns a target's direct grants unioned with the
	// grants derived from its safe's membership (Phase 17). The connect-time
	// authorization decision uses this, so a target in a safe is reachable by the
	// safe's members. An empty result means the target is unrestricted (open).
	EffectiveTargetGrants(ctx context.Context, targetID int64) ([]TargetGrant, error)

	// CreateSafe inserts a safe, populating its ID and CreatedAt.
	CreateSafe(ctx context.Context, s *Safe) error
	// ListSafes returns safes in the (limit, afterID) window, id-ascending
	// (creation order — the stable order a cursor needs).
	ListSafes(ctx context.Context, limit int, afterID int64) ([]Safe, error)
	// GetSafe returns a safe by ID, or ErrNotFound.
	GetSafe(ctx context.Context, id int64) (*Safe, error)
	// UpdateSafe replaces the Name and Description of the safe with s.ID,
	// refreshing s.CreatedAt from the stored row. ErrNotFound if the safe is
	// missing, ErrConflict if the new name is taken. Membership and target
	// assignment are untouched — renaming a safe never changes who may reach what.
	UpdateSafe(ctx context.Context, s *Safe) error
	// DeleteSafe removes a safe by ID (its members cascade; member targets are
	// unassigned), or ErrNotFound.
	DeleteSafe(ctx context.Context, id int64) error
	// AddSafeMember adds a member to a safe (ErrConflict on a duplicate subject,
	// ErrNotFound if the safe does not exist).
	AddSafeMember(ctx context.Context, m *SafeMember) error
	// ListSafeMembers returns a safe's members ordered by id.
	ListSafeMembers(ctx context.Context, safeID int64) ([]SafeMember, error)
	// DeleteSafeMember removes a safe member by ID, or ErrNotFound.
	DeleteSafeMember(ctx context.Context, id int64) error
	// AssignTargetSafe sets (or clears, when safeID is nil) a target's safe.
	AssignTargetSafe(ctx context.Context, targetID int64, safeID *int64) error

	// CreateCredentialDependency declares a consumer of a credential (ErrNotFound
	// if the credential does not exist).
	CreateCredentialDependency(ctx context.Context, d *CredentialDependency) error
	// ListCredentialDependencies returns a credential's declared consumers.
	ListCredentialDependencies(ctx context.Context, credentialID int64) ([]CredentialDependency, error)
	// DeleteCredentialDependency removes a dependency by ID, or ErrNotFound.
	DeleteCredentialDependency(ctx context.Context, id int64) error

	// CreateCampaign inserts a certification campaign, populating ID/CreatedAt.
	CreateCampaign(ctx context.Context, c *Campaign) error
	// ListCampaigns returns all campaigns, newest first.
	ListCampaigns(ctx context.Context) ([]Campaign, error)
	// GetCampaign returns a campaign by ID, or ErrNotFound.
	GetCampaign(ctx context.Context, id int64) (*Campaign, error)
	// CloseCampaign marks a campaign closed at the given time, or ErrNotFound.
	CloseCampaign(ctx context.Context, id int64, at time.Time) error
	// AddCampaignItem adds one access item to a campaign (ErrNotFound if absent).
	AddCampaignItem(ctx context.Context, item *CampaignItem) error
	// ListCampaignItems returns a campaign's items ordered by id.
	ListCampaignItems(ctx context.Context, campaignID int64) ([]CampaignItem, error)
	// GetCampaignItem returns one item by ID, or ErrNotFound.
	GetCampaignItem(ctx context.Context, id int64) (*CampaignItem, error)
	// DecideCampaignItem records a certify/revoke decision on an item.
	DecideCampaignItem(ctx context.Context, id int64, decision, decidedBy string, at time.Time) error

	// Access requests (4-eyes approval workflow).
	CreateAccessRequest(ctx context.Context, ar *AccessRequest) error
	// GetAccessRequest returns one access request by ID, or ErrNotFound.
	GetAccessRequest(ctx context.Context, id int64) (*AccessRequest, error)
	// ListAccessRequests returns requests with the given status (all when
	// status is "") in the (limit, afterID) window, id-ascending.
	ListAccessRequests(ctx context.Context, status string, limit int, afterID int64) ([]AccessRequest, error)
	// DecideAccessRequest records an approve/deny decision by approver.
	DecideAccessRequest(ctx context.Context, id int64, status, approver string, decidedAt time.Time) error
	// SetApprovalState records a multi-approver decision (Phase 21): the updated
	// distinct-approver set, the resulting status ("pending" while partial,
	// "approved" once the required count is met), the final approver, and the
	// decided-at time (nil while still partial).
	SetApprovalState(ctx context.Context, id int64, approvedBy, status, approver string, decidedAt *time.Time) error
	// HasActiveApproval reports whether requester has an approved, unexpired
	// request for targetID as of now. A consumed single-use approval is not
	// active.
	HasActiveApproval(ctx context.Context, requester string, targetID int64, now time.Time) (bool, error)
	// ConsumeApproval is the use-time twin of HasActiveApproval (Phase 26): it
	// reports whether requester holds an active approval for targetID and, when
	// the only active approval is single-use (OneTime), atomically burns it by
	// stamping ConsumedAt so it cannot admit a second use. A standing
	// (non-one-time) active approval is preferred and left untouched.
	// consumedID is the burned request's ID (0 when nothing was consumed).
	// Atomic under concurrent use: one single-use approval admits exactly one
	// of two racing consumers.
	ConsumeApproval(ctx context.Context, requester string, targetID int64, now time.Time) (ok bool, consumedID int64, err error)

	// Credential checkout/check-in (exclusive time-boxed leases).
	// CreateCheckout fails with ErrConflict if the credential already has an
	// active (unreturned, unexpired) checkout as of now.
	CreateCheckout(ctx context.Context, co *Checkout, now time.Time) error
	// GetActiveCheckout returns the active checkout for a credential, or ErrNotFound.
	GetActiveCheckout(ctx context.Context, credentialID int64, now time.Time) (*Checkout, error)
	// CheckinCheckout marks a checkout returned; ErrNotFound if missing or already returned.
	CheckinCheckout(ctx context.Context, id int64, at time.Time) error
	// ListCheckouts lists checkouts in the (limit, afterID) window,
	// id-ascending; activeOnly limits to unreturned, unexpired ones.
	ListCheckouts(ctx context.Context, activeOnly bool, now time.Time, limit int, afterID int64) ([]Checkout, error)

	// AppendAudit appends an audit event, populating its ID and TS. When an audit
	// HMAC key has been configured (EnableAuditChain), the event is linked into the
	// tamper-evident chain (prev_hash/hmac) as part of the same atomic append.
	AppendAudit(ctx context.Context, e *AuditEvent) error
	// EnableAuditChain turns on tamper-evident chaining of the primary audit trail
	// using the given HMAC key (KeySize bytes). Passing nil/empty disables it (the
	// default). Call once at startup, before serving.
	EnableAuditChain(key []byte)
	// VerifyAuditChain recomputes the chain over every audit event in order and
	// reports whether it is intact. brokeAtID is the id of the first event whose
	// HMAC does not match (0 when ok). It errors if the chain is not enabled.
	VerifyAuditChain(ctx context.Context) (ok bool, brokeAtID int64, err error)
	// GetAuditHead returns the most recent chained audit event (for a signed
	// checkpoint that detects tail truncation), or (nil, nil) when the chain is
	// empty. Unaffected by whether chaining is enabled — it simply reads the latest
	// row that carries an HMAC.
	GetAuditHead(ctx context.Context) (*AuditEvent, error)
	// ListAudit returns the most recent audit events, newest first.
	//
	// limit semantics are part of the contract, and both implementations must
	// obey them exactly:
	//   limit <= 0            → DefaultAuditPage events
	//   limit >  MaxAuditPage → MaxAuditPage events (capped, NOT reduced)
	//   otherwise             → at most limit events
	//
	// The "capped, not reduced" clause is the one that was wrong. pgstore used to
	// collapse any limit above 500 back to the 100 default, so asking for more
	// returned dramatically FEWER — while memstore returned everything it had.
	// A caller asking for 2000 got 2000 in tests and 100 in production, which is
	// the worst possible way for two implementations of one interface to differ.
	ListAudit(ctx context.Context, limit int) ([]AuditEvent, error)
	// ExportAudit returns every audit event with since <= ts < until, ordered
	// oldest-first (for NIS2 incident-report exports). A zero since means "from
	// the beginning"; a zero until means "up to now".
	ExportAudit(ctx context.Context, since, until time.Time) ([]AuditEvent, error)
	// LatestAuditByAction returns the most recent audit event with the given
	// action, or (nil, nil) when there is none.
	//
	// It exists so a periodic job can find its own high-water mark in the trail
	// rather than keeping a separate cursor that could disagree with reality —
	// retention's archiver reads the last `audit.archived` to know where the
	// previous archive finished. Scanning a page of recent events instead would
	// silently lose the marker on a busy system, and losing it means re-exporting
	// history that is already archived.
	LatestAuditByAction(ctx context.Context, action string) (*AuditEvent, error)
	// AuditSince returns up to limit audit events with id > afterID, ordered
	// oldest-first (ascending id). It is the cursor read for the SIEM forwarder
	// (Phase 35): tail the trail by advancing afterID past the last event sent.
	AuditSince(ctx context.Context, afterID int64, limit int) ([]AuditEvent, error)
	// PruneAuditBefore deletes audit events with ts < cutoff and returns how many
	// were removed (Phase 36 retention). The caller must NOT prune when the
	// tamper-evident HMAC chain is enabled — deleting the chain head breaks
	// verification — so the retention worker skips it in that case.
	PruneAuditBefore(ctx context.Context, cutoff time.Time) (int, error)
	// FindAuditDetail reports whether any audit event with the given action has
	// a detail containing substr, matched literally (Phase 26). The playback
	// path uses it to verify a served session recording's SHA-256 against the
	// value audited when the recording was written.
	FindAuditDetail(ctx context.Context, action, substr string) (bool, error)

	// CreateUser inserts a user, populating its ID and CreatedAt.
	CreateUser(ctx context.Context, u *User) error
	// ListUsers returns users in the (limit, afterID) window, id-ascending.
	ListUsers(ctx context.Context, limit int, afterID int64) ([]User, error)
	// GetUser returns one user by ID, or ErrNotFound.
	GetUser(ctx context.Context, id int64) (*User, error)
	// GetUserByTokenHash returns the user whose token hash matches, or ErrNotFound.
	GetUserByTokenHash(ctx context.Context, tokenHashHex string) (*User, error)
	// UpdateUserRole changes a user's role (a built-in role or a custom profile
	// name), or ErrNotFound. The username and token are immutable: the username
	// is the subject key referenced by grants, sessions and vendor records, and
	// re-keying an identity is a delete + re-mint, not an edit. Local tokens are
	// re-resolved on every request, so a role change takes effect immediately.
	UpdateUserRole(ctx context.Context, id int64, role string) error
	// DeleteUser removes a user by ID, or ErrNotFound.
	DeleteUser(ctx context.Context, id int64) error

	// CreateAgentKey inserts an AI-agent identity key, populating ID and CreatedAt.
	CreateAgentKey(ctx context.Context, k *AgentKey) error
	// GetAgentKey returns an agent key by ID, or ErrNotFound — used to re-check an
	// agent is still enabled at approval time (post-park revocation).
	GetAgentKey(ctx context.Context, id int64) (*AgentKey, error)
	// GetAgentKeyByTokenHash returns the enabled agent key whose token hash
	// matches, or ErrNotFound (a disabled key is treated as not found).
	GetAgentKeyByTokenHash(ctx context.Context, tokenHashHex string) (*AgentKey, error)
	// ListAgentKeys returns all agent keys.
	ListAgentKeys(ctx context.Context) ([]AgentKey, error)
	// DeleteAgentKey removes an agent key by ID, or ErrNotFound.
	DeleteAgentKey(ctx context.Context, id int64) error

	// Operator-issued SSH certificates + KRL revocation (Phase 28).
	// RecordSSHCert stores an issued certificate (its serial is the revocation
	// handle), populating ID and IssuedAt.
	RecordSSHCert(ctx context.Context, c *SSHCert) error
	// RevokeSSHCert stamps a certificate serial revoked; ErrNotFound if unknown,
	// ErrConflict if already revoked.
	RevokeSSHCert(ctx context.Context, serial int64, by string, at time.Time) error
	// ListRevokedSSHCertSerials returns the serials of every revoked certificate,
	// for KRL generation.
	ListRevokedSSHCertSerials(ctx context.Context) ([]int64, error)
	// ListSSHCerts returns recent issued certificates (newest first, capped).
	ListSSHCerts(ctx context.Context, limit int) ([]SSHCert, error)

	// Third-party vendor access gate (Phase 29).
	// CreateVendor registers a vendor (ErrConflict on a duplicate username).
	CreateVendor(ctx context.Context, v *Vendor) error
	// GetVendorByUsername returns the vendor for a login, or ErrNotFound.
	GetVendorByUsername(ctx context.Context, username string) (*Vendor, error)
	// ListVendors returns vendors in the (limit, afterID) window, id-ascending.
	ListVendors(ctx context.Context, limit int, afterID int64) ([]Vendor, error)
	// SetVendorDisabled enables/disables a vendor by id, or ErrNotFound.
	SetVendorDisabled(ctx context.Context, id int64, disabled bool) error
	// UpdateVendorOrg changes a vendor's organization label, or ErrNotFound. The
	// username is immutable (it links the vendor to its users row); disabling is
	// SetVendorDisabled / OffboardVendor, never an edit.
	UpdateVendorOrg(ctx context.Context, id int64, org string) error
	// CreateVendorGrant records a pending contract grant, populating ID/CreatedAt;
	// ErrNotFound if the vendor or target is missing.
	CreateVendorGrant(ctx context.Context, g *VendorGrant) error
	// ApproveVendorGrant flips a pending grant to approved by approver; ErrNotFound
	// if unknown, ErrConflict if not pending.
	ApproveVendorGrant(ctx context.Context, id int64, approver string, at time.Time) error
	// RevokeVendorGrant marks a grant revoked; ErrNotFound if unknown.
	RevokeVendorGrant(ctx context.Context, id int64, at time.Time) error
	// ListVendorGrants lists a vendor's grants (newest first) — for review + evidence.
	ListVendorGrants(ctx context.Context, vendorID int64) ([]VendorGrant, error)
	// OffboardVendor disables the vendor and revokes all its grants atomically; the
	// caller then kills live sessions. ErrNotFound if the vendor is missing.
	OffboardVendor(ctx context.Context, id int64, at time.Time) error
	// VendorSessionAllowed reports, for a login username connecting to target NAME
	// as the account `account`, whether username is a vendor and (if so) whether an
	// approved, unrevoked, in-window grant to that target is active as of now AND
	// authorizes that account (grant.Principal must equal `account`, or be empty
	// for an any-account grant). A blank `account` means "any account" — used by
	// the sweeper to ask "does this vendor still have ANY active grant to this
	// target". A non-vendor returns (isVendor=false, allowed=true) so non-vendor
	// users are unaffected.
	VendorSessionAllowed(ctx context.Context, username, targetName, account string, now time.Time) (isVendor, allowed bool, err error)

	// CreateAppKey inserts an application identity key, populating ID and CreatedAt
	// (ErrConflict on a duplicate token hash).
	CreateAppKey(ctx context.Context, k *AppKey) error
	// GetAppKeyByTokenHash returns the enabled app key whose token hash matches, or
	// ErrNotFound (a disabled key is treated as not found).
	GetAppKeyByTokenHash(ctx context.Context, tokenHashHex string) (*AppKey, error)
	// ListAppKeys returns all application keys.
	ListAppKeys(ctx context.Context) ([]AppKey, error)
	// DeleteAppKey removes an app key by ID (cascading its secret grants), or ErrNotFound.
	DeleteAppKey(ctx context.Context, id int64) error
	// GrantAppSecret authorizes an app to retrieve a credential's secret
	// (ErrConflict on a duplicate grant, ErrNotFound if the app or credential is missing).
	GrantAppSecret(ctx context.Context, g *AppSecretGrant) error
	// ListAppSecretGrants returns an app's secret grants ordered by id.
	ListAppSecretGrants(ctx context.Context, appID int64) ([]AppSecretGrant, error)
	// DeleteAppSecretGrant removes a grant by ID, or ErrNotFound.
	DeleteAppSecretGrant(ctx context.Context, id int64) error
	// AppMayAccessCredential reports whether app appID has a grant for credentialID.
	AppMayAccessCredential(ctx context.Context, appID, credentialID int64) (bool, error)

	// CreateBrokerToken stores a single-use resume token (its JTI is the token's
	// SHA-256 hash) for a parked, approval-pending tool call.
	CreateBrokerToken(ctx context.Context, t *BrokerToken) error
	// ConsumeBrokerToken atomically spends the token identified by jti, returning
	// the bound call id. It succeeds at most once: a used, expired, or unknown jti
	// yields ErrNotFound, so a replayed token can never collect a result twice.
	ConsumeBrokerToken(ctx context.Context, jti string) (callID string, err error)
	// PeekBrokerToken returns the call id a token is bound to WITHOUT spending it
	// (ErrNotFound if used/expired/unknown), so a resume can avoid burning the
	// token before the parked call is ready to collect.
	PeekBrokerToken(ctx context.Context, jti string) (callID string, err error)
	// DeleteExpiredBrokerTokens removes spent or expired tokens, returning the
	// count deleted; a periodic sweep keeps the table bounded.
	DeleteExpiredBrokerTokens(ctx context.Context) (int64, error)

	// EnsureKeyMaterial claims custody of a named long-lived key. It stores value
	// only if no row exists for name, and returns whatever is stored either way —
	// so N replicas starting at the same moment all converge on ONE key instead of
	// each generating its own (Phase 42). value is the vault envelope of the PEM:
	// the database never holds usable key material.
	EnsureKeyMaterial(ctx context.Context, name, value string) (string, error)
	// ListKeyMaterial returns every named key envelope, ordered by name. It exists
	// so KEK rotation can re-wrap them: without a read path, `-rotate-kek` could
	// re-encrypt credentials, MFA secrets and settings but silently leave the SSH
	// host key and the ZSP CA key sealed under the OLD key, and the next startup
	// would fail to unwrap them (which is deliberately fatal). Values are vault
	// envelopes; the database never holds usable key material.
	ListKeyMaterial(ctx context.Context) ([]KeyMaterial, error)
	// UpdateKeyMaterial replaces a named key's envelope — the re-wrap half of the
	// pair above. ErrNotFound when the name is absent, so a rotation cannot
	// silently create custody of a key nobody claimed.
	UpdateKeyMaterial(ctx context.Context, name, value string) error

	// PutSetting upserts a configuration override, stamping UpdatedAt.
	PutSetting(ctx context.Context, s *Setting) error
	// GetSetting returns the override for key, or ErrNotFound.
	GetSetting(ctx context.Context, key string) (*Setting, error)
	// ListSettings returns all configuration overrides.
	ListSettings(ctx context.Context) ([]Setting, error)
	// DeleteSetting removes the override for key, or ErrNotFound.
	DeleteSetting(ctx context.Context, key string) error

	// CreateProfile inserts a custom permission profile; ErrConflict on a
	// duplicate name.
	CreateProfile(ctx context.Context, p *Profile) error
	// GetProfile returns the profile with the given name, or ErrNotFound.
	GetProfile(ctx context.Context, name string) (*Profile, error)
	// ListProfiles returns all custom profiles.
	ListProfiles(ctx context.Context) ([]Profile, error)
	// DeleteProfile removes a profile by ID, or ErrNotFound.
	DeleteProfile(ctx context.Context, id int64) error

	// AppendBrokerAuditLinked appends one broker audit event whose hash-chain
	// link is computed from the CURRENT persisted head under a serialization
	// that also holds across processes (a Postgres advisory lock in pgstore),
	// so two writers — e.g. an old and a new pod overlapping during a rolling
	// deploy, or HA replicas — cannot fork the chain. link receives the current
	// head (nil at genesis) and returns the fully-linked event (its PrevHash and
	// HMAC set from that head); the store assigns ID and TS, inserts it, and
	// returns the stored event. Reading the head and inserting are one atomic
	// step, so the in-memory head an appender may cache is only advisory.
	AppendBrokerAuditLinked(ctx context.Context, link func(head *BrokerAuditEvent) BrokerAuditEvent) (BrokerAuditEvent, error)
	// ListBrokerAudit returns broker audit events ordered oldest-first (id ASC);
	// limit <= 0 returns all (used by the chain verifier).
	ListBrokerAudit(ctx context.Context, limit int) ([]BrokerAuditEvent, error)
	// GetBrokerAuditHead returns the most recent broker audit event, or (nil, nil)
	// when the log is empty (genesis).
	GetBrokerAuditHead(ctx context.Context) (*BrokerAuditEvent, error)

	// CreateSession inserts a login session, populating its ID and CreatedAt.
	CreateSession(ctx context.Context, s *Session) error
	// GetSessionByTokenHash returns a non-expired session, or ErrNotFound.
	GetSessionByTokenHash(ctx context.Context, tokenHashHex string) (*Session, error)
	// DeleteSession removes the session with the given token hash, or ErrNotFound.
	DeleteSession(ctx context.Context, tokenHashHex string) error
	// ListSessions returns all non-expired login sessions (newest first), so an
	// admin can see and revoke active logins.
	ListSessions(ctx context.Context) ([]Session, error)
	// DeleteSessionsByUsername revokes every login session for a username (e.g. a
	// directory user disabled upstream, or a compromised account), returning how
	// many were removed. It is idempotent — zero is not an error.
	DeleteSessionsByUsername(ctx context.Context, username string) (int, error)
	// DeleteExpiredSessions removes login sessions whose expiry has passed,
	// returning how many were deleted.
	//
	// Expiry was previously enforced only by FILTERING reads, never by removing
	// rows: the sole deletes were an explicit logout and per-username revocation.
	// Every portal login, every break-glass activation and every 60-second RDP
	// viewer token therefore left a row behind forever — table bloat in
	// PostgreSQL, and in memstore a genuine leak of one permanent map entry per
	// RDP viewer open. Broker tokens and OIDC states already had this sweep; login
	// sessions were the omission.
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error)

	// PublishSessionKill broadcasts a live-session kill to every replica so the
	// kill-switch works in HA (Postgres LISTEN/NOTIFY; an in-process hub for the
	// memory store). SubscribeSessionKills returns a stream of kills published by
	// any replica, delivered until ctx is cancelled — the local session registry
	// applies each to the sessions it hosts.
	PublishSessionKill(ctx context.Context, sel session.KillSelector) error
	SubscribeSessionKills(ctx context.Context) (<-chan session.KillSelector, error)

	// UpsertMFAEnrollment creates or replaces a user's TOTP enrollment.
	UpsertMFAEnrollment(ctx context.Context, e *MFAEnrollment) error
	// GetMFAEnrollment returns a user's TOTP enrollment, or ErrNotFound.
	GetMFAEnrollment(ctx context.Context, username string) (*MFAEnrollment, error)
	// ListMFAEnrollments returns all TOTP enrollments.
	ListMFAEnrollments(ctx context.Context) ([]MFAEnrollment, error)
	// DeleteMFAEnrollment removes a user's enrollment (and recovery codes), or ErrNotFound.
	DeleteMFAEnrollment(ctx context.Context, username string) error
	// ConsumeTOTPStep atomically records step as the user's last-used TOTP
	// time-step, returning true if step is newer than the last recorded one
	// (accept) and false if it was already used (a replay to reject).
	ConsumeTOTPStep(ctx context.Context, username string, step int64) (bool, error)

	// ReplaceMFARecoveryCodes stores a fresh set of recovery-code hashes for a
	// user, discarding any previous set.
	ReplaceMFARecoveryCodes(ctx context.Context, username string, codeHashes []string) error
	// ConsumeMFARecoveryCode removes a matching unused recovery code and reports
	// whether one was consumed.
	ConsumeMFARecoveryCode(ctx context.Context, username, codeHash string) (bool, error)
	// CountMFARecoveryCodes returns how many recovery codes remain.
	CountMFARecoveryCodes(ctx context.Context, username string) (int, error)

	// OIDC login PKCE/nonce state, shared across replicas so the auth-code
	// callback can land on any instance (HA).
	PutOIDCState(ctx context.Context, state, verifier, nonce string, expiresAt time.Time) error
	// TakeOIDCState atomically fetches and deletes an unexpired state; ok is false
	// if it is missing or expired.
	TakeOIDCState(ctx context.Context, state string, now time.Time) (verifier, nonce string, ok bool, err error)

	// Ping reports whether the backend is reachable (readiness probe).
	Ping(ctx context.Context) error

	// WithLeaderLock runs fn only if it can immediately acquire the advisory lock
	// for key (a non-blocking try). It returns ran=false without calling fn when
	// another process already holds the lock, so exactly one replica runs a periodic
	// job per tick (leader election for the background workers). The single-process
	// memstore always runs fn (ran=true). fn's error is returned unchanged.
	WithLeaderLock(ctx context.Context, key int64, fn func(context.Context) error) (ran bool, err error)

	// Close releases the backend's resources.
	Close()
}
