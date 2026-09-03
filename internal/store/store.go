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
	"github.com/morandeirachema/pamv1/internal/auditfmt"
	"github.com/morandeirachema/pamv1/internal/timeframe"
	"strings"
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
	SafeID *int64 `json:"safe_id,omitempty"`
	// RDPClipboard / RDPClipboardAudit tighten the global RDP clipboard policy
	// (PAM_RDP_CLIPBOARD / PAM_RDP_CLIPBOARD_AUDIT) for this one target; ""
	// inherits the global. The effective policy is the STRICTER of the two
	// (allow < readonly < deny; off < meta < full) — a high-sensitivity target
	// may deny what the fleet allows, but no target can loosen a global deny.
	RDPClipboard      string    `json:"rdp_clipboard,omitempty"`
	RDPClipboardAudit string    `json:"rdp_clipboard_audit,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
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

	// Scope narrows what the campaign snapshots (Phase 68). Empty ScopeKind is
	// the whole estate, which is what every campaign was before — a review of
	// several thousand grants that nobody completes. A scoped one is the review
	// somebody actually runs: this safe, this quarter; or everything this leaver
	// still holds.
	ScopeKind CampaignScope `json:"scope_kind,omitempty"`
	// ScopeSafeID is the safe reviewed when ScopeKind is CampaignScopeSafe: its
	// members, and the grants on every target assigned to it.
	ScopeSafeID *int64 `json:"scope_safe_id,omitempty"`
	// ScopeSubject is the grant holder reviewed when ScopeKind is
	// CampaignScopeSubject — matched against CampaignItem.Subject, so it covers
	// a user and a role alike.
	ScopeSubject string `json:"scope_subject,omitempty"`

	// RecurDays makes this campaign the ANCHOR of a recurring series: every
	// RecurDays a fresh campaign is opened with the same name and scope. Zero is
	// a one-off, which is what every campaign was before.
	//
	// The schedule lives on the anchor and never moves, so there is no invariant
	// about which row in a series carries it: the anchor spawns children, the
	// children are ordinary campaigns, and CLOSING THE ANCHOR ENDS THE SERIES.
	// That last part is the whole stop button — "close the recurring campaign"
	// is what an operator would try first, so it had better be the thing that
	// works.
	RecurDays int `json:"recur_days,omitempty"`
	// NextRunAt is when the anchor next spawns. Nil on a one-off or a child.
	NextRunAt *time.Time `json:"next_run_at,omitempty"`

	// Reviewer is the default reviewer stamped onto every item this campaign
	// snapshots (Phase 69). Empty means unassigned, which is what every campaign
	// was before.
	Reviewer string `json:"reviewer,omitempty"`

	// RemindAt is when the next reminder fires (Phase 70). Nil means no reminder
	// is scheduled — which is the case for a campaign with no due date, since
	// there is nothing to be early for.
	RemindAt *time.Time `json:"remind_at,omitempty"`
}

// CampaignScope is what a campaign reviews.
type CampaignScope string

const (
	// CampaignScopeAll reviews every target grant and safe membership.
	CampaignScopeAll CampaignScope = ""
	// CampaignScopeSafe reviews one safe: its members, and the grants on every
	// target assigned to it.
	CampaignScopeSafe CampaignScope = "safe"
	// CampaignScopeSubject reviews everything one subject holds, anywhere.
	CampaignScopeSubject CampaignScope = "subject"
)

// ValidCampaignScope reports whether s is a scope the snapshot understands. An
// unknown scope must never fall through to "review everything": that silently
// turns a typo into a campaign nobody can complete, which is the failure the
// scope exists to prevent.
func ValidCampaignScope(s CampaignScope) bool {
	switch s {
	case CampaignScopeAll, CampaignScopeSafe, CampaignScopeSubject:
		return true
	}
	return false
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
	// Reviewer is who is EXPECTED to decide this item (Phase 69), seeded from
	// the campaign and reassignable per item. Empty means unassigned.
	//
	// It is ADVISORY, deliberately: it routes work and makes a queue visible, it
	// is not an authorization gate. Anyone holding `approve` can still decide any
	// item, and DecidedBy records who actually did — so accountability comes from
	// the trail rather than from the assignment. Making it binding would add a
	// deadlock (the assigned reviewer leaves, nobody can close the campaign)
	// without adding evidence, since any approver could reassign the item anyway.
	Reviewer string `json:"reviewer,omitempty"`
}

// CredentialDependency declares a consumer of a credential — a Windows Service,
// Scheduled Task or IIS App Pool that logs on with the account — so that when
// the credential is rotated, PAMv1 also updates the consumer over WinRM and the
// rotation does not break production (Phase 17).
type CredentialDependency struct {
	ID           int64  `json:"id"`
	CredentialID int64  `json:"credential_id"`
	Kind         string `json:"kind"` // windows_service | scheduled_task | iis_apppool
	Host         string `json:"host"` // WinRM-reachable host running the consumer
	Port         int    `json:"port"` // WinRM port (0 → 5985)
	Name         string `json:"name"` // service / task / app-pool name
	// ManagementCredentialID names the credential PAMv1 connects to Host WITH in
	// order to update this consumer (Phase 61). 0 means "connect as the rotated
	// account", which is what PAMv1 did before this existed — and what it should
	// rarely do, since reconfiguring a service needs administrative rights on the
	// host that a service account is not supposed to hold.
	ManagementCredentialID int64 `json:"management_credential_id,omitempty"`
}

// Safe is a named container that groups targets and delegates who may access
// them (Phase 17). Membership is an additional grant path alongside per-target
// grants: a member of a target's safe may connect to it.
type Safe struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	// RequireApproval and MinApprovers are the safe's own access policy
	// (Phase 58). They bind every target placed in the safe, so a whole class of
	// systems — the production safe, the OT safe — is governed in one place
	// instead of target by target, which is how a newly onboarded target ends up
	// less protected than its neighbours.
	//
	// The policy is STRICTEST-WINS with the global and per-target settings: a
	// safe can tighten what they allow, never loosen it. MinApprovers is a floor
	// on DISTINCT approvers (dual control); 0 means the safe sets no floor and
	// the global/request value stands.
	RequireApproval bool `json:"require_approval,omitempty"`
	MinApprovers    int  `json:"min_approvers,omitempty"`
	// Personal (Phase 139) marks the safe private: auth.CanConnectTarget's
	// unconditional admin bypass no longer applies to a target placed here —
	// only the safe's own members, or a principal holding
	// auth.CapUnlimitedVaultAccess, may reach it. Set only at creation
	// (CreateSafe); UpdateSafe in both store implementations deliberately
	// never changes it, the same way it never changes CreatedAt, so a later
	// rename/policy edit cannot silently un-personalize a safe.
	Personal bool `json:"personal,omitempty"`
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
	// ExpiresAt and TimeFrame bound a standing membership in time (Phase
	// 240), exactly as on TargetGrant — see there.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	TimeFrame string     `json:"time_frame,omitempty"`
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
	// RecurDays makes an APPROVED request the ANCHOR of a recurring series
	// (Phase 120), mirroring Campaign's RecurDays/NextRunAt exactly: every
	// RecurDays a fresh, independently-approved child request is auto-filed
	// with the same requester/target/reason, so a periodic access need does
	// not depend on remembering to re-request it. The child is spawned
	// PENDING, not pre-approved — recurrence automates the paperwork, never
	// the four-eyes decision itself, so recurring access can never quietly
	// become standing access nobody re-reviews. Zero is a one-off, which is
	// what every request was before. StopAccessRequestRecurrence (RecurDays
	// -> 0) is the anchor's stop button, campaign-style.
	RecurDays int `json:"recur_days,omitempty"`
	// NextRunAt is when the anchor next spawns a child. Set when the anchor
	// is approved (not at creation, so an approval that takes days to arrive
	// doesn't make the first recurrence fire immediately on approval). Nil on
	// a one-off, a still-pending anchor, or a child (children never recur).
	NextRunAt *time.Time `json:"next_run_at,omitempty"`
}

// Credential is a privileged account on a Target. SecretEnc is always an
// encrypted vault token — plaintext never touches the store or the JSON
// encoder (note the "-" tag).
type Credential struct {
	ID         int64  `json:"id"`
	TargetID   int64  `json:"target_id"`
	Username   string `json:"username"`
	SecretType string `json:"secret_type"` // one of the SecretType* constants
	SecretEnc  string `json:"-"`
	// Provisioner marks this credential as eligible to run the DDL a db_zsp
	// dial needs (CREATE ROLE/LOGIN, DROP ROLE/LOGIN) for its target — a
	// real, stored, elevated credential, never itself db_zsp (Phase 129).
	// Exactly one provisioner per target is the supported shape; a second
	// one is legal in the schema but ambiguous at dial time, refused there.
	Provisioner bool `json:"provisioner"`
	// DoubleLockHolder names who holds this credential's DoubleLock password
	// (Phase 135) — a person or comma-separated set, never the password
	// itself. Empty (the default) means not double-locked: reveal/checkout
	// decrypt SecretEnc exactly as before. Non-empty means the reveal and
	// checkout API paths (never the session-proxy JIT-decrypt path, which
	// always uses SecretEnc unmodified) additionally require the matching
	// password, verified against DoubleLockVerifier before DoubleLockEnc —
	// a second ciphertext of the same secret keyed directly off the password
	// (PBKDF2-derived, no KEK involved) — is decrypted in its place. Kept
	// independent of the vault/KEK layer entirely, on purpose: `-rotate-kek`
	// re-wraps every KEK-protected artifact exhaustively, and a ciphertext
	// only the password (which the tool never has) can open would break
	// that guarantee, the same tension sealed session recordings already
	// have with KEK rotation — see internal/maint/rotate.go.
	DoubleLockHolder string `json:"double_lock_holder,omitempty"`
	// DoubleLockVerifier is a salted PBKDF2 hash of the DoubleLock password,
	// checked BEFORE ever attempting to decrypt DoubleLockEnc, so a caller
	// gets a clean "wrong password" instead of one opaque decrypt-failed
	// error indistinguishable from a corrupted ciphertext. Never the
	// password itself; never serialized.
	DoubleLockVerifier string `json:"-"`
	// DoubleLockEnc is the secret re-encrypted under a key derived from the
	// DoubleLock password (see DoubleLockHolder); empty when not
	// double-locked. Never serialized.
	DoubleLockEnc string     `json:"-"`
	CreatedAt     time.Time  `json:"created_at"`
	RotatedAt     *time.Time `json:"rotated_at,omitempty"`
}

// The secret types a Credential may hold. SecretTypeSSHCA and SecretTypeDBZSP
// are both Zero Standing Privilege (Phase 22, extended to databases in Phase
// 129): neither stores a secret — the proxy mints a short-lived SSH
// certificate, or provisions-and-drops an ephemeral database role, at dial
// time instead — so every path that would decrypt, reveal, rotate or check
// out a secret must special-case both. Naming the values (and the IsZSP
// predicate) means a new such path cannot silently skip the guard by
// mistyping a string literal — the failure mode a bare "ssh_ca" invites.
const (
	SecretTypePassword = "password"
	SecretTypeSSHKey   = "ssh_key"
	SecretTypeSSHCA    = "ssh_ca"
	SecretTypeDBZSP    = "db_zsp"
	// SecretTypeFile (Phase 145) holds arbitrary file content — a license
	// key, a cert bundle, a short document — client-encoded (base64) before
	// it ever reaches this struct, vaulted and revealed exactly like any
	// other secret. The one thing that IS special-cased for it is size: a
	// credential is not general object storage, so `internal/api` refuses a
	// file secret over PAM_CREDENTIAL_FILE_MAX_KB before it is ever
	// encrypted, the same hard-refuse-not-truncate posture the SFTP capture
	// byte cap already established.
	SecretTypeFile = "file"
	// SecretTypeK8sToken (Phase 155) is a Kubernetes bearer credential — a
	// service-account token — for a `kubernetes` target: vaulted, revealed and
	// rotated like any other secret, injected just-in-time as the
	// `Authorization: Bearer …` header of one brokered API call and never
	// handed to the operator. What that token may do is decided by the
	// CLUSTER's own RBAC; PAMv1 brokers and audits the call, it does not
	// re-implement Kubernetes authorization.
	SecretTypeK8sToken = "k8s_token"
)

// IsZSP reports whether this is a Zero Standing Privilege credential
// (SecretTypeSSHCA or SecretTypeDBZSP), which carries no stored secret to
// decrypt or reveal.
func (c Credential) IsZSP() bool {
	return c.SecretType == SecretTypeSSHCA || c.SecretType == SecretTypeDBZSP
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
	// ExpiresAt, when set, is the instant the grant stops admitting (Phase
	// 240): EffectiveTargetGrants and the reach view never return an expired
	// row, and the expiry sweeper deletes it (audited). Nil is a grant with no
	// end date — what every row before Phase 240 is.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// TimeFrame, when non-empty, is a recurring weekly window
	// (timeframe.Parse: "Mon-Fri 08:00-18:00 Europe/Madrid") outside which
	// the grant does not admit. The row persists; only its effect is
	// periodic. A session admitted inside the window is given the window's
	// end as its deadline (auth.GrantDeadline), so it cannot outlive the
	// authorization that admitted it.
	TimeFrame string `json:"time_frame,omitempty"`
}

// GrantLive reports whether a grant with the given bounds admits at now: not
// expired, and inside its time frame (an unparsable frame is treated as never
// live, fail-closed — the API refuses to store one, so it cannot occur short
// of a hand-edited row). Shared by both store implementations so the two
// paths (direct grants, safe membership) and both engines agree.
func GrantLive(expiresAt *time.Time, frame string, now time.Time) bool {
	if expiresAt != nil && !expiresAt.After(now) {
		return false
	}
	if frame == "" {
		return true
	}
	f, err := timeframe.Parse(frame)
	if err != nil {
		return false
	}
	return f.Contains(now)
}

// GrantBound returns the instant a live grant stops admitting — the sooner of
// its expiry and the end of the time-frame window containing now. ok is false
// for a grant bounded by neither. Callers pass a grant GrantLive said yes to.
func GrantBound(expiresAt *time.Time, frame string, now time.Time) (bound time.Time, ok bool) {
	if expiresAt != nil {
		bound, ok = *expiresAt, true
	}
	if frame != "" {
		if f, err := timeframe.Parse(frame); err == nil {
			if end, has := f.End(now); has && (!ok || end.Before(bound)) {
				bound, ok = end, true
			}
		}
	}
	return bound, ok
}

// LiveTargetGrants filters gs to the rows admitting at now (GrantLive).
func LiveTargetGrants(gs []TargetGrant, now time.Time) []TargetGrant {
	out := make([]TargetGrant, 0, len(gs))
	for _, g := range gs {
		if GrantLive(g.ExpiresAt, g.TimeFrame, now) {
			out = append(out, g)
		}
	}
	return out
}

// LiveSubjectGrants is LiveTargetGrants for the subject-side view.
func LiveSubjectGrants(gs []SubjectGrant, now time.Time) []SubjectGrant {
	out := make([]SubjectGrant, 0, len(gs))
	for _, g := range gs {
		if GrantLive(g.ExpiresAt, g.TimeFrame, now) {
			out = append(out, g)
		}
	}
	return out
}

// Grant paths — how a subject came to hold a grant, recorded on SubjectGrant.
const (
	// GrantViaGrant is a row in target_grants naming the subject directly.
	GrantViaGrant = "grant"
	// GrantViaSafe is membership of the safe the target sits in (Phase 17),
	// which grants every target placed in that safe.
	GrantViaSafe = "safe"
)

// GrantSubject is one identifier a grant can name: a username ("user") or a
// role ("role"). A principal presents several — its own name plus every role it
// holds — and GrantsForSubjects takes the whole set, because a subject's access
// is the union of the grants naming any of them.
type GrantSubject struct {
	Type string `json:"type"` // user | role
	Name string `json:"name"`
}

// SubjectGrant is one grant seen from the subject's side: which target it
// reaches, which of the presented subjects it named, and which path it came
// from. TargetName is joined in because the answer to "what can this subject
// reach?" is read by a person, and a list of target ids is not an answer.
type SubjectGrant struct {
	TargetID    int64  `json:"target_id"`
	TargetName  string `json:"target_name"`
	SubjectType string `json:"subject_type"` // user | role
	Subject     string `json:"subject"`
	Via         string `json:"via"` // grant | safe
	// SafeID is the safe the grant came through, set only when Via is
	// GrantViaSafe (nil for a direct grant).
	SafeID *int64 `json:"safe_id,omitempty"`
	// ExpiresAt and TimeFrame are the underlying row's bounds (Phase 240),
	// reported so an entitlement review can show WHEN a reach ends; the view
	// itself only ever contains rows live at the time it was taken.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	TimeFrame string     `json:"time_frame,omitempty"`
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

// SessionShareInvite is a request to let a second party join a live SSH
// session, view-only or view-control (Phase 116). It goes through the same
// request-then-approve shape as an AccessRequest/VendorGrant — four eyes: the
// Requester and the Approver must differ, and nothing is redeemable (no email
// sent, no join: token valid) until Status=="approved". Kind distinguishes the
// two invite surfaces: "internal" resolves Invitee as an existing PAMv1
// username, redeemed by an SSH login; "external" resolves Email as an
// unauthenticated contact address, redeemed via a mailed link + QR code by a
// browser. TokenHash and ExpiresAt are populated only once approved — ExpiresAt
// is stamped from the approval instant, not the request instant, so the
// redemption window is always the configured TTL from when the invite actually
// became live, however long it sat pending. ConsumedAt marks single-use
// redemption; a session can still be watched multiple times only by requesting
// (and approving) a fresh invite per join, matching the codebase's existing
// one-time-approval philosophy (Phase 26).
type SessionShareInvite struct {
	ID         int64      `json:"id"`
	SessionID  string     `json:"session_id"`
	Mode       string     `json:"mode"` // view_only | view_control
	Kind       string     `json:"kind"` // internal | external
	Invitee    string     `json:"invitee,omitempty"`
	Email      string     `json:"email,omitempty"`
	Status     string     `json:"status"` // pending | approved | denied | revoked
	Requester  string     `json:"requester"`
	Approver   string     `json:"approver,omitempty"`
	TokenHash  string     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	DecidedAt  *time.Time `json:"decided_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// ApprovalInvite is a magic link that lets a named person decide a pending
// AccessRequest without ever logging into PAMv1 (Phase 137) — BeyondTrust's
// out-of-band approval, the buildable "link" half (no native mobile app).
// Minting one requires CapApprove (the same capability the authenticated
// approve/deny routes require), so it is a delegation of a capability the
// creator already holds, not a request for one — unlike SessionShareInvite,
// there is no separate meta-approval stage. Redemption is split into a
// safe, non-consuming preview (GetApprovalInviteByTokenHash, a GET, so a
// mail client's link-prefetcher cannot trigger anything) and the actual
// state-changing decision (ConsumeApprovalInviteByTokenHash, a POST,
// single-use).
//
// Self-approval is closed at TWO points, not one — an easy mistake to make
// (and one this phase's own review caught): the redemption actor
// decideAccessRequest sees is built as "magiclink:<Email>", a form no real
// principal's actor string can ever take, but that alone does not stop the
// REQUESTER from minting an invite addressed to their own inbox — the
// synthetic string is different from their real actor name either way, so
// decideAccessRequest's Requester != approver check would never trip on
// it. What actually closes that path is createApprovalInvite refusing a
// caller who IS the request's own Requester, mirroring the exact rule
// decideAccessRequest enforces, applied one step earlier — a requester can
// never create the delegation in the first place, regardless of whose
// email they address it to.
type ApprovalInvite struct {
	ID              int64     `json:"id"`
	AccessRequestID int64     `json:"access_request_id"`
	Email           string    `json:"email"`
	CreatedBy       string    `json:"created_by"`
	TokenHash       string    `json:"-"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	// Decision is set on redemption ("approved" | "denied"), purely for the
	// creator's own visibility — empty until then.
	Decision   string     `json:"decision,omitempty"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
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
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"` // admin | user | auditor | approver
	// IPAllowlist restricts this user to connecting from a source address
	// inside one of these comma-separated CIDR blocks (Phase 118), e.g.
	// "10.0.0.0/8, 192.168.1.0/24". Empty (the default) means unrestricted.
	// Validated with auth.ValidateCIDRList at write time, so a stored value
	// is always well-formed; checked with auth.IPAllowed at both HTTP authz
	// and session-proxy connect time.
	IPAllowlist string `json:"ip_allowlist,omitempty"`
	// DeviceFingerprint binds this user to one enrolled client-certificate
	// fingerprint (Phase 133), e.g. a SHA-256 hex digest of the cert a trusted
	// reverse proxy terminated. Empty (the default) means unbound — no device
	// check for this user even when PAM_DEVICE_HEADER is set deployment-wide.
	// Checked against the configured header's value at HTTP authz time; not a
	// secret (derived from a public certificate), so an ordinary equality
	// check is enough — no constant-time comparison needed.
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
	// ExternalID is an IdP's own correlation key for this user (SCIM's
	// "externalId", Phase 149) — distinct from Username, which is this
	// user's own login identity. Empty (the default) for every user not
	// provisioned through /scim/v2/Users; unique among non-empty values.
	ExternalID string `json:"external_id,omitempty"`
	// SlackUserID links this user to one Slack member ID (Phase 236, e.g.
	// "U0123456789" — the workspace-scoped id Slack sends in an
	// interactivity payload's user.id, never the display handle, which a
	// member can change at will). It is the ONLY way a Slack button click
	// becomes a PAMv1 decision: the interactivity handler resolves the
	// clicking member to this row and decides as that PAMv1 identity, so
	// four-eyes and distinct-approver checks compare like with like. Empty
	// (the default) means this user cannot decide from Slack at all; unique
	// among non-empty values, since one member must not map to two humans.
	SlackUserID string `json:"slack_user_id,omitempty"`
	// Active is SCIM's deprovisioning switch (Phase 149): false blocks this
	// user's own local access token from resolving (see
	// auth.Resolver.Resolve) without deleting the row, so re-activating (or
	// an IdP re-provisioning the same externalId) restores access without a
	// new token ever needing to be minted or distributed. True (the
	// default) for every user created before this field existed and for
	// every user created outside SCIM, so nothing already-working changes.
	Active    bool      `json:"active"`
	TokenHash string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

// ScimKey is a non-human client identity for the SCIM 2.0 provisioning API
// (Phase 149): a bearer key whose SHA-256 hash is stored, scoped only to
// /scim/v2/Users — an IdP holding one can provision/deprovision the user
// roster but never anything a human's own capability set would reach (it is
// not an auth.Principal at all, the same non-human shape AgentKey/AppKey
// already use). Owner is the accountable human/team recorded in the audit
// trail.
type ScimKey struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Owner     string    `json:"owner"`
	TokenHash string    `json:"-"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
}

// EndpointAgent is an OUTBOUND-ONLY connectivity agent installed on a target
// endpoint that PAMv1 cannot dial into — a NAT'd branch box, a CGNAT'd
// contractor laptop, an unattended host with no inbound firewall rule (Phase
// 153, BeyondTrust "Jump Client"-style). The agent (cmd/pam-agent) dials OUT
// to pam-server's SSH listener as "endpoint-agent:<Name>" with the bearer key
// whose SHA-256 hash is stored here, requests a reverse forward, and from then
// on the proxy reaches the target by opening channels back through that
// connection instead of dialing Target.Host. One agent per target: while an
// unrevoked EndpointAgent row exists for a target, that target is reached ONLY
// through it — never dialed directly — so an offline agent means "target
// unreachable", not "fall back to a direct dial".
//
// Not to be confused with AgentKey, the AI-agent identity for the access
// broker: an endpoint agent is infrastructure (a tunnel), holds no capability
// set, is never an auth.Principal, and can open nothing toward PAMv1 — its
// connection only ever carries channels PAMv1 opens toward IT.
type EndpointAgent struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	TargetID  int64      `json:"target_id"`
	KeyHash   string     `json:"-"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// Active reports whether the agent may still authenticate (not revoked).
func (a *EndpointAgent) Active() bool { return a.RevokedAt == nil }

// The two audit actions a brokered tool call spends budget on, spelled here so
// both store backends charge for exactly the same thing.
//
// They are a deliberate DUPLICATE of `broker.ActionToolCallExecuted` and
// `broker.ActionToolCallResumed`, because `internal/store` cannot import
// `internal/broker` — the broker imports the store, so the dependency only runs
// one way. Duplicated constants drift, so the copy is not left to discipline:
// an external test (`store_test`, which may import the broker without creating
// a cycle) asserts these are byte-identical to the broker's own names.
const (
	AuditActionToolCallExecuted = "broker.tool_call.executed"
	AuditActionToolCallResumed  = "broker.tool_call.resumed"
)

// MaxTokenIDField bounds a presented token's `jti` on the audit trail. The SVID
// verifier already truncates to the same length; this is where the audit side
// states it, so the writer and the counter below agree on the exact bytes.
const MaxTokenIDField = 64

// AgentTokenAuditField renders the ` svid_jti:"…"` field exactly as it appears
// in a brokered call's audit detail.
//
// It exists for the same reason CredentialAAD does, and carries the same hazard:
// TWO sides must produce byte-identical output or the feature silently fails.
// The API writes this field onto every brokered call; CountAgentCallsForTokenSince
// searches the trail for it. If they diverged, the search would simply match
// nothing — and a ceiling that counts zero is a ceiling that never fires, which
// is the failure direction that does not announce itself. So neither side builds
// the string: both call this.
//
// The value is quoted through auditfmt.Field rather than concatenated raw,
// because a `jti` is chosen by the token's issuer and reaches an audit detail
// that is later SUBSTRING-matched. Quoting both delimits the value (so one jti
// cannot match as a prefix of another) and escapes anything that would let an
// issuer-chosen string forge a neighbouring `key:value` pair.
func AgentTokenAuditField(jti string) string {
	return " svid_jti:" + auditfmt.Field(jti, MaxTokenIDField)
}

// AgentKey is an AI-agent identity for the access broker: a bearer key whose
// SHA-256 hash is stored, granting only the ability to request brokered tool
// calls (never a credential). Owner is the accountable human/service recorded in
// every audit entry the agent produces.
//
// Lifecycle (Phase 159) mirrors EndpointAgent's: a key can be suspended
// (Disabled) without destroying it, can be given a hard end date, and records
// when it was last used — so an agent identity is a managed credential rather
// than an immortal standing bearer token.
type AgentKey struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Owner     string    `json:"owner"`
	TokenHash string    `json:"-"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt is the instant the key stops authenticating. Nil means "never
	// expires", which is the behaviour every key had before this field existed
	// — so rows created earlier keep working unchanged.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// LastUsedAt is when the key last authenticated a broker call, stamped by
	// TouchAgentKey. Nil means it has never been used since the field was
	// added, which is exactly what a dormant-credential report wants to see.
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	// BudgetPerDay is this agent's cumulative cap on brokered tool calls per
	// day (Phase 167) — the "how much in total" control a per-minute rate
	// limit cannot express, since 60 calls/minute still allows 86,400 a day.
	//
	// It is a POINTER because three states must stay distinguishable, and
	// conflating any two of them is a security bug:
	//
	//   nil  — no per-agent setting; the server-wide default budget applies.
	//          (In Python terms: the key is absent, not set to zero.)
	//   0    — a deliberate hard stop: this agent may make NO calls at all.
	//          This is an explicit administrative decision and must never be
	//          read as "unset" and quietly replaced by the server default.
	//   > 0  — exactly that many brokered tool calls per day.
	//
	// A plain int cannot hold that: Go zero-values an absent int to 0, so
	// "nobody configured this" and "forbid everything" would arrive at the
	// enforcement gate looking identical. Test the pointer for nil first, then
	// dereference; never compare *BudgetPerDay before the nil check.
	BudgetPerDay *int `json:"budget_per_day,omitempty"`
}

// Active reports whether the key may still authenticate at the given instant.
//
// Both halves matter and neither implies the other: Disabled is an explicit
// human act (suspend this agent now, keep the row so it can be re-enabled and
// so its audit history still resolves), while ExpiresAt is a policy clock that
// retires the key with no operator involved. A key can be enabled but expired,
// or unexpired but suspended; only "neither" means it still works. A nil
// ExpiresAt is treated as "never expires" rather than "expired long ago", so
// pre-Phase-159 rows stay usable.
func (k *AgentKey) Active(now time.Time) bool {
	if k.Disabled {
		return false
	}
	return k.ExpiresAt == nil || now.Before(*k.ExpiresAt)
}

// AgentQuarantine is a local stop-switch on one AI agent's identity, keyed by
// Subject — the agent's canonical identity name as the broker sees it: the
// agent-key name for a static bearer key, or the full SPIFFE ID (e.g.
// "spiffe://example.org/agent/planner") for an SVID-authenticated agent.
//
// It is keyed by name rather than by agent_keys row ID precisely because an
// SVID-authenticated agent has NO row in agent_keys at all — its identity is
// attested by the SPIFFE workload API, and PAMv1 never issued it a key it
// could disable. Without a subject-keyed quarantine there would be no local
// way to stop such an agent short of changing the trust domain itself.
// Quarantine is therefore the one containment control that covers every agent
// authentication path, static or attested.
type AgentQuarantine struct {
	ID        int64     `json:"id"`
	Subject   string    `json:"subject"`
	Reason    string    `json:"reason"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// AgentCallReservation is one compare-and-spend against an agent's daily budget
// and, when the call presented a token, that token's ceiling (Phase 219; the
// 2026-08-26 audit's M-3, reservation half).
//
// Both limits are COUNTED from the audit trail — that is what an operator
// reads, and it stays that way — but a count followed by a call is a
// check-then-act: two calls arriving together each read the same number, both
// pass, and the limit over-runs by the width of the burst. A reservation is the
// row the gate writes at the instant of its decision, under the store's own
// serialisation, so the comparison and the spend are one operation. It is kept
// when the call does work and released when it does not, and a row older than
// the rolling window is purged by the next reservation for that agent.
type AgentCallReservation struct {
	ID      int64
	Agent   string
	TokenID string
	At      time.Time
	// Refused names the limit that refused the reservation —
	// ReservationRefusedBudget or ReservationRefusedToken — and is empty when
	// the reservation was made (ID is then non-zero).
	Refused string
	// AgentUsed and TokenUsed are the reservations already standing in the
	// window for the agent and for the token at the instant of the decision,
	// this one excluded — the "used" an exhaustion record reports.
	AgentUsed int
	TokenUsed int
}

// The two limits ReserveAgentCall can refuse on, in the order it checks them.
const (
	ReservationRefusedBudget = "budget"
	ReservationRefusedToken  = "token"
)

// AgentIdentity records the accountable human behind an agent identity PAMv1
// never issued a key to: a SPIFFE/SVID-authenticated workload, whose credential
// is attested by the trust domain rather than minted here.
//
// It exists because "who owns this agent" is load-bearing in two places that
// both silently no-opped for an attested agent. Four-eyes approval refuses the
// human who owns an agent from approving that agent's own parked call — a
// comparison against `Identity.OnBehalfOf`, which for an SVID is the outermost
// SPIFFE ID in its delegation chain and can never equal a person's username, so
// the refusal could not fire and the human operating an agent could approve its
// privileged calls alone. And deleting a human suspends every agent key they
// owned, which reaches nothing when the agent has no key row. Both need one
// fact PAMv1 had nowhere to record: the person accountable for a SPIFFE ID.
//
// This is an OWNER registry, not enrollment or attestation. Recording an owner
// does not admit a workload (the trust domain already did that) and does not
// attest it (SPIRE workload attestation stays infra-bound, see
// docs/EXTERNAL-INFRA-GAPS.md). It answers "who do we hold responsible", which
// is the question both controls above were asking.
// Enrolled (Phase 174) separates the two ways a row gets here, which mean
// opposite things to an operator: an ENROLLED row was recorded deliberately by
// an admin, and an unenrolled one was created by PAMv1 the first time that
// SPIFFE ID authenticated — a workload nobody has claimed, listed so it can be
// reviewed rather than discovered from a refused approval. FirstSeen/LastSeen
// exist for the same reason: an inventory that only holds what somebody
// remembered to type is not an inventory.
type AgentIdentity struct {
	ID        int64      `json:"id"`
	SPIFFEID  string     `json:"spiffe_id"`
	Owner     string     `json:"owner"`
	Note      string     `json:"note,omitempty"`
	Enrolled  bool       `json:"enrolled"`
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
}

// Attributed reports whether this registration names an accountable human. An
// auto-discovered row has none, which is exactly the state the four-eyes gate
// must treat as unattributed — a row existing is not the same as somebody
// answering for it.
func (a *AgentIdentity) Attributed() bool { return strings.TrimSpace(a.Owner) != "" }

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
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Org      string `json:"org"`
	// Email is an optional on-file contact address (Phase 116), used to
	// auto-fill a session-share invite issued in this vendor's context. Empty
	// on rows that predate the field; unrelated to Username, which is the
	// vendor's own login identity, not necessarily reachable by mail.
	Email     string    `json:"email,omitempty"`
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

// SSHCert records an operator-issued SSH certificate (Phase 28): PAMv1 signed the
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
	ID           int64 `json:"id"`
	AppID        int64 `json:"app_id"`
	CredentialID int64 `json:"credential_id"`
	// Alias is a stable, operator-chosen name for this grant, unique within the
	// app (Phase 197). It exists because a declarative consumer — an External
	// Secrets Operator SecretStore, say — has to name the secret in a manifest
	// held in git, and a credential's BIGSERIAL id is not stable across
	// environments, a restore, or a delete-and-recreate. Empty means the grant is
	// addressable by credential id only, which is every grant made before this
	// field existed.
	Alias     string    `json:"alias,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// BrokerToken is a short-lived, single-use ticket the broker mints when a tool
// call is parked for approval (Phase 13). The agent presents its opaque token to
// resume and collect the post-approval result exactly once; the stored JTI is the
// token's SHA-256 hash, bound to the parked call and an expiry.
type BrokerToken struct {
	JTI    string `json:"-"` // SHA-256 hex of the opaque token
	CallID string `json:"call_id"`
	// Subject is the identity that parked the call and may therefore collect
	// its result (Phase 222; the 2026-08-26 audit's F-7): the same subject
	// string the broker uses to tell one agent from another — a static key's
	// row id, an attested workload's SPIFFE ID. Peek and Consume refuse any
	// other presenter as if the token did not exist. Empty on a row minted
	// before the binding existed, which spends for anyone for the remainder
	// of its TTL — the one-window upgrade path, not a bypass.
	Subject   string     `json:"-"`
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

// WebAuthnCredential is one registered FIDO2/WebAuthn authenticator (a
// hardware key or a platform authenticator). A user may register several —
// unlike MFAEnrollment, Username is not the key: ID is a surrogate, since one
// account can hold more than one authenticator (a YubiKey and a phone).
//
// PublicKey is stored in the clear, deliberately: unlike MFAEnrollment's
// SecretEnc, this is a public key. Knowing it lets nobody forge an assertion —
// only the authenticator's private key, which never leaves the device, can do
// that — the same reasoning that already lets an SSH authorized_keys entry
// live unencrypted.
type WebAuthnCredential struct {
	ID                int64  `json:"id"`
	Username          string `json:"username"`
	CredentialID      []byte `json:"-"`
	PublicKey         []byte `json:"-"`
	AttestationType   string `json:"attestation_type,omitempty"`
	AttestationFormat string `json:"attestation_format,omitempty"`
	// Transports is a comma-separated hint list ("usb,nfc"), as reported by the
	// authenticator at registration; advisory only, never enforced.
	Transports string `json:"transports,omitempty"`
	AAGUID     []byte `json:"aaguid,omitempty"`
	// SignCount lets a future login detect a cloned authenticator: a genuine
	// device's counter only increases, so a login whose count does not exceed
	// the stored value indicates the credential was duplicated.
	SignCount    uint32     `json:"-"`
	CloneWarning bool       `json:"clone_warning,omitempty"`
	Name         string     `json:"name"` // user-chosen nickname, e.g. "YubiKey 5C"
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

// List-cursor semantics (Phase 44). Every top-level inventory list read takes a
// (limit, afterID) window: rows are returned in ascending id order, starting
// strictly after afterID, at most limit rows when limit > 0. limit <= 0 means
// "no cap" — reserved for in-process sweeps (rotation, reconciliation, the
// vendor sweeper); the HTTP handlers always pass a clamped limit so an
// authenticated client can never pull an unbounded result set. afterID <= 0
// starts from the beginning. Child lists scoped to one parent (a target's
// grants, a safe's members) stay unwindowed — they are bounded by their parent.

// The Store interface is composed from ROLE interfaces, one per domain, rather
// than written as one flat list. It had grown to 137 methods, which made it the
// main tax on every change — a new feature edits the interface and both
// implementations — and made it impossible for a consumer to state the small
// slice it actually needs.
//
// The pattern is not new here: `session.LiveStore`, `session.StepUpStore`,
// `ApprovalClaimStore` and `SafeReader` were already narrow views taken by the
// code that needed them. This applies the same idea to the whole surface.
//
// Store still embeds every role, so both implementations and every existing
// caller are unchanged — the method set is identical. What it buys is that a new
// consumer can depend on `store.CampaignStore` (14 methods) instead of
// `store.Store` (137), which is what makes a fake or a second backend tractable.

// TargetStore is the target inventory.
type TargetStore interface {
	// CreateTarget inserts a target, populating its ID and CreatedAt.
	//
	// SafeID on the passed struct is NOT persisted: a target's safe is set by
	// AssignTargetSafe and only there, the same way UpdateTarget never touches
	// it (see Target.SafeID), and no create path — the REST API included —
	// accepts a safe at creation. Set it here and pgstore drops it silently
	// while memstore happens to keep it, so a memstore-only test can pass while
	// the real backend has no assignment at all. Assign in a second call.
	CreateTarget(ctx context.Context, t *Target) error
	// ListTargets returns targets in the (limit, afterID) window, id-ascending.
	ListTargets(ctx context.Context, limit int, afterID int64) ([]Target, error)
	// GetTarget returns one target by ID, or ErrNotFound.
	GetTarget(ctx context.Context, id int64) (*Target, error)
	// UpdateTarget replaces the editable fields (Name, Host, Port, OSType,
	// Protocol, RequireApproval, RDPClipboard, RDPClipboardAudit) of the target
	// with t.ID, refreshing t's SafeID
	// and CreatedAt from the stored row. It deliberately does NOT touch the safe
	// assignment (AssignTargetSafe owns that). ErrNotFound if the target is
	// missing, ErrConflict if the new name is taken — so fixing a host or port
	// no longer means delete + recreate, which cascades away the target's
	// credentials, grants, dependencies and safe assignment.
	UpdateTarget(ctx context.Context, t *Target) error
	// DeleteTarget removes a target (cascading to its dependents), or ErrNotFound.
	DeleteTarget(ctx context.Context, id int64) error
}

// CredentialStore is the vaulted credentials and the consumers that
// depend on them.
type CredentialStore interface {
	// CreateCredential inserts a credential for a target, or ErrNotFound if the target is missing.
	CreateCredential(ctx context.Context, c *Credential) error
	// ListCredentials returns credentials for one target (or all when targetID
	// is 0) in the (limit, afterID) window, id-ascending, WITH SecretEnc
	// populated. That is deliberate, not an oversight: several real internal
	// callers — -rotate-kek's exhaustive re-wrap, the credential lifecycle
	// reconciler, findProvisioner (db_zsp), and every JIT-decrypt path that
	// resolves "the target's credential" by username rather than by ID
	// (dbproxy.lookupTargetCred, the RDP/VNC viewer, REST WinRM, the broker's
	// ssh_exec/winrm_exec tools) — all list first and decrypt from the result
	// afterward, exactly so every authorization gate can run before any
	// plaintext exists. Stripping the secret here would silently break every
	// one of them. A caller that only needs to DISPLAY a list — the REST
	// inventory endpoint, the broker's own list_credentials tool — uses
	// ListCredentialsMeta instead (Phase 145).
	ListCredentials(ctx context.Context, targetID int64, limit int, afterID int64) ([]Credential, error)
	// ListCredentialsMeta is ListCredentials without SecretEnc, DoubleLockVerifier
	// or DoubleLockEnc (Phase 145) — all three are json:"-" and unbounded, so a
	// caller that only lists credentials for display (never decrypts one from
	// the result) uses this instead and skips paying for ciphertext it will
	// never read. A file-attachment secret makes that cost real: it is no
	// longer a small fixed-size token, potentially up to PAM_CREDENTIAL_FILE_MAX_KB
	// per row. Getting this wrong in the other direction is the dangerous one —
	// see ListCredentials's own doc comment before pointing a new caller here.
	ListCredentialsMeta(ctx context.Context, targetID int64, limit int, afterID int64) ([]Credential, error)
	// GetCredential returns one credential by ID, or ErrNotFound.
	GetCredential(ctx context.Context, id int64) (*Credential, error)
	// UpdateCredentialSecretEnc replaces a credential's encrypted secret (used
	// by vault key rotation). It deliberately does NOT touch rotated_at — a KEK
	// re-wrap is not a credential rotation.
	UpdateCredentialSecretEnc(ctx context.Context, id int64, secretEnc string) error
	// RotateCredentialSecret replaces the encrypted secret AND stamps rotated_at
	// (used by the credential-lifecycle rotation, where the secret on the target
	// actually changed). Also clears any DoubleLock (Phase 135): a DoubleLockEnc
	// sealed under the OLD secret is now stale, and the password that produced
	// it is not available here to re-seal a new one — the holder must re-enable
	// DoubleLock afterward. UpdateCredentialSecretEnc (the KEK re-wrap path,
	// same plaintext under a new KEK) deliberately does NOT do this.
	RotateCredentialSecret(ctx context.Context, id int64, secretEnc string, rotatedAt time.Time) error
	// SetCredentialDoubleLock enables DoubleLock on a credential (Phase 135):
	// holder is a display name (never the password), verifier is a salted
	// PBKDF2 hash used only to distinguish a wrong password from a corrupted
	// token, and enc is the secret re-encrypted under a key derived from the
	// password. ErrNotFound if absent.
	SetCredentialDoubleLock(ctx context.Context, id int64, holder, verifier, enc string) error
	// ClearCredentialDoubleLock disables DoubleLock on a credential, or
	// ErrNotFound if absent.
	ClearCredentialDoubleLock(ctx context.Context, id int64) error
	// DeleteCredential removes a credential by ID, or ErrNotFound.
	DeleteCredential(ctx context.Context, id int64) error

	// CreateCredentialDependency declares a consumer of a credential (ErrNotFound
	// if the credential does not exist).
	CreateCredentialDependency(ctx context.Context, d *CredentialDependency) error
	// ListCredentialDependencies returns a credential's declared consumers.
	ListCredentialDependencies(ctx context.Context, credentialID int64) ([]CredentialDependency, error)
	// DeleteCredentialDependency removes a dependency by ID, or ErrNotFound.
	DeleteCredentialDependency(ctx context.Context, id int64) error
}

// GrantStore is who may reach what: direct target grants, and safes with
// their members (the two paths EffectiveTargetGrants folds together).
type GrantStore interface {
	// CreateTargetGrant adds an authorization grant to a target.
	CreateTargetGrant(ctx context.Context, g *TargetGrant) error
	// ListTargetGrants returns the grants for a target.
	ListTargetGrants(ctx context.Context, targetID int64) ([]TargetGrant, error)
	// DeleteTargetGrant removes a grant by ID, or ErrNotFound.
	DeleteTargetGrant(ctx context.Context, id int64) error
	// SweepExpiredGrants deletes every target grant and safe membership whose
	// ExpiresAt is at or before now (Phase 240), returning the deleted rows so
	// the caller can audit each one. Rows with no expiry are never touched.
	SweepExpiredGrants(ctx context.Context, now time.Time) ([]TargetGrant, []SafeMember, error)
	// EffectiveTargetGrants returns a target's direct grants unioned with the
	// grants derived from its safe's membership (Phase 17). The connect-time
	// authorization decision uses this, so a target in a safe is reachable by the
	// safe's members. An empty result means the target is unrestricted (open).
	EffectiveTargetGrants(ctx context.Context, targetID int64) ([]TargetGrant, error)
	// GrantsForSubjects is EffectiveTargetGrants read from the other side
	// (Phase 189): instead of "who may reach this target", it answers "which
	// grants name any of these subjects", across the whole estate, in one read.
	// The subjects are the identifiers one principal presents — its username and
	// every role it holds — so a caller asks once rather than per target.
	//
	// The same two paths are folded as EffectiveTargetGrants folds them, and each
	// row records which one it came from in Via (GrantViaGrant / GrantViaSafe)
	// so a review can say WHY, not just that. Rows are ordered by target id, then
	// by path (GrantViaGrant before GrantViaSafe), then by subject — a
	// SubjectGrant carries no grant id of its own, so there is nothing finer to
	// order by, and callers that need one row per target pick it themselves (see
	// auth.bestGrant). An empty result does NOT mean "reaches nothing": a target with no
	// grants at all is open to any connect-capable principal, which is a fact
	// about the target, not about the subject — see GatedTargetIDs.
	GrantsForSubjects(ctx context.Context, subjects []GrantSubject) ([]SubjectGrant, error)
	// GatedTargetIDs returns the ids of every target that has at least one
	// effective grant (a direct grant, or a member of the safe it sits in),
	// ascending. It is the missing half of the subject-indexed view: a target
	// absent from this set has no grants, and an ungated target that is not in a
	// safe is open. Exactly equivalent to len(EffectiveTargetGrants(id)) > 0 for
	// every target, computed in one read instead of one per target.
	GatedTargetIDs(ctx context.Context) ([]int64, error)
	// ReachGrantSnapshot returns GrantsForSubjects and GatedTargetIDs together,
	// from ONE CONSISTENT VIEW of the estate. It exists because the two answers
	// are only meaningful against each other: "this target is gated" and "these
	// are the subject's grants on it" combine into a reachability decision, and
	// if the two halves come from different moments the combination describes an
	// estate that never existed.
	//
	// Read separately, either order is wrong in one direction. Gated first: a
	// grant created in the window leaves the target ungated in the older
	// snapshot and it is reported OPEN — reachable by anyone — at the moment
	// somebody restricted it. Grants first: revoking THIS subject's grant on a
	// target other grants still hold leaves the deleted row in hand and the
	// target still gated, so it is reported reachable via a grant that no longer
	// exists. Phase 191 swapped the order and closed the first; this closes both,
	// which is the only version that does not trade one window for another.
	//
	// Implementations must make the two reads atomic with respect to writers —
	// pgstore uses a read-only REPEATABLE READ transaction, memstore holds its
	// lock across both.
	ReachGrantSnapshot(ctx context.Context, subjects []GrantSubject) (grants []SubjectGrant, gated []int64, err error)

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
}

// CertificationStore is access certification — campaigns, their items, and
// the recurrence and reminder schedules behind them.
type CertificationStore interface {
	// CreateCampaign inserts a certification campaign, populating ID/CreatedAt.
	CreateCampaign(ctx context.Context, c *Campaign) error
	// ListCampaigns returns all campaigns, newest first.
	ListCampaigns(ctx context.Context) ([]Campaign, error)
	// GetCampaign returns a campaign by ID, or ErrNotFound.
	GetCampaign(ctx context.Context, id int64) (*Campaign, error)
	// CloseCampaign marks a campaign closed at the given time, or ErrNotFound.
	// Closing a recurring anchor also ends the series, because ListDueCampaigns
	// only considers open ones.
	CloseCampaign(ctx context.Context, id int64, at time.Time) error
	// ListCampaignsToRemind returns the OPEN campaigns whose next reminder has
	// come due, oldest first. Closed is not a reminder: the review is over.
	ListCampaignsToRemind(ctx context.Context, now time.Time) ([]Campaign, error)
	// SetCampaignRemindAt schedules (or, with nil, cancels) a campaign's next
	// reminder. ErrNotFound if the campaign is absent.
	SetCampaignRemindAt(ctx context.Context, id int64, at *time.Time) error
	// ListDueCampaigns returns the OPEN recurring anchors whose next run has
	// arrived, oldest first. Scoped deliberately narrowly: a closed anchor is a
	// stopped series, and a campaign with no recurrence is not a schedule.
	ListDueCampaigns(ctx context.Context, now time.Time) ([]Campaign, error)
	// SetCampaignNextRun moves an anchor's next occurrence. ErrNotFound if the
	// campaign is absent. Called after a spawn, so a failure to advance repeats
	// the spawn on the next tick rather than skipping one — duplicating a review
	// is recoverable, silently missing a quarter's recertification is not.
	SetCampaignNextRun(ctx context.Context, id int64, next time.Time) error
	// AddCampaignItem adds one access item to a campaign (ErrNotFound if absent).
	AddCampaignItem(ctx context.Context, item *CampaignItem) error
	// ListCampaignItems returns a campaign's items ordered by id.
	ListCampaignItems(ctx context.Context, campaignID int64) ([]CampaignItem, error)
	// SetCampaignItemReviewer reassigns one item, or ErrNotFound. An empty
	// reviewer unassigns it.
	SetCampaignItemReviewer(ctx context.Context, itemID int64, reviewer string) error
	// ListItemsForReviewer returns the PENDING items assigned to reviewer across
	// every OPEN campaign, oldest first — a reviewer's queue. A campaign that is
	// closed is not work; an item already decided is not work.
	ListItemsForReviewer(ctx context.Context, reviewer string) ([]CampaignItem, error)
	// GetCampaignItem returns one item by ID, or ErrNotFound.
	GetCampaignItem(ctx context.Context, id int64) (*CampaignItem, error)
	// DecideCampaignItem records a certify/revoke decision on an item.
	DecideCampaignItem(ctx context.Context, id int64, decision, decidedBy string, at time.Time) error
}

// ApprovalStore is the four-eyes access-request workflow and the use-time
// approval claim.
type ApprovalStore interface {
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
	// ActiveApprovals returns EVERY approval that could admit requester to
	// targetID as of now, WITHOUT consuming any of them, most-preferred first
	// (standing approvals before single-use ones, then oldest id) and capped at
	// limit. It exists so a use-time check can inspect the admitting request
	// (its ITSM ticket, Phase 60) before deciding to burn it.
	//
	// It returns the whole set rather than the single front-runner because the
	// caller must be free to move on to the next candidate (Phase 61a's sibling
	// finding, fixed in 60a): peeking at one approval and then consuming
	// "whichever the store picks" let a use be admitted on an approval whose
	// ticket was never checked, and let one approval with a cancelled ticket
	// permanently shadow a valid one behind it.
	ActiveApprovals(ctx context.Context, requester string, targetID int64, now time.Time, limit int) ([]AccessRequest, error)
	// ConsumeApproval is the use-time twin of HasActiveApproval (Phase 26): it
	// reports whether requester holds an active approval for targetID and, when
	// the only active approval is single-use (OneTime), atomically burns it by
	// stamping ConsumedAt so it cannot admit a second use. A standing
	// (non-one-time) active approval is preferred and left untouched.
	// consumedID is the burned request's ID (0 when nothing was consumed).
	// Atomic under concurrent use: one single-use approval admits exactly one
	// of two racing consumers.
	ConsumeApproval(ctx context.Context, requester string, targetID int64, now time.Time) (ok bool, consumedID int64, err error)
	// ConsumeApprovalByID claims ONE NAMED approval — the one the caller
	// inspected — rather than whichever the store would have picked. ok is false
	// when that approval is no longer active for (requester, targetID) as of
	// now, which includes a concurrent use having burned it first; that is not
	// an error, it is the caller's cue to try its next candidate. A single-use
	// approval is burned atomically, so exactly one of two racing consumers
	// wins; a standing one is confirmed and left untouched.
	//
	// The requester and targetID are re-checked here and not taken on trust:
	// an id alone must never be able to claim somebody else's approval.
	ConsumeApprovalByID(ctx context.Context, id int64, requester string, targetID int64, now time.Time) (ok bool, err error)

	// ListDueAccessRequests returns the approved recurring anchors whose next
	// run has arrived, oldest first (Phase 120) — the AccessRequest analogue
	// of ListDueCampaigns. Scoped narrowly on purpose: a denied or still-
	// pending anchor is not a live series, and a request with no recurrence
	// is not a schedule.
	ListDueAccessRequests(ctx context.Context, now time.Time) ([]AccessRequest, error)
	// SetAccessRequestNextRun moves an anchor's next occurrence, or sets it
	// for the first time on approval. ErrNotFound if the request is absent.
	SetAccessRequestNextRun(ctx context.Context, id int64, next time.Time) error
	// StopAccessRequestRecurrence ends a recurring anchor's series (RecurDays
	// -> 0, NextRunAt -> nil) — the stop button an operator reaches for first,
	// so it has to just work. Idempotent: stopping an already one-off request
	// succeeds without error. ErrNotFound if the request is absent.
	StopAccessRequestRecurrence(ctx context.Context, id int64) error
}

// CheckoutStore is exclusive, time-boxed credential leases.
type CheckoutStore interface {
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
	// GetCheckout returns one checkout by ID, or ErrNotFound (Phase 120) — the
	// by-ID twin of GetActiveCheckout (which looks up by credential instead),
	// needed so the extend handler can check the caller is the lease's own
	// holder before extending it.
	GetCheckout(ctx context.Context, id int64) (*Checkout, error)
	// ExtendCheckout pushes an active (unreturned, unexpired as of now)
	// checkout's expiry to newExpiresAt (Phase 120). ErrNotFound if the
	// checkout is missing, already returned, or already expired — an
	// extension is a continuation, not a resurrection: a lapsed lease must be
	// checked out again fresh rather than revived past its own deadline. The
	// caller (not the store) is responsible for validating newExpiresAt
	// against any configured ceiling, matching how CreateCheckout's own
	// expiry is entirely caller-computed.
	ExtendCheckout(ctx context.Context, id int64, newExpiresAt, now time.Time) error
}

// PasswordHistoryStore is a credential's rotation history — SHA-256 hashes of
// its past secrets, never the secrets themselves — checked at rotation time
// to enforce PAM_PASSWORD_HISTORY_COUNT reuse prevention (Phase 120). A bare
// SHA-256 is sufficient here (not HMAC-keyed like a bearer token hash) because
// generated passwords are high-entropy random strings, not user-chosen
// low-entropy ones — nothing a rainbow table gains purchase on.
type PasswordHistoryStore interface {
	// RecordPasswordHistory appends secretHash to credentialID's history and
	// prunes anything beyond the most recent keep entries in the same call, so
	// the table never grows unbounded relative to what reuse-prevention can
	// actually check against. Callers gate this on keep > 0 themselves — a
	// deployment with history checking off should not pay even the write.
	RecordPasswordHistory(ctx context.Context, credentialID int64, secretHash string, at time.Time, keep int) error
	// RecentPasswordHashes returns up to limit of a credential's most recent
	// rotation hashes, newest first.
	RecentPasswordHashes(ctx context.Context, credentialID int64, limit int) ([]string, error)
}

// AuditStore is the primary audit trail, its optional hash chain, and the
// reads that export or prune it.
type AuditStore interface {
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
}

// UserStore is local users and the custom permission profiles assignable to
// them.
type UserStore interface {
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
	// UpdateUserIPAllowlist sets a user's source-address restriction (Phase
	// 118, see User.IPAllowlist), or ErrNotFound. The caller (currently
	// POST/PUT /api/users) is responsible for validating it with
	// auth.ValidateCIDRList first — the store layer trusts that check rather
	// than re-enforcing it, the same division of responsibility every other
	// write-time validation in this codebase uses.
	UpdateUserIPAllowlist(ctx context.Context, id int64, allowlist string) error
	// UpdateUserDeviceFingerprint sets a user's enrolled device-certificate
	// fingerprint (Phase 133, see User.DeviceFingerprint), or ErrNotFound.
	UpdateUserDeviceFingerprint(ctx context.Context, id int64, fingerprint string) error
	// DeleteUser removes a user by ID, or ErrNotFound.
	DeleteUser(ctx context.Context, id int64) error
	// GetUserByUsername returns one user by username, or ErrNotFound — the
	// lookup SCIM's idempotent-provisioning filter (Phase 149,
	// `filter=userName eq "..."`) needs, the same attribute an IdP checks
	// before deciding whether to POST a create or treat a user as existing.
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	// GetUserByExternalID returns one user by their IdP-assigned ExternalID
	// (Phase 149), or ErrNotFound. An empty externalID always misses — the
	// column's own default, shared by every non-SCIM user, must never
	// resolve to an arbitrary one of them.
	GetUserByExternalID(ctx context.Context, externalID string) (*User, error)
	// UpdateUserActive sets a user's SCIM active flag (Phase 149, see
	// User.Active), or ErrNotFound. false blocks the user's own local
	// access token from resolving; see auth.Resolver.Resolve.
	UpdateUserActive(ctx context.Context, id int64, active bool) error
	// UpdateUserExternalID sets a user's IdP correlation key (Phase 149, see
	// User.ExternalID), or ErrNotFound. ErrConflict if another user already
	// claims the same non-empty value.
	UpdateUserExternalID(ctx context.Context, id int64, externalID string) error
	// GetUserBySlackUserID returns one user by their linked Slack member ID
	// (Phase 236, see User.SlackUserID), or ErrNotFound. An empty id always
	// misses — the column's default, shared by every unlinked user, must
	// never resolve to an arbitrary one of them.
	GetUserBySlackUserID(ctx context.Context, slackUserID string) (*User, error)
	// UpdateUserSlackUserID sets a user's linked Slack member ID (Phase 236,
	// see User.SlackUserID), or ErrNotFound. ErrConflict if another user
	// already claims the same non-empty value.
	UpdateUserSlackUserID(ctx context.Context, id int64, slackUserID string) error

	// CreateProfile inserts a custom permission profile; ErrConflict on a
	// duplicate name.
	CreateProfile(ctx context.Context, p *Profile) error
	// GetProfile returns the profile with the given name, or ErrNotFound.
	GetProfile(ctx context.Context, name string) (*Profile, error)
	// ListProfiles returns all custom profiles.
	ListProfiles(ctx context.Context) ([]Profile, error)
	// DeleteProfile removes a profile by ID, or ErrNotFound.
	DeleteProfile(ctx context.Context, id int64) error
}

// LoginSessionStore is portal login sessions and the OIDC handshake state
// shared across replicas.
type LoginSessionStore interface {
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

	// OIDC login PKCE/nonce state, shared across replicas so the auth-code
	// callback can land on any instance (HA).
	PutOIDCState(ctx context.Context, state, verifier, nonce string, expiresAt time.Time) error
	// TakeOIDCState atomically fetches and deletes an unexpired state; ok is false
	// if it is missing or expired.
	TakeOIDCState(ctx context.Context, state string, now time.Time) (verifier, nonce string, ok bool, err error)
}

// MFAStore is TOTP enrollment, its replay guard, and recovery codes.
type MFAStore interface {
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

	// CreateWebAuthnCredential registers a new authenticator, populating ID and
	// CreatedAt.
	CreateWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error
	// ListWebAuthnCredentials returns every authenticator a user has registered,
	// oldest first.
	ListWebAuthnCredentials(ctx context.Context, username string) ([]WebAuthnCredential, error)
	// GetWebAuthnCredentialByCredentialID looks up an authenticator by the
	// credential ID an assertion presents, or ErrNotFound.
	GetWebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error)
	// UpdateWebAuthnSignCount writes back the sign counter and clone-warning flag
	// after a successful login, and stamps LastUsedAt — the three fields the
	// WebAuthn ceremony requires be persisted on every use, not just at
	// registration.
	UpdateWebAuthnSignCount(ctx context.Context, id int64, signCount uint32, cloneWarning bool, usedAt time.Time) error
	// DeleteWebAuthnCredential removes one authenticator by ID, scoped to
	// username so a user cannot delete another's, or ErrNotFound.
	DeleteWebAuthnCredential(ctx context.Context, id int64, username string) error

	// PutWebAuthnChallenge stores (or replaces) the in-flight ceremony state for
	// a (username, purpose) pair — purpose is "register" or "login" — so a
	// second Begin call simply supersedes an abandoned first one, the same
	// overwrite-on-conflict shape PutOIDCState uses.
	PutWebAuthnChallenge(ctx context.Context, username, purpose string, sessionData []byte, expiresAt time.Time) error
	// TakeWebAuthnChallenge atomically fetches and deletes an unexpired
	// challenge; ok is false if it is missing or expired. Single-use: a Finish
	// call consumes the state a Begin call produced, so it cannot be replayed.
	TakeWebAuthnChallenge(ctx context.Context, username, purpose string, now time.Time) (sessionData []byte, ok bool, err error)
}

// BrokerStore is the AI-agent broker: agent identities, single-use resume
// tokens, and the broker's own hash-chained audit.
type BrokerStore interface {
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
	// SetAgentKeyDisabled suspends (true) or restores (false) an agent key,
	// or ErrNotFound. Idempotent: setting the value it already has succeeds.
	// Suspension is the reversible alternative to DeleteAgentKey — the row
	// survives, so the agent can be brought back and its identity still
	// resolves for anything reading the audit trail.
	SetAgentKeyDisabled(ctx context.Context, id int64, disabled bool) error
	// TouchAgentKey records when the key last authenticated, or ErrNotFound.
	// Called on every successful agent authentication, which is what makes a
	// dormant-agent report possible at all.
	TouchAgentKey(ctx context.Context, id int64, at time.Time) error
	// ListAgentKeysByOwner returns the agent keys belonging to one owner
	// (the accountable human/service), ordered by ID; an empty slice, never
	// nil, when that owner has none. Owner match is exact.
	ListAgentKeysByOwner(ctx context.Context, owner string) ([]AgentKey, error)
	// SetAgentKeyBudget sets (or clears, with nil) an agent key's daily call
	// budget, or ErrNotFound for an unknown id. Idempotent: writing the value
	// the key already holds succeeds.
	//
	// Passing nil clears the per-agent setting so the server-wide default
	// applies again; passing a pointer to 0 is the opposite — an explicit
	// "this agent may make no calls at all". See AgentKey.BudgetPerDay: the
	// two must never be conflated, which is why this takes *int and not an
	// int plus a "clear" flag.
	SetAgentKeyBudget(ctx context.Context, id int64, budgetPerDay *int) error

	// CountAgentToolCallsSince counts the brokered tool calls the named agent
	// has actually SPENT since `since` (inclusive), reading the primary audit
	// trail — the same record an auditor would count by hand, so the budget
	// and the audit report can never disagree.
	//
	// Exactly two actions count, and no others:
	//
	//   broker.tool_call.executed — a call that did privileged work
	//     immediately.
	//   broker.tool_call.resumed  — the agent collecting the result of a call
	//     a human approved. This is the OTHER way work gets done: the call was
	//     parked for approval rather than run on the spot, and if it were not
	//     counted, routing every call through the approval path would make an
	//     agent's whole day of work free.
	//
	// Denied and failed calls are deliberately NOT counted. A budget answers
	// "how much was this agent allowed to DO", and letting refusals consume it
	// would mean a misconfigured agent burns its own quota on rejections and
	// then a legitimate call is refused for the wrong reason — the budget
	// would report exhaustion where the real fault is configuration. Bounding
	// refusal storms is the per-minute rate limit's job, not the budget's.
	//
	// The actor must match `agent` exactly (agent names are case-sensitive
	// throughout this store) and the two action names are matched literally,
	// never as a `broker.tool_call.%` prefix: a prefix match would silently
	// start charging the budget for any future broker.tool_call.* action
	// somebody adds, including outcomes that did no work.
	CountAgentToolCallsSince(ctx context.Context, agent string, since time.Time) (int, error)
	// CountAgentCallsForTokenSince counts the brokered tool calls made while
	// presenting ONE token, identified by the `jti` its issuer stamped into it.
	//
	// It counts the same two actions CountAgentToolCallsSince does, for the same
	// reasons, and reads the same trail — the difference is only what it groups
	// by. That sentence was untrue when first written: the resume handlers did
	// not write `svid_jti:`, so a `resumed` row could never match and
	// approval-path work was free. Both handlers now write the field through
	// api.resumeDetail, and TestTokenCeilingCountsResumedWork pins it. The daily budget asks "how much has this AGENT done today"; this asks
	// "how much has been done with this one CREDENTIAL", which is the question a
	// runaway or stolen token raises.
	//
	// It is keyed on `jti` rather than on the caller's declared `session:` run id
	// deliberately, and that is the whole point of the method: `session:` is
	// chosen by the party being limited, so a ceiling built on it is escaped by
	// sending a different string. A `jti` is chosen by the ISSUER — PAMv1 itself
	// for a delegated token — so the agent cannot mint itself a fresh allowance
	// without going back through the exchange, which is audited, depth-capped
	// and `may_act`-gated.
	//
	// The actor is matched as well as the token, so one agent cannot spend
	// another's ceiling by quoting its jti: both must agree.
	//
	// An empty jti counts nothing and returns 0 — a static agent key carries no
	// token id, and answering "unlimited" for it is correct rather than a
	// fallback: its ceiling is the per-day budget on its own key row.
	CountAgentCallsForTokenSince(ctx context.Context, agent, jti string, since time.Time) (int, error)
	// ReserveAgentCall atomically records one call about to be made by agent —
	// and, when jti is non-empty, under that token — provided both limits hold
	// at the instant of recording; see AgentCallReservation for why (Phase 219).
	//
	// The reservations counted are those stamped at or after `since` (the
	// rolling window the caller computed, the same one the audit-trail counts
	// use); older rows for this agent are purged first, so the ledger never
	// grows past one window per agent. agentLimit < 0 means no daily budget
	// applies; 0 is a hard stop and refuses. tokenLimit <= 0, or an empty jti,
	// means no ceiling applies to the token. The budget is checked before the
	// ceiling, matching the gate: an agent out of budget for the day is told
	// that rather than told about one of its tokens.
	//
	// A refusal writes nothing and returns Refused set with ID zero; it is not
	// an error. Two reservations for the same agent can never both read the
	// count the other is about to change: pgstore holds a per-agent
	// transaction-level advisory lock across the purge, the counts and the
	// insert; memstore holds its one lock.
	ReserveAgentCall(ctx context.Context, agent, jti string, at, since time.Time, agentLimit, tokenLimit int) (AgentCallReservation, error)
	// ReleaseAgentCallReservation deletes a reservation whose call did no work
	// (refused by policy, failed, withdrawn, denied by the approver, or expired
	// unapproved), so it stops counting. ErrNotFound if unknown — including a
	// second release of the same id and one already purged by age.
	ReleaseAgentCallReservation(ctx context.Context, id int64) error
	// QuarantineAgent stops one agent by subject, populating ID and CreatedAt;
	// ErrConflict if that subject is already quarantined (quarantine is a
	// set-membership fact, so re-adding is a caller error, not a no-op).
	QuarantineAgent(ctx context.Context, q *AgentQuarantine) error
	// IsAgentQuarantined reports whether the subject is currently quarantined
	// — the check every agent authentication path makes, static key or SVID.
	IsAgentQuarantined(ctx context.Context, subject string) (bool, error)
	// ListAgentQuarantine returns every quarantine entry ordered by ID; an
	// empty slice, never nil, when nothing is quarantined.
	ListAgentQuarantine(ctx context.Context) ([]AgentQuarantine, error)
	// ReleaseAgentQuarantine lifts one quarantine by ID, or ErrNotFound.
	ReleaseAgentQuarantine(ctx context.Context, id int64) error
	// CreateAgentIdentity records the accountable owner of a SPIFFE-attested
	// agent, populating ID and CreatedAt; ErrConflict if that SPIFFE ID is
	// already registered (one identity has one owner — a second row would make
	// "who is accountable" ambiguous at the exact moment it must not be).
	CreateAgentIdentity(ctx context.Context, a *AgentIdentity) error
	// GetAgentIdentity returns the registration for one SPIFFE ID, or
	// ErrNotFound. The four-eyes gate reads it on every approval decision.
	GetAgentIdentity(ctx context.Context, spiffeID string) (*AgentIdentity, error)
	// ListAgentIdentities returns every registration ordered by ID; an empty
	// slice, never nil.
	ListAgentIdentities(ctx context.Context) ([]AgentIdentity, error)
	// ListAgentIdentitiesByOwner returns the registrations one human is
	// accountable for — the offboarding cascade's query, mirroring
	// ListAgentKeysByOwner for the identity kind that has no key row.
	ListAgentIdentitiesByOwner(ctx context.Context, owner string) ([]AgentIdentity, error)
	// EnrollAgentIdentity claims an identity PAMv1 discovered for itself: it sets
	// the owner and note and marks the row enrolled. It is the "adopt what you
	// saw" half of the inventory — a first sighting creates an unowned row, and
	// enrolling it is how a human takes responsibility for it without losing
	// when it was first seen. ErrNotFound if the row is gone.
	EnrollAgentIdentity(ctx context.Context, id int64, owner, note string) error
	// SetAgentIdentityOwner reassigns one registration's owner, or ErrNotFound.
	// Ownership outlives people: reassigning must not require deleting the row
	// and losing when it was first recorded and by whom.
	SetAgentIdentityOwner(ctx context.Context, id int64, owner string) error
	// DeleteAgentIdentity removes one registration by ID, or ErrNotFound.
	DeleteAgentIdentity(ctx context.Context, id int64) error
	// SeeAgentIdentity records that a SPIFFE identity authenticated, creating an
	// UNENROLLED row (no owner) the first time one does and stamping last-seen
	// every time after. It reports whether the row was created, so the caller
	// can audit a first sighting — a workload nobody enrolled calling for the
	// first time is a thing an operator should be told about once, not on every
	// call. Idempotent and safe to call concurrently: the upsert is keyed on the
	// SPIFFE ID's unique index.
	SeeAgentIdentity(ctx context.Context, spiffeID string, seen time.Time) (created bool, err error)

	// CreateBrokerToken stores a single-use resume token (its JTI is the token's
	// SHA-256 hash) for a parked, approval-pending tool call.
	CreateBrokerToken(ctx context.Context, t *BrokerToken) error
	// ConsumeBrokerToken atomically spends the token identified by jti when
	// presented by subject, returning the bound call id. It succeeds at most
	// once: a used, expired, or unknown jti yields ErrNotFound, so a replayed
	// token can never collect a result twice — and so does a jti bound to a
	// DIFFERENT subject (Phase 222), so a token that leaked to another agent is
	// worth nothing to it and tells it nothing. A row whose Subject is empty
	// predates the binding and spends for any presenter until it expires.
	ConsumeBrokerToken(ctx context.Context, jti, subject string) (callID string, err error)
	// PeekBrokerToken returns the call id a token is bound to WITHOUT spending it
	// (ErrNotFound if used/expired/unknown — or bound to another subject, the
	// same refusal Consume makes, so a stranger cannot learn a call id it could
	// never collect), so a resume can avoid burning the token before the parked
	// call is ready to collect.
	PeekBrokerToken(ctx context.Context, jti, subject string) (callID string, err error)
	// DeleteExpiredBrokerTokens removes spent or expired tokens, returning the
	// count deleted; a periodic sweep keeps the table bounded.
	DeleteExpiredBrokerTokens(ctx context.Context) (int64, error)
	BrokerAuditStore
}

// BrokerAuditStore is the agent broker's own hash-chained audit — a separate
// chain from the primary trail, with its own head and verification. Split out
// because auditchain.Chain needs exactly these three methods and nothing else;
// it used to take the whole 149-method Store to reach them.
type BrokerAuditStore interface {
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
}

// AppSecretStore is the application-secrets API: app identities and the
// grants that let one fetch a credential.
type AppSecretStore interface {
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
	// SetAppGrantAlias sets (or, with an empty alias, clears) a grant's stable
	// name. ErrConflict if the app already uses that alias for another grant,
	// ErrNotFound if the grant does not exist.
	SetAppGrantAlias(ctx context.Context, grantID int64, alias string) error
	// AppCredentialByAlias resolves one of app appID's own grants by alias to the
	// credential id it names. It is scoped to the app on purpose: resolution and
	// authorization are the same lookup, so an alias can never name a credential
	// this app was not granted. ErrNotFound when the app has no such alias.
	AppCredentialByAlias(ctx context.Context, appID int64, alias string) (int64, error)
}

// ScimStore is the SCIM 2.0 provisioning API's client-key registry (Phase
// 149) — the IdP-facing counterpart to UserStore's own CRUD, which the SCIM
// handlers call directly for the user roster itself (no separate SCIM-side
// user table).
type ScimStore interface {
	// CreateScimKey inserts a SCIM client identity key, populating ID and
	// CreatedAt (ErrConflict on a duplicate token hash).
	CreateScimKey(ctx context.Context, k *ScimKey) error
	// GetScimKeyByTokenHash returns the enabled SCIM key whose token hash
	// matches, or ErrNotFound (a disabled key is treated as not found).
	GetScimKeyByTokenHash(ctx context.Context, tokenHashHex string) (*ScimKey, error)
	// ListScimKeys returns all SCIM client keys.
	ListScimKeys(ctx context.Context) ([]ScimKey, error)
	// DeleteScimKey removes a SCIM key by ID, or ErrNotFound.
	DeleteScimKey(ctx context.Context, id int64) error
}

// EndpointAgentStore is the registry of outbound-only endpoint agents (Phase
// 153). Live connectivity (which agents are connected right now) is NOT here —
// it is in-process state in session.EndpointAgents; this is the durable half:
// identity, key hash, target binding, revocation and last-seen.
type EndpointAgentStore interface {
	// CreateEndpointAgent inserts an agent, populating ID and CreatedAt.
	// ErrConflict if the key hash is taken or the target already has an
	// unrevoked agent (one agent per target); ErrNotFound if the target does
	// not exist.
	CreateEndpointAgent(ctx context.Context, a *EndpointAgent) error
	// GetEndpointAgentByKeyHash returns the agent whose key hash matches,
	// revoked or not (the caller checks Active so a revoked key's attempt can
	// be audited as such), or ErrNotFound.
	GetEndpointAgentByKeyHash(ctx context.Context, keyHashHex string) (*EndpointAgent, error)
	// GetEndpointAgentForTarget returns the target's unrevoked agent, or
	// ErrNotFound when the target is dialed directly.
	GetEndpointAgentForTarget(ctx context.Context, targetID int64) (*EndpointAgent, error)
	// ListEndpointAgents returns every agent (revoked included) ordered by ID.
	ListEndpointAgents(ctx context.Context) ([]EndpointAgent, error)
	// RevokeEndpointAgent stamps RevokedAt (idempotent), or ErrNotFound.
	RevokeEndpointAgent(ctx context.Context, id int64, at time.Time) error
	// TouchEndpointAgent records when the agent last connected, or ErrNotFound.
	TouchEndpointAgent(ctx context.Context, id int64, at time.Time) error
}

// VendorStore is the third-party vendor access gate.
type VendorStore interface {
	// Third-party vendor access gate (Phase 29).
	// CreateVendor registers a vendor (ErrConflict on a duplicate username).
	CreateVendor(ctx context.Context, v *Vendor) error
	// GetVendorByUsername returns the vendor for a login, or ErrNotFound.
	GetVendorByUsername(ctx context.Context, username string) (*Vendor, error)
	// ListVendors returns vendors in the (limit, afterID) window, id-ascending.
	ListVendors(ctx context.Context, limit int, afterID int64) ([]Vendor, error)
	// UpdateVendorOrg changes a vendor's organization label, or ErrNotFound. The
	// username is immutable (it links the vendor to its users row); disabling is
	// OffboardVendor, never an edit.
	UpdateVendorOrg(ctx context.Context, id int64, org string) error
	// UpdateVendorEmail sets the vendor's on-file contact address (Phase 116),
	// or ErrNotFound. Empty clears it.
	UpdateVendorEmail(ctx context.Context, id int64, email string) error
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
}

// ShareInviteStore is the request/approve/redeem lifecycle for session-sharing
// invites (Phase 116). See SessionShareInvite's doc comment for the shape.
type ShareInviteStore interface {
	// CreateSessionShareInvite records a pending request, populating
	// ID/CreatedAt. Nothing is redeemable yet — TokenHash/ExpiresAt are set
	// only by DecideSessionShareInvite on approval.
	CreateSessionShareInvite(ctx context.Context, inv *SessionShareInvite) error
	// GetSessionShareInvite returns one invite by id, or ErrNotFound.
	GetSessionShareInvite(ctx context.Context, id int64) (*SessionShareInvite, error)
	// ListSessionShareInvites lists a session's invites (requested, active and
	// ended), newest first (created_at then id, both descending) — backs the
	// console roster and the outstanding-invite screen.
	ListSessionShareInvites(ctx context.Context, sessionID string) ([]SessionShareInvite, error)
	// DecideSessionShareInvite records an approver's decision. Approving stamps
	// tokenHash and expiresAt (the redemption window starts NOW, not at the
	// original request time) and moves Status to "approved"; denying leaves
	// them empty — whatever the caller passed — and moves Status to "denied",
	// so a denial can never be redeemed by a hash minted before the decision.
	// ErrNotFound if unknown. Matching
	// DecideAccessRequest's own convention, the caller — not this method — is
	// responsible for checking the invite is still pending and that approver
	// differs from Requester before calling this.
	DecideSessionShareInvite(ctx context.Context, id int64, status, approver string, at time.Time, tokenHash string, expiresAt *time.Time) error
	// RevokeSessionShareInvite marks an approved-but-not-yet-consumed invite
	// revoked, so a later redemption attempt fails even though the token and
	// TTL would otherwise still be valid. ErrNotFound if unknown.
	RevokeSessionShareInvite(ctx context.Context, id int64, at time.Time) error
	// ConsumeSessionShareInviteByTokenHash atomically finds the invite matching
	// tokenHash and, only if it is approved, unexpired (ExpiresAt > now),
	// unrevoked and not already consumed, stamps ConsumedAt and returns it —
	// single-use redemption. ErrNotFound covers every refusal reason (unknown
	// hash, expired, revoked, already consumed): the caller does not get to
	// distinguish "expired" from "wrong token" from the store layer, the same
	// fail-closed shape TakeOIDCState/TakeWebAuthnChallenge use elsewhere.
	ConsumeSessionShareInviteByTokenHash(ctx context.Context, tokenHash string, now time.Time) (*SessionShareInvite, error)
}

// ApprovalInviteStore is the create/preview/redeem lifecycle for magic-link
// access-request approval (Phase 137). See ApprovalInvite's doc comment for
// the shape.
type ApprovalInviteStore interface {
	// CreateApprovalInvite records a new invite, populating ID/CreatedAt. The
	// caller has already generated and hashed the token and computed
	// ExpiresAt — unlike SessionShareInvite, there is no separate approval
	// stage for the invite itself: minting one already requires CapApprove,
	// so the invite IS the delegation. ErrNotFound if the access request does
	// not exist and ErrConflict on a duplicate token hash — the two
	// constraints the schema enforces, which the demo store must too (Phase 217).
	CreateApprovalInvite(ctx context.Context, inv *ApprovalInvite) error
	// GetApprovalInvite returns one invite by id, or ErrNotFound.
	GetApprovalInvite(ctx context.Context, id int64) (*ApprovalInvite, error)
	// ListApprovalInvitesForRequest lists an access request's invites
	// (outstanding, consumed and revoked), newest first — created_at then id,
	// both descending, the tie-break both backends share so two invites
	// minted in one instant list identically everywhere.
	ListApprovalInvitesForRequest(ctx context.Context, accessRequestID int64) ([]ApprovalInvite, error)
	// RevokeApprovalInvite marks a not-yet-consumed invite revoked, so a later
	// redemption attempt fails even though the token and TTL would otherwise
	// still be valid. ErrNotFound if unknown.
	RevokeApprovalInvite(ctx context.Context, id int64, at time.Time) error
	// GetApprovalInviteByTokenHash is a READ-ONLY lookup for the redemption
	// page's preview step (show the request's target/requester/reason before
	// asking for a decision) — it does NOT consume the invite, so it is safe
	// to call from a bare page load an email link-scanner might trigger.
	// Refuses (ErrNotFound) an expired, revoked or already-consumed invite,
	// the same as the consuming lookup below, so a preview never leaks a
	// dead invite's request details either.
	GetApprovalInviteByTokenHash(ctx context.Context, tokenHash string) (*ApprovalInvite, error)
	// ConsumeApprovalInviteByTokenHash atomically finds the invite matching
	// tokenHash and, only if it is unexpired (ExpiresAt > now), unrevoked and
	// not already consumed, stamps ConsumedAt and returns it — single-use
	// redemption. ErrNotFound covers every refusal reason, the same
	// fail-closed shape ConsumeSessionShareInviteByTokenHash uses.
	ConsumeApprovalInviteByTokenHash(ctx context.Context, tokenHash string, now time.Time) (*ApprovalInvite, error)
	// RecordApprovalInviteDecision stamps the outcome (approved | denied) on
	// an already-consumed invite, purely for the creator's own visibility —
	// it does not itself decide the underlying AccessRequest (the caller does
	// that separately, via the same decideAccessRequest every authenticated
	// approve/deny call already goes through). ErrNotFound if unknown.
	RecordApprovalInviteDecision(ctx context.Context, id int64, decision string) error
}

// SSHCertStore is operator-issued SSH certificates and their revocation list.
type SSHCertStore interface {
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
}

// KeyMaterialStore is shared custody of long-lived keys (the SSH host key,
// the ZSP CA, the broker and bus keys), each held KEK-sealed.
type KeyMaterialStore interface {
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
}

// SettingStore is the runtime configuration overrides.
type SettingStore interface {
	// PutSetting upserts a configuration override, stamping UpdatedAt.
	PutSetting(ctx context.Context, s *Setting) error
	// GetSetting returns the override for key, or ErrNotFound.
	GetSetting(ctx context.Context, key string) (*Setting, error)
	// ListSettings returns all configuration overrides.
	ListSettings(ctx context.Context) ([]Setting, error)
	// DeleteSetting removes the override for key, or ErrNotFound.
	DeleteSetting(ctx context.Context, key string) error
}

// SessionBusStore is the cross-replica session surface: the kill broadcast,
// the live-monitoring relay and the step-up decision bus.
type SessionBusStore interface {
	// PublishSessionKill broadcasts a live-session kill to every replica so the
	// kill-switch works in HA (Postgres LISTEN/NOTIFY; an in-process hub for the
	// memory store). SubscribeSessionKills returns a stream of kills published by
	// any replica, delivered until ctx is cancelled — the local session registry
	// applies each to the sessions it hosts.
	PublishSessionKill(ctx context.Context, sel session.KillSelector) error
	SubscribeSessionKills(ctx context.Context) (<-chan session.KillSelector, error)

	// session.LiveStore is the cross-replica live-monitoring surface (Phase 55):
	// the frame + interest bus that fans a watched session's output to the
	// replica whose supervisor is watching it, and the shared live-session
	// inventory behind cluster-wide GET /api/sessions. pgstore rides
	// LISTEN/NOTIFY plus an UNLOGGED table; memstore fans out in-process, so
	// the demo and tests drive the same session.Cluster code the HA path does.
	session.LiveStore

	// session.StepUpStore is the cross-replica step-up surface (Phase 56): the
	// shared pending-pause inventory behind cluster-wide GET
	// /api/sessions/stepups (statements sealed under the cluster bus key —
	// this store carries them opaque), and the sealed-decision bus that lets a
	// supervisor on any replica release or refuse a statement paused on
	// another. pgstore rides an UNLOGGED table plus LISTEN/NOTIFY; memstore is
	// in-process, so the demo and tests drive the same session.StepUp code the
	// HA path does.
	session.StepUpStore
}

// SystemStore is the backend itself — reachability, leader election and
// shutdown.
type SystemStore interface {
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

// Store is the whole persistence surface: every role above, in one interface,
// so existing callers and both implementations are untouched.
type Store interface {
	TargetStore
	CredentialStore
	GrantStore
	CertificationStore
	ApprovalStore
	CheckoutStore
	PasswordHistoryStore
	AuditStore
	UserStore
	LoginSessionStore
	MFAStore
	BrokerStore
	AppSecretStore
	ScimStore
	EndpointAgentStore
	VendorStore
	ShareInviteStore
	ApprovalInviteStore
	SSHCertStore
	KeyMaterialStore
	SettingStore
	SessionBusStore
	SystemStore
}
