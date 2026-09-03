// Package auth defines PAMv1's identity and role-based access control.
//
// There are four profiles (roles):
//
//	admin    — manage targets, credentials, users and configuration; reveal secrets
//	user     — connect to targets through the session proxy; read the inventory
//	auditor  — read-only access to the inventory and the audit trail
//	approver — review and approve/deny access requests; read inventory and audit
//
// A Resolver turns a presented key (the X-API-Key header or the SSH proxy
// password) into a Principal. Three key kinds are accepted, in order: the
// bootstrap admin key (PAM_API_KEY), the sealed break-glass key, and per-user
// tokens minted by an admin (stored only as a SHA-256 hash).
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

var ErrUnauthorized = errors.New("auth: unauthorized")

// Role is one of the four profiles.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleUser     Role = "user"
	RoleAuditor  Role = "auditor"
	RoleApprover Role = "approver"
	// RoleAgent is an AI agent identity: it may call brokered tools and read
	// inventory, nothing else. It is assigned by the broker's agent-auth path, not
	// via ParseRole (agents are never provisioned as human/user tokens).
	RoleAgent Role = "agent"
)

// ParseRole validates s and returns the corresponding Role, or an error if it is
// not one of the four known roles.
func ParseRole(s string) (Role, error) {
	switch Role(s) {
	case RoleAdmin, RoleUser, RoleAuditor, RoleApprover:
		return Role(s), nil
	default:
		return "", fmt.Errorf("auth: invalid role %q (want admin|user|auditor|approver)", s)
	}
}

// ParseGrantRole validates a role name usable as a target-grant subject. Unlike
// ParseRole it also accepts RoleAgent, so a target can be scoped to AI agents
// (a "role:agent" grant), without letting an agent be provisioned as a human
// user or session token.
func ParseGrantRole(s string) (Role, error) {
	if Role(s) == RoleAgent {
		return RoleAgent, nil
	}
	return ParseRole(s)
}

// Capability is a single permission checked at each protected operation.
type Capability int

const (
	CapReadInventory     Capability = iota // list targets/credentials (no secrets)
	CapManageTargets                       // create/delete targets
	CapManageCredentials                   // create/delete credentials
	CapRevealSecret                        // decrypt a secret via the API
	CapConnect                             // open a proxied session to a target
	CapReadAudit                           // read the audit trail
	CapManageUsers                         // create/delete users
	CapApprove                             // review and approve/deny access requests
	CapCallTool                            // invoke a brokered tool call (AI agents)
	// CapUnlimitedVaultAccess (Phase 139) is the named override that lets a
	// principal reach a target placed in a Personal safe despite not being one
	// of its members. Deliberately NOT in roleCaps[RoleAdmin] — see
	// CanConnectTarget's doc comment for why a plain admin no longer bypasses
	// a personal safe by role alone, and canManageSafe for why CapManageTargets
	// alone is likewise not enough to manage one's membership.
	CapUnlimitedVaultAccess

	capCount // sentinel: keep LAST. Loops range [CapReadInventory, capCount) so a
	// new capability added above is picked up everywhere automatically.
)

// roleCaps is the authoritative role → capability matrix.
var roleCaps = map[Role]map[Capability]bool{
	RoleAdmin: {
		CapReadInventory: true, CapManageTargets: true, CapManageCredentials: true,
		CapRevealSecret: true, CapConnect: true, CapReadAudit: true, CapManageUsers: true,
		CapApprove: true,
	},
	RoleUser: {
		CapReadInventory: true, CapConnect: true,
	},
	RoleAuditor: {
		CapReadInventory: true, CapReadAudit: true,
	},
	RoleApprover: {
		CapReadInventory: true, CapReadAudit: true, CapApprove: true,
	},
	RoleAgent: {
		CapReadInventory: true, CapCallTool: true,
	},
}

// Can reports whether the role is granted the capability.
func (r Role) Can(c Capability) bool {
	return roleCaps[r][c]
}

// CapabilitySet returns the concrete capability set a built-in role confers.
func (r Role) CapabilitySet() CapSet {
	out := make(CapSet)
	for c := CapReadInventory; c < capCount; c++ {
		if r.Can(c) {
			out[c] = true
		}
	}
	return out
}

// capNames maps each capability to a stable snake_case name. The portal keys its
// role-aware menu off these, so they are part of the /api/me contract — do not
// rename without updating the portal.
var capNames = map[Capability]string{
	CapReadInventory:        "read_inventory",
	CapManageTargets:        "manage_targets",
	CapManageCredentials:    "manage_credentials",
	CapRevealSecret:         "reveal_secret",
	CapConnect:              "connect",
	CapReadAudit:            "read_audit",
	CapManageUsers:          "manage_users",
	CapApprove:              "approve",
	CapCallTool:             "call_tool",
	CapUnlimitedVaultAccess: "unlimited_vault_access",
}

// String returns the capability's stable snake_case name.
func (c Capability) String() string {
	if s, ok := capNames[c]; ok {
		return s
	}
	return "unknown"
}

// Capabilities returns the stable names of every capability the role is granted,
// in capability-enum order.
func (r Role) Capabilities() []string {
	out := make([]string, 0, len(capNames))
	for c := CapReadInventory; c < capCount; c++ {
		if r.Can(c) {
			out = append(out, c.String())
		}
	}
	return out
}

// CanConnectTarget reports whether the principal may connect to a target given
// its effective grants (direct grants ∪ safe members), whether the target is
// placed in a safe, whether that safe is Personal (Phase 139), and what the
// deployment means by a target with no grants at all (Phase 203). When no
// grant matches, an *ungated* target (safeScoped=false) is open to any
// connect-capable principal under UngatedOpen and reachable by nobody under
// UngatedDeny, while a *safe-scoped* target (safeScoped=true) is
// default-DENY — placing a target in a safe restricts it to that safe's
// members, so an empty/unmatched grant set must not fall through to "open".
// Otherwise a grant must match the user or role.
//
// Admins may always connect — UNLESS the target sits in a Personal safe, in
// which case the unconditional role-based bypass is replaced by a check for
// CapUnlimitedVaultAccess, a narrow capability no built-in role carries by
// default (only a custom profile that explicitly lists it does). This is the
// one place personal-folder privacy actually lives: without it, "personal"
// would mean nothing, since every admin bypassed every safe already. An admin
// who lacks the capability still falls through to ordinary grant matching, so
// the safe's own owner (a member by construction — see createSafe) connects
// normally regardless of role; only a *different* admin without the override
// is turned away. For an ordinary (non-personal) target this function's
// behavior is byte-identical to before Phase 139.
// UngatedDefault is what a deployment means by a target with NO grants at all.
//
// It is a named type rather than another bool because CanConnectTarget already
// takes two, and a transposed argument here would silently invert an
// authorization decision.
type UngatedDefault int

const (
	// UngatedOpen: a target nobody has restricted is reachable by any
	// connect-capable principal. This is what PAMv1 has always done, and it stays
	// the default so an upgrade changes nothing — but it is an estate-wide
	// default rather than a decision anyone made about a particular system, which
	// is why the reachability review renders those targets in red.
	UngatedOpen UngatedDefault = iota
	// UngatedDeny: a target with no grants is reachable by nobody until somebody
	// grants it. Set PAM_REQUIRE_TARGET_GRANT=true to choose this. Admins still
	// bypass (that is an explicit decision about a role), and a safe-scoped target
	// was already default-deny — this closes the remaining hole, which is the
	// target nobody ever got round to restricting.
	UngatedDeny
)

func CanConnectTarget(p *Principal, grants []store.TargetGrant, safeScoped, personal bool, ungated UngatedDefault) bool {
	return CanConnectTargetAt(p, grants, safeScoped, personal, ungated, time.Now())
}

// CanConnectTargetAt is CanConnectTarget evaluated at a given instant (Phase
// 240): a grant that has expired or is outside its time frame at now does
// not match — but it still COUNTS as a grant, so a target whose last grant
// expired stays gated (closed to everyone but admins) rather than falling
// open. Callers that also compute a session deadline pass the same now.
func CanConnectTargetAt(p *Principal, grants []store.TargetGrant, safeScoped, personal bool, ungated UngatedDefault, now time.Time) bool {
	if !personal {
		for _, r := range p.effectiveRoles() {
			if r == RoleAdmin {
				return true
			}
		}
	} else if p.Can(CapUnlimitedVaultAccess) {
		return true
	}
	if len(grants) == 0 {
		// Safe-scoped but no members ⇒ closed (containment), always. An UNGATED
		// target is open or closed depending on what the deployment decided.
		if safeScoped || ungated == UngatedDeny {
			return false
		}
		return true
	}
	for _, g := range grants {
		if store.GrantLive(g.ExpiresAt, g.TimeFrame, now) && SubjectMatches(p, g.SubjectType, g.Subject) {
			return true
		}
	}
	return false
}

// PersonalOverrideUsed reports whether p's access to a personal-safe target
// specifically relied on CapUnlimitedVaultAccess, so a caller that admitted
// the connection via CanConnectTarget can decide to audit it loudly (Phase
// 139) — mirroring how break-glass access is always loudly audited.
// Deliberately over-inclusive: a principal who also holds a direct grant on
// the target still reports true here if they carry the capability, since
// erring toward more visibility on a privileged bypass is the safe
// direction, not less. Always false when personal is false.
func (p *Principal) PersonalOverrideUsed(personal bool) bool {
	return personal && p.Can(CapUnlimitedVaultAccess)
}

// SubjectMatches reports whether p matches an authorization subject: a "user"
// with p's name, or a "role" that p holds (any of its effective roles). Shared
// by target grants and safe membership (Phase 17).
func SubjectMatches(p *Principal, subjectType, subject string) bool {
	switch subjectType {
	case "user":
		return subject == p.Name
	case "role":
		for _, r := range p.effectiveRoles() {
			if subject == string(r) {
				return true
			}
		}
	}
	return false
}

// MatchedRoles maps directory claims to roles via m (keys lower-cased) and
// returns the highest-privilege role (for display/audit) plus EVERY matched role
// in precedence order, so an identity in multiple mapped groups gets the union of
// their capabilities and role-grants. ok is false when nothing matches.
func MatchedRoles(claims []string, m map[string]Role) (display Role, all []Role, ok bool) {
	have := make(map[Role]bool)
	for _, c := range claims {
		if r, ok := m[strings.ToLower(c)]; ok {
			have[r] = true
		}
	}
	for _, r := range []Role{RoleAdmin, RoleApprover, RoleAuditor, RoleUser} {
		if have[r] {
			if display == "" {
				display = r
			}
			all = append(all, r)
		}
	}
	return display, all, len(all) > 0
}

// JoinRoles / SplitRoles serialize a role set for session persistence.
func JoinRoles(roles []Role) string {
	parts := make([]string, len(roles))
	for i, r := range roles {
		parts[i] = string(r)
	}
	return strings.Join(parts, ",")
}

// SplitRoles parses a comma-separated role set (empty ⇒ nil), ignoring unknowns.
func SplitRoles(s string) []Role {
	if s == "" {
		return nil
	}
	var out []Role
	for _, p := range strings.Split(s, ",") {
		if r, err := ParseGrantRole(p); err == nil {
			out = append(out, r)
		}
	}
	return out
}

// SessionScopeEnroll marks a login session that may only be used to complete
// MFA enrollment (issued when a policy requires MFA but the user has none).
const SessionScopeEnroll = "enroll"

// SessionScopeMFAPending marks a login session issued after a correct
// password but before the WebAuthn second factor has been verified. Unlike
// TOTP (which types inline, so password+otp is one request), WebAuthn is an
// unavoidable two-round-trip ceremony — this scope is what ties the two
// requests together without letting an unauthenticated caller probe for a
// username's factor type: password verification happens first, and only on
// success is this narrow token minted. It resolves to an MFAPending
// principal, refused everywhere except the WebAuthn login-ceremony routes —
// a claim that held for the API middleware and the proxies but NOT for the
// RDP/VNC viewer tunnel until the 2026-08-26 audit, which found the tunnel
// opening a live desktop on a password-only token. See Principal.NarrowScope
// for why there is now exactly one implementation of "is this token narrow".
const SessionScopeMFAPending = "mfa_pending"

// SessionScopeBreakGlass marks a short-lived emergency session issued after a
// successful M-of-N quorum unseal; it grants admin and is audited loudly.
const SessionScopeBreakGlass = "breakglass"

// SessionScopeRDP and SessionScopeVNC mark short-lived tokens minted for the
// in-portal graphical viewers. Because such a token travels in the WebSocket URL
// (browsers cannot set headers on a WS handshake), it is deliberately usable ONLY
// at a viewer tunnel: it resolves to a TunnelOnly principal that the API
// authz/authenticated middleware refuse, so a copy leaked from a proxy/access log
// cannot call any other endpoint or re-mint.
//
// Both scopes are equivalent in power — each names the viewer it was minted for so
// the audit trail says which one, and IsViewerScope is what confers TunnelOnly.
// Adding a scope without adding it there would hand out a full API token in a URL.
const (
	SessionScopeRDP = "rdp"
	SessionScopeVNC = "vnc"
)

// IsViewerScope reports whether a session scope belongs to an in-portal graphical
// viewer, and therefore must resolve to a TunnelOnly principal.
func IsViewerScope(scope string) bool {
	return scope == SessionScopeRDP || scope == SessionScopeVNC
}

// SessionScopeExtension marks a token minted for the browser-extension
// autofill client (Phase 147). It travels in the extension's own local
// storage rather than a URL, so unlike the viewer scopes above it can live
// for hours or days, not seconds — but the same "narrow purpose, broad
// refusal" shape applies: it resolves to an ExtensionOnly principal, refused
// on every route except the one the extension actually needs.
const SessionScopeExtension = "extension"

// CapSet is a resolved set of capabilities (used for custom profiles).
type CapSet map[Capability]bool

// Principal is an authenticated identity for the duration of a request or
// session.
type Principal struct {
	Name string
	Role Role // primary/highest role (display, audit, IsAdmin)
	// Roles holds every directory-matched role when an identity is in more than one
	// mapped group, so its capabilities and role-grants are the UNION of them (a
	// user+auditor member keeps `connect`). nil ⇒ just [Role]. Ignored when Caps is
	// set (a custom profile carries its own capability set).
	Roles      []Role
	Caps       CapSet // resolved custom-profile capabilities; nil for a built-in role
	BreakGlass bool   // authenticated via the emergency key; use is audited loudly
	EnrollOnly bool   // session may only complete MFA enrollment, nothing else
	TunnelOnly bool   // token minted for the RDP tunnel only; API middleware refuses it
	MFAPending bool   // password verified, awaiting a WebAuthn second factor; nothing else
	// ExtensionOnly marks a token minted for the browser extension (Phase
	// 147): unlike TunnelOnly, it is not a blanket refusal everywhere — the
	// reveal route specifically admits it (see the api package's authzExtOK),
	// where Can(cap) still applies normally, since the token inherits the
	// minting user's own role/capabilities. Every OTHER authenticated route
	// refuses it exactly like TunnelOnly, so a token that leaked from an
	// endpoint's local storage cannot do anything but reveal. That sentence was
	// FALSE from Phase 147 until the 2026-08-26 audit: the session proxies and
	// the viewer tunnel resolve their own principal and had never been taught
	// this field, so the leaked token opened SSH, database and desktop sessions
	// for 24 hours. It is true now only because every such entry point calls
	// MayOpenSession rather than reading these fields by hand.
	ExtensionOnly bool
	// IPAllowlist restricts this principal to connecting from a source address
	// inside one of these comma-separated CIDR blocks (Phase 118), e.g.
	// "10.0.0.0/8, 192.168.1.0/24". Empty (the default) means unrestricted —
	// setting it never affects anyone who has not opted in. Sourced from
	// store.User.IPAllowlist for a local (bearer-token) identity; a
	// directory-authenticated principal (AD/LDAP/Entra/OIDC — no backing
	// store.User row) has no allowlist to source, so it is always unrestricted
	// for v1. Checked with IPAllowed at both HTTP authz and session-proxy
	// connect time; BreakGlass bypasses it, matching every other gate
	// break-glass already bypasses.
	IPAllowlist string
	// DeviceFingerprint binds this principal to one enrolled client-certificate
	// fingerprint (Phase 133). Empty (the default) means unbound — no device
	// check even when PAM_DEVICE_HEADER is set deployment-wide. Sourced from
	// store.User.DeviceFingerprint for a local (bearer-token) identity only,
	// same v1 scope as IPAllowlist above and for the same reason (a
	// directory-authenticated principal has no store.User row to source it
	// from). Checked against the configured header's value at HTTP authz time.
	DeviceFingerprint string
}

// SessionScope names the narrow purposes a session token can be minted for.
// A Principal resolved from such a token carries exactly one of them set; a
// full login session carries none.
type SessionScope int

// The narrow scopes, in the order they were introduced. ScopeNone is the
// full-session case and is what NarrowScope returns for it.
const (
	ScopeNone SessionScope = iota
	ScopeEnrollOnly
	ScopeMFAPending
	ScopeTunnelOnly
	ScopeExtensionOnly
)

// NarrowScope reports which narrow scope, if any, this principal is confined to.
//
// This exists because of the 2026-08-26 audit. Four entry points resolve a
// principal themselves rather than through the API middleware — the SSH proxy,
// both database proxies, and the RDP/VNC viewer tunnel — and each of them had
// re-implemented the "is this a narrow token?" test by hand with a different
// subset of the fields. The tunnel checked one of four; the proxies checked
// three. So a browser-extension token, which the middleware correctly refuses
// everywhere except reveal, was accepted as an SSH password and opened desktops;
// and an mfa_pending token, refused by the proxies, opened a desktop through the
// tunnel. Two authentication-scope bypasses, both caused by the same omission:
// a field was added to Principal and not to every copy of the check.
//
// There is now one copy. An entry point that resolves its own principal calls
// this and compares the result against the ONE scope it is built to serve; any
// other narrow scope is refused. Adding a scope means adding it here, and the
// compiler cannot make a caller forget a case it never enumerated.
func (p *Principal) NarrowScope() SessionScope {
	switch {
	case p.EnrollOnly:
		return ScopeEnrollOnly
	case p.MFAPending:
		return ScopeMFAPending
	case p.TunnelOnly:
		return ScopeTunnelOnly
	case p.ExtensionOnly:
		return ScopeExtensionOnly
	}
	return ScopeNone
}

// MayOpenSession reports whether this principal's scope permits opening a
// brokered session or a viewer desktop — the thing every narrow scope exists to
// PREVENT. `serving` names the one narrow scope the calling entry point is
// legitimately for (the viewer tunnel passes ScopeTunnelOnly, since a tunnel
// token is the credential it was built to accept); the proxies pass ScopeNone.
//
// The rule is deliberately a whitelist of two: a full session, or exactly the
// scope this door is for. Every other narrow scope is refused, including ones
// added after this comment was written.
func (p *Principal) MayOpenSession(serving SessionScope) bool {
	sc := p.NarrowScope()
	return sc == ScopeNone || (serving != ScopeNone && sc == serving)
}

// effectiveRoles returns the role set to evaluate capabilities and role-grants
// against: the multi-group set when present, otherwise just the primary role.
func (p *Principal) effectiveRoles() []Role {
	if len(p.Roles) > 0 {
		return p.Roles
	}
	return []Role{p.Role}
}

// Can reports whether the principal holds capability c. A custom profile carries
// its own Caps; a built-in role falls back to the role→capability matrix, so
// existing role behavior is unchanged.
func (p *Principal) Can(c Capability) bool {
	if p.Caps != nil {
		return p.Caps[c]
	}
	for _, r := range p.effectiveRoles() {
		if r.Can(c) {
			return true
		}
	}
	return false
}

// IPAllowed reports whether ip satisfies allowlist — a comma-separated list of
// CIDR blocks (Phase 118). An empty (or all-whitespace) allowlist means
// unrestricted: true. An ip that fails to parse can never satisfy a
// non-empty restriction (fail-closed) rather than erroring the caller — the
// gates that call this always have a concrete remote address string, so a
// parse failure here means malformed input, not "no restriction configured".
// A malformed CIDR entry is skipped rather than aborting the whole check, so
// one bad entry degrades to "that one entry never matches" instead of
// silently disabling every other entry in the list — ValidateCIDRList is
// what keeps a malformed entry from being stored in the first place.
func IPAllowed(allowlist, ip string) bool {
	entries := splitCIDRList(allowlist)
	if len(entries) == 0 {
		return true
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	for _, entry := range entries {
		if _, network, err := net.ParseCIDR(entry); err == nil && network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// ValidateCIDRList reports an error naming the first malformed entry in a
// comma-separated CIDR list, or nil if every entry (there may be zero) parses
// — the write-time guard that keeps IPAllowed's per-entry skip-on-parse-error
// from ever masking an operator's typo. Called wherever a caller may set a
// principal's allowlist (currently POST/PUT /api/users).
func ValidateCIDRList(s string) error {
	for _, entry := range splitCIDRList(s) {
		if _, _, err := net.ParseCIDR(entry); err != nil {
			return fmt.Errorf("invalid CIDR block %q: %w", entry, err)
		}
	}
	return nil
}

// splitCIDRList splits a comma-separated CIDR list into trimmed, non-empty
// entries.
func splitCIDRList(s string) []string {
	var out []string
	for _, entry := range strings.Split(s, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			out = append(out, entry)
		}
	}
	return out
}

// IsAdmin reports whether the principal is a built-in administrator — the
// bootstrap key, a break-glass session, or a user with the admin role — as
// opposed to a custom profile (which always carries a non-nil Caps set). A
// built-in admin holds every capability and is unconstrained by Covers.
func (p *Principal) IsAdmin() bool {
	return p.Caps == nil && p.Role == RoleAdmin
}

// Covers reports whether the principal holds every capability in want. It backs
// the "you cannot grant more than you have" rule when minting users or profiles,
// so a delegated user-admin can never escalate past its own capabilities. A
// built-in admin is unconstrained (it holds every capability, including ones like
// call_tool that the roleCaps matrix doesn't list for humans).
func (p *Principal) Covers(want CapSet) bool {
	if p.IsAdmin() {
		return true
	}
	for c, needed := range want {
		if needed && !p.Can(c) {
			return false
		}
	}
	return true
}

// ApproverGroups returns the group tokens a broker policy rule's `approvers:` list
// is matched against for separation of duties (Phase 27): the principal's
// effective role names — a built-in role, or a directory group mapped to one.
// Deliberately NOT the principal's own username: a username lives in a namespace
// that a `manage_users` delegate can freely create, so allowing a rule to name a
// user would let that delegate mint a user with the group's name and self-approve,
// defeating the very separation SoD enforces. Groups are roles/directory groups.
func (p *Principal) ApproverGroups() []string {
	out := make([]string, 0, len(p.Roles)+1)
	for _, r := range p.effectiveRoles() {
		out = append(out, string(r))
	}
	return out
}

// CapabilityNames returns the stable names of every capability the principal
// holds — from its custom profile, or the union of its (possibly multiple)
// built-in roles — so /api/me reflects a multi-group user's full set.
func (p *Principal) CapabilityNames() []string {
	out := make([]string, 0, int(capCount))
	for c := CapReadInventory; c < capCount; c++ {
		if p.Can(c) {
			out = append(out, c.String())
		}
	}
	return out
}

// ParseCapabilities resolves stable capability names into a CapSet, erroring on
// any unknown name. An empty list yields an empty (no-capability) set.
func ParseCapabilities(names []string) (CapSet, error) {
	byName := make(map[string]Capability, len(capNames))
	for c, n := range capNames {
		byName[n] = c
	}
	caps := make(CapSet, len(names))
	for _, n := range names {
		c, ok := byName[n]
		if !ok {
			return nil, fmt.Errorf("auth: unknown capability %q", n)
		}
		caps[c] = true
	}
	return caps, nil
}

// Directory is the slice of the store the resolver needs: per-user tokens and
// login sessions, both looked up by token hash.
type Directory interface {
	GetUserByTokenHash(ctx context.Context, tokenHashHex string) (*store.User, error)
	GetSessionByTokenHash(ctx context.Context, tokenHashHex string) (*store.Session, error)
	// GetUserByUsername returns the LOCAL user row behind a username, or
	// store.ErrNotFound for an identity that has none (a directory login).
	// Resolve consults it for a session token (2026-08-27 audit) so a
	// deactivated local user's still-live sessions stop resolving the moment
	// the row says so, and so the row's IP allowlist and device binding apply
	// to those sessions exactly as they apply to the per-user token.
	GetUserByUsername(ctx context.Context, username string) (*store.User, error)
}

// ProfileSource looks up a custom permission profile by name. Optional: nil
// means only the four built-in roles are recognized.
type ProfileSource interface {
	GetProfile(ctx context.Context, name string) (*store.Profile, error)
}

// Resolver authenticates a presented key into a Principal.
type Resolver struct {
	dir      Directory
	profiles ProfileSource
	// keys holds the two values compared against a presented key. It is an
	// atomic pointer rather than two fields because a secret refresh
	// (PAM_CONJUR_REFRESH_MIN, Phase 78) replaces them while requests are being
	// authenticated: Resolve runs on every request on every connection, so a
	// plain field write is a data race, and swapping the pair as one pointer also
	// means a refresh can never be observed half-applied — with the API key
	// updated and the break-glass hash not yet.
	keys atomic.Pointer[bootstrapKeys]
	// setMu serialises WRITES so a per-secret setter can replace one half without
	// racing another setter over the other half. Reads stay lock-free through the
	// atomic pointer, because Resolve runs on every request on every connection.
	setMu sync.Mutex
}

// bootstrapKeys is the pair of key-derived comparison values, swapped together.
// A nil slice means that path is disabled.
type bootstrapKeys struct {
	apiKeyHash     []byte // SHA-256 of the bootstrap API key (empty = disabled)
	breakGlassHash []byte
}

// SetBootstrapSecrets atomically replaces the bootstrap API key and break-glass
// hash — the hot-swap behind runtime secret refresh.
//
// Both are passed every call, and both are replaced together, so a caller cannot
// accidentally leave one stale. An empty apiKey disables the bootstrap-admin
// path; an empty breakGlassHashHex disables break-glass. The hash is validated
// before anything is swapped, so a malformed value from the secret store leaves
// the running configuration untouched rather than disabling break-glass.
func (r *Resolver) SetBootstrapSecrets(apiKey, breakGlassHashHex string) error {
	k, err := newBootstrapKeys(apiKey, breakGlassHashHex)
	if err != nil {
		return err
	}
	r.setMu.Lock()
	defer r.setMu.Unlock()
	r.keys.Store(k)
	return nil
}

// SetBootstrapAPIKey replaces just the bootstrap API key.
//
// Per-secret rather than pair-at-once because the refresher applies each secret
// independently: with one call taking both, a single malformed break-glass hash
// rejected the whole pair and blocked an otherwise-valid key rotation on every
// tick, forever.
func (r *Resolver) SetBootstrapAPIKey(apiKey string) error {
	r.setMu.Lock()
	defer r.setMu.Unlock()
	cur := r.keys.Load()
	next := &bootstrapKeys{breakGlassHash: cur.breakGlassHash}
	if apiKey != "" {
		h := sha256.Sum256([]byte(apiKey))
		next.apiKeyHash = h[:]
	}
	r.keys.Store(next)
	return nil
}

// SetBreakGlassHash replaces just the break-glass hash. The hex is validated
// before anything is swapped, so a bad value from the secret store leaves the
// running configuration untouched rather than disabling the emergency path.
func (r *Resolver) SetBreakGlassHash(breakGlassHashHex string) error {
	var h []byte
	if breakGlassHashHex != "" {
		b, err := hex.DecodeString(breakGlassHashHex)
		if err != nil || len(b) != sha256.Size {
			return errors.New("auth: PAM_BREAK_GLASS_KEY_HASH must be a hex-encoded SHA-256")
		}
		h = b
	}
	r.setMu.Lock()
	defer r.setMu.Unlock()
	cur := r.keys.Load()
	r.keys.Store(&bootstrapKeys{apiKeyHash: cur.apiKeyHash, breakGlassHash: h})
	return nil
}

// newBootstrapKeys derives the comparison values, rejecting a malformed
// break-glass hash.
func newBootstrapKeys(apiKey, breakGlassHashHex string) (*bootstrapKeys, error) {
	k := &bootstrapKeys{}
	if apiKey != "" {
		// Store the SHA-256 so the bootstrap-key comparison is over a fixed
		// 32-byte value, not raw bytes (a raw ConstantTimeCompare short-circuits
		// on length, leaking the key's length via timing).
		h := sha256.Sum256([]byte(apiKey))
		k.apiKeyHash = h[:]
	}
	if breakGlassHashHex != "" {
		b, err := hex.DecodeString(breakGlassHashHex)
		if err != nil || len(b) != sha256.Size {
			return nil, errors.New("auth: PAM_BREAK_GLASS_KEY_HASH must be a hex-encoded SHA-256")
		}
		k.breakGlassHash = b
	}
	return k, nil
}

// WithProfiles enables custom-profile resolution for identities whose stored role
// is not one of the four built-in roles. It returns the resolver for chaining.
func (r *Resolver) WithProfiles(ps ProfileSource) *Resolver {
	r.profiles = ps
	return r
}

// NewResolver builds a Resolver. breakGlassHashHex may be empty to disable the
// break-glass path; otherwise it must be a hex-encoded SHA-256.
func NewResolver(dir Directory, apiKey, breakGlassHashHex string) (*Resolver, error) {
	r := &Resolver{dir: dir}
	if err := r.SetBootstrapSecrets(apiKey, breakGlassHashHex); err != nil {
		return nil, err
	}
	return r, nil
}

// BreakGlassEnabled reports whether a break-glass hash is currently configured.
func (r *Resolver) BreakGlassEnabled() bool { return len(r.keys.Load().breakGlassHash) != 0 }

// TokenHash returns the hex-encoded SHA-256 of a bearer secret. It is the single
// definition of how PAMv1 derives the stored lookup key for every kind of token
// — per-user access tokens, agent keys, application keys, session tokens,
// recovery codes and the broker's resume JTIs — so the plaintext is never
// persisted and the hashing cannot drift between the places that write a hash
// and the places that look one up. A drift here would be an authentication
// bypass or a lockout, which is why it lives in exactly one place.
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// MatchesBreakGlass reports, in constant time, whether sum is the SHA-256 of the
// CURRENT break-glass key.
//
// It exists so nothing else has to keep its own copy of that hash. The Shamir
// quorum-unseal endpoint did, decoded once at construction, and Phase 78 then
// added rotation that reached only the resolver — so a rotated deployment
// rejected the new emergency key on the quorum path while the RETIRED one still
// minted full-admin sessions. Rotation inverted, on the one path that exists for
// when nothing else works. A second copy of a comparison value is the bug; one
// accessor is the fix.
func (r *Resolver) MatchesBreakGlass(sum []byte) bool {
	h := r.keys.Load().breakGlassHash
	if len(h) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(sum, h) == 1
}

// Resolve maps a presented key to a Principal, or ErrUnauthorized.
func (r *Resolver) Resolve(ctx context.Context, key string) (*Principal, error) {
	kb := []byte(key)
	if len(kb) == 0 {
		return nil, ErrUnauthorized
	}
	sum := sha256.Sum256(kb)
	// One load, so both comparisons are made against the same generation of the
	// secrets even if a refresh lands mid-request.
	k := r.keys.Load()
	if len(k.apiKeyHash) != 0 && subtle.ConstantTimeCompare(sum[:], k.apiKeyHash) == 1 {
		return &Principal{Name: "bootstrap-admin", Role: RoleAdmin}, nil
	}
	if len(k.breakGlassHash) != 0 && subtle.ConstantTimeCompare(sum[:], k.breakGlassHash) == 1 {
		return &Principal{Name: "break-glass", Role: RoleAdmin, BreakGlass: true}, nil
	}
	hash := hex.EncodeToString(sum[:])
	if r.dir != nil {
		// Per-user access token (local identity).
		if u, err := r.dir.GetUserByTokenHash(ctx, hash); err == nil {
			// SCIM deprovisioning (Phase 149): a user an IdP has pushed
			// active:false for is refused exactly like an unknown token —
			// deactivating must actually cut access, not just change a
			// flag nothing reads. Directory/SSO logins are unaffected: they
			// resolve through GetSessionByTokenHash below, governed by the
			// directory's own membership, not this local row's Active flag.
			if !u.Active {
				return nil, ErrUnauthorized
			}
			p, perr := r.principalFor(ctx, u.Username, u.Role, false)
			if perr == nil {
				p.IPAllowlist = u.IPAllowlist
				p.DeviceFingerprint = u.DeviceFingerprint
			}
			return p, perr
		}
		// Login session token (e.g. Active Directory / Entra ID / break-glass).
		if s, err := r.dir.GetSessionByTokenHash(ctx, hash); err == nil {
			if s.Scope == SessionScopeBreakGlass {
				return &Principal{Name: s.Username, Role: RoleAdmin, BreakGlass: true}, nil
			}
			p, perr := r.principalFor(ctx, s.Username, s.Role, s.Scope == SessionScopeEnroll)
			if perr != nil {
				return nil, perr
			}
			p.Roles = SplitRoles(s.Roles) // restore the multi-group union
			p.TunnelOnly = IsViewerScope(s.Scope)
			p.MFAPending = s.Scope == SessionScopeMFAPending
			p.ExtensionOnly = s.Scope == SessionScopeExtension
			// A session is minted from a principal and then lives on its own row,
			// so nothing above re-reads the user it was minted for. For a LOCAL
			// user that was a gap the per-user-token path never had (2026-08-27
			// audit): SCIM deactivation flips users.active and the token path
			// refuses it, but an extension token (hours) or a viewer token minted
			// before the flip kept resolving until it expired — and, because only
			// the token path copied them, the row's IP allowlist and device
			// binding never applied to a session at all. Refuse an inactive row,
			// fail closed on a lookup error, and carry the row's restrictions. A
			// directory identity has no local row (ErrNotFound) and is governed by
			// its session's own TTL and POST /api/login-sessions/revoke, as before.
			switch u, uerr := r.dir.GetUserByUsername(ctx, s.Username); {
			case uerr == nil:
				if !u.Active {
					return nil, ErrUnauthorized
				}
				p.IPAllowlist = u.IPAllowlist
				p.DeviceFingerprint = u.DeviceFingerprint
			case !errors.Is(uerr, store.ErrNotFound):
				return nil, ErrUnauthorized
			}
			return p, nil
		}
	}
	return nil, ErrUnauthorized
}

// PrincipalForRole builds the Principal a stored role-or-profile string would
// confer on the named identity, WITHOUT authenticating anything: no key is
// presented and no session is created. It exists so a review can ask what some
// OTHER subject may reach (see ReachableTargets) and get the same capability
// resolution the subject itself would get when it logs in — a custom profile's
// capabilities included. An unresolvable role is refused, fail-closed, exactly
// as it is on the authentication path.
//
// It is not an authentication bypass: the caller must have already authorized
// itself, and nothing here mints or accepts a credential.
func (r *Resolver) PrincipalForRole(ctx context.Context, name, roleOrProfile string) (*Principal, error) {
	return r.principalFor(ctx, name, roleOrProfile, false)
}

// principalFor builds a Principal from a stored role string: a built-in role uses
// the role→capability matrix, otherwise the string is resolved as a custom
// profile (its capabilities become the principal's CapSet). An unresolvable role
// is unauthorized (fail-closed).
func (r *Resolver) principalFor(ctx context.Context, name, roleOrProfile string, enrollOnly bool) (*Principal, error) {
	if role, err := ParseRole(roleOrProfile); err == nil {
		return &Principal{Name: name, Role: role, EnrollOnly: enrollOnly}, nil
	}
	if r.profiles != nil {
		if p, err := r.profiles.GetProfile(ctx, roleOrProfile); err == nil {
			caps, cerr := ParseCapabilities(p.Capabilities)
			if cerr != nil {
				return nil, ErrUnauthorized
			}
			return &Principal{Name: name, Role: Role(p.Name), Caps: caps, EnrollOnly: enrollOnly}, nil
		}
	}
	return nil, ErrUnauthorized
}
