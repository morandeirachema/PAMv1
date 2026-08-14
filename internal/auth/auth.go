// Package auth defines pamv1's identity and role-based access control.
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
	CapReadInventory:     "read_inventory",
	CapManageTargets:     "manage_targets",
	CapManageCredentials: "manage_credentials",
	CapRevealSecret:      "reveal_secret",
	CapConnect:           "connect",
	CapReadAudit:         "read_audit",
	CapManageUsers:       "manage_users",
	CapApprove:           "approve",
	CapCallTool:          "call_tool",
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
// its effective grants (direct grants ∪ safe members) and whether the target is
// placed in a safe. Admins may always connect. When no grant matches, an
// *ungated* target (safeScoped=false) is open to any connect-capable principal,
// but a *safe-scoped* target (safeScoped=true) is default-DENY — placing a target
// in a safe restricts it to that safe's members, so an empty/unmatched grant set
// must not fall through to "open". Otherwise a grant must match the user or role.
func CanConnectTarget(p *Principal, grants []store.TargetGrant, safeScoped bool) bool {
	for _, r := range p.effectiveRoles() {
		if r == RoleAdmin {
			return true
		}
	}
	if len(grants) == 0 {
		// Ungated ⇒ open; safe-scoped-but-no-members ⇒ closed (containment).
		return !safeScoped
	}
	for _, g := range grants {
		if SubjectMatches(p, g.SubjectType, g.Subject) {
			return true
		}
	}
	return false
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
// principal, refused everywhere except the WebAuthn login-ceremony routes.
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
// definition of how pamv1 derives the stored lookup key for every kind of token
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
			if perr == nil {
				p.Roles = SplitRoles(s.Roles) // restore the multi-group union
				p.TunnelOnly = IsViewerScope(s.Scope)
				p.MFAPending = s.Scope == SessionScopeMFAPending
			}
			return p, perr
		}
	}
	return nil, ErrUnauthorized
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
