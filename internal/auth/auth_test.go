package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestRoleCapabilities checks the role→capability matrix across all four roles.
func TestRoleCapabilities(t *testing.T) {
	cases := []struct {
		role Role
		cap  Capability
		want bool
	}{
		{RoleAdmin, CapManageUsers, true},
		{RoleAdmin, CapRevealSecret, true},
		{RoleUser, CapConnect, true},
		{RoleUser, CapReadInventory, true},
		{RoleUser, CapRevealSecret, false},
		{RoleUser, CapReadAudit, false},
		{RoleUser, CapManageTargets, false},
		{RoleAuditor, CapReadAudit, true},
		{RoleAuditor, CapReadInventory, true},
		{RoleAuditor, CapConnect, false},
		{RoleAuditor, CapManageTargets, false},
		{RoleAuditor, CapRevealSecret, false},
		{RoleAuditor, CapApprove, false},
		{RoleApprover, CapApprove, true},
		{RoleApprover, CapReadAudit, true},
		{RoleApprover, CapReadInventory, true},
		{RoleApprover, CapConnect, false},
		{RoleApprover, CapManageTargets, false},
		{RoleApprover, CapRevealSecret, false},
		{RoleAdmin, CapApprove, true},
		{RoleUser, CapApprove, false},
	}
	for _, c := range cases {
		if got := c.role.Can(c.cap); got != c.want {
			t.Errorf("%s.Can(%d) = %v, want %v", c.role, c.cap, got, c.want)
		}
	}
}

// TestCanConnectTarget checks target-grant logic: open when ungranted, admins
// always allowed, and user/role grants matched or denied.
func TestCanConnectTarget(t *testing.T) {
	admin := &Principal{Name: "boss", Role: RoleAdmin}
	user := &Principal{Name: "alice", Role: RoleUser}
	other := &Principal{Name: "bob", Role: RoleUser}

	// No grants on an ungated target → open to any connect-capable principal.
	if !CanConnectTarget(user, nil, false, false) {
		t.Fatal("no grants on an ungated target should be open")
	}
	grants := []store.TargetGrant{
		{SubjectType: "user", Subject: "alice"},
		{SubjectType: "role", Subject: "approver"},
	}
	if !CanConnectTarget(admin, grants, false, false) {
		t.Fatal("admin should always connect")
	}
	if !CanConnectTarget(user, grants, false, false) {
		t.Fatal("granted user should connect")
	}
	if CanConnectTarget(other, grants, false, false) {
		t.Fatal("ungranted user must be denied")
	}
	if !CanConnectTarget(&Principal{Name: "x", Role: RoleApprover}, grants, false, false) {
		t.Fatal("granted role should connect")
	}
}

// TestCanConnectSafeScoped verifies that a target placed in an ordinary
// (non-personal) safe is default-DENY when its effective grants yield no
// match — an empty safe must not fall through to the ungated "open to all"
// behavior. Admins are still allowed, since personal=false here.
func TestCanConnectSafeScoped(t *testing.T) {
	user := &Principal{Name: "alice", Role: RoleUser}
	admin := &Principal{Name: "boss", Role: RoleAdmin}

	// Safe-scoped target with no members/grants: closed to a normal user.
	if CanConnectTarget(user, nil, true, false) {
		t.Fatal("safe-scoped target with no grants must be default-deny")
	}
	// ...but an admin may always connect to an ordinary safe.
	if !CanConnectTarget(admin, nil, true, false) {
		t.Fatal("admin should connect to a non-personal safe-scoped target")
	}
	// A matching safe member is allowed.
	grants := []store.TargetGrant{{SubjectType: "user", Subject: "alice"}}
	if !CanConnectTarget(user, grants, true, false) {
		t.Fatal("safe member should connect")
	}
	// A non-matching principal on a safe-scoped target is denied.
	if CanConnectTarget(&Principal{Name: "bob", Role: RoleUser}, grants, true, false) {
		t.Fatal("non-member must be denied on a safe-scoped target")
	}
}

// TestCanConnectPersonalSafe proves the actual Phase 139 protection: a
// Personal safe's admin auto-bypass is replaced by CapUnlimitedVaultAccess,
// while the safe's own member (regardless of role) is unaffected.
func TestCanConnectPersonalSafe(t *testing.T) {
	admin := &Principal{Name: "boss", Role: RoleAdmin}
	overrideAdmin := &Principal{Name: "security-lead", Role: RoleAdmin,
		Caps: CapSet{CapReadInventory: true, CapManageTargets: true, CapManageCredentials: true,
			CapRevealSecret: true, CapConnect: true, CapReadAudit: true, CapManageUsers: true,
			CapApprove: true, CapUnlimitedVaultAccess: true}}
	owner := &Principal{Name: "alice", Role: RoleUser}
	stranger := &Principal{Name: "bob", Role: RoleUser}
	grants := []store.TargetGrant{{SubjectType: "user", Subject: "alice"}}

	if CanConnectTarget(admin, grants, true, true) {
		t.Fatal("a plain admin without CapUnlimitedVaultAccess must NOT bypass a personal safe")
	}
	if !CanConnectTarget(overrideAdmin, grants, true, true) {
		t.Fatal("a principal holding CapUnlimitedVaultAccess must bypass a personal safe")
	}
	if !CanConnectTarget(owner, grants, true, true) {
		t.Fatal("the personal safe's own member must connect regardless of role")
	}
	if CanConnectTarget(stranger, grants, true, true) {
		t.Fatal("a non-member without the override must be denied on a personal safe")
	}
	// The override is irrelevant off a personal safe: an ordinary admin still
	// bypasses exactly as before Phase 139 (byte-identical old behavior).
	if !CanConnectTarget(admin, grants, true, false) {
		t.Fatal("admin must still bypass an ordinary (non-personal) safe")
	}
}

// TestPersonalOverrideUsed proves the loud-audit predicate matches
// CanConnectTarget's own override condition exactly.
func TestPersonalOverrideUsed(t *testing.T) {
	overrideAdmin := &Principal{Name: "security-lead", Role: RoleAdmin,
		Caps: CapSet{CapUnlimitedVaultAccess: true}}
	admin := &Principal{Name: "boss", Role: RoleAdmin}

	if !overrideAdmin.PersonalOverrideUsed(true) {
		t.Fatal("a CapUnlimitedVaultAccess holder on a personal target should report override used")
	}
	if overrideAdmin.PersonalOverrideUsed(false) {
		t.Fatal("a non-personal target should never report override used")
	}
	if admin.PersonalOverrideUsed(true) {
		t.Fatal("a principal without the capability should never report override used")
	}
}

// TestParseRole checks that the four valid roles parse and an unknown one errors.
func TestParseRole(t *testing.T) {
	for _, ok := range []string{"admin", "user", "auditor", "approver"} {
		if _, err := ParseRole(ok); err != nil {
			t.Errorf("ParseRole(%q) unexpected error: %v", ok, err)
		}
	}
	if _, err := ParseRole("root"); err == nil {
		t.Error("ParseRole(root) should fail")
	}
}

// fakeDir implements auth.Directory for tests.
type fakeDir struct {
	users    map[string]*store.User    // tokenHashHex -> user
	sessions map[string]*store.Session // tokenHashHex -> session
}

// GetUserByTokenHash returns the seeded user for hash h, or store.ErrNotFound.
func (f fakeDir) GetUserByTokenHash(_ context.Context, h string) (*store.User, error) {
	if u, ok := f.users[h]; ok {
		return u, nil
	}
	return nil, store.ErrNotFound
}

// GetSessionByTokenHash returns the seeded session for hash h, or store.ErrNotFound.
func (f fakeDir) GetSessionByTokenHash(_ context.Context, h string) (*store.Session, error) {
	if s, ok := f.sessions[h]; ok {
		return s, nil
	}
	return nil, store.ErrNotFound
}

// hashOf returns the hex SHA-256 of tok, matching how the resolver keys tokens.
func hashOf(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// TestResolve exercises every accepted key kind (bootstrap admin, break-glass,
// per-user token, login session) and rejection of empty/unknown/bad-role keys.
func TestResolve(t *testing.T) {
	bg := sha256.Sum256([]byte("emergency"))
	dir := fakeDir{
		users: map[string]*store.User{
			hashOf("alice-token"): {Username: "alice", Role: "user", Active: true},
			hashOf("theo-token"):  {Username: "theo", Role: "auditor", Active: true},
			hashOf("broken"):      {Username: "bad", Role: "wizard", Active: true},
		},
		sessions: map[string]*store.Session{
			hashOf("ad-session"): {Username: "ad-alice", Role: "approver"},
		},
	}
	r, err := NewResolver(dir, "bootstrap", hex.EncodeToString(bg[:]))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	check := func(key, name string, role Role, breakglass bool) {
		t.Helper()
		p, err := r.Resolve(ctx, key)
		if err != nil {
			t.Fatalf("Resolve(%q) error: %v", key, err)
		}
		if p.Name != name || p.Role != role || p.BreakGlass != breakglass {
			t.Fatalf("Resolve(%q) = %+v, want name=%s role=%s bg=%v", key, p, name, role, breakglass)
		}
	}
	check("bootstrap", "bootstrap-admin", RoleAdmin, false)
	check("emergency", "break-glass", RoleAdmin, true)
	check("alice-token", "alice", RoleUser, false)
	check("theo-token", "theo", RoleAuditor, false)
	check("ad-session", "ad-alice", RoleApprover, false) // login session token

	for _, bad := range []string{"", "nope", "broken"} {
		if _, err := r.Resolve(ctx, bad); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("Resolve(%q) = %v, want ErrUnauthorized", bad, err)
		}
	}
}

// TestSetBootstrapSecretsSwapsAtomically covers the hot-swap behind runtime
// secret refresh (Phase 78): after a rotation the retired key must stop working
// immediately and the new one must work, with no restart.
func TestSetBootstrapSecretsSwapsAtomically(t *testing.T) {
	ctx := context.Background()
	oldBG := sha256.Sum256([]byte("old-break-glass"))
	r, err := NewResolver(nil, "old-key", hex.EncodeToString(oldBG[:]))
	if err != nil {
		t.Fatal(err)
	}
	if p, err := r.Resolve(ctx, "old-key"); err != nil || p.Name != "bootstrap-admin" {
		t.Fatalf("the initial key should resolve: %v %v", p, err)
	}

	newBG := sha256.Sum256([]byte("new-break-glass"))
	if err := r.SetBootstrapSecrets("new-key", hex.EncodeToString(newBG[:])); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Resolve(ctx, "old-key"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("the RETIRED key still authenticates — a rotation that leaves the old key live is not a rotation")
	}
	if p, err := r.Resolve(ctx, "new-key"); err != nil || p.Name != "bootstrap-admin" {
		t.Fatalf("the new key does not authenticate: %v %v", p, err)
	}
	if _, err := r.Resolve(ctx, "old-break-glass"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("the retired break-glass key still authenticates")
	}
	p, err := r.Resolve(ctx, "new-break-glass")
	if err != nil || !p.BreakGlass {
		t.Fatalf("the new break-glass key does not authenticate: %v %v", p, err)
	}
}

// TestSetBootstrapSecretsRejectsBeforeSwapping proves a malformed value from the
// secret store leaves the running configuration untouched. The failure this
// guards is the dangerous one: a bad hash that cleared break-glass would remove
// the emergency path at the moment nobody is looking.
func TestSetBootstrapSecretsRejectsBeforeSwapping(t *testing.T) {
	ctx := context.Background()
	bg := sha256.Sum256([]byte("break-glass"))
	r, err := NewResolver(nil, "key", hex.EncodeToString(bg[:]))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetBootstrapSecrets("new-key", "not-a-hash"); err == nil {
		t.Fatal("a malformed break-glass hash must be refused")
	}
	// Nothing moved: both original values still work.
	if _, err := r.Resolve(ctx, "key"); err != nil {
		t.Fatal("the rejected swap changed the API key anyway")
	}
	if p, err := r.Resolve(ctx, "break-glass"); err != nil || !p.BreakGlass {
		t.Fatal("the rejected swap disabled break-glass")
	}
}

// TestResolveIsSafeWhileSecretsRotate is the reason the pair is an atomic
// pointer rather than two fields: Resolve runs on every request on every
// connection, so a refresh lands while requests are in flight. Run under -race,
// which CI does.
func TestResolveIsSafeWhileSecretsRotate(t *testing.T) {
	ctx := context.Background()
	bg := sha256.Sum256([]byte("bg"))
	r, err := NewResolver(nil, "key-0", hex.EncodeToString(bg[:]))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 200 {
			if err := r.SetBootstrapSecrets(fmt.Sprintf("key-%d", i), hex.EncodeToString(bg[:])); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for range 200 {
		// The answer varies with the race; only the absence of a data race and of
		// a panic is asserted here.
		_, _ = r.Resolve(ctx, "key-7")
	}
	<-done
}

// TestIPAllowed covers empty-is-unrestricted, a matching/non-matching CIDR,
// multiple entries, whitespace tolerance, an unparseable ip, and a malformed
// entry being skipped rather than aborting the whole check (Phase 118).
func TestIPAllowed(t *testing.T) {
	cases := []struct {
		name      string
		allowlist string
		ip        string
		want      bool
	}{
		{"empty allowlist is unrestricted", "", "203.0.113.5", true},
		{"whitespace-only allowlist is unrestricted", "   ", "203.0.113.5", true},
		{"single matching CIDR", "10.0.0.0/8", "10.1.2.3", true},
		{"single non-matching CIDR", "10.0.0.0/8", "192.168.1.1", false},
		{"second entry matches", "10.0.0.0/8, 192.168.1.0/24", "192.168.1.42", true},
		{"whitespace around entries tolerated", " 10.0.0.0/8 , 192.168.1.0/24 ", "192.168.1.42", true},
		{"unparseable ip never matches a restriction", "10.0.0.0/8", "not-an-ip", false},
		{"a malformed entry is skipped, not fatal to the rest", "not-a-cidr, 10.0.0.0/8", "10.1.2.3", true},
		{"every entry malformed matches nothing", "not-a-cidr, also-not", "10.1.2.3", false},
		{"IPv6 CIDR", "2001:db8::/32", "2001:db8::1", true},
		{"IPv6 CIDR non-matching", "2001:db8::/32", "2001:db9::1", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IPAllowed(c.allowlist, c.ip); got != c.want {
				t.Errorf("IPAllowed(%q, %q) = %v, want %v", c.allowlist, c.ip, got, c.want)
			}
		})
	}
}

// TestValidateCIDRList covers acceptance of a well-formed list (including
// empty) and rejection of the first malformed entry.
func TestValidateCIDRList(t *testing.T) {
	for _, ok := range []string{"", "  ", "10.0.0.0/8", "10.0.0.0/8,192.168.1.0/24", " 10.0.0.0/8 , 192.168.1.0/24 "} {
		if err := ValidateCIDRList(ok); err != nil {
			t.Errorf("ValidateCIDRList(%q) unexpected error: %v", ok, err)
		}
	}
	for _, bad := range []string{"not-a-cidr", "10.0.0.0/8,not-a-cidr", "10.0.0.0", "999.0.0.0/8"} {
		if err := ValidateCIDRList(bad); err == nil {
			t.Errorf("ValidateCIDRList(%q) should have failed", bad)
		}
	}
}

// TestResolveThreadsIPAllowlist proves a per-user token's IPAllowlist survives
// Resolve into the returned Principal (Phase 118) — the store.User.IPAllowlist
// -> Principal.IPAllowlist wiring that IPAllowed/the gates actually read.
func TestResolveThreadsIPAllowlist(t *testing.T) {
	dir := fakeDir{
		users: map[string]*store.User{
			hashOf("alice-token"): {Username: "alice", Role: "user", IPAllowlist: "10.0.0.0/8", Active: true},
			hashOf("bob-token"):   {Username: "bob", Role: "user", Active: true}, // no allowlist
		},
	}
	r, err := NewResolver(dir, "bootstrap", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p, err := r.Resolve(ctx, "alice-token")
	if err != nil {
		t.Fatal(err)
	}
	if p.IPAllowlist != "10.0.0.0/8" {
		t.Fatalf("alice's Principal.IPAllowlist = %q, want %q", p.IPAllowlist, "10.0.0.0/8")
	}
	p, err = r.Resolve(ctx, "bob-token")
	if err != nil {
		t.Fatal(err)
	}
	if p.IPAllowlist != "" {
		t.Fatalf("bob's Principal.IPAllowlist = %q, want empty", p.IPAllowlist)
	}
	// The bootstrap admin is unaffected — no store.User backs it, so it stays
	// permanently unrestricted regardless of any per-user allowlist.
	p, err = r.Resolve(ctx, "bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	if p.IPAllowlist != "" {
		t.Fatalf("bootstrap-admin's Principal.IPAllowlist = %q, want empty", p.IPAllowlist)
	}
}
