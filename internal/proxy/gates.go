package proxy

// gates.go holds the ONE admission-gate sequence shared by all three session
// proxies — the SSH proxy (proxy.go), the PostgreSQL proxy (dbproxy.go) and the
// SQL Server proxy (mssqlproxy.go). Each proxy's handleConn authenticates the
// operator in its own protocol, then hands the resolved principal to admit(),
// which runs every authorization gate in a FIXED order and, only if all pass,
// performs the just-in-time credential decryption. It returns the target, the
// credential, the decrypted secret and a typed outcome that classifies any
// refusal; each proxy maps that outcome back to its own protocol's refusal.
//
// Why this exists. The three handleConn bodies used to inline the same gate
// sequence three times, differing only in how each said no. That is precisely
// the shape that produced the Phase 96 bugs: a gate fixed on one proxy and
// forgotten on the siblings. With the sequence written once, a gate added,
// removed or reordered here lands on every proxy at once — the transport is all
// that differs, never the policy.
//
// The three genuine per-proxy variations are carried as narrow hooks on the
// admitRequest (an exact-protocol match versus SSH's "can this gateway broker
// it" check; whether a credential carries a stored secret to decrypt; and the
// protocol-specific session-start audit line), so the ORDER stays authoritative
// here while the wording stays with each proxy.

import (
	"context"
	"log/slog"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/oncall"
	"github.com/morandeirachema/pamv1/internal/posture"
	"github.com/morandeirachema/pamv1/internal/ratelimit"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// admitKind is the coarse classification of an admission outcome: success, or
// one of the five refusal families. A caller switches on it (and, for the
// refusals that vary by which gate tripped, on admitGate) to choose the audit
// action and the wire refusal its protocol has always used.
type admitKind int

const (
	admitOK               admitKind = iota // every gate passed; target/cred/secret are set
	admitDenied                            // a policy gate said no (role, grant, approval, …)
	admitCheckFailed                       // a store/policy lookup errored — fail closed
	admitSessionLimited                    // the concurrent-session cap was reached
	admitAuditUnavailable                  // the fail-closed session-start audit could not be written
	admitDecryptFailed                     // just-in-time credential decryption failed
)

// admitGate names the specific gate that produced a refusal. It is the
// sub-discriminator a caller uses to reproduce the EXACT audit detail and wire
// message each gate has always emitted (the coarse admitKind alone cannot tell
// "role may not connect" from "not authorized for this target"). gateNone is the
// success value.
type admitGate int

const (
	gateNone              admitGate = iota
	gateTunnelOnly                  // tunnel-scoped viewer token presented to a session proxy
	gateEnrollOnly                  // MFA enrollment still pending
	gateMFAPending                  // WebAuthn second factor not yet verified this login
	gateExtensionOnly               // browser-extension token presented to a session proxy
	gateRoleConnect                 // role/profile lacks CapConnect
	gateIPAllowlist                 // principal's source address is outside its IP allowlist
	gatePosture                     // live device-posture attestation failed
	gateOnCall                      // on-call attestation failed (Phase 232)
	gateResolve                     // target/credential could not be resolved (reason = the error text)
	gateProtocolMatch               // target is not the exact protocol this proxy brokers (DB proxies)
	gateProtocolAllowed             // protocol forbidden by the OT allowlist
	gateTargetGrants                // effective-grants lookup errored (check-failed)
	gateTargetPolicy                // per-target grants/safe-membership denied the connect
	gateApprovalPolicy              // approval-policy lookup errored (check-failed)
	gateApprovalClaim               // the approval claim errored (check-failed)
	gateApproval                    // no approved access request (reason = approval-required / ticket-not-valid)
	gateVendorCheck                 // vendor-contract lookup errored (check-failed)
	gateVendor                      // vendor lacks an active, in-window contract grant
	gateProtocolProxyable           // this gateway cannot broker the target's protocol (SSH proxy)
	gateSessionLimit                // concurrent-session cap
	gateAudit                       // the fail-closed session-start audit could not be written
	gateDecrypt                     // JIT decryption failed
)

// admitResult is what admit() returns. On success outcome is admitOK, gate is
// gateNone, and target/cred/secret are populated (secret is empty for a
// credential the caller declared has no stored secret to decrypt, e.g. SSH Zero
// Standing Privilege). On a refusal, outcome/gate/reason describe it, and
// target/cred are set only if resolution had already succeeded when the gate
// tripped (nil otherwise).
type admitResult struct {
	outcome admitKind
	gate    admitGate
	// reason carries the gate's dynamic text: the resolution error string for
	// gateResolve, or the approval reason (approval-required / ticket-not-valid)
	// for gateApproval. Empty for gates whose refusal text is fixed.
	reason string
	target *store.Target
	cred   *store.Credential
	secret string
	// bounds is the session lifetime the admitting grant imposes (Phase 240):
	// stamped on the registered session as its deadline. Zero when the
	// principal's access is not bounded by a grant edge.
	bounds sessionBounds
}

// sessionBounds carries a grant-imposed end for a session: the instant and
// the reason ("grant-expiry" | "time-frame") the lifetime monitor audits.
type sessionBounds struct {
	deadline *time.Time
	reason   string
}

// admitRequest bundles admit()'s inputs. principal, targetName and credUser are
// always required; the four hooks carry the genuine per-proxy variations so the
// gate ORDER stays owned by admit() while the protocol-specific wording stays
// with each proxy.
type admitRequest struct {
	principal  *auth.Principal
	targetName string
	credUser   string
	// remoteAddr is the already-resolved client address (host:port or bare
	// host) each proxy computes before calling admit — checked against
	// principal.IPAllowlist (Phase 118). Every call site already has this
	// value for logging/audit, so admit just needs it threaded through.
	remoteAddr string

	// expectProtocol, when non-empty, requires target.Protocol to equal it right
	// after resolution — the PostgreSQL/SQL Server proxies' exact-protocol gate.
	// Empty skips that gate (the SSH proxy, which uses proxyable below instead).
	expectProtocol string
	// proxyable, when non-nil, is the SSH proxy's post-vendor "can this gateway
	// actually broker this target's protocol" gate. nil skips it (the DB proxies).
	proxyable func(*store.Target) bool
	// skipDecrypt reports a credential that carries no stored secret to decrypt
	// (SSH "ssh_ca" Zero Standing Privilege, whose certificate is minted at dial
	// time). nil means always decrypt. When it returns true, admit leaves secret
	// empty and does not touch the vault.
	skipDecrypt func(*store.Credential) bool
	// startAudit builds the fail-closed session-start audit — action and detail —
	// that must land BEFORE any secret is decrypted. Its wording is
	// protocol-specific (session.start vs db.session.start, and the detail
	// fields), so each proxy supplies it; admit calls it with the resolved
	// target/credential and refuses the session if the write cannot land.
	startAudit func(*store.Target, *store.Credential) (action, detail string)
}

// gates holds the policy dependencies the admission sequence reads. Each proxy
// builds one in its constructor from fields it already has, so the three share a
// single admit() implementation instead of three hand-kept copies.
// ungatedDefault maps the deployment's boolean to the policy the authorization
// layer takes, so the mapping lives in one place on this side too.
func ungatedDefault(requireGrant bool) auth.UngatedDefault {
	if requireGrant {
		return auth.UngatedDeny
	}
	return auth.UngatedOpen
}

type gates struct {
	store        store.Store
	vault        *vault.Vault
	log          *slog.Logger
	allowedProto map[string]bool
	// ungated is what a target with NO grants means (Phase 203): auth.UngatedOpen
	// (the historical default) or auth.UngatedDeny under PAM_REQUIRE_TARGET_GRANT.
	ungated      auth.UngatedDefault
	requireApprv bool
	ticketCheck  store.TicketChecker
	// sessions is the live-session registry; nil disables the concurrent-session
	// cap. Held as the concrete pointer (not an interface) so a nil registry
	// compares equal to nil — a typed-nil interface would slip past the guard.
	sessions *session.Registry
	// posture (optional) validates a user's live device posture on every
	// connect (Phase 133); nil disables posture checking. The broker's
	// ssh_exec/winrm_exec tools never reach admit() at all (they run over
	// rotate.SSHConnector, a separate one-shot path), so this gate can never
	// fire for a RoleAgent identity — no explicit exemption needed.
	posture *posture.Attestor
	// oncall (optional) validates a user is currently on call on every
	// connect (Phase 232); nil disables on-call checking. Same shape and
	// same broker exemption as posture above.
	oncall *oncall.Attestor
}

// admit runs every authorization gate in the fixed order below and, only if all
// pass, performs the just-in-time credential decryption. It is the single
// decision path for the SSH, PostgreSQL and SQL Server proxies.
//
// The order (a gate added or moved here changes it for all three at once):
//
//  1. tunnel-only token          — a viewer-scoped token may not open a session
//  2. MFA enrollment pending     — an enroll-only session may not open a session
//  3. MFA (WebAuthn) pending     — password verified, second factor not yet confirmed
//  4. role CapConnect            — the role/profile must be allowed to connect
//  5. IP allowlist               — source address must fall inside the principal's CIDR allowlist, if it has one; break-glass bypasses
//  6. live device posture        — re-checked every connect, not just at approval; break-glass bypasses
//  7. on-call attestation        — re-checked every connect, same shape as posture; break-glass bypasses
//  8. resolve target+credential  — WITHOUT decrypting the secret
//  9. exact-protocol match       — DB proxies only (expectProtocol)
//  10. protocol allowlist         — OT policy may forbid the protocol
//  11. per-target authorization  — effective grants ∪ safe membership
//  12. approval gate             — 4-eyes / OT window; break-glass bypasses; single-use burned here
//  13. vendor contract gate      — a vendor needs an active, in-window contract
//  14. protocol proxyable        — SSH proxy only (can this gateway broker it)
//  15. concurrent-session cap    — before any secret is decrypted
//  16. fail-closed session-start audit — durable evidence BEFORE decryption
//  17. just-in-time decryption   — plaintext exists only from here, never for a denied session
//
// admit itself emits only the audits that are byte-identical across all three
// proxies and are intrinsic to a gate rather than to a refusal: the approval
// sub-events (access.consumed / access.ticket_revoked, via claimApproval), the
// access.denied rows for the approval and vendor denials, the session-start
// audit (through the caller's startAudit hook), and credential.decrypt_failed —
// plus the identical check-failed error LOGS. Every refusal whose audit action
// or detail differs between proxies (session.denied vs db.session.denied, the
// deny-row wording, …) is left to the caller, which maps the returned
// outcome/gate/reason to its own protocol.
func (g *gates) admit(ctx context.Context, req admitRequest) admitResult {
	principal := req.principal
	actor := principal.Name

	// 1-3. A narrow-scope token may not open a brokered session. Until the
	// 2026-08-26 audit this was three hand-written field checks, and it was
	// missing the fourth field: a browser-extension token — which the HTTP
	// middleware refuses everywhere except reveal — was accepted here as an SSH
	// or database password and opened full sessions for 24 hours. The test now
	// lives in ONE place, auth.Principal.MayOpenSession, and this gate only maps
	// its answer to a per-scope audit reason. A proxy serves no narrow scope
	// at all, hence ScopeNone.
	if !principal.MayOpenSession(auth.ScopeNone) {
		switch principal.NarrowScope() {
		case auth.ScopeTunnelOnly:
			return admitResult{outcome: admitDenied, gate: gateTunnelOnly}
		case auth.ScopeEnrollOnly:
			return admitResult{outcome: admitDenied, gate: gateEnrollOnly}
		case auth.ScopeMFAPending:
			return admitResult{outcome: admitDenied, gate: gateMFAPending}
		default:
			// ScopeExtensionOnly today; any scope added later lands here rather
			// than being silently admitted, which is the whole point.
			return admitResult{outcome: admitDenied, gate: gateExtensionOnly}
		}
	}
	// 4. The role (or custom profile) must carry the connect capability.
	if !principal.Can(auth.CapConnect) {
		return admitResult{outcome: admitDenied, gate: gateRoleConnect}
	}

	// 5. Source-address restriction (Phase 118): a principal with a non-empty
	// IPAllowlist may connect only from inside it. Break-glass bypasses,
	// matching every other gate break-glass already bypasses (emergency
	// access is already loud on its own). Cheap and principal-only (no store
	// lookup), so it stays grouped with gates 1-3 ahead of target resolution.
	if !principal.BreakGlass && !auth.IPAllowed(principal.IPAllowlist, ratelimit.Host(req.remoteAddr)) {
		return admitResult{outcome: admitDenied, gate: gateIPAllowlist}
	}

	// 6. Live device posture (Phase 133): re-checked on every connect, not
	// just once at approval, since posture — unlike vendor employment — can
	// change between one connection and the next. A nil/unconfigured
	// attestor always passes. Break-glass bypasses. The broker's
	// ssh_exec/winrm_exec tools never reach admit() (a separate one-shot
	// path over rotate.SSHConnector), so this can never fire for a
	// RoleAgent identity.
	if !principal.BreakGlass && g.posture.Enabled() {
		if err := g.posture.Attest(ctx, actor); err != nil {
			return admitResult{outcome: admitDenied, gate: gatePosture}
		}
	}

	// 7. On-call attestation (Phase 232): re-checked on every connect, the same
	// shape and same reasoning as posture above — whether an identity is
	// currently on shift can change between one connection and the next. A
	// nil/unconfigured attestor always passes. Break-glass bypasses. The
	// broker's ssh_exec/winrm_exec tools never reach admit(), so this can
	// never fire for a RoleAgent identity — "on call" is a human-shift
	// concept, not something an agent identity has.
	if !principal.BreakGlass && g.oncall.Enabled() {
		if err := g.oncall.Attest(ctx, actor); err != nil {
			return admitResult{outcome: admitDenied, gate: gateOnCall}
		}
	}

	// 8. Resolve the target and the credential WITHOUT decrypting the secret, so
	// every gate below runs before any plaintext exists.
	target, cred, err := lookupTargetCred(ctx, g.store, req.targetName, req.credUser)
	if err != nil {
		return admitResult{outcome: admitDenied, gate: gateResolve, reason: err.Error()}
	}

	// 9. Exact-protocol gate (DB proxies): a PostgreSQL/SQL Server broker refuses
	// a target of any other protocol here.
	if req.expectProtocol != "" && target.Protocol != req.expectProtocol {
		return admitResult{outcome: admitDenied, gate: gateProtocolMatch, target: target, cred: cred}
	}

	// 10. Protocol allowlist (OT policy): refuse a forbidden protocol.
	if g.allowedProto != nil && !g.allowedProto[target.Protocol] {
		return admitResult{outcome: admitDenied, gate: gateProtocolAllowed, target: target, cred: cred}
	}

	// 11. Per-target authorization: honor effective grants (direct ∪ safe members).
	grants, err := g.store.EffectiveTargetGrants(ctx, target.ID)
	if err != nil {
		g.log.Error("target grants lookup failed", "target", target.Name, "err", err)
		return admitResult{outcome: admitCheckFailed, gate: gateTargetGrants, target: target, cred: cred}
	}
	// A target's safe being Personal (Phase 139) narrows the admin bypass
	// CanConnectTarget otherwise grants to CapUnlimitedVaultAccess only — see
	// its doc comment. V1 scope, stated plainly rather than silently
	// dropped: unlike the REST paths (authorizedForTarget,
	// viewer_handlers.go), a successful override here is not additionally
	// loud-audited — admitResult carries only a DENIAL reason today, and
	// threading a success-side signal through it and all three proxies'
	// gate-result switches is real, separable plumbing this phase doesn't
	// attempt. The access-control property itself — a plain admin without
	// the capability is turned away exactly the same as on the REST paths —
	// is not weakened; only the extra audit line is REST-only for now.
	personal, err := store.EffectiveSafePersonal(ctx, g.store, target)
	if err != nil {
		g.log.Error("safe personal lookup failed", "target", target.Name, "err", err)
		return admitResult{outcome: admitCheckFailed, gate: gateTargetGrants, target: target, cred: cred}
	}
	now := time.Now()
	if !auth.CanConnectTargetAt(principal, grants, target.SafeID != nil, personal, g.ungated, now) {
		return admitResult{outcome: admitDenied, gate: gateTargetPolicy, target: target, cred: cred}
	}
	// A grant with an edge — an expiry, or a time-frame window that closes —
	// gives the session that edge as its deadline (Phase 240), so the session
	// ends with the authorization instead of outliving it. Grants without an
	// edge, or a principal admitted without needing one, leave it unset.
	var bounds sessionBounds
	if dl, why, bounded := auth.GrantDeadline(principal, grants, personal, now); bounded {
		bounds = sessionBounds{deadline: &dl, reason: why}
	}

	// 12. Approval gate (4-eyes / OT window). Break-glass bypasses. A single-use
	// approval is BURNED by the connection it admits (consume-on-connect), even
	// one that later fails upstream, so it can never authorize a second session.
	// The policy is the strictest of the global flag, the target's own flag and
	// the target's safe — folded in one place so the proxies cannot drift.
	approvalPolicy, aperr := store.EffectiveApprovalPolicy(ctx, g.store, target, g.requireApprv)
	if aperr != nil {
		g.log.Error("approval policy lookup failed", "target", target.Name, "err", aperr)
		return admitResult{outcome: admitCheckFailed, gate: gateApprovalPolicy, target: target, cred: cred}
	}
	if approvalPolicy.Required && !principal.BreakGlass {
		ok, reason, aerr := claimApproval(ctx, g.store, g.ticketCheck, actor, target,
			func(action, detail string) { appendAudit(ctx, g.store, g.log, actor, action, detail) })
		if aerr != nil {
			g.log.Error("approval check failed", "target", target.Name, "err", aerr)
			return admitResult{outcome: admitCheckFailed, gate: gateApprovalClaim, target: target, cred: cred}
		}
		if !ok {
			// access.denied here is byte-identical on all three proxies, so admit
			// owns it; the caller only writes the wire refusal.
			appendAudit(ctx, g.store, g.log, actor, "access.denied", "target:"+target.Name+" reason:"+reason)
			return admitResult{outcome: admitDenied, gate: gateApproval, reason: reason, target: target, cred: cred}
		}
	}

	// 13. Vendor contract gate: a third-party vendor may reach a target only while
	// an approved, in-window contract grant is active. Non-vendors are unaffected.
	if isVendor, allowed, verr := g.store.VendorSessionAllowed(ctx, actor, target.Name, cred.Username, time.Now()); verr != nil {
		g.log.Error("vendor gate check failed", "target", target.Name, "err", verr)
		return admitResult{outcome: admitCheckFailed, gate: gateVendorCheck, target: target, cred: cred}
	} else if isVendor && !allowed {
		// access.denied is byte-identical on all three proxies, so admit owns it.
		appendAudit(ctx, g.store, g.log, actor, "access.denied", "target:"+target.Name+" reason:vendor-contract")
		return admitResult{outcome: admitDenied, gate: gateVendor, target: target, cred: cred}
	}

	// 14. Refuse a protocol this gateway cannot broker (SSH proxy: ssh always,
	// winrm only with a runner configured) — before decrypting, so plaintext
	// never materializes for a session about to be denied.
	if req.proxyable != nil && !req.proxyable(target) {
		return admitResult{outcome: admitDenied, gate: gateProtocolProxyable, target: target, cred: cred}
	}

	// 15. Concurrent-session cap: refuse a session that would exceed the per-user
	// or global limit BEFORE any secret is decrypted, so one (or a compromised)
	// identity cannot exhaust connections, goroutines or recording disk.
	if g.sessions != nil && !g.sessions.AllowNew(actor) {
		return admitResult{outcome: admitSessionLimited, gate: gateSessionLimit, target: target, cred: cred}
	}

	// 16. Fail closed: durably audit the session start BEFORE any secret is
	// decrypted or a certificate minted. If the audit store is unavailable we
	// refuse rather than open an unaudited privileged session — the audit
	// analogue of the fail-closed recording policy.
	startAction, startDetail := req.startAudit(target, cred)
	if err := appendAuditErr(ctx, g.store, g.log, actor, startAction, startDetail); err != nil {
		return admitResult{outcome: admitAuditUnavailable, gate: gateAudit, target: target, cred: cred}
	}

	// 17. Just-in-time decryption. A credential the caller declared has no stored
	// secret (SSH Zero Standing Privilege) is left for dial-time certificate
	// minting; every other secret is decrypted here — plaintext exists only from
	// this point, never for a session that was denied above.
	var secret string
	if req.skipDecrypt == nil || !req.skipDecrypt(cred) {
		secret, err = jitDecrypt(ctx, g.vault, target, cred)
		if err != nil {
			g.log.Error("credential decryption failed", "actor", actor, "target", target.Name, "err", err)
			appendAudit(ctx, g.store, g.log, actor, "credential.decrypt_failed",
				"target:"+target.Name+" cred_user:"+cred.Username+" op:connect")
			return admitResult{outcome: admitDecryptFailed, gate: gateDecrypt, target: target, cred: cred}
		}
	}

	return admitResult{outcome: admitOK, gate: gateNone, target: target, cred: cred, secret: secret, bounds: bounds}
}
