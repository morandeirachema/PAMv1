package proxy

// sqlproxy.go holds the per-statement pipeline shared by the two database
// brokers — the PostgreSQL proxy (dbproxy.go) and the SQL Server proxy
// (mssqlproxy.go). Both watch every client statement identically: echo it into
// the recording and the live-monitoring hub, audit it, apply command control
// and in-session step-up, and latch the recording-size cap. Only two things are
// genuinely protocol-specific — how a refusal is written back to the client
// (PostgreSQL's pgproto3 ErrorResponse/ReadyForQuery versus SQL Server's TDS
// error token), and a handful of naming quirks (the "psql> "/"mssql> " prompt
// and the audit via-tag). This file captures the first behind the sqlClient
// interface and the second in the sqlPolicy value, so the policy logic lives in
// exactly one place and the two proxies cannot silently drift apart.
//
// Nothing here imports a wire-protocol package: each proxy supplies its own
// sqlClient implementation (pgSQLClient in dbproxy.go, mssqlSQLClient in
// mssqlproxy.go), so this file stays transport-agnostic.

import (
	"context"
	"errors"
	"fmt"
	"github.com/morandeirachema/pamv1/internal/auditfmt"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/cmdguard"
	"github.com/morandeirachema/pamv1/internal/restrict"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// sqlClient is the tiny protocol-specific surface the shared per-statement
// pipeline needs: how to refuse a single statement over the operator-facing
// wire. It captures ONLY refusals — everything else (audit, recording, live
// monitoring, step-up coordination) is protocol-independent and lives in the
// shared methods below.
//
// The two refusals differ in whether the session survives them. `refuse` leaves
// the session usable (PostgreSQL sends an ERROR ErrorResponse followed by a
// fresh ReadyForQuery; SQL Server sends a TDS error token, and with MARS off
// there is no pipelining to desync, so its session always stays usable).
// `refuseFatal` is the PostgreSQL extended-protocol fail-closed case: a Parse
// that is blocked or denied cannot be answered with a graceful error without
// desyncing the Parse/Bind/Execute stream, so it gets a FATAL ErrorResponse and
// the caller ends the session. TDS has no analogue, so the SQL Server proxy
// never asks for `extended` refusals and its refuseFatal is unreachable.
type sqlClient interface {
	// refuse rejects one statement, leaving the session usable. msg is the
	// client-facing message text.
	refuse(msg string)
	// refuseFatal rejects one statement fatally; the caller must end the session
	// afterwards. Used only by the PostgreSQL extended protocol.
	refuseFatal(msg string)
}

// sqlPolicy is the protocol-independent configuration the shared per-statement
// pipeline reads. Both database proxies build one at construction and hand a
// pointer to the shared methods, so the two share every policy knob and only
// their transport (the sqlClient) differs.
type sqlPolicy struct {
	// guard blocks statements matching its deny patterns (command control); a nil
	// guard blocks nothing. allowGuard (Phase 131), once non-nil, narrows this
	// path to ONLY statements it matches — deny still wins. stepupGuard marks
	// statements that require in-session supervisor approval; a nil stepupGuard
	// (or nil stepup) disables step-up.
	guard       *cmdguard.Guard
	allowGuard  *cmdguard.Guard
	stepupGuard *cmdguard.Guard
	// stepup coordinates the pause + supervisor decision; stepupTTL bounds how
	// long a paused statement waits before it is denied.
	stepup    *session.StepUp
	stepupTTL time.Duration
	// live publishes each recorded statement so a supervisor can watch the
	// session; nil-safe (a nil hub simply publishes nowhere).
	live *session.Hub
	// prompt is the recording/live-hub line prefix — "psql> " or "mssql> " — and
	// carries its own trailing space so it can be concatenated directly.
	prompt string
	// via is the protocol tag ("postgres" / "mssql") placed in the command.blocked
	// and session.record_limit audit details, on BOTH proxies.
	via string
	// viaInQuery reports whether the via tag ALSO appears in the db.query,
	// db.stepup_* and db.session.denied details. The PostgreSQL proxy predates the
	// tag and omits it from those (its single-database era), so it sets this false;
	// the SQL Server proxy adds " via:mssql" everywhere to disambiguate the shared
	// db.query vocabulary, so it sets this true. Preserving the difference keeps
	// existing audit details byte-for-byte stable.
	viaInQuery bool
}

// queryTag returns the via-fragment (" via:<proto>") used in the db.query,
// step-up and session-denied details, or "" when this proxy omits it there.
func (s *sqlPolicy) queryTag() string {
	if s.viaInQuery {
		return " via:" + s.via
	}
	return ""
}

// sqlRecordQuery audits and records a single SQL statement, and publishes it to
// the live hub so a supervisor can watch the session. It reports whether the
// recording size cap was reached, in which case the caller must END the session.
//
// The write error must not be discarded: Recording.Write LATCHES
// errRecordingLimit, so past PAM_MAX_RECORDING_MB every subsequent statement
// would otherwise be silently dropped and the session carry on UNRECORDED,
// indefinitely, with no session.record_limit audit — while the SSH path tears
// the session down. Both database proxies return limitReached and end the
// session; a non-limit write error (disk full, IO) is logged, not swallowed.
func sqlRecordQuery(ctx context.Context, l *listener, pol *sqlPolicy, rec *Recording, actor string, target *store.Target, sql, sid string) (limitReached bool) {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" {
		return false
	}
	l.audit(ctx, actor, "db.query", "target:"+target.Name+pol.queryTag()+" sql:"+auditCmd(trimmed))
	line := []byte(pol.prompt + trimmed + "\r\n")
	if rec != nil {
		if _, werr := rec.Write(line); werr != nil {
			if errors.Is(werr, errRecordingLimit) {
				l.audit(ctx, actor, "session.record_limit",
					"target:"+target.Name+" via:"+pol.via+" reason:recording-size-cap")
				l.log.Warn("ending session: recording size cap reached", "target", target.Name, "actor", actor)
				return true
			}
			l.log.Error("session recording write failed", "target", target.Name, "err", werr)
		}
	}
	pol.live.Publish(sid, line)
	return false
}

// sqlStepUpRefused reports whether a statement matched the step-up guard and its
// supervisor decision was a denial (or timeout) — in which case the caller
// refuses the statement. A match pauses the session (audited db.stepup_required,
// surfaced on the live hub) and blocks on a supervisor's decision via
// session.StepUp; an approval returns false so the statement proceeds (audited
// db.stepup_approved). No step-up configured, or no match, returns false
// immediately. When extended is true a denial refuses fatally (PostgreSQL
// extended protocol); otherwise the session stays usable.
func sqlStepUpRefused(ctx context.Context, l *listener, pol *sqlPolicy, cl sqlClient, actor string, target *store.Target, sql, sid string, extended bool) bool {
	if pol.stepupGuard == nil || pol.stepup == nil || sid == "" {
		return false
	}
	pat, match := pol.stepupGuard.Blocked(sql)
	if !match {
		return false
	}
	l.audit(ctx, actor, "db.stepup_required", fmt.Sprintf("target:%s%s pattern:%s sql:%s", target.Name, pol.queryTag(), pat, auditCmd(sql)))
	if pol.live != nil {
		pol.live.Publish(sid, []byte(pol.prompt+"[step-up: awaiting supervisor approval] "+strings.TrimSpace(sql)+"\r\n"))
	}
	if pol.stepup.Await(ctx, sid, actor, strings.TrimSpace(sql), pol.stepupTTL) {
		l.audit(ctx, actor, "db.stepup_approved", fmt.Sprintf("target:%s%s sql:%s", target.Name, pol.queryTag(), auditCmd(sql)))
		return false // approved — the statement proceeds
	}
	l.audit(ctx, actor, "db.stepup_denied", fmt.Sprintf("target:%s%s sql:%s", target.Name, pol.queryTag(), auditCmd(sql)))
	const msg = "PAMv1: statement requires supervisor approval (denied or timed out)"
	if extended {
		cl.refuseFatal(msg)
	} else {
		cl.refuse(msg)
	}
	return true
}

// sqlBlockedStatement reports whether sql is blocked by command control. When it
// is, it audits command.blocked and refuses the statement to the client: a
// graceful (usable) refusal for a simple statement, or a fatal refusal for a
// PostgreSQL extended-protocol Parse (extended=true), which the caller then ends.
//
// kill reports a restriction rule with action kill (Phase 275): the caller
// must END the session, not merely skip the statement. Until the review of
// 274-280 both relay loops treated it as an ordinary refusal and relayed the
// client's next statement, so a kill rule on SQL only ever refused.
func sqlBlockedStatement(ctx context.Context, l *listener, pol *sqlPolicy, cl sqlClient, actor string, target *store.Target, sql string, extended bool, rs *restrict.Set) (blocked, kill bool) {
	pat, blocked := cmdguard.Check(pol.guard, pol.allowGuard, sql)
	if !blocked {
		// The operator's own restriction set (Phase 275): a notify match is
		// on the record and runs; a kill match refuses the statement fatally,
		// which ends the session.
		if rm, ok := rs.Check("sql", sql); ok {
			detail := fmt.Sprintf("target:%s via:%s rule:%d pattern:%s sql:%s", target.Name, pol.via, rm.RuleID, auditValue(rm.Pattern, 128), auditCmd(sql))
			l.audit(ctx, actor, rm.AuditAction(), detail)
			if rm.Action == restrict.ActionNotify {
				return false, false
			}
			cl.refuseFatal("PAMv1: session ended by a restriction rule")
			return true, true
		}
		return false, false
	}
	l.audit(ctx, actor, "command.blocked", fmt.Sprintf("target:%s via:%s pattern:%s sql:%s", target.Name, pol.via, pat, auditCmd(sql)))
	const msg = "PAMv1: command blocked by policy"
	if extended {
		cl.refuseFatal(msg)
	} else {
		cl.refuse(msg)
	}
	return true, false
}

// auditValueDB renders an untrusted database name (unauthenticated wire input on
// both DB proxies) for a key:value audit detail, colon-escaped so it cannot
// forge a neighbouring field. See auditfmt.Value and the 2026-08-26 audit's M-1.
func auditValueDB(database string) string { return auditfmt.Value(database, 128) }

// sqlDeny audits a refused session (db.session.denied) and reports it to the
// client via the fail closure, which writes the protocol-specific login-failure
// token with the "PAMv1: <reason>" text. The caller logs the refusal itself, so
// each proxy's log line stays exactly as it was.
func sqlDeny(ctx context.Context, l *listener, pol *sqlPolicy, actor, login, reason string, fail func(msg string)) {
	l.audit(ctx, actor, "db.session.denied", "login:"+auditField(login, 64)+pol.queryTag()+" reason:"+reason)
	fail("PAMv1: " + reason)
}

// sqlFailKind is the class of a SQL listener's wire refusal. PostgreSQL gives
// each its own SQLSTATE (sqlstate); SQL Server sends the one login-failed
// error for all three.
type sqlFailKind int

const (
	sqlFailAuth  sqlFailKind = iota // refused: invalid authorization
	sqlFailCheck                    // a check could not run: fail closed
	sqlFailLimit                    // the concurrent-session cap
)

// sqlstate is the PostgreSQL error code for a kind of refusal.
func (k sqlFailKind) sqlstate() string {
	switch k {
	case sqlFailCheck:
		return "58000" // system_error
	case sqlFailLimit:
		return "53300" // too_many_connections
	default:
		return "28000" // invalid_authorization_specification
	}
}

// sqlRefuse maps an admit() refusal to a SQL listener's audit and wire
// refusal: the one table the PostgreSQL and SQL Server listeners share, so a
// gate's message and audit row cannot drift between them (until Phase 285
// each kept its own copy). proto is the target protocol the listener brokers,
// named in the wrong-protocol refusal; name labels the error log of a gate
// the table does not map. deny refuses through the listener's own deny, which
// logs, audits db.session.denied and fails with "PAMv1: <reason>"; fail writes
// the listener's wire refusal.
//
// admit already emitted the audits identical across all three proxies
// (access.denied for the approval and vendor denials, and
// credential.decrypt_failed) and the shared check-failed error logs; this adds
// only what is specific to the SQL listeners. gateProtocolProxyable is an
// SSH-only gate and gateTerminalTarget needs a terminal token, which a SQL
// listener refuses earlier as narrow-scoped; both fall to the default.
// TestSQLRefusalContract pins every row on both listeners.
func sqlRefuse(ctx context.Context, l *listener, res admitResult, actor, login, proto, name string, deny func(reason string), fail func(kind sqlFailKind, msg string)) {
	// audited refuses with a db.session.denied row of its own, for the gates
	// whose detail is not deny's.
	audited := func(detail string, kind sqlFailKind, msg string) {
		l.audit(ctx, actor, "db.session.denied", detail)
		fail(kind, msg)
	}
	switch res.gate {
	case gateTunnelOnly:
		// Audited here (with the short reason slug shared by the SSH proxy and the
		// HTTP authz middleware) and failed directly — NOT via deny(), which would
		// audit a second, differently-worded db.session.denied row for the same
		// refusal.
		audited("login:"+auditField(login, 64)+" reason:tunnel-only-token", sqlFailAuth, "PAMv1: this token may only be used by the in-portal viewer")
	case gateEnrollOnly:
		audited("login:"+auditField(login, 64)+" reason:mfa-enrollment-incomplete", sqlFailAuth, "PAMv1: complete MFA enrollment first")
	case gateExtensionOnly:
		audited("login:"+auditField(login, 64)+" reason:extension-scoped-token", sqlFailAuth, "PAMv1: a browser-extension token cannot open a database session")
	case gateMFAPending:
		audited("login:"+auditField(login, 64)+" reason:mfa-webauthn-pending", sqlFailAuth, "PAMv1: complete WebAuthn sign-in first")
	case gateRoleConnect:
		deny("your role may not open sessions")
	case gateIPAllowlist:
		deny("this account may not connect from this network")
	case gatePosture:
		deny("your device failed its posture check")
	case gateOnCall:
		deny("you are not currently on call")
	case gateResolve:
		deny(res.reason)
	case gateProtocolMatch:
		deny("target is not a " + proto + " target")
	case gateProtocolAllowed:
		deny("protocol not allowed by policy")
	case gateTargetGrants:
		// admit logged "target grants lookup failed"; fail closed on the wire.
		fail(sqlFailCheck, "PAMv1: authorization check failed")
	case gateTargetPolicy:
		deny("not authorized for this target")
	case gateSessionMFACheck:
		// admit logged the policy-lookup or ticket-spend error; fail closed.
		fail(sqlFailCheck, "PAMv1: authorization check failed")
	case gateSessionMFA:
		audited("target:"+res.target.Name+" reason:"+res.reason, sqlFailAuth, sessionMFARefusal(res.reason, false))
	case gateApprovalPolicy, gateApprovalClaim:
		// admit logged the specific approval error; fail closed on the wire.
		fail(sqlFailCheck, "PAMv1: approval check failed")
	case gateApproval:
		// admit already audited access.denied with the reason.
		fail(sqlFailAuth, "PAMv1: connection requires an approved access request")
	case gateVendorCheck:
		// admit logged "vendor gate check failed"; fail closed on the wire.
		fail(sqlFailCheck, "PAMv1: authorization check failed")
	case gateVendor:
		// admit already audited access.denied reason:vendor-contract.
		fail(sqlFailAuth, "PAMv1: vendor access requires an approved, in-window contract grant")
	case gateSessionLimit:
		audited("target:"+res.target.Name+" reason:session-limit", sqlFailLimit, "PAMv1: too many concurrent sessions")
	case gateAudit:
		// admit's fail-closed db.session.start write did not land; refuse.
		fail(sqlFailCheck, "PAMv1: audit log unavailable; session refused")
	case gateDecrypt:
		// admit already audited credential.decrypt_failed and logged the error.
		fail(sqlFailCheck, "PAMv1: credential unavailable")
	default:
		l.log.Error("unhandled admit refusal on the "+name+" proxy", "gate", int(res.gate), "actor", actor)
		fail(sqlFailCheck, "PAMv1: authorization check failed")
	}
}
