package proxy

// dbzsp.go implements Zero Standing Privilege for PostgreSQL targets (Phase
// 129, extending Phase 22's SSH-only ZSP): a db_zsp credential carries no
// stored secret. Instead, at dial time, pamv1 uses the target's separately
// vaulted "provisioner" credential to CREATE a fresh, randomly-named
// PostgreSQL role with a random password and a VALID UNTIL expiry, dials
// AGAIN as that ephemeral role for the real session, and DROPs the role when
// the session ends. Neither the provisioner's password nor the ephemeral
// role's password is ever seen by the operator — both exist only inside this
// process, in memory, for the span of a single connect.
//
// SQL Server is out of scope here: internal/tds only ever parses what a
// client sends (pamv1 acting as a TDS server) and has no code for reading a
// real server's response token stream, which issuing pamv1's own CREATE
// LOGIN would need — a genuinely separate piece of work, not attempted here.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/morandeirachema/pamv1/internal/store"
)

// zspRolePrefix marks every role this feature creates, so an operator
// reviewing `pg_roles` can immediately tell a pamv1-minted role from a real
// one — never reused for anything a human would name.
const zspRolePrefix = "pamv1_zsp_"

// zspRoleTTL is a hard safety-net expiry independent of teardown succeeding:
// even if the DROP ROLE call is lost (process killed mid-teardown, network
// partition), the role stops accepting new logins on its own.
const zspRoleTTL = 30 * time.Minute

// errNoProvisioner and errAmbiguousProvisioner are returned by
// findProvisioner; both are fail-closed — a db_zsp dial with no unambiguous
// provisioner is refused, never guessed at.
var (
	errNoProvisioner        = errors.New("target has no provisioner credential configured")
	errAmbiguousProvisioner = errors.New("target has more than one provisioner credential")
)

// findProvisioner returns the one credential on target flagged Provisioner,
// or a fail-closed error if none or more than one exists.
func findProvisioner(ctx context.Context, st store.Store, targetID int64) (*store.Credential, error) {
	creds, err := st.ListCredentials(ctx, targetID, 0, 0)
	if err != nil {
		return nil, err
	}
	var found *store.Credential
	for i := range creds {
		if !creds[i].Provisioner {
			continue
		}
		if found != nil {
			return nil, errAmbiguousProvisioner
		}
		c := creds[i]
		found = &c
	}
	if found == nil {
		return nil, errNoProvisioner
	}
	return found, nil
}

// randomIdentifier returns n random bytes as lowercase hex. It is pamv1's own
// randomness, never derived from client-controlled input, so embedding it in
// generated SQL (via the quoting helpers below) is not an injection surface.
func randomIdentifier(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// provisionPGRole dials target as provisioner and creates a fresh role only
// this process knows the password to, expiring VALID UNTIL zspRoleTTL from
// now as a safety net independent of teardown. Returns the new role's
// username/password; the caller must not attempt the real session without
// both a successful provisioner dial and a successful CREATE ROLE.
func (d *DBProxy) provisionPGRole(ctx context.Context, target *store.Target, provisioner *store.Credential, provisionerSecret string) (username, password string, err error) {
	suffix, err := randomIdentifier(8)
	if err != nil {
		return "", "", fmt.Errorf("generate role name: %w", err)
	}
	pw, err := randomIdentifier(24)
	if err != nil {
		return "", "", fmt.Errorf("generate role password: %w", err)
	}
	username = zspRolePrefix + suffix

	up, err := d.dialUpstream(ctx, target, provisioner.Username, provisionerSecret, "postgres")
	if err != nil {
		return "", "", fmt.Errorf("provisioner dial: %w", err)
	}
	defer up.conn.Close()

	validUntil := time.Now().Add(zspRoleTTL).UTC().Format(time.RFC3339)
	stmt := fmt.Sprintf("CREATE ROLE %s WITH LOGIN PASSWORD %s VALID UNTIL %s",
		pgQuoteIdent(username), pgQuoteLiteral(pw), pgQuoteLiteral(validUntil))
	if err := pgSimpleExec(up.fe, stmt); err != nil {
		return "", "", fmt.Errorf("create role: %w", err)
	}
	return username, pw, nil
}

// teardownPGRole dials target as provisioner and drops the ephemeral role.
// Best-effort by design: a failure here leaves an orphaned role that
// provisionPGRole's own VALID UNTIL will still expire on its own, so this
// audits the failure rather than retrying or blocking the caller.
func (d *DBProxy) teardownPGRole(ctx context.Context, actor string, target *store.Target, provisioner *store.Credential, provisionerSecret, ephemeralUser string) {
	up, err := d.dialUpstream(ctx, target, provisioner.Username, provisionerSecret, "postgres")
	if err != nil {
		d.audit(ctx, actor, "db.zsp_teardown_failed", fmt.Sprintf("target:%s role:%s error:%v", target.Name, ephemeralUser, err))
		return
	}
	defer up.conn.Close()
	if err := pgSimpleExec(up.fe, "DROP ROLE "+pgQuoteIdent(ephemeralUser)); err != nil {
		d.audit(ctx, actor, "db.zsp_teardown_failed", fmt.Sprintf("target:%s role:%s error:%v", target.Name, ephemeralUser, err))
		return
	}
	d.audit(ctx, actor, "db.zsp_teardown", fmt.Sprintf("target:%s role:%s", target.Name, ephemeralUser))
}

// pgSimpleExec sends stmt as a PostgreSQL simple-query message over fe and
// reads the response through ReadyForQuery, returning the server's own error
// if any. This is pamv1 acting as its own PostgreSQL client — distinct from
// the relay path (relay.go), which never originates a statement itself, only
// forwards the operator's.
func pgSimpleExec(fe *pgproto3.Frontend, stmt string) error {
	fe.Send(&pgproto3.Query{String: stmt})
	if err := fe.Flush(); err != nil {
		return err
	}
	for {
		msg, err := fe.Receive()
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			return fmt.Errorf("%s: %s", m.Code, m.Message)
		case *pgproto3.ReadyForQuery:
			return nil
		}
	}
}

// pgQuoteIdent double-quotes a PostgreSQL identifier, doubling any embedded
// double quote (the standard SQL identifier-quoting escape). Callers here
// only ever pass pamv1-generated hex identifiers, never client input, but the
// function quotes correctly regardless.
func pgQuoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// pgQuoteLiteral single-quotes a PostgreSQL string literal, doubling any
// embedded single quote (the standard SQL string-literal escape).
func pgQuoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
