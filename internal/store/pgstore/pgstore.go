// Package pgstore implements store.Store on PostgreSQL via pgx. Embedded,
// versioned migrations (migrations/*.sql, tracked in schema_migrations) are
// applied in order on startup.
package pgstore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/store"
)

const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
)

type PGStore struct {
	pool     *pgxpool.Pool
	log      *slog.Logger
	auditKey []byte // set ⇒ chain the primary audit trail (EnableAuditChain)
}

// Open connects to the Postgres database at url, verifies connectivity, applies
// pending migrations, and returns a ready PGStore.
func Open(ctx context.Context, url string) (*PGStore, error) {
	log := logging.Component("store")
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	// Trace every query at debug level (SQL text + duration + rows, never
	// arguments — those could carry ciphertext or token hashes).
	cfg.ConnConfig.Tracer = queryTracer{log: log}

	// HA resilience: after a CloudNativePG (or managed-Postgres) failover the
	// read-write endpoint re-points to a new primary, so recycle connections and
	// health-check idle ones — otherwise the pool would keep handing out
	// connections stapled to the demoted/dead primary. Callers only override
	// these by putting pool_* params in the URL (ParseConfig already applied them).
	if cfg.MaxConnLifetime == 0 {
		cfg.MaxConnLifetime = 30 * time.Minute
	}
	if cfg.MaxConnIdleTime == 0 {
		cfg.MaxConnIdleTime = 5 * time.Minute
	}
	if cfg.HealthCheckPeriod == 0 {
		cfg.HealthCheckPeriod = time.Minute
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	log.Info("connected to postgres", "host", cfg.ConnConfig.Host, "db", cfg.ConnConfig.Database)
	return &PGStore{pool: pool, log: log}, nil
}

// queryTracer logs each SQL statement's outcome. It implements pgx.QueryTracer.
type queryTracer struct{ log *slog.Logger }

type qtCtxKey struct{}

type qtState struct {
	start time.Time
	sql   string
}

// TraceQueryStart stashes the query text and start time in the context for
// TraceQueryEnd to log.
func (t queryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, qtCtxKey{}, qtState{start: time.Now(), sql: d.SQL})
}

// TraceQueryEnd logs the completed query's collapsed SQL, rows affected, and
// duration (errors other than no-rows are logged at error level).
func (t queryTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	st, _ := ctx.Value(qtCtxKey{}).(qtState)
	sql := strings.Join(strings.Fields(st.sql), " ") // collapse whitespace to one line
	if len(sql) > 120 {
		sql = sql[:120] + "…"
	}
	if d.Err != nil && !errors.Is(d.Err, pgx.ErrNoRows) {
		t.log.Error("query failed", "sql", sql, "err", d.Err)
		return
	}
	t.log.Debug("query", "sql", sql, "rows", d.CommandTag.RowsAffected(),
		"dur_ms", time.Since(st.start).Milliseconds())
}

// pgCode returns the PostgreSQL SQLSTATE code of err, or "" if err is not a pg error.
func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// getOne runs a single-row query, scanning with scan, and maps pgx.ErrNoRows to
// store.ErrNotFound — the shared shape of every Get* lookup.
func getOne[T any](ctx context.Context, pool *pgxpool.Pool, scan func(pgx.CollectableRow) (T, error), sql string, args ...any) (*T, error) {
	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	v, err := pgx.CollectExactlyOneRow(rows, scan)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// execExpectingRow runs an Exec that must affect a row, returning
// store.ErrNotFound when it affects none — the shared shape of Delete* and
// single-row Update* methods.
func execExpectingRow(ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) error {
	tag, err := pool.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// limitArg maps the shared list-window limit to a SQL LIMIT argument: NULL
// (no cap) when limit <= 0, so one query serves both the bounded HTTP reads
// and the unbounded in-process sweeps (Phase 44).
func limitArg(limit int) any {
	if limit <= 0 {
		return nil
	}
	return limit
}

// CreateTarget inserts a target, populating its ID and CreatedAt; ErrConflict if the name is taken.
func (s *PGStore) CreateTarget(ctx context.Context, t *store.Target) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO targets (name, host, port, os_type, protocol, require_approval, rdp_clipboard, rdp_clipboard_audit)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, created_at`,
		t.Name, t.Host, t.Port, t.OSType, t.Protocol, t.RequireApproval, t.RDPClipboard, t.RDPClipboardAudit,
	).Scan(&t.ID, &t.CreatedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// ListTargets returns targets in the (limit, afterID) window, ordered by ID.
func (s *PGStore) ListTargets(ctx context.Context, limit int, afterID int64) ([]store.Target, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, host, port, os_type, protocol, require_approval, safe_id, rdp_clipboard, rdp_clipboard_audit, created_at
		 FROM targets WHERE id > $1 ORDER BY id LIMIT $2`, afterID, limitArg(limit))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanTarget)
}

// UpdateTarget replaces a target's editable fields, refreshing t's SafeID and
// CreatedAt from the stored row; ErrNotFound if absent, ErrConflict if the new
// name belongs to another target.
func (s *PGStore) UpdateTarget(ctx context.Context, t *store.Target) error {
	err := s.pool.QueryRow(ctx,
		`UPDATE targets SET name = $1, host = $2, port = $3, os_type = $4, protocol = $5, require_approval = $6,
		        rdp_clipboard = $7, rdp_clipboard_audit = $8
		 WHERE id = $9 RETURNING safe_id, created_at`,
		t.Name, t.Host, t.Port, t.OSType, t.Protocol, t.RequireApproval, t.RDPClipboard, t.RDPClipboardAudit, t.ID,
	).Scan(&t.SafeID, &t.CreatedAt)
	switch {
	case pgCode(err) == pgUniqueViolation:
		return store.ErrConflict
	case errors.Is(err, pgx.ErrNoRows):
		return store.ErrNotFound
	}
	return err
}

// GetTarget returns the target with the given ID, or ErrNotFound.
func (s *PGStore) GetTarget(ctx context.Context, id int64) (*store.Target, error) {
	return getOne(ctx, s.pool, scanTarget,
		`SELECT id, name, host, port, os_type, protocol, require_approval, safe_id, rdp_clipboard, rdp_clipboard_audit, created_at
		 FROM targets WHERE id = $1`, id)
}

// DeleteTarget removes a target by ID (cascading via FK constraints); ErrNotFound if absent.
func (s *PGStore) DeleteTarget(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM targets WHERE id = $1`, id)
}

// CreateCredential inserts a credential, populating its ID and CreatedAt;
// ErrNotFound if the target does not exist.
func (s *PGStore) CreateCredential(ctx context.Context, c *store.Credential) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO credentials (target_id, username, secret_type, secret_enc, is_provisioner)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`,
		c.TargetID, c.Username, c.SecretType, c.SecretEnc, c.Provisioner,
	).Scan(&c.ID, &c.CreatedAt)
	if pgCode(err) == pgForeignKeyViolation {
		return store.ErrNotFound
	}
	return err
}

// ListCredentials returns credentials for one target (or all when targetID is
// 0) in the (limit, afterID) window, ordered by ID, WITH secret_enc — see the
// interface doc comment (store.Store) for why this must stay full-fidelity.
func (s *PGStore) ListCredentials(ctx context.Context, targetID int64, limit int, afterID int64) ([]store.Credential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, target_id, username, secret_type, secret_enc, is_provisioner, double_lock_holder, double_lock_verifier, double_lock_enc, created_at, rotated_at
		 FROM credentials WHERE ($1 = 0 OR target_id = $1) AND id > $2 ORDER BY id LIMIT $3`,
		targetID, afterID, limitArg(limit))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCredential)
}

// ListCredentialsMeta is ListCredentials without secret_enc, double_lock_verifier
// or double_lock_enc (Phase 145) — see the interface doc comment for which
// callers this is, and is not, safe for.
func (s *PGStore) ListCredentialsMeta(ctx context.Context, targetID int64, limit int, afterID int64) ([]store.Credential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, target_id, username, secret_type, is_provisioner, double_lock_holder, created_at, rotated_at
		 FROM credentials WHERE ($1 = 0 OR target_id = $1) AND id > $2 ORDER BY id LIMIT $3`,
		targetID, afterID, limitArg(limit))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCredentialMeta)
}

// GetCredential returns the credential with the given ID, or ErrNotFound.
func (s *PGStore) GetCredential(ctx context.Context, id int64) (*store.Credential, error) {
	return getOne(ctx, s.pool, scanCredential,
		`SELECT id, target_id, username, secret_type, secret_enc, is_provisioner, double_lock_holder, double_lock_verifier, double_lock_enc, created_at, rotated_at
		 FROM credentials WHERE id = $1`, id)
}

// UpdateCredentialSecretEnc replaces a credential's encrypted secret without
// touching rotated_at or DoubleLock; ErrNotFound if absent. Used only by the
// KEK re-wrap path (-rotate-kek): the plaintext is unchanged, only which KEK
// wraps it, so any DoubleLock (independent of the KEK entirely) stays valid.
func (s *PGStore) UpdateCredentialSecretEnc(ctx context.Context, id int64, secretEnc string) error {
	return execExpectingRow(ctx, s.pool, `UPDATE credentials SET secret_enc = $1 WHERE id = $2`, secretEnc, id)
}

// RotateCredentialSecret replaces the encrypted secret, stamps rotated_at, and
// clears any DoubleLock — the password-derived DoubleLockEnc now seals a
// stale secret and the password to reseal a new one isn't available here;
// ErrNotFound if absent.
func (s *PGStore) RotateCredentialSecret(ctx context.Context, id int64, secretEnc string, rotatedAt time.Time) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE credentials SET secret_enc = $1, rotated_at = $2, double_lock_holder = '', double_lock_verifier = '', double_lock_enc = '' WHERE id = $3`,
		secretEnc, rotatedAt.UTC(), id)
}

// SetCredentialDoubleLock enables DoubleLock on a credential; ErrNotFound if absent.
func (s *PGStore) SetCredentialDoubleLock(ctx context.Context, id int64, holder, verifier, enc string) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE credentials SET double_lock_holder = $1, double_lock_verifier = $2, double_lock_enc = $3 WHERE id = $4`,
		holder, verifier, enc, id)
}

// ClearCredentialDoubleLock disables DoubleLock on a credential; ErrNotFound if absent.
func (s *PGStore) ClearCredentialDoubleLock(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE credentials SET double_lock_holder = '', double_lock_verifier = '', double_lock_enc = '' WHERE id = $1`, id)
}

// CreateTargetGrant adds a grant, populating its ID; ErrConflict if an identical
// grant exists, ErrNotFound if the target is missing.
func (s *PGStore) CreateTargetGrant(ctx context.Context, g *store.TargetGrant) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO target_grants (target_id, subject_type, subject, created_by) VALUES ($1, $2, $3, $4) RETURNING id`,
		g.TargetID, g.SubjectType, g.Subject, g.CreatedBy,
	).Scan(&g.ID)
	switch pgCode(err) {
	case pgUniqueViolation:
		return store.ErrConflict
	case pgForeignKeyViolation:
		return store.ErrNotFound
	}
	return err
}

// ListTargetGrants returns the grants for a target, ordered by ID.
func (s *PGStore) ListTargetGrants(ctx context.Context, targetID int64) ([]store.TargetGrant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, target_id, subject_type, subject, created_by FROM target_grants WHERE target_id = $1 ORDER BY id`, targetID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.TargetGrant, error) {
		var g store.TargetGrant
		err := row.Scan(&g.ID, &g.TargetID, &g.SubjectType, &g.Subject, &g.CreatedBy)
		return g, err
	})
}

// DeleteTargetGrant removes a grant by ID; ErrNotFound if absent.
func (s *PGStore) DeleteTargetGrant(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM target_grants WHERE id = $1`, id)
}

// EffectiveTargetGrants unions a target's direct grants with grants derived from
// its safe's membership, so a target placed in a safe is reachable by the safe's
// members (Phase 17).
func (s *PGStore) EffectiveTargetGrants(ctx context.Context, targetID int64) ([]store.TargetGrant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, target_id, subject_type, subject FROM target_grants WHERE target_id = $1
		 UNION
		 SELECT sm.id, $1::bigint, sm.subject_type, sm.subject
		   FROM safe_members sm JOIN targets t ON t.safe_id = sm.safe_id
		  WHERE t.id = $1
		 ORDER BY id`, targetID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.TargetGrant, error) {
		var g store.TargetGrant
		err := row.Scan(&g.ID, &g.TargetID, &g.SubjectType, &g.Subject)
		return g, err
	})
}

// GrantsForSubjects returns every grant naming any of the given subjects, from
// both paths, in one round trip: the subject pairs are sent as two parallel
// text arrays and unnested into a join, so the query cost is one index scan per
// path rather than one query per target. See store.GrantStore for why the
// question is asked from the subject's side.
func (s *PGStore) GrantsForSubjects(ctx context.Context, subjects []store.GrantSubject) ([]store.SubjectGrant, error) {
	return grantsForSubjects(ctx, s.pool, subjects)
}

// reachQuerier is the sliver of pgxpool.Pool and pgx.Tx that the two
// subject-indexed grant reads need, so one implementation serves both.
type reachQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// ReachGrantSnapshot runs both grant reads inside one read-only REPEATABLE READ
// transaction, so the gated set and the subject's grants describe the same
// instant. READ COMMITTED would not do: it gives each STATEMENT its own
// snapshot, which is exactly the split this method exists to remove.
func (s *PGStore) ReachGrantSnapshot(ctx context.Context, subjects []store.GrantSubject) ([]store.SubjectGrant, []int64, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }() // read-only: nothing to commit
	grants, err := grantsForSubjects(ctx, tx, subjects)
	if err != nil {
		return nil, nil, err
	}
	gated, err := gatedTargetIDs(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	return grants, gated, nil
}

// grantsForSubjects is GrantsForSubjects' body, taking the querier so the same
// SQL can run on the pool or inside ReachGrantSnapshot's transaction.
func grantsForSubjects(ctx context.Context, q reachQuerier, subjects []store.GrantSubject) ([]store.SubjectGrant, error) {
	if len(subjects) == 0 {
		return []store.SubjectGrant{}, nil
	}
	types := make([]string, len(subjects))
	names := make([]string, len(subjects))
	for i, sub := range subjects {
		types[i], names[i] = sub.Type, sub.Name
	}
	rows, err := q.Query(ctx,
		`WITH subs AS (SELECT * FROM unnest($1::text[], $2::text[]) AS s(subject_type, subject))
		 SELECT g.target_id, t.name, g.subject_type, g.subject, 'grant'::text, NULL::bigint
		   FROM target_grants g
		   JOIN targets t ON t.id = g.target_id
		   JOIN subs ON subs.subject_type = g.subject_type AND subs.subject = g.subject
		 UNION ALL
		 SELECT t.id, t.name, sm.subject_type, sm.subject, 'safe'::text, sm.safe_id
		   FROM safe_members sm
		   JOIN targets t ON t.safe_id = sm.safe_id
		   JOIN subs ON subs.subject_type = sm.subject_type AND subs.subject = sm.subject
		 ORDER BY 1, 5, 4`, types, names)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.SubjectGrant, error) {
		var g store.SubjectGrant
		err := row.Scan(&g.TargetID, &g.TargetName, &g.SubjectType, &g.Subject, &g.Via, &g.SafeID)
		return g, err
	})
}

// GatedTargetIDs returns the ids of targets holding at least one effective
// grant, ascending — the targets that are NOT open to every connect-capable
// principal.
func (s *PGStore) GatedTargetIDs(ctx context.Context) ([]int64, error) {
	return gatedTargetIDs(ctx, s.pool)
}

// gatedTargetIDs is GatedTargetIDs' body, taking the querier for the same
// reason grantsForSubjects does.
func gatedTargetIDs(ctx context.Context, q reachQuerier) ([]int64, error) {
	rows, err := q.Query(ctx,
		`SELECT t.id FROM targets t
		  WHERE EXISTS (SELECT 1 FROM target_grants g WHERE g.target_id = t.id)
		     OR EXISTS (SELECT 1 FROM safe_members sm WHERE sm.safe_id = t.safe_id)
		  ORDER BY t.id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (int64, error) {
		var id int64
		err := row.Scan(&id)
		return id, err
	})
}

// CreateSafe inserts a safe, populating its ID and CreatedAt. Personal is
// set here and only here — see store.Safe.Personal.
func (s *PGStore) CreateSafe(ctx context.Context, sf *store.Safe) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO safes (name, description, require_approval, min_approvers, personal)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`,
		sf.Name, sf.Description, sf.RequireApproval, sf.MinApprovers, sf.Personal,
	).Scan(&sf.ID, &sf.CreatedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// ListSafes returns safes in the (limit, afterID) window, ordered by ID
// (creation order — the stable order a cursor needs).
func (s *PGStore) ListSafes(ctx context.Context, limit int, afterID int64) ([]store.Safe, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, description, created_at, require_approval, min_approvers, personal
		 FROM safes WHERE id > $1 ORDER BY id LIMIT $2`,
		afterID, limitArg(limit))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanSafe)
}

// UpdateSafe replaces a safe's name, description and approval policy,
// refreshing s.CreatedAt and s.Personal from the stored row; ErrNotFound if
// absent, ErrConflict if the new name belongs to another safe. Personal is
// deliberately NOT in the SET list — see store.Safe.Personal — so whatever
// the caller's struct happened to carry in that field is discarded in favor
// of the true stored value the RETURNING clause reads back.
func (s *PGStore) UpdateSafe(ctx context.Context, sf *store.Safe) error {
	err := s.pool.QueryRow(ctx,
		`UPDATE safes SET name = $1, description = $2, require_approval = $3, min_approvers = $4
		 WHERE id = $5 RETURNING created_at, personal`,
		sf.Name, sf.Description, sf.RequireApproval, sf.MinApprovers, sf.ID,
	).Scan(&sf.CreatedAt, &sf.Personal)
	switch {
	case pgCode(err) == pgUniqueViolation:
		return store.ErrConflict
	case errors.Is(err, pgx.ErrNoRows):
		return store.ErrNotFound
	}
	return err
}

// GetSafe returns a safe by ID, or ErrNotFound.
func (s *PGStore) GetSafe(ctx context.Context, id int64) (*store.Safe, error) {
	return getOne(ctx, s.pool, scanSafe,
		`SELECT id, name, description, created_at, require_approval, min_approvers, personal FROM safes WHERE id = $1`, id)
}

// DeleteSafe removes a safe by ID (members cascade; targets are unassigned).
func (s *PGStore) DeleteSafe(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM safes WHERE id = $1`, id)
}

// AddSafeMember adds a member to a safe.
func (s *PGStore) AddSafeMember(ctx context.Context, m *store.SafeMember) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO safe_members (safe_id, subject_type, subject, can_manage, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		m.SafeID, m.SubjectType, m.Subject, m.CanManage, m.CreatedBy,
	).Scan(&m.ID)
	switch pgCode(err) {
	case pgUniqueViolation:
		return store.ErrConflict
	case pgForeignKeyViolation:
		return store.ErrNotFound
	}
	return err
}

// ListSafeMembers returns a safe's members ordered by id.
func (s *PGStore) ListSafeMembers(ctx context.Context, safeID int64) ([]store.SafeMember, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, safe_id, subject_type, subject, can_manage, created_by FROM safe_members WHERE safe_id = $1 ORDER BY id`, safeID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.SafeMember, error) {
		var m store.SafeMember
		err := row.Scan(&m.ID, &m.SafeID, &m.SubjectType, &m.Subject, &m.CanManage, &m.CreatedBy)
		return m, err
	})
}

// DeleteSafeMember removes a safe member by ID, or ErrNotFound.
func (s *PGStore) DeleteSafeMember(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM safe_members WHERE id = $1`, id)
}

// AssignTargetSafe sets (or clears, when safeID is nil) a target's safe.
func (s *PGStore) AssignTargetSafe(ctx context.Context, targetID int64, safeID *int64) error {
	return execExpectingRow(ctx, s.pool, `UPDATE targets SET safe_id = $2 WHERE id = $1`, targetID, safeID)
}

// CreateCredentialDependency declares a consumer of a credential.
func (s *PGStore) CreateCredentialDependency(ctx context.Context, d *store.CredentialDependency) error {
	if d.Port == 0 {
		d.Port = 5985
	}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO credential_dependencies (credential_id, kind, host, port, name, management_credential_id)
		 VALUES ($1, $2, $3, $4, $5, NULLIF($6, 0)::BIGINT) RETURNING id`,
		d.CredentialID, d.Kind, d.Host, d.Port, d.Name, d.ManagementCredentialID,
	).Scan(&d.ID)
	if pgCode(err) == pgForeignKeyViolation {
		return store.ErrNotFound
	}
	return err
}

// ListCredentialDependencies returns a credential's declared consumers.
func (s *PGStore) ListCredentialDependencies(ctx context.Context, credentialID int64) ([]store.CredentialDependency, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, credential_id, kind, host, port, name, COALESCE(management_credential_id, 0)
		 FROM credential_dependencies WHERE credential_id = $1 ORDER BY id`, credentialID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.CredentialDependency, error) {
		var d store.CredentialDependency
		err := row.Scan(&d.ID, &d.CredentialID, &d.Kind, &d.Host, &d.Port, &d.Name, &d.ManagementCredentialID)
		return d, err
	})
}

// DeleteCredentialDependency removes a dependency by ID, or ErrNotFound.
func (s *PGStore) DeleteCredentialDependency(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM credential_dependencies WHERE id = $1`, id)
}

// CreateCampaign inserts a certification campaign, populating ID and CreatedAt.
func (s *PGStore) CreateCampaign(ctx context.Context, c *store.Campaign) error {
	if c.Status == "" {
		c.Status = "open"
	}
	return s.pool.QueryRow(ctx,
		`INSERT INTO campaigns (name, created_by, due_at, status, scope_kind, scope_safe_id, scope_subject, recur_days, next_run_at, reviewer, remind_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id, created_at`,
		c.Name, c.CreatedBy, c.DueAt, c.Status,
		string(c.ScopeKind), c.ScopeSafeID, c.ScopeSubject, c.RecurDays, c.NextRunAt, c.Reviewer, c.RemindAt,
	).Scan(&c.ID, &c.CreatedAt)
}

// campaignCols is the one column list every campaign read uses, so a field
// cannot reach some reads and quietly miss others.
const campaignCols = `id, name, created_by, created_at, due_at, status, closed_at,
	scope_kind, scope_safe_id, scope_subject, recur_days, next_run_at, reviewer, remind_at`

// ListCampaigns returns all campaigns, newest first.
func (s *PGStore) ListCampaigns(ctx context.Context) ([]store.Campaign, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+campaignCols+` FROM campaigns ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCampaign)
}

// GetCampaign returns a campaign by ID, or ErrNotFound.
func (s *PGStore) GetCampaign(ctx context.Context, id int64) (*store.Campaign, error) {
	return getOne(ctx, s.pool, scanCampaign, `SELECT `+campaignCols+` FROM campaigns WHERE id = $1`, id)
}

// CloseCampaign marks a campaign closed at the given time.
func (s *PGStore) CloseCampaign(ctx context.Context, id int64, at time.Time) error {
	return execExpectingRow(ctx, s.pool, `UPDATE campaigns SET status = 'closed', closed_at = $2 WHERE id = $1`, id, at)
}

// ListDueCampaigns returns the open recurring anchors whose next run has
// arrived, oldest first. The predicate matches the partial index in migration
// 0029, so this stays a lookup rather than a scan of every campaign ever run.
func (s *PGStore) ListDueCampaigns(ctx context.Context, now time.Time) ([]store.Campaign, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+campaignCols+` FROM campaigns
		WHERE status = 'open' AND recur_days > 0 AND next_run_at IS NOT NULL AND next_run_at <= $1
		ORDER BY next_run_at, id`, now)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCampaign)
}

// ListCampaignsToRemind returns the open campaigns whose reminder has come due.
func (s *PGStore) ListCampaignsToRemind(ctx context.Context, now time.Time) ([]store.Campaign, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+campaignCols+` FROM campaigns
		WHERE status = 'open' AND remind_at IS NOT NULL AND remind_at <= $1
		ORDER BY remind_at, id`, now)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCampaign)
}

// SetCampaignRemindAt schedules or cancels a campaign's next reminder.
func (s *PGStore) SetCampaignRemindAt(ctx context.Context, id int64, at *time.Time) error {
	return execExpectingRow(ctx, s.pool, `UPDATE campaigns SET remind_at = $2 WHERE id = $1`, id, at)
}

// SetCampaignNextRun moves an anchor's next occurrence.
func (s *PGStore) SetCampaignNextRun(ctx context.Context, id int64, next time.Time) error {
	return execExpectingRow(ctx, s.pool, `UPDATE campaigns SET next_run_at = $2 WHERE id = $1`, id, next)
}

// AddCampaignItem adds one access item to a campaign.
func (s *PGStore) AddCampaignItem(ctx context.Context, item *store.CampaignItem) error {
	if item.Decision == "" {
		item.Decision = "pending"
	}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO campaign_items (campaign_id, kind, ref_id, subject_type, subject, detail, granted_by, decision, reviewer)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		item.CampaignID, item.Kind, item.RefID, item.SubjectType, item.Subject, item.Detail, item.GrantedBy, item.Decision, item.Reviewer,
	).Scan(&item.ID)
	if pgCode(err) == pgForeignKeyViolation {
		return store.ErrNotFound
	}
	return err
}

// ListCampaignItems returns a campaign's items ordered by id.
func (s *PGStore) ListCampaignItems(ctx context.Context, campaignID int64) ([]store.CampaignItem, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+campaignItemCols+` FROM campaign_items WHERE campaign_id = $1 ORDER BY id`, campaignID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCampaignItem)
}

// GetCampaignItem returns one item by ID, or ErrNotFound.
func (s *PGStore) GetCampaignItem(ctx context.Context, id int64) (*store.CampaignItem, error) {
	return getOne(ctx, s.pool, scanCampaignItem, `SELECT `+campaignItemCols+` FROM campaign_items WHERE id = $1`, id)
}

// DecideCampaignItem records a certify/revoke decision on an item.
func (s *PGStore) DecideCampaignItem(ctx context.Context, id int64, decision, decidedBy string, at time.Time) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE campaign_items SET decision = $2, decided_by = $3, decided_at = $4 WHERE id = $1`, id, decision, decidedBy, at)
}

// SetCampaignItemReviewer reassigns one item.
func (s *PGStore) SetCampaignItemReviewer(ctx context.Context, itemID int64, reviewer string) error {
	return execExpectingRow(ctx, s.pool, `UPDATE campaign_items SET reviewer = $2 WHERE id = $1`, itemID, reviewer)
}

// ListItemsForReviewer returns the pending items assigned to reviewer across
// every open campaign, oldest first. The join is what makes it a queue: a closed
// campaign's leftovers are not work anybody should still be shown.
func (s *PGStore) ListItemsForReviewer(ctx context.Context, reviewer string) ([]store.CampaignItem, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+prefixed(campaignItemCols, "i.")+`
		FROM campaign_items i JOIN campaigns c ON c.id = i.campaign_id
		WHERE i.reviewer = $1 AND i.decision = 'pending' AND c.status = 'open'
		ORDER BY i.id`, reviewer)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCampaignItem)
}

// prefixed qualifies a comma-separated column list with a table alias, so the
// one column list stays the single source of truth even in a join.
func prefixed(cols, alias string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = alias + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}

const campaignItemCols = `id, campaign_id, kind, ref_id, subject_type, subject, detail, granted_by, decision, decided_by, decided_at, reviewer`

// scanCampaign scans one campaign row.
func scanCampaign(row pgx.CollectableRow) (store.Campaign, error) {
	var c store.Campaign
	var scope string
	err := row.Scan(&c.ID, &c.Name, &c.CreatedBy, &c.CreatedAt, &c.DueAt, &c.Status, &c.ClosedAt,
		&scope, &c.ScopeSafeID, &c.ScopeSubject, &c.RecurDays, &c.NextRunAt, &c.Reviewer, &c.RemindAt)
	c.ScopeKind = store.CampaignScope(scope)
	return c, err
}

// scanCampaignItem scans one campaign-item row.
func scanCampaignItem(row pgx.CollectableRow) (store.CampaignItem, error) {
	var it store.CampaignItem
	err := row.Scan(&it.ID, &it.CampaignID, &it.Kind, &it.RefID, &it.SubjectType, &it.Subject, &it.Detail, &it.GrantedBy, &it.Decision, &it.DecidedBy, &it.DecidedAt, &it.Reviewer)
	return it, err
}

// scanSafe scans one safe row.
func scanSafe(row pgx.CollectableRow) (store.Safe, error) {
	var sf store.Safe
	err := row.Scan(&sf.ID, &sf.Name, &sf.Description, &sf.CreatedAt, &sf.RequireApproval, &sf.MinApprovers, &sf.Personal)
	return sf, err
}

// DeleteCredential removes a credential by ID; ErrNotFound if absent.
func (s *PGStore) DeleteCredential(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM credentials WHERE id = $1`, id)
}

// accessRequestCols is the one column list every access-request read uses, so
// a field cannot reach some reads and quietly miss others.
const accessRequestCols = `id, requester, target_id, reason, status, approver, created_at, decided_at,
	expires_at, ticket, required_approvals, approved_by, not_before, one_time, consumed_at, recur_days, next_run_at`

// CreateAccessRequest inserts a request (defaulting status to pending),
// populating its ID and CreatedAt; ErrNotFound if the target is missing.
func (s *PGStore) CreateAccessRequest(ctx context.Context, ar *store.AccessRequest) error {
	if ar.Status == "" {
		ar.Status = "pending"
	}
	if ar.RequiredApprovals < 1 {
		ar.RequiredApprovals = 1
	}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO access_requests (requester, target_id, reason, status, expires_at, ticket, required_approvals, not_before, one_time, recur_days)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id, created_at`,
		ar.Requester, ar.TargetID, ar.Reason, ar.Status, ar.ExpiresAt, ar.Ticket, ar.RequiredApprovals, ar.NotBefore, ar.OneTime, ar.RecurDays,
	).Scan(&ar.ID, &ar.CreatedAt)
	if pgCode(err) == pgForeignKeyViolation {
		return store.ErrNotFound
	}
	return err
}

// GetAccessRequest returns the access request with the given ID, or ErrNotFound.
func (s *PGStore) GetAccessRequest(ctx context.Context, id int64) (*store.AccessRequest, error) {
	return getOne(ctx, s.pool, scanAccessRequest,
		`SELECT `+accessRequestCols+`
		 FROM access_requests WHERE id = $1`, id)
}

// ListAccessRequests returns requests with the given status (all when status is
// "") in the (limit, afterID) window, ordered by ID.
func (s *PGStore) ListAccessRequests(ctx context.Context, status string, limit int, afterID int64) ([]store.AccessRequest, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+accessRequestCols+`
		 FROM access_requests WHERE ($1 = '' OR status = $1) AND id > $2 ORDER BY id LIMIT $3`,
		status, afterID, limitArg(limit))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAccessRequest)
}

// DecideAccessRequest records an approve/deny decision, approver, and decision
// time; ErrNotFound if the request is missing.
func (s *PGStore) DecideAccessRequest(ctx context.Context, id int64, status, approver string, decidedAt time.Time) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE access_requests SET status = $1, approver = $2, decided_at = $3 WHERE id = $4`,
		status, approver, decidedAt.UTC(), id)
}

// ListDueAccessRequests returns the approved recurring anchors whose next run
// has arrived, oldest first.
func (s *PGStore) ListDueAccessRequests(ctx context.Context, now time.Time) ([]store.AccessRequest, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+accessRequestCols+` FROM access_requests
		WHERE status = 'approved' AND recur_days > 0 AND next_run_at IS NOT NULL AND next_run_at <= $1
		ORDER BY next_run_at, id`, now)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAccessRequest)
}

// SetAccessRequestNextRun moves an anchor's next occurrence.
func (s *PGStore) SetAccessRequestNextRun(ctx context.Context, id int64, next time.Time) error {
	return execExpectingRow(ctx, s.pool, `UPDATE access_requests SET next_run_at = $2 WHERE id = $1`, id, next)
}

// StopAccessRequestRecurrence ends a recurring anchor's series.
func (s *PGStore) StopAccessRequestRecurrence(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE access_requests SET recur_days = 0, next_run_at = NULL WHERE id = $1`, id)
}

// HasActiveApproval reports whether requester has an approved, unexpired request
// for targetID as of now. A consumed single-use approval is not active.
func (s *PGStore) HasActiveApproval(ctx context.Context, requester string, targetID int64, now time.Time) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM access_requests
			WHERE requester = $1 AND target_id = $2 AND status = 'approved'
			  AND expires_at > $3 AND (not_before IS NULL OR not_before <= $3)
			  AND (NOT one_time OR consumed_at IS NULL))`,
		requester, targetID, now.UTC()).Scan(&exists)
	return exists, err
}

// ActiveApprovals returns every approval that could admit requester to targetID
// as of now, without consuming any of them. The ORDER BY mirrors
// ConsumeApproval's selection — standing approvals first (`one_time` sorts
// false before true), then the oldest — so the caller walks them in the order
// the store would have picked them.
func (s *PGStore) ActiveApprovals(ctx context.Context, requester string, targetID int64, now time.Time, limit int) ([]store.AccessRequest, error) {
	if limit <= 0 {
		limit = 1
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+accessRequestCols+`
		 FROM access_requests
		 WHERE requester = $1 AND target_id = $2 AND status = 'approved'
		   AND expires_at > $3 AND (not_before IS NULL OR not_before <= $3)
		   AND (NOT one_time OR consumed_at IS NULL)
		 ORDER BY one_time, id LIMIT $4`,
		requester, targetID, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAccessRequest)
}

// ConsumeApproval reports whether requester holds an active approval for
// targetID and, when the only active approval is single-use, atomically burns
// it (stamps consumed_at) so it cannot admit a second use. A standing
// approval, when present, is preferred and left untouched. The UPDATE takes
// the row lock, so of two racing consumers exactly one burns the approval —
// the other sees no eligible row and is refused.
func (s *PGStore) ConsumeApproval(ctx context.Context, requester string, targetID int64, now time.Time) (bool, int64, error) {
	var standing bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM access_requests
			WHERE requester = $1 AND target_id = $2 AND status = 'approved'
			  AND expires_at > $3 AND (not_before IS NULL OR not_before <= $3)
			  AND NOT one_time)`,
		requester, targetID, now.UTC()).Scan(&standing)
	if err != nil {
		return false, 0, err
	}
	if standing {
		return true, 0, nil
	}
	var id int64
	err = s.pool.QueryRow(ctx,
		`UPDATE access_requests SET consumed_at = $3
		 WHERE id = (
			SELECT id FROM access_requests
			WHERE requester = $1 AND target_id = $2 AND status = 'approved'
			  AND expires_at > $3 AND (not_before IS NULL OR not_before <= $3)
			  AND one_time AND consumed_at IS NULL
			ORDER BY id LIMIT 1
			FOR UPDATE SKIP LOCKED)
		 RETURNING id`,
		requester, targetID, now.UTC()).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	return true, id, nil
}

// ConsumeApprovalByID claims the one approval the caller named. The active
// predicate is repeated in the UPDATE's WHERE — not taken from the read — so
// the burn is a compare-and-set: two connections racing for the same
// single-use approval both see `consumed_at IS NULL`, the row lock serializes
// them, and the loser's UPDATE matches nothing and returns ok=false. That is
// the caller's cue to try its next candidate, not an error.
//
// A standing approval is never burned, so it takes the cheap path: confirming
// it is active is the whole job, and writing to it on every connect would
// churn the row for nothing.
func (s *PGStore) ConsumeApprovalByID(ctx context.Context, id int64, requester string, targetID int64, now time.Time) (bool, error) {
	var oneTime bool
	err := s.pool.QueryRow(ctx,
		`SELECT one_time FROM access_requests
		 WHERE id = $1 AND requester = $2 AND target_id = $3 AND status = 'approved'
		   AND expires_at > $4 AND (not_before IS NULL OR not_before <= $4)
		   AND (NOT one_time OR consumed_at IS NULL)`,
		id, requester, targetID, now.UTC()).Scan(&oneTime)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !oneTime {
		return true, nil
	}
	var burned int64
	err = s.pool.QueryRow(ctx,
		`UPDATE access_requests SET consumed_at = $4
		 WHERE id = $1 AND requester = $2 AND target_id = $3 AND status = 'approved'
		   AND expires_at > $4 AND (not_before IS NULL OR not_before <= $4)
		   AND one_time AND consumed_at IS NULL
		 RETURNING id`,
		id, requester, targetID, now.UTC()).Scan(&burned)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // a concurrent use burned it first
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// SetApprovalState records a multi-approver decision (Phase 21).
func (s *PGStore) SetApprovalState(ctx context.Context, id int64, approvedBy, status, approver string, decidedAt *time.Time) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE access_requests SET approved_by = $2, status = $3, approver = $4, decided_at = $5 WHERE id = $1`,
		id, approvedBy, status, approver, decidedAt)
}

// auditChainLockKey serializes chained audit appends across every process sharing
// this database, so the hash chain over audit_events cannot fork. Distinct from
// the migration/broker/leader lock keys.
const auditChainLockKey = int64(0x70616d5f61756463) // "pam_audc"

// EnableAuditChain turns on tamper-evident chaining of the primary audit trail.
func (s *PGStore) EnableAuditChain(key []byte) { s.auditKey = key }

// AppendAudit inserts an audit event, populating its ID and TS. With an audit key
// configured it links the event into the tamper-evident chain in the same
// transaction, under an advisory lock so concurrent writers can't fork the chain.
func (s *PGStore) AppendAudit(ctx context.Context, e *store.AuditEvent) error {
	if len(s.auditKey) == 0 {
		return s.pool.QueryRow(ctx,
			`INSERT INTO audit_events (actor, action, detail)
			 VALUES ($1, $2, $3) RETURNING id, ts`,
			e.Actor, e.Action, e.Detail,
		).Scan(&e.ID, &e.TS)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditChainLockKey); err != nil {
		return err
	}
	var prev []byte
	if err := tx.QueryRow(ctx,
		`SELECT hmac FROM audit_events WHERE hmac IS NOT NULL ORDER BY id DESC LIMIT 1`).Scan(&prev); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	e.PrevHash = prev
	e.HMAC = store.AuditMAC(s.auditKey, prev, e)
	if err := tx.QueryRow(ctx,
		`INSERT INTO audit_events (actor, action, detail, prev_hash, hmac)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id, ts`,
		e.Actor, e.Action, e.Detail, e.PrevHash, e.HMAC,
	).Scan(&e.ID, &e.TS); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// GetAuditHead returns the most recent chained audit event, or (nil, nil) if none.
func (s *PGStore) GetAuditHead(ctx context.Context) (*store.AuditEvent, error) {
	var e store.AuditEvent
	err := s.pool.QueryRow(ctx,
		`SELECT id, ts, actor, action, detail, prev_hash, hmac
		 FROM audit_events WHERE hmac IS NOT NULL ORDER BY id DESC LIMIT 1`).
		Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.Detail, &e.PrevHash, &e.HMAC)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// VerifyAuditChain recomputes the chain over every chained audit event in id
// order and reports the first id whose HMAC does not match (0 when intact).
func (s *PGStore) VerifyAuditChain(ctx context.Context) (bool, int64, error) {
	if len(s.auditKey) == 0 {
		return false, 0, errors.New("pgstore: audit chain not enabled")
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, actor, action, detail, prev_hash, hmac
		 FROM audit_events WHERE hmac IS NOT NULL ORDER BY id ASC`)
	if err != nil {
		return false, 0, err
	}
	defer rows.Close()
	var prev []byte
	for rows.Next() {
		var e store.AuditEvent
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Detail, &e.PrevHash, &e.HMAC); err != nil {
			return false, 0, err
		}
		want := store.AuditMAC(s.auditKey, prev, &e)
		if !hmac.Equal(want, e.HMAC) || !bytes.Equal(prev, e.PrevHash) {
			return false, e.ID, nil
		}
		prev = e.HMAC
	}
	return true, 0, rows.Err()
}

// ListAudit returns the most recent audit events, newest first, applying the
// limit semantics defined on store.Store: non-positive means the default page,
// and an oversized limit is CAPPED at store.MaxAuditPage rather than collapsed
// back to the default (which is what this function used to do, so a caller
// asking for 2000 silently received 100 here while receiving all 2000 from
// memstore).
func (s *PGStore) ListAudit(ctx context.Context, limit int) ([]store.AuditEvent, error) {
	limit = store.ClampAuditLimit(limit)
	rows, err := s.pool.Query(ctx,
		`SELECT id, ts, actor, action, detail
		 FROM audit_events ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAuditEvent)
}

// CreateCheckout leases a credential within a transaction; ErrConflict if it
// already has an active checkout as of now, ErrNotFound if the credential is missing.
func (s *PGStore) CreateCheckout(ctx context.Context, co *store.Checkout, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Auto-close expired-but-unreturned leases so an expired lease does not block
	// a new checkout (and does not collide with the partial unique index below).
	if _, err := tx.Exec(ctx,
		`UPDATE checkouts SET returned_at = $2
		 WHERE credential_id = $1 AND returned_at IS NULL AND expires_at <= $2`,
		co.CredentialID, now.UTC()); err != nil {
		return err
	}
	// Exclusivity is enforced atomically by the checkouts_one_active_idx partial
	// unique index: a concurrent second insert fails with a unique violation
	// rather than both check-then-inserts racing to success.
	err = tx.QueryRow(ctx,
		`INSERT INTO checkouts (credential_id, target_id, holder, reason, expires_at)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id, checked_out_at`,
		co.CredentialID, co.TargetID, co.Holder, co.Reason, co.ExpiresAt,
	).Scan(&co.ID, &co.CheckedOutAt)
	switch pgCode(err) {
	case pgUniqueViolation:
		return store.ErrConflict
	case pgForeignKeyViolation:
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// checkoutCols is the one column list every checkout read uses, so a field
// cannot reach some reads and quietly miss others.
const checkoutCols = `id, credential_id, target_id, holder, reason, checked_out_at, expires_at, returned_at`

// GetActiveCheckout returns the credential's active (unreturned, unexpired)
// checkout as of now, or ErrNotFound.
func (s *PGStore) GetActiveCheckout(ctx context.Context, credentialID int64, now time.Time) (*store.Checkout, error) {
	return getOne(ctx, s.pool, scanCheckout,
		`SELECT `+checkoutCols+`
		 FROM checkouts
		 WHERE credential_id = $1 AND returned_at IS NULL AND expires_at > $2
		 ORDER BY id DESC LIMIT 1`, credentialID, now.UTC())
}

// CheckinCheckout marks a checkout returned; ErrNotFound if missing or already returned.
func (s *PGStore) CheckinCheckout(ctx context.Context, id int64, at time.Time) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE checkouts SET returned_at = $1 WHERE id = $2 AND returned_at IS NULL`, at.UTC(), id)
}

// ListCheckouts returns checkouts in the (limit, afterID) window, ordered by
// ID; activeOnly limits to unreturned, unexpired ones as of now.
func (s *PGStore) ListCheckouts(ctx context.Context, activeOnly bool, now time.Time, limit int, afterID int64) ([]store.Checkout, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+checkoutCols+`
		 FROM checkouts
		 WHERE ((NOT $1) OR (returned_at IS NULL AND expires_at > $2)) AND id > $3
		 ORDER BY id LIMIT $4`, activeOnly, now.UTC(), afterID, limitArg(limit))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCheckout)
}

// GetCheckout returns one checkout by ID, or ErrNotFound.
func (s *PGStore) GetCheckout(ctx context.Context, id int64) (*store.Checkout, error) {
	return getOne(ctx, s.pool, scanCheckout, `SELECT `+checkoutCols+` FROM checkouts WHERE id = $1`, id)
}

// ExtendCheckout pushes an active (unreturned, unexpired as of now) checkout's
// expiry to newExpiresAt; ErrNotFound if missing, already returned, or already
// expired.
func (s *PGStore) ExtendCheckout(ctx context.Context, id int64, newExpiresAt, now time.Time) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE checkouts SET expires_at = $2 WHERE id = $1 AND returned_at IS NULL AND expires_at > $3`,
		id, newExpiresAt.UTC(), now.UTC())
}

// RecordPasswordHistory appends secretHash to credentialID's history and
// prunes anything beyond the most recent keep entries, in one transaction.
func (s *PGStore) RecordPasswordHistory(ctx context.Context, credentialID int64, secretHash string, at time.Time, keep int) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`INSERT INTO password_history (credential_id, secret_hash, created_at) VALUES ($1, $2, $3)`,
		credentialID, secretHash, at.UTC()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM password_history WHERE credential_id = $1 AND id NOT IN (
			SELECT id FROM password_history WHERE credential_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2)`,
		credentialID, keep); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RecentPasswordHashes returns up to limit of a credential's most recent
// rotation hashes, newest first.
func (s *PGStore) RecentPasswordHashes(ctx context.Context, credentialID int64, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT secret_hash FROM password_history WHERE credential_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2`,
		credentialID, limitArg(limit))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (string, error) {
		var h string
		err := row.Scan(&h)
		return h, err
	})
}

// scanCheckout maps one result row into a store.Checkout.
func scanCheckout(row pgx.CollectableRow) (store.Checkout, error) {
	var co store.Checkout
	err := row.Scan(&co.ID, &co.CredentialID, &co.TargetID, &co.Holder, &co.Reason,
		&co.CheckedOutAt, &co.ExpiresAt, &co.ReturnedAt)
	return co, err
}

// ExportAudit returns audit events with since <= ts < until, oldest-first; a
// zero since means from the beginning and a zero until means up to now.
func (s *PGStore) ExportAudit(ctx context.Context, since, until time.Time) ([]store.AuditEvent, error) {
	if until.IsZero() {
		until = time.Now()
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, ts, actor, action, detail
		 FROM audit_events
		 WHERE ($1::timestamptz IS NULL OR ts >= $1) AND ts < $2
		 ORDER BY id ASC`, nullableTime(since), until.UTC())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAuditEvent)
}

// LatestAuditByAction returns the most recent event with the given action, or
// (nil, nil) if there is none.
//
// This runs from periodic maintenance (the retention archiver), not a request
// path, so an index scan on id descending filtered by action is an acceptable
// cost — and it is bounded by LIMIT 1 rather than by a page size that could miss
// the row entirely.
func (s *PGStore) LatestAuditByAction(ctx context.Context, action string) (*store.AuditEvent, error) {
	var e store.AuditEvent
	err := s.pool.QueryRow(ctx,
		`SELECT id, ts, actor, action, detail FROM audit_events
		 WHERE action = $1 ORDER BY id DESC LIMIT 1`, action).
		Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.Detail)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// AuditSince returns up to limit audit events with id > afterID, oldest-first —
// the cursor read the SIEM forwarder tails the trail with.
func (s *PGStore) AuditSince(ctx context.Context, afterID int64, limit int) ([]store.AuditEvent, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, ts, actor, action, detail
		 FROM audit_events
		 WHERE id > $1
		 ORDER BY id ASC
		 LIMIT $2`, afterID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAuditEvent)
}

// PruneAuditBefore deletes audit events with ts < cutoff, returning the count.
func (s *PGStore) PruneAuditBefore(ctx context.Context, cutoff time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM audit_events WHERE ts < $1`, cutoff.UTC())
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// FindAuditDetail reports whether any audit event with the given action has a
// detail containing substr. The substring is matched literally: LIKE wildcards
// in substr are escaped so a caller-supplied value cannot widen the match.
func (s *PGStore) FindAuditDetail(ctx context.Context, action, substr string) (bool, error) {
	quoted := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(substr)
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM audit_events WHERE action = $1 AND detail LIKE '%' || $2 || '%')`,
		action, quoted).Scan(&exists)
	return exists, err
}

// nullableTime maps the zero time to a SQL NULL (used as "no lower bound").
func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// CreateUser inserts a user, populating its ID and CreatedAt; ErrConflict if the username is taken.
// CreateUser always creates an active user — Active on the input struct is
// ignored, deliberately, not read. A bare Go bool cannot tell "the caller
// wants an inactive user" apart from "the caller has never heard of this
// field and left it at its zero value," and the second case must never
// silently create a deactivated account. A caller that genuinely needs a
// freshly-created user to start deactivated (a SCIM POST whose body already
// says active:false) makes a separate UpdateUserActive call right after.
func (s *PGStore) CreateUser(ctx context.Context, u *store.User) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO users (username, role, ip_allowlist, device_fingerprint, external_id, active, token_hash)
		 VALUES ($1, $2, $3, $4, $5, TRUE, $6) RETURNING id, created_at`,
		u.Username, u.Role, u.IPAllowlist, u.DeviceFingerprint, u.ExternalID, u.TokenHash,
	).Scan(&u.ID, &u.CreatedAt)
	if err != nil {
		if pgCode(err) == pgUniqueViolation {
			return store.ErrConflict
		}
		return err
	}
	u.Active = true
	return nil
}

// ListUsers returns users in the (limit, afterID) window, ordered by ID.
func (s *PGStore) ListUsers(ctx context.Context, limit int, afterID int64) ([]store.User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, username, role, ip_allowlist, device_fingerprint, external_id, active, token_hash, created_at FROM users WHERE id > $1 ORDER BY id LIMIT $2`,
		afterID, limitArg(limit))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanUser)
}

// GetUser returns the user with the given ID, or ErrNotFound.
func (s *PGStore) GetUser(ctx context.Context, id int64) (*store.User, error) {
	return getOne(ctx, s.pool, scanUser,
		`SELECT id, username, role, ip_allowlist, device_fingerprint, external_id, active, token_hash, created_at FROM users WHERE id = $1`, id)
}

// GetUserByUsername returns the user with the given username, or ErrNotFound.
func (s *PGStore) GetUserByUsername(ctx context.Context, username string) (*store.User, error) {
	return getOne(ctx, s.pool, scanUser,
		`SELECT id, username, role, ip_allowlist, device_fingerprint, external_id, active, token_hash, created_at FROM users WHERE username = $1`, username)
}

// GetUserByExternalID returns the user with the given SCIM externalId, or
// ErrNotFound. An empty externalID always misses — WHERE excludes it
// explicitly rather than relying on callers to never pass "", since the
// column's own default is empty and shared by every non-SCIM user.
func (s *PGStore) GetUserByExternalID(ctx context.Context, externalID string) (*store.User, error) {
	if externalID == "" {
		return nil, store.ErrNotFound
	}
	return getOne(ctx, s.pool, scanUser,
		`SELECT id, username, role, ip_allowlist, device_fingerprint, external_id, active, token_hash, created_at FROM users WHERE external_id = $1`, externalID)
}

// UpdateUserActive sets a user's SCIM active flag (Phase 149); ErrNotFound if absent.
func (s *PGStore) UpdateUserActive(ctx context.Context, id int64, active bool) error {
	return execExpectingRow(ctx, s.pool, `UPDATE users SET active = $1 WHERE id = $2`, active, id)
}

// UpdateUserExternalID sets a user's SCIM externalId (Phase 149); ErrNotFound
// if absent, ErrConflict if another user already claims the same non-empty value.
func (s *PGStore) UpdateUserExternalID(ctx context.Context, id int64, externalID string) error {
	err := execExpectingRow(ctx, s.pool, `UPDATE users SET external_id = $1 WHERE id = $2`, externalID, id)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// UpdateUserRole changes a user's role, leaving username and token untouched;
// ErrNotFound if absent.
func (s *PGStore) UpdateUserRole(ctx context.Context, id int64, role string) error {
	return execExpectingRow(ctx, s.pool, `UPDATE users SET role = $1 WHERE id = $2`, role, id)
}

// UpdateUserIPAllowlist sets a user's source-address restriction (Phase 118);
// ErrNotFound if absent.
func (s *PGStore) UpdateUserIPAllowlist(ctx context.Context, id int64, allowlist string) error {
	return execExpectingRow(ctx, s.pool, `UPDATE users SET ip_allowlist = $1 WHERE id = $2`, allowlist, id)
}

// UpdateUserDeviceFingerprint sets a user's enrolled device-certificate
// fingerprint (Phase 133); ErrNotFound if absent.
func (s *PGStore) UpdateUserDeviceFingerprint(ctx context.Context, id int64, fingerprint string) error {
	return execExpectingRow(ctx, s.pool, `UPDATE users SET device_fingerprint = $1 WHERE id = $2`, fingerprint, id)
}

// GetUserByTokenHash returns the user whose token hash matches, or ErrNotFound.
func (s *PGStore) GetUserByTokenHash(ctx context.Context, tokenHashHex string) (*store.User, error) {
	return getOne(ctx, s.pool, scanUser,
		`SELECT id, username, role, ip_allowlist, device_fingerprint, external_id, active, token_hash, created_at FROM users WHERE token_hash = $1`,
		tokenHashHex)
}

// DeleteUser removes a user by ID; ErrNotFound if absent.
func (s *PGStore) DeleteUser(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM users WHERE id = $1`, id)
}

// CreateAgentKey inserts an agent key, populating its ID and CreatedAt.
func (s *PGStore) CreateAgentKey(ctx context.Context, k *store.AgentKey) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO agent_keys (name, owner, token_hash, disabled, expires_at, budget_per_day)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`,
		k.Name, k.Owner, k.TokenHash, k.Disabled, k.ExpiresAt, k.BudgetPerDay,
	).Scan(&k.ID, &k.CreatedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// GetAgentKeyByTokenHash returns the enabled agent key whose token hash matches,
// or ErrNotFound (a disabled key is treated as not found). Expiry is NOT
// filtered here: the caller checks AgentKey.Active so an expired key's attempt
// can be audited as an expired key rather than as an unknown one.
func (s *PGStore) GetAgentKeyByTokenHash(ctx context.Context, tokenHashHex string) (*store.AgentKey, error) {
	return getOne(ctx, s.pool, scanAgentKey,
		`SELECT id, name, owner, token_hash, disabled, created_at, expires_at, last_used_at, budget_per_day
		 FROM agent_keys WHERE token_hash = $1 AND disabled = FALSE`, tokenHashHex)
}

// GetAgentKey returns an agent key by ID (regardless of disabled), or ErrNotFound.
func (s *PGStore) GetAgentKey(ctx context.Context, id int64) (*store.AgentKey, error) {
	return getOne(ctx, s.pool, scanAgentKey,
		`SELECT id, name, owner, token_hash, disabled, created_at, expires_at, last_used_at, budget_per_day
		 FROM agent_keys WHERE id = $1`, id)
}

// ListAgentKeys returns all agent keys ordered by ID.
func (s *PGStore) ListAgentKeys(ctx context.Context) ([]store.AgentKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, owner, token_hash, disabled, created_at, expires_at, last_used_at, budget_per_day
		 FROM agent_keys ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAgentKey)
}

// ListAgentKeysByOwner returns one owner's agent keys ordered by ID (empty, not
// nil, when the owner has none).
func (s *PGStore) ListAgentKeysByOwner(ctx context.Context, owner string) ([]store.AgentKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, owner, token_hash, disabled, created_at, expires_at, last_used_at, budget_per_day
		 FROM agent_keys WHERE owner = $1 ORDER BY id`, owner)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAgentKey)
}

// DeleteAgentKey removes an agent key by ID; ErrNotFound if absent.
func (s *PGStore) DeleteAgentKey(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM agent_keys WHERE id = $1`, id)
}

// SetAgentKeyDisabled suspends or restores an agent key (idempotent);
// ErrNotFound if absent.
func (s *PGStore) SetAgentKeyDisabled(ctx context.Context, id int64, disabled bool) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE agent_keys SET disabled = $2 WHERE id = $1`, id, disabled)
}

// TouchAgentKey records when the agent key last authenticated; ErrNotFound if absent.
func (s *PGStore) TouchAgentKey(ctx context.Context, id int64, at time.Time) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE agent_keys SET last_used_at = $2 WHERE id = $1`, id, at)
}

// SetAgentKeyBudget sets an agent key's daily brokered-call budget, or clears
// it with nil so the server-wide default applies again; ErrNotFound if absent.
//
// budgetPerDay is a *int so all three states survive the trip to the database:
// nil writes SQL NULL ("no per-agent setting"), a pointer to 0 writes 0 ("this
// agent may make no calls at all"), and a positive value writes that number.
// pgx maps a nil *int to NULL for us, so no special case is needed here -- but
// note that the difference only survives because the column is nullable and
// the field is a pointer on both sides.
func (s *PGStore) SetAgentKeyBudget(ctx context.Context, id int64, budgetPerDay *int) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE agent_keys SET budget_per_day = $2 WHERE id = $1`, id, budgetPerDay)
}

// CountAgentToolCallsSince counts the brokered tool calls one agent has spent
// since `since` (inclusive), from the primary audit trail.
//
// Only `broker.tool_call.executed` (work done immediately) and
// `broker.tool_call.resumed` (the agent collecting the result of a call a
// human approved) count -- denied and failed calls do not, because a budget
// measures what the agent was allowed to DO, and refusals must not eat it. The
// two names are compared with `IN (...)` rather than `LIKE
// 'broker.tool_call.%'` deliberately: a prefix would silently start charging
// the budget for any future broker.tool_call.* action. See BrokerStore's
// interface doc for the full reasoning; the constants themselves live in
// internal/broker (ActionToolCallExecuted / ActionToolCallResumed), which this
// package cannot import without an import cycle, so they are repeated here as
// literals and must be kept in step.
//
// Actor is matched with `=`, i.e. exactly and case-sensitively, the same way
// every other actor lookup in this store works.
func (s *PGStore) CountAgentToolCallsSince(ctx context.Context, agent string, since time.Time) (int, error) {
	var n int
	// The action names come from the shared constants rather than being spelled
	// into the SQL, so this backend cannot drift from memstore or from the broker
	// that writes them (a `store_test` guard pins those two together). Passed as
	// a parameter, not interpolated: a constant would be safe to interpolate, but
	// leaving no string-built SQL in the file at all is the habit worth keeping.
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events
		 WHERE actor = $1
		   AND action = ANY($2)
		   AND ts >= $3`,
		agent,
		[]string{store.AuditActionToolCallExecuted, store.AuditActionToolCallResumed},
		since.UTC()).Scan(&n)
	return n, err
}

// QuarantineAgent stops one agent by subject, populating ID and CreatedAt;
// ErrConflict if that subject is already quarantined.
func (s *PGStore) QuarantineAgent(ctx context.Context, q *store.AgentQuarantine) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO agent_quarantine (subject, reason, created_by)
		 VALUES ($1, $2, $3) RETURNING id, created_at`,
		q.Subject, q.Reason, q.CreatedBy,
	).Scan(&q.ID, &q.CreatedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// IsAgentQuarantined reports whether the subject is currently quarantined.
func (s *PGStore) IsAgentQuarantined(ctx context.Context, subject string) (bool, error) {
	var found bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM agent_quarantine WHERE subject = $1)`, subject).Scan(&found)
	return found, err
}

// ListAgentQuarantine returns every quarantine entry ordered by ID.
func (s *PGStore) ListAgentQuarantine(ctx context.Context) ([]store.AgentQuarantine, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, subject, reason, created_by, created_at FROM agent_quarantine ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAgentQuarantine)
}

// ReleaseAgentQuarantine lifts one quarantine by ID; ErrNotFound if absent.
func (s *PGStore) ReleaseAgentQuarantine(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM agent_quarantine WHERE id = $1`, id)
}

// CreateAgentIdentity records the owner of a SPIFFE-attested agent, populating
// ID and CreatedAt; ErrConflict if that SPIFFE ID is already registered.
func (s *PGStore) CreateAgentIdentity(ctx context.Context, a *store.AgentIdentity) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO agent_identities (spiffe_id, owner, note, created_by, enrolled)
		 VALUES ($1, $2, $3, $4, TRUE) RETURNING id, created_at, enrolled`,
		a.SPIFFEID, a.Owner, a.Note, a.CreatedBy,
	).Scan(&a.ID, &a.CreatedAt, &a.Enrolled)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// GetAgentIdentity returns one SPIFFE ID's registration, or ErrNotFound.
func (s *PGStore) GetAgentIdentity(ctx context.Context, spiffeID string) (*store.AgentIdentity, error) {
	return getOne(ctx, s.pool, scanAgentIdentity,
		`SELECT id, spiffe_id, owner, note, enrolled, first_seen, last_seen, created_by, created_at
		   FROM agent_identities WHERE spiffe_id = $1`, spiffeID)
}

// ListAgentIdentities returns every registration ordered by ID.
func (s *PGStore) ListAgentIdentities(ctx context.Context) ([]store.AgentIdentity, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, spiffe_id, owner, note, enrolled, first_seen, last_seen, created_by, created_at
		   FROM agent_identities ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAgentIdentity)
}

// ListAgentIdentitiesByOwner returns one owner's registrations ordered by ID.
func (s *PGStore) ListAgentIdentitiesByOwner(ctx context.Context, owner string) ([]store.AgentIdentity, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, spiffe_id, owner, note, enrolled, first_seen, last_seen, created_by, created_at
		   FROM agent_identities WHERE owner = $1 ORDER BY id`, owner)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAgentIdentity)
}

// EnrollAgentIdentity claims a discovered identity: owner, note, enrolled.
func (s *PGStore) EnrollAgentIdentity(ctx context.Context, id int64, owner, note string) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE agent_identities SET owner = $2, note = $3, enrolled = TRUE WHERE id = $1`,
		id, owner, note)
}

// SetAgentIdentityOwner reassigns one registration's owner; ErrNotFound if absent.
func (s *PGStore) SetAgentIdentityOwner(ctx context.Context, id int64, owner string) error {
	// Naming an owner IS enrolling: it is the act by which a human takes
	// responsibility for the identity, whether the row was typed in by an admin
	// or created by pamv1 the first time the workload called.
	return execExpectingRow(ctx, s.pool,
		`UPDATE agent_identities SET owner = $2, enrolled = TRUE WHERE id = $1`, id, owner)
}

// SeeAgentIdentity records that a SPIFFE identity authenticated: it inserts an
// UNENROLLED row on the first sighting and stamps last_seen on every one after,
// reporting whether the row was created.
//
// ON CONFLICT rather than a read-then-write because two calls from the same
// workload can land concurrently on two replicas; the unique index on spiffe_id
// is what makes the race harmless. `xmax = 0` is the standard way to tell an
// INSERT from an UPDATE in a single round trip — on a freshly inserted row no
// transaction has yet superseded it.
func (s *PGStore) SeeAgentIdentity(ctx context.Context, spiffeID string, seen time.Time) (bool, error) {
	var created bool
	err := s.pool.QueryRow(ctx,
		`INSERT INTO agent_identities (spiffe_id, owner, note, created_by, enrolled, first_seen, last_seen)
		 VALUES ($1, '', '', 'first-seen', FALSE, $2, $2)
		 ON CONFLICT (spiffe_id) DO UPDATE
		   SET last_seen  = EXCLUDED.last_seen,
		       first_seen = COALESCE(agent_identities.first_seen, EXCLUDED.first_seen)
		 RETURNING (xmax = 0)`,
		spiffeID, seen.UTC()).Scan(&created)
	return created, err
}

// DeleteAgentIdentity removes one registration by ID; ErrNotFound if absent.
func (s *PGStore) DeleteAgentIdentity(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM agent_identities WHERE id = $1`, id)
}

// RecordSSHCert stores an issued operator SSH certificate (Phase 28); ErrConflict
// if the serial is already recorded.
func (s *PGStore) RecordSSHCert(ctx context.Context, c *store.SSHCert) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO ssh_certificates (serial, key_id, principal, actor, valid_before)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id, issued_at`,
		c.Serial, c.KeyID, c.Principal, c.Actor, c.ValidBefore,
	).Scan(&c.ID, &c.IssuedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// RevokeSSHCert stamps a certificate serial revoked; ErrNotFound if unknown,
// ErrConflict if already revoked.
func (s *PGStore) RevokeSSHCert(ctx context.Context, serial int64, by string, at time.Time) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE ssh_certificates SET revoked_at = $2, revoked_by = $3
		 WHERE serial = $1 AND revoked_at IS NULL`, serial, at.UTC(), by)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Distinguish "unknown serial" from "already revoked".
		var exists bool
		if e := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ssh_certificates WHERE serial = $1)`, serial).Scan(&exists); e != nil {
			return e
		}
		if exists {
			return store.ErrConflict
		}
		return store.ErrNotFound
	}
	return nil
}

// ListRevokedSSHCertSerials returns the serials of every revoked certificate.
func (s *PGStore) ListRevokedSSHCertSerials(ctx context.Context) ([]int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT serial FROM ssh_certificates WHERE revoked_at IS NOT NULL ORDER BY serial`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (int64, error) {
		var serial int64
		err := row.Scan(&serial)
		return serial, err
	})
}

// ListSSHCerts returns recent issued certificates, newest first (capped).
func (s *PGStore) ListSSHCerts(ctx context.Context, limit int) ([]store.SSHCert, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, serial, key_id, principal, actor, issued_at, valid_before, revoked_at, revoked_by
		 FROM ssh_certificates ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.SSHCert, error) {
		var c store.SSHCert
		err := row.Scan(&c.ID, &c.Serial, &c.KeyID, &c.Principal, &c.Actor, &c.IssuedAt, &c.ValidBefore, &c.RevokedAt, &c.RevokedBy)
		return c, err
	})
}

// scanVendorGrant maps one vendor_grants row into a store.VendorGrant.
func scanVendorGrant(row pgx.CollectableRow) (store.VendorGrant, error) {
	var g store.VendorGrant
	err := row.Scan(&g.ID, &g.VendorID, &g.TargetID, &g.Principal, &g.Status,
		&g.NotBefore, &g.NotAfter, &g.Approver, &g.ApprovedAt, &g.RevokedAt, &g.CreatedAt)
	return g, err
}

// CreateVendor registers a vendor (Phase 29); ErrConflict on a duplicate username.
func (s *PGStore) CreateVendor(ctx context.Context, v *store.Vendor) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO vendors (username, org, email, disabled) VALUES ($1, $2, $3, $4) RETURNING id, created_at`,
		v.Username, v.Org, v.Email, v.Disabled).Scan(&v.ID, &v.CreatedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// GetVendorByUsername returns the vendor for a login, or ErrNotFound.
func (s *PGStore) GetVendorByUsername(ctx context.Context, username string) (*store.Vendor, error) {
	return getOne(ctx, s.pool, func(row pgx.CollectableRow) (store.Vendor, error) {
		var v store.Vendor
		err := row.Scan(&v.ID, &v.Username, &v.Org, &v.Email, &v.Disabled, &v.CreatedAt)
		return v, err
	}, `SELECT id, username, org, email, disabled, created_at FROM vendors WHERE username = $1`, username)
}

// ListVendors returns vendors in the (limit, afterID) window, ordered by ID.
func (s *PGStore) ListVendors(ctx context.Context, limit int, afterID int64) ([]store.Vendor, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, username, org, email, disabled, created_at FROM vendors WHERE id > $1 ORDER BY id LIMIT $2`,
		afterID, limitArg(limit))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.Vendor, error) {
		var v store.Vendor
		err := row.Scan(&v.ID, &v.Username, &v.Org, &v.Email, &v.Disabled, &v.CreatedAt)
		return v, err
	})
}

// UpdateVendorOrg changes a vendor's organization label; ErrNotFound if absent.
func (s *PGStore) UpdateVendorOrg(ctx context.Context, id int64, org string) error {
	return execExpectingRow(ctx, s.pool, `UPDATE vendors SET org = $2 WHERE id = $1`, id, org)
}

// UpdateVendorEmail sets the vendor's on-file contact address, or ErrNotFound.
func (s *PGStore) UpdateVendorEmail(ctx context.Context, id int64, email string) error {
	return execExpectingRow(ctx, s.pool, `UPDATE vendors SET email = $2 WHERE id = $1`, id, email)
}

// CreateVendorGrant records a pending contract grant; ErrNotFound if the vendor
// or target is missing.
func (s *PGStore) CreateVendorGrant(ctx context.Context, g *store.VendorGrant) error {
	if g.Status == "" {
		g.Status = "pending"
	}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO vendor_grants (vendor_id, target_id, principal, status, not_before, not_after)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`,
		g.VendorID, g.TargetID, g.Principal, g.Status, g.NotBefore, g.NotAfter).Scan(&g.ID, &g.CreatedAt)
	if pgCode(err) == pgForeignKeyViolation {
		return store.ErrNotFound
	}
	return err
}

// ApproveVendorGrant flips a pending grant to approved; ErrNotFound if unknown,
// ErrConflict if not pending.
func (s *PGStore) ApproveVendorGrant(ctx context.Context, id int64, approver string, at time.Time) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE vendor_grants SET status = 'approved', approver = $2, approved_at = $3
		 WHERE id = $1 AND status = 'pending'`, id, approver, at.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if e := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vendor_grants WHERE id = $1)`, id).Scan(&exists); e != nil {
			return e
		}
		if exists {
			return store.ErrConflict
		}
		return store.ErrNotFound
	}
	return nil
}

// RevokeVendorGrant marks a grant revoked; ErrNotFound if unknown.
func (s *PGStore) RevokeVendorGrant(ctx context.Context, id int64, at time.Time) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE vendor_grants SET status = 'revoked', revoked_at = $2 WHERE id = $1`, id, at.UTC())
}

// ListVendorGrants lists a vendor's grants, newest first.
func (s *PGStore) ListVendorGrants(ctx context.Context, vendorID int64) ([]store.VendorGrant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, vendor_id, target_id, principal, status, not_before, not_after, approver, approved_at, revoked_at, created_at
		 FROM vendor_grants WHERE vendor_id = $1 ORDER BY id DESC`, vendorID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanVendorGrant)
}

// OffboardVendor disables the vendor and revokes all its grants atomically.
func (s *PGStore) OffboardVendor(ctx context.Context, id int64, at time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE vendors SET disabled = TRUE WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`UPDATE vendor_grants SET status = 'revoked', revoked_at = $2 WHERE vendor_id = $1 AND status <> 'revoked'`,
		id, at.UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// VendorSessionAllowed reports whether username is a vendor and, if so, whether an
// active contract grant to targetName exists as of now.
func (s *PGStore) VendorSessionAllowed(ctx context.Context, username, targetName, account string, now time.Time) (bool, bool, error) {
	var vendorID int64
	var disabled bool
	err := s.pool.QueryRow(ctx, `SELECT id, disabled FROM vendors WHERE username = $1`, username).Scan(&vendorID, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, true, nil // not a vendor — unaffected
	}
	if err != nil {
		return false, false, err
	}
	if disabled {
		return true, false, nil
	}
	var allowed bool
	err = s.pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM vendor_grants g JOIN targets t ON t.id = g.target_id
			WHERE g.vendor_id = $1 AND t.name = $2 AND g.status = 'approved' AND g.revoked_at IS NULL
			  AND g.not_after > $3 AND (g.not_before IS NULL OR g.not_before <= $3)
			  AND ($4 = '' OR g.principal = '' OR g.principal = $4))`,
		vendorID, targetName, now.UTC(), account).Scan(&allowed)
	return true, allowed, err
}

// scanAppKey scans one app_keys row into a store.AppKey.
func scanAppKey(row pgx.CollectableRow) (store.AppKey, error) {
	var k store.AppKey
	err := row.Scan(&k.ID, &k.Name, &k.Owner, &k.TokenHash, &k.Disabled, &k.CreatedAt)
	return k, err
}

// scanAppSecretGrant scans one app_secret_grants row into a store.AppSecretGrant.
func scanAppSecretGrant(row pgx.CollectableRow) (store.AppSecretGrant, error) {
	var g store.AppSecretGrant
	err := row.Scan(&g.ID, &g.AppID, &g.CredentialID, &g.CreatedAt)
	return g, err
}

// CreateAppKey inserts an application identity key, populating ID and CreatedAt.
func (s *PGStore) CreateAppKey(ctx context.Context, k *store.AppKey) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO app_keys (name, owner, token_hash, disabled)
		 VALUES ($1, $2, $3, $4) RETURNING id, created_at`,
		k.Name, k.Owner, k.TokenHash, k.Disabled,
	).Scan(&k.ID, &k.CreatedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// GetAppKeyByTokenHash returns the enabled app key whose token hash matches, or
// ErrNotFound (a disabled key is treated as not found).
func (s *PGStore) GetAppKeyByTokenHash(ctx context.Context, tokenHashHex string) (*store.AppKey, error) {
	return getOne(ctx, s.pool, scanAppKey,
		`SELECT id, name, owner, token_hash, disabled, created_at
		 FROM app_keys WHERE token_hash = $1 AND disabled = FALSE`, tokenHashHex)
}

// ListAppKeys returns all application keys ordered by ID.
func (s *PGStore) ListAppKeys(ctx context.Context) ([]store.AppKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, owner, token_hash, disabled, created_at FROM app_keys ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAppKey)
}

// DeleteAppKey removes an app key by ID (its grants cascade); ErrNotFound if absent.
func (s *PGStore) DeleteAppKey(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM app_keys WHERE id = $1`, id)
}

// CreateScimKey inserts a SCIM client identity key, populating ID and CreatedAt.
func (s *PGStore) CreateScimKey(ctx context.Context, k *store.ScimKey) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO scim_keys (name, owner, token_hash, disabled)
		 VALUES ($1, $2, $3, $4) RETURNING id, created_at`,
		k.Name, k.Owner, k.TokenHash, k.Disabled,
	).Scan(&k.ID, &k.CreatedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// GetScimKeyByTokenHash returns the enabled SCIM key whose token hash
// matches, or ErrNotFound (a disabled key is treated as not found).
func (s *PGStore) GetScimKeyByTokenHash(ctx context.Context, tokenHashHex string) (*store.ScimKey, error) {
	return getOne(ctx, s.pool, scanScimKey,
		`SELECT id, name, owner, token_hash, disabled, created_at
		 FROM scim_keys WHERE token_hash = $1 AND disabled = FALSE`, tokenHashHex)
}

// ListScimKeys returns all SCIM client keys ordered by ID.
func (s *PGStore) ListScimKeys(ctx context.Context) ([]store.ScimKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, owner, token_hash, disabled, created_at FROM scim_keys ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanScimKey)
}

// DeleteScimKey removes a SCIM key by ID; ErrNotFound if absent.
func (s *PGStore) DeleteScimKey(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM scim_keys WHERE id = $1`, id)
}

// CreateEndpointAgent inserts an endpoint agent, populating ID and CreatedAt.
// A duplicate key hash or a second live agent for the target is ErrConflict;
// a missing target is ErrNotFound.
func (s *PGStore) CreateEndpointAgent(ctx context.Context, a *store.EndpointAgent) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO endpoint_agents (name, target_id, key_hash, created_by)
		 VALUES ($1, $2, $3, $4) RETURNING id, created_at`,
		a.Name, a.TargetID, a.KeyHash, a.CreatedBy,
	).Scan(&a.ID, &a.CreatedAt)
	switch pgCode(err) {
	case pgUniqueViolation:
		return store.ErrConflict
	case pgForeignKeyViolation:
		return store.ErrNotFound
	}
	return err
}

// GetEndpointAgentByKeyHash returns the agent (revoked or not) whose key hash
// matches, or ErrNotFound.
func (s *PGStore) GetEndpointAgentByKeyHash(ctx context.Context, keyHashHex string) (*store.EndpointAgent, error) {
	return getOne(ctx, s.pool, scanEndpointAgent,
		`SELECT id, name, target_id, key_hash, created_by, created_at, last_seen, revoked_at
		 FROM endpoint_agents WHERE key_hash = $1`, keyHashHex)
}

// GetEndpointAgentForTarget returns the target's unrevoked agent, or ErrNotFound.
func (s *PGStore) GetEndpointAgentForTarget(ctx context.Context, targetID int64) (*store.EndpointAgent, error) {
	return getOne(ctx, s.pool, scanEndpointAgent,
		`SELECT id, name, target_id, key_hash, created_by, created_at, last_seen, revoked_at
		 FROM endpoint_agents WHERE target_id = $1 AND revoked_at IS NULL`, targetID)
}

// ListEndpointAgents returns every endpoint agent ordered by ID.
func (s *PGStore) ListEndpointAgents(ctx context.Context) ([]store.EndpointAgent, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, target_id, key_hash, created_by, created_at, last_seen, revoked_at
		 FROM endpoint_agents ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanEndpointAgent)
}

// RevokeEndpointAgent stamps revoked_at (left alone if already set); ErrNotFound if absent.
func (s *PGStore) RevokeEndpointAgent(ctx context.Context, id int64, at time.Time) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE endpoint_agents SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1`, id, at)
}

// TouchEndpointAgent records the agent's last connection time; ErrNotFound if absent.
func (s *PGStore) TouchEndpointAgent(ctx context.Context, id int64, at time.Time) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE endpoint_agents SET last_seen = $2 WHERE id = $1`, id, at)
}

// GrantAppSecret authorizes an app to retrieve a credential's secret.
func (s *PGStore) GrantAppSecret(ctx context.Context, g *store.AppSecretGrant) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO app_secret_grants (app_id, credential_id)
		 VALUES ($1, $2) RETURNING id, created_at`,
		g.AppID, g.CredentialID,
	).Scan(&g.ID, &g.CreatedAt)
	switch pgCode(err) {
	case pgUniqueViolation:
		return store.ErrConflict
	case pgForeignKeyViolation:
		return store.ErrNotFound
	}
	return err
}

// ListAppSecretGrants returns an app's secret grants ordered by id.
func (s *PGStore) ListAppSecretGrants(ctx context.Context, appID int64) ([]store.AppSecretGrant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, app_id, credential_id, created_at FROM app_secret_grants WHERE app_id = $1 ORDER BY id`, appID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAppSecretGrant)
}

// DeleteAppSecretGrant removes a grant by ID, or ErrNotFound.
func (s *PGStore) DeleteAppSecretGrant(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM app_secret_grants WHERE id = $1`, id)
}

// AppMayAccessCredential reports whether app appID has a grant for credentialID.
func (s *PGStore) AppMayAccessCredential(ctx context.Context, appID, credentialID int64) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM app_secret_grants WHERE app_id = $1 AND credential_id = $2)`,
		appID, credentialID).Scan(&ok)
	return ok, err
}

// CreateBrokerToken stores a single-use resume token for a parked tool call.
func (s *PGStore) CreateBrokerToken(ctx context.Context, t *store.BrokerToken) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO broker_tokens (jti, call_id, expires_at) VALUES ($1, $2, $3)`,
		t.JTI, t.CallID, t.ExpiresAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict // a duplicate jti maps to the sentinel, like sibling Create*
	}
	return err
}

// ConsumeBrokerToken atomically spends a token, returning its bound call id. The
// UPDATE ... WHERE used_at IS NULL AND expires_at > now() RETURNING makes the
// spend a single winner; a used, expired, or unknown jti returns ErrNotFound.
func (s *PGStore) ConsumeBrokerToken(ctx context.Context, jti string) (string, error) {
	var callID string
	err := s.pool.QueryRow(ctx,
		`UPDATE broker_tokens SET used_at = now()
		 WHERE jti = $1 AND used_at IS NULL AND expires_at > now()
		 RETURNING call_id`, jti).Scan(&callID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", store.ErrNotFound
	}
	return callID, err
}

// PeekBrokerToken returns a token's bound call id without spending it.
func (s *PGStore) PeekBrokerToken(ctx context.Context, jti string) (string, error) {
	var callID string
	err := s.pool.QueryRow(ctx,
		`SELECT call_id FROM broker_tokens WHERE jti = $1 AND used_at IS NULL AND expires_at > now()`,
		jti).Scan(&callID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", store.ErrNotFound
	}
	return callID, err
}

// DeleteExpiredBrokerTokens removes spent or expired tokens (periodic GC).
func (s *PGStore) DeleteExpiredBrokerTokens(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM broker_tokens WHERE used_at IS NOT NULL OR expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// EnsureKeyMaterial atomically claims custody of a named key: the insert either
// wins or is a no-op, and the following select returns whichever value is stored.
// Two replicas racing at startup therefore agree on one key — the loser adopts
// the winner's rather than quietly running with its own.
func (s *PGStore) EnsureKeyMaterial(ctx context.Context, name, value string) (string, error) {
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO key_material (name, value) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`,
		name, value); err != nil {
		return "", err
	}
	var stored string
	if err := s.pool.QueryRow(ctx,
		`SELECT value FROM key_material WHERE name = $1`, name).Scan(&stored); err != nil {
		return "", err
	}
	return stored, nil
}

// ListKeyMaterial returns every named key envelope, ordered by name.
func (s *PGStore) ListKeyMaterial(ctx context.Context) ([]store.KeyMaterial, error) {
	rows, err := s.pool.Query(ctx, `SELECT name, value FROM key_material ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.KeyMaterial, error) {
		var k store.KeyMaterial
		err := row.Scan(&k.Name, &k.Value)
		return k, err
	})
}

// UpdateKeyMaterial replaces a named key's envelope; ErrNotFound if absent.
func (s *PGStore) UpdateKeyMaterial(ctx context.Context, name, value string) error {
	return execExpectingRow(ctx, s.pool, `UPDATE key_material SET value = $2 WHERE name = $1`, name, value)
}

// PutSetting upserts a configuration override, stamping UpdatedAt.
func (s *PGStore) PutSetting(ctx context.Context, st *store.Setting) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO settings (key, value, secret) VALUES ($1, $2, $3)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, secret = EXCLUDED.secret, updated_at = now()
		 RETURNING updated_at`, st.Key, st.Value, st.Secret).Scan(&st.UpdatedAt)
}

// GetSetting returns the override for key, or ErrNotFound.
func (s *PGStore) GetSetting(ctx context.Context, key string) (*store.Setting, error) {
	return getOne(ctx, s.pool, scanSetting,
		`SELECT key, value, secret, updated_at FROM settings WHERE key = $1`, key)
}

// ListSettings returns all configuration overrides ordered by key.
func (s *PGStore) ListSettings(ctx context.Context) ([]store.Setting, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, value, secret, updated_at FROM settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanSetting)
}

// DeleteSetting removes the override for key; ErrNotFound if absent.
func (s *PGStore) DeleteSetting(ctx context.Context, key string) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM settings WHERE key = $1`, key)
}

// CreateProfile inserts a custom permission profile; ErrConflict on a duplicate name.
func (s *PGStore) CreateProfile(ctx context.Context, p *store.Profile) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO profiles (name, capabilities) VALUES ($1, $2) RETURNING id, created_at`,
		p.Name, strings.Join(p.Capabilities, ",")).Scan(&p.ID, &p.CreatedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// GetProfile returns the profile with the given name, or ErrNotFound.
func (s *PGStore) GetProfile(ctx context.Context, name string) (*store.Profile, error) {
	return getOne(ctx, s.pool, scanProfile,
		`SELECT id, name, capabilities, created_at FROM profiles WHERE name = $1`, name)
}

// ListProfiles returns all custom profiles ordered by name.
func (s *PGStore) ListProfiles(ctx context.Context) ([]store.Profile, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, capabilities, created_at FROM profiles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanProfile)
}

// DeleteProfile removes a profile by ID; ErrNotFound if absent.
func (s *PGStore) DeleteProfile(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM profiles WHERE id = $1`, id)
}

// scanProfile maps one result row into a store.Profile, splitting the
// comma-separated capabilities column.
func scanProfile(row pgx.CollectableRow) (store.Profile, error) {
	var p store.Profile
	var caps string
	if err := row.Scan(&p.ID, &p.Name, &caps, &p.CreatedAt); err != nil {
		return p, err
	}
	if caps != "" {
		p.Capabilities = strings.Split(caps, ",")
	}
	return p, nil
}

const brokerAuditCols = `id, ts, actor, on_behalf_of, actor_chain, action, detail, scope, prev_hash, hmac`

// brokerChainLockKey serializes broker-audit appends across every process that
// shares this database (rolling-deploy pod overlap, HA replicas), so the
// keyed-HMAC chain cannot fork. Distinct from the migration advisory-lock key.
const brokerChainLockKey = int64(0x70616d5f6272) // "pam_br"

// AppendBrokerAuditLinked reads the current chain head and inserts the linked
// event as one atomic step, under a Postgres advisory lock held for the whole
// transaction so concurrent writers serialize instead of forking the chain.
func (s *PGStore) AppendBrokerAuditLinked(ctx context.Context, link func(head *store.BrokerAuditEvent) store.BrokerAuditEvent) (store.BrokerAuditEvent, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return store.BrokerAuditEvent{}, err
	}
	defer tx.Rollback(ctx)
	// The xact lock is released automatically on commit or rollback.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, brokerChainLockKey); err != nil {
		return store.BrokerAuditEvent{}, err
	}
	var head *store.BrokerAuditEvent
	rows, err := tx.Query(ctx, `SELECT `+brokerAuditCols+` FROM broker_audit_events ORDER BY id DESC LIMIT 1`)
	if err != nil {
		return store.BrokerAuditEvent{}, err
	}
	h, err := pgx.CollectExactlyOneRow(rows, scanBrokerAudit)
	if err == nil {
		head = &h
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return store.BrokerAuditEvent{}, err
	}
	ev := link(head)
	if err := tx.QueryRow(ctx,
		`INSERT INTO broker_audit_events (actor, on_behalf_of, actor_chain, action, detail, scope, prev_hash, hmac)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, ts`,
		ev.Actor, ev.OnBehalfOf, ev.ActorChain, ev.Action, ev.Detail, ev.Scope, ev.PrevHash, ev.HMAC,
	).Scan(&ev.ID, &ev.TS); err != nil {
		return store.BrokerAuditEvent{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return store.BrokerAuditEvent{}, err
	}
	return ev, nil
}

// ListBrokerAudit returns broker audit events oldest-first (id ASC). limit <= 0
// returns the whole chain (for verification); limit > 0 returns the most recent
// limit events, still in chain order.
func (s *PGStore) ListBrokerAudit(ctx context.Context, limit int) ([]store.BrokerAuditEvent, error) {
	var rows pgx.Rows
	var err error
	if limit > 0 {
		rows, err = s.pool.Query(ctx,
			`SELECT `+brokerAuditCols+` FROM (SELECT `+brokerAuditCols+
				` FROM broker_audit_events ORDER BY id DESC LIMIT $1) t ORDER BY id ASC`, limit)
	} else {
		rows, err = s.pool.Query(ctx, `SELECT `+brokerAuditCols+` FROM broker_audit_events ORDER BY id ASC`)
	}
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanBrokerAudit)
}

// GetBrokerAuditHead returns the most recent broker audit event, or (nil, nil)
// when the log is empty.
func (s *PGStore) GetBrokerAuditHead(ctx context.Context) (*store.BrokerAuditEvent, error) {
	e, err := getOne(ctx, s.pool, scanBrokerAudit,
		`SELECT `+brokerAuditCols+` FROM broker_audit_events ORDER BY id DESC LIMIT 1`)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return e, err
}

// CreateSession inserts a session, populating its ID and CreatedAt.
func (s *PGStore) CreateSession(ctx context.Context, sess *store.Session) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO sessions (username, role, roles, scope, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`,
		sess.Username, sess.Role, sess.Roles, sess.Scope, sess.TokenHash, sess.ExpiresAt,
	).Scan(&sess.ID, &sess.CreatedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// GetSessionByTokenHash returns a non-expired session matching the token hash,
// or ErrNotFound.
func (s *PGStore) GetSessionByTokenHash(ctx context.Context, tokenHashHex string) (*store.Session, error) {
	return getOne(ctx, s.pool, scanSession,
		`SELECT id, username, role, roles, scope, token_hash, created_at, expires_at
		 FROM sessions WHERE token_hash = $1 AND expires_at > now()`, tokenHashHex)
}

// DeleteSession removes the session with the given token hash; ErrNotFound if absent.
func (s *PGStore) DeleteSession(ctx context.Context, tokenHashHex string) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM sessions WHERE token_hash = $1`, tokenHashHex)
}

// ListSessions returns all non-expired login sessions, newest first.
func (s *PGStore) ListSessions(ctx context.Context) ([]store.Session, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, username, role, roles, scope, token_hash, created_at, expires_at
		 FROM sessions WHERE expires_at > now() ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanSession)
}

// DeleteSessionsByUsername revokes every session for a username, returning the count.
func (s *PGStore) DeleteSessionsByUsername(ctx context.Context, username string) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE username = $1`, username)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// DeleteExpiredSessions removes login sessions past their expiry.
func (s *PGStore) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// UpsertMFAEnrollment creates or replaces a user's TOTP enrollment, populating CreatedAt.
func (s *PGStore) UpsertMFAEnrollment(ctx context.Context, e *store.MFAEnrollment) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO mfa_enrollments (username, secret_enc, confirmed, last_totp_step)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (username) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, confirmed = EXCLUDED.confirmed, last_totp_step = EXCLUDED.last_totp_step
		 RETURNING created_at`,
		e.Username, e.SecretEnc, e.Confirmed, e.LastTOTPStep,
	).Scan(&e.CreatedAt)
}

// GetMFAEnrollment returns a user's TOTP enrollment, or ErrNotFound.
func (s *PGStore) GetMFAEnrollment(ctx context.Context, username string) (*store.MFAEnrollment, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT username, secret_enc, confirmed, created_at, last_totp_step FROM mfa_enrollments WHERE username = $1`, username)
	if err != nil {
		return nil, err
	}
	e, err := pgx.CollectExactlyOneRow(rows, func(row pgx.CollectableRow) (store.MFAEnrollment, error) {
		var m store.MFAEnrollment
		err := row.Scan(&m.Username, &m.SecretEnc, &m.Confirmed, &m.CreatedAt, &m.LastTOTPStep)
		return m, err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// ConsumeTOTPStep atomically advances the user's last-used TOTP step: the UPDATE
// affects a row only when step is newer than the stored one, so a replayed code
// (step <= stored) is rejected without a read-modify-write race.
func (s *PGStore) ConsumeTOTPStep(ctx context.Context, username string, step int64) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE mfa_enrollments SET last_totp_step = $2 WHERE username = $1 AND $2 > last_totp_step`,
		username, step)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ListMFAEnrollments returns all enrollments ordered by username.
func (s *PGStore) ListMFAEnrollments(ctx context.Context) ([]store.MFAEnrollment, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT username, secret_enc, confirmed, created_at, last_totp_step FROM mfa_enrollments ORDER BY username`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.MFAEnrollment, error) {
		var m store.MFAEnrollment
		// last_totp_step must be selected/scanned: a caller that re-Upserts a listed
		// enrollment (KEK rotation) would otherwise reset the TOTP anti-replay
		// high-water mark to 0 and reopen replay.
		err := row.Scan(&m.Username, &m.SecretEnc, &m.Confirmed, &m.CreatedAt, &m.LastTOTPStep)
		return m, err
	})
}

// DeleteMFAEnrollment removes a user's enrollment and their recovery codes;
// ErrNotFound if the enrollment is absent.
func (s *PGStore) DeleteMFAEnrollment(ctx context.Context, username string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Delete recovery codes and the enrollment atomically, so a failure between
	// them can't leave orphaned recovery-code hashes for a user with no enrollment.
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE username = $1`, username); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM mfa_enrollments WHERE username = $1`, username)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return tx.Commit(ctx)
}

// ReplaceMFARecoveryCodes stores a fresh set of recovery-code hashes for a user
// within a transaction, discarding any previous set.
func (s *PGStore) ReplaceMFARecoveryCodes(ctx context.Context, username string, codeHashes []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE username = $1`, username); err != nil {
		return err
	}
	for _, h := range codeHashes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO mfa_recovery_codes (username, code_hash) VALUES ($1, $2)
			 ON CONFLICT DO NOTHING`, username, h); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ConsumeMFARecoveryCode removes a matching unused recovery code and reports
// whether one was consumed.
func (s *PGStore) ConsumeMFARecoveryCode(ctx context.Context, username, codeHash string) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM mfa_recovery_codes WHERE username = $1 AND code_hash = $2`, username, codeHash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// CountMFARecoveryCodes returns how many recovery codes remain for a user.
func (s *PGStore) CountMFARecoveryCodes(ctx context.Context, username string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM mfa_recovery_codes WHERE username = $1`, username).Scan(&n)
	return n, err
}

const webauthnCredentialCols = `id, username, credential_id, public_key, attestation_type, attestation_format, transports, aaguid, sign_count, clone_warning, name, created_at, last_used_at`

func scanWebAuthnCredential(row pgx.CollectableRow) (store.WebAuthnCredential, error) {
	var c store.WebAuthnCredential
	err := row.Scan(&c.ID, &c.Username, &c.CredentialID, &c.PublicKey, &c.AttestationType,
		&c.AttestationFormat, &c.Transports, &c.AAGUID, &c.SignCount, &c.CloneWarning,
		&c.Name, &c.CreatedAt, &c.LastUsedAt)
	return c, err
}

// CreateWebAuthnCredential registers a new authenticator, populating ID and CreatedAt.
func (s *PGStore) CreateWebAuthnCredential(ctx context.Context, c *store.WebAuthnCredential) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO webauthn_credentials (username, credential_id, public_key, attestation_type, attestation_format, transports, aaguid, sign_count, clone_warning, name)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING id, created_at`,
		c.Username, c.CredentialID, c.PublicKey, c.AttestationType, c.AttestationFormat,
		c.Transports, c.AAGUID, c.SignCount, c.CloneWarning, c.Name,
	).Scan(&c.ID, &c.CreatedAt)
}

// ListWebAuthnCredentials returns every authenticator a user has registered, oldest first.
func (s *PGStore) ListWebAuthnCredentials(ctx context.Context, username string) ([]store.WebAuthnCredential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+webauthnCredentialCols+` FROM webauthn_credentials WHERE username = $1 ORDER BY id`, username)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanWebAuthnCredential)
}

// GetWebAuthnCredentialByCredentialID looks up an authenticator by the credential ID an assertion presents, or ErrNotFound.
func (s *PGStore) GetWebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (*store.WebAuthnCredential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+webauthnCredentialCols+` FROM webauthn_credentials WHERE credential_id = $1`, credentialID)
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, scanWebAuthnCredential)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// UpdateWebAuthnSignCount writes back the sign counter, clone-warning flag and
// last-used time after a successful login.
func (s *PGStore) UpdateWebAuthnSignCount(ctx context.Context, id int64, signCount uint32, cloneWarning bool, usedAt time.Time) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE webauthn_credentials SET sign_count = $2, clone_warning = $3, last_used_at = $4 WHERE id = $1`,
		id, signCount, cloneWarning, usedAt.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// DeleteWebAuthnCredential removes one authenticator by ID, scoped to username, or ErrNotFound.
func (s *PGStore) DeleteWebAuthnCredential(ctx context.Context, id int64, username string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM webauthn_credentials WHERE id = $1 AND username = $2`, id, username)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// PutWebAuthnChallenge stores (or replaces) the in-flight ceremony state for a
// (username, purpose) pair, best-effort GCing expired rows first.
func (s *PGStore) PutWebAuthnChallenge(ctx context.Context, username, purpose string, sessionData []byte, expiresAt time.Time) error {
	_, _ = s.pool.Exec(ctx, `DELETE FROM mfa_webauthn_challenges WHERE expires_at <= now()`)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO mfa_webauthn_challenges (username, purpose, session_data, expires_at) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (username, purpose) DO UPDATE SET session_data = EXCLUDED.session_data, expires_at = EXCLUDED.expires_at`,
		username, purpose, sessionData, expiresAt.UTC())
	return err
}

// TakeWebAuthnChallenge atomically fetches and deletes an unexpired challenge; ok is false if it is missing or expired.
func (s *PGStore) TakeWebAuthnChallenge(ctx context.Context, username, purpose string, now time.Time) ([]byte, bool, error) {
	var sessionData []byte
	err := s.pool.QueryRow(ctx,
		`DELETE FROM mfa_webauthn_challenges WHERE username = $1 AND purpose = $2 AND expires_at > $3 RETURNING session_data`,
		username, purpose, now.UTC()).Scan(&sessionData)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return sessionData, true, nil
}

// PutOIDCState stores (or replaces) PKCE verifier/nonce state for an OIDC login,
// best-effort GCing expired rows first.
func (s *PGStore) PutOIDCState(ctx context.Context, state, verifier, nonce string, expiresAt time.Time) error {
	// Best-effort GC of expired rows, then upsert.
	_, _ = s.pool.Exec(ctx, `DELETE FROM oidc_states WHERE expires_at <= now()`)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO oidc_states (state, verifier, nonce, expires_at) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (state) DO UPDATE SET verifier = EXCLUDED.verifier, nonce = EXCLUDED.nonce, expires_at = EXCLUDED.expires_at`,
		state, verifier, nonce, expiresAt.UTC())
	return err
}

// TakeOIDCState atomically deletes and returns an unexpired state; ok is false
// if it is missing or expired.
func (s *PGStore) TakeOIDCState(ctx context.Context, state string, now time.Time) (string, string, bool, error) {
	var verifier, nonce string
	err := s.pool.QueryRow(ctx,
		`DELETE FROM oidc_states WHERE state = $1 AND expires_at > $2 RETURNING verifier, nonce`,
		state, now.UTC()).Scan(&verifier, &nonce)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return verifier, nonce, true, nil
}

// scanSessionShareInvite maps one session_share_invites row into a
// store.SessionShareInvite.
func scanSessionShareInvite(row pgx.CollectableRow) (store.SessionShareInvite, error) {
	var inv store.SessionShareInvite
	err := row.Scan(&inv.ID, &inv.SessionID, &inv.Mode, &inv.Kind, &inv.Invitee, &inv.Email,
		&inv.Status, &inv.Requester, &inv.Approver, &inv.TokenHash, &inv.CreatedAt,
		&inv.DecidedAt, &inv.ExpiresAt, &inv.ConsumedAt, &inv.RevokedAt)
	return inv, err
}

const sessionShareInviteCols = `id, session_id, mode, kind, invitee, email, status, requester, approver, token_hash, created_at, decided_at, expires_at, consumed_at, revoked_at`

// CreateSessionShareInvite records a pending session-share request.
func (s *PGStore) CreateSessionShareInvite(ctx context.Context, inv *store.SessionShareInvite) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO session_share_invites (session_id, mode, kind, invitee, email, status, requester)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, created_at`,
		inv.SessionID, inv.Mode, inv.Kind, inv.Invitee, inv.Email, inv.Status, inv.Requester,
	).Scan(&inv.ID, &inv.CreatedAt)
}

// GetSessionShareInvite returns one invite by id, or ErrNotFound.
func (s *PGStore) GetSessionShareInvite(ctx context.Context, id int64) (*store.SessionShareInvite, error) {
	return getOne(ctx, s.pool, scanSessionShareInvite,
		`SELECT `+sessionShareInviteCols+` FROM session_share_invites WHERE id = $1`, id)
}

// ListSessionShareInvites lists a session's invites, newest first.
func (s *PGStore) ListSessionShareInvites(ctx context.Context, sessionID string) ([]store.SessionShareInvite, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+sessionShareInviteCols+` FROM session_share_invites WHERE session_id = $1 ORDER BY created_at DESC`,
		sessionID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanSessionShareInvite)
}

// DecideSessionShareInvite records an approve/deny decision; ErrNotFound if
// unknown. The caller (matching DecideAccessRequest's own convention) is
// responsible for checking the invite is still pending before calling this —
// the store layer here trusts that check rather than re-enforcing it, the
// same division of responsibility the access-request approval flow already
// uses.
func (s *PGStore) DecideSessionShareInvite(ctx context.Context, id int64, status, approver string, at time.Time, tokenHash string, expiresAt *time.Time) error {
	var exp *time.Time
	if expiresAt != nil {
		e := expiresAt.UTC()
		exp = &e
	}
	return execExpectingRow(ctx, s.pool,
		`UPDATE session_share_invites SET status = $2, approver = $3, decided_at = $4, token_hash = $5, expires_at = $6 WHERE id = $1`,
		id, status, approver, at.UTC(), tokenHash, exp)
}

// RevokeSessionShareInvite marks an invite revoked, or ErrNotFound.
func (s *PGStore) RevokeSessionShareInvite(ctx context.Context, id int64, at time.Time) error {
	return execExpectingRow(ctx, s.pool, `UPDATE session_share_invites SET revoked_at = $2 WHERE id = $1`, id, at.UTC())
}

// ConsumeSessionShareInviteByTokenHash atomically redeems an approved,
// unexpired, unrevoked, not-yet-consumed invite matching tokenHash — the
// UPDATE...RETURNING is the single statement that makes this a genuine
// single-use check-and-set rather than a read-then-write race.
func (s *PGStore) ConsumeSessionShareInviteByTokenHash(ctx context.Context, tokenHash string, now time.Time) (*store.SessionShareInvite, error) {
	rows, err := s.pool.Query(ctx,
		`UPDATE session_share_invites SET consumed_at = $2
		 WHERE token_hash = $1 AND status = 'approved' AND revoked_at IS NULL
		   AND consumed_at IS NULL AND expires_at > $2
		 RETURNING `+sessionShareInviteCols,
		tokenHash, now.UTC())
	if err != nil {
		return nil, err
	}
	inv, err := pgx.CollectExactlyOneRow(rows, scanSessionShareInvite)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &inv, nil
}

// scanApprovalInvite maps one approval_invites row into a store.ApprovalInvite.
func scanApprovalInvite(row pgx.CollectableRow) (store.ApprovalInvite, error) {
	var inv store.ApprovalInvite
	err := row.Scan(&inv.ID, &inv.AccessRequestID, &inv.Email, &inv.CreatedBy, &inv.TokenHash,
		&inv.CreatedAt, &inv.ExpiresAt, &inv.Decision, &inv.ConsumedAt, &inv.RevokedAt)
	return inv, err
}

const approvalInviteCols = `id, access_request_id, email, created_by, token_hash, created_at, expires_at, decision, consumed_at, revoked_at`

// CreateApprovalInvite records a new magic-link invite; the caller has
// already generated and hashed the token and computed ExpiresAt.
func (s *PGStore) CreateApprovalInvite(ctx context.Context, inv *store.ApprovalInvite) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO approval_invites (access_request_id, email, created_by, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`,
		inv.AccessRequestID, inv.Email, inv.CreatedBy, inv.TokenHash, inv.ExpiresAt.UTC(),
	).Scan(&inv.ID, &inv.CreatedAt)
}

// GetApprovalInvite returns one invite by id, or ErrNotFound.
func (s *PGStore) GetApprovalInvite(ctx context.Context, id int64) (*store.ApprovalInvite, error) {
	return getOne(ctx, s.pool, scanApprovalInvite,
		`SELECT `+approvalInviteCols+` FROM approval_invites WHERE id = $1`, id)
}

// ListApprovalInvitesForRequest lists an access request's invites, newest first.
func (s *PGStore) ListApprovalInvitesForRequest(ctx context.Context, accessRequestID int64) ([]store.ApprovalInvite, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+approvalInviteCols+` FROM approval_invites WHERE access_request_id = $1 ORDER BY created_at DESC`,
		accessRequestID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanApprovalInvite)
}

// RevokeApprovalInvite marks an invite revoked, or ErrNotFound.
func (s *PGStore) RevokeApprovalInvite(ctx context.Context, id int64, at time.Time) error {
	return execExpectingRow(ctx, s.pool, `UPDATE approval_invites SET revoked_at = $2 WHERE id = $1`, id, at.UTC())
}

// GetApprovalInviteByTokenHash is the non-consuming preview lookup: it
// refuses (ErrNotFound) an unknown, expired, revoked or already-consumed
// invite, but does not itself write anything — safe to call from a bare
// page load.
func (s *PGStore) GetApprovalInviteByTokenHash(ctx context.Context, tokenHash string) (*store.ApprovalInvite, error) {
	return getOne(ctx, s.pool, scanApprovalInvite,
		`SELECT `+approvalInviteCols+` FROM approval_invites
		 WHERE token_hash = $1 AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at > now()`,
		tokenHash)
}

// ConsumeApprovalInviteByTokenHash atomically redeems an unexpired,
// unrevoked, not-yet-consumed invite matching tokenHash — the
// UPDATE...RETURNING is the single statement that makes this a genuine
// single-use check-and-set rather than a read-then-write race.
func (s *PGStore) ConsumeApprovalInviteByTokenHash(ctx context.Context, tokenHash string, now time.Time) (*store.ApprovalInvite, error) {
	rows, err := s.pool.Query(ctx,
		`UPDATE approval_invites SET consumed_at = $2
		 WHERE token_hash = $1 AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at > $2
		 RETURNING `+approvalInviteCols,
		tokenHash, now.UTC())
	if err != nil {
		return nil, err
	}
	inv, err := pgx.CollectExactlyOneRow(rows, scanApprovalInvite)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &inv, nil
}

// RecordApprovalInviteDecision stamps the outcome on an already-consumed
// invite, or ErrNotFound.
func (s *PGStore) RecordApprovalInviteDecision(ctx context.Context, id int64, decision string) error {
	return execExpectingRow(ctx, s.pool, `UPDATE approval_invites SET decision = $2 WHERE id = $1`, id, decision)
}

// Ping reports whether the database is reachable (readiness probe).
func (s *PGStore) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// WithLeaderLock runs fn only if it can immediately acquire the session-level
// advisory lock for key. It holds the lock on a dedicated pooled connection for
// the whole of fn (which uses the pool's other connections normally), so across
// HA replicas exactly one runs the job per tick. pg_try_advisory_lock is
// non-blocking: a replica that doesn't get the lock returns ran=false and skips
// fn rather than piling up behind the leader.
func (s *PGStore) WithLeaderLock(ctx context.Context, key int64, fn func(context.Context) error) (bool, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); err != nil {
		return false, err
	}
	if !got {
		return false, nil // another replica holds the lock; skip this tick
	}
	// Unlock on the same connection, even if ctx is cancelled mid-run.
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key)
	return true, fn(ctx)
}

// Close releases the underlying connection pool.
func (s *PGStore) Close() {
	s.pool.Close()
}

// scanTarget maps one result row into a store.Target.
func scanTarget(row pgx.CollectableRow) (store.Target, error) {
	var t store.Target
	err := row.Scan(&t.ID, &t.Name, &t.Host, &t.Port, &t.OSType, &t.Protocol, &t.RequireApproval, &t.SafeID, &t.RDPClipboard, &t.RDPClipboardAudit, &t.CreatedAt)
	return t, err
}

// scanAccessRequest maps one result row into a store.AccessRequest.
func scanAccessRequest(row pgx.CollectableRow) (store.AccessRequest, error) {
	var ar store.AccessRequest
	err := row.Scan(&ar.ID, &ar.Requester, &ar.TargetID, &ar.Reason, &ar.Status,
		&ar.Approver, &ar.CreatedAt, &ar.DecidedAt, &ar.ExpiresAt, &ar.Ticket,
		&ar.RequiredApprovals, &ar.ApprovedBy, &ar.NotBefore, &ar.OneTime, &ar.ConsumedAt,
		&ar.RecurDays, &ar.NextRunAt)
	return ar, err
}

// scanCredential maps one result row into a store.Credential.
func scanCredential(row pgx.CollectableRow) (store.Credential, error) {
	var c store.Credential
	err := row.Scan(&c.ID, &c.TargetID, &c.Username, &c.SecretType, &c.SecretEnc, &c.Provisioner,
		&c.DoubleLockHolder, &c.DoubleLockVerifier, &c.DoubleLockEnc, &c.CreatedAt, &c.RotatedAt)
	return c, err
}

// scanCredentialMeta mirrors scanCredential for ListCredentials' narrower
// column list (Phase 145) — SecretEnc, DoubleLockVerifier and DoubleLockEnc
// stay at their zero value, exactly as a caller relying only on json-visible
// fields already expected.
func scanCredentialMeta(row pgx.CollectableRow) (store.Credential, error) {
	var c store.Credential
	err := row.Scan(&c.ID, &c.TargetID, &c.Username, &c.SecretType, &c.Provisioner,
		&c.DoubleLockHolder, &c.CreatedAt, &c.RotatedAt)
	return c, err
}

// scanUser maps one result row into a store.User.
func scanUser(row pgx.CollectableRow) (store.User, error) {
	var u store.User
	err := row.Scan(&u.ID, &u.Username, &u.Role, &u.IPAllowlist, &u.DeviceFingerprint, &u.ExternalID, &u.Active, &u.TokenHash, &u.CreatedAt)
	return u, err
}

// scanScimKey maps one result row into a store.ScimKey.
func scanScimKey(row pgx.CollectableRow) (store.ScimKey, error) {
	var k store.ScimKey
	err := row.Scan(&k.ID, &k.Name, &k.Owner, &k.TokenHash, &k.Disabled, &k.CreatedAt)
	return k, err
}

// scanEndpointAgent maps one result row into a store.EndpointAgent.
func scanEndpointAgent(row pgx.CollectableRow) (store.EndpointAgent, error) {
	var a store.EndpointAgent
	err := row.Scan(&a.ID, &a.Name, &a.TargetID, &a.KeyHash, &a.CreatedBy, &a.CreatedAt, &a.LastSeen, &a.RevokedAt)
	return a, err
}

// scanSession maps one result row into a store.Session.
func scanSession(row pgx.CollectableRow) (store.Session, error) {
	var s store.Session
	err := row.Scan(&s.ID, &s.Username, &s.Role, &s.Roles, &s.Scope, &s.TokenHash, &s.CreatedAt, &s.ExpiresAt)
	return s, err
}

// scanAgentKey maps one result row into a store.AgentKey.
func scanAgentKey(row pgx.CollectableRow) (store.AgentKey, error) {
	var k store.AgentKey
	err := row.Scan(&k.ID, &k.Name, &k.Owner, &k.TokenHash, &k.Disabled, &k.CreatedAt, &k.ExpiresAt, &k.LastUsedAt, &k.BudgetPerDay)
	return k, err
}

// scanAgentIdentity maps one result row into a store.AgentIdentity.
func scanAgentIdentity(row pgx.CollectableRow) (store.AgentIdentity, error) {
	var a store.AgentIdentity
	err := row.Scan(&a.ID, &a.SPIFFEID, &a.Owner, &a.Note, &a.Enrolled, &a.FirstSeen, &a.LastSeen, &a.CreatedBy, &a.CreatedAt)
	return a, err
}

// scanAgentQuarantine maps one result row into a store.AgentQuarantine.
func scanAgentQuarantine(row pgx.CollectableRow) (store.AgentQuarantine, error) {
	var q store.AgentQuarantine
	err := row.Scan(&q.ID, &q.Subject, &q.Reason, &q.CreatedBy, &q.CreatedAt)
	return q, err
}

// scanSetting maps one result row into a store.Setting.
func scanSetting(row pgx.CollectableRow) (store.Setting, error) {
	var s store.Setting
	err := row.Scan(&s.Key, &s.Value, &s.Secret, &s.UpdatedAt)
	return s, err
}

// scanAuditEvent maps one result row into a store.AuditEvent, for the read paths
// that project (id, ts, actor, action, detail). It is one definition so that the
// three list/export/tail closures that used to each inline this scan cannot drift
// when a column is added — the exact shape the review flagged as most at risk.
func scanAuditEvent(row pgx.CollectableRow) (store.AuditEvent, error) {
	var e store.AuditEvent
	err := row.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.Detail)
	return e, err
}

// scanBrokerAudit maps one result row into a store.BrokerAuditEvent.
func scanBrokerAudit(row pgx.CollectableRow) (store.BrokerAuditEvent, error) {
	var e store.BrokerAuditEvent
	err := row.Scan(&e.ID, &e.TS, &e.Actor, &e.OnBehalfOf, &e.ActorChain, &e.Action, &e.Detail, &e.Scope, &e.PrevHash, &e.HMAC)
	return e, err
}
