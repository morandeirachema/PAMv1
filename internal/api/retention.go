package api

// retention.go bounds the unbounded growth of two data stores: session
// recordings on disk and audit rows in the database. Both are opt-in
// (0 = keep forever) and run under the same leader lock as the other background
// workers, so one replica prunes per tick. Audit pruning is refused while the
// tamper-evident HMAC chain is enabled — deleting the chain head would break
// verification — so the integrity guarantee is never silently traded for space.

import (
	"context"
	"fmt"
	"time"

	"github.com/morandeirachema/pamv1/internal/maint"
)

// RetentionPolicy configures the retention worker. Days <= 0 disables that
// dimension. AuditChained is true when the primary audit HMAC chain is on, in
// which case audit pruning is skipped (loudly).
type RetentionPolicy struct {
	RecordingDays int
	AuditDays     int
	AuditChained  bool
}

// enabled reports whether either dimension will prune anything.
func (p RetentionPolicy) enabled() bool { return p.RecordingDays > 0 || p.AuditDays > 0 }

// RunRetentionWorker prunes aged recordings and audit rows every interval until
// ctx is cancelled. It is a no-op when nothing is configured to prune.
func (s *Server) RunRetentionWorker(ctx context.Context, interval time.Duration, p RetentionPolicy) {
	if !p.enabled() || interval <= 0 {
		return
	}
	s.log.Info("retention worker started",
		"interval", interval.String(), "recording_days", p.RecordingDays, "audit_days", p.AuditDays, "audit_chained", p.AuditChained)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ran, err := s.store.WithLeaderLock(systemContext(ctx), retentionLockKey, func(c context.Context) error {
				s.retentionPass(c, time.Now(), p)
				return nil
			})
			if err != nil {
				s.log.Warn("retention lock unavailable; skipping pass", "err", err)
			} else if !ran {
				s.log.Debug("retention pass skipped (another replica is leader)")
			}
		}
	}
}

// retentionPass runs one prune of recordings and audit rows against the given
// now. It audits the count removed in each dimension; a failure in one dimension
// is logged and does not stop the other.
func (s *Server) retentionPass(ctx context.Context, now time.Time, p RetentionPolicy) {
	if p.RecordingDays > 0 && s.recordingDir != "" {
		cutoff := now.AddDate(0, 0, -p.RecordingDays)
		removed, err := maint.PruneRecordings(s.recordingDir, cutoff)
		if err != nil {
			s.log.Warn("recording retention: some files could not be pruned", "err", err)
		}
		if removed > 0 {
			s.audit(ctx, "recording.pruned", fmt.Sprintf("count:%d older_than_days:%d", removed, p.RecordingDays))
		}
	}
	if p.AuditDays > 0 {
		if p.AuditChained {
			// Deleting the chain head breaks VerifyAuditChain; retention here must be
			// an out-of-band WORM export + re-genesis, not an automated delete.
			s.log.Warn("audit retention skipped: the tamper-evident HMAC chain is enabled (pruning would break verification); export to WORM storage and re-anchor manually")
			return
		}
		cutoff := now.AddDate(0, 0, -p.AuditDays)
		removed, err := s.store.PruneAuditBefore(ctx, cutoff)
		if err != nil {
			s.log.Warn("audit retention: prune failed", "err", err)
			return
		}
		if removed > 0 {
			s.audit(ctx, "audit.pruned", fmt.Sprintf("count:%d older_than_days:%d", removed, p.AuditDays))
		}
	}
}
