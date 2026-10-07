package api

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/report"
)

const (
	// digestLockKey keeps N replicas to one digest per tick ("pam_dig").
	digestLockKey = int64(0x70616d5f646967)
	// digestTick is how often the worker looks at the clock; the mail goes
	// out on the first tick at or after the configured hour.
	digestTick = 5 * time.Minute
	// digestRetry spaces the attempts after a failed send, so a dead relay
	// costs one report.digest_failed row an hour rather than one a tick.
	digestRetry = time.Hour
	// digestUnusedDays is the unused-objects window the digest reports.
	digestUnusedDays = 30
	digestActor      = "system-report"
)

// digestState is the daily digest's configuration and its retry clock.
type digestState struct {
	to   []string
	hour int
	// send delivers the mail; nil is the SMTP relay. Tests replace it.
	send func(to []string, subject, body string) error

	mu        sync.Mutex
	failedDay string
	retryAt   time.Time
}

// RunDigestWorker mails the daily report digest (Phase 277) until ctx is
// cancelled. It is a no-op when no recipient or no relay is configured.
// Under PAM_OT_AIRGAP, config validation refuses PAM_REPORT_DIGEST_TO unless
// PAM_OT_AIRGAP_ALLOW certifies the relay is inside the enclave.
func (s *Server) RunDigestWorker(ctx context.Context) {
	if len(s.digest.to) == 0 || s.shareSMTPAddr == "" {
		return
	}
	s.log.Info("report digest worker started", "hour_utc", s.digest.hour, "recipients", len(s.digest.to))
	t := time.NewTicker(digestTick)
	defer t.Stop()
	for {
		ran, err := s.store.WithLeaderLock(ctx, digestLockKey, func(c context.Context) error {
			s.digestPass(c, time.Now())
			return nil
		})
		if err != nil {
			s.log.Warn("report digest lock unavailable; skipping tick", "err", err)
		} else if !ran {
			s.log.Debug("report digest tick skipped (another replica is leader)")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// digestPass sends today's digest if it is due and not already sent. "Sent"
// is read from the audit trail — the last report.digest_sent row names its
// day — rather than kept in memory, so a restart or a failover to another
// replica neither repeats nor skips a day. It reports whether a mail went
// out.
func (s *Server) digestPass(ctx context.Context, now time.Time) bool {
	now = now.UTC()
	if now.Hour() < s.digest.hour {
		return false
	}
	day := now.Format(time.DateOnly)
	last, err := s.store.LatestAuditByAction(ctx, "report.digest_sent")
	if err != nil {
		s.log.Warn("report digest: cannot read the last digest", "err", err)
		return false
	}
	if last != nil && report.Field(last.Detail, "day") == day {
		return false
	}
	s.digest.mu.Lock()
	waiting := s.digest.failedDay == day && now.Before(s.digest.retryAt)
	s.digest.mu.Unlock()
	if waiting {
		return false
	}

	ctx = withPrincipal(ctx, &auth.Principal{Name: digestActor, Role: auth.RoleAdmin})
	until := time.Date(now.Year(), now.Month(), now.Day(), s.digest.hour, 0, 0, 0, time.UTC)
	since := until.Add(-24 * time.Hour)
	unusedSince := until.AddDate(0, 0, -digestUnusedDays)
	subject, body, conns, err := s.buildDigest(ctx, day, since, until, unusedSince)
	if err == nil {
		err = s.sendDigest(subject, body)
	}
	if err != nil {
		s.digest.mu.Lock()
		s.digest.failedDay, s.digest.retryAt = day, now.Add(digestRetry)
		s.digest.mu.Unlock()
		s.log.Error("report digest failed", "day", day, "err", err)
		s.audit(ctx, "report.digest_failed", fmt.Sprintf("day:%s error:%q", day, err.Error()))
		return false
	}
	// The digest_sent row is the only record that today's mail went out; if
	// it cannot be written, the next tick would mail again, every five
	// minutes (review of 274-280). Hold this replica off for the retry
	// period instead: one duplicate an hour at worst, not a flood.
	if err := s.auditAs(ctx, digestActor, "report.digest_sent", fmt.Sprintf("day:%s recipients:%d connections:%d", day, len(s.digest.to), conns)); err != nil {
		s.digest.mu.Lock()
		s.digest.failedDay, s.digest.retryAt = day, now.Add(digestRetry)
		s.digest.mu.Unlock()
		s.log.Error("report digest sent but not recorded; holding off", "day", day, "err", err)
	}
	return true
}

// buildDigest reads the trail and inventory and renders the mail.
func (s *Server) buildDigest(ctx context.Context, day string, since, until, unusedSince time.Time) (subject, body string, conns int, err error) {
	events, err := s.store.ExportAuditActions(ctx, unusedSince, until, report.Actions())
	if err != nil {
		return "", "", 0, err
	}
	users, err := s.store.ListUsers(ctx, 0, 0)
	if err != nil {
		return "", "", 0, err
	}
	targets, err := s.store.ListTargets(ctx, 0, 0)
	if err != nil {
		return "", "", 0, err
	}
	var dayEvents = events[:0:0]
	for _, e := range events {
		if !e.TS.Before(since) {
			dayEvents = append(dayEvents, e)
		}
	}
	st := report.Summarize(report.Connections(dayEvents), since, until)
	unused := report.FindUnused(users, targets, events, unusedSince, until)
	subject, body = report.Digest(day, st, report.CriticalConnects(dayEvents), unused, digestUnusedDays)
	return subject, body, st.Total, nil
}

func (s *Server) sendDigest(subject, body string) error {
	if s.digest.send != nil {
		return s.digest.send(s.digest.to, subject, body)
	}
	return alert.SendText(s.shareSMTPAddr, s.shareSMTPFrom, s.digest.to, s.shareSMTPUser, s.shareSMTPPass, subject, body)
}
