package api

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// RotationPolicy configures the background credential-lifecycle worker.
type RotationPolicy struct {
	// Interval is how often the worker runs (0 disables it).
	Interval time.Duration
	// MaxAge rotates password credentials whose secret is older than this
	// (0 = reconcile/report only, never auto-rotate).
	MaxAge time.Duration
}

// lifecycleReport summarizes one worker pass.
type lifecycleReport struct {
	Checked   int
	OutOfSync int
	Rotated   int
}

// systemContext is the actor context the scheduler audits under.
func systemContext(ctx context.Context) context.Context {
	return withPrincipal(ctx, &auth.Principal{Name: "system-scheduler", Role: auth.RoleAdmin})
}

// RotateCredentialByID rotates a single credential by ID and audits the result.
// It is the entry point the SSH proxy calls to force post-session rotation
// (actor system-scheduler); a missing credential/target is a no-op with a log.
func (s *Server) RotateCredentialByID(ctx context.Context, credentialID int64) {
	ctx = systemContext(ctx)
	cred, err := s.store.GetCredential(ctx, credentialID)
	if err != nil {
		s.log.Warn("post-session rotation: credential not found", "credential", credentialID, "err", err)
		return
	}
	target, err := s.store.GetTarget(ctx, cred.TargetID)
	if err != nil {
		s.log.Warn("post-session rotation: target not found", "credential", credentialID, "err", err)
		return
	}
	// A Zero Standing Privilege credential has no stored secret to rotate: the
	// certificate used in the session was ephemeral and has already expired.
	if cred.SecretType == "ssh_ca" {
		s.log.Debug("post-session rotation skipped for zero-standing-privilege credential", "credential", credentialID)
		return
	}
	if _, err := s.rotateCredential(ctx, cred, target); err != nil {
		s.audit(ctx, "credential.rotate_failed", fmt.Sprintf("credential:%d reason:post-session error:%v", cred.ID, err))
		s.log.Error("post-session rotation failed", "credential", cred.ID, "err", err)
		return
	}
	s.audit(ctx, "credential.rotate", fmt.Sprintf("credential:%d target:%s reason:post-session", cred.ID, target.Name))
}

// invalidateCheckout closes an expired-but-unreturned lease and rotates the
// credential behind it, so the secret its holder saw stops working. Closing the
// lease first (idempotent) acts as a claim: if a concurrent sweep or check-in
// already returned it, CheckinCheckout errors and we skip, so the credential is
// never rotated twice for the same expiry. Returns (true, nil) when it rotated,
// (false, nil) when the claim was lost or the credential/target vanished, and
// (false, err) when the rotation itself failed (already audited).
func (s *Server) invalidateCheckout(ctx context.Context, co store.Checkout, now time.Time) (bool, error) {
	if err := s.store.CheckinCheckout(ctx, co.ID, now); err != nil {
		return false, nil // a concurrent sweep or check-in already closed this lease
	}
	cred, err := s.store.GetCredential(ctx, co.CredentialID)
	if err != nil {
		return false, nil
	}
	target, err := s.store.GetTarget(ctx, cred.TargetID)
	if err != nil {
		return false, nil
	}
	if _, rerr := s.rotateCredential(ctx, cred, target); rerr != nil {
		s.audit(ctx, "credential.checkin_rotate_failed",
			fmt.Sprintf("credential:%d reason:checkout-expired error:%v", cred.ID, rerr))
		return false, rerr
	}
	s.audit(ctx, "credential.rotate",
		fmt.Sprintf("credential:%d target:%s reason:checkout-expired", cred.ID, target.Name))
	return true, nil
}

// sweepExpiredCheckouts rotates the credential behind every expired-but-unreturned
// checkout and marks the lease returned, so a secret revealed at checkout stops
// working even when the holder never checks it back in. Returns the count rotated.
func (s *Server) sweepExpiredCheckouts(ctx context.Context, now time.Time) int {
	cos, err := s.store.ListCheckouts(ctx, false, now, 0, 0)
	if err != nil {
		s.log.Error("lifecycle: list checkouts", "err", err)
		return 0
	}
	rotated := 0
	for i := range cos {
		co := cos[i]
		if co.ReturnedAt != nil || !co.ExpiresAt.Before(now) {
			continue // already returned, or still active
		}
		func() {
			defer func() {
				if p := recover(); p != nil {
					s.log.Error("lifecycle: panic sweeping checkout", "checkout", co.ID, "panic", p)
				}
			}()
			if ok, _ := s.invalidateCheckout(ctx, co, now); ok {
				rotated++
			}
		}()
	}
	return rotated
}

// invalidateExpiredCheckoutFor rotates and closes an expired-but-unreturned lease
// on credentialID (if any) before the credential is handed to a new holder, so a
// re-checkout that races ahead of the periodic sweep can never reuse an expired
// holder's still-valid secret. Returns whether it rotated; an error means an
// expired lease existed but could not be invalidated (the caller must not proceed).
func (s *Server) invalidateExpiredCheckoutFor(ctx context.Context, credentialID int64, now time.Time) (bool, error) {
	cos, err := s.store.ListCheckouts(ctx, false, now, 0, 0)
	if err != nil {
		return false, err
	}
	for i := range cos {
		co := cos[i]
		if co.CredentialID != credentialID || co.ReturnedAt != nil || !co.ExpiresAt.Before(now) {
			continue
		}
		return s.invalidateCheckout(ctx, co, now)
	}
	return false, nil
}

// Advisory-lock keys for the background workers, so across HA replicas only one
// runs each periodic job per tick (leader election). Distinct from the migration
// ("pam_mig") and broker-chain ("pam_br") lock keys in pgstore.
const (
	lifecycleLockKey = int64(0x70616d5f6c6663) // "pam_lfc"
	analyticsLockKey = int64(0x70616d5f616e61) // "pam_ana"
	retentionLockKey = int64(0x70616d5f726574) // "pam_ret"
	campaignLockKey  = int64(0x70616d5f636d70) // "pam_cmp"
)

// RunLifecycleWorker runs the credential-lifecycle worker until ctx is cancelled:
// on each tick it reconciles every credential (detecting drift) and rotates any
// password credential older than pol.MaxAge. It is safe to call in a goroutine.
// The pass runs under a leader lock so N replicas don't each rotate the same
// credential concurrently.
func (s *Server) RunLifecycleWorker(ctx context.Context, pol RotationPolicy) {
	if pol.Interval <= 0 {
		return
	}
	s.log.Info("credential-lifecycle worker started", "interval", pol.Interval.String(), "max_age", pol.MaxAge.String())
	ticker := time.NewTicker(pol.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ran, err := s.store.WithLeaderLock(systemContext(ctx), lifecycleLockKey, func(c context.Context) error {
				rep := s.runLifecycleOnce(c, pol.MaxAge, time.Now())
				s.log.Info("credential-lifecycle pass",
					"checked", rep.Checked, "out_of_sync", rep.OutOfSync, "rotated", rep.Rotated)
				return nil
			})
			if err != nil {
				s.log.Warn("credential-lifecycle lock unavailable; skipping pass", "err", err)
			} else if !ran {
				s.log.Debug("credential-lifecycle pass skipped (another replica is leader)")
			}
		}
	}
}

// RunCampaignScheduler opens the next campaign in every recurring series whose
// turn has come, until ctx is cancelled.
//
// Recertification is a calendar obligation — "every quarter, someone reviews who
// can reach the PCI safe" — and a control that depends on somebody remembering
// to press a button is one that lapses the first busy quarter. This is the
// button being pressed.
//
// Under the leader lock, so N replicas do not each open the same campaign. The
// anchor's schedule is advanced AFTER the spawn succeeds: a crash between the
// two repeats the spawn next tick, which duplicates a review, and duplicating a
// review is recoverable in a way that silently skipping a quarter is not.
func (s *Server) RunCampaignScheduler(ctx context.Context) {
	const interval = time.Hour
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ran, err := s.store.WithLeaderLock(systemContext(ctx), campaignLockKey, func(c context.Context) error {
				now := time.Now()
				if n := s.spawnDueCampaigns(c, now); n > 0 {
					s.log.Info("recurring certification campaigns opened", "count", n)
				}
				if n := s.sendCampaignReminders(c, now); n > 0 {
					s.log.Info("certification reminders sent", "count", n)
				}
				return nil
			})
			if err != nil {
				s.log.Warn("campaign scheduler lock unavailable; skipping pass", "err", err)
			} else if !ran {
				s.log.Debug("campaign scheduler pass skipped (another replica is leader)")
			}
		}
	}
}

// spawnDueCampaigns opens one successor per due anchor and returns how many were
// opened. One anchor's failure does not stop the others: a broken series must
// not take the rest of the schedule down with it.
func (s *Server) spawnDueCampaigns(ctx context.Context, now time.Time) int {
	due, err := s.store.ListDueCampaigns(ctx, now)
	if err != nil {
		s.log.Warn("campaign scheduler: reading due campaigns failed", "err", err)
		return 0
	}
	opened := 0
	for _, anchor := range due {
		next := now.UTC().AddDate(0, 0, anchor.RecurDays)
		child := store.Campaign{
			// The child is named for the occasion, so a list of ten quarters is
			// ten distinguishable rows rather than ten identical ones.
			Name:      fmt.Sprintf("%s (%s)", anchor.Name, now.UTC().Format("2006-01-02")),
			CreatedBy: anchor.CreatedBy, Status: "open", DueAt: &next,
			ScopeKind: anchor.ScopeKind, ScopeSafeID: anchor.ScopeSafeID, ScopeSubject: anchor.ScopeSubject,
			Reviewer: anchor.Reviewer, RemindAt: s.firstReminder(&next, now),
			// Children carry no schedule: the anchor is the only row that spawns,
			// so a series can never fork.
		}
		if err := s.store.CreateCampaign(ctx, &child); err != nil {
			s.log.Warn("campaign scheduler: creating the next campaign failed", "anchor", anchor.ID, "err", err)
			continue
		}
		items, serr := s.snapshotAccess(ctx, &child)
		if serr != nil {
			s.log.Warn("campaign scheduler: snapshotting access failed", "campaign", child.ID, "err", serr)
			// The campaign exists but is empty; leave the schedule where it is so
			// the next tick tries again rather than silently skipping the period.
			continue
		}
		s.auditAs(ctx, anchor.CreatedBy, "certification.campaign_created",
			fmt.Sprintf("campaign:%d name:%q items:%d %s recurring_from:%d",
				child.ID, child.Name, items, campaignScopeDetail(&child), anchor.ID))
		if err := s.store.SetCampaignNextRun(ctx, anchor.ID, next); err != nil {
			s.log.Warn("campaign scheduler: advancing the schedule failed; it will retry", "anchor", anchor.ID, "err", err)
		}
		opened++
	}
	return opened
}

// campaignReminderEvery is how often a campaign is nudged again once its first
// reminder has fired. Daily: often enough that an overdue review is visible,
// rare enough that the alert channel stays worth reading — an alert nobody reads
// is the same as no alert.
const campaignReminderEvery = 24 * time.Hour

// sendCampaignReminders nudges the reviewers of every open campaign whose
// reminder has come due, and returns how many were sent.
//
// Recertification lapses quietly: the campaign stays open, the items stay
// pending, and nothing happens until an auditor asks. This is the thing that
// makes it noisy instead. Assignment (Phase 69) is what makes the nudge
// actionable — the alert names who is holding it up.
//
// A campaign with nothing pending is DONE even if nobody closed it, so its
// reminder is cancelled rather than repeated: nagging about finished work is how
// a channel gets muted, and a muted channel is where the next lapse hides.
func (s *Server) sendCampaignReminders(ctx context.Context, now time.Time) int {
	due, err := s.store.ListCampaignsToRemind(ctx, now)
	if err != nil {
		s.log.Warn("campaign reminders: reading due reminders failed", "err", err)
		return 0
	}
	sent := 0
	for _, c := range due {
		items, ierr := s.store.ListCampaignItems(ctx, c.ID)
		if ierr != nil {
			s.log.Warn("campaign reminders: reading items failed", "campaign", c.ID, "err", ierr)
			continue
		}
		pending, byReviewer := 0, map[string]int{}
		for _, it := range items {
			if it.Decision != "pending" {
				continue
			}
			pending++
			who := it.Reviewer
			if who == "" {
				who = "(unassigned)"
			}
			byReviewer[who]++
		}
		if pending == 0 {
			// Finished but not closed. Stop nudging; closing it is a human's call.
			if err := s.store.SetCampaignRemindAt(ctx, c.ID, nil); err != nil {
				s.log.Warn("campaign reminders: cancelling failed", "campaign", c.ID, "err", err)
			}
			continue
		}
		detail := fmt.Sprintf("campaign:%d name:%q pending:%d %s reviewers:%s",
			c.ID, c.Name, pending, duePhrase(c.DueAt, now), reviewerBreakdown(byReviewer))
		s.alerter.Notify(ctx, alert.Event{
			Type: "certification.reminder", Actor: c.CreatedBy, Detail: detail, Time: now,
		})
		s.auditAs(ctx, c.CreatedBy, "certification.reminder", detail)
		next := now.Add(campaignReminderEvery)
		if err := s.store.SetCampaignRemindAt(ctx, c.ID, &next); err != nil {
			s.log.Warn("campaign reminders: rescheduling failed", "campaign", c.ID, "err", err)
		}
		sent++
	}
	return sent
}

// duePhrase renders how a campaign stands against its due date. "overdue" is
// said in those words rather than as a negative number, because the alert is
// read by a human deciding whether to care today.
func duePhrase(due *time.Time, now time.Time) string {
	if due == nil {
		return "due:none"
	}
	days := int(due.Sub(now).Hours() / 24)
	if days < 0 {
		return fmt.Sprintf("due:overdue_by_%dd", -days)
	}
	return fmt.Sprintf("due:in_%dd", days)
}

// reviewerBreakdown renders "who is holding this up", sorted so the same state
// always produces the same string — an alert that reorders itself looks like a
// change when nothing changed.
func reviewerBreakdown(byReviewer map[string]int) string {
	names := make([]string, 0, len(byReviewer))
	for k := range byReviewer {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s(%d)", n, byReviewer[n]))
	}
	return strings.Join(parts, ",")
}

// RunGC periodically deletes rows whose lifetime has ended, so the tables that
// grow with ordinary use stay bounded. It stops when ctx is cancelled.
//
// It sweeps expired **login sessions** unconditionally, and agent-broker resume
// tokens and abandoned parked approvals when the broker is enabled. The login
// sessions are the reason this loop is no longer broker-conditional: expiry used
// to be enforced only by filtering reads, so every portal login, every
// break-glass activation and every 60-second RDP viewer token left a row behind
// forever — bloat in PostgreSQL, and a real leak in the in-memory store. Broker
// tokens and OIDC states already had a sweep; login sessions were simply
// forgotten, and a deployment with no broker had no GC at all.
func (s *Server) RunGC(ctx context.Context) {
	const interval = 10 * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sysCtx := systemContext(ctx)
			if n, err := s.store.DeleteExpiredSessions(sysCtx, time.Now()); err != nil {
				s.log.Warn("login session GC failed", "err", err)
			} else if n > 0 {
				s.log.Debug("login session GC swept expired sessions", "deleted", n)
			}
			if s.broker == nil {
				continue
			}
			if n, err := s.store.DeleteExpiredBrokerTokens(sysCtx); err != nil {
				s.log.Warn("broker token GC failed", "err", err)
			} else if n > 0 {
				s.log.Debug("broker token GC swept expired/used tokens", "deleted", n)
			}
			if n := s.broker.SweepExpiredParked(ctx, time.Now()); n > 0 {
				s.log.Debug("broker swept abandoned parked approvals", "evicted", n)
			}
		}
	}
}

// runLifecycleOnce performs a single reconcile+age-rotation pass. now is passed
// explicitly so the aging decision is testable.
func (s *Server) runLifecycleOnce(ctx context.Context, maxAge time.Duration, now time.Time) lifecycleReport {
	var rep lifecycleReport
	// Invalidate any secret still outstanding on an expired checkout that was
	// never returned, so "the password the holder saw stops working" holds even
	// without an explicit check-in.
	rep.Rotated += s.sweepExpiredCheckouts(ctx, now)
	creds, err := s.store.ListCredentials(ctx, 0, 0, 0)
	if err != nil {
		s.log.Error("lifecycle: list credentials", "err", err)
		return rep
	}
	for i := range creds {
		cred := &creds[i]
		// Isolate each credential: a panic in a third-party-backed connector must
		// not crash the worker goroutine (and with it the whole process).
		func() {
			defer func() {
				if p := recover(); p != nil {
					s.log.Error("lifecycle: panic handling credential", "credential", cred.ID, "panic", p)
				}
			}()
			target, terr := s.store.GetTarget(ctx, cred.TargetID)
			if terr != nil {
				s.log.Warn("lifecycle: target lookup failed", "credential", cred.ID, "err", terr)
				return
			}
			res := s.reconcileOne(ctx, cred, target, false)
			rep.Checked++
			if res.Status == "out_of_sync" {
				rep.OutOfSync++
			}
			if maxAge > 0 && cred.SecretType == "password" && credentialAge(cred, now) > maxAge {
				if _, ok := s.rotators[target.Protocol]; ok {
					if _, rerr := s.rotateCredential(ctx, cred, target); rerr == nil {
						rep.Rotated++
						s.audit(ctx, "credential.rotate",
							"credential:"+strconv.FormatInt(cred.ID, 10)+" target:"+target.Name+" reason:max-age")
					} else {
						s.audit(ctx, "credential.rotate_failed",
							fmt.Sprintf("credential:%d target:%s reason:max-age error:%v", cred.ID, target.Name, rerr))
						s.log.Error("lifecycle: rotate", "credential", cred.ID, "err", rerr)
					}
				}
			}
		}()
	}
	return rep
}

// credentialAge is the time since the secret was last set (rotated, else created).
func credentialAge(cred *store.Credential, now time.Time) time.Duration {
	last := cred.CreatedAt
	if cred.RotatedAt != nil {
		last = *cred.RotatedAt
	}
	return now.Sub(last)
}
