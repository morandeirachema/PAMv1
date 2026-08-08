package analytics

import (
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// ev builds an audit event with a fixed timestamp.
func ev(actor, action string, ts time.Time) store.AuditEvent {
	return store.AuditEvent{Actor: actor, Action: action, TS: ts}
}

// businessTime returns a weekday timestamp inside default business hours.
func businessTime() time.Time {
	// 2026-07-20 is a Monday; 10:00 is inside 07:00–20:00.
	return time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
}

// TestScoreBreakGlassIsHigh proves a break-glass access alone pushes an actor to
// at least high risk, and that the finding is explainable (a break_glass signal).
func TestScoreBreakGlassIsHigh(t *testing.T) {
	e := New(DefaultConfig())
	bt := businessTime()
	findings := e.Score([]store.AuditEvent{
		ev("mallory", "breakglass.access", bt),
		ev("mallory", "session.start", bt),
	})
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Actor != "mallory" {
		t.Fatalf("actor = %q", f.Actor)
	}
	if LevelRank(f.Level) < LevelRank(LevelHigh) {
		t.Fatalf("break-glass should be at least high; got %s (score %d)", f.Level, f.Score)
	}
	var hasBG bool
	for _, s := range f.Signals {
		if s.Name == "break_glass" {
			hasBG = true
		}
	}
	if !hasBG {
		t.Fatalf("finding must name the break_glass signal: %+v", f.Signals)
	}
}

// TestScoreClean proves an actor doing ordinary in-hours work scores no risk.
func TestScoreClean(t *testing.T) {
	e := New(DefaultConfig())
	bt := businessTime()
	findings := e.Score([]store.AuditEvent{
		ev("alice", "session.start", bt),
		ev("alice", "session.end", bt),
		ev("alice", "ssh.exec", bt),
	})
	if len(findings) != 0 {
		t.Fatalf("clean in-hours activity should score 0 findings, got %d: %+v", len(findings), findings)
	}
}

// TestScoreOffHours proves activity outside business hours contributes risk.
func TestScoreOffHours(t *testing.T) {
	e := New(DefaultConfig())
	night := time.Date(2026, 7, 20, 3, 0, 0, 0, time.UTC) // Monday 03:00
	day := businessTime()
	night1 := e.Score([]store.AuditEvent{ev("bob", "session.start", night)})
	day1 := e.Score([]store.AuditEvent{ev("bob", "session.start", day)})
	if len(day1) != 0 {
		t.Fatalf("a single in-hours session should not score: %+v", day1)
	}
	if len(night1) != 1 || night1[0].Score <= 0 {
		t.Fatalf("an off-hours session should score > 0: %+v", night1)
	}
}

// TestScoreAuthFailureBurstAndSort proves repeated auth failures accumulate and
// that findings sort by score descending.
func TestScoreAuthFailureBurstAndSort(t *testing.T) {
	e := New(DefaultConfig())
	bt := businessTime()
	var events []store.AuditEvent
	for i := 0; i < 6; i++ {
		events = append(events, ev("prober", "proxy.auth_failed", bt))
	}
	events = append(events, ev("normal", "session.start", bt)) // scores 0, omitted
	findings := e.Score(events)
	if len(findings) != 1 || findings[0].Actor != "prober" {
		t.Fatalf("expected only prober flagged, got %+v", findings)
	}
	if findings[0].Score < 6*DefaultConfig().Weights.AuthFailure && findings[0].Score != DefaultConfig().PerSignalCap {
		t.Fatalf("auth-failure burst under-scored: %d", findings[0].Score)
	}
}

// TestOffHoursTimezone proves the off-hours signal is evaluated in the
// configured timezone, not blindly in the UTC of the audit timestamp.
func TestOffHoursTimezone(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("tzdata unavailable")
	}
	// Monday 23:00 UTC = 19:00 EDT (July): off-hours in UTC (>= 20:00), but inside
	// business hours (07:00–20:00) in New York.
	ts := time.Date(2026, 7, 20, 23, 0, 0, 0, time.UTC)
	score := func(loc *time.Location) []Finding {
		return New(Config{Location: loc}).Score([]store.AuditEvent{
			{Actor: "bob", Action: "session.start", TS: ts},
		})
	}
	if f := score(time.UTC); len(f) != 1 {
		t.Fatalf("23:00 UTC should score off-hours when interpreted as UTC, got %+v", f)
	}
	if f := score(ny); len(f) != 0 {
		t.Fatalf("23:00 UTC = 19:00 EDT should be in-hours in New York, got %+v", f)
	}
}

// TestPerSignalCap proves a single signal category cannot exceed the cap.
func TestPerSignalCap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PerSignalCap = 20
	e := New(cfg)
	bt := businessTime()
	var events []store.AuditEvent
	for i := 0; i < 100; i++ {
		events = append(events, ev("x", "proxy.auth_failed", bt))
	}
	f := e.Score(events)[0]
	for _, s := range f.Signals {
		if s.Points > 20 {
			t.Fatalf("signal %s exceeded cap: %d", s.Name, s.Points)
		}
	}
}

// evT builds an activity event carrying a target, which is what the novelty
// signal reads.
func evT(actor, target string, ts time.Time) store.AuditEvent {
	return store.AuditEvent{Actor: actor, Action: "session.start", TS: ts,
		Detail: "target:" + target + " cred_user:svc"}
}

// signal returns a finding's named signal, or nil.
func signal(f Finding, name string) *Signal {
	for i := range f.Signals {
		if f.Signals[i].Name == name {
			return &f.Signals[i]
		}
	}
	return nil
}

// find returns the finding for one actor, or a zero Finding.
func find(fs []Finding, actor string) Finding {
	for _, f := range fs {
		if f.Actor == actor {
			return f
		}
	}
	return Finding{}
}

// TestNoveltyNeedsHistoryToMeanAnything is the whole point of the baseline: the
// same event is unremarkable for someone who works on that host every day and
// interesting for someone who has never touched it.
func TestNoveltyScoresOnlyUnfamiliarTargets(t *testing.T) {
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC) // a Monday, in hours
	past := now.Add(-72 * time.Hour)
	base := BuildBaseline([]store.AuditEvent{
		evT("alice", "web-01", past),
		evT("alice", "web-02", past),
	})
	e := New(DefaultConfig())

	// Familiar target: no novelty.
	f := find(e.ScoreWithBaseline([]store.AuditEvent{evT("alice", "web-01", now)}, base), "alice")
	if s := signal(f, "new_target"); s != nil {
		t.Fatalf("a target alice uses every day scored as novel: %+v", s)
	}
	// Unfamiliar target: novelty, counted once however many sessions.
	f = find(e.ScoreWithBaseline([]store.AuditEvent{
		evT("alice", "dc-01", now), evT("alice", "dc-01", now), evT("alice", "vault-01", now),
	}, base), "alice")
	s := signal(f, "new_target")
	if s == nil {
		t.Fatal("access to two never-before-used targets scored no novelty")
	}
	if s.Count != 2 {
		t.Fatalf("new_target count = %d, want 2 (distinct targets, not sessions)", s.Count)
	}
}

// TestNoveltyIsSilentWithoutHistory guards the failure mode that would get this
// signal switched off: on the first run, and for every new joiner, EVERY target
// is unfamiliar. Scoring that is an alert storm, and an alert storm is how
// people learn to ignore alerts.
func TestNoveltyIsSilentWithoutHistory(t *testing.T) {
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	e := New(DefaultConfig())
	for _, tc := range []struct {
		name string
		base *Baseline
	}{
		{"no baseline at all", nil},
		{"baseline that does not know this actor", BuildBaseline([]store.AuditEvent{evT("bob", "web-01", now.Add(-time.Hour))})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := find(e.ScoreWithBaseline([]store.AuditEvent{evT("newjoiner", "dc-01", now)}, tc.base), "newjoiner")
			if s := signal(f, "new_target"); s != nil {
				t.Fatalf("scored novelty with nothing to compare against: %+v", s)
			}
		})
	}
}

// TestPeerOutlierFlagsTheOutlierAndNotThePeers proves what this fixture can
// actually show: an actor well above the group is flagged and the group is not.
//
// It deliberately does NOT claim to prove "median, not mean". With a single
// outlier both statistics reach the same verdict here, so a test named for that
// distinction would be asserting something it cannot see. The median is still
// the right choice — it is the one that stays put when several actors are
// extreme — but that is a design argument recorded in peerVolumes, not a claim
// this test earns.
func TestPeerOutlierFlagsTheOutlierAndNotThePeers(t *testing.T) {
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	var events []store.AuditEvent
	// Five peers with two sessions each: median 2, threshold 2*3 = 6.
	for _, who := range []string{"a", "b", "c", "d", "e"} {
		events = append(events, evT(who, "web-01", now), evT(who, "web-01", now))
	}
	// One actor far above them.
	for range 12 {
		events = append(events, evT("mallory", "web-01", now))
	}
	fs := New(DefaultConfig()).ScoreWithBaseline(events, nil)
	if s := signal(find(fs, "mallory"), "peer_outlier"); s == nil {
		t.Fatal("an actor with 6x the peer median was not flagged as an outlier")
	}
	for _, who := range []string{"a", "b", "c", "d", "e"} {
		if s := signal(find(fs, who), "peer_outlier"); s != nil {
			t.Fatalf("ordinary actor %s was flagged as a peer outlier: %+v", who, s)
		}
	}
}

// TestPeerOutlierNeedsAPeerGroup: two people are not a distribution, and
// flagging one of them teaches nobody anything.
func TestPeerOutlierNeedsAPeerGroup(t *testing.T) {
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	events := []store.AuditEvent{evT("a", "web-01", now)}
	for range 20 {
		events = append(events, evT("busy", "web-01", now))
	}
	fs := New(DefaultConfig()).ScoreWithBaseline(events, nil)
	if s := signal(find(fs, "busy"), "peer_outlier"); s != nil {
		t.Fatalf("flagged an outlier against a peer group of two: %+v", s)
	}
}

// TestTargetOfParsesTheAuditDetail covers the extraction the novelty signal
// depends on, including the quoted form auditField produces.
func TestTargetOfParsesTheAuditDetail(t *testing.T) {
	for detail, want := range map[string]string{
		"target:web-01 cred_user:svc":       "web-01",
		`target:"Prod DB 01" cred_user:svc`: "Prod DB 01",
		"cred_user:svc target:db-02":        "db-02",
		"target:db-03":                      "db-03",
		"user:alice action:login":           "",
		"":                                  "",
	} {
		if got := targetOf(store.AuditEvent{Detail: detail}); got != want {
			t.Errorf("targetOf(%q) = %q, want %q", detail, got, want)
		}
	}
}

// TestResponseScoreExcludesAuthFailures pins the fix for the session-DoS: risk
// from auth failures — which carry an attacker-CHOSEN, unauthenticated name — is
// visible in Level (so it alerts) but excluded from ResponseLevel (so it drives
// no automated action against the named account).
func TestResponseScoreExcludesAuthFailures(t *testing.T) {
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	e := New(DefaultConfig())

	// Pure failed logins under a victim's name, enough to peg the full score.
	var evs []store.AuditEvent
	for range 15 {
		evs = append(evs, ev("victim", "login.failed", now))
	}
	f := find(e.Score(evs), "victim")
	if f.Level != LevelCritical {
		t.Fatalf("full level = %s, want critical (the alert must still fire)", f.Level)
	}
	if f.ResponseLevel != LevelLow {
		t.Fatalf("response level = %s, want low — auth failures under a name the actor "+
			"did not choose must not drive a response against them", f.ResponseLevel)
	}

	// A genuinely authenticated bad actor: response level tracks the full level,
	// so the response still fires for someone who actually did something.
	bg := []store.AuditEvent{ev("mallory", "breakglass.access", now), ev("mallory", "breakglass.access", now)}
	fb := find(e.Score(bg), "mallory")
	if fb.Level != LevelCritical || fb.ResponseLevel != LevelCritical {
		t.Fatalf("an authenticated critical actor must keep a critical response level, got level=%s response=%s",
			fb.Level, fb.ResponseLevel)
	}

	// Mixed: an attacker cannot PUSH a legitimately-active actor over the response
	// threshold by adding failed logins under their name.
	mixed := []store.AuditEvent{evT("dana", "web-01", now)} // one ordinary session
	for range 15 {
		mixed = append(mixed, ev("dana", "login.failed", now))
	}
	fm := find(e.Score(mixed), "dana")
	if fm.ResponseLevel == LevelCritical || fm.ResponseLevel == LevelHigh {
		t.Fatalf("failed logins pushed a legitimate actor's RESPONSE level to %s", fm.ResponseLevel)
	}
}
