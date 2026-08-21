package analytics

import (
	"fmt"
	"strings"
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

// evBroker builds a brokered tool-call audit event as the primary audit trail
// records it (Phase 161): an outcome-bearing action name, and a detail carrying
// `tool:<name> status:<s> call:<id>` plus `target:<name>` when the call's
// arguments named a target. Pass target "" for a call that names none.
func evBroker(actor, action, target string, ts time.Time) store.AuditEvent {
	status := action
	if i := strings.LastIndex(action, "."); i >= 0 {
		status = action[i+1:]
	}
	detail := "tool:ssh_exec status:" + status + " call:c-1"
	if target != "" {
		detail += " target:" + target
	}
	return store.AuditEvent{Actor: actor, Action: action, TS: ts, Detail: detail}
}

// TestBrokeredCallsCountAsActivity proves the gap Phase 161 closes: an AI agent
// hammering the broker used to score nothing at all, because none of the
// broker's actions were in any signal map. Now an executed call is activity, so
// the volume signals — velocity and peer outlier — see agents.
//
// The control case is the honest half of the proof: the SAME burst of calls
// that never executed still scores nothing, so what is being tested is
// membership of the activity set, not "any event with broker in the name".
func TestBrokeredCallsCountAsActivity(t *testing.T) {
	bt := businessTime()
	e := New(DefaultConfig())

	t.Run("velocity", func(t *testing.T) {
		var evs []store.AuditEvent
		for range 20 { // well past the default VelocityLimit of 8
			evs = append(evs, evBroker("agent-7", "broker.tool_call.executed", "web-01", bt))
		}
		f := find(e.Score(evs), "agent-7")
		if f.Score <= 0 {
			t.Fatalf("20 executed brokered calls scored nothing: %+v", f)
		}
		s := signal(f, "high_velocity")
		if s == nil {
			t.Fatalf("a burst of brokered calls produced no velocity signal: %+v", f.Signals)
		}
		if want := 20 - DefaultConfig().VelocityLimit; s.Count != want {
			t.Fatalf("high_velocity count = %d, want %d (only the calls past the limit)", s.Count, want)
		}
	})

	t.Run("peer outlier among agents", func(t *testing.T) {
		var evs []store.AuditEvent
		// Five ordinary agents, two calls each: median 2, threshold 2*3 = 6.
		for _, who := range []string{"agent-a", "agent-b", "agent-c", "agent-d", "agent-e"} {
			evs = append(evs,
				evBroker(who, "broker.tool_call.executed", "web-01", bt),
				evBroker(who, "broker.tool_call.executed", "web-01", bt))
		}
		for range 12 {
			evs = append(evs, evBroker("agent-runaway", "broker.tool_call.executed", "web-01", bt))
		}
		fs := e.Score(evs)
		if s := signal(find(fs, "agent-runaway"), "peer_outlier"); s == nil {
			t.Fatalf("an agent doing 6x its peers' brokered volume was not an outlier: %+v", find(fs, "agent-runaway"))
		}
		for _, who := range []string{"agent-a", "agent-b", "agent-c", "agent-d", "agent-e"} {
			if s := signal(find(fs, who), "peer_outlier"); s != nil {
				t.Fatalf("ordinary agent %s flagged as an outlier: %+v", who, s)
			}
		}
	})

	t.Run("control: calls that never executed are not activity", func(t *testing.T) {
		var evs []store.AuditEvent
		for range 20 {
			evs = append(evs, evBroker("agent-7", "broker.tool_call.pending_approval", "web-01", bt))
		}
		if fs := e.Score(evs); len(fs) != 0 {
			t.Fatalf("calls awaiting approval did no privileged work and must not score: %+v", fs)
		}
	})
}

// TestOffHoursExemptsBrokeredCallsButNotHumans is the deliberate asymmetry, with
// both actors in one test so it cannot be changed by accident: at the very same
// 03:00 timestamp the human session scores off-hours and the agent's brokered
// call does not. An agent has no working day, so the hour tells us nothing about
// it; marking every agent every night would make the signal noise.
func TestOffHoursExemptsBrokeredCallsButNotHumans(t *testing.T) {
	night := time.Date(2026, 7, 20, 3, 0, 0, 0, time.UTC) // a Monday, 03:00
	fs := New(DefaultConfig()).Score([]store.AuditEvent{
		ev("human-alice", "session.start", night),
		evBroker("agent-7", "broker.tool_call.executed", "web-01", night),
	})

	if s := signal(find(fs, "human-alice"), "off_hours"); s == nil {
		t.Fatalf("a human session at 03:00 must still score off-hours: %+v", find(fs, "human-alice"))
	}
	if s := signal(find(fs, "agent-7"), "off_hours"); s != nil {
		t.Fatalf("an agent's brokered call at 03:00 scored off-hours: %+v", s)
	}
	if f := find(fs, "agent-7"); f.Score != 0 {
		t.Fatalf("a single ordinary brokered call should score nothing at all, got %d: %+v", f.Score, f.Signals)
	}
	// And the exemption is about the hour only — the same call still counted as
	// activity, which is what the volume signals read.
	if !offHoursExempt("broker.tool_call.executed") || offHoursExempt("session.start") {
		t.Fatal("offHoursExempt must cover the broker family and nothing else here")
	}
}

// TestBrokerRefusalsAreCommandBlockedAndDriveResponse proves the classification
// choice that matters operationally: a denied tool call, a refused approval and
// a quarantined agent's rejected authentication all land in command_blocked, and
// — unlike auth_failure — they are allowed to drive an automated response,
// because in all three cases the actor had already authenticated as themselves
// and so the risk cannot be pinned on them by a stranger.
func TestBrokerRefusalsAreCommandBlockedAndDriveResponse(t *testing.T) {
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC) // a Monday, in hours
	e := New(DefaultConfig())

	for _, action := range []string{
		"broker.tool_call.denied",
		"broker.approval.refused",
		"agent.quarantine_refused",
	} {
		t.Run(action, func(t *testing.T) {
			f := find(e.Score([]store.AuditEvent{evBroker("agent-7", action, "web-01", now)}), "agent-7")
			s := signal(f, "command_blocked")
			if s == nil {
				t.Fatalf("%s did not score as command_blocked: %+v", action, f.Signals)
			}
			if s.Count != 1 {
				t.Fatalf("command_blocked count = %d, want 1", s.Count)
			}
			if signal(f, "auth_failure") != nil {
				t.Fatalf("%s must not be classified as auth_failure — it is forgeable-name risk that it is not", action)
			}
			if f.ResponseScore != f.Score || f.ResponseScore <= 0 {
				t.Fatalf("%s must be able to drive a response: score=%d response=%d",
					action, f.Score, f.ResponseScore)
			}
			if LevelRank(f.ResponseLevel) < LevelRank(LevelMedium) {
				t.Fatalf("%s response level = %s, want at least medium", action, f.ResponseLevel)
			}
		})
	}

	// The contrast that gives the above its meaning: an unauthenticated party
	// failing logins under a name still drives no response for that name.
	var failures []store.AuditEvent
	for range 15 {
		failures = append(failures, ev("agent-7", "login.failed", now))
	}
	if f := find(e.Score(failures), "agent-7"); f.ResponseLevel != LevelLow {
		t.Fatalf("auth failures must stay response-excluded, got %s", f.ResponseLevel)
	}
}

// TestBrokeredCallNoveltyOnNewTarget proves the novelty signal now works for
// agents: the target name the broker records in the call's detail is the same
// `target:` token the baseline reads, so an agent reaching a host it has never
// used before is visible exactly as a human would be — and a host it uses every
// day still is not.
func TestBrokeredCallNoveltyOnNewTarget(t *testing.T) {
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	past := now.Add(-72 * time.Hour)
	base := BuildBaseline([]store.AuditEvent{
		evBroker("agent-7", "broker.tool_call.executed", "api-01", past),
		evBroker("agent-7", "broker.tool_call.executed", "api-02", past),
	})
	e := New(DefaultConfig())

	f := find(e.ScoreWithBaseline([]store.AuditEvent{
		evBroker("agent-7", "broker.tool_call.executed", "api-01", now),
	}, base), "agent-7")
	if s := signal(f, "new_target"); s != nil {
		t.Fatalf("a host the agent works on every day scored as novel: %+v", s)
	}

	f = find(e.ScoreWithBaseline([]store.AuditEvent{
		evBroker("agent-7", "broker.tool_call.executed", "dc-01", now),
		evBroker("agent-7", "broker.tool_call.executed", "dc-01", now),
		evBroker("agent-7", "broker.tool_call.executed", "vault-01", now),
	}, base), "agent-7")
	s := signal(f, "new_target")
	if s == nil {
		t.Fatalf("an agent reaching two never-used targets scored no novelty: %+v", f.Signals)
	}
	if s.Count != 2 {
		t.Fatalf("new_target count = %d, want 2 (distinct targets, not calls)", s.Count)
	}
}

// TestPeerOutlierComparesLikeWithLike pins the regression that adding brokered
// calls to the activity set would otherwise ship: agents are high-volume by
// nature, so pooling them with people drags the median up by an order of
// magnitude and the human outlier disappears under a threshold set by software.
//
// The fixture is the realistic shape of a deployment: a crowd of busy agents, a
// handful of ordinary humans, and one human doing ten times their peers' volume.
// That human is the person an insider-threat signal exists to surface, and they
// must still be surfaced with the agents present.
func TestPeerOutlierComparesLikeWithLike(t *testing.T) {
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC) // a Monday, in hours
	humans := []string{"alice", "bob", "carol", "dave", "erin"}
	var agents []string
	var evs []store.AuditEvent

	// Ten agents at 100 brokered calls each — a normal day for software.
	for i := range 10 {
		who := fmt.Sprintf("agent-%d", i)
		agents = append(agents, who)
		for range 100 {
			evs = append(evs, evBroker(who, "broker.tool_call.executed", "web-01", now))
		}
	}
	// Five ordinary humans at 5 sessions each: human median 5, threshold 5*3 = 15.
	for _, who := range humans {
		for range 5 {
			evs = append(evs, evT(who, "web-01", now))
		}
	}
	// One human at ten times their peers — and still far below every agent, so a
	// single pooled median hides them completely.
	for range 50 {
		evs = append(evs, evT("mallory", "web-01", now))
	}

	fs := New(DefaultConfig()).Score(evs)
	if s := signal(find(fs, "mallory"), "peer_outlier"); s == nil {
		t.Fatalf("a human at 10x their HUMAN peers was hidden by a crowd of busier agents: %+v",
			find(fs, "mallory"))
	}
	for _, who := range humans {
		if s := signal(find(fs, who), "peer_outlier"); s != nil {
			t.Fatalf("ordinary human %s flagged as an outlier: %+v", who, s)
		}
	}
	for _, who := range agents {
		if s := signal(find(fs, who), "peer_outlier"); s != nil {
			t.Fatalf("agent %s doing exactly what its peers do was flagged: %+v", who, s)
		}
	}
}

// TestPeerOutlierClassTooSmallFallsSilent proves each class keeps the
// PeerMinActors guard on its own: a deployment with two agents gets NO agent
// peer comparison rather than a nonsense one against people. Silence is the
// right failure direction — a missed comparison is recoverable, a confident
// comparison against an unrelated population is not.
func TestPeerOutlierClassTooSmallFallsSilent(t *testing.T) {
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	var evs []store.AuditEvent
	for _, who := range []string{"alice", "bob", "carol", "dave", "erin"} {
		for range 5 {
			evs = append(evs, evT(who, "web-01", now))
		}
	}
	evs = append(evs, evBroker("agent-quiet", "broker.tool_call.executed", "web-01", now))
	for range 500 {
		evs = append(evs, evBroker("agent-busy", "broker.tool_call.executed", "web-01", now))
	}

	fs := New(DefaultConfig()).Score(evs)
	if s := signal(find(fs, "agent-busy"), "peer_outlier"); s != nil {
		t.Fatalf("flagged an agent against a peer group of two agents (or against humans): %+v", s)
	}
}

// TestAgentAdmissionRefusalsScoreAsBlocked pins Phase 185's half of the
// detection-parity fix: an authenticated identity being refused at the door is a
// behavioural signal, and until this phase most of those refusals scored zero.
//
// The engine counted `agent.quarantine_refused` and nothing else from the agent
// admission path, so an identity hammering the door while unenrolled — or with a
// workload its posture system would not vouch for — looked exactly like an
// identity that had gone quiet.
func TestAgentAdmissionRefusalsScoreAsBlocked(t *testing.T) {
	for _, action := range []string{
		"agent.not_enrolled", "agent.posture_denied",
		"broker.token.refused", "forward.refused", "k8s.refused",
		"winrm.refused", "sftp.blocked",
	} {
		if !cmdBlockedActions[action] {
			t.Errorf("%s is a refusal of an authenticated party and should count as a blocked command", action)
		}
	}
	// And the one that is deliberately absent: nothing was blocked — the
	// approval went through — so counting it would inflate a signal that is
	// allowed to drive an automated response.
	if cmdBlockedActions["broker.approval.four_eyes_unverified"] {
		t.Error("four_eyes_unverified is not a blocked command: the call was approved, only unverifiably")
	}
}
