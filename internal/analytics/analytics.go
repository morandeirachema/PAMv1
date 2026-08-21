// Package analytics is pamv1's privileged threat-analytics engine: a behavioral
// risk scorer over the audit trail (the CyberArk PTA / Wallix analytics gap).
// It is deliberately deterministic and explainable — every point of an actor's
// risk score traces back to a named signal (break-glass use, blocked commands,
// authentication-failure bursts, off-hours activity, decryption failures,
// session velocity) — rather than an opaque ML model, so a reviewer can defend
// each finding. The API surfaces the scores and a background worker alerts on
// and optionally responds to high-risk actors.
package analytics

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// Risk levels, from an actor's total score via the Config thresholds.
const (
	LevelLow      = "low"
	LevelMedium   = "medium"
	LevelHigh     = "high"
	LevelCritical = "critical"
)

// Weights assigns a per-occurrence point value to each behavioral signal. Each
// signal's total contribution is capped (see PerSignalCap) so one noisy category
// cannot alone peg an actor to critical.
type Weights struct {
	BreakGlass     int // any break-glass access/unseal — inherently elevated
	CommandBlocked int // a command the guard refused (attempted dangerous action)
	AuthFailure    int // failed auth / denied authz / denied session (probing)
	OffHours       int // sensitive action outside business hours / on a weekend
	DecryptFailure int // a credential decrypt failed (tampering / AAD mismatch)
	VelocityOver   int // per session past the velocity threshold (burst of access)
	// NewTarget scores access to a target this actor has never used before,
	// judged against a Baseline. Nothing about such an event looks wrong on its
	// own, which is exactly why it needs history to see (Phase 86).
	NewTarget int
	// PeerOutlier scores an actor whose activity is far above their peers' in
	// the same window. Volume only means something relative to a peer group.
	PeerOutlier int
}

// Config tunes the scorer: signal weights, per-signal caps, level thresholds,
// business hours and the session-velocity threshold.
type Config struct {
	Weights       Weights
	PerSignalCap  int // max points any single signal category may contribute
	MediumScore   int // total score at/above which an actor is "medium"
	HighScore     int // …"high"
	CriticalScore int // …"critical"
	BusinessStart int // first business hour, inclusive [0,23]
	BusinessEnd   int // first non-business hour, exclusive [1,24]
	VelocityLimit int // sessions within the window before velocity counts as risk
	// PeerFactor is how many times the peer MEDIAN an actor's activity must
	// exceed to count as an outlier. The median, not the mean: the mean is
	// dragged up by the very outlier being looked for.
	PeerFactor int
	// PeerMinActors is the smallest peer group worth comparing against, applied
	// to each actor class separately. Below it the signal is skipped rather than
	// guessed — two people are not a distribution, and neither are two agents.
	PeerMinActors int
	// Location is the timezone the business hours are interpreted in. Audit
	// timestamps are stored in UTC, so an operator whose business hours are local
	// must set this (e.g. "America/New_York"); nil defaults to UTC.
	Location *time.Location
}

// DefaultConfig returns sensible defaults: business hours 07:00–20:00 Mon–Fri,
// break-glass and blocked commands weigh heaviest, medium/high/critical at
// 25/50/80 points. A single break-glass access alone reaches "high" (it is the
// emergency path and should always surface); two reach "critical".
func DefaultConfig() Config {
	return Config{
		Weights: Weights{
			BreakGlass:     50,
			CommandBlocked: 25,
			AuthFailure:    8,
			OffHours:       5,
			DecryptFailure: 15,
			VelocityOver:   4,
			// Modest on purpose. A first visit to a new target is INTERESTING,
			// not damning — people are onboarded onto systems every week — so it
			// nudges an actor toward review rather than tripping a response on
			// its own. Ten new targets in one window is a different story, and
			// the per-signal cap still bounds it.
			NewTarget: 6,
			// Being well above your peers is one fact, not a verdict; it earns
			// medium alongside anything else, and nothing alone.
			PeerOutlier: 20,
		},
		PerSignalCap:  100,
		MediumScore:   25,
		HighScore:     50,
		CriticalScore: 80,
		PeerFactor:    3,
		PeerMinActors: 5,
		BusinessStart: 7,
		BusinessEnd:   20,
		VelocityLimit: 8,
	}
}

// Signal is one named contributor to an actor's risk score.
type Signal struct {
	Name   string `json:"name"`
	Count  int    `json:"count"`
	Points int    `json:"points"`
}

// Finding is the aggregate risk assessment for one actor over the scored window.
type Finding struct {
	Actor string `json:"actor"`
	Score int    `json:"score"`
	Level string `json:"level"`
	// ResponseScore is Score with the signals EXCLUDED that an unauthenticated
	// party can attribute to a name they do not control (auth failures). It is
	// the score an automated response must be gated on, and it is usually equal
	// to Score — they differ only for an actor whose risk is inflated by failed
	// logins carrying their name.
	//
	// The reason is a real attack. A failed login records the PRESENTED username
	// as the actor, and anyone can present any username unauthenticated, so
	// "many auth failures for X" means "someone is attacking X", not "X is
	// misbehaving". Auto-responding on Level would let an attacker who knows a
	// username force that user's sessions to be revoked or killed by failing
	// login as them. Alerts still use Level — a human should be told X is being
	// brute-forced — but the response uses ResponseLevel, so the attack drives no
	// automated action against the victim.
	ResponseScore int    `json:"response_score"`
	ResponseLevel string `json:"response_level"`

	Signals []Signal  `json:"signals"`
	Events  int       `json:"events"`
	FirstTS time.Time `json:"first_ts"`
	LastTS  time.Time `json:"last_ts"`
}

// responseExcludedSignals are the signals an unauthenticated party can pin on a
// victim's name, so they must not drive an automated response. auth_failure is
// the only one: every other signal requires the actor to have authenticated and
// acted, which an attacker cannot do under someone else's name without first
// compromising them (in which case the response is warranted).
var responseExcludedSignals = map[string]bool{"auth_failure": true}

// SignalSummary renders the finding's signals as a compact "name=points" list
// for an audit detail or alert body.
func (f Finding) SignalSummary() string {
	parts := make([]string, 0, len(f.Signals))
	for _, s := range f.Signals {
		parts = append(parts, fmt.Sprintf("%s=%d", s.Name, s.Points))
	}
	return strings.Join(parts, ",")
}

// Engine scores audit events into per-actor risk findings.
type Engine struct {
	cfg Config
}

// New builds an Engine with cfg, filling any zero threshold/hours field from the
// defaults so a partially-specified config is still usable.
func New(cfg Config) *Engine {
	d := DefaultConfig()
	if cfg.PerSignalCap <= 0 {
		cfg.PerSignalCap = d.PerSignalCap
	}
	if cfg.MediumScore <= 0 {
		cfg.MediumScore = d.MediumScore
	}
	if cfg.HighScore <= 0 {
		cfg.HighScore = d.HighScore
	}
	if cfg.CriticalScore <= 0 {
		cfg.CriticalScore = d.CriticalScore
	}
	if cfg.BusinessEnd <= 0 || cfg.BusinessEnd > 24 {
		cfg.BusinessStart, cfg.BusinessEnd = d.BusinessStart, d.BusinessEnd
	}
	if cfg.VelocityLimit <= 0 {
		cfg.VelocityLimit = d.VelocityLimit
	}
	// These two must be defaulted, not left zero. A zero PeerFactor makes the
	// outlier threshold `median * 0` = 0, and a zero PeerMinActors removes the
	// "is there even a peer group?" guard — so every actor in every window scores
	// as an outlier. A zero value that silently means "flag everything" is the
	// worst kind, because it looks like the feature working.
	if cfg.PeerFactor <= 0 {
		cfg.PeerFactor = d.PeerFactor
	}
	if cfg.PeerMinActors <= 0 {
		cfg.PeerMinActors = d.PeerMinActors
	}
	if cfg.Weights == (Weights{}) {
		cfg.Weights = d.Weights
	}
	if cfg.Location == nil {
		cfg.Location = time.UTC
	}
	return &Engine{cfg: cfg}
}

// signal action classification.
//
// Membership in these maps is the ONLY thing that makes an audit action visible
// to the scorer: an action in none of them contributes nothing, whatever it did.
// That is why the AI-agent broker's actions are listed here (Phase 161) — until
// they were, an agent could execute brokered privileged calls at any rate, at
// any hour, against targets it had never touched, and score exactly zero.
//
// The classifying switch in ScoreWithBaseline is FIRST-MATCH (`switch { case
// ... }` in Go runs the first case whose condition is true and then stops, like
// an if/elif chain in Python), so an action listed in two of these maps lands in
// whichever case comes first. Ordering there is part of the semantics.
var (
	breakGlassActions = map[string]bool{"breakglass.access": true, "breakglass.unseal": true}
	// cmdBlockedActions means "an already-authenticated actor's privileged
	// attempt was refused by policy". Besides the command guard it covers the
	// three ways the AI-agent broker says no: a tool call the policy denied, an
	// approval attempted by a human outside the rule's separation-of-duties
	// group, and a suspended/quarantined agent identity turned away when it tried
	// to authenticate.
	//
	// Those three belong here and deliberately NOT in authFailActions, even
	// though "refused" sounds like an authentication failure. auth_failure is the
	// one signal excluded from driving an automated response (see
	// responseExcludedSignals) because a failed login records the name that was
	// PRESENTED, so an unauthenticated stranger can pile risk onto a victim's
	// account and trigger a response against them. None of these three can be
	// forged that way: each requires the actor to have already proved who they
	// are — the agent presented a valid identity, the approver was logged in —
	// before the refusal was recorded. The actor really is the actor, so the
	// signal should be allowed to drive a response.
	cmdBlockedActions = map[string]bool{
		"command.blocked":          true,
		"broker.tool_call.denied":  true,
		"broker.approval.refused":  true,
		"agent.quarantine_refused": true,
		// The two admission refusals added after this map was written (Phases
		// 174 and 180). Both meet the criterion above exactly: the agent proved
		// who it was — an SVID verified against the trust domain — and was then
		// refused for not being enrolled, or for a workload its posture system
		// would not vouch for. An identity hammering the door in either state is
		// a behavioural signal, and it scored zero.
		"agent.not_enrolled":   true,
		"agent.posture_denied": true,
		// And five refusals that predate this map's last revision, found by the
		// OCSF coverage guard in Phase 185. Every one is an authenticated party
		// being told no — the criterion above — and every one scored zero:
		// a refused delegated-token mint, an `ssh -L` aimed at another host, a
		// refused Kubernetes operation, a WinRM command stopped by command
		// control, and a file transfer stopped by SFTP policy.
		//
		// **Operator-visible consequence**: a deployment where these refusals are
		// routine will see risk scores rise, because behaviour that was invisible
		// to the engine now counts. That is the intent — an operator repeatedly
		// refused a forward is exactly what the signal is for — but it is worth
		// knowing before `PAM_ANALYTICS_AUTO_KILL` acts on it.
		"broker.token.refused": true,
		"forward.refused":      true,
		"k8s.refused":          true,
		"winrm.refused":        true,
		"sftp.blocked":         true,
	}
	// Deliberately NOT in the map above: `broker.approval.four_eyes_unverified`
	// (Phase 176). Nothing was blocked — the approval proceeded — so counting it
	// as a blocked command would inflate a signal that drives an automated
	// response. It is exported to the SIEM as a finding instead, which is the
	// surface where "a control could not be verified" belongs.
	authFailActions = map[string]bool{
		"proxy.auth_failed": true, "login.failed": true, "authz.denied": true,
		"session.denied": true, "access.denied": true, "db.session.denied": true,
		// A rejected bearer credential on the REST/broker/app-secrets surfaces
		// (Phase 37); attributed to "unknown", so it scores that pseudo-actor.
		"api.auth_failed": true,
	}
	decryptActions = map[string]bool{"credential.decrypt_failed": true}
	// sensitive "activity" actions that count toward off-hours and velocity.
	activityActions = map[string]bool{
		"session.start": true, "db.session.start": true, "session.cert_issued": true,
		"ssh.exec": true, "winrm.run": true, "rdp.connect": true,
		// A brokered tool call that actually RAN is privileged work against a
		// target, the same as opening a session, so it feeds velocity, the peer
		// comparison and new-target novelty. Only the executed outcome counts:
		// a call that was denied, is still awaiting approval or failed did no
		// work, and counting it would let a rejected agent inflate its own
		// volume. Executed calls are exempt from off-hours — see offHoursExempt.
		"broker.tool_call.executed": true,
	}
)

// perActor accumulates raw signal counts for one actor while scanning events.
type perActor struct {
	counts  map[string]int
	events  int
	firstTS time.Time
	lastTS  time.Time
	// newTargets is a SET, so repeated use of one new host counts once.
	newTargets map[string]struct{}
	// brokerActivity is how many of this actor's activity events were brokered
	// tool calls, tracked alongside the total so the actor's class can be
	// derived from behaviour. See perActor.class.
	brokerActivity int
}

// actorClass is the kind of actor a finding is about — a person or an AI agent.
// It is DERIVED from behaviour rather than read from a field, because the engine
// scores audit events and an audit event carries no actor type.
type actorClass string

const (
	classHuman actorClass = "human"
	classAgent actorClass = "agent"
)

// class reports which peer pool this actor belongs to, and whether they belong
// to one at all.
//
// An actor whose activity is ENTIRELY brokered tool calls is an agent. Entirely,
// not merely mostly, on purpose: the cost of the two mistakes is not symmetric.
// Misreading a person as an agent moves them into a pool of high-volume software
// where nothing they could plausibly do looks unusual, which is exactly the
// blindness this partition exists to prevent — so a human whose trail happens to
// contain a single brokered row stays a human. The strict rule costs nothing in
// practice, because an agent identity cannot open an interactive session, a
// database session or an RDP connection at all (the broker is its only path to a
// target), so a real agent's activity is 100% brokered.
//
// An actor with NO activity events — someone who only failed to log in, say —
// has no class and takes no part in peer comparison in either direction. There
// is nothing to compare: a volume signal needs volume, and zero is not a
// quantity of work, it is the absence of any.
func (pa *perActor) class() (actorClass, bool) {
	total := pa.counts["activity"]
	if total <= 0 {
		return "", false
	}
	if pa.brokerActivity == total {
		return classAgent, true
	}
	return classHuman, true
}

// Score computes a risk finding per actor from events (the caller chooses the
// window). It is a pure function of its inputs — no clock, no I/O — so a given
// event set always yields the same findings. Findings are returned sorted by
// score descending; actors with a zero score are omitted.
func (e *Engine) Score(events []store.AuditEvent) []Finding {
	return e.ScoreWithBaseline(events, nil)
}

// ScoreWithBaseline scores events against what the actors did BEFORE them.
//
// A nil baseline scores exactly as Score does: novelty contributes nothing
// rather than marking every target new. That is the difference between a useful
// first run and an alert storm on the day it is switched on.
func (e *Engine) ScoreWithBaseline(events []store.AuditEvent, baseline *Baseline) []Finding {
	byActor := map[string]*perActor{}
	for _, ev := range events {
		if ev.Actor == "" {
			continue
		}
		pa := byActor[ev.Actor]
		if pa == nil {
			pa = &perActor{counts: map[string]int{}, firstTS: ev.TS, lastTS: ev.TS}
			byActor[ev.Actor] = pa
		}
		pa.events++
		if ev.TS.Before(pa.firstTS) {
			pa.firstTS = ev.TS
		}
		if ev.TS.After(pa.lastTS) {
			pa.lastTS = ev.TS
		}
		switch {
		case breakGlassActions[ev.Action]:
			pa.counts["break_glass"]++
		case cmdBlockedActions[ev.Action]:
			pa.counts["command_blocked"]++
		case authFailActions[ev.Action]:
			pa.counts["auth_failure"]++
		case decryptActions[ev.Action]:
			pa.counts["decrypt_failure"]++
		}
		if activityActions[ev.Action] {
			pa.counts["activity"]++
			if brokerAction(ev.Action) {
				// Tallied separately from the total so the peer pass can tell an
				// agent from a person (perActor.class).
				pa.brokerActivity++
			}
			if !offHoursExempt(ev.Action) && e.offHours(ev.TS) {
				pa.counts["off_hours"]++
			}
			// Novelty needs BOTH a baseline and history for this actor. Without
			// the second check every new joiner's first week reads as a stream of
			// anomalies, which is how a signal gets ignored.
			if t := targetOf(ev); t != "" && baseline.hasHistoryFor(ev.Actor) && !baseline.knows(ev.Actor, t) {
				if pa.newTargets == nil {
					pa.newTargets = map[string]struct{}{}
				}
				// Counted once per DISTINCT target: ten sessions on one new host
				// is one new thing, not ten.
				pa.newTargets[t] = struct{}{}
			}
		}
	}

	// Peer comparison is a second pass, because it needs every actor's totals.
	//
	// Actors are compared only against others of their own KIND — agents against
	// agents, people against people — because a peer group is only a peer group
	// if its members are comparable, and an AI agent is not comparable to a
	// person by volume. Agents make brokered calls continuously; people open a
	// handful of sessions a day. Pooling them puts the median where the software
	// is, and a human doing ten times their normal volume then sails under a
	// threshold set by machines: the volume signal would go quiet for exactly the
	// insider it exists to catch. The mirror image is just as wrong — one busy
	// person among many idle agents is not evidence about the person.
	//
	// Each pool applies the PeerMinActors guard independently, so a deployment
	// with two agents gets NO agent comparison rather than a nonsense one against
	// humans. A class too small to compare falls silent, which is the right
	// direction to fail: a comparison not made can be made later with more data,
	// while a confident comparison against an unrelated population produces a
	// finding an operator cannot tell from a real one.
	pools := map[actorClass]map[string]int{}
	for actor, pa := range byActor {
		class, ok := pa.class()
		if !ok {
			continue
		}
		if pools[class] == nil {
			pools[class] = map[string]int{}
		}
		pools[class][actor] = pa.counts["activity"]
	}
	for _, pool := range pools {
		threshold, ok := peerVolumes(pool, e.cfg.PeerFactor, e.cfg.PeerMinActors)
		if !ok {
			continue
		}
		for actor, count := range pool {
			if count > threshold {
				byActor[actor].counts["peer_outlier"] = 1
			}
		}
	}
	for _, pa := range byActor {
		pa.counts["new_target"] = len(pa.newTargets)
	}

	findings := make([]Finding, 0, len(byActor))
	for actor, pa := range byActor {
		f := e.finding(actor, pa)
		if f.Score > 0 {
			findings = append(findings, f)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Score != findings[j].Score {
			return findings[i].Score > findings[j].Score
		}
		return findings[i].Actor < findings[j].Actor
	})
	return findings
}

// finding turns one actor's raw counts into a scored, leveled Finding.
func (e *Engine) finding(actor string, pa *perActor) Finding {
	w := e.cfg.Weights
	f := Finding{Actor: actor, Events: pa.events, FirstTS: pa.firstTS, LastTS: pa.lastTS}
	add := func(name string, count, weight int) {
		if count <= 0 || weight <= 0 {
			return
		}
		pts := count * weight
		if pts > e.cfg.PerSignalCap {
			pts = e.cfg.PerSignalCap
		}
		f.Signals = append(f.Signals, Signal{Name: name, Count: count, Points: pts})
		f.Score += pts
	}
	add("break_glass", pa.counts["break_glass"], w.BreakGlass)
	add("command_blocked", pa.counts["command_blocked"], w.CommandBlocked)
	add("auth_failure", pa.counts["auth_failure"], w.AuthFailure)
	add("off_hours", pa.counts["off_hours"], w.OffHours)
	add("decrypt_failure", pa.counts["decrypt_failure"], w.DecryptFailure)
	// Velocity: only the sessions beyond the limit contribute.
	if over := pa.counts["activity"] - e.cfg.VelocityLimit; over > 0 {
		add("high_velocity", over, w.VelocityOver)
	}
	// History-relative signals (Phase 86). Both are absent, not zero, when there
	// is nothing to compare against — an actor with no baseline and a window with
	// no peer group simply do not carry them.
	add("new_target", pa.counts["new_target"], w.NewTarget)
	add("peer_outlier", pa.counts["peer_outlier"], w.PeerOutlier)
	f.Level = e.level(f.Score)
	// The response-eligibility score drops the signals a stranger can attribute
	// to this actor's name (see responseExcludedSignals). Everything left is
	// something the actor themselves did while authenticated.
	resp := 0
	for _, sig := range f.Signals {
		if !responseExcludedSignals[sig.Name] {
			resp += sig.Points
		}
	}
	f.ResponseScore = resp
	f.ResponseLevel = e.level(resp)
	// Present the strongest signals first.
	sort.SliceStable(f.Signals, func(i, j int) bool { return f.Signals[i].Points > f.Signals[j].Points })
	return f
}

// level maps a total score to a risk level via the configured thresholds.
func (e *Engine) level(score int) string {
	switch {
	case score >= e.cfg.CriticalScore:
		return LevelCritical
	case score >= e.cfg.HighScore:
		return LevelHigh
	case score >= e.cfg.MediumScore:
		return LevelMedium
	default:
		return LevelLow
	}
}

// offHours reports whether ts falls outside business hours or on a weekend,
// evaluated in the configured business-hours timezone (audit timestamps are
// UTC, so this converts before reading the weekday/hour).
func (e *Engine) offHours(ts time.Time) bool {
	ts = ts.In(e.cfg.Location)
	if wd := ts.Weekday(); wd == time.Saturday || wd == time.Sunday {
		return true
	}
	h := ts.Hour()
	return h < e.cfg.BusinessStart || h >= e.cfg.BusinessEnd
}

// offHoursExempt reports whether an action must be left OUT of the off_hours
// signal even though it counts as activity.
//
// (For a reader coming from Python: this is a plain package-level function
// rather than a method on Engine, because the answer depends only on WHAT was
// done — never on the clock, the config or the actor — so it needs no state.)
//
// The whole `broker.` family is exempt, because the off-hours signal encodes an
// assumption that is true of people and false of software: that working at 03:00
// is unusual and therefore worth a look. An AI agent has no working day. It runs
// whenever its queue has work, which is as likely to be 03:00 on a Sunday as
// 14:00 on a Tuesday. Scoring that would mark EVERY agent, permanently, and —
// because off-hours points accumulate per event up to the per-signal cap — at
// close to the maximum the signal can give. A detector that fires on every
// member of a class every day is one operators learn to scroll past, which is
// the same failure the novelty signal avoids by staying silent for a new joiner
// with no history.
//
// So the trade is explicit: brokered calls count as activity — velocity, peer
// comparison and new-target novelty all say something real about an agent,
// because "far more calls than the other agents" and "a host it has never
// touched" are genuine anomalies for software — but the hour of the day says
// nothing about one, so it scores nothing.
func offHoursExempt(action string) bool {
	return brokerAction(action)
}

// brokerAction reports whether an audit action was produced by the AI-agent
// access broker, which is the one thing in the trail that tells an agent's
// behaviour apart from a person's.
//
// It is a prefix test on the action name rather than a list of names on purpose:
// every action the broker emits is in scope for both of its callers — the
// off-hours exemption and the actor-class derivation — so a new broker action
// added later is classified correctly without anyone remembering to come here.
func brokerAction(action string) bool {
	return strings.HasPrefix(action, "broker.")
}

// LevelRank returns an ordinal for a level so callers can filter "high and
// above". An unknown level ranks 0 (low).
func LevelRank(level string) int {
	switch level {
	case LevelCritical:
		return 3
	case LevelHigh:
		return 2
	case LevelMedium:
		return 1
	default:
		return 0
	}
}
