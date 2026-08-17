package analytics

import (
	"sort"
	"strings"

	"github.com/morandeirachema/pamv1/internal/store"
)

// The six original signals all answer "is this event itself suspicious?" — a
// break-glass use, a blocked command, a failed decrypt. That catches the loud
// things and misses the quiet one an insider actually does: ordinary,
// well-formed access to somewhere they have no business being.
//
// Two signals here need history rather than a single event, which is why the
// roadmap deferred them as "needs a longer history model":
//
//   - **novelty** — this actor has never touched this target before. The first
//     time someone opens a session on the domain controller is the interesting
//     one, and nothing about that event in isolation looks wrong.
//   - **peer outlier** — this actor is doing far more than the people they are
//     comparable to. Volume is only meaningful relative to a peer group; "twenty
//     sessions" is alarming for a developer and a normal Tuesday for an SRE.
//
// Both are computed from the same audit trail, so they need no new storage —
// only a wider read.

// Baseline is what an actor's normal looked like BEFORE the scored window.
//
// It is deliberately just membership: which targets each actor has already
// touched. Building anything richer — a per-actor rate model, say — would make
// findings unexplainable, and this engine's whole contract is that an operator
// can see exactly why a score is what it is.
type Baseline struct {
	// seen maps actor → the set of targets that actor has already used.
	seen map[string]map[string]struct{}
	// events is how many events went into the baseline, so a caller can tell an
	// empty history from a quiet one.
	events int
}

// BuildBaseline summarises historical events into a Baseline.
//
// A nil Baseline is valid and means "no history": novelty then contributes
// nothing, rather than marking every target new. That distinction matters on the
// first run after deployment, when scoring every actor as maximally novel would
// produce an alert storm that teaches people to ignore the alerts.
func BuildBaseline(events []store.AuditEvent) *Baseline {
	b := &Baseline{seen: map[string]map[string]struct{}{}, events: len(events)}
	for _, ev := range events {
		if ev.Actor == "" {
			continue
		}
		t := targetOf(ev)
		if t == "" {
			continue
		}
		if b.seen[ev.Actor] == nil {
			b.seen[ev.Actor] = map[string]struct{}{}
		}
		b.seen[ev.Actor][t] = struct{}{}
	}
	return b
}

// Events reports how many events the baseline was built from.
func (b *Baseline) Events() int {
	if b == nil {
		return 0
	}
	return b.events
}

// knows reports whether actor has used target before.
func (b *Baseline) knows(actor, target string) bool {
	if b == nil {
		return false
	}
	targets, ok := b.seen[actor]
	if !ok {
		return false
	}
	_, seen := targets[target]
	return seen
}

// hasHistoryFor reports whether the baseline knows this actor at all.
//
// An actor with no history is NEW, not anomalous, and scoring their first day as
// a string of novel targets would swamp the signal that matters. A new joiner
// looks identical to an account takeover on day one; the difference is only
// visible once there is something to deviate from.
func (b *Baseline) hasHistoryFor(actor string) bool {
	if b == nil {
		return false
	}
	_, ok := b.seen[actor]
	return ok
}

// targetOf extracts the target name from an audit detail.
//
// Details are space-separated `key:value` text, and since Phase 77 a name cannot
// contain a colon or whitespace, so the token after `target:` is the whole name.
// A quoted value (auditField) is unwrapped. An event with no target — a login, a
// config change — yields "" and takes no part in novelty, which is correct: those
// are not access to somewhere.
func targetOf(ev store.AuditEvent) string {
	const key = "target:"
	i := strings.Index(ev.Detail, key)
	if i < 0 {
		return ""
	}
	rest := ev.Detail[i+len(key):]
	if strings.HasPrefix(rest, `"`) {
		if j := strings.Index(rest[1:], `"`); j >= 0 {
			return rest[1 : 1+j]
		}
		return ""
	}
	if j := strings.IndexAny(rest, " \t"); j >= 0 {
		rest = rest[:j]
	}
	// A numeric target id (`target:12`) is an identifier, not a name; both are
	// usable as a membership key so long as the same event kinds are compared,
	// which they are — the baseline and the window are read from one trail.
	return rest
}

// peerVolumes computes the outlier threshold for ONE peer pool in a scoring
// window. Since Phase 161 the caller runs it once per actor class (agents and
// people are pooled separately, see perActor.class), so `activity` holds only
// comparable actors and every guard below applies to that class alone.
//
// The comparison is against the MEDIAN of the peer group rather than the mean,
// because the mean is dragged up by exactly the outlier being looked for — one
// runaway actor raises the bar that would have caught them. With fewer than
// minPeers actors there is no meaningful peer group, and the signal is skipped
// rather than guessed: two people are not a distribution.
func peerVolumes(activity map[string]int, factor, minPeers int) (threshold int, ok bool) {
	// Refuse a nonsense configuration outright rather than computing a threshold
	// of zero, which would flag every actor. Engine.New defaults these, so this
	// is the second line of defence for a caller that builds a Config directly.
	if factor <= 0 || minPeers <= 0 {
		return 0, false
	}
	if len(activity) < minPeers {
		return 0, false
	}
	vals := make([]int, 0, len(activity))
	for _, v := range activity {
		vals = append(vals, v)
	}
	sort.Ints(vals)
	med := vals[len(vals)/2]
	if len(vals)%2 == 0 {
		med = (vals[len(vals)/2-1] + vals[len(vals)/2]) / 2
	}
	if med <= 0 {
		// A median of zero makes any activity infinitely above peers, which is
		// not an anomaly, it is a quiet window. Require a floor of one so the
		// threshold means something.
		med = 1
	}
	return med * factor, true
}
