package store

// approvaltiers.go is the vocabulary of an ORDERED approval chain (Phase 256
// — CyberArk's multi-level confirmation, with a direct-manager level). Until
// now an access request needed N distinct approvers, any N; a tier spec says
// WHO must approve, and in what order:
//
//	manager; approver:2; admin
//
// Tiers are separated by ';' and satisfied in order — an approval counts
// only toward the FIRST unsatisfied tier the approver qualifies for. A tier
// is `subject[:count]`, count 1 unless given:
//
//	manager        the requester's direct manager (users.manager)
//	user=<name>    one named identity
//	<role>         anyone holding that built-in role or custom profile
//
// It is stored as text on a target or a safe, parsed on write, and evaluated
// from ApprovedBy's existing order at every decision — so no new column on
// the request, and a policy raised while a request waits binds it at the
// next approval, exactly as Phase 58's dual-control floor does.

import (
	"fmt"
	"strconv"
	"strings"
)

// The three kinds of tier subject.
const (
	TierManager = "manager"
	TierUser    = "user"
	TierRole    = "role"
)

// maxTierCount bounds one tier; maxTiers bounds the chain. Both are
// generous — real chains have two or three levels — and exist so a spec can
// never demand more approvals than an estate could produce.
const (
	maxTierCount = 10
	maxTiers     = 8
)

// ApprovalTier is one level of the chain.
type ApprovalTier struct {
	Kind  string `json:"kind"`           // TierManager | TierUser | TierRole
	Name  string `json:"name,omitempty"` // the user or role; empty for manager
	Count int    `json:"count"`          // distinct approvers this tier needs
}

// String renders the tier in the spec's own grammar.
func (t ApprovalTier) String() string {
	var s string
	switch t.Kind {
	case TierManager:
		s = TierManager
	case TierUser:
		s = "user=" + t.Name
	default:
		s = t.Name
	}
	if t.Count > 1 {
		s += ":" + strconv.Itoa(t.Count)
	}
	return s
}

// validTierName is what a role, profile or username may look like here: the
// same character set every other name in the system is held to.
func validTierName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == '@':
		default:
			return false
		}
	}
	return true
}

// ParseApprovalTiers reads a spec. An empty spec is no chain (nil, nil) —
// the untiered N-of-M count every request had before Phase 256.
func ParseApprovalTiers(spec string) ([]ApprovalTier, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var out []ApprovalTier
	for _, raw := range strings.Split(spec, ";") {
		term := strings.TrimSpace(raw)
		if term == "" {
			return nil, fmt.Errorf("approval tiers %q: empty tier", spec)
		}
		count := 1
		if i := strings.LastIndex(term, ":"); i >= 0 {
			n, err := strconv.Atoi(strings.TrimSpace(term[i+1:]))
			if err != nil || n < 1 || n > maxTierCount {
				return nil, fmt.Errorf("approval tier %q: count must be 1-%d", term, maxTierCount)
			}
			count, term = n, strings.TrimSpace(term[:i])
		}
		t := ApprovalTier{Count: count}
		switch {
		case term == TierManager:
			t.Kind = TierManager
			if count != 1 {
				return nil, fmt.Errorf("approval tier %q: an identity has one direct manager", raw)
			}
		case strings.HasPrefix(term, "user="):
			t.Kind, t.Name = TierUser, strings.TrimSpace(strings.TrimPrefix(term, "user="))
			if !validTierName(t.Name) {
				return nil, fmt.Errorf("approval tier %q: bad username", raw)
			}
			if count != 1 {
				return nil, fmt.Errorf("approval tier %q: a named identity approves once", raw)
			}
		default:
			t.Kind, t.Name = TierRole, term
			if !validTierName(t.Name) {
				return nil, fmt.Errorf("approval tier %q: want manager, user=<name> or a role/profile name, optionally :count", raw)
			}
		}
		out = append(out, t)
		if len(out) > maxTiers {
			return nil, fmt.Errorf("approval tiers: at most %d tiers", maxTiers)
		}
	}
	return out, nil
}

// NormalizeApprovalTiers parses and re-renders a spec in canonical form.
func NormalizeApprovalTiers(spec string) (string, error) {
	tiers, err := ParseApprovalTiers(spec)
	if err != nil {
		return "", err
	}
	return JoinApprovalTiers(tiers), nil
}

// JoinApprovalTiers is the stored form of a chain.
func JoinApprovalTiers(tiers []ApprovalTier) string {
	parts := make([]string, 0, len(tiers))
	for _, t := range tiers {
		parts = append(parts, t.String())
	}
	return strings.Join(parts, "; ")
}

// HasManagerTier reports whether any tier needs the requester's manager —
// what a request must be refused for, at creation, when the requester has
// none.
func HasManagerTier(tiers []ApprovalTier) bool {
	for _, t := range tiers {
		if t.Kind == TierManager {
			return true
		}
	}
	return false
}

// TierState is one tier's progress, reported to approvers and the console.
type TierState struct {
	ApprovalTier
	ApprovedBy []string `json:"approved_by,omitempty"`
	Satisfied  bool     `json:"satisfied"`
	Current    bool     `json:"current,omitempty"` // the tier the next approval must satisfy
}

// TierProgress replays approvers (ApprovedBy, in the order they approved)
// against the chain: each approver is credited to the FIRST unsatisfied tier
// they qualify for, so a level-2 approver who approved before level 1 was
// complete is not counted early — but is not lost either, and is credited
// once level 1 completes. qualifies answers whether an approver may satisfy
// a tier. It returns the per-tier state, the index of the current tier (len
// when the chain is complete) and whether the chain is complete.
func TierProgress(tiers []ApprovalTier, approvers []string, qualifies func(approver string, tier ApprovalTier) bool) (states []TierState, current int, complete bool) {
	states = make([]TierState, len(tiers))
	for i, t := range tiers {
		states[i].ApprovalTier = t
	}
	if len(tiers) == 0 {
		return states, 0, true
	}
	// Replay until nothing more can be credited: an approver skipped because a
	// later tier was not yet current may become creditable after an earlier
	// tier completes, so the pass repeats until it makes no progress.
	credited := make([]bool, len(approvers))
	for progressed := true; progressed; {
		progressed = false
		current = firstUnsatisfied(states)
		if current == len(states) {
			break
		}
		for i, a := range approvers {
			if credited[i] {
				continue
			}
			cur := firstUnsatisfied(states)
			if cur == len(states) {
				break
			}
			if !qualifies(a, states[cur].ApprovalTier) {
				continue
			}
			states[cur].ApprovedBy = append(states[cur].ApprovedBy, a)
			credited[i] = true
			progressed = true
			if len(states[cur].ApprovedBy) >= states[cur].Count {
				states[cur].Satisfied = true
			}
		}
	}
	current = firstUnsatisfied(states)
	if current < len(states) {
		states[current].Current = true
	}
	return states, current, current == len(states)
}

func firstUnsatisfied(states []TierState) int {
	for i := range states {
		if !states[i].Satisfied {
			return i
		}
	}
	return len(states)
}
