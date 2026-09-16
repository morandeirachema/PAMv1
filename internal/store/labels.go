package store

// labels.go is the target-label vocabulary and the selector that reads it
// (Phase 250), the way safepermissions.go is the vocabulary of what a safe
// membership confers. Both sides are pure: a label set is text on the target
// row, a selector is text on a label rule, and one function decides whether
// they match — so a selector cannot mean one thing at the connect gate and
// another in an entitlement review.
//
// A label is `key=value`; a target carries a set, stored canonically as
// `env=prod,tier=db` (sorted by key, deduplicated, one value per key). A
// selector is a conjunction of terms — every term must match:
//
//	env=prod            the target has env, and its value is prod
//	env=prod,tier=db    both, ANDed
//	env=*               the target has env, whatever its value
//
// There is deliberately no OR, no negation and no empty selector. A rule that
// matches everything by accident is the failure mode that matters here: these
// selectors carry DENY rules, and "this text turned out to match the whole
// estate" is how an operator locks themselves out of it.

import (
	"fmt"
	"sort"
	"strings"
)

// LabelWildcard is the value that matches any value for a key present on the
// target. It is only meaningful in a selector, never in a label set.
const LabelWildcard = "*"

// maxLabelsPerTarget bounds a target's label set. Labels are an authorization
// input read on every connect, and an unbounded set is a row that makes every
// decision about that target slower with no operator ever having asked for it.
const maxLabelsPerTarget = 32

// maxLabelPartLen bounds one key or one value.
const maxLabelPartLen = 63

// validLabelPart reports whether s is a usable key or value: non-empty, within
// length, and free of the two characters the stored form uses as separators.
// Anything else would round-trip wrong, which for an authorization input means
// a rule that reads differently than it was written.
func validLabelPart(s string) bool {
	if s == "" || len(s) > maxLabelPartLen {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == '/':
		default:
			return false
		}
	}
	return true
}

// NormalizeLabels validates a caller-supplied label set and returns its
// canonical stored form: sorted by key, one value per key, `k=v` joined by
// commas. An empty input is an empty set, which is what every target has
// before it is labelled.
func NormalizeLabels(in map[string]string) (string, error) {
	if len(in) == 0 {
		return "", nil
	}
	if len(in) > maxLabelsPerTarget {
		return "", fmt.Errorf("a target may carry at most %d labels", maxLabelsPerTarget)
	}
	keys := make([]string, 0, len(in))
	for k, v := range in {
		if !validLabelPart(k) {
			return "", fmt.Errorf("label key %q: want 1-%d characters of [A-Za-z0-9._/-]", k, maxLabelPartLen)
		}
		if v == LabelWildcard {
			return "", fmt.Errorf("label %q: %q is a selector wildcard, not a value", k, LabelWildcard)
		}
		if !validLabelPart(v) {
			return "", fmt.Errorf("label value %q for key %q: want 1-%d characters of [A-Za-z0-9._/-]", v, k, maxLabelPartLen)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+in[k])
	}
	return strings.Join(parts, ","), nil
}

// ParseLabels reads the stored form back. Unreadable terms are DROPPED rather
// than guessed at: a label this build cannot read confers nothing and matches
// nothing, which is the same fail-closed reading ParseSafePermissions makes of
// an unknown permission. Never nil.
func ParseLabels(s string) map[string]string {
	out := map[string]string{}
	for _, term := range strings.Split(s, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		k, v, ok := strings.Cut(term, "=")
		if !ok || !validLabelPart(k) || !validLabelPart(v) {
			continue
		}
		out[k] = v
	}
	return out
}

// LabelSelector is a parsed conjunction of terms. The zero value matches
// nothing, deliberately: an unparsed or empty selector must never be the thing
// that opens — or, worse, denies — the whole estate.
type LabelSelector struct {
	terms map[string]string // key -> value, or LabelWildcard for "any value"
	src   string
}

// ParseLabelSelector reads a selector. An empty selector is an error: a rule
// has to say what it is about, and "everything" must be spelled out as a
// wildcard on a key the operator chose.
func ParseLabelSelector(s string) (LabelSelector, error) {
	sel := LabelSelector{terms: map[string]string{}, src: strings.TrimSpace(s)}
	if sel.src == "" {
		return LabelSelector{}, fmt.Errorf("a label selector cannot be empty (use key=%s to match every target carrying a key)", LabelWildcard)
	}
	for _, term := range strings.Split(sel.src, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			return LabelSelector{}, fmt.Errorf("label selector %q: empty term", s)
		}
		k, v, ok := strings.Cut(term, "=")
		if !ok {
			return LabelSelector{}, fmt.Errorf("label selector term %q: want key=value or key=%s", term, LabelWildcard)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !validLabelPart(k) {
			return LabelSelector{}, fmt.Errorf("label selector key %q: want 1-%d characters of [A-Za-z0-9._/-]", k, maxLabelPartLen)
		}
		if v != LabelWildcard && !validLabelPart(v) {
			return LabelSelector{}, fmt.Errorf("label selector value %q: want 1-%d characters of [A-Za-z0-9._/-], or %s", v, maxLabelPartLen, LabelWildcard)
		}
		if prev, dup := sel.terms[k]; dup && prev != v {
			return LabelSelector{}, fmt.Errorf("label selector names key %q twice with different values; terms are ANDed, so this matches nothing", k)
		}
		sel.terms[k] = v
	}
	return sel, nil
}

// IsZero reports whether the selector is the zero value, which matches nothing.
func (s LabelSelector) IsZero() bool { return len(s.terms) == 0 }

// String returns the source text the selector was parsed from.
func (s LabelSelector) String() string { return s.src }

// Matches reports whether a target's label set satisfies every term.
func (s LabelSelector) Matches(labels map[string]string) bool {
	if s.IsZero() {
		return false
	}
	for k, want := range s.terms {
		got, present := labels[k]
		if !present {
			return false
		}
		if want != LabelWildcard && got != want {
			return false
		}
	}
	return true
}

// LabelSelectorMatches parses sel and reports whether it matches the stored
// label text. An unparsable selector matches NOTHING — which for an allow rule
// means it admits nobody, and for a deny rule means it denies nobody. That
// asymmetry is deliberate and is why the API refuses to store an unparsable
// selector: a deny rule that silently stopped denying would be the worse
// failure, so it is prevented on the way in rather than guessed at here.
func LabelSelectorMatches(sel, labels string) bool {
	s, err := ParseLabelSelector(sel)
	if err != nil {
		return false
	}
	return s.Matches(ParseLabels(labels))
}
