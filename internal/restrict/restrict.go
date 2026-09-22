// Package restrict evaluates per-subject restriction rules (Phase 275): what
// a user, or any role they hold, may not do inside a session, per
// sub-protocol — WALLIX's user-group Restrictions tab. It complements the
// deployment-wide command guard (internal/cmdguard): the guard is one policy
// for everyone; a restriction set belongs to a subject and is loaded ONCE at
// admission (Load) so a session pays no store read per command.
//
// Two kinds of rule share one table: a regular expression over a command
// (ssh_exec, winrm, sql, kubernetes, or "*" for every one), and an SFTP size
// rule — "$filesize:>10m" for an upload larger than that, "$downsize:>100m"
// for a download. Each rule carries an action: "kill" ends the session (or
// refuses the call where no session exists), "notify" records the match and
// lets it through. Like cmdguard, this is not a containment boundary: an
// interactive PTY is never parsed, so a restriction covers exec, WinRM, SQL,
// kubectl and SFTP — the paths where a discrete command or transfer is
// visible.
package restrict

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/morandeirachema/pamv1/internal/store"
)

// Actions.
const (
	ActionKill   = "kill"
	ActionNotify = "notify"
)

// Sub-protocol names a rule may name (plus "*").
var Subprotocols = []string{"ssh_exec", "winrm", "sql", "kubernetes", "sftp"}

// Match is a rule that matched.
type Match struct {
	RuleID  int64
	Pattern string
	Action  string
}

// SizeRule is a parsed "$filesize:>N" / "$downsize:>N" rule.
type SizeRule struct {
	RuleID int64
	Up     bool // $filesize (upload); false = $downsize (download)
	Max    int64
	Action string
}

// compiledRule is one regex rule ready to run.
type compiledRule struct {
	id     int64
	sub    string
	re     *regexp.Regexp
	src    string
	action string
}

// Set is one subject's compiled restriction set.
type Set struct {
	rules []compiledRule
	sizes []SizeRule
}

// Store is the slice of store.Store Load needs.
type Store interface {
	ListRestrictionRules(ctx context.Context) ([]store.RestrictionRule, error)
}

// Subject names whose rules apply: the user and every role they hold.
type Subject struct {
	Name  string
	Roles []string
}

// Validate refuses a rule that could not mean anything: an unknown
// sub-protocol or action, a pattern that does not compile, a size rule
// that is not "$filesize:>N" / "$downsize:>N" (with an optional k/m/g
// suffix) or that names a sub-protocol other than sftp.
func Validate(r store.RestrictionRule) error {
	switch r.Action {
	case ActionKill, ActionNotify:
	default:
		return fmt.Errorf(`action must be %q or %q`, ActionKill, ActionNotify)
	}
	if r.Subprotocol != "*" {
		known := false
		for _, s := range Subprotocols {
			if s == r.Subprotocol {
				known = true
			}
		}
		if !known {
			return fmt.Errorf("subprotocol must be one of %s or *", strings.Join(Subprotocols, ", "))
		}
	}
	if strings.HasPrefix(r.Pattern, "$") {
		if _, _, err := parseSize(r.Pattern); err != nil {
			return err
		}
		if r.Subprotocol != "sftp" {
			return fmt.Errorf("a size rule applies to sftp only")
		}
		return nil
	}
	if strings.TrimSpace(r.Pattern) == "" {
		return fmt.Errorf("pattern is required")
	}
	if _, err := regexp.Compile(r.Pattern); err != nil {
		return fmt.Errorf("pattern: %w", err)
	}
	return nil
}

// parseSize parses "$filesize:>10m" into (up=true, 10<<20).
func parseSize(s string) (up bool, max int64, err error) {
	var rest string
	switch {
	case strings.HasPrefix(s, "$filesize:>"):
		up, rest = true, strings.TrimPrefix(s, "$filesize:>")
	case strings.HasPrefix(s, "$downsize:>"):
		up, rest = false, strings.TrimPrefix(s, "$downsize:>")
	default:
		return false, 0, fmt.Errorf(`a size rule is "$filesize:>N" or "$downsize:>N" (N with an optional k/m/g suffix)`)
	}
	rest = strings.ToLower(strings.TrimSpace(rest))
	mult := int64(1)
	switch {
	case strings.HasSuffix(rest, "k"):
		mult, rest = 1<<10, strings.TrimSuffix(rest, "k")
	case strings.HasSuffix(rest, "m"):
		mult, rest = 1<<20, strings.TrimSuffix(rest, "m")
	case strings.HasSuffix(rest, "g"):
		mult, rest = 1<<30, strings.TrimSuffix(rest, "g")
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || n <= 0 {
		return false, 0, fmt.Errorf("size rule: %q is not a positive size", s)
	}
	return up, n * mult, nil
}

// applies reports whether a rule names the subject.
func applies(r store.RestrictionRule, sub Subject) bool {
	switch r.SubjectType {
	case "user":
		return strings.EqualFold(r.Subject, sub.Name)
	case "role":
		for _, role := range sub.Roles {
			if strings.EqualFold(r.Subject, role) {
				return true
			}
		}
	}
	return false
}

// Load compiles the subject's rules from the store. A rule that no longer
// compiles (edited by hand in the database) is skipped rather than failing
// the whole set. An empty set is a nil *Set, on which every method is a
// no-op.
func Load(ctx context.Context, st Store, sub Subject) (*Set, error) {
	all, err := st.ListRestrictionRules(ctx)
	if err != nil {
		return nil, err
	}
	return Compile(all, sub), nil
}

// Compile builds the subject's set from rules already in hand.
func Compile(all []store.RestrictionRule, sub Subject) *Set {
	var s Set
	for _, r := range all {
		if !applies(r, sub) {
			continue
		}
		if strings.HasPrefix(r.Pattern, "$") {
			up, max, err := parseSize(r.Pattern)
			if err != nil {
				continue
			}
			s.sizes = append(s.sizes, SizeRule{RuleID: r.ID, Up: up, Max: max, Action: r.Action})
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			continue
		}
		s.rules = append(s.rules, compiledRule{id: r.ID, sub: r.Subprotocol, re: re, src: r.Pattern, action: r.Action})
	}
	if len(s.rules) == 0 && len(s.sizes) == 0 {
		return nil
	}
	return &s
}

// Check reports the first rule matching cmd on subprotocol. A kill rule
// wins over a notify rule that also matches: the outcome is the stricter
// one, whatever the order the rules were written in.
func (s *Set) Check(subprotocol, cmd string) (Match, bool) {
	if s == nil {
		return Match{}, false
	}
	var found Match
	ok := false
	for _, r := range s.rules {
		if r.sub != "*" && r.sub != subprotocol {
			continue
		}
		if !r.re.MatchString(cmd) {
			continue
		}
		if !ok || (found.Action == ActionNotify && r.action == ActionKill) {
			found, ok = Match{RuleID: r.id, Pattern: r.src, Action: r.action}, true
		}
	}
	return found, ok
}

// SizeLimit reports the tightest size rule in a direction (up = upload):
// the smallest Max among the subject's rules for it, and whether one exists.
func (s *Set) SizeLimit(up bool) (SizeRule, bool) {
	if s == nil {
		return SizeRule{}, false
	}
	var best SizeRule
	ok := false
	for _, r := range s.sizes {
		if r.Up != up {
			continue
		}
		if !ok || r.Max < best.Max || (r.Max == best.Max && r.Action == ActionKill) {
			best, ok = r, true
		}
	}
	return best, ok
}

// Empty reports whether the set holds no rule at all.
func (s *Set) Empty() bool { return s == nil || (len(s.rules) == 0 && len(s.sizes) == 0) }
