// Package cmdguard implements command control: a policy-driven denylist that
// blocks a dangerous command before it reaches a target.
//
// It applies on every path where pamv1 can see a **discrete command** — the SSH
// `exec` request (non-interactive `ssh target "cmd"`), each WinRM command-loop
// line and each REST WinRM run, each PostgreSQL statement, and the agent
// broker's `ssh_exec`/`winrm_exec` tools. One policy, loaded once from
// PAM_COMMAND_DENY_FILE, is shared by the session proxies and the API server so
// a pattern cannot be enforced for a human on the proxy yet ignored for an AI
// agent calling a tool.
//
// What it does NOT cover is inherent, not an oversight: an interactive SSH shell
// streams a raw PTY that is never parsed, so the guard must not be read as a
// containment boundary. Use read-only observer sessions, or restrict shell
// access, where you need that guarantee.
package cmdguard

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

// Guard blocks commands matching any of its deny patterns. A nil Guard blocks
// nothing, so callers can hold one unconditionally.
type Guard struct {
	patterns []*regexp.Regexp
}

// New compiles the given regular expressions into a Guard. Blank lines and lines
// beginning with '#' are ignored, so a deny file can carry comments. A malformed
// pattern is a fail-loud error. A set with no usable pattern yields a nil Guard
// (the disabled case), not an empty one.
func New(patterns []string) (*Guard, error) {
	var ps []*regexp.Regexp
	for _, raw := range patterns {
		p := strings.TrimSpace(raw)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("command-deny pattern %q: %w", p, err)
		}
		ps = append(ps, re)
	}
	if len(ps) == 0 {
		return nil, nil
	}
	return &Guard{patterns: ps}, nil
}

// ParseDeny splits a deny file's contents into one pattern per line.
func ParseDeny(contents string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(contents))
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// Blocked reports the first deny pattern that matches cmd, if any. A nil Guard
// never blocks.
func (g *Guard) Blocked(cmd string) (pattern string, blocked bool) {
	if g == nil {
		return "", false
	}
	for _, re := range g.patterns {
		if re.MatchString(cmd) {
			return re.String(), true
		}
	}
	return "", false
}

// Size reports how many patterns the Guard holds (0 for a nil Guard).
func (g *Guard) Size() int {
	if g == nil {
		return 0
	}
	return len(g.patterns)
}
