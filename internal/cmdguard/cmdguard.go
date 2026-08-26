// Package cmdguard implements command control: a policy-driven denylist that
// blocks a dangerous command before it reaches a target, plus an optional
// allow-list (Phase 131) that, once configured, narrows a path to ONLY the
// listed commands — Delinea's "Command Menus" is the closest commercial-PAM
// analogue. Deny always wins when both would match; an allow-list is
// deliberately its own separate Guard value, not a mode flag on one, so a
// path with no allow-list configured keeps exactly its pre-Phase-131
// deny-only behavior.
//
// It applies on every path where PAMv1 can see a **discrete command** — the SSH
// `exec` request (non-interactive `ssh target "cmd"`), each WinRM command-loop
// line and each REST WinRM run, each PostgreSQL/SQL Server statement, and the
// agent broker's `ssh_exec`/`winrm_exec` tools. One deny policy, loaded once
// from PAM_COMMAND_DENY_FILE, and one optional allow policy, loaded once from
// PAM_COMMAND_ALLOW_FILE, are each shared by the session proxies and the API
// server so a pattern cannot be enforced for a human on the proxy yet ignored
// for an AI agent calling a tool.
//
// What it does NOT cover is inherent, not an oversight: an interactive SSH shell
// streams a raw PTY that is never parsed, so the guard must not be read as a
// containment boundary. Use read-only observer sessions, or restrict shell
// access, where you need that guarantee.
package cmdguard

import (
	"errors"
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
		// A caller that asked for a guard and got none must be able to tell that
		// apart from "no guard was configured" — see ErrNoPatterns. Returning a
		// bare nil here is what let an empty or unmounted policy file disable the
		// control while startup logged it as enabled.
		return nil, ErrNoPatterns
	}
	return &Guard{patterns: ps}, nil
}

// ErrNoPatterns is returned by New when the input contained no usable pattern —
// an empty file, one that is only comments, or a ConfigMap that failed to mount.
//
// It is an error rather than an empty guard because the alternative fails OPEN:
// `PAM_COMMAND_DENY_FILE`, `PAM_SSH_SFTP_DENY_FILE` and `PAM_DB_STEPUP_FILE`
// would each be silently inert while the operator who set them believed
// otherwise. Setting the variable is a statement of intent, and the only safe
// reading of "I asked for command control and got none" is to refuse to start.
var ErrNoPatterns = errors.New("no usable patterns")

// ParseDeny splits a deny file's contents into one pattern per line.
//
// It splits the string directly rather than running a bufio.Scanner over it. The
// Scanner has a 64 KiB default token limit and stops at the first line that
// exceeds it — and its Err() was never checked, so a single over-long line
// silently discarded every pattern after it while startup logged the control as
// enabled. Splitting a string that is already fully in memory has no size limit
// to get wrong, which is the point: a security control should not be able to
// half-load.
//
// Trailing carriage returns are trimmed so a file saved with CRLF endings
// produces the same patterns as one with LF.
func ParseDeny(contents string) []string {
	lines := strings.Split(contents, "\n")
	// A file ending in a newline splits with a trailing empty element; drop it so
	// the result matches line-oriented reading exactly.
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, strings.TrimSuffix(l, "\r"))
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

// Allowed reports whether cmd matches any pattern this Guard holds — the same
// compiled set Blocked reads, interpreted the opposite way by the caller (this
// is an allow-list, not a denylist). A nil Guard allows nothing, mirroring
// Blocked's "nil blocks nothing": the caller decides what a nil allow-list
// MEANS (see cmd/pam-server/main.go's PAM_COMMAND_ALLOW_FILE wiring — an
// unconfigured allow-list leaves every path deny-only, exactly as it worked
// before this method existed; it is only once a caller HOLDS a non-nil
// allow Guard that "no pattern matched" becomes a refusal).
func (g *Guard) Allowed(cmd string) bool {
	if g == nil {
		return false
	}
	for _, re := range g.patterns {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// Size reports how many patterns the Guard holds (0 for a nil Guard).
func (g *Guard) Size() int {
	if g == nil {
		return 0
	}
	return len(g.patterns)
}
