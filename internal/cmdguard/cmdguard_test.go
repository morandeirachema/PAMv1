package cmdguard

import (
	"errors"
	"strings"
	"testing"
)

// TestGuard checks pattern matching, comment/blank skipping, the nil-guard
// no-op, and fail-loud compilation.
func TestGuard(t *testing.T) {
	g, err := New([]string{
		"# dangerous filesystem wipes",
		`rm\s+-rf`,
		"",
		"(?i)drop\\s+table",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if g.Size() != 2 {
		t.Fatalf("Size = %d, want 2 (comment + blank skipped)", g.Size())
	}
	cases := []struct {
		cmd     string
		blocked bool
	}{
		{"rm -rf /", true},
		{"DROP TABLE users", true},
		{"drop table users", true}, // case-insensitive pattern
		{"ls -la", false},
		{"select * from users", false},
	}
	for _, c := range cases {
		if _, got := g.Blocked(c.cmd); got != c.blocked {
			t.Errorf("Blocked(%q) = %v, want %v", c.cmd, got, c.blocked)
		}
	}

	// A nil guard blocks nothing.
	var nilGuard *Guard
	if _, blocked := nilGuard.Blocked("rm -rf /"); blocked {
		t.Fatal("nil guard must not block")
	}
	if nilGuard.Size() != 0 {
		t.Fatal("nil guard Size must be 0")
	}

	// An all-comment set is an ERROR, not an empty guard. Returning (nil, nil)
	// here used to fail OPEN: an empty or unmounted policy file silently disabled
	// the control while startup logged "command control enabled patterns=0".
	// Setting the env var is a statement of intent, so the only safe reading of
	// "I asked for command control and got none" is to refuse.
	empty, err := New([]string{"# only a comment", "  "})
	if !errors.Is(err, ErrNoPatterns) {
		t.Fatalf("all-comment set: guard=%v err=%v, want ErrNoPatterns", empty, err)
	}
	if empty != nil {
		t.Fatalf("all-comment set returned a guard: %v", empty)
	}

	// A malformed pattern is a fail-loud error.
	if _, err := New([]string{"("}); err == nil {
		t.Fatal("expected an error for a malformed pattern")
	}
}

// TestGuardAllowed proves Allowed reads the same compiled pattern set Blocked
// does (built via the same New/ParseDeny loader — an allow-list is just a
// Guard value used the other way round), and that a nil Guard allows nothing,
// mirroring Blocked's "nil blocks nothing" — the opposite default, on purpose,
// since an allow-list's whole point is to be restrictive once configured.
func TestGuardAllowed(t *testing.T) {
	g, err := New([]string{
		"^service\\s+nginx\\s+(status|restart)$",
		"^df\\s+-h$",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := []struct {
		cmd     string
		allowed bool
	}{
		{"service nginx status", true},
		{"service nginx restart", true},
		{"df -h", true},
		{"rm -rf /", false},
		{"service nginx stop", false}, // not in the (status|restart) alternation
	}
	for _, c := range cases {
		if got := g.Allowed(c.cmd); got != c.allowed {
			t.Errorf("Allowed(%q) = %v, want %v", c.cmd, got, c.allowed)
		}
	}

	var nilGuard *Guard
	if nilGuard.Allowed("df -h") {
		t.Fatal("nil guard must not allow anything")
	}
}

// TestParseDeny proves the deny-file loader keeps every line verbatim (New is
// where comments/blank handling and compilation happen) and round-trips into a
// working guard — the PAM_COMMAND_DENY_FILE path main.go uses.
func TestParseDeny(t *testing.T) {
	lines := ParseDeny("rm -rf /\n# a comment\n\n^shutdown\\b\n")
	if len(lines) != 4 {
		t.Fatalf("ParseDeny kept %d lines, want 4 (verbatim)", len(lines))
	}
	g, err := New(lines)
	if err != nil {
		t.Fatalf("New from parsed file: %v", err)
	}
	if _, blocked := g.Blocked("shutdown -h now"); !blocked {
		t.Fatal("pattern from a parsed file did not block")
	}
	if _, blocked := g.Blocked("ls -la"); blocked {
		t.Fatal("innocent command blocked")
	}
}

// TestParseDenyHandlesLongLines proves a deny file is never silently truncated.
//
// ParseDeny used to run a bufio.Scanner over the contents. The Scanner has a
// 64 KiB default token limit, stops at the first line that exceeds it, and
// reports that through Err() — which nothing checked. So one over-long line
// discarded every pattern after it while startup logged the control as enabled
// with whatever count survived. A security control that half-loads is worse than
// one that fails, because nothing looks wrong.
func TestParseDenyHandlesLongLines(t *testing.T) {
	// A comment line well past the Scanner's old 64 KiB limit, followed by the
	// pattern that actually matters.
	long := "# " + strings.Repeat("x", 200*1024)
	lines := ParseDeny(long + "\n^shutdown\\b\ncurl\\s+http\n")
	if len(lines) != 3 {
		t.Fatalf("ParseDeny kept %d lines, want 3 — a long line must not truncate the file", len(lines))
	}
	g, err := New(lines)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if g.Size() != 2 {
		t.Fatalf("guard holds %d patterns, want 2", g.Size())
	}
	// The patterns AFTER the long line are the ones that used to disappear.
	if _, blocked := g.Blocked("shutdown -h now"); !blocked {
		t.Fatal("a pattern following an over-long line was lost")
	}
	if _, blocked := g.Blocked("curl http://evil.example/x"); !blocked {
		t.Fatal("the last pattern in the file was lost")
	}
}

// TestParseDenyCRLF proves a policy file saved with Windows line endings yields
// the same patterns as one with Unix endings. Without trimming, every pattern
// would carry a trailing \r and quietly fail to match.
func TestParseDenyCRLF(t *testing.T) {
	g, err := New(ParseDeny("^shutdown\\b\r\n# comment\r\nrm\\s+-rf\r\n"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, blocked := g.Blocked("shutdown -h now"); !blocked {
		t.Fatal("a CRLF-terminated pattern did not match")
	}
}
