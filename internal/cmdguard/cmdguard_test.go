package cmdguard

import "testing"

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

	// An all-comment set yields a nil guard (nothing to enforce).
	empty, err := New([]string{"# only a comment", "  "})
	if err != nil || empty != nil {
		t.Fatalf("all-comment set: guard=%v err=%v, want nil,nil", empty, err)
	}

	// A malformed pattern is a fail-loud error.
	if _, err := New([]string{"("}); err == nil {
		t.Fatal("expected an error for a malformed pattern")
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
