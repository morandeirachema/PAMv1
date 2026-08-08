package web

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The portal is ~2,500 lines of JavaScript embedded in index.html. `go:embed`
// copies bytes without parsing them, so nothing in the build, the tests or the
// container image ever looked at that script: a syntax error compiled clean,
// tested clean, shipped, and broke the portal at runtime. Three real defects
// reached main through the same hole and were caught only by rendering screens
// by hand — including one where the console asked for a capability the API had
// stopped requiring six phases earlier, which every security sweep missed
// because no sweep reads the console.
//
// These are the tests that close it. They shell out to node, which the CI runner
// has; locally they skip when it is absent, and CI runs the same checks as an
// explicit step so a missing node fails the build rather than silently skipping.

// consoleScript returns the portal's single inline script.
func consoleScript(t *testing.T) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`).FindSubmatch(indexHTML)
	if m == nil {
		t.Fatal("index.html has no <script> block — the console is the page's only logic")
	}
	if len(m[1]) < 10000 {
		t.Fatalf("the extracted console script is only %d bytes; the extraction is probably wrong", len(m[1]))
	}
	return string(m[1])
}

// node reports the node binary, or skips when it is unavailable.
func node(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; CI runs this check as an explicit step so it cannot be skipped there")
	}
	return bin
}

// TestConsoleScriptParses is the floor: the embedded console must be valid
// JavaScript. Without it a typo in index.html ships, because embedding does not
// parse and no Go test reads the script.
func TestConsoleScriptParses(t *testing.T) {
	bin := node(t)
	script := consoleScript(t)
	f := filepath.Join(t.TempDir(), "console.js")
	if err := writeFile(f, script); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "--check", f).CombinedOutput()
	if err != nil {
		t.Fatalf("the embedded console is not valid JavaScript:\n%s", out)
	}
}

// TestConsoleScreensAreBounded proves the invariant behind the layout bug that
// shipped: a table row must not widen with its data. Each screen is rendered
// twice, with short values and with pathological ones, and the rendered rows must
// come out the same width — so a cell that is padded but never truncated fails
// here instead of pushing the last column off a 980px terminal, which on a
// refused row is where the reason lives.
//
// It also exercises the audit-detail parser, which handles two different quoting
// granularities and was wrong about one of them once.
func TestConsoleScreensAreBounded(t *testing.T) {
	bin := node(t)
	// Written from the embedded bytes rather than read off disk, so the test
	// checks what actually ships.
	dir := t.TempDir()
	page := filepath.Join(dir, "index.html")
	if err := writeFile(page, string(indexHTML)); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, filepath.Join("testdata", "console_check.js"), page).CombinedOutput()
	if err != nil {
		t.Fatalf("console checks failed:\n%s", out)
	}
	if !strings.Contains(string(out), "ok:") {
		t.Fatalf("console checks reported nothing:\n%s", out)
	}
	t.Log(strings.TrimSpace(string(out)))
}

// writeFile is os.WriteFile with the test's usual permissions.
func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }
