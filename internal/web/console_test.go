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

// TestConsoleThemeTokensAreConsistent proves the invariant the Phase 126 color
// themes depend on: every CSS custom property the stylesheet USES (var(--x)) is
// DEFINED somewhere in the base :root block, and every property a [data-theme]
// override DEFINES is a real token from that same base set — not a typo that
// silently renders as the browser's initial value (transparent/black), and not
// a stray new token one theme defines that the others never override, which
// would make that theme quietly inherit a wrong color from whichever palette
// happened to be active.
//
// This is a text-level check, not a rendered one: the JS-eval harness above
// measures row *width*, which no CSS custom property can affect, so it is the
// wrong tool for a color-token regression. No browser runs here to check
// contrast or overflow either — this test catches the one class of theme bug
// that is mechanically checkable without one: a token used or defined that
// does not match the base set, letter for letter.
func TestConsoleThemeTokensAreConsistent(t *testing.T) {
	style := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindSubmatch(indexHTML)
	if style == nil {
		t.Fatal("index.html has no <style> block")
	}
	css := string(style[1])

	rootBlock := regexp.MustCompile(`(?s):root\s*\{([^}]*)\}`).FindStringSubmatch(css)
	if rootBlock == nil {
		t.Fatal("no base :root { ... } block found")
	}
	tokenName := regexp.MustCompile(`--([a-z-]+)\s*:`)
	defined := map[string]bool{}
	for _, m := range tokenName.FindAllStringSubmatch(rootBlock[1], -1) {
		defined[m[1]] = true
	}
	if len(defined) < 10 {
		t.Fatalf("base :root only defines %d custom properties; the extraction is probably wrong", len(defined))
	}

	used := map[string]bool{}
	for _, m := range regexp.MustCompile(`var\(--([a-z-]+)\)`).FindAllStringSubmatch(css, -1) {
		used[m[1]] = true
	}
	for name := range used {
		if !defined[name] {
			t.Errorf("stylesheet uses var(--%s), which the base :root block never defines", name)
		}
	}

	themes := regexp.MustCompile(`(?s):root\[data-theme="([a-z]+)"\]\s*\{([^}]*)\}`).FindAllStringSubmatch(css, -1)
	if len(themes) < 2 {
		t.Fatalf("expected at least 2 [data-theme] palettes (amber, slate), found %d", len(themes))
	}
	for _, th := range themes {
		name, block := th[1], th[2]
		for _, m := range tokenName.FindAllStringSubmatch(block, -1) {
			if !defined[m[1]] {
				t.Errorf("theme %q defines --%s, which is not one of the base :root tokens (typo?)", name, m[1])
			}
		}
	}
}
