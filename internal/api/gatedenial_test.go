package api

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestGateDenialNamesAreDocumented closes a documentation defect class rather
// than a code one, and it is the third variant of the same guard this repo keeps
// needing: Phase 161's "a classification no code can emit", Phase 185's "an
// emitted refusal nothing classifies", and now "an emitted action §5 never
// names".
//
// The specific trap is that `gateCredentialAccess` does not audit the string it
// is given — it audits that string PLUS `_denied`. So the refusal name never
// appears as a literal anywhere in the source, and every previous audit of the
// vocabulary looked for literals. Two names had been missing from the low-level
// doc's §5 since Phase 135 for exactly that reason: a grep for
// `credential.doublelock_enable_denied` finds nothing in the tree, because the
// code only ever writes `"credential.doublelock_enable"` and lets the helper
// append the rest.
//
// The test therefore reconstructs the names the way the helper does, and asserts
// the documentation carries each one. It fails on a NEW call site whose refusal
// nobody documented, which is the moment the gap is cheap to close.
func TestGateDenialNamesAreDocumented(t *testing.T) {
	src, err := os.ReadFile("targets.go")
	if err != nil {
		t.Fatal(err)
	}
	// The helper's own body is the definition of the suffix; if it ever stops
	// appending "_denied", this test must stop assuming it does.
	if !strings.Contains(string(src), `s.audit(r.Context(), action+"_denied"`) {
		t.Fatal("gateCredentialAccess no longer audits action+\"_denied\"; update this guard to match")
	}

	// Every call site's action argument, read from the sources that call it.
	call := regexp.MustCompile(`gateCredentialAccess\([^)]*"([a-z][a-z0-9_.]*)"\)`)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]string{} // action -> file it was found in
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name) // #nosec G304 -- test-only read of this package's own sources
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range call.FindAllStringSubmatch(string(b), -1) {
			actions[m[1]] = name
		}
	}
	if len(actions) == 0 {
		t.Fatal("found no gateCredentialAccess call sites; the regexp has drifted from the code")
	}

	doc, err := os.ReadFile("../../docs/ARCHITECTURE-LOW-LEVEL.md")
	if err != nil {
		t.Fatal(err)
	}
	// Only §5 counts. A name mentioned in the change log is history, not
	// vocabulary — the distinction Phase 193 had to learn the hard way, when a
	// doc "documented" a value only in a row describing a past phase.
	whole := string(doc)
	start := strings.Index(whole, "## 5.")
	end := strings.Index(whole[max(start, 0):], "## 6.")
	if start < 0 || end < 0 {
		t.Fatal("could not locate §5 in ARCHITECTURE-LOW-LEVEL.md")
	}
	section := whole[start : start+end]

	for action, file := range actions {
		denial := action + "_denied"
		if !strings.Contains(section, "`"+denial+"`") {
			t.Errorf("%s emits %q on refusal, and §5 of docs/ARCHITECTURE-LOW-LEVEL.md never names it.\n"+
				"It is invisible to a literal grep because gateCredentialAccess appends the suffix, "+
				"which is exactly how two of these stayed undocumented for seventy phases.", file, denial)
		}
	}
}

// max returns the larger of two ints. Present only so the §5 lookup above reads
// as one expression; Go's builtin min/max cover ints from 1.21 but this file is
// explicit about the zero-floor it wants.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
