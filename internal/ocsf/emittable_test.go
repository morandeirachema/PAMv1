package ocsf

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// scanRoots are the source trees walked by TestFindingExactActionsAreEmittable,
// relative to this package's directory (a Go test always runs with its own
// package directory as the working directory, so "../.." is the repo root).
var scanRoots = []string{
	filepath.Join("..", "..", "internal"),
	filepath.Join("..", "..", "cmd"),
}

// collectGoSources walks the given directories and returns the paths of every
// production Go file underneath them. "Production" excludes `_test.go` files
// (a name that only ever appears in a test proves nothing about what the server
// can emit) and excludes this very package, whose whole job is to *hold* the
// names rather than emit them. Hidden directories and the vendor/testdata trees
// are skipped, like most Go tooling does.
//
// For a Python reader: this is the equivalent of os.walk() plus a filter, and
// the returned slice is just a list of path strings. `filepath.WalkDir` calls
// the closure once per entry; returning `fs.SkipDir` from it is how you tell
// the walker "do not descend into this directory", the way you would prune
// `dirnames` in place with os.walk.
func collectGoSources(t *testing.T, roots []string) []string {
	t.Helper()
	var files []string
	skipDir := map[string]bool{"vendor": true, "testdata": true, "node_modules": true}
	ocsfDir := filepath.Join("..", "..", "internal", "ocsf")
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			t.Fatalf("cannot scan %s: %v (this test must run from the internal/ocsf package directory)", root, err)
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if d.IsDir() {
				if skipDir[name] || (strings.HasPrefix(name, ".") && name != "." && name != "..") {
					return fs.SkipDir
				}
				if filepath.Clean(path) == filepath.Clean(ocsfDir) {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			files = append(files, path)
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	if len(files) == 0 {
		t.Fatal("scanned no Go sources at all; the roots or the working directory are wrong, and a guard that scans nothing passes vacuously")
	}
	return files
}

// TestFindingExactActionsAreEmittable is the standing guard against this
// package's oldest recurring defect: an audit-action name sitting in
// findingExact that no code in the repository can ever produce. Such an entry
// is worse than a missing one — it advertises SIEM coverage that does not
// exist, and a detection rule written against it can never fire. See this
// file's sibling ocsf.go header for the two real incidents
// (`proxy.auth_rate_limited`, dead for a week after Phase 52e; and its mirror
// image `breakglass.unseal_failed`, emitted but classified nowhere).
//
// How it works: it reads every production Go file under internal/ and cmd/
// (minus internal/ocsf and minus *_test.go) into memory once, then asserts that
// each key of findingExact occurs somewhere as a *quoted* string literal, i.e.
// `"authz.denied"` including the double quotes. A plain substring search is
// used on purpose rather than parsing the files into an AST: it is far shorter,
// it cannot be defeated by a parse error in an unrelated package, and quoting
// the name is already enough to rule out accidental matches against comments'
// prose or against a longer action that merely contains this one.
//
// Known limits, stated honestly so a future reader does not over-trust this:
//
//   - Presence of the literal proves some code *mentions* the name, not that
//     the name reaches the PRIMARY audit trail that the OCSF exporter reads.
//     `broker.tool_call.denied` is precisely that case historically: it lived
//     only in the hash-chained broker audit (internal/auditchain, table
//     broker_audit_events), which this exporter never reads, so the literal
//     existed while the classification stayed dead. Only a human can check the
//     destination; this test checks existence.
//   - It deliberately does NOT test the reverse direction — that every denial
//     shaped action emitted anywhere is classified as a finding. That check
//     cannot be made reliable: many actions are assembled by concatenation at
//     the call site (broker.go builds `"broker.tool_call."+string(out.Status)`),
//     so no scan of string literals can enumerate the emitted set; and the
//     suffix rules in isFinding (`_denied`, `_failed`) plus the `breakglass.`
//     and `analytics.` prefixes already catch most of them without needing a
//     map entry. A reverse test would therefore be a noisy approximation, and a
//     guard that cries wolf gets deleted.
func TestFindingExactActionsAreEmittable(t *testing.T) {
	files := collectGoSources(t, scanRoots)

	sources := make([]string, 0, len(files))
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- test-only walk over the repo's own source tree
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		sources = append(sources, string(b))
	}

	actions := make([]string, 0, len(findingExact))
	for action := range findingExact {
		actions = append(actions, action)
	}
	sort.Strings(actions) // map order is random in Go; sort so failures read the same every run

	var dead []string
	for _, action := range actions {
		literal := `"` + action + `"`
		found := false
		for _, src := range sources {
			if strings.Contains(src, literal) {
				found = true
				break
			}
		}
		if !found {
			dead = append(dead, action)
		}
	}

	if len(dead) > 0 {
		t.Fatalf("findingExact classifies %d action(s) that no code under internal/ or cmd/ can emit:\n  %s\n"+
			"Each one is a defect, not a harmless extra: a SIEM rule built on that name can never fire, "+
			"so the trail advertises detection coverage it does not have (the same failure as "+
			"`proxy.auth_rate_limited`, dead in this map for a week after Phase 52e — see the ocsf.go header). "+
			"Fix it by deleting the stale key, or by correcting it to the name the emitting code actually appends. "+
			"Scanned %d Go files.",
			len(dead), strings.Join(dead, "\n  "), len(files))
	}
}
