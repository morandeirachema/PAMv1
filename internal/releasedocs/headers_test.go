package releasedocs

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	bannerRe    = regexp.MustCompile(`\*\*Phases 0–227 and 229–(\d+) are shipped\*\*`)
	headerRe    = regexp.MustCompile(`(?m)^> Last updated: (\d{4}-\d{2}-\d{2}) · Reflects: Phases 0–227 and 229–(\d+)`)
	logRowRe    = regexp.MustCompile(`(?m)^\| (\d{4}-\d{2}-\d{2}) \|`)
	readmeEnRe  = regexp.MustCompile(`runs 0–227 and 229–(\d+),`)
	readmeEsRe  = regexp.MustCompile(`de la 0 a la 227 y de la 229 a la (\d+),`)
	docsRelease = regexp.MustCompile(`and release v(\d+\.\d+\.\d+) \(see \[CHANGELOG\.md\]`)
)

// TestDocHeadersAgree is the guard Phase 267 added after a review found the
// documentation's own currency stamps disagreeing with each other: thirteen
// `Reflects:` headers naming phases that landed two weeks after the date
// beside them, `docs/README.md` naming a release nine releases old, and
// SECURITY.md describing a project with no releases. Each was a hand sweep
// that touched the line and left the token.
//
// The rules, each tied to one of those findings:
//
//   - every `> Last updated: D · Reflects: Phases 0–227 and 229–N` header under
//     docs/ names the same N as the ROADMAP banner ("Phases 0–227 and 229–N are
//     shipped"), and so do both READMEs' phase-range sentences;
//   - a header's date D is never older than the newest row of that document's
//     own change-log table — the range moved, so the date must have;
//   - docs/README.md's release token is CHANGELOG's newest version.
//
// A document without such a header (RELATED-PROJECTS.md reflects a market
// survey, not a phase range) is not checked.
func TestDocHeadersAgree(t *testing.T) {
	roadmap := read(t, "ROADMAP.md")
	m := bannerRe.FindStringSubmatch(roadmap)
	if m == nil {
		t.Fatal("ROADMAP.md: no 'Phases 0–227 and 229–N are shipped' banner")
	}
	want := m[1]

	docs, err := filepath.Glob(filepath.Join("..", "..", "docs", "*.md"))
	if err != nil || len(docs) == 0 {
		t.Fatalf("docs/*.md: %v", err)
	}
	sort.Strings(docs)
	checked := 0
	for _, p := range docs {
		b, err := os.ReadFile(p) // #nosec G304 -- repository documents, enumerated by glob
		if err != nil {
			t.Fatal(err)
		}
		doc := string(b)
		h := headerRe.FindStringSubmatch(doc)
		if h == nil {
			continue
		}
		checked++
		name := filepath.Base(p)
		if h[2] != want {
			t.Errorf("docs/%s: header reflects phases through %s, but ROADMAP.md's banner says %s are shipped", name, h[2], want)
		}
		newest := ""
		for _, r := range logRowRe.FindAllStringSubmatch(doc, -1) {
			if r[1] > newest {
				newest = r[1]
			}
		}
		if newest != "" && h[1] < newest {
			t.Errorf("docs/%s: header says 'Last updated: %s' but its own change log has a row dated %s — the range moved and the date did not", name, h[1], newest)
		}
	}
	if checked < 10 {
		t.Fatalf("only %d docs carry a Reflects header — the pattern this test looks for has drifted", checked)
	}

	for _, rd := range []struct {
		file string
		re   *regexp.Regexp
	}{{"README.md", readmeEnRe}, {"README.es.md", readmeEsRe}} {
		r := rd.re.FindStringSubmatch(read(t, rd.file))
		if r == nil {
			t.Errorf("%s: the phase-range sentence is missing or reworded", rd.file)
		} else if r[1] != want {
			t.Errorf("%s: says the roadmap runs through %s, but ROADMAP.md's banner says %s", rd.file, r[1], want)
		}
	}

	sections := changelogSecRe.FindAllStringSubmatch(read(t, "CHANGELOG.md"), -1)
	if len(sections) == 0 {
		t.Fatal("CHANGELOG.md: no release section")
	}
	newestRelease := sections[0][1]
	d := docsRelease.FindStringSubmatch(read(t, filepath.Join("docs", "README.md")))
	if d == nil {
		t.Error("docs/README.md: the header's 'and release vX.Y.Z (see [CHANGELOG.md]' token is missing")
	} else if d[1] != newestRelease {
		t.Errorf("docs/README.md: header says the docs reflect release v%s, but CHANGELOG.md's newest is %s", d[1], newestRelease)
	}
	if strings.Contains(read(t, "SECURITY.md"), "There are no published releases yet") {
		t.Error("SECURITY.md still says there are no published releases")
	}
}
