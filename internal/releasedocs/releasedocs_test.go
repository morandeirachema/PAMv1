package releasedocs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	digestRe       = regexp.MustCompile(`sha256:[0-9a-f]{64}`)
	versionRe      = regexp.MustCompile(`v(\d+\.\d+\.\d+)`)
	roadmapRelRe   = regexp.MustCompile(`(?m)^## Phase \d+ — (v\d+\.\d+\.\d+[^\n]*)✅$`)
	changelogSecRe = regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`)
	// A digest recorded against its release page: the form every changelog
	// entry uses since Phase 262.
	pageLinkRe     = regexp.MustCompile("`(sha256:[0-9a-f]{64})`\\s*\\(\\[release page\\]\\(https://github\\.com/morandeirachema/PAMv1/releases/tag/v(\\d+\\.\\d+\\.\\d+)\\)\\)")
	readmeStatusRe = regexp.MustCompile("(?s)\\*\\*Status:\\*\\* \\*\\*\\[v(\\d+\\.\\d+\\.\\d+)\\].*?`(sha256:[0-9a-f]{64}|TBD)`")
)

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// sections splits a document at each heading match, keyed by version: a
// ROADMAP release heading may name two versions ("v0.58.0, and v0.58.1 …"),
// and both map to the same body.
func roadmapReleases(doc string) (order []string, body map[string]string) {
	body = map[string]string{}
	idx := roadmapRelRe.FindAllStringSubmatchIndex(doc, -1)
	for i, m := range idx {
		end := len(doc)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		// The body runs to the next "## " heading of any kind.
		rest := doc[m[1]:end]
		if j := strings.Index(rest, "\n## "); j >= 0 {
			rest = rest[:j]
		}
		for _, v := range versionRe.FindAllStringSubmatch(doc[m[2]:m[3]], -1) {
			if _, seen := body[v[1]]; !seen {
				order = append(order, v[1])
			}
			body[v[1]] += rest
		}
	}
	return order, body
}

func changelogSections(doc string) map[string]string {
	out := map[string]string{}
	idx := changelogSecRe.FindAllStringSubmatchIndex(doc, -1)
	for i, m := range idx {
		end := len(doc)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		out[doc[m[2]:m[3]]] = doc[m[0]:end]
	}
	return out
}

// TestReleaseDigestsAgree proves the three documents tell one story about
// each release's image digest: the changelog's recorded digest is the one the
// roadmap's release entry records, the README's current release and digest
// match both, a pointer to a place that does not hold the value is gone, and
// only the newest release entry may still say `TBD` (its digest PR has not
// landed yet).
func TestReleaseDigestsAgree(t *testing.T) {
	readme, changelog, roadmap := read(t, "README.md"), read(t, "CHANGELOG.md"), read(t, "ROADMAP.md")
	order, releases := roadmapReleases(roadmap)
	if len(order) == 0 {
		t.Fatal("no release entries found in ROADMAP.md — has the heading format changed?")
	}
	has := func(body, digest string) bool {
		// Digests are sometimes wrapped mid-backtick-span; compare with whitespace removed.
		return strings.Contains(strings.Join(strings.Fields(body), ""), digest)
	}

	for i, v := range order {
		if strings.Contains(releases[v], "digest `TBD`") && i != 0 {
			t.Errorf("ROADMAP.md: the v%s release entry still records digest `TBD`, and it is not the newest release", v)
		}
	}

	if strings.Contains(changelog, "full value is in the README") {
		t.Error("CHANGELOG.md: a digest still points at the README, which keeps only the latest one — record the full digest")
	}
	links := pageLinkRe.FindAllStringSubmatch(changelog, -1)
	if len(links) == 0 {
		t.Fatal("no release-page digest records found in CHANGELOG.md — has the format changed?")
	}
	sections := changelogSections(changelog)
	for _, l := range links {
		digest, v := l[1], l[2]
		if !strings.Contains(sections[v], l[0]) {
			t.Errorf("CHANGELOG.md: the digest linked to v%s's release page sits outside the [%s] entry", v, v)
		}
		body, ok := releases[v]
		if !ok {
			// The earliest releases predate "## Phase N — vX.Y.Z" entries
			// (v0.10.0 is recorded under "What is left"): the digest must at
			// least appear in the roadmap.
			if !has(roadmap, digest) {
				t.Errorf("CHANGELOG.md records %s for v%s, which ROADMAP.md does not record anywhere", digest, v)
			}
			continue
		}
		if !has(body, digest) {
			t.Errorf("CHANGELOG.md records %s for v%s, but ROADMAP.md's v%s entry does not", digest, v, v)
		}
	}

	// The [Unreleased] comparison starts at the newest release; it sat at
	// v0.58.2 for seventeen releases before this check existed.
	if newest := changelogSecRe.FindStringSubmatch(changelog); newest != nil {
		want := "[Unreleased]: https://github.com/morandeirachema/pamv1/compare/v" + newest[1] + "...HEAD"
		if !strings.Contains(changelog, want) {
			t.Errorf("CHANGELOG.md: the [Unreleased] link must compare from v%s, the newest entry: %s", newest[1], want)
		}
	}

	m := readmeStatusRe.FindStringSubmatch(readme)
	if m == nil {
		t.Fatal("README.md: no **Status:** release line with a digest found — has the format changed?")
	}
	v, digest := m[1], m[2]
	if order[0] != v {
		t.Errorf("README.md's status names v%s, but the newest ROADMAP release entry is v%s", v, order[0])
	}
	if strings.Contains(releases[v], "digest `TBD`") {
		// Between a release PR and its digest PR the README already names the
		// new release; it must say TBD too (Phase 267). It used to be allowed
		// to keep the previous release's digest, which for the fifteen minutes
		// between PRs labelled the old image as the new release — exactly the
		// tag/digest confusion the paragraph exists to prevent.
		if digest != "TBD" {
			t.Errorf("README.md shows %s for v%s, whose digest is not recorded yet — it must say `TBD` until the digest PR lands", digest, v)
		}
		return
	}
	if digest == "TBD" {
		t.Errorf("README.md still says `TBD` for v%s, whose digest ROADMAP.md records", v)
		return
	}
	if !has(releases[v], digest) {
		t.Errorf("README.md gives v%s the digest %s, which ROADMAP.md's v%s entry does not record", v, digest, v)
	}
	if !has(sections[v], digest) {
		t.Errorf("README.md gives v%s the digest %s, which CHANGELOG.md's [%s] entry does not record", v, digest, v)
	}
	for _, d := range digestRe.FindAllString(readme, -1) {
		if d != digest && !strings.Contains(changelog, d) {
			t.Errorf("README.md mentions %s, which CHANGELOG.md does not record for any release", d)
		}
	}
}
