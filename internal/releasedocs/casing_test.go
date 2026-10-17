package releasedocs

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// projectName is the lowercase spelling the test hunts for, kept in one
// place so this file's own prose can follow the rule it enforces.
const projectName = "pamv1"

var (
	// The match is an argument to a command-line flag or to a Helm, systemd or
	// account command: "-n pamv1", "helm install pamv1", "systemctl status
	// pamv1", "id pamv1".
	argumentOfRe = regexp.MustCompile(`(?:^|[\s(])(?:-{1,2}[A-Za-z][\w-]*|helm(?: secrets)? (?:install|upgrade|template|uninstall)|systemctl [a-z-]+|id|/usr/sbin/nologin)\s+$`)
	// The whole line is a Debian preseed answer whose value is the name (the
	// appliance's hostname): "d-i netcfg/hostname string pamv1".
	preseedValueRe = regexp.MustCompile(`^d-i\s+\S+\s+(?:string|password)\s+` + projectName + `\s*$`)
	// The whole line is a YAML scalar: "namespace: pamv1", with an optional
	// trailing comment.
	yamlValueRe = regexp.MustCompile(`^\s*(?:-\s+)?[\w./-]+:\s+` + projectName + `\s*(?:#.*)?$`)
	// A Markdown code span.
	codeSpanRe = regexp.MustCompile("`[^`]*`")
)

// skipCasing are the paths the test does not read. Applied migrations are
// never edited, so their comments keep the spelling they shipped with.
var skipCasing = []string{
	"go.mod",
	"go.sum",
	"internal/store/pgstore/migrations/",
}

// TestProjectNameCasing is the gate for house style §8 (docs/README.md): the
// project is PAMv1 in prose, and lowercase only where it is an identifier —
// the module path, the image, Kubernetes and Helm names, file paths. #463 and
// #464 fixed the casing by hand, one sweep at a time, and each sweep missed
// files the next one found.
//
// A lowercase match is an identifier, and allowed, when any of these hold:
//
//   - it is glued to a path, URL, flag, key or quote on either side
//     (`/`, `.`, `-`, `_`, `@`, `:`, `=`, `$`, `{`, `<`, `#`, a backtick, or a
//     closing quote), so "ghcr.io/…/pamv1:0.0.79" and a string literal
//     holding exactly the name both pass;
//   - it is the argument of a flag or of a Helm or systemd command;
//   - its line is a YAML `key: value`, or a preseed answer, with it as the
//     whole value;
//   - it is inside a Markdown code span or fenced block.
//
// Everything else is prose and fails, with a pointer to the line. The fix is
// PAMv1, or backticks when the lowercase identifier is what is meant.
func TestProjectNameCasing(t *testing.T) {
	root := filepath.Join("..", "..")
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("needs a git checkout to list tracked files: %v", err)
	}
	var bad []string
	for _, name := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if skippedForCasing(name) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, name)) // #nosec G304 -- tracked repository files, listed by git
		if err != nil {
			t.Fatal(err)
		}
		if bytes.IndexByte(b, 0) >= 0 || !bytes.Contains(b, []byte(projectName)) {
			continue // binary, or nothing to check
		}
		bad = append(bad, proseUses(name, string(b))...)
	}
	if len(bad) > 0 {
		t.Errorf("%d prose uses of lowercase %s; write PAMv1, or put an identifier in backticks (house style §8, docs/README.md):\n%s",
			len(bad), projectName, strings.Join(bad, "\n"))
	}
}

func skippedForCasing(name string) bool {
	for _, s := range skipCasing {
		if name == s || (strings.HasSuffix(s, "/") && strings.HasPrefix(name, s)) {
			return true
		}
	}
	return false
}

// proseUses returns "file:line: text" for every prose use in one file.
func proseUses(name, doc string) []string {
	markdown := strings.HasSuffix(name, ".md")
	fenced := false
	var bad []string
	for i, line := range strings.Split(doc, "\n") {
		text := line
		if markdown {
			if t := strings.TrimSpace(line); strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
				fenced = !fenced
				continue
			}
			if fenced {
				continue
			}
			text = codeSpanRe.ReplaceAllString(line, "``")
		}
		if hasProseUse(text) {
			bad = append(bad, name+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
		}
	}
	return bad
}

// hasProseUse reports whether any match on the line is prose.
func hasProseUse(line string) bool {
	if yamlValueRe.MatchString(line) || preseedValueRe.MatchString(line) {
		return false
	}
	for from := 0; ; {
		j := strings.Index(line[from:], projectName)
		if j < 0 {
			return false
		}
		start := from + j
		end := start + len(projectName)
		from = end
		if gluedBefore(line, start) || gluedAfter(line, end) {
			continue
		}
		if argumentOfRe.MatchString(line[:start]) {
			continue
		}
		return true
	}
}

func isWord(c byte) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

func gluedBefore(line string, start int) bool {
	if start == 0 {
		return false
	}
	c := line[start-1]
	return isWord(c) || strings.IndexByte("/.-@:=${<#\\`", c) >= 0
}

func gluedAfter(line string, end int) bool {
	if end == len(line) {
		return false
	}
	c := line[end]
	switch {
	case c == '\'':
		// A closing quote is glue; a possessive ("…'s") is prose.
		return !strings.HasPrefix(line[end:], "'s")
	case c == '.':
		// "pamv1.svc" is a host name; a full stop ends a sentence.
		return end+1 < len(line) && isWord(line[end+1])
	default:
		return isWord(c) || strings.IndexByte("/-@:=}>\"`", c) >= 0
	}
}

// TestProseUseHeuristic pins what the gate calls prose and what it calls an
// identifier, with one case for each kind of line it met in the repository.
// NAME stands for the lowercase name, so this file passes its own gate.
func TestProseUseHeuristic(t *testing.T) {
	cases := []struct {
		file, text string
		prose      bool
	}{
		{"policy.yaml", "# NAME Conjur policy (Phase 18)", true},
		{"policy.yaml", "    description: The NAME server process.", true},
		{"secret.yaml", "# One workload secret, sourced from NAME.", true},
		{".env.example", "# pair with NAME's TOTP MFA.", true},
		{"manifest.json", `  "name": "NAME Autofill",`, true},
		{"NOTICE", "NAME", true},
		{"preseed.cfg", "d-i passwd/user-fullname string NAME appliance admin", true},
		{"README.md", "Then NAME starts.", true},

		{"go.mod", "module github.com/morandeirachema/NAME", false},
		{"deployment.yaml", "image: ghcr.io/morandeirachema/NAME:0.0.79", false},
		{"README.md", "kubectl -n NAME create secret generic pam-secrets \\", false},
		{"ci.yml", "helm template NAME deploy/helm/NAME \\", false},
		{"README.md", "systemctl status NAME          # the service", false},
		{"deployment.yaml", "  namespace: NAME", false},
		{"guacd.yaml", "  app.kubernetes.io/name: NAME   # pam-server only", false},
		{"main.go", `	RPDisplayName: "NAME",`, false},
		{"preseed.cfg", "d-i netcfg/hostname string NAME", false},
		{"firstboot.sh", `chown root:NAME "$ENV_FILE"`, false},
		{"README.md", "PAM_CONJUR_URL=https://conjur.NAME.svc.cluster.local", false},
		{"firstboot.sh", "if ! id NAME >/dev/null 2>&1; then", false},
		{"10-base.sh", "install -d -o NAME -g NAME -m 0750 /var/lib/NAME", false},
		{"ADMIN-GUIDE.md", "Run `kubectl -n NAME logs` to see it.", false},
		{"README.md", "```bash\nNAME starts here\n```", false},
	}
	for _, c := range cases {
		text := strings.ReplaceAll(c.text, "NAME", projectName)
		if got := len(proseUses(c.file, text)) > 0; got != c.prose {
			t.Errorf("%s %q: prose = %v, want %v", c.file, text, got, c.prose)
		}
	}
}
