package ocsf

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// deliberatelyNotFindings are refusal-shaped action names that are correctly NOT
// Detection Findings, each with the reason it is an exception rather than an
// oversight. A name may only be added here with one.
var deliberatelyNotFindings = map[string]string{
	// Input validation on an operator's own request, not a security event: the
	// caller mistyped a field and was told so. Exporting these would bury the
	// refusals that matter under a stream of 422s.
	"dependency.create_denied": "input validation on an admin's own request",
}

// refusalShaped matches the naming pamv1 uses when something was refused,
// blocked, or could not be verified. It is the vocabulary's own convention, so a
// new action that follows it is exactly the kind a SIEM should see.
var refusalShaped = regexp.MustCompile(`(_|\.)(denied|refused|failed|blocked|unverified)$|(^|\.)not_`)

// TestRefusalShapedActionsAreClassified closes the drift class its sibling
// TestFindingExactActionsAreEmittable leaves open, in the other direction.
//
// That test catches a classification no code can emit — coverage advertised and
// absent. This one catches the inverse: an action pamv1 really emits, named the
// way pamv1 names a refusal, that no classification reaches. Between Phases 174
// and 185 there were two — `agent.not_enrolled` and
// `broker.approval.four_eyes_unverified` — and both exported to a SIEM as
// routine API activity, which is how `broker.tool_call.denied` spent four phases
// invisible before Phase 161 noticed.
//
// The rule is deliberately narrow. It does not demand that every action be
// classified — most are routine and should stay that way. It demands only that
// an action whose NAME says something was refused either classifies as a finding
// or is listed above with a reason, so the decision is made once, on purpose,
// and written down.
func TestRefusalShapedActionsAreClassified(t *testing.T) {
	files := collectGoSources(t, scanRoots)
	literal := regexp.MustCompile(`"([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)"`)

	seen := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- test-only walk over the repo's own source tree
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		for _, m := range literal.FindAllStringSubmatch(string(b), -1) {
			if refusalShaped.MatchString(m[1]) {
				seen[m[1]] = true
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("scanned the tree and found no refusal-shaped action literals at all — the scan is broken, not the code")
	}

	var missing []string
	for action := range seen {
		if isFinding(action) {
			continue
		}
		if _, ok := deliberatelyNotFindings[action]; ok {
			continue
		}
		missing = append(missing, action)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("%d action(s) are named as refusals and classify as routine activity:\n  %s\n"+
			"A SIEM receiving these sees nothing worth a rule, which is the same failure as a rule that "+
			"can never fire — just pointed the other way. Fix by classifying the action (findingExact, or a "+
			"suffix the vocabulary already uses) or by adding it to deliberatelyNotFindings WITH its reason.\n"+
			"Scanned %d Go files and %d refusal-shaped names.",
			len(missing), strings.Join(missing, "\n  "), len(files), len(seen))
	}
}
