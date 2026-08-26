package web_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// notOperable are routes an operator is not expected to reach from the 5250
// console, each with the reason. A route may only be added here with one — the
// point of the list is that skipping a screen becomes a decision somebody wrote
// down rather than an omission nobody noticed.
var notOperable = map[string]string{
	// Browser-driven flows: the console is the thing being logged into, or the
	// browser follows the URL itself.
	"POST /api/login":                                 "the login screen posts this directly, before the console exists",
	"POST /api/logout":                                "the sign-off path, not a menu action",
	"GET /api/auth/oidc/start":                        "a browser redirect, followed by the browser",
	"GET /api/auth/oidc/callback":                     "the IdP redirects here; nothing calls it",
	"GET /api/auth/saml/start":                        "a browser redirect, followed by the browser",
	"GET /api/auth/saml/metadata":                     "fetched by the IdP, not by an operator",
	"POST /api/auth/saml/acs":                         "the IdP posts the assertion here",
	"GET /api/targets/{id}/rdp":                       "the RDP viewer opens this with its own token",
	"GET /api/targets/{id}/vnc":                       "the VNC viewer opens this with its own token",
	"GET /api/sessions/{id}/stream":                   "an EventSource stream, not an api() call",
	"GET /api/recordings/{name}":                      "the player fetches the artifact directly",
	"GET /api/audit/export":                           "a download link the browser follows",
	"GET /api/audit/ocsf":                             "a download link the browser follows",
	"GET /api/ca/ssh/krl":                             "a file an SSH server fetches, not a person",
	"POST /api/ca/ssh/challenge":                      "the ssh-cert client flow, driven by the CLI",
	"POST /api/ca/ssh/sign":                           "the ssh-cert client flow, driven by the CLI",
	"POST /api/rdp-token":                             "minted by the viewer as it opens",
	"POST /api/vnc-token":                             "minted by the viewer as it opens",
	"POST /api/targets/{id}/winrm":                    "a one-shot API for scripts; interactive WinRM is the proxy",
	"GET /api/targets/{id}":                           "the console lists targets and holds the row it needs",
	"GET /api/credentials":                            "reached through the target listing, which scopes it",
	"GET /api/checkouts":                              "menu 3 lists checkouts through its own loader",
	"GET /api/access-requests":                        "menu 5 lists requests through its own loader",
	"GET /api/vendors":                                "menu 22 lists vendors through its own loader",
	"GET /api/users":                                  "menu 8 lists users through its own loader",
	"GET /api/targets":                                "menu 1 lists targets through its own loader",
	"GET /api/vendors/{id}/evidence":                  "an evidence bundle an auditor exports, not a screen",
	"GET /api/access-requests/{id}/invites":           "the invite list is rendered from the request row",
	"POST /api/access-requests/{id}/invite":           "magic-link invites are issued from the request screen's own flow",
	"POST /api/approval-invites/{id}/revoke":          "same flow as issuing one",
	"PUT /api/campaigns/{id}/items/{itemID}/reviewer": "menu 17's assign-reviewer screen posts this",
	"POST /api/sessions/{id}/suspend":                 "menu 4's live-session view toggles this",
	"POST /api/sessions/{id}/resume":                  "menu 4's live-session view toggles this",
	"GET /v1/audit":                                   "the broker's own chain, exported rather than browsed",
	"GET /v1/audit/head":                              "the audit screen's F7 fetches this",
	"GET /v1/audit/verify":                            "the audit screen's F6 fetches this",
	"GET /v1/audit/jwks":                              "a verifying key an auditor fetches",
}

// operatorGuards are the capability guards a human operator can hold. A route
// behind one of these is, by definition, something a person is expected to do —
// which is what the console is for.
var operatorGuards = map[string]bool{
	"CapManageUsers": true, "CapManageTargets": true, "CapManageCredentials": true,
	"CapRevealSecret": true, "CapApprove": true, "CapReadAudit": true,
	"CapReadInventory": true, "CapConnect": true,
}

// consoleCalls reports whether the console builds a URL for this route.
//
// Matching the static PREFIX alone is not enough, and the first draft of this
// guard proved it: `/api/credentials/{id}/doublelock` shares its prefix with
// half the credential screen, so a route with no screen at all looked reachable.
// Every literal segment must appear, in order, separated only by what a
// template parameter can expand to — which is what distinguishes a sub-resource
// nobody calls from its parent that everybody does.
func consoleCalls(page, path string) bool {
	segments := regexp.MustCompile(`\{[^}]+\}`).Split(path, -1)
	var pattern strings.Builder
	for i, seg := range segments {
		if i > 0 {
			// A path parameter as the console writes it: `${c.id}`, `${k.id}`,
			// an inline number. Bounded so the match cannot wander across an
			// unrelated string literal.
			pattern.WriteString(`[^"` + "`" + `\s]{0,40}`)
		}
		pattern.WriteString(regexp.QuoteMeta(seg))
	}
	return regexp.MustCompile(pattern.String()).MatchString(page)
}

// TestConsoleCanReachEveryOperatorRoute pins the parity claim the README and the
// roadmap both make: "every shipped capability is operable from the portal".
//
// It was false when this test was written. DoubleLock (Phase 135), SCIM client
// keys (149) and the browser-extension token (147) had shipped with routes, an
// admin-guide curl command, and **no screen at all** — three capabilities an
// operator could only reach by leaving the product. Nobody noticed because
// nothing checked, which is the same reason the OCSF classification drifted
// (Phase 185) and the deploy examples fell behind (182).
//
// The rule: a route behind an operator capability must be called by the console,
// or be listed in notOperable WITH its reason.
func TestConsoleCanReachEveryOperatorRoute(t *testing.T) {
	diagrams := filepath.Join("..", "..", "docs", "ARCHITECTURE-DIAGRAMS.md")
	table, err := os.ReadFile(diagrams) // #nosec G304 -- test-only read of the repo's own generated docs
	if err != nil {
		t.Fatalf("reading the generated route table: %v", err)
	}
	console, err := os.ReadFile(filepath.Join("static", "index.html")) // #nosec G304 -- test-only
	if err != nil {
		t.Fatalf("reading the console: %v", err)
	}
	page := string(console)

	rowRE := regexp.MustCompile(`(?m)^\| (GET|POST|PUT|DELETE|PATCH) \| ` + "`" + `([^` + "`" + `]+)` + "`" + ` \| ([^|]+) \|$`)
	rows := rowRE.FindAllStringSubmatch(string(table), -1)
	if len(rows) < 100 {
		t.Fatalf("parsed only %d routes from %s — the table's shape changed and this guard is not looking at it",
			len(rows), diagrams)
	}

	var unreachable []string
	for _, r := range rows {
		method, path, guard := r[1], r[2], strings.TrimSpace(r[3])
		if !operatorGuards[guard] {
			continue // public, agent-bearer, token-in-query: not an operator action
		}
		key := method + " " + path
		if _, ok := notOperable[key]; ok {
			continue
		}
		if consoleCalls(page, path) {
			continue
		}
		unreachable = append(unreachable, key+"  ("+guard+")")
	}
	sort.Strings(unreachable)

	if len(unreachable) > 0 {
		t.Fatalf("%d operator route(s) the 5250 console cannot reach:\n  %s\n"+
			"PAMv1 claims every shipped capability is operable from the portal (README, ROADMAP), so each of "+
			"these is either a missing screen or a claim that needs narrowing. Add the screen, or add the "+
			"route to notOperable WITH the reason a person is not expected to use it.",
			len(unreachable), strings.Join(unreachable, "\n  "))
	}
}
