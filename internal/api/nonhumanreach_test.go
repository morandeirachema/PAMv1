package api_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every credential pamv1 issues to something that is not a person, and the exact
// set of routes a bearer of it reaches. Adding a route here WIDENS what one of
// these credentials can do, which is a decision worth writing down rather than a
// line somebody adds to server.go on the way past.
//
// The operator API is deliberately absent: those routes are gated per capability
// by auth.Capability, and TestConsoleCanReachEveryOperatorRoute already holds
// that surface to its own promise. What is listed below is the surface reachable
// WITHOUT a human principal at all.
var nonHumanReach = map[string]map[string]string{
	// An AI-agent credential: a pamv1-issued static key, or a SPIFFE-attested
	// SVID. Policy decides which TOOL a call may run; these routes are the
	// transport that carries it, so widening this set widens what every agent
	// in the deployment can address.
	"agent credential": {
		"POST /v1/tool-calls":             "submit a brokered tool call",
		"GET /v1/tool-calls/{id}":         "poll the call's own result",
		"POST /v1/tool-calls/{id}/resume": "resume a call parked for approval",
		"POST /v1/token":                  "exchange for a delegated, on-behalf-of token",
		"POST /mcp":                       "the MCP transport for the same broker",
		"GET /mcp":                        "the MCP SSE stream for the same broker",
	},
	// An IdP's SCIM client key. This surface CREATES AND DELETES USERS, which is
	// why it is worth a written list: a route added here is reachable by a
	// bearer token an IdP holds, with no pamv1 capability check anywhere.
	"SCIM client key": {
		"GET /scim/v2/ServiceProviderConfig": "SCIM discovery document",
		"GET /scim/v2/Users":                 "list provisioned users",
		"POST /scim/v2/Users":                "provision a user",
		"GET /scim/v2/Users/{id}":            "read one provisioned user",
		"PUT /scim/v2/Users/{id}":            "replace a provisioned user",
		"PATCH /scim/v2/Users/{id}":          "patch a provisioned user (SCIM active=false is the deprovision)",
		"DELETE /scim/v2/Users/{id}":         "deprovision a user",
	},
	// An application key (Phase 24): a thick app fetching one secret it has been
	// granted. One route by design — the whole point is that an app never gets
	// the operator API.
	"application key": {
		"GET /v1/app-secrets/{id}": "fetch one granted application secret",
	},
	// Guest links: a single-use token emailed to somebody with no pamv1 login,
	// for one session share or one approval decision.
	"token (single-use link)": {
		"GET /api/approval/preview/{token}": "show the decision the invite is for",
		"POST /api/approval/redeem/{token}": "record that decision",
		"POST /api/share/redeem/{token}":    "join the shared session the invite names",
		"GET /api/share/stream":             "the guest's view of that session",
		"POST /api/share/input":             "the guest's keystrokes into that session",
	},
	// The graphical viewers: a browser cannot set headers on a WebSocket
	// handshake, so these authenticate a short-lived token from the query string.
	"token (query)": {
		"GET /api/targets/{id}/rdp": "the in-portal RDP viewer's tunnel",
		"GET /api/targets/{id}/vnc": "the in-portal VNC viewer's tunnel",
	},
}

// routeTable reads the generated API surface — the same source
// TestConsoleCanReachEveryOperatorRoute uses, and accurate about guards since
// Phase 195 taught the generator to refuse to guess.
func routeTable(t *testing.T) [][]string {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "ARCHITECTURE-DIAGRAMS.md")
	table, err := os.ReadFile(path) // #nosec G304 -- test-only read of the repo's own generated docs
	if err != nil {
		t.Fatalf("reading the generated route table: %v", err)
	}
	rowRE := regexp.MustCompile(`(?m)^\| (GET|POST|PUT|DELETE|PATCH) \| ` + "`" + `([^` + "`" + `]+)` + "`" + ` \| ([^|]+) \|$`)
	rows := rowRE.FindAllStringSubmatch(string(table), -1)
	if len(rows) < 100 {
		t.Fatalf("parsed only %d routes from %s — the table's shape changed and this guard is not looking at it",
			len(rows), path)
	}
	return rows
}

// TestNonHumanCredentialReach holds each non-human credential to a written list
// of what it reaches.
//
// Phase 195 made the route table say WHICH scheme guards each route, after it had
// published sixteen authenticated routes as "public". This is the next question,
// and the one that actually bounds damage: given that a route is reachable by an
// agent key, an IdP's SCIM token or an app key, is that the set somebody
// intended? Those credentials pass no capability check — the middleware
// authenticates the bearer and hands off — so the route list IS the authorization
// boundary for them.
func TestNonHumanCredentialReach(t *testing.T) {
	var surprises []string
	for _, r := range routeTable(t) {
		method, path, guard := r[1], r[2], strings.TrimSpace(r[3])
		listed, tracked := nonHumanReach[guard]
		if !tracked {
			continue // a human capability, or a genuinely public route
		}
		key := method + " " + path
		if _, ok := listed[key]; !ok {
			surprises = append(surprises, key+"  ("+guard+")")
		}
	}
	sort.Strings(surprises)
	if len(surprises) > 0 {
		t.Fatalf("%d route(s) reachable by a non-human credential that nobody wrote down:\n  %s\n"+
			"These credentials pass no capability check — the middleware authenticates the bearer and "+
			"hands off — so this list is the authorization boundary for them. Add each route to "+
			"nonHumanReach with the reason it belongs there, or give it a capability instead.",
			len(surprises), strings.Join(surprises, "\n  "))
	}

	// And the reverse, so the list cannot rot into describing routes that no
	// longer exist — a stale allowlist reads as more scrutiny than it gives.
	live := map[string]bool{}
	for _, r := range routeTable(t) {
		live[r[1]+" "+r[2]] = true
	}
	for guard, listed := range nonHumanReach {
		for key, reason := range listed {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("nonHumanReach[%q][%q] has no reason recorded", guard, key)
			}
			if !live[key] {
				t.Errorf("nonHumanReach[%q] lists %q, which is not a route any more", guard, key)
			}
		}
	}
}

// TestExtensionTokenReachIsOneRoute pins a claim that was living in a trailing
// comment.
//
// server.go says of the reveal route: "browser-extension tokens (Phase 147) reach
// only this route". That is the entire scoping of a credential deliberately
// issued to a browser extension — a thing running in a page, on a machine pamv1
// does not control.
//
// TestExtensionTokenRefusedEverywhereElse already checks the BEHAVIOUR, and it is
// the stronger test of the two for what it covers: it mints a real token and
// watches five real routes refuse it. But it samples the complement, so a SIXTH
// route wrapped in authzExtOK would leave it passing and the comment quietly
// false. This one asserts the set instead of a sample — the two together are
// "these routes refuse it" plus "and there are no others".
func TestExtensionTokenReachIsOneRoute(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("server.go")) // #nosec G304 -- test-only read of this package's own source
	if err != nil {
		t.Fatalf("reading server.go: %v", err)
	}
	routeRE := regexp.MustCompile(`mux\.Handle(?:Func)?\("([A-Z]+ [^"]+)",\s*s\.authzExtOK\(`)
	var got []string
	for _, m := range routeRE.FindAllStringSubmatch(string(src), -1) {
		got = append(got, m[1])
	}
	sort.Strings(got)

	want := []string{"POST /api/credentials/{id}/reveal"}
	if len(got) != len(want) || (len(got) == 1 && got[0] != want[0]) {
		t.Fatalf("browser-extension tokens reach %v, want exactly %v\n"+
			"authzExtOK widens a route to a credential held by an extension running in a page on a "+
			"machine pamv1 does not control. If a second route genuinely needs it, change this test "+
			"deliberately and say why in the phase — do not let the scoping drift.", got, want)
	}
}

// TestNoMutatingRouteIsPublic is a fail-closed floor under the whole table: a
// request that CHANGES something must present something. Rate-limited pre-auth
// routes (login, the SSO callbacks, break-glass unseal) are the deliberate
// exception and carry their own label, which is why they read as
// "public (rate-limited)" rather than bare "public".
func TestNoMutatingRouteIsPublic(t *testing.T) {
	var bare []string
	for _, r := range routeTable(t) {
		if r[1] == "GET" || strings.TrimSpace(r[3]) != "public" {
			continue
		}
		bare = append(bare, r[1]+" "+r[2])
	}
	sort.Strings(bare)
	if len(bare) > 0 {
		t.Fatalf("%d mutating route(s) with no credential at all:\n  %s\n"+
			"A request that changes state must present something — a capability, a non-human "+
			"credential, a single-use token, or at minimum the rate-limited pre-auth wrapper.",
			len(bare), strings.Join(bare, "\n  "))
	}
}
