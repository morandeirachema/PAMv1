package main

import (
	"strings"
	"testing"
)

// TestArchgenProducesDiagrams runs the three generators against the real module
// and checks each emits its diagram with content derived from the current code
// (a package node, an ER relationship, a known route). This guards the generator
// itself; CI separately fails if the committed doc is stale.
func TestArchgenProducesDiagrams(t *testing.T) {
	root, module, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := writePackageGraph(&b, root, module); err != nil {
		t.Fatal(err)
	}
	if err := writeDataModel(&b, root); err != nil {
		t.Fatal(err)
	}
	if err := writeRouteMap(&b, root); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"flowchart LR",
		"n_api[api]",
		"n_proxy --> n_vault", // proxy decrypts JIT via vault
		"erDiagram",
		"Credential ||--o{ Checkout", // inferred FK relationship
		"| GET | `/api/me` |",        // route map picked up the new endpoint
	} {
		if !strings.Contains(out, want) {
			t.Errorf("generated architecture output is missing %q", want)
		}
	}
}

// TestRouteGuardRefusesToGuess is the point of the classifier, not a detail of
// it. It used to fall back to "public" for any registration it could not place,
// and three schemes added to the mux after it was written — agentAuth, scimAuth,
// appAuth — were published in the security map as unauthenticated: the whole
// AI-agent tool-call surface, and the whole SCIM surface, which creates and
// deletes users. The routes were protected the entire time; the document said
// they were not. A fail-open default in the one file whose job is to say what
// guards each route is worth a test that will not let it come back.
func TestRouteGuardRefusesToGuess(t *testing.T) {
	for _, tc := range []struct {
		name, registration, want string
	}{
		{"capability", `s.authz(auth.CapReadAudit, s.subjectReach))`, "CapReadAudit"},
		{"capability via the extension variant", `s.authzExtOK(auth.CapRevealSecret, s.revealCredential))`, "CapRevealSecret"},
		{"session login", `s.authenticated(s.me))`, "authenticated"},
		{"agent broker", `s.agentAuth(s.processToolCall))`, "agent credential"},
		{"scim client", `s.scimAuth(s.scimListUsers))`, "SCIM client key"},
		{"application key", `s.appAuth(s.fetchAppSecret))`, "application key"},
		{"pre-auth, rate limited", `s.rateLimit(s.login))`, "public (rate-limited)"},
		{"websocket query token", `s.rdpTunnel)`, "token (query)"},
		{"guest magic link", `s.redeemShareInvite)`, "token (single-use link)"},
		// The nested case: rateLimit is a MODIFIER and must not swallow what it
		// wraps. It used to, and both WebAuthn login routes were published as
		// "public (rate-limited)" while mfaPendingOnly was checking a credential.
		{"a scheme wrapped in the throttle", `s.rateLimit(s.mfaPendingOnly(s.webauthnLoginBegin)))`, "MFA-pending token (rate-limited)"},
		{"a capability wrapped in the throttle", `s.rateLimit(s.authz(auth.CapReadAudit, s.x)))`, "CapReadAudit (rate-limited)"},
		{"throttled pre-auth with nothing inside", `s.rateLimit(s.login))`, "public (rate-limited)"},
	} {
		got, err := routeGuard("POST", "/api/whatever", tc.registration)
		if err != nil {
			t.Errorf("%s: routeGuard returned an error: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: guard = %q, want %q", tc.name, got, tc.want)
		}
	}

	// A route that carries no credential must SAY so, by name, with a reason.
	if got, err := routeGuard("GET", "/healthz", "s.health)"); err != nil || got != "public" {
		t.Errorf(`allowlisted route: guard = %q, err = %v; want "public", nil`, got, err)
	}

	// And anything else stops the generator. CI runs the generator, so this is
	// what turns "somebody added a route with a new wrapper" into a failed build
	// rather than a line in the security map that quietly reads "public".
	if _, err := routeGuard("GET", "/api/brand-new", "s.somethingNobodyTaughtUsAbout)"); err == nil {
		t.Fatal("an unrecognised wrapper must be an error, not a default of \"public\"")
	}

	// Every allowlisted route must carry a non-empty reason: the list is the
	// place a person justifies "no credential", so an empty string defeats it.
	for route, reason := range publicRoutes {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("publicRoutes[%q] has no reason recorded", route)
		}
	}
}
