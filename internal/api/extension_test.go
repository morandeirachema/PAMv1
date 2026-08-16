package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
)

// TestExtensionTokenMintRequiresRevealSecret proves a principal without
// CapRevealSecret cannot mint a browser-extension token at all — the mint
// gate, not just the reveal-route gate, refuses it (Phase 147).
func TestExtensionTokenMintRequiresRevealSecret(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})
	_, ud := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "plain-user", "role": "user"})
	userTok, _ := jsonMap(t, ud)["token"].(string)
	if userTok == "" {
		t.Fatal("expected a token back from user creation")
	}
	if code, data := do(t, srv, http.MethodPost, "/api/extension-token", userTok, nil); code != http.StatusForbidden {
		t.Fatalf("plain user minting an extension token: got %d, want 403: %s", code, data)
	}
}

// TestExtensionTokenRevealRoundTrip proves the whole Phase 147 flow end to
// end: mint a token as an admin (who holds CapRevealSecret), use ONLY that
// token to reveal a credential, get back the exact secret that was vaulted,
// and confirm the audit trail marks the reveal as having come via the
// extension.
func TestExtensionTokenRevealRoundTrip(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{ExtensionTokenTTL: time.Hour})
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "t-ext", "host": "h", "os_type": "linux", "protocol": "ssh",
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	_, cd := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "root", "secret": secretPassword,
	})
	cid := int64(jsonMap(t, cd)["id"].(float64))

	code, data := do(t, srv, http.MethodPost, "/api/extension-token", testAPIKey, nil)
	if code != http.StatusOK {
		t.Fatalf("mint extension token: %d %s", code, data)
	}
	extTok, _ := jsonMap(t, data)["token"].(string)
	if extTok == "" {
		t.Fatal("expected a token back from minting")
	}

	code, data = do(t, srv, http.MethodPost, "/api/credentials/"+itoa(cid)+"/reveal", extTok, nil)
	if code != http.StatusOK {
		t.Fatalf("reveal via extension token: %d %s", code, data)
	}
	if got := jsonMap(t, data)["secret"]; got != secretPassword {
		t.Fatalf("revealed secret = %v, want %q", got, secretPassword)
	}

	events, err := st.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	sawExtensionReveal := false
	for _, e := range events {
		if e.Action == "credential.reveal" && strings.Contains(e.Detail, "via:extension") {
			sawExtensionReveal = true
		}
	}
	if !sawExtensionReveal {
		t.Fatal("reveal via an extension token should be marked via:extension in the audit trail")
	}
}

// TestExtensionTokenRefusedEverywhereElse is the load-bearing security proof
// of Phase 147: a minted extension token can do exactly one thing — reveal —
// and is refused everywhere else, exactly like a leaked RDP-tunnel token.
func TestExtensionTokenRefusedEverywhereElse(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{ExtensionTokenTTL: time.Hour})
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "t-ext-scope", "host": "h", "os_type": "linux", "protocol": "ssh",
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "root", "secret": secretPassword,
	})

	_, data := do(t, srv, http.MethodPost, "/api/extension-token", testAPIKey, nil)
	extTok, _ := jsonMap(t, data)["token"].(string)
	if extTok == "" {
		t.Fatal("expected a token back from minting")
	}

	cases := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/credentials?target_id=" + itoa(tid)}, // list — not the reveal route
		{http.MethodGet, "/api/targets"},                            // an ordinary authz(cap, ...) route
		{http.MethodPost, "/api/rdp-token"},                         // a different token-minting route
		{http.MethodPost, "/api/extension-token"},                   // cannot re-mint itself
		{http.MethodGet, "/api/me"},                                 // an authenticated(...)-only route
	}
	for _, c := range cases {
		if code, respData := do(t, srv, c.method, c.path, extTok, nil); code != http.StatusForbidden {
			t.Fatalf("%s %s with an extension token: got %d, want 403: %s", c.method, c.path, code, respData)
		}
	}
}

// TestExtensionTokenDoesNotBreakNormalReveal is a regression guard on the
// authzExtOK refactor: a normal, non-extension reveal-capable principal must
// keep working on the reveal route exactly as before.
func TestExtensionTokenDoesNotBreakNormalReveal(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "t-ext-normal", "host": "h", "os_type": "linux", "protocol": "ssh",
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	_, cd := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "root", "secret": secretPassword,
	})
	cid := int64(jsonMap(t, cd)["id"].(float64))

	code, data := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(cid)+"/reveal", testAPIKey, nil)
	if code != http.StatusOK || jsonMap(t, data)["secret"] != secretPassword {
		t.Fatalf("normal reveal: %d %s", code, data)
	}
}
