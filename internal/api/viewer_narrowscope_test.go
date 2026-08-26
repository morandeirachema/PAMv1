package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestViewerTunnelRefusesNarrowScopes is the regression test for the 2026-08-26
// audit's findings H-1 and H-2 at the surface where they were worst.
//
// viewerTunnel resolves its own principal from ?token= and, until this test, it
// checked EnrollOnly and nothing else. Two tokens the API middleware and every
// proxy refused therefore opened a live desktop here:
//
//   - an mfa_pending session — password verified, WebAuthn NOT yet verified —
//     bypassing the second factor entirely (the existing ceremony test asserts
//     "refused everywhere" while checking only /api/me);
//   - a browser-extension token, documented as unable to "do anything but
//     reveal", carrying the minting admin's full role for 24 hours.
//
// This path ends in a decrypted credential inside a Windows session, which is
// why it must not be the one door with a shorter checklist than the rest. The
// scope test now has a single implementation, and each case here asserts both
// the refusal AND its distinct audit reason — a refusal that leaves no trace
// would be the next audit's finding.
func TestViewerTunnelRefusesNarrowScopes(t *testing.T) {
	connectCh := make(chan []string, 1)
	inputCh := make(chan string, 1)
	guacdAddr := fakeGuacd(t, connectCh, inputCh)
	srv, st := newTestServerOpts(t, nil, api.Options{GuacdAddr: guacdAddr})

	_, data := do(t, srv, "POST", "/api/targets", testAPIKey, map[string]any{
		"name": "win-rdp", "host": "10.0.0.9", "port": 3389, "os_type": "windows", "protocol": "rdp",
	})
	id := int64(jsonMap(t, data)["id"].(float64))
	do(t, srv, "POST", "/api/credentials", testAPIKey, map[string]any{
		"target_id": id, "username": "Administrator", "secret": "Rdp-S3cret!",
	})

	seed := func(scope string) string {
		token := "scoped-" + scope + "-9a2f"
		sum := sha256.Sum256([]byte(token))
		if err := st.CreateSession(context.Background(), &store.Session{
			Username: "alice", Role: "admin", Scope: scope,
			TokenHash: hex.EncodeToString(sum[:]), ExpiresAt: time.Now().Add(time.Hour).UTC(),
		}); err != nil {
			t.Fatal(err)
		}
		return token
	}

	for _, tc := range []struct {
		name, scope, wantReason string
	}{
		{"mfa_pending token", auth.SessionScopeMFAPending, "reason:mfa-webauthn-pending"},
		{"extension token", auth.SessionScopeExtension, "reason:extension-scoped-token"},
		{"enroll-only token", auth.SessionScopeEnroll, "reason:mfa-enrollment-incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := seed(tc.scope)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/targets/" + itoa(id) + "/rdp?token=" + tok
			c, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
			if err == nil {
				c.Close(websocket.StatusNormalClosure, "")
				t.Fatalf("a %s opened the RDP tunnel", tc.name)
			}
			if resp == nil || resp.StatusCode != http.StatusForbidden {
				code := 0
				if resp != nil {
					code = resp.StatusCode
				}
				t.Fatalf("a %s was refused with %d, want 403", tc.name, code)
			}
			select {
			case <-connectCh:
				t.Fatalf("a %s reached guacd: the refusal happened AFTER the credential was decrypted", tc.name)
			default:
			}
			events, err := st.ListAudit(context.Background(), 50)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, e := range events {
				if e.Action == "authz.denied" && strings.Contains(e.Detail, tc.wantReason) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("no authz.denied … %s was recorded for the %s", tc.wantReason, tc.name)
			}
		})
	}

	// And the control: the token the tunnel is FOR still works, so the fix
	// narrowed the door without closing it.
	status, data := do(t, srv, "POST", "/api/rdp-token", testAPIKey, nil)
	if status != 200 {
		t.Fatalf("rdp-token: %d %s", status, data)
	}
	tok, _ := jsonMap(t, data)["token"].(string)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/targets/" + itoa(id) + "/rdp?token=" + tok + "&width=800&height=600"
	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatalf("the legitimate tunnel token was refused after the fix: %v", err)
	}
	c.Close(websocket.StatusNormalClosure, "")
}
