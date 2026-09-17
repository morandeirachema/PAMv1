package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestBrowserTerminalWithSessionMFAKeepsTheBrowserAddress proves the portal
// terminal to a target that demands a session-MFA ticket is still a TERMINAL
// session to the proxy: registered under the browser's address, and gated on
// the user's IP allowlist against that address. The API used to send the
// ticket ALONE as the SSH password, so the proxy resolved a ticket principal,
// never learned it was the terminal, recorded 127.0.0.1 — and evaluated an
// allowlisted user against loopback, refusing them on every such target.
func TestBrowserTerminalWithSessionMFAKeepsTheBrowserAddress(t *testing.T) {
	env := newTermEnv(t, api.Options{TrustedProxyHops: 1})
	ctx := context.Background()
	env.tgt.RequireSessionMFA = true
	if err := env.st.UpdateTarget(ctx, env.tgt); err != nil {
		t.Fatal(err)
	}
	aliceID, aliceTok := seedUserWithID(t, env.srv, "alice", "user")
	if code, d := do(t, env.srv, http.MethodPut, "/api/users/"+itoa(aliceID), testAPIKey, map[string]any{"role": "user", "ip_allowlist": "203.0.113.0/24, 127.0.0.0/8"}); code != http.StatusOK {
		t.Fatalf("allowlist: %d %s", code, d)
	}
	code, d := do(t, env.srv, http.MethodPost, "/api/ssh-token", aliceTok, map[string]any{"target_id": env.tgt.ID})
	if code != http.StatusOK || jsonMap(t, d)["session_mfa_required"] != true {
		t.Fatalf("mint: %d %s", code, d)
	}
	tok := jsonMap(t, d)["token"].(string)
	// The ticket a fresh factor would have minted, placed directly.
	const ticket = "ticket-for-web-01"
	if err := env.st.CreateSession(ctx, &store.Session{Username: "alice", Role: "user", Scope: auth.SessionScopeSessionMFA,
		TokenHash: auth.TokenHash(ticket), ExpiresAt: time.Now().Add(2 * time.Minute), TargetID: &env.tgt.ID}); err != nil {
		t.Fatal(err)
	}
	// Narrow the allowlist to the BROWSER's network only: a session judged
	// against loopback is now refused.
	if code, d := do(t, env.srv, http.MethodPut, "/api/users/"+itoa(aliceID), testAPIKey, map[string]any{"role": "user", "ip_allowlist": "203.0.113.0/24"}); code != http.StatusOK {
		t.Fatalf("allowlist: %d %s", code, d)
	}

	wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(wctx, env.wsURL(env.tgt.ID, "token="+tok+"&ticket="+ticket+"&cols=80&rows=24"), &websocket.DialOptions{
		Subprotocols: []string{"pamv1-terminal"}, HTTPHeader: http.Header{"X-Forwarded-For": {"203.0.113.9"}},
	})
	if err != nil {
		t.Fatalf("open terminal: %v", err)
	}
	defer ws.Close(websocket.StatusNormalClosure, "")
	readUntil(t, ws, strings.TrimSpace(termBanner), 30*time.Second)
	var remote string
	for _, s := range env.reg.List() {
		if s.Actor == "alice" {
			remote = s.Remote
		}
	}
	// Let the proxy finish its recording before the temp dir goes away.
	ws.Close(websocket.StatusNormalClosure, "")
	if !waitAudit(env.st, "session.end", "target:web-01", 30*time.Second) {
		t.Fatal("the proxy never audited session.end")
	}
	for deadline := time.Now().Add(10 * time.Second); len(env.reg.List()) > 0 && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.HasPrefix(remote, "203.0.113.9") {
		t.Fatalf("session remote = %q, want the browser's address", remote)
	}
	auditHas(t, env.st, "session.mfa_verified", "target:web-01")
}
