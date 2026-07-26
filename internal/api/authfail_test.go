package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/store"
)

// countAuthFailures returns the api.auth_failed events recorded for one surface,
// and fails the test if any of them carries the presented credential.
func countAuthFailures(t *testing.T, st store.Store, surface, presented string) int {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Action != "api.auth_failed" || !strings.Contains(e.Detail, "surface:"+surface) {
			continue
		}
		if strings.Contains(e.Detail, presented) {
			t.Fatalf("audit detail leaked the presented credential: %s", e.Detail)
		}
		n++
	}
	return n
}

// TestAPIKeyFailureThrottledAndAudited proves a wrong X-API-Key is both throttled
// per source IP and written to the audit trail. Before this the REST surface only
// logged the failure, so guessing a per-user token (or the bootstrap key) was an
// unthrottled online oracle that the risk engine and the SIEM forwarder — both fed
// from the audit trail — never saw.
func TestAPIKeyFailureThrottledAndAudited(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{AuthRatePerMin: 3})
	const bad = "not-a-real-api-key"

	for i := 0; i < 3; i++ {
		if code, body := do(t, srv, http.MethodGet, "/api/targets", bad, nil); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d body %s, want 401", i+1, code, body)
		}
	}
	if code, body := do(t, srv, http.MethodGet, "/api/targets", bad, nil); code != http.StatusTooManyRequests {
		t.Fatalf("attempt 4: status %d body %s, want 429", code, body)
	}

	// The three admitted attempts are auditable; the throttled one deliberately
	// writes nothing, so a flood cannot amplify into the audit trail.
	if n := countAuthFailures(t, st, "api", bad); n != 3 {
		t.Fatalf("api.auth_failed events = %d, want 3", n)
	}

	// A valid key is unaffected by another identity's failures on the same IP.
	if code, _ := do(t, srv, http.MethodGet, "/api/targets", testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("valid key after failures: status %d, want 200", code)
	}
}

// TestAppKeyFailureThrottledAndAudited proves the application-secrets surface —
// the one path that hands plaintext secrets to machines — throttles and records a
// guessed application token.
func TestAppKeyFailureThrottledAndAudited(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{AppSecretsEnabled: true, AuthRatePerMin: 2})
	const bad = "not-a-real-app-token"

	for i := 0; i < 2; i++ {
		if code, body := appGet(t, srv, "/v1/app-secrets/1", bad); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d body %s, want 401", i+1, code, body)
		}
	}
	if code, body := appGet(t, srv, "/v1/app-secrets/1", bad); code != http.StatusTooManyRequests {
		t.Fatalf("attempt 3: status %d body %s, want 429", code, body)
	}
	if n := countAuthFailures(t, st, "app", bad); n != 2 {
		t.Fatalf("app auth_failed events = %d, want 2", n)
	}
}

// TestAgentKeyFailureThrottledAndAudited proves the same for the AI-agent broker:
// the per-agent tool-call limiter only applies AFTER a key resolves, so a rejected
// agent credential was previously neither throttled nor recorded.
func TestAgentKeyFailureThrottledAndAudited(t *testing.T) {
	opts := brokerOpts(t, &fakeWinRM{}, brokerRules)
	opts.AuthRatePerMin = 2
	srv, st := newTestServerOpts(t, nil, opts)
	const bad = "not-a-real-agent-token"

	call := map[string]any{"tool": "list_targets", "arguments": map[string]any{}}
	for i := 0; i < 2; i++ {
		if code, body := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", bad, call); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d body %s, want 401", i+1, code, body)
		}
	}
	if code, body := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", bad, call); code != http.StatusTooManyRequests {
		t.Fatalf("attempt 3: status %d body %s, want 429", code, body)
	}
	if n := countAuthFailures(t, st, "agent", bad); n != 2 {
		t.Fatalf("agent auth_failed events = %d, want 2", n)
	}
}
