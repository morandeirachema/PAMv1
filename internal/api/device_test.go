package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/oncall"
	"github.com/morandeirachema/pamv1/internal/posture"
)

// TestCreateUserWithDeviceFingerprint proves POST /api/users accepts and
// persists a device_fingerprint, rejects an oversized one, and that a fresh
// user with none stays unbound (Phase 133).
func TestCreateUserWithDeviceFingerprint(t *testing.T) {
	srv := newTestServer(t)

	code, data := do(t, srv, http.MethodPost, "/api/users", testAPIKey,
		map[string]any{"username": "alice", "role": "user", "device_fingerprint": "aa:bb:cc:dd"})
	if code != http.StatusCreated {
		t.Fatalf("create with fingerprint: %d %s", code, data)
	}
	if got := jsonMap(t, data)["device_fingerprint"]; got != "aa:bb:cc:dd" {
		t.Fatalf("device_fingerprint in response = %v", got)
	}

	if code, d := do(t, srv, http.MethodPost, "/api/users", testAPIKey,
		map[string]any{"username": "bob", "role": "user", "device_fingerprint": strings.Repeat("a", 300)}); code != http.StatusUnprocessableEntity {
		t.Fatalf("create with oversized fingerprint: %d %s, want 422", code, d)
	}

	code, data = do(t, srv, http.MethodPost, "/api/users", testAPIKey,
		map[string]any{"username": "carol", "role": "user"})
	if code != http.StatusCreated {
		t.Fatalf("create without fingerprint: %d %s", code, data)
	}
	if got, ok := jsonMap(t, data)["device_fingerprint"]; ok && got != "" {
		t.Fatalf("device_fingerprint for a user who never set one = %v, want empty/absent", got)
	}
}

// TestUpdateUserDeviceFingerprintOmitVsClear mirrors
// TestUpdateUserIPAllowlistOmitVsClear: omitting device_fingerprint from a
// PUT leaves it untouched; explicitly sending "" clears it (Phase 133).
func TestUpdateUserDeviceFingerprintOmitVsClear(t *testing.T) {
	srv := newTestServer(t)
	_, data := do(t, srv, http.MethodPost, "/api/users", testAPIKey,
		map[string]any{"username": "alice", "role": "user", "device_fingerprint": "aa:bb:cc:dd"})
	id := int64(jsonMap(t, data)["id"].(float64))
	path := "/api/users/" + itoa(id)

	if code, d := do(t, srv, http.MethodPut, path, testAPIKey, map[string]any{"role": "auditor"}); code != http.StatusOK {
		t.Fatalf("role-only update: %d %s", code, d)
	}
	code, data := do(t, srv, http.MethodGet, "/api/users", testAPIKey, nil)
	if code != http.StatusOK || !strings.Contains(string(data), "aa:bb:cc:dd") {
		t.Fatalf("fingerprint should survive a role-only update: %d %s", code, data)
	}

	if code, d := do(t, srv, http.MethodPut, path, testAPIKey,
		map[string]any{"role": "auditor", "device_fingerprint": ""}); code != http.StatusOK {
		t.Fatalf("explicit clear: %d %s", code, d)
	}
	code, data = do(t, srv, http.MethodGet, "/api/users", testAPIKey, nil)
	if code != http.StatusOK || strings.Contains(string(data), "aa:bb:cc:dd") {
		t.Fatalf("fingerprint should be cleared: %d %s", code, data)
	}
}

// TestAuthzRefusesDeviceMismatch proves the shared authz middleware enforces
// a principal's enrolled device fingerprint against PAM_DEVICE_HEADER's
// value on every authenticated request (Phase 133), and that break-glass
// bypasses it.
func TestAuthzRefusesDeviceMismatch(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{DeviceHeader: "X-Client-Cert-Fingerprint"})
	_, data := do(t, srv, http.MethodPost, "/api/users", testAPIKey,
		map[string]any{"username": "alice", "role": "user", "device_fingerprint": "aa:bb:cc:dd"})
	tok := jsonMap(t, data)["token"].(string)

	get := func(fp string) int {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/targets", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-API-Key", tok)
		if fp != "" {
			req.Header.Set("X-Client-Cert-Fingerprint", fp)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(""); code != http.StatusForbidden {
		t.Fatalf("request with no device header: %d, want 403", code)
	}
	if code := get("wrong-fingerprint"); code != http.StatusForbidden {
		t.Fatalf("request with a mismatched device header: %d, want 403", code)
	}
	if code := get("aa:bb:cc:dd"); code != http.StatusOK {
		t.Fatalf("request with the enrolled device header: %d, want 200", code)
	}

	events, err := st.ListAudit(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "authz.denied" && strings.Contains(e.Detail, "reason:device-not-trusted") {
			found = true
		}
	}
	if !found {
		t.Fatal("no authz.denied reason:device-not-trusted audit event")
	}
}

// TestAuthzUnaffectedWithoutDeviceHeaderConfigured proves an enrolled
// fingerprint has no effect at all when PAM_DEVICE_HEADER is unset — the
// mechanism-off default (Phase 133).
func TestAuthzUnaffectedWithoutDeviceHeaderConfigured(t *testing.T) {
	srv := newTestServer(t)
	_, data := do(t, srv, http.MethodPost, "/api/users", testAPIKey,
		map[string]any{"username": "alice", "role": "user", "device_fingerprint": "aa:bb:cc:dd"})
	tok := jsonMap(t, data)["token"].(string)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/targets", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("request with an enrolled fingerprint but no PAM_DEVICE_HEADER: %d, want 200", resp.StatusCode)
	}
}

// TestAuthzRefusesFailedPosture proves the shared authz middleware checks
// live device posture on every authenticated request when a PostureAttestor
// is configured (Phase 133), and that break-glass bypasses it.
func TestAuthzRefusesFailedPosture(t *testing.T) {
	var healthy atomic.Bool
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if healthy.Load() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer webhook.Close()

	srv, st := newTestServerOpts(t, nil, api.Options{PostureAttestor: posture.NewAttestor(webhook.URL)})
	// Posture must pass to create the user in the first place — the gate
	// applies to every authenticated call, including this setup step.
	healthy.Store(true)
	_, data := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "alice", "role": "user"})
	tok := jsonMap(t, data)["token"].(string)
	healthy.Store(false)

	get := func(key string) int {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/targets", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-API-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(tok); code != http.StatusForbidden {
		t.Fatalf("request while posture fails: %d, want 403", code)
	}
	healthy.Store(true)
	if code := get(tok); code != http.StatusOK {
		t.Fatalf("request once posture passes: %d, want 200", code)
	}

	events, err := st.ListAudit(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "authz.denied" && strings.Contains(e.Detail, "reason:posture-check-failed") {
			found = true
		}
	}
	if !found {
		t.Fatal("no authz.denied reason:posture-check-failed audit event")
	}

	// Break-glass bypasses the posture gate, matching every other gate it
	// already bypasses — proven against the SAME still-unhealthy webhook.
	healthy.Store(false)
	if code := get(breakGlassKey); code != http.StatusOK {
		t.Fatalf("break-glass request while posture fails: %d, want 200 (break-glass bypasses)", code)
	}
}

// TestAuthzRefusesFailedOnCall proves the shared authz middleware checks
// live on-call status on every authenticated request when an OnCallAttestor
// is configured (Phase 232), and that break-glass bypasses it — the same
// shape TestAuthzRefusesFailedPosture proves for the posture gate this one
// is modeled on.
func TestAuthzRefusesFailedOnCall(t *testing.T) {
	var onCall atomic.Bool
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if onCall.Load() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer webhook.Close()

	srv, st := newTestServerOpts(t, nil, api.Options{OnCallAttestor: oncall.NewAttestor(webhook.URL)})
	// On-call must pass to create the user in the first place — the gate
	// applies to every authenticated call, including this setup step.
	onCall.Store(true)
	_, data := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "bob", "role": "user"})
	tok := jsonMap(t, data)["token"].(string)
	onCall.Store(false)

	get := func(key string) int {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/targets", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-API-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(tok); code != http.StatusForbidden {
		t.Fatalf("request while not on call: %d, want 403", code)
	}
	onCall.Store(true)
	if code := get(tok); code != http.StatusOK {
		t.Fatalf("request once on call: %d, want 200", code)
	}

	events, err := st.ListAudit(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "authz.denied" && strings.Contains(e.Detail, "reason:oncall-check-failed") {
			found = true
		}
	}
	if !found {
		t.Fatal("no authz.denied reason:oncall-check-failed audit event")
	}

	// Break-glass bypasses the on-call gate, matching every other gate it
	// already bypasses — proven against the SAME still-refusing webhook.
	onCall.Store(false)
	if code := get(breakGlassKey); code != http.StatusOK {
		t.Fatalf("break-glass request while not on call: %d, want 200 (break-glass bypasses)", code)
	}
}
