package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/morandeirachema/pamv1/internal/api"
)

// The tests in this file all check the same class of defect: a gate that every
// comparable path enforces, missing on one. None of them is about a clever
// attack — each is about an inconsistency, which is how this kind of bug
// survives review. A reviewer looking at one handler sees nothing wrong; the
// problem is only visible next to its siblings.

// auditContains reports whether the audit trail holds an event with the given
// action. Refusals that leave no durable trace are invisible to the risk engine
// and the SIEM forwarder, so "was it refused?" and "was the refusal recorded?"
// are two separate assertions.
func auditContains(t *testing.T, srv *httptest.Server, action string) bool {
	t.Helper()
	code, data := do(t, srv, http.MethodGet, "/api/audit?limit=200", testAPIKey, nil)
	if code != http.StatusOK {
		t.Fatalf("read audit: %d %s", code, data)
	}
	var events []map[string]any
	if err := json.Unmarshal(data, &events); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	for _, e := range events {
		if e["action"] == action {
			return true
		}
	}
	return false
}

// TestRDPTunnelAuthFailureIsThrottledAndAudited proves the RDP tunnel handles a
// bad bearer token exactly as every other bearer surface does.
//
// It resolves its own principal (a browser cannot set headers on a WebSocket
// handshake), which is why it drifted: it wrote a bare 401 instead of going
// through authFailed. That made it the ONE surface where token guessing was
// neither throttled nor recorded — invisible to the risk engine and the SIEM
// forwarder — while identical guessing against /api/* was both.
func TestRDPTunnelAuthFailureIsThrottledAndAudited(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{GuacdAddr: "127.0.0.1:1", AuthRatePerMin: 5})
	targetID := createTestTarget(t, srv, "win-gate", "10.0.0.20")

	url := fmt.Sprintf("/api/targets/%d/rdp?token=%s", targetID, "not-a-real-token")
	code, _ := do(t, srv, http.MethodGet, url, "", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("bad tunnel token: got %d, want 401", code)
	}
	if !auditContains(t, srv, "api.auth_failed") {
		t.Fatal("a failed RDP tunnel authentication left no api.auth_failed record; it is invisible to the risk engine and the SIEM forwarder")
	}

	// Past the per-IP budget the surface must throttle rather than keep
	// answering, so it cannot be used as an unmetered oracle.
	throttled := false
	for i := 0; i < 12; i++ {
		if code, _ := do(t, srv, http.MethodGet, url, "", nil); code == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Fatal("repeated RDP tunnel token guesses were never throttled; the surface is an unmetered oracle")
	}
}

// Step-up self-approval (finding L) is covered where it can actually be
// exercised: session.TestStepUpRefusesSelfApproval. Reaching it through the API
// would need a live paused session, and a test that cannot reach the branch it
// names is worse than no test — it reads like coverage.

// TestVendorCreateRefusesPrivilegeEscalation proves creating a vendor login
// applies the same escalation guard as creating any other user.
//
// The vendor's role is fixed at "user" rather than caller-chosen, which is
// exactly why the check was missed — but a fixed role is not the same as a safe
// one. A delegated user-admin whose own profile lacks the `user` role's
// capabilities could mint a vendor login that has them, and the token comes back
// in the response body.
func TestVendorCreateRefusesPrivilegeEscalation(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})

	// A profile that can manage users and nothing else — deliberately WITHOUT
	// the connect/read capabilities the built-in `user` role carries.
	code, data := do(t, srv, http.MethodPost, "/api/profiles", testAPIKey, map[string]any{
		"name": "user-admin-only", "caps": []string{"manage_users"},
	})
	if code != http.StatusCreated {
		t.Skipf("custom profiles unavailable in this build: %d %s", code, data)
	}
	limited := seedUser(t, srv, "limited-admin", "user-admin-only")

	code, body := do(t, srv, http.MethodPost, "/api/vendors", limited, map[string]any{
		"username": "acme-contractor", "org": "ACME",
	})
	if code != http.StatusForbidden {
		t.Fatalf("a user-admin without the user role's capabilities created a vendor login: got %d %s, want 403", code, body)
	}
	if strings.Contains(string(body), "token") {
		t.Fatal("the refused response carried a token")
	}

	// The unconstrained bootstrap admin must still be able to do it, or the
	// guard has simply broken the feature.
	if code, body := do(t, srv, http.MethodPost, "/api/vendors", testAPIKey, map[string]any{
		"username": "acme-ok", "org": "ACME",
	}); code != http.StatusCreated {
		t.Fatalf("admin vendor creation broke: %d %s", code, body)
	}
}

// TestWinRMRefusedWhenRecordingRequired proves PAM_REQUIRE_RECORDING now covers
// the REST WinRM endpoint.
//
// The flag shipped enforcing this for the SSH, WinRM and PostgreSQL proxies but
// not for the two paths that reach a target through the HTTP server. An operator
// who set it believed every session was recorded, and the two newest ways to
// reach a machine were the two it did not cover — a security control silently
// narrower than its name.
//
// The refusal must happen BEFORE the command runs: the transcript is written
// from the result, so a post-hoc check would report a failure the command had
// already caused on the target.
func TestWinRMRefusedWhenRecordingRequired(t *testing.T) {
	fake := &fakeWinRM{}
	srv, _ := newTestServerOpts(t, nil, api.Options{
		WinRM: fake, RequireRecording: true, RecordingDir: "", // required but impossible
	})
	_, tdata := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "win-rec", "host": "10.0.0.21", "port": 5985, "os_type": "windows", "protocol": "winrm",
	})
	targetID := int64(jsonMap(t, tdata)["id"].(float64))
	code, data := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": targetID, "username": "Administrator", "secret": secretPassword,
	})
	if code != http.StatusCreated {
		t.Fatalf("seed credential: %d %s", code, data)
	}

	code, body := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/winrm", targetID), testAPIKey,
		map[string]any{"command": "hostname"})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("WinRM with recording required but unconfigured: got %d %s, want 503", code, body)
	}
	if fake.gotCmd != "" {
		t.Fatal("the command ran on the target before the recording requirement was checked; refusing afterwards is not refusing")
	}
	if !auditContains(t, srv, "winrm.refused") {
		t.Fatal("the refusal left no audit record")
	}
}

// TestRDPRefusedWhenRecordingRequired is the RDP half of the same guarantee: the
// in-portal viewer must not open a privileged desktop that cannot be recorded.
func TestRDPRefusedWhenRecordingRequired(t *testing.T) {
	connectCh := make(chan []string, 1)
	inputCh := make(chan string, 1)
	guacdAddr := fakeGuacd(t, connectCh, inputCh)
	srv, _ := newTestServerOpts(t, nil, api.Options{
		GuacdAddr: guacdAddr, RequireRecording: true, GuacdRecordingPath: "", // required but impossible
	})

	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "win-rdp-rec", "host": "10.0.0.22", "port": 3389, "os_type": "windows", "protocol": "rdp",
	})
	id := int64(jsonMap(t, data)["id"].(float64))
	do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": id, "username": "Administrator", "secret": secretPassword,
	})
	_, tokData := do(t, srv, http.MethodPost, "/api/rdp-token", testAPIKey, nil)
	tok, _ := jsonMap(t, tokData)["token"].(string)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/targets/" + itoa(id) + "/rdp?token=" + tok
	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	if err == nil {
		c.Close(websocket.StatusNormalClosure, "")
		t.Fatal("the RDP tunnel opened even though recording is required and unconfigured")
	}
	if !auditContains(t, srv, "rdp.refused") {
		t.Fatal("the RDP refusal left no audit record")
	}
	select {
	case <-connectCh:
		t.Fatal("guacd was contacted before the recording requirement was checked")
	default:
	}
}
