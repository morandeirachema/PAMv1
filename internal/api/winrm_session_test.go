package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// blockingWinRM parks in Run until the caller's context is cancelled (or the test
// releases it), so a WinRM run can be observed while it is still in flight.
type blockingWinRM struct {
	started chan struct{} // closed on the first Run
	release chan struct{} // close to let Run return normally
	gotPass string
}

// Run signals that it started, then waits for cancellation or release.
func (b *blockingWinRM) Run(ctx context.Context, _ string, _ int, _, password, _ string) (winrm.Result, error) {
	b.gotPass = password
	select {
	case <-b.started:
	default:
		close(b.started)
	}
	select {
	case <-ctx.Done():
		return winrm.Result{}, ctx.Err()
	case <-b.release:
		return winrm.Result{Stdout: "done", ExitCode: 0}, nil
	}
}

// TestWinRMRunIsASupervisedSession proves the REST WinRM endpoint now behaves like
// every other brokered session: it is capped before the credential is decrypted,
// it appears in GET /api/sessions while it runs, and a kill terminates it. Before
// Phase 40 the run was invisible to the registry, so it could not be listed,
// killed, counted against PAM_MAX_SESSIONS_*, or reached by the analytics
// auto-response and the vendor sweeper, which both terminate by actor.
func TestWinRMRunIsASupervisedSession(t *testing.T) {
	fake := &blockingWinRM{started: make(chan struct{}), release: make(chan struct{})}
	reg := session.NewRegistry()
	reg.SetLimits(1, 0) // one concurrent session per actor
	srv, _ := newTestServerOpts(t, nil, api.Options{
		WinRM: fake, RecordingDir: t.TempDir(), Sessions: reg,
	})

	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "win-sess", "host": "10.0.0.7", "port": 5986, "os_type": "windows", "protocol": "winrm",
	})
	targetID := int64(jsonMap(t, td)["id"].(float64))
	if code, body := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": targetID, "username": "Administrator", "secret": "vaulted-pw",
	}); code != http.StatusCreated {
		t.Fatalf("seed credential: %d %s", code, body)
	}
	runURL := fmt.Sprintf("/api/targets/%d/winrm", targetID)

	// Start a run that will park inside the WinRM client.
	type result struct {
		code int
		body []byte
	}
	done := make(chan result, 1)
	go func() {
		code, body := do(t, srv, http.MethodPost, runURL, testAPIKey, map[string]any{"command": "sleep"})
		done <- result{code, body}
	}()

	select {
	case <-fake.started:
	case <-time.After(3 * time.Second):
		t.Fatal("the WinRM run never reached the runner")
	}

	// It is listed as a live session with the winrm protocol.
	var live []map[string]any
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, ld := do(t, srv, http.MethodGet, "/api/sessions", testAPIKey, nil)
		if err := json.Unmarshal(ld, &live); err != nil {
			t.Fatalf("decode sessions: %v (%s)", err, ld)
		}
		if len(live) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(live) != 1 {
		t.Fatalf("live sessions = %d, want 1 (the WinRM run must be registered)", len(live))
	}
	if live[0]["protocol"] != "winrm" || live[0]["target"] != "win-sess" {
		t.Fatalf("unexpected session entry: %+v", live[0])
	}
	sid, _ := live[0]["id"].(string)

	// The per-actor cap now applies to WinRM too — a second run is refused before
	// anything is decrypted.
	if code, body := do(t, srv, http.MethodPost, runURL, testAPIKey,
		map[string]any{"command": "whoami"}); code != http.StatusTooManyRequests {
		t.Fatalf("second concurrent run: status %d body %s, want 429", code, body)
	}

	// A kill terminates the in-flight run.
	if code, body := do(t, srv, http.MethodDelete, "/api/sessions/"+sid, testAPIKey, nil); code != http.StatusNoContent {
		t.Fatalf("kill session: status %d body %s, want 204", code, body)
	}
	select {
	case got := <-done:
		if got.code != http.StatusServiceUnavailable {
			t.Fatalf("killed run returned %d %s, want 503", got.code, got.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the killed WinRM run did not return")
	}

	// The registry is empty again, so the cap frees up.
	_, ld := do(t, srv, http.MethodGet, "/api/sessions", testAPIKey, nil)
	if err := json.Unmarshal(ld, &live); err != nil {
		t.Fatal(err)
	}
	if len(live) != 0 {
		t.Fatalf("sessions after the run ended = %d, want 0", len(live))
	}

	// JIT injection still holds: the runner received the vaulted secret.
	if fake.gotPass != "vaulted-pw" {
		t.Fatalf("runner got password %q, want vaulted-pw", fake.gotPass)
	}
}

// TestWinRMRunStreamsLive proves the REST WinRM run reaches the live-monitoring
// hub (Phase 16 follow-on): a supervisor subscribed to the session id sees the
// run's output the moment it completes. Before this, the run was registered —
// listable, capped, killable — but silent on the watch stream, so a supervisor
// could see THAT a WinRM run existed and never WHAT it did.
func TestWinRMRunStreamsLive(t *testing.T) {
	fake := &blockingWinRM{started: make(chan struct{}), release: make(chan struct{})}
	reg := session.NewRegistry()
	hub := session.NewHub()
	reg.AttachHub(hub) // wired the way main wires production: session end closes watch streams
	srv, _ := newTestServerOpts(t, nil, api.Options{
		WinRM: fake, RecordingDir: t.TempDir(), Sessions: reg, Live: hub,
	})

	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "win-live", "host": "10.0.0.8", "port": 5986, "os_type": "windows", "protocol": "winrm",
	})
	targetID := int64(jsonMap(t, td)["id"].(float64))
	if code, body := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": targetID, "username": "Administrator", "secret": "vaulted-pw",
	}); code != http.StatusCreated {
		t.Fatalf("seed credential: %d %s", code, body)
	}

	done := make(chan int, 1)
	go func() {
		code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/winrm", targetID),
			testAPIKey, map[string]any{"command": "Get-Service"})
		done <- code
	}()
	select {
	case <-fake.started:
	case <-time.After(3 * time.Second):
		t.Fatal("the WinRM run never reached the runner")
	}

	// The run is parked inside the runner; subscribe to its session, then let it
	// finish — the output must arrive on the hub.
	var sid string
	for i := 0; i < 200 && sid == ""; i++ {
		if ls := reg.List(); len(ls) > 0 {
			sid = ls[0].ID
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if sid == "" {
		t.Fatal("winrm run was not registered")
	}
	frames, cancel := hub.Subscribe(sid)
	defer cancel()
	close(fake.release)

	var acc string
	deadline := time.After(3 * time.Second)
	for !strings.Contains(acc, "done") { // blockingWinRM's canned stdout
		select {
		case b, open := <-frames:
			if !open {
				// With the hub attached, the session ending closes the channel;
				// without this check the loop would busy-spin on zero values.
				t.Fatalf("session ended before its output streamed; saw %q", acc)
			}
			acc += string(b)
		case <-deadline:
			t.Fatalf("live stream missing the run's output; saw %q", acc)
		}
	}
	if code := <-done; code != http.StatusOK {
		t.Fatalf("run returned %d, want 200", code)
	}
}
