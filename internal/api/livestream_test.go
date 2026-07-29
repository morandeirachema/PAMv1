package api_test

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/session"
)

// TestSessionStreamSSE proves an authorized supervisor can watch a live session
// over the SSE endpoint and receives the published output frames.
func TestSessionStreamSSE(t *testing.T) {
	hub := session.NewHub()
	srv, _ := newTestServerOpts(t, nil, api.Options{Live: hub})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/sessions/sess-1/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", testAPIKey) // admin holds CapReadAudit
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %q, want text/event-stream", ct)
	}

	// The handler subscribed before flushing headers, so publishing now is safe;
	// repeat to cover any scheduling delay before the reader is ready.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				hub.Publish("sess-1", []byte("live-output-42"))
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
	defer close(stop)

	br := bufio.NewReader(resp.Body)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading SSE stream: %v", err)
		}
		if strings.Contains(line, "live-output-42") {
			return // received the live frame
		}
	}
	t.Fatal("did not receive the live frame over SSE")
}

// TestSessionStreamRequiresAudit proves a role without CapReadAudit cannot watch
// a session (the endpoint is authz-gated like the session list).
func TestSessionStreamRequiresAudit(t *testing.T) {
	hub := session.NewHub()
	srv, _ := newTestServerOpts(t, nil, api.Options{Live: hub})
	userTok := seedUser(t, srv, "bob", "user") // user lacks CapReadAudit

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/sessions/sess-1/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", userTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

// TestSessionStreamOutlivesWriteTimeout proves a live-monitoring stream is not
// cut off by the HTTP server's global write timeout.
//
// http.Server.WriteTimeout (30s in production) is right for a request/response
// API and wrong for a stream: net/http arms the deadline before the handler
// runs, so a supervisor watching a session had the connection dropped mid-frame
// after thirty seconds however healthy it was — and reconnecting simply started
// another thirty-second clock. Nothing logged an error, because from the
// server's point of view the timeout did exactly what it was configured to do.
//
// The handler now clears the deadline for the connection with
// http.ResponseController, which only works because the access-log wrapper
// exposes Unwrap. This test runs a server with a deliberately tiny WriteTimeout
// and asserts frames still arrive well after it has elapsed; without either
// piece it fails in under a second.
func TestSessionStreamOutlivesWriteTimeout(t *testing.T) {
	hub := session.NewHub()
	handler := newTestHandler(t, api.Options{Live: hub})

	srv := httptest.NewUnstartedServer(handler)
	const writeTimeout = 250 * time.Millisecond
	srv.Config.WriteTimeout = writeTimeout
	srv.Start()
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/sessions/sess-slow/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", testAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Publish frames spaced so that the last one lands several write timeouts
	// after the stream opened. Under the old behaviour the connection is gone
	// before the second frame.
	const frames = 4
	go func() {
		for i := 0; i < frames; i++ {
			time.Sleep(writeTimeout * 2)
			hub.Publish("sess-slow", []byte("frame"))
		}
	}()

	sc := bufio.NewScanner(resp.Body)
	got := 0
	for got < frames && sc.Scan() {
		if strings.HasPrefix(sc.Text(), "data: ") {
			got++
		}
	}
	if got < frames {
		t.Fatalf("received %d of %d frames before the stream died (scanner err: %v) — the stream is still capped by the server WriteTimeout of %s",
			got, frames, sc.Err(), writeTimeout)
	}
}

// TestSessionStreamEndsWithSession proves the fix for the eternally-silent
// watch pane: when the watched session is removed from the registry — the path
// every session end funnels through, kills included — the SSE response ends,
// so the portal can say "session ended" instead of showing a quiet stream
// forever. Especially visible on short WinRM runs, which stream and finish in
// under a second.
func TestSessionStreamEndsWithSession(t *testing.T) {
	hub := session.NewHub()
	reg := session.NewRegistry()
	reg.AttachHub(hub)
	srv, _ := newTestServerOpts(t, nil, api.Options{Live: hub, Sessions: reg})

	sid := reg.Register(session.Info{Actor: "op", Target: "web-01", Protocol: "winrm"}, func() {})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/sessions/"+sid+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", testAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// A frame flows while the session lives...
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				hub.Publish(sid, []byte("winrm-output"))
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
	br := bufio.NewReader(resp.Body)
	got := false
	for !got {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading SSE stream before the end: %v", err)
		}
		got = strings.Contains(line, "winrm-output")
	}
	close(stop)

	// ...and the response ENDS when the session does.
	reg.Remove(sid)
	deadline := time.After(5 * time.Second)
	done := make(chan error, 1)
	go func() {
		for {
			if _, err := br.ReadString('\n'); err != nil {
				done <- err
				return
			}
		}
	}()
	select {
	case <-done: // EOF (or connection close) — the stream ended with the session
	case <-deadline:
		t.Fatal("SSE stream still open after the session ended")
	}
}

// TestSessionStreamUnknownSessionRefused proves that, with a registry wired, a
// watch on an unknown (or already-over) session id is refused with 404 rather
// than subscribing the supervisor to eternal silence.
func TestSessionStreamUnknownSessionRefused(t *testing.T) {
	hub := session.NewHub()
	reg := session.NewRegistry()
	reg.AttachHub(hub)
	srv, _ := newTestServerOpts(t, nil, api.Options{Live: hub, Sessions: reg})

	code, body := do(t, srv, http.MethodGet, "/api/sessions/no-such-session/stream", testAPIKey, nil)
	if code != http.StatusNotFound {
		t.Fatalf("watching an unknown session: %d %s, want 404", code, body)
	}
}
