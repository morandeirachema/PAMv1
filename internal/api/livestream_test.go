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
	"github.com/morandeirachema/pamv1/internal/store/memstore"
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

// apiTestBusKey is a fixed live-bus key shared by the simulated replicas.
func apiTestBusKey() []byte {
	k := make([]byte, session.LiveBusKeySize)
	for i := range k {
		k[i] = byte(i + 11)
	}
	return k
}

// TestSessionStreamRemoteReplica proves the Phase 55 story end to end at the
// API: a supervisor's SSE request lands on replica B for a session hosted on
// replica A, and still streams the session's output — B announces interest
// over the shared store bus, A's hub forwards each published chunk, B's
// bridge feeds its local hub, and the same handler serves the frames. Killing
// the story's tail too: when A removes the session, B's stream ends. Also
// asserts GET /api/sessions on B lists A's session (cluster-wide inventory)
// and that the cross-replica watch is audited with via:relay.
func TestSessionStreamRemoteReplica(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()

	// Replica A: hosts the session. Only its registry/hub/cluster exist here —
	// no HTTP server; it stands in for the pod the LB did NOT pick.
	regA := session.NewRegistry()
	hubA := session.NewHub()
	regA.AttachHub(hubA)
	if _, err := session.StartCluster(ctx, session.ClusterConfig{Store: st, Registry: regA, Hub: hubA, Replica: "replica-a", BusKey: apiTestBusKey()}); err != nil {
		t.Fatalf("StartCluster(a): %v", err)
	}
	id := regA.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})

	// Replica B: the API server the supervisor reached.
	regB := session.NewRegistry()
	hubB := session.NewHub()
	regB.AttachHub(hubB)
	clusterB, err := session.StartCluster(ctx, session.ClusterConfig{Store: st, Registry: regB, Hub: hubB, Replica: "replica-b", BusKey: apiTestBusKey()})
	if err != nil {
		t.Fatalf("StartCluster(b): %v", err)
	}
	srv, _ := newTestServerStoreOpts(t, nil, st, api.Options{Sessions: regB, Live: hubB, Cluster: clusterB})

	// The cluster-wide listing shows A's session from B, naming its replica.
	code, body := do(t, srv, http.MethodGet, "/api/sessions", testAPIKey, nil)
	if code != http.StatusOK || !strings.Contains(string(body), id) || !strings.Contains(string(body), "replica-a") {
		t.Fatalf("GET /api/sessions on B = %d %s, want 200 listing %s on replica-a", code, body, id)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/sessions/"+id+"/stream", nil)
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
		t.Fatalf("remote stream status = %d, want 200", resp.StatusCode)
	}

	// Interest propagates asynchronously; publish on A until a frame arrives.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				hubA.Publish(id, []byte("remote-live-output-55"))
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
	br := bufio.NewReader(resp.Body)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(deadline) {
			close(stop)
			t.Fatal("did not receive the remote session's frame over SSE")
		}
		line, err := br.ReadString('\n')
		if err != nil {
			close(stop)
			t.Fatalf("reading SSE stream: %v", err)
		}
		if strings.Contains(line, "remote-live-output-55") {
			break
		}
	}
	close(stop)

	// Ending the session on A ends the supervisor's stream on B.
	regA.Remove(id)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := br.ReadString('\n'); err != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SSE stream still open after the remote session ended")
	}

	// The cross-replica watch is audited, marked via:relay.
	events, err := st.ListAudit(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "session.monitor" && strings.Contains(e.Detail, "session:"+id) &&
			strings.Contains(e.Detail, "via:relay") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no session.monitor via:relay audit event; got %+v", events)
	}
}

// TestSessionStreamClusterUnknownRefused proves that with the cluster wired, a
// watch on an id unknown ANYWHERE is refused 404 with the cluster-checked
// wording and audited — the pre-Phase-55 refusal blamed the replica; this one
// can honestly say the session is not live at all.
func TestSessionStreamClusterUnknownRefused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	reg := session.NewRegistry()
	hub := session.NewHub()
	reg.AttachHub(hub)
	cluster, err := session.StartCluster(ctx, session.ClusterConfig{Store: st, Registry: reg, Hub: hub, Replica: "replica-solo", BusKey: apiTestBusKey()})
	if err != nil {
		t.Fatalf("StartCluster: %v", err)
	}
	srv, _ := newTestServerStoreOpts(t, nil, st, api.Options{Sessions: reg, Live: hub, Cluster: cluster})

	code, body := do(t, srv, http.MethodGet, "/api/sessions/no-such-session/stream", testAPIKey, nil)
	if code != http.StatusNotFound || !strings.Contains(string(body), "not live (unknown or already ended)") {
		t.Fatalf("cluster-checked unknown watch = %d %s, want 404 with the cluster wording", code, body)
	}
	events, err := st.ListAudit(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "session.monitor" && strings.Contains(e.Detail, "refused:not-live") {
			found = true
		}
	}
	if !found {
		t.Fatal("refused cluster watch left no session.monitor audit event")
	}
}
