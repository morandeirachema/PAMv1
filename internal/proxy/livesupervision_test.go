package proxy_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestLiveSupervisionOffByDefault proves the zero-value Config (no
// RequireSupervision) behaves exactly as before this phase: a session runs
// immediately with nobody watching. A regression here would make every
// existing deployment start blocking on a flag they never set.
func TestLiveSupervisionOffByDefault(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		Sessions: session.NewRegistry(), Live: session.NewHub(),
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	out, err := sess.Output("run")
	if err != nil {
		t.Fatalf("output: %v", err)
	}
	if string(out) != targetOutput {
		t.Fatalf("output = %q, want %q — an unwatched session must not be blocked when the flag is off", out, targetOutput)
	}
}

// TestLiveSupervisionTimesOutAndRefuses proves that with RequireSupervision
// set, a session nobody ever watches is refused once SupervisionTimeout
// elapses, and the refusal is audited.
func TestLiveSupervisionTimesOutAndRefuses(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		Sessions: session.NewRegistry(), Live: session.NewHub(),
		RequireSupervision: true, SupervisionTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	out, _ := sess.Output("run")
	if string(out) != "" {
		t.Fatalf("session should be refused when nobody ever watches, got %q", out)
	}
	if !auditHas(t, st, "session.unsupervised") {
		t.Error("the supervision timeout was not audited as session.unsupervised")
	}
}

// TestLiveSupervisionReleasesOnceWatched proves the other half: a session
// held at the gate proceeds the moment a supervisor subscribes to it, well
// before the timeout would have refused it — the common case, since the
// timeout exists for the supervisor who never shows up, not the one who does.
func TestLiveSupervisionReleasesOnceWatched(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	reg, hub := session.NewRegistry(), session.NewHub()
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		Sessions: reg, Live: hub,
		RequireSupervision: true, SupervisionTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	outc := make(chan []byte, 1)
	go func() { b, _ := sess.Output("run"); outc <- b }()

	// Poll for the session to register (mirrors TestMSSQLProxyLiveMonitor's
	// pattern), then subscribe — becoming the watcher the gate is waiting for.
	var sid string
	for i := 0; i < 200 && sid == ""; i++ {
		if ls := reg.List(); len(ls) > 0 {
			sid = ls[0].ID
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if sid == "" {
		t.Fatal("the session was not registered")
	}
	_, cancel := hub.Subscribe(sid)
	defer cancel()

	select {
	case out := <-outc:
		if string(out) != targetOutput {
			t.Fatalf("output = %q, want %q — the session should have proceeded once watched", out, targetOutput)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session never proceeded after a supervisor subscribed")
	}
}

// TestLiveSupervisionExemptsObserver proves an observer (view-only, +observe)
// session is never gated — it already IS the watching role, so requiring it
// to also be watched would be circular.
func TestLiveSupervisionExemptsObserver(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		Sessions: session.NewRegistry(), Live: session.NewHub(),
		RequireSupervision: true, SupervisionTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, "web-01+observe", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	done := make(chan struct{})
	go func() { _, _ = sess.Output("run"); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("an observer session must not wait for a supervisor to watch it")
	}
}

// TestLiveSupervisionExemptsBreakGlass proves the emergency key bypasses the
// gate — an emergency exists precisely for when no supervisor is reachable,
// so blocking it on one would defeat the purpose.
func TestLiveSupervisionExemptsBreakGlass(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	const emergencyKey = "the-sealed-emergency-key"
	sum := sha256.Sum256([]byte(emergencyKey))
	resolver, err := auth.NewResolver(st, proxyAPIKey, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		Sessions: session.NewRegistry(), Live: session.NewHub(),
		RequireSupervision: true, SupervisionTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, "web-01", emergencyKey)
	if err != nil {
		t.Fatalf("dial proxy with the emergency key: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	done := make(chan struct{})
	go func() { _, _ = sess.Output("run"); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a break-glass session must not wait for a supervisor to watch it")
	}
}
