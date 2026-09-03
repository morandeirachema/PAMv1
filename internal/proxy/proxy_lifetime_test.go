package proxy_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// lifetimeProxy builds a proxy over a real in-process sshd whose session
// registry runs the lifetime monitor with the given bounds on a 20 ms tick,
// auditing into st as main does.
func lifetimeProxy(t *testing.T, st store.Store, maxDur, idle time.Duration) (addr string) {
	t.Helper()
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := session.NewRegistry()
	reg.StartLifetimeMonitor(ctx, session.LifetimeConfig{
		MaxDuration: maxDur, IdleTimeout: idle, Tick: 20 * time.Millisecond,
		Audit: func(actx context.Context, action, detail string) {
			_ = st.AppendAudit(actx, &store.AuditEvent{Actor: "system-lifetime", Action: action, Detail: detail})
		},
	})
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second, Sessions: reg,
	})
	if err != nil {
		t.Fatal(err)
	}
	return serveProxy(t, px)
}

// waitClosed reports whether the client's connection is closed within d.
func waitClosed(client interface{ Wait() error }, d time.Duration) bool {
	done := make(chan struct{})
	go func() { client.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

func killedReason(t *testing.T, st store.Store) string {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == "session.killed" {
			return e.Detail
		}
	}
	return ""
}

// TestSessionMaxDurationProxy proves a deployment-wide maximum session
// duration (Phase 240) ends a live, admitted SSH session — the connection is
// closed under the operator, audited session.killed reason:max-duration —
// while a session with no bound stays up.
func TestSessionMaxDurationProxy(t *testing.T) {
	st := memstore.New()
	addr := lifetimeProxy(t, st, 300*time.Millisecond, 0)
	client, err := dialProxy(t, addr, upstreamUser+"@web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if !waitClosed(client, 3*time.Second) {
		t.Fatal("the session outlived PAM_SESSION_MAX_MIN")
	}
	if d := killedReason(t, st); !strings.Contains(d, "reason:max-duration") {
		t.Fatalf("session.killed audit = %q, want reason:max-duration", d)
	}

	unbounded := memstore.New()
	addr2 := lifetimeProxy(t, unbounded, 0, 0)
	client2, err := dialProxy(t, addr2, upstreamUser+"@web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client2.Close()
	if waitClosed(client2, 600*time.Millisecond) {
		t.Fatal("an unbounded session was ended")
	}
}

// TestSessionIdleTimeoutProxy proves the idle timeout ends a session that
// sends no operator input.
func TestSessionIdleTimeoutProxy(t *testing.T) {
	st := memstore.New()
	addr := lifetimeProxy(t, st, 0, 300*time.Millisecond)
	client, err := dialProxy(t, addr, upstreamUser+"@web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if !waitClosed(client, 3*time.Second) {
		t.Fatal("an idle session outlived PAM_SESSION_IDLE_MIN")
	}
	if d := killedReason(t, st); !strings.Contains(d, "reason:idle-timeout") {
		t.Fatalf("session.killed audit = %q, want reason:idle-timeout", d)
	}
}

// TestGrantExpiryEndsSessionProxy proves a session admitted under a grant
// that expires while it runs ends AT the expiry (the deadline the gate
// stamped), with no deployment-wide bound configured at all.
func TestGrantExpiryEndsSessionProxy(t *testing.T) {
	st := memstore.New()
	addr := lifetimeProxy(t, st, 0, 0)
	tok := "carol-token"
	sum := sha256.Sum256([]byte(tok))
	if err := st.CreateUser(context.Background(), &store.User{Username: "carol", Role: "user", TokenHash: hex.EncodeToString(sum[:])}); err != nil {
		t.Fatal(err)
	}
	targets, _ := st.ListTargets(context.Background(), 0, 0)
	exp := time.Now().Add(700 * time.Millisecond)
	if err := st.CreateTargetGrant(context.Background(), &store.TargetGrant{TargetID: targets[0].ID, SubjectType: "user", Subject: "carol", ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	client, err := dialProxy(t, addr, upstreamUser+"@web-01", tok)
	if err != nil {
		t.Fatalf("dial as carol: %v", err)
	}
	if waitClosed(client, 300*time.Millisecond) {
		t.Fatal("the session ended before the grant expired")
	}
	if !waitClosed(client, 3*time.Second) {
		t.Fatal("the session outlived its grant")
	}
	if d := killedReason(t, st); !strings.Contains(d, "reason:grant-expiry") || !strings.Contains(d, "actor:carol") {
		t.Fatalf("session.killed audit = %q, want carol's session ended for grant-expiry", d)
	}
	// And once expired, the same grant refuses a new session outright.
	client2, err := dialProxy(t, addr, upstreamUser+"@web-01", tok)
	if err == nil {
		if sess, serr := client2.NewSession(); serr == nil {
			sess.Close()
			client2.Close()
			t.Fatal("an expired grant admitted a new session")
		}
		client2.Close()
	}
}
