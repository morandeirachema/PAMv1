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
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// seedUserTokenAllowlisted creates a user with a bearer token AND a source-IP
// allowlist (Phase 118) — a variant of sessionshare_test.go's seedUserToken.
func seedUserTokenAllowlisted(t *testing.T, st store.Store, username, rawToken, allowlist string) {
	t.Helper()
	sum := sha256.Sum256([]byte(rawToken))
	if err := st.CreateUser(context.Background(), &store.User{
		Username: username, Role: "user", IPAllowlist: allowlist, TokenHash: hex.EncodeToString(sum[:]),
	}); err != nil {
		t.Fatal(err)
	}
}

// TestIPAllowlistRefusesOutsideCIDR proves a user restricted to a CIDR block
// that does NOT cover the proxy's test loopback address is refused a session
// — dial succeeds (authentication only checks the token; the gate fires at
// channel-open, inside admit()), and NewSession fails, matching the refusal
// shape every other admit() gate test in this package already uses.
func TestIPAllowlistRefusesOutsideCIDR(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	seedUserTokenAllowlisted(t, st, "alice", "alices-token", "10.0.0.0/8") // excludes 127.0.0.1

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, "web-01", "alices-token")
	if err != nil {
		t.Fatalf("dial should succeed (the gate fires at channel-open): %v", err)
	}
	defer client.Close()
	if _, err := client.NewSession(); err == nil {
		t.Fatal("expected the session to be refused (source address outside the allowlist), it opened")
	}

	events, err := st.ListAudit(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "session.denied" && strings.Contains(e.Detail, "reason:source-ip-not-allowed") {
			found = true
		}
	}
	if !found {
		t.Fatal("no session.denied reason:source-ip-not-allowed audit event")
	}
}

// TestIPAllowlistAdmitsInsideCIDR proves a user restricted to a CIDR block
// that DOES cover the proxy's test loopback address connects normally.
func TestIPAllowlistAdmitsInsideCIDR(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	seedUserTokenAllowlisted(t, st, "alice", "alices-token", "127.0.0.0/8") // covers 127.0.0.1

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, "web-01", "alices-token")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session should be admitted (source address is inside the allowlist): %v", err)
	}
	out, err := sess.Output("run")
	if err != nil || string(out) != targetOutput {
		t.Fatalf("session output = %q err %v, want %q", out, err, targetOutput)
	}
}
