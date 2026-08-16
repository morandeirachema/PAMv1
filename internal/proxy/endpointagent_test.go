package proxy_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/endpointagent"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/testutil"
	"github.com/morandeirachema/pamv1/internal/vault"
)

const (
	agentName = "branch-agent"
	agentKey  = "endpoint-agent-bearer-key-0123456789"
)

// closedPort returns a loopback port nothing listens on, so a direct dial to
// it fails immediately — the way a test proves the proxy did NOT dial the
// target's own address.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// startProxyWithAgents launches the proxy with the endpoint-agent registry
// wired (nil = feature disabled) and returns its address plus the host key
// the agent must pin.
func startProxyWithAgents(t *testing.T, st store.Store, v *vault.Vault, hub *session.EndpointAgents) (string, ssh.PublicKey) {
	t.Helper()
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	signer := mustSigner(t)
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey:        signer,
		RecordingDir:   t.TempDir(),
		DialTimeout:    5 * time.Second,
		EndpointAgents: hub,
	})
	if err != nil {
		t.Fatal(err)
	}
	return serveProxy(t, px), signer.PublicKey()
}

// seedAgentTarget creates the "web-01" target pointing at a CLOSED loopback
// port (never reachable directly), vaults the upstream credential, and binds
// an endpoint agent to it. It returns the agent row.
func seedAgentTarget(t *testing.T, st store.Store, v *vault.Vault) *store.EndpointAgent {
	t.Helper()
	target := seedTarget(t, st, v, "127.0.0.1", closedPort(t))
	a := &store.EndpointAgent{Name: agentName, TargetID: target.ID, KeyHash: auth.TokenHash(agentKey), CreatedBy: "admin"}
	if err := st.CreateEndpointAgent(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	return a
}

// runAgent starts the real endpoint-agent client against the proxy, exposing
// local (the in-process upstream sshd), and blocks until its tunnel is up.
func runAgent(t *testing.T, ctx context.Context, proxyAddr string, hostKey ssh.PublicKey, name, key, local string) {
	t.Helper()
	up := make(chan string, 4)
	go func() {
		_ = endpointagent.Run(ctx, endpointagent.Config{
			Servers: []string{proxyAddr}, Name: name, Key: key, LocalAddr: local,
			HostKey: ssh.FixedHostKey(hostKey), DialTimeout: 5 * time.Second,
			KeepAlive: 500 * time.Millisecond, MinBackoff: 100 * time.Millisecond, MaxBackoff: 300 * time.Millisecond,
			OnTunnel: func(s string) { up <- s },
		})
	}()
	select {
	case <-up:
	case <-time.After(10 * time.Second):
		t.Fatal("endpoint agent tunnel did not come up")
	}
}

// TestEndpointAgentTunnelJITInjection is the phase's flagship proof: the
// target's own address is a closed port, so the only way an operator's session
// can reach the upstream sshd — which accepts ONLY the vaulted password — is
// through the reverse tunnel the agent holds open. The operator authenticates
// to the proxy with the PAM key and never learns the credential; the proxy
// injects it just-in-time over the tunnel exactly as it does over a direct
// dial. Then revocation: the live tunnel is kicked, the agent's reconnect is
// refused, and the target becomes unreachable — never silently dialed direct.
func TestEndpointAgentTunnelJITInjection(t *testing.T) {
	upHost, upPort := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	agent := seedAgentTarget(t, st, v)
	hub := session.NewEndpointAgents()
	addr, hostKey := startProxyWithAgents(t, st, v, hub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runAgent(t, ctx, addr, hostKey, agentName, agentKey, fmt.Sprintf("%s:%d", upHost, upPort))
	testutil.WaitFor(t, 3*time.Second, func() bool { _, ok := hub.Lookup(agent.TargetID); return ok })
	if link, _ := hub.Lookup(agent.TargetID); link.AgentID != agent.ID || link.Name != agentName {
		t.Fatalf("registry link = %+v", link)
	}

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	out, err := sess.Output("whoami")
	if err != nil {
		t.Fatalf("exec through proxy via endpoint agent: %v", err)
	}
	if string(out) != targetOutput {
		t.Fatalf("output = %q, want %q", out, targetOutput)
	}
	sess.Close()
	client.Close()

	seen, _ := waitForAudit(t, st, "endpoint_agent.connected", "session.start", "session.end", "session.record")
	for _, w := range []string{"endpoint_agent.connected", "session.start", "session.end", "session.record"} {
		if !seen[w] {
			t.Fatalf("missing audit %q: %v", w, seen)
		}
	}
	events, _ := st.ListAudit(context.Background(), 50)
	var startDetail string
	for _, e := range events {
		if e.Action == "session.start" {
			startDetail = e.Detail
		}
	}
	if !strings.Contains(startDetail, "via:endpoint-agent:"+agentName) {
		t.Fatalf("session.start should say it went via the agent: %q", startDetail)
	}
	if a, _ := st.GetEndpointAgentByKeyHash(context.Background(), auth.TokenHash(agentKey)); a.LastSeen == nil {
		t.Fatal("last-seen not stamped on connect")
	}

	// Revoke: what the API does — stamp the row, kick the live link.
	if err := st.RevokeEndpointAgent(context.Background(), agent.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !hub.Kick(agent.ID) {
		t.Fatal("kick should find the live link")
	}
	// The agent reconnects with backoff and is refused as revoked; the link
	// never comes back.
	seen, _ = waitForAudit(t, st, "endpoint_agent.disconnected", "endpoint_agent.auth_failed")
	if !seen["endpoint_agent.auth_failed"] {
		t.Fatalf("revoked agent's reconnect should be audited as refused: %v", seen)
	}
	events, _ = st.ListAudit(context.Background(), 50)
	refused := false
	for _, e := range events {
		if e.Action == "endpoint_agent.auth_failed" && strings.Contains(e.Detail, "reason:revoked") {
			refused = true
		}
	}
	if !refused {
		t.Fatal("expected reason:revoked on the refused reconnect")
	}
	if _, ok := hub.Lookup(agent.TargetID); ok {
		t.Fatal("revoked agent must not be registered")
	}
	// The row is revoked, so the target is now dialed directly — to a closed
	// port — and the session fails; the point is that it does NOT succeed
	// through a tunnel a revoked agent might still be holding.
	if c, err := dialProxy(t, addr, "web-01", proxyAPIKey); err == nil {
		s, err := c.NewSession()
		if err == nil {
			if _, err := s.Output("whoami"); err == nil {
				t.Fatal("session succeeded after the agent was revoked")
			}
		}
		c.Close()
	}
}

// TestEndpointAgentOfflineRefused proves fail-closed routing: a target bound to
// an agent that is not connected is unreachable — the proxy does not fall
// back to dialing the target's address (which here is a closed port; a
// fallback would fail too, so the audit reason is what proves the path).
func TestEndpointAgentOfflineRefused(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	seedAgentTarget(t, st, v)
	addr, _ := startProxyWithAgents(t, st, v, session.NewEndpointAgents())

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	if s, err := client.NewSession(); err == nil {
		if _, err := s.Output("whoami"); err == nil {
			t.Fatal("session should fail while the endpoint agent is offline")
		}
	}
	seen, _ := waitForAudit(t, st, "session.error")
	if !seen["session.error"] {
		t.Fatal("expected session.error")
	}
	events, _ := st.ListAudit(context.Background(), 50)
	found := false
	for _, e := range events {
		if e.Action == "session.error" && strings.Contains(e.Detail, "endpoint agent") && strings.Contains(e.Detail, "not connected") {
			found = true
		}
	}
	if !found {
		t.Fatalf("session.error should name the offline endpoint agent: %+v", events)
	}
}

// TestEndpointAgentAuthRefusals covers every refusal of the agent login form:
// unknown key, wrong name for a valid key, revoked agent, and the feature
// being disabled — each audited with its reason, and none reaching the human
// resolver (a valid OPERATOR key under the agent login is refused too).
func TestEndpointAgentAuthRefusals(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	agent := seedAgentTarget(t, st, v)
	addr, _ := startProxyWithAgents(t, st, v, session.NewEndpointAgents())

	try := func(login, password string) error {
		c, err := dialProxy(t, addr, login, password)
		if err == nil {
			c.Close()
		}
		return err
	}
	if err := try(proxy.EndpointAgentLoginPrefix+agentName, "not-the-key"); err == nil {
		t.Fatal("unknown agent key accepted")
	}
	if err := try(proxy.EndpointAgentLoginPrefix+"other-name", agentKey); err == nil {
		t.Fatal("valid key under the wrong agent name accepted")
	}
	if err := try(proxy.EndpointAgentLoginPrefix+agentName, proxyAPIKey); err == nil {
		t.Fatal("an operator's key must not authenticate as an endpoint agent")
	}
	// An agent key is not an operator credential either.
	if err := try("web-01", agentKey); err == nil {
		t.Fatal("an endpoint agent key must not authenticate an operator")
	}
	if err := st.RevokeEndpointAgent(context.Background(), agent.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := try(proxy.EndpointAgentLoginPrefix+agentName, agentKey); err == nil {
		t.Fatal("revoked agent accepted")
	}
	seen, _ := waitForAudit(t, st, "endpoint_agent.auth_failed", "proxy.auth_failed")
	if !seen["endpoint_agent.auth_failed"] || !seen["proxy.auth_failed"] {
		t.Fatalf("expected both refusal audits: %v", seen)
	}
	events, _ := st.ListAudit(context.Background(), 50)
	reasons := map[string]bool{}
	for _, e := range events {
		if e.Action == "endpoint_agent.auth_failed" {
			for _, r := range []string{"unknown-key", "name-mismatch", "revoked"} {
				if strings.Contains(e.Detail, "reason:"+r) {
					reasons[r] = true
				}
			}
		}
	}
	for _, r := range []string{"unknown-key", "name-mismatch", "revoked"} {
		if !reasons[r] {
			t.Fatalf("missing refusal reason %q in %v", r, reasons)
		}
	}

	// Feature disabled (no registry wired): even a valid key is refused.
	st2 := memstore.New()
	seedAgentTarget(t, st2, v)
	addr2, _ := startProxyWithAgents(t, st2, v, nil)
	if c, err := dialProxy(t, addr2, proxy.EndpointAgentLoginPrefix+agentName, agentKey); err == nil {
		c.Close()
		t.Fatal("agent login accepted while the feature is disabled")
	}
	waitForAudit(t, st2, "endpoint_agent.auth_failed")
	events, _ = st2.ListAudit(context.Background(), 50)
	disabled := false
	for _, e := range events {
		if e.Action == "endpoint_agent.auth_failed" && strings.Contains(e.Detail, "reason:disabled") {
			disabled = true
		}
	}
	if !disabled {
		t.Fatal("expected reason:disabled")
	}
}

// TestEndpointAgentConnectionIsInboundOnly proves an authenticated agent
// connection can carry NOTHING toward pamv1: a session channel and a
// direct-tcpip channel are both refused, a second tcpip-forward is refused,
// and — from the other side — an operator's connection cannot request a
// tcpip-forward at all (operators' global requests are discarded).
func TestEndpointAgentConnectionIsInboundOnly(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	seedAgentTarget(t, st, v)
	hub := session.NewEndpointAgents()
	addr, _ := startProxyWithAgents(t, st, v, hub)

	// A raw agent-class client, driven by hand rather than through the agent
	// library, so the test can misbehave on purpose.
	agentClient, err := dialProxy(t, addr, proxy.EndpointAgentLoginPrefix+agentName, agentKey)
	if err != nil {
		t.Fatalf("agent auth: %v", err)
	}
	defer agentClient.Close()
	if s, err := agentClient.NewSession(); err == nil {
		s.Close()
		t.Fatal("agent connection opened a session channel")
	}
	if c, err := agentClient.Dial("tcp", "127.0.0.1:22"); err == nil {
		c.Close()
		t.Fatal("agent connection opened a direct-tcpip channel")
	}
	ln, err := agentClient.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("first tcpip-forward should be accepted: %v", err)
	}
	defer ln.Close()
	if ln2, err := agentClient.Listen("tcp", "127.0.0.1:0"); err == nil {
		ln2.Close()
		t.Fatal("second tcpip-forward on one agent connection should be refused")
	}

	// An operator connection cannot register a forward.
	op, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("operator auth: %v", err)
	}
	defer op.Close()
	if l, err := op.Listen("tcp", "127.0.0.1:0"); err == nil {
		l.Close()
		t.Fatal("an operator connection must not be able to register a reverse forward")
	}
}
