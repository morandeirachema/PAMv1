package proxy_test

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/endpointagent"
	"github.com/morandeirachema/pamv1/internal/probe"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/testutil"
	"github.com/morandeirachema/pamv1/internal/vault"
)

const (
	probeName = "win-probe"
	probeKey  = "probe-bearer-key-0123456789abcdef"
)

// sessionPlatform is a scripted Windows logon session for the probe: a
// process table the probe can end entries of.
type sessionPlatform struct {
	mu     sync.Mutex
	procs  []probe.Process
	killed []uint32
}

func (s *sessionPlatform) Identity() (probe.Hello, error) {
	return probe.Hello{Hostname: "WIN-01", OS: "windows", User: `CORP\alice`, SessionID: 2, LogonTime: time.Now()}, nil
}
func (s *sessionPlatform) Processes(context.Context) ([]probe.Process, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]probe.Process(nil), s.procs...), nil
}
func (s *sessionPlatform) Connections(context.Context) ([]probe.Connection, error) {
	return nil, nil
}
func (s *sessionPlatform) Kill(_ context.Context, pid uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := s.procs[:0]
	found := false
	for _, p := range s.procs {
		if p.PID == pid {
			found = true
			continue
		}
		keep = append(keep, p)
	}
	s.procs = keep
	if !found {
		return errors.New("no such process")
	}
	s.killed = append(s.killed, pid)
	return nil
}

// policyFromStore is the hub's rule source, the same closure main wires.
func policyFromStore(st store.Store) probe.PolicySource {
	return func(ctx context.Context, targetID int64) ([]probe.Rule, error) {
		all, err := st.ListProbeRules(ctx)
		if err != nil {
			return nil, err
		}
		var rules []probe.Rule
		for _, r := range all {
			if r.TargetID == 0 || r.TargetID == targetID {
				rules = append(rules, probe.Rule{ID: r.ID, Kind: r.Kind, Match: r.Match, Port: r.Port, Proto: r.Proto})
			}
		}
		return rules, nil
	}
}

// startProxyWithProbes launches the proxy with both agent registries wired.
func startProxyWithProbes(t *testing.T, st store.Store, v *vault.Vault, agents *session.EndpointAgents, hub *probe.Hub) (string, ssh.PublicKey) {
	t.Helper()
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	signer := mustSigner(t)
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: signer, RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		EndpointAgents: agents, ProbeHub: hub,
	})
	if err != nil {
		t.Fatal(err)
	}
	return serveProxy(t, px), signer.PublicKey()
}

// seedProbeTarget creates the RDP target "win-01" with an "alice" credential
// and binds a probe-kind agent to it.
func seedProbeTarget(t *testing.T, st store.Store) (*store.Target, *store.EndpointAgent) {
	t.Helper()
	ctx := context.Background()
	target := &store.Target{Name: "win-01", Host: "10.0.0.9", Port: 3389, OSType: "windows", Protocol: "rdp"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateCredential(ctx, &store.Credential{TargetID: target.ID, Username: "alice", SecretType: "password"}); err != nil {
		t.Fatal(err)
	}
	a := &store.EndpointAgent{Name: probeName, TargetID: target.ID, Kind: store.EndpointAgentProbe, KeyHash: auth.TokenHash(probeKey), CreatedBy: "admin"}
	if err := st.CreateEndpointAgent(ctx, a); err != nil {
		t.Fatal(err)
	}
	return target, a
}

// runProbe starts the real agent library in probe mode against the proxy and
// blocks until the probe channel is established.
func runProbe(t *testing.T, ctx context.Context, proxyAddr string, hostKey ssh.PublicKey, pl probe.Platform) {
	t.Helper()
	up := make(chan string, 4)
	go func() {
		_ = endpointagent.Run(ctx, endpointagent.Config{
			Servers: []string{proxyAddr}, Name: probeName, Key: probeKey, Mode: endpointagent.ModeProbe,
			ProbePlatform: pl, Probe: probe.Options{Interval: 50 * time.Millisecond},
			HostKey: ssh.FixedHostKey(hostKey), DialTimeout: 5 * time.Second,
			KeepAlive: 500 * time.Millisecond, MinBackoff: 100 * time.Millisecond, MaxBackoff: 300 * time.Millisecond,
			OnTunnel: func(s string) { up <- s },
		})
	}()
	select {
	case <-up:
	case <-time.After(10 * time.Second):
		t.Fatal("probe did not come up")
	}
}

// TestSessionProbeEndToEnd is Phase 266's proof: the REAL agent library in
// probe mode, over a real SSH connection to the real proxy, announces a
// logon session, is handed the probe channel, reports the session, receives
// a rule pushed after it connected, ends the process the rule names, answers
// a kill command — every step audited under the agent's actor with the
// session it concerns — and is matched to a brokered session of the same
// account. Then the two kinds are shown to be non-interchangeable, and
// revocation kicks the live probe.
func TestSessionProbeEndToEnd(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	target, agent := seedProbeTarget(t, st)
	seedAgentTarget(t, st, v) // the tunnel-kind agent on "web-01", for the cross-refusal below
	agents := session.NewEndpointAgents()
	hub := probe.NewHub(policyFromStore(st), nil)
	addr, hostKey := startProxyWithProbes(t, st, v, agents, hub)

	pl := &sessionPlatform{procs: []probe.Process{
		{PID: 100, Name: "explorer.exe", Path: `C:\Windows\explorer.exe`},
		{PID: 200, Name: "PsExec.exe", Path: `C:\Tools\PsExec.exe`},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runProbe(t, ctx, addr, hostKey, pl)

	waitForAuditDetail(t, st, "probe.connected", "agent:"+itoa(agent.ID)+` target:win-01 host:"WIN-01" user:"CORP\\alice" session:2`)
	testutil.WaitFor(t, 5*time.Second, func() bool {
		l := hub.List()
		return len(l) == 1 && l[0].Processes == 2
	})
	link := hub.List()[0]
	if link.AgentName != probeName || link.TargetID != target.ID || link.Hello.User != `CORP\alice` {
		t.Fatalf("link: %+v", link)
	}
	// No rule yet: nothing ended.
	if pl.killed != nil {
		t.Fatalf("killed before any rule: %v", pl.killed)
	}

	// A rule created after the probe connected reaches it on refresh and is
	// enforced on the next scan.
	rule := &store.ProbeRule{TargetID: target.ID, Kind: store.ProbeRuleProcess, Match: "psexec*", CreatedBy: "admin"}
	if err := st.CreateProbeRule(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	hub.RefreshPolicy(context.Background())
	waitForAuditDetail(t, st, "probe.process_killed", `target:win-01 user:"CORP\\alice" session:2 pid:200 name:"PsExec.exe" path:"C\x3a\\Tools\\PsExec.exe" rule:`+itoa(rule.ID))
	testutil.WaitFor(t, 5*time.Second, func() bool {
		_, snap, ok := hub.Get(link.Key)
		return ok && snap != nil && len(snap.Processes) == 1
	})

	// A kill command round-trips through the channel.
	if err := hub.Kill(context.Background(), link.Key, 100); err != nil {
		t.Fatalf("kill: %v", err)
	}
	waitForAuditDetail(t, st, "probe.command_killed", "pid:100 command:1")
	if err := hub.Kill(context.Background(), link.Key, 100); err == nil || !strings.Contains(err.Error(), "no such process") {
		t.Fatalf("second kill of a gone pid: %v", err)
	}

	// The probe is matched to a brokered session opened as the same account.
	if got := hub.ForSession("win-01", "alice"); len(got) != 1 || got[0].Key != link.Key {
		t.Fatalf("ForSession: %+v", got)
	}

	// Kinds are not interchangeable: the tunnel agent's key cannot announce a
	// probe, and the probe's key cannot register a forward.
	tunnelClient, err := dialProxy(t, addr, proxy.EndpointAgentLoginPrefix+agentName, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	defer tunnelClient.Close()
	hello, _ := json.Marshal(probe.Hello{Hostname: "x", User: "y"})
	if ok, _, err := tunnelClient.SendRequest(probe.RequestType, true, hello); err != nil || ok {
		t.Fatalf("tunnel agent's probe request: ok=%v err=%v, want refused", ok, err)
	}
	waitForAuditDetail(t, st, "probe.refused", "reason:not-a-probe")
	probeClient, err := dialProxy(t, addr, proxy.EndpointAgentLoginPrefix+probeName, probeKey)
	if err != nil {
		t.Fatal(err)
	}
	defer probeClient.Close()
	if ln, err := probeClient.Listen("tcp", "127.0.0.1:0"); err == nil {
		ln.Close()
		t.Fatal("probe agent registered a reverse forward")
	}
	waitForAuditDetail(t, st, "endpoint_agent.refused", "reason:not-a-tunnel")
	// And a bare probe agent is never the target's dial.
	if a, err := st.GetEndpointAgentForTarget(context.Background(), target.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a probe must not become the target's tunnel: %+v %v", a, err)
	}

	// Revocation: the live probe is kicked, the disconnect audited, and the
	// agent's reconnect is refused as revoked.
	if err := st.RevokeEndpointAgent(context.Background(), agent.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if n := hub.Kick(agent.ID); n != 1 {
		t.Fatalf("kick: %d", n)
	}
	waitForAuditDetail(t, st, "probe.disconnected", "agent:"+itoa(agent.ID)+" target:win-01")
	waitForAuditDetail(t, st, "endpoint_agent.auth_failed", "reason:revoked")
	if l := hub.List(); len(l) != 0 {
		t.Fatalf("probe still registered after kick: %+v", l)
	}
}

// TestSessionProbeRefusedWhenDisabled: with no hub wired, a probe-kind
// agent authenticates (the agent registry is on) but its announcement is
// refused and audited as disabled.
func TestSessionProbeRefusedWhenDisabled(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	seedProbeTarget(t, st)
	addr, _ := startProxyWithProbes(t, st, v, session.NewEndpointAgents(), nil)
	c, err := dialProxy(t, addr, proxy.EndpointAgentLoginPrefix+probeName, probeKey)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hello, _ := json.Marshal(probe.Hello{Hostname: "x", User: "y"})
	if ok, _, err := c.SendRequest(probe.RequestType, true, hello); err != nil || ok {
		t.Fatalf("probe request with probes disabled: ok=%v err=%v", ok, err)
	}
	waitForAuditDetail(t, st, "probe.refused", "reason:disabled")
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
