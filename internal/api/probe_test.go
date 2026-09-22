package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/probe"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/testutil"
)

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// scriptedSession is a fake logon session for the probe side of the tests.
type scriptedSession struct {
	mu    sync.Mutex
	procs []probe.Process
}

func (s *scriptedSession) Identity() (probe.Hello, error) {
	return probe.Hello{Hostname: "WIN-01", OS: "windows", User: `CORP\alice`, SessionID: 5, LogonTime: time.Now()}, nil
}
func (s *scriptedSession) Processes(context.Context) ([]probe.Process, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]probe.Process(nil), s.procs...), nil
}
func (s *scriptedSession) Connections(context.Context) ([]probe.Connection, error) {
	return []probe.Connection{{PID: 300, Proto: "tcp", LocalAddr: "10.1.1.9", LocalPort: 50000, RemoteAddr: "10.99.0.5", RemotePort: 445, State: "Established"}}, nil
}
func (s *scriptedSession) Kill(_ context.Context, pid uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.procs {
		if p.PID == pid {
			s.procs = append(s.procs[:i], s.procs[i+1:]...)
			return nil
		}
	}
	return errors.New("access is denied")
}

// TestProbesAPI covers the Phase 266 surface: a probe-kind agent binds an
// RDP target (a tunnel cannot), the rule routes validate and push, a live
// probe is listed with its snapshot, a kill round-trips, the session lookup
// matches by target + account, capability boundaries hold, and everything is
// 404 with the feature off.
func TestProbesAPI(t *testing.T) {
	st0 := memstore.New()
	hub := probe.NewHub(func(ctx context.Context, targetID int64) ([]probe.Rule, error) {
		all, err := st0.ListProbeRules(ctx)
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
	}, nil)
	sessions := session.NewRegistry()
	srv, st := newTestServerStoreOpts(t, nil, st0, api.Options{EndpointAgents: session.NewEndpointAgents(), ProbeHub: hub, Sessions: sessions})

	status, body := do(t, srv, http.MethodPost, "/api/targets", testAPIKey,
		map[string]any{"name": "win-01", "host": "10.0.0.9", "port": 3389, "os_type": "windows", "protocol": "rdp"})
	if status != http.StatusCreated {
		t.Fatalf("create target: %d %s", status, body)
	}
	var win store.Target
	_ = json.Unmarshal(body, &win)

	// A tunnel cannot bind an RDP target; a probe can, once.
	if status, body = do(t, srv, http.MethodPost, "/api/endpoint-agents", testAPIKey,
		map[string]any{"name": "win-tunnel", "target_id": win.ID}); status != http.StatusUnprocessableEntity {
		t.Fatalf("tunnel on rdp target: %d %s", status, body)
	}
	if status, body = do(t, srv, http.MethodPost, "/api/endpoint-agents", testAPIKey,
		map[string]any{"name": "win-probe", "target_id": win.ID, "kind": "sensor"}); status != http.StatusUnprocessableEntity {
		t.Fatalf("unknown kind: %d %s", status, body)
	}
	status, body = do(t, srv, http.MethodPost, "/api/endpoint-agents", testAPIKey,
		map[string]any{"name": "win-probe", "target_id": win.ID, "kind": "probe"})
	if status != http.StatusCreated {
		t.Fatalf("create probe agent: %d %s", status, body)
	}
	var created struct {
		ID   int64  `json:"id"`
		Kind string `json:"kind"`
		Key  string `json:"key"`
		Note string `json:"note"`
	}
	_ = json.Unmarshal(body, &created)
	if created.Kind != "probe" || created.Key == "" || !strings.Contains(created.Note, "PAM_AGENT_MODE=probe") {
		t.Fatalf("create response: %s", body)
	}
	if status, _ = do(t, srv, http.MethodPost, "/api/endpoint-agents", testAPIKey,
		map[string]any{"name": "win-probe-2", "target_id": win.ID, "kind": "probe"}); status != http.StatusConflict {
		t.Fatalf("second probe for the target: %d", status)
	}

	// Rules: validation, then a process rule and a global connection rule.
	for _, bad := range []map[string]any{
		{"kind": "process"},
		{"kind": "connection", "proto": "tcp"},
		{"kind": "connection", "match": "nope"},
		{"kind": "shell", "match": "x"},
		{"kind": "process", "match": "x", "target_id": 999999},
	} {
		if status, body = do(t, srv, http.MethodPost, "/api/probe-rules", testAPIKey, bad); status != http.StatusUnprocessableEntity && status != http.StatusNotFound {
			t.Fatalf("bad rule %v: %d %s", bad, status, body)
		}
	}
	status, body = do(t, srv, http.MethodPost, "/api/probe-rules", testAPIKey,
		map[string]any{"kind": "process", "match": "PSEXEC*", "target_id": win.ID, "note": "lateral movement"})
	if status != http.StatusCreated {
		t.Fatalf("create process rule: %d %s", status, body)
	}
	var procRule store.ProbeRule
	_ = json.Unmarshal(body, &procRule)
	status, body = do(t, srv, http.MethodPost, "/api/probe-rules", testAPIKey,
		map[string]any{"kind": "connection", "match": "10.0.0.0/8", "port": 445, "proto": "TCP"})
	if status != http.StatusCreated {
		t.Fatalf("create connection rule: %d %s", status, body)
	}
	status, body = do(t, srv, http.MethodGet, "/api/probe-rules", testAPIKey, nil)
	var rules []struct {
		store.ProbeRule
		TargetName string `json:"target_name"`
	}
	_ = json.Unmarshal(body, &rules)
	if status != http.StatusOK || len(rules) != 2 || rules[0].TargetName != "win-01" || rules[1].TargetID != 0 || rules[1].Proto != "tcp" {
		t.Fatalf("list rules: %d %s", status, body)
	}

	// A live probe: the real probe loop over a pipe, served by the hub the
	// API reads, under the agent just created.
	pl := &scriptedSession{procs: []probe.Process{
		{PID: 100, Name: "explorer.exe"}, {PID: 200, Name: "psexec.exe", Path: `C:\Tools\psexec.exe`}, {PID: 300, Name: "smbclient.exe"},
	}}
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var audits []string
	var amu sync.Mutex
	go func() {
		_ = hub.Serve(ctx, probe.Link{AgentID: created.ID, AgentName: "win-probe", TargetID: win.ID, TargetName: "win-01", Remote: "203.0.113.9:5000",
			Hello: probe.Hello{Hostname: "WIN-01", OS: "windows", User: `CORP\alice`, SessionID: 5}}, a,
			func(action, detail string) { amu.Lock(); audits = append(audits, action+" "+detail); amu.Unlock() })
	}()
	go func() { _ = probe.Serve(ctx, b, pl, probe.Options{Interval: 30 * time.Millisecond}) }()
	t.Cleanup(func() { cancel(); a.Close(); b.Close() })

	// Both rules bite: psexec by name, smbclient by its SMB connection.
	testutil.WaitFor(t, 5*time.Second, func() bool {
		amu.Lock()
		defer amu.Unlock()
		return strings.Contains(strings.Join(audits, "\n"), "probe.process_killed") && strings.Contains(strings.Join(audits, "\n"), "probe.connection_blocked")
	})

	status, body = do(t, srv, http.MethodGet, "/api/probes", testAPIKey, nil)
	var probes []struct {
		Key        int64  `json:"key"`
		AgentID    int64  `json:"agent_id"`
		TargetName string `json:"target_name"`
		Processes  int    `json:"processes"`
		Rules      int    `json:"rules"`
		Hello      struct {
			User string `json:"user"`
		} `json:"hello"`
	}
	_ = json.Unmarshal(body, &probes)
	if status != http.StatusOK || len(probes) != 1 || probes[0].AgentID != created.ID || probes[0].TargetName != "win-01" || probes[0].Rules != 2 || probes[0].Hello.User != `CORP\alice` {
		t.Fatalf("list probes: %d %s", status, body)
	}
	key := probes[0].Key
	status, body = do(t, srv, http.MethodGet, "/api/probes/"+itoa64(key), testAPIKey, nil)
	var one struct {
		Snapshot *probe.Snapshot `json:"snapshot"`
	}
	_ = json.Unmarshal(body, &one)
	if status != http.StatusOK || one.Snapshot == nil || len(one.Snapshot.Connections) != 1 {
		t.Fatalf("get probe: %d %s", status, body)
	}
	// The endpoint-agents list reports the probe as connected with a count.
	status, body = do(t, srv, http.MethodGet, "/api/endpoint-agents", testAPIKey, nil)
	var agents []struct {
		Kind      string `json:"kind"`
		Connected bool   `json:"connected"`
		Probes    int    `json:"probes"`
	}
	_ = json.Unmarshal(body, &agents)
	if status != http.StatusOK || len(agents) != 1 || agents[0].Kind != "probe" || !agents[0].Connected || agents[0].Probes != 1 {
		t.Fatalf("agents list: %d %s", status, body)
	}

	// Kill: a live pid succeeds; a pid the session user cannot end is refused
	// with the platform's own words; both audited.
	if status, body = do(t, srv, http.MethodPost, "/api/probes/"+itoa64(key)+"/kill", testAPIKey, map[string]any{"pid": 100}); status != http.StatusOK {
		t.Fatalf("kill 100: %d %s", status, body)
	}
	if status, body = do(t, srv, http.MethodPost, "/api/probes/"+itoa64(key)+"/kill", testAPIKey, map[string]any{"pid": 999}); status != http.StatusBadGateway || !strings.Contains(string(body), "access is denied") {
		t.Fatalf("kill 999: %d %s", status, body)
	}
	if status, _ = do(t, srv, http.MethodPost, "/api/probes/"+itoa64(key)+"/kill", testAPIKey, map[string]any{"pid": 0}); status != http.StatusUnprocessableEntity {
		t.Fatalf("kill without pid: %d", status)
	}
	if status, _ = do(t, srv, http.MethodPost, "/api/probes/424242/kill", testAPIKey, map[string]any{"pid": 1}); status != http.StatusNotFound {
		t.Fatalf("kill on unknown probe: %d", status)
	}
	events, _ := st.ListAudit(context.Background(), 100)
	seen := map[string]bool{}
	for _, e := range events {
		if strings.HasPrefix(e.Action, "probe.") {
			seen[e.Action+"|"+e.Detail] = true
		}
	}
	want := []string{"probe.rule_create|rule:" + itoa64(procRule.ID) + ` target:win-01 kind:process match:"PSEXEC*" port:0 proto:`, "probe.kill|probe:" + itoa64(key) + " agent:" + itoa64(created.ID) + ` target:win-01 user:"CORP\\alice" session:5 pid:100`}
	for _, w := range want {
		if !seen[w] {
			t.Fatalf("missing audit %q in %v", w, seen)
		}
	}
	refused := false
	for k := range seen {
		if strings.HasPrefix(k, "probe.kill_refused|") && strings.Contains(k, "pid:999") && strings.Contains(k, "access is denied") {
			refused = true
		}
	}
	if !refused {
		t.Fatalf("missing kill_refused audit in %v", seen)
	}

	// Session lookup: an RDP session opened as "alice" on win-01 finds the
	// probe; one as "bob" or on another target does not; a session with no
	// account (cred_user empty) gets an empty list, not an error.
	sidAlice := sessions.Register(session.Info{Actor: "chema", Target: "win-01", Protocol: "rdp", CredUser: "alice", Started: time.Now()}, func() {})
	sidBob := sessions.Register(session.Info{Actor: "chema", Target: "win-01", Protocol: "rdp", CredUser: "bob", Started: time.Now()}, func() {})
	sidNone := sessions.Register(session.Info{Actor: "chema", Target: "win-01", Protocol: "postgres", Started: time.Now()}, func() {})
	for sid, n := range map[string]int{sidAlice: 1, sidBob: 0, sidNone: 0} {
		status, body = do(t, srv, http.MethodGet, "/api/sessions/"+sid+"/probes", testAPIKey, nil)
		var got []struct {
			Key      int64           `json:"key"`
			Snapshot *probe.Snapshot `json:"snapshot"`
		}
		_ = json.Unmarshal(body, &got)
		if status != http.StatusOK || len(got) != n || (n == 1 && (got[0].Key != key || got[0].Snapshot == nil)) {
			t.Fatalf("session probes for %s: %d %s (want %d)", sid, status, body, n)
		}
	}
	if status, _ = do(t, srv, http.MethodGet, "/api/sessions/nope/probes", testAPIKey, nil); status != http.StatusNotFound {
		t.Fatalf("unknown session: %d", status)
	}

	// Capability boundaries: an auditor reads probes and rules but cannot
	// create a rule or kill; a plain user cannot read telemetry at all.
	auditor := seedUser(t, srv, "aud", "auditor")
	user := seedUser(t, srv, "usr", "user")
	if status, _ = do(t, srv, http.MethodGet, "/api/probes", auditor, nil); status != http.StatusOK {
		t.Fatalf("auditor list probes: %d", status)
	}
	if status, _ = do(t, srv, http.MethodGet, "/api/probe-rules", auditor, nil); status != http.StatusOK {
		t.Fatalf("auditor list rules: %d", status)
	}
	if status, _ = do(t, srv, http.MethodPost, "/api/probe-rules", auditor, map[string]any{"kind": "process", "match": "x"}); status != http.StatusForbidden {
		t.Fatalf("auditor create rule: %d", status)
	}
	if status, _ = do(t, srv, http.MethodPost, "/api/probes/"+itoa64(key)+"/kill", auditor, map[string]any{"pid": 200}); status != http.StatusForbidden {
		t.Fatalf("auditor kill: %d", status)
	}
	if status, _ = do(t, srv, http.MethodGet, "/api/probes", user, nil); status != http.StatusForbidden {
		t.Fatalf("user list probes: %d", status)
	}

	// Delete a rule: pushed to the probe, whose rule count drops.
	if status, _ = do(t, srv, http.MethodDelete, "/api/probe-rules/"+itoa64(procRule.ID), testAPIKey, nil); status != http.StatusNoContent {
		t.Fatalf("delete rule: %d", status)
	}
	if status, _ = do(t, srv, http.MethodDelete, "/api/probe-rules/"+itoa64(procRule.ID), testAPIKey, nil); status != http.StatusNotFound {
		t.Fatalf("delete rule twice: %d", status)
	}
	testutil.WaitFor(t, 5*time.Second, func() bool { l := hub.List(); return len(l) == 1 && l[0].Rules == 1 })

	// Revoking the agent kicks the probe.
	if status, _ = do(t, srv, http.MethodDelete, "/api/endpoint-agents/"+itoa64(created.ID), testAPIKey, nil); status != http.StatusNoContent {
		t.Fatalf("revoke: %d", status)
	}
	testutil.WaitFor(t, 5*time.Second, func() bool { return len(hub.List()) == 0 })

	// Feature off: routes absent, probe kind refused.
	srvOff, stOff := newTestServerOpts(t, nil, api.Options{EndpointAgents: session.NewEndpointAgents()})
	status, body = do(t, srvOff, http.MethodPost, "/api/targets", testAPIKey,
		map[string]any{"name": "win-02", "host": "10.0.0.10", "port": 3389, "os_type": "windows", "protocol": "rdp"})
	if status != http.StatusCreated {
		t.Fatalf("create target (off): %d %s", status, body)
	}
	var win2 store.Target
	_ = json.Unmarshal(body, &win2)
	if status, _ = do(t, srvOff, http.MethodPost, "/api/endpoint-agents", testAPIKey, map[string]any{"name": "p", "target_id": win2.ID, "kind": "probe"}); status != http.StatusNotFound {
		t.Fatalf("probe kind with probes off: %d", status)
	}
	if status, _ = do(t, srvOff, http.MethodGet, "/api/probes", testAPIKey, nil); status != http.StatusNotFound {
		t.Fatalf("probes route with probes off: %d", status)
	}
	if list, _ := stOff.ListProbeRules(context.Background()); len(list) != 0 {
		t.Fatalf("rules with probes off: %+v", list)
	}
}
