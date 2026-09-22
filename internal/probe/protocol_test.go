package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePlatform is a scripted logon session: a fixed process and connection
// table, and Kill removes a process (or refuses it, for a PID in denied).
type fakePlatform struct {
	mu     sync.Mutex
	procs  []Process
	conns  []Connection
	denied map[uint32]bool
	killed []uint32
}

func (f *fakePlatform) Identity() (Hello, error) {
	return Hello{Hostname: "WIN-01", OS: "windows", User: `CORP\alice`, SessionID: 3, LogonTime: time.Now()}, nil
}
func (f *fakePlatform) Processes(context.Context) ([]Process, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Process(nil), f.procs...), nil
}
func (f *fakePlatform) Connections(context.Context) ([]Connection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Connection(nil), f.conns...), nil
}
func (f *fakePlatform) Kill(_ context.Context, pid uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.denied[pid] {
		return errors.New("access is denied")
	}
	found := false
	keep := f.procs[:0]
	for _, p := range f.procs {
		if p.PID == pid {
			found = true
			continue
		}
		keep = append(keep, p)
	}
	f.procs = keep
	cs := f.conns[:0]
	for _, c := range f.conns {
		if c.PID != pid {
			cs = append(cs, c)
		}
	}
	f.conns = cs
	if !found {
		return errors.New("no such process")
	}
	f.killed = append(f.killed, pid)
	return nil
}
func (f *fakePlatform) killedPIDs() []uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint32(nil), f.killed...)
}

// auditLog collects audit rows the hub emits.
type auditLog struct {
	mu   sync.Mutex
	rows []string
}

func (a *auditLog) add(action, detail string) {
	a.mu.Lock()
	a.rows = append(a.rows, action+" "+detail)
	a.mu.Unlock()
}
func (a *auditLog) has(sub string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range a.rows {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

// waitFor polls cond for up to 5s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// startPair wires a real Serve (probe side) to a real Hub.Serve (server
// side) over net.Pipe and returns the hub, the fake platform and the audit
// log. The policy source hands out rules.
func startPair(t *testing.T, pl *fakePlatform, rules *[]Rule) (*Hub, *auditLog, context.CancelFunc) {
	t.Helper()
	var rmu sync.Mutex
	hub := NewHub(func(_ context.Context, targetID int64) ([]Rule, error) {
		rmu.Lock()
		defer rmu.Unlock()
		if targetID != 42 {
			return nil, fmt.Errorf("unexpected target %d", targetID)
		}
		return append([]Rule(nil), (*rules)...), nil
	}, nil)
	al := &auditLog{}
	srv, cli := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	hello, _ := pl.Identity()
	go func() {
		_ = hub.Serve(ctx, Link{AgentID: 9, AgentName: "win-probe", TargetID: 42, TargetName: "win-01", Remote: "203.0.113.7:5000", Hello: hello}, srv, al.add)
	}()
	go func() {
		_ = Serve(ctx, cli, pl, Options{Interval: 20 * time.Millisecond})
	}()
	t.Cleanup(func() { cancel(); srv.Close(); cli.Close() })
	return hub, al, cancel
}

func TestProbeReportsAndEnforces(t *testing.T) {
	pl := &fakePlatform{
		procs: []Process{
			{PID: 100, Name: "explorer.exe", Path: `C:\Windows\explorer.exe`},
			{PID: 200, Name: "psexec.exe", Path: `C:\Tools\PsExec.exe`},
			{PID: 300, Name: "chrome.exe", Path: `C:\Program Files\Google\Chrome\chrome.exe`},
			{PID: 400, Name: "svchost.exe", Path: `C:\Windows\System32\svchost.exe`},
		},
		conns: []Connection{
			{PID: 300, Proto: "tcp", LocalAddr: "10.1.1.9", LocalPort: 50000, RemoteAddr: "142.250.0.1", RemotePort: 443, State: "Established"},
			{PID: 300, Proto: "tcp", LocalAddr: "10.1.1.9", LocalPort: 50001, RemoteAddr: "10.99.0.5", RemotePort: 445, State: "Established"},
			{PID: 400, Proto: "tcp", LocalAddr: "0.0.0.0", LocalPort: 135, State: "Listen"},
		},
		denied: map[uint32]bool{400: true},
	}
	rules := []Rule{
		{ID: 1, Kind: RuleProcess, Match: "*psexec*"},
		{ID: 2, Kind: RuleConnection, Match: "10.0.0.0/8", Port: 445},
	}
	hub, al, _ := startPair(t, pl, &rules)

	// The probe registers, receives the policy and reports a snapshot.
	waitFor(t, "a snapshot", func() bool {
		st := hub.List()
		return len(st) == 1 && st[0].Processes > 0
	})
	st := hub.List()[0]
	if st.AgentName != "win-probe" || st.TargetName != "win-01" || st.Hello.User != `CORP\alice` || st.Hello.SessionID != 3 || st.Rules != 2 {
		t.Fatalf("status: %+v", st)
	}
	// The first snapshot is what was there BEFORE enforcement: all four.
	_, snap, ok := hub.Get(st.Key)
	if !ok || snap == nil {
		t.Fatal("no snapshot")
	}

	// Enforcement: psexec by process rule, chrome by its SMB connection into
	// 10/8; svchost's listener matches nothing; explorer is untouched.
	waitFor(t, "enforcement", func() bool { return len(pl.killedPIDs()) == 2 })
	killed := pl.killedPIDs()
	if !(killed[0] == 200 && killed[1] == 300) {
		t.Fatalf("killed %v, want [200 300]", killed)
	}
	waitFor(t, "audit rows", func() bool {
		return al.has(`probe.process_killed agent:9 target:win-01 user:"CORP\\alice" session:3 pid:200 name:"psexec.exe" path:"C\x3a\\Tools\\PsExec.exe" rule:1`) &&
			al.has(`probe.connection_blocked agent:9 target:win-01 user:"CORP\\alice" session:3 pid:300 name:"chrome.exe" path:"C\x3a\\Program Files\\Google\\Chrome\\chrome.exe" remote:"10.99.0.5\x3a445/tcp" rule:2`)
	})
	// The next snapshot reflects the terminations.
	waitFor(t, "post-enforcement snapshot", func() bool {
		_, s, _ := hub.Get(st.Key)
		return s != nil && len(s.Processes) == 2
	})

	// ForSession matches the credential's bare user name against the
	// session's domain-qualified one.
	if got := hub.ForSession("win-01", "alice"); len(got) != 1 || got[0].Key != st.Key {
		t.Fatalf("ForSession: %+v", got)
	}
	if got := hub.ForSession("win-01", "bob"); len(got) != 0 {
		t.Fatalf("ForSession(bob): %+v", got)
	}
	if got := hub.ForSession("other", "alice"); len(got) != 0 {
		t.Fatalf("ForSession(other): %+v", got)
	}

	// A kill command: explorer goes; svchost (another owner) is refused by
	// the platform and the refusal comes back as the error, audited.
	if err := hub.Kill(context.Background(), st.Key, 100); err != nil {
		t.Fatalf("kill 100: %v", err)
	}
	err := hub.Kill(context.Background(), st.Key, 400)
	if err == nil || !strings.Contains(err.Error(), "access is denied") {
		t.Fatalf("kill 400: %v, want the platform's refusal", err)
	}
	waitFor(t, "command audit", func() bool {
		return al.has(`probe.command_killed agent:9 target:win-01 user:"CORP\\alice" session:3 pid:100 command:1`) &&
			al.has(`probe.kill_failed agent:9 target:win-01 user:"CORP\\alice" session:3 pid:400 command:2 error:"access is denied"`)
	})

	// A policy refresh re-pushes rules and the probe scans at once: a new
	// rule catches a process the earlier policy allowed.
	pl.mu.Lock()
	pl.procs = append(pl.procs, Process{PID: 500, Name: "mimikatz.exe"})
	pl.mu.Unlock()
	rules = append(rules, Rule{ID: 3, Kind: RuleProcess, Match: "mimikatz*"})
	hub.RefreshPolicy(context.Background())
	waitFor(t, "new rule enforced", func() bool { return al.has(`pid:500 name:"mimikatz.exe" rule:3`) })
	if hub.List()[0].Rules != 3 {
		t.Fatalf("rules after refresh: %d", hub.List()[0].Rules)
	}

	// Kick drops the probe; Kill then reports it gone.
	if n := hub.Kick(9); n != 1 {
		t.Fatalf("kick: %d", n)
	}
	waitFor(t, "link removed", func() bool { return len(hub.List()) == 0 })
	if err := hub.Kill(context.Background(), st.Key, 100); !errors.Is(err, ErrProbeGone) {
		t.Fatalf("kill after kick: %v", err)
	}
}

func TestProbeRefusedWhenPolicyUnreadable(t *testing.T) {
	hub := NewHub(func(context.Context, int64) ([]Rule, error) { return nil, errors.New("db down") }, nil)
	srv, cli := net.Pipe()
	defer cli.Close()
	err := hub.Serve(context.Background(), Link{TargetID: 1}, srv, func(string, string) {})
	if err == nil || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("want fail-closed policy error, got %v", err)
	}
	if _, err := cli.Write([]byte("x")); err == nil {
		t.Fatal("probe side should have been closed")
	}
}

func TestNilHubIsNoop(t *testing.T) {
	var h *Hub
	if h.List() != nil || h.ForSession("a", "b") != nil || h.Kick(1) != 0 {
		t.Fatal("nil hub must be empty")
	}
	if err := h.Kill(context.Background(), 1, 1); !errors.Is(err, ErrProbeGone) {
		t.Fatal(err)
	}
	srv, cli := net.Pipe()
	defer cli.Close()
	if err := h.Serve(context.Background(), Link{}, srv, nil); err == nil {
		t.Fatal("nil hub must refuse to serve")
	}
}

func TestReadLineBounds(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	hub := NewHub(func(context.Context, int64) ([]Rule, error) { return nil, nil }, nil)
	done := make(chan error, 1)
	go func() { done <- hub.Serve(context.Background(), Link{}, srv, func(string, string) {}) }()
	// Drain the policy line the hub sends first, then feed an overlong one.
	buf := make([]byte, 1024)
	if _, err := cli.Read(buf); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = cli.Write([]byte(strings.Repeat("a", MaxLine+2) + "\n")) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("want a bounds error, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hub did not end on an overlong line")
	}
}
