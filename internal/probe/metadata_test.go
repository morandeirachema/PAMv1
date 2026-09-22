package probe

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// memArtifacts collects artifacts in memory.
type memArtifacts struct {
	mu    sync.Mutex
	lines []string
	fail  bool
}

type memArtifact struct{ a *memArtifacts }

func (m *memArtifacts) Open(Link) (Artifact, error) {
	if m.fail {
		return nil, errors.New("disk full")
	}
	return &memArtifact{a: m}, nil
}
func (m *memArtifact) WriteLine(line []byte) error {
	m.a.mu.Lock()
	m.a.lines = append(m.a.lines, string(line))
	m.a.mu.Unlock()
	return nil
}
func (m *memArtifact) Close() string { return "file:mem bytes:1 sha256:abc chain:def" }
func (m *memArtifacts) has(sub string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range m.lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// fgPlatform is fakePlatform plus a scripted foreground window.
type fgPlatform struct {
	*fakePlatform
	mu sync.Mutex
	fg Window
}

func (f *fgPlatform) Foreground() (Window, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fg, f.fg.PID != 0
}

// TestProbeMetadataAndNotify (Phase 271): process start/end and foreground
// changes reach the artifact and never the audit trail; a notify rule
// reports its match to both and leaves the process running; the artifact is
// closed and audited when the probe leaves.
func TestProbeMetadataAndNotify(t *testing.T) {
	base := &fakePlatform{procs: []Process{{PID: 100, Name: "explorer.exe"}, {PID: 200, Name: "cmd.exe"}}}
	pl := &fgPlatform{fakePlatform: base, fg: Window{PID: 100, Title: "Desktop"}}
	rules := []Rule{{ID: 1, Kind: RuleProcess, Match: "cmd.exe", Action: ActionNotify}}
	art := &memArtifacts{}
	hub := NewHub(func(context.Context, int64) ([]Rule, error) { return rules, nil }, nil)
	hub.Artifacts = art
	al := &auditLog{}
	srv, cli := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	hello, _ := pl.Identity()
	served := make(chan error, 1)
	go func() {
		served <- hub.Serve(ctx, Link{AgentID: 9, AgentName: "p", TargetID: 42, TargetName: "win-01", Hello: hello}, srv, al.add)
	}()
	go func() { _ = Serve(ctx, cli, pl, Options{Interval: 20 * time.Millisecond}) }()

	// The notify rule matches cmd.exe every scan: audited, in the artifact,
	// and cmd.exe is still there.
	waitFor(t, "notify audit", func() bool {
		return al.has(`probe.rule_notified agent:9 target:win-01 user:"CORP\\alice" session:3 pid:200 name:"cmd.exe" rule:1`)
	})
	if len(pl.killedPIDs()) != 0 {
		t.Fatal("a notify rule must not kill")
	}
	waitFor(t, "notify in artifact", func() bool { return art.has(`"kind":"rule_notified"`) && art.has(`"probe":{"agent_id":9`) })

	// A new process and a foreground change: artifact lines, no audit rows.
	pl.fakePlatform.mu.Lock()
	pl.fakePlatform.procs = append(pl.fakePlatform.procs, Process{PID: 300, Name: "notepad.exe", CommandLine: "notepad.exe C:\\secret.txt"})
	pl.fakePlatform.mu.Unlock()
	pl.mu.Lock()
	pl.fg = Window{PID: 300, Title: "secret.txt - Notepad"}
	pl.mu.Unlock()
	waitFor(t, "process_started", func() bool { return art.has(`"kind":"process_started"`) && art.has(`notepad.exe C:\\secret.txt`) })
	waitFor(t, "foreground_window", func() bool { return art.has(`"kind":"foreground_window"`) && art.has(`secret.txt - Notepad`) })
	// Then it ends.
	if err := base.Kill(context.Background(), 300); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "process_ended", func() bool { return art.has(`"kind":"process_ended"`) })
	al.mu.Lock()
	for _, r := range al.rows {
		if strings.Contains(r, "process_started") || strings.Contains(r, "foreground_window") || strings.Contains(r, "process_ended") {
			t.Fatalf("metadata reached the audit trail: %s", r)
		}
	}
	al.mu.Unlock()
	// The last snapshot names the foreground window.
	waitFor(t, "snapshot foreground", func() bool {
		_, s, ok := hub.Get(hub.List()[0].Key)
		return ok && s != nil && s.Foreground != nil && s.Foreground.PID == 300
	})

	// Disconnect: the artifact is closed and audited.
	cancel()
	cli.Close()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("hub did not return")
	}
	if !al.has("probe.record agent:9 target:win-01") || !al.has("file:mem bytes:1 sha256:abc chain:def") {
		t.Fatalf("probe.record not audited: %v", al.rows)
	}
	// Every artifact line is valid JSON.
	art.mu.Lock()
	for _, l := range art.lines {
		var v map[string]any
		if err := json.Unmarshal([]byte(l), &v); err != nil {
			t.Fatalf("artifact line is not JSON: %s", l)
		}
	}
	art.mu.Unlock()
}

// TestProbeRefusedWhenArtifactUnavailable: no record, no probe.
func TestProbeRefusedWhenArtifactUnavailable(t *testing.T) {
	hub := NewHub(func(context.Context, int64) ([]Rule, error) { return nil, nil }, nil)
	hub.Artifacts = &memArtifacts{fail: true}
	srv, cli := net.Pipe()
	defer cli.Close()
	// The policy push precedes the artifact open and a pipe write blocks
	// until read: drain the probe side so the refusal can happen.
	go func() { _, _ = io.Copy(io.Discard, cli) }()
	err := hub.Serve(context.Background(), Link{TargetID: 1}, srv, func(string, string) {})
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("want artifact error, got %v", err)
	}
}

func TestRuleValidateAction(t *testing.T) {
	if err := (Rule{Kind: RuleProcess, Match: "x", Action: "block"}).Validate(); err == nil {
		t.Fatal("unknown action accepted")
	}
	if err := (Rule{Kind: RuleProcess, Match: "x", Action: ActionNotify}).Validate(); err != nil {
		t.Fatal(err)
	}
}
