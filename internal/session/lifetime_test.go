package session

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSweepLifetimes proves the three lifetime bounds (Phase 240) end exactly
// the sessions they should, each audited with its own reason, and that
// operator input resets the idle clock.
func TestSweepLifetimes(t *testing.T) {
	r := NewRegistry()
	var mu sync.Mutex
	killed := map[string]bool{}
	var audits []string
	cfg := LifetimeConfig{MaxDuration: time.Hour, IdleTimeout: 10 * time.Minute, Audit: func(_ context.Context, action, detail string) {
		mu.Lock()
		audits = append(audits, action+" "+detail)
		mu.Unlock()
	}}
	start := time.Now()
	reg := func(name string, started time.Time, deadline *time.Time, reason string) string {
		return r.Register(Info{Actor: name, Target: "t", Started: started, Deadline: deadline, DeadlineReason: reason}, func() {
			mu.Lock()
			killed[name] = true
			mu.Unlock()
		})
	}
	dl := start.Add(30 * time.Minute)
	reg("fresh", start, nil, "")
	reg("old", start.Add(-2*time.Hour), nil, "")
	idle := reg("idle", start.Add(-20*time.Minute), nil, "")
	busy := reg("busy", start.Add(-20*time.Minute), nil, "")
	reg("framed", start, &dl, "time-frame")

	// Nothing has happened yet at start+1m except "old" (2h > 1h max) and the
	// two idle candidates; "busy" typed just now.
	r.Activity(busy)()
	_ = idle
	n := r.SweepLifetimes(context.Background(), start.Add(time.Minute), cfg)
	mu.Lock()
	defer mu.Unlock()
	if n != 2 || !killed["old"] || !killed["idle"] || killed["busy"] || killed["fresh"] || killed["framed"] {
		t.Fatalf("first sweep killed %v (n=%d)", killed, n)
	}
	mu.Unlock()
	// At the frame's edge the framed session ends with the grant's reason. The
	// deployment-wide bounds are dropped for this sweep so the sessions the
	// first pass already ended (a real proxy removes itself on kill; this test
	// keeps them registered) are not counted twice.
	n = r.SweepLifetimes(context.Background(), dl, LifetimeConfig{Audit: cfg.Audit})
	mu.Lock()
	if n != 1 || !killed["framed"] {
		t.Fatalf("deadline sweep killed %v (n=%d)", killed, n)
	}
	joined := strings.Join(audits, "\n")
	for _, want := range []string{"actor:old target:t reason:max-duration", "actor:idle target:t reason:idle-timeout", "actor:framed target:t reason:time-frame"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("audit missing %q in:\n%s", want, joined)
		}
	}
	if r.Activity("nope") == nil {
		t.Fatal("Activity must return a usable no-op for an unknown session")
	}
}
