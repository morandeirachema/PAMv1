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

// TestSweepEndsASessionOnce proves the lifetime monitor ends a session once,
// however long its handler takes to unwind (Phase 248). kill() only asks the
// handler to stop; the entry leaves the registry when that handler's own
// deferred Remove runs, which for a brokered command can be minutes. Before
// the fix every 5-second tick re-selected the same session, so one ending was
// killed and audited dozens of times.
func TestSweepEndsASessionOnce(t *testing.T) {
	r := NewRegistry()
	var kills, audits int
	cfg := LifetimeConfig{
		MaxDuration: time.Minute,
		Audit:       func(context.Context, string, string) { audits++ },
	}
	started := time.Now().Add(-time.Hour)
	sid := r.Register(Info{Actor: "alice", Target: "db", Started: started}, func() { kills++ })
	// The handler is blocked, so the entry stays registered across ticks.
	for i := 0; i < 5; i++ {
		r.SweepLifetimes(t.Context(), time.Now(), cfg)
	}
	if kills != 1 || audits != 1 {
		t.Fatalf("a blocked handler must be ended once: kills=%d audits=%d", kills, audits)
	}
	// It is still listed while it unwinds, and ending it is still the
	// handler's own job.
	if len(r.List()) != 1 {
		t.Fatalf("a swept session stays listed until its handler removes it")
	}
	r.Remove(sid)
	if len(r.List()) != 0 {
		t.Fatal("Remove must still work on a swept session")
	}
}
