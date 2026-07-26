package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// newRetentionServer builds a minimal Server with a recording directory.
func newRetentionServer(t *testing.T, recDir string) (*Server, store.Store) {
	t.Helper()
	key, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	st := memstore.New()
	resolver, err := auth.NewResolver(st, "k", "")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, v, resolver, nil, Options{RecordingDir: recDir})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

// TestRetentionPassPrunesRecordings proves the pass removes aged recordings and
// audits the count.
func TestRetentionPassPrunesRecordings(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-72 * time.Hour)
	p := filepath.Join(dir, "1_web_alice.cast")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(p, old, old)

	srv, st := newRetentionServer(t, dir)
	srv.retentionPass(context.Background(), time.Now(), RetentionPolicy{RecordingDays: 1})

	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("aged recording was not pruned")
	}
	if auditActions(t, st)["recording.pruned"] == 0 {
		t.Fatal("recording prune was not audited")
	}
}

// TestRetentionPassPrunesAudit proves audit rows older than the cutoff are
// deleted (unchained store) and the prune is itself audited.
func TestRetentionPassPrunesAudit(t *testing.T) {
	srv, st := newRetentionServer(t, t.TempDir())
	ctx := context.Background()
	for _, a := range []string{"target.create", "credential.reveal"} {
		st.AppendAudit(ctx, &store.AuditEvent{Actor: "a", Action: a, Detail: "d"})
	}
	// A "now" in the future makes the cutoff (now - 1 day) still later than the
	// just-appended events, so they fall before it and are pruned.
	srv.retentionPass(ctx, time.Now().Add(72*time.Hour), RetentionPolicy{AuditDays: 1})

	acts := auditActions(t, st)
	if acts["target.create"] != 0 || acts["credential.reveal"] != 0 {
		t.Fatalf("aged audit rows were not pruned: %v", acts)
	}
	if acts["audit.pruned"] == 0 {
		t.Fatal("audit prune was not itself audited")
	}
}

// TestRetentionPassSkipsChainedAudit proves audit pruning is refused when the
// tamper-evident HMAC chain is enabled, so verification is never broken.
func TestRetentionPassSkipsChainedAudit(t *testing.T) {
	srv, st := newRetentionServer(t, t.TempDir())
	ctx := context.Background()
	st.AppendAudit(ctx, &store.AuditEvent{Actor: "a", Action: "target.create", Detail: "d"})

	srv.retentionPass(ctx, time.Now().Add(72*time.Hour), RetentionPolicy{AuditDays: 1, AuditChained: true})

	acts := auditActions(t, st)
	if acts["target.create"] == 0 {
		t.Fatal("chained audit rows must NOT be pruned (would break verification)")
	}
	if acts["audit.pruned"] != 0 {
		t.Fatal("no prune should have happened for a chained trail")
	}
}

// TestRetentionWorkerNoop proves the worker returns immediately when nothing is
// configured to prune (no goroutine leak, no panic).
func TestRetentionWorkerNoop(t *testing.T) {
	srv, _ := newRetentionServer(t, t.TempDir())
	done := make(chan struct{})
	go func() {
		srv.RunRetentionWorker(context.Background(), time.Hour, RetentionPolicy{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunRetentionWorker with an empty policy should return immediately")
	}
}
