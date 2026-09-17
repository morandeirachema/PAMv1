package maint_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/maint"
)

// write creates a file in dir with the given modification time.
func write(t *testing.T, dir, name string, modTime time.Time) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, modTime, modTime); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPruneRecordings proves old recording files are removed while the chain head
// dotfile, recent recordings, and unrelated files are preserved.
func TestPruneRecordings(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	recent := now.Add(-1 * time.Hour)

	oldCast := write(t, dir, "111_web-01_alice.cast", old)
	oldWinRM := write(t, dir, "222_win_bob.winrm.log", old)
	oldSFTP := write(t, dir, "111_web-01_alice_f0.sftp", old) // captured SFTP content (Phase 59)
	// Every kind the recordings directory holds ages out (Phase 264): the list
	// here had stopped at the three above, so exec transcripts, forensic
	// reconstructions and desktop recordings were kept forever.
	var oldRest []string
	for _, n := range []string{"444_win-rdp_dave.guac", "555_lin_erin.ssh.log", "666_k8s_fay.k8s.log", "777_web-01_gil.forensics.log"} {
		oldRest = append(oldRest, write(t, dir, n, old))
	}
	newCast := write(t, dir, "333_web-01_carol.cast", recent)
	newSFTP := write(t, dir, "333_web-01_carol_f0.sftp", recent)
	chain := write(t, dir, ".chain", old)        // the hash-chain head — a dotfile
	other := write(t, dir, "notes.txt", old)     // a non-recording file
	dotOld := write(t, dir, ".hidden.cast", old) // dotfile masquerading as a recording

	removed, err := maint.PruneRecordings(dir, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 7 {
		t.Fatalf("removed %d, want 7 (every old recording, of every kind)", removed)
	}
	for _, p := range append([]string{oldCast, oldWinRM, oldSFTP}, oldRest...) {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be pruned", filepath.Base(p))
		}
	}
	for _, p := range []string{newCast, newSFTP, chain, other, dotOld} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s to be preserved: %v", filepath.Base(p), err)
		}
	}
}

// TestPruneRecordingsMissingDir proves a missing directory is not an error.
func TestPruneRecordingsMissingDir(t *testing.T) {
	if n, err := maint.PruneRecordings(filepath.Join(t.TempDir(), "nope"), time.Now()); err != nil || n != 0 {
		t.Fatalf("missing dir: n=%d err=%v, want 0/nil", n, err)
	}
	if n, err := maint.PruneRecordings("", time.Now()); err != nil || n != 0 {
		t.Fatalf("empty dir: n=%d err=%v, want 0/nil", n, err)
	}
}
