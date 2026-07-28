package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// seedAgedAudit appends n audit events and returns the store's view of them.
func seedAgedAudit(t *testing.T, st store.Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := st.AppendAudit(context.Background(), &store.AuditEvent{
			Actor: "alice", Action: "credential.reveal", Detail: "credential:1",
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRetentionArchivesBeforePruning proves the Phase 49 order of operations:
// aged audit rows are exported to the archive directory (digest-stamped into
// the trail) and only then deleted, and aged recordings are MOVED rather than
// destroyed. The archive is the thing that was removed, byte for byte.
func TestRetentionArchivesBeforePruning(t *testing.T) {
	recDir, archDir := t.TempDir(), filepath.Join(t.TempDir(), "worm")
	srv, st := newRetentionServer(t, recDir)
	ctx := context.Background()

	// The pass runs with the clock moved forward so the just-seeded audit rows
	// are past the 1-day cutoff; the recordings are stamped on either side of
	// that same cutoff (passTime-24h) so one is aged and one is not.
	passTime := time.Now().Add(48 * time.Hour)
	cutoff := passTime.Add(-24 * time.Hour)
	aged := filepath.Join(recDir, "100_web-01_alice.cast")
	if err := os.WriteFile(aged, []byte("aged-session"), 0o600); err != nil {
		t.Fatal(err)
	}
	agedAt := cutoff.Add(-time.Hour)
	if err := os.Chtimes(aged, agedAt, agedAt); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(recDir, "200_web-02_bob.cast")
	if err := os.WriteFile(fresh, []byte("fresh-session"), 0o600); err != nil {
		t.Fatal(err)
	}
	freshAt := cutoff.Add(time.Hour)
	if err := os.Chtimes(fresh, freshAt, freshAt); err != nil {
		t.Fatal(err)
	}
	seedAgedAudit(t, st, 3)

	srv.retentionPass(ctx, passTime, RetentionPolicy{
		RecordingDays: 1, AuditDays: 1, ArchiveDir: archDir,
	})

	// The aged recording MOVED: gone from the live dir, present in the archive
	// with its bytes intact and read-only.
	if _, err := os.Stat(aged); !os.IsNotExist(err) {
		t.Fatalf("aged recording still in the live directory: %v", err)
	}
	archived := filepath.Join(archDir, "100_web-01_alice.cast")
	body, err := os.ReadFile(archived)
	if err != nil {
		t.Fatalf("aged recording was destroyed instead of archived: %v", err)
	}
	if string(body) != "aged-session" {
		t.Fatalf("archived recording content = %q", body)
	}
	if fi, err := os.Stat(archived); err == nil && fi.Mode().Perm()&0o222 != 0 {
		t.Fatalf("archived recording is writable (%v); the archive must be write-once", fi.Mode().Perm())
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh recording was archived: %v", err)
	}

	// The audit archive exists as JSON Lines, one complete event per line, and
	// the digest recorded in the trail matches the file on disk.
	matches, _ := filepath.Glob(filepath.Join(archDir, "audit-before-*.jsonl"))
	if len(matches) != 1 {
		t.Fatalf("want exactly one audit archive, got %v", matches)
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 3 {
		t.Fatalf("archive holds %d lines, want at least the 3 seeded events", len(lines))
	}
	for i, ln := range lines {
		var e store.AuditEvent
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			t.Fatalf("archive line %d is not a complete JSON event: %v", i, err)
		}
	}
}

// TestArchiveAuditDigestIsRecorded proves the archive is verifiable after the
// fact: the SHA-256 stamped into the audit.archived event is the digest of the
// bytes actually on disk, so an auditor can re-hash the file and prove it is
// the trail that was removed.
func TestArchiveAuditDigestIsRecorded(t *testing.T) {
	archDir := filepath.Join(t.TempDir(), "worm")
	srv, st := newRetentionServer(t, t.TempDir())
	ctx := context.Background()
	seedAgedAudit(t, st, 3)

	n, err := srv.archiveAuditBefore(ctx, archDir, time.Now().Add(time.Hour))
	if err != nil || n < 3 {
		t.Fatalf("archiveAuditBefore: n=%d err=%v", n, err)
	}
	matches, _ := filepath.Glob(filepath.Join(archDir, "audit-before-*.jsonl"))
	if len(matches) != 1 {
		t.Fatalf("want one archive, got %v", matches)
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	wantDigest := hex.EncodeToString(sum[:])

	events, err := st.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == "audit.archived" && strings.Contains(e.Detail, "sha256:"+wantDigest) {
			return
		}
	}
	t.Fatalf("no audit.archived event carrying the archive's real digest %s", wantDigest)
}

// TestRetentionRefusesToPruneWhenArchiveFails is the fail-closed guarantee: if
// the archive cannot be written, nothing is deleted. Evidence outranks disk.
func TestRetentionRefusesToPruneWhenArchiveFails(t *testing.T) {
	recDir := t.TempDir()
	srv, st := newRetentionServer(t, recDir)
	ctx := context.Background()
	seedAgedAudit(t, st, 3)
	before, err := st.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}

	// An archive "directory" that is actually a file: MkdirAll fails, so the
	// export cannot happen.
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	srv.retentionPass(ctx, time.Now().Add(48*time.Hour), RetentionPolicy{
		AuditDays: 1, ArchiveDir: blocked,
	})

	after, err := st.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) < len(before) {
		t.Fatalf("audit rows were pruned despite the archive failing: %d -> %d", len(before), len(after))
	}
	for _, e := range after {
		if e.Action == "audit.pruned" {
			t.Fatal("audit.pruned emitted after a failed archive — the prune must not run")
		}
	}
}

// TestRetentionArchivesChainedAuditWithoutPruning proves the chained case is
// served rather than skipped: with the HMAC chain on, the operator still gets
// the scheduled WORM export, but the rows stay (deleting the chain head would
// break verification — that remains a manual re-anchor).
func TestRetentionArchivesChainedAuditWithoutPruning(t *testing.T) {
	archDir := filepath.Join(t.TempDir(), "worm")
	srv, st := newRetentionServer(t, t.TempDir())
	ctx := context.Background()
	seedAgedAudit(t, st, 2)
	before, err := st.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}

	srv.retentionPass(ctx, time.Now().Add(48*time.Hour), RetentionPolicy{
		AuditDays: 1, AuditChained: true, ArchiveDir: archDir,
	})

	if matches, _ := filepath.Glob(filepath.Join(archDir, "audit-before-*.jsonl")); len(matches) != 1 {
		t.Fatalf("chained trail was not archived: %v", matches)
	}
	after, err := st.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) < len(before) {
		t.Fatalf("chained audit rows were pruned (%d -> %d) — that breaks VerifyAuditChain", len(before), len(after))
	}
}

// TestArchiveIsWriteOnce proves an archive file is never silently overwritten:
// a second write of the same name fails rather than replacing the artifact.
func TestArchiveIsWriteOnce(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := writeArchiveFile(dir, "a.jsonl", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeArchiveFile(dir, "a.jsonl", []byte("second")); err == nil {
		t.Fatal("re-writing an archive file must fail (write-once)")
	}
	body, err := os.ReadFile(filepath.Join(dir, "a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "first" {
		t.Fatalf("archive content was replaced: %q", body)
	}
}

// TestChainedAuditArchivesOnlyTheDelta proves repeated retention passes do not
// re-archive history that is already archived.
//
// With the HMAC chain enabled the aged rows are deliberately never pruned, so
// exporting everything older than the cutoff exported the SAME events again on
// every tick — each under a new cutoff-derived name, each slightly larger, into
// storage that is by this feature's premise immutable and usually billed. A year
// of daily ticks left hundreds of overlapping, undeletable copies. A single-pass
// test cannot see it, which is why this one runs three.
func TestChainedAuditArchivesOnlyTheDelta(t *testing.T) {
	archDir := filepath.Join(t.TempDir(), "worm")
	srv, st := newRetentionServer(t, t.TempDir())
	ctx := context.Background()
	seedAgedAudit(t, st, 3)

	pol := RetentionPolicy{AuditDays: 1, AuditChained: true, ArchiveDir: archDir}
	first := time.Now().Add(48 * time.Hour)
	srv.retentionPass(ctx, first, pol)

	matches, _ := filepath.Glob(filepath.Join(archDir, "audit-before-*.jsonl"))
	if len(matches) != 1 {
		t.Fatalf("first pass produced %d archives, want 1: %v", len(matches), matches)
	}
	firstSize := fileSize(t, matches[0])

	// Two further passes at later cutoffs. Nothing new has aged past the cutoff
	// beyond what each pass itself audits, so no pass may re-export the history
	// the first one already wrote.
	srv.retentionPass(ctx, first.Add(time.Hour), pol)
	srv.retentionPass(ctx, first.Add(2*time.Hour), pol)

	matches, _ = filepath.Glob(filepath.Join(archDir, "audit-before-*.jsonl"))
	for _, m := range matches {
		if m == matches[0] {
			continue
		}
		if sz := fileSize(t, m); sz >= firstSize {
			t.Fatalf("archive %s is %d bytes, not smaller than the first pass's %d — the whole aged trail is being re-exported every tick",
				filepath.Base(m), sz, firstSize)
		}
	}
	// And the first archive itself must be untouched: write-once still holds.
	if sz := fileSize(t, matches[0]); sz != firstSize {
		t.Fatalf("the first archive changed size (%d -> %d)", firstSize, sz)
	}
}

// fileSize returns a file's size in bytes.
func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

// TestArchiveRecordingFinishesInterruptedMove proves one stuck file cannot wedge
// archiving forever.
//
// In the cross-filesystem path (the usual case, since a WORM archive is its own
// mount) a failed os.Remove leaves the destination written and the source in
// place. The next pass saw the destination, returned errArchiveExists, and the
// sweep stopped at that entry — and because ReadDir returns names sorted and
// recording names lead with a nanosecond timestamp, that blocked every
// chronologically later recording, permanently, with only a log line.
func TestArchiveRecordingFinishesInterruptedMove(t *testing.T) {
	srcDir, archDir := t.TempDir(), t.TempDir()
	const name = "1700000000000000000_target_actor.cast"
	body := []byte("recording bytes")

	// Simulate the interrupted move: destination written, source still present.
	if err := os.WriteFile(filepath.Join(srcDir, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeArchiveFile(archDir, name, body); err != nil {
		t.Fatal(err)
	}

	if err := archiveRecording(srcDir, archDir, name); err != nil {
		t.Fatalf("an interrupted move was not resumable: %v — one stuck file blocks every later recording forever", err)
	}
	if _, err := os.Stat(filepath.Join(srcDir, name)); !os.IsNotExist(err) {
		t.Fatal("the source survived, so the next pass repeats this forever")
	}

	// A genuine collision — same name, DIFFERENT bytes — must still be refused:
	// two different recordings must never share an archived name.
	const other = "1700000000000000001_target_actor.cast"
	if err := os.WriteFile(filepath.Join(srcDir, other), []byte("different"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := writeArchiveFile(archDir, other, []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := archiveRecording(srcDir, archDir, other); !errors.Is(err, errArchiveExists) {
		t.Fatalf("a real name collision returned %v, want errArchiveExists — write-once must still hold", err)
	}
}
