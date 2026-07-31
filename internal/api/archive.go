package api

// archive.go is the WORM half of retention (Phase 49). Phase 36 could delete
// aged audit rows and recordings; deleting evidence with nowhere for it to go
// is only acceptable when it has been written somewhere durable first. This
// exports what is about to be pruned into an archive directory the operator
// points at write-once storage (S3 Object Lock, an appliance, a WORM mount) —
// and, crucially, makes the prune CONDITIONAL on that export succeeding, so a
// broken or full archive costs disk space rather than the audit trail.
//
// pamv1 cannot make storage immutable from inside the process; that is the
// operator's mount. What it does guarantee is that every archived artifact is
// written once (never overwritten), read-only, and digest-stamped into the
// audit trail, so a later reader can prove the archive is the thing that was
// removed.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// errArchiveExists guards the write-once property: an archive file for a given
// cutoff already exists, so this pass would overwrite it.
var errArchiveExists = errors.New("archive file already exists")

// writeArchiveFile writes data to name under dir exactly once: it fails if the
// file exists (O_EXCL) and the result is read-only to its owner alone (0400),
// so a re-run cannot silently replace an archived artifact, a careless process
// cannot append to one, and the archived audit trail is no more readable than
// the live one. It returns the path and the SHA-256 of the bytes written.
func writeArchiveFile(dir, name string, data []byte) (string, string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if err != nil {
		if os.IsExist(err) {
			return "", "", fmt.Errorf("%w: %s", errArchiveExists, path)
		}
		return "", "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(path) // a partial archive must not look complete
		return "", "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", "", err
	}
	sum := sha256.Sum256(data)
	return path, hex.EncodeToString(sum[:]), nil
}

// archiveAuditBefore exports every audit event older than cutoff as JSON Lines
// into the archive directory and audits the export with its digest. It returns
// how many events were archived; zero means there was nothing to archive (not
// an error). Any failure is returned so the caller can refuse to prune.
//
// JSON Lines rather than one array: an archive is read by grep and by streaming
// tools long after the fact, and a truncated array is unparseable while a
// truncated JSONL file still yields every complete line before the break.
func (s *Server) archiveAuditBefore(ctx context.Context, dir string, cutoff time.Time) (int, error) {
	// Start from where the last archive finished, not from the beginning of time.
	//
	// Exporting [zero, cutoff) every pass is only harmless when the rows are
	// pruned afterwards. With the HMAC chain enabled they deliberately are not —
	// so each tick re-exported the entire aged trail under a new cutoff-derived
	// name, writing a fresh, slightly larger copy of the same history into
	// storage that is by this feature's own premise immutable and usually billed.
	// A year of daily ticks left hundreds of overlapping, undeletable exports.
	since, err := s.lastArchivedThrough(ctx)
	if err != nil {
		return 0, err
	}
	if !since.Before(cutoff) {
		return 0, nil // everything up to the cutoff is already archived
	}
	events, err := s.store.ExportAudit(ctx, since, cutoff)
	if err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return 0, nil
	}
	var buf []byte
	for i := range events {
		line, err := json.Marshal(events[i])
		if err != nil {
			return 0, err
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	name := fmt.Sprintf("audit-before-%s.jsonl", cutoff.UTC().Format("20060102T150405Z"))
	path, digest, err := writeArchiveFile(dir, name, buf)
	if err != nil {
		return 0, err
	}
	// The digest in the trail is what makes the archive verifiable later: an
	// auditor re-hashes the file and compares it against this event — and
	// lastArchivedThrough reads its high-water mark from the same event.
	//
	// So the error is RETURNED, not discarded. The caller's contract is
	// "archive failed => do not prune", and a dropped digest is an archive failure
	// in every way that matters: the rows would be deleted behind a file nothing
	// in the system attests to, which could then be swapped or truncated
	// undetectably, and the lost marker would silently widen the next window.
	if aerr := s.auditAs(ctx, actorFrom(ctx), "audit.archived", fmt.Sprintf("file:%s count:%d sha256:%s older_than:%s",
		filepath.Base(path), len(events), digest, cutoff.UTC().Format(time.RFC3339))); aerr != nil {
		return 0, fmt.Errorf("archive written to %s but its digest could not be audited, so the rows must not be pruned: %w", path, aerr)
	}
	return len(events), nil
}

// lastArchivedThrough returns the cutoff of the most recent successful audit
// archive, or the zero time if none has run.
//
// The high-water mark lives in the audit trail itself rather than in a new
// table: every archive already appends `audit.archived` with `older_than:<RFC
// 3339>`, which is exactly the fact needed, and it is a fact an auditor can see.
// A mark stored anywhere else could disagree with the archives that exist.
//
// A malformed or missing marker reads as "nothing archived yet", which
// re-exports more than necessary rather than skipping events — the safe
// direction to fail in for an archive.
func (s *Server) lastArchivedThrough(ctx context.Context) (time.Time, error) {
	// A targeted lookup, not a scan of recent events: on a busy deployment the
	// marker would fall off the end of any fixed page, and losing it means
	// re-exporting history that is already archived — the exact problem this is
	// here to prevent.
	e, err := s.store.LatestAuditByAction(ctx, "audit.archived")
	if err != nil {
		return time.Time{}, err
	}
	if e == nil {
		return time.Time{}, nil // nothing archived yet
	}
	for _, f := range strings.Fields(e.Detail) {
		if !strings.HasPrefix(f, "older_than:") {
			continue
		}
		ts, perr := time.Parse(time.RFC3339, strings.TrimPrefix(f, "older_than:"))
		if perr != nil {
			return time.Time{}, nil // unreadable marker: re-export rather than skip
		}
		return ts, nil
	}
	return time.Time{}, nil
}

// archiveRecording moves one recording into the archive directory instead of
// deleting it, preserving the artifact (and its hash-chain membership) under
// whatever immutability the archive mount provides. A cross-filesystem rename
// falls back to copy-then-remove. The archived file is made read-only (0400).
func archiveRecording(srcDir, dir, name string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	src := filepath.Join(srcDir, name)
	dst := filepath.Join(dir, name)
	if _, err := os.Stat(dst); err == nil {
		// The destination already exists. Usually that means a previous pass
		// copied the file and then failed to remove the source — the source and
		// destination are byte-identical and the move simply needs finishing.
		// Treating that as a hard error wedged archiving permanently: ReadDir
		// returns names sorted, recording names begin with a nanosecond
		// timestamp, and the sweep stopped at the first failure, so one stuck
		// file blocked every chronologically later recording forever.
		//
		// If the contents DIFFER, that is a genuine write-once violation and
		// still an error: two different recordings must never share a name.
		same, cerr := sameFileContents(src, dst)
		if cerr != nil {
			return cerr
		}
		if !same {
			return fmt.Errorf("%w: %s", errArchiveExists, dst)
		}
		return os.Remove(src) // finish the interrupted move
	}
	if err := os.Rename(src, dst); err == nil {
		_ = os.Chmod(dst, 0o400)
		return nil
	}
	// Different filesystems (the usual case when the archive is a WORM mount):
	// copy, then remove the original only once the copy is safely on disk.
	data, err := os.ReadFile(src) // #nosec G304 -- name is a validated recording file in the server's own directory
	if err != nil {
		return err
	}
	if _, _, err := writeArchiveFile(dir, name, data); err != nil {
		return err
	}
	return os.Remove(src)
}

// sameFileContents reports whether two files hold identical bytes. Used to tell
// an interrupted move (copy succeeded, remove did not) apart from a genuine
// name collision between two different recordings.
func sameFileContents(a, b string) (bool, error) {
	da, err := os.ReadFile(a) // #nosec G304 -- both names are validated recording files in directories the server owns
	if err != nil {
		return false, err
	}
	db, err := os.ReadFile(b) // #nosec G304 -- see above
	if err != nil {
		return false, err
	}
	return sha256.Sum256(da) == sha256.Sum256(db), nil
}

// archiveRecordingsBefore moves every recording older than cutoff into the
// archive directory, returning how many were archived.
//
// It continues past a failing file and returns the accumulated errors, rather
// than stopping at the first one. Both halves matter: returning an error keeps
// the caller's refusal to prune a half-archived sweep, while continuing means a
// single unarchivable file no longer blocks every chronologically later
// recording — ReadDir returns names sorted and recording names lead with a
// nanosecond timestamp, so aborting at the first failure was effectively
// permanent for everything after it.
func (s *Server) archiveRecordingsBefore(ctx context.Context, dir string, cutoff time.Time) (int, error) {
	entries, err := os.ReadDir(s.recordingDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	moved := 0
	var failures []error
	for _, e := range entries {
		// Same filter as the pruner: dotfiles (the .chain head) and unrelated
		// files are never touched.
		if e.IsDir() || !recordingNameRe.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		if aerr := archiveRecording(s.recordingDir, dir, e.Name()); aerr != nil {
			s.log.Error("recording archive failed", "file", e.Name(), "err", aerr)
			failures = append(failures, fmt.Errorf("%s: %w", e.Name(), aerr))
			continue
		}
		moved++
	}
	if len(failures) > 0 {
		// Report every failure, not just the first: an operator fixing a WORM
		// mount wants the whole list, and the caller still refuses to prune.
		return moved, errors.Join(failures...)
	}
	if moved > 0 {
		s.audit(ctx, "recording.archived", fmt.Sprintf("count:%d older_than:%s", moved, cutoff.UTC().Format(time.RFC3339)))
	}
	return moved, nil
}
