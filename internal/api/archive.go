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
	events, err := s.store.ExportAudit(ctx, time.Time{}, cutoff)
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
	// auditor re-hashes the file and compares it against this event.
	s.audit(ctx, "audit.archived", fmt.Sprintf("file:%s count:%d sha256:%s older_than:%s",
		filepath.Base(path), len(events), digest, cutoff.UTC().Format(time.RFC3339)))
	return len(events), nil
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
		return fmt.Errorf("%w: %s", errArchiveExists, dst)
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

// archiveRecordingsBefore moves every recording older than cutoff into the
// archive directory, returning how many were archived. It stops at the first
// failure and returns it, so the caller can refuse to prune the rest — a
// half-archived sweep must not be mistaken for a completed one.
func (s *Server) archiveRecordingsBefore(ctx context.Context, dir string, cutoff time.Time) (int, error) {
	entries, err := os.ReadDir(s.recordingDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	moved := 0
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
		if err := archiveRecording(s.recordingDir, dir, e.Name()); err != nil {
			return moved, err
		}
		moved++
	}
	if moved > 0 {
		s.audit(ctx, "recording.archived", fmt.Sprintf("count:%d older_than:%s", moved, cutoff.UTC().Format(time.RFC3339)))
	}
	return moved, nil
}
