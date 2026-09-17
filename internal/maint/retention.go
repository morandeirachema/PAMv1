package maint

// retention.go bounds the on-disk growth of session recordings. A recording is a
// file per session (an asciicast `.cast` or a WinRM `.winrm.log`) or per
// transferred file (an SFTP content-capture `.sftp` chunk log, Phase 59); left
// alone the directory grows without limit. PruneRecordings deletes those older
// than a cutoff, deliberately preserving dotfiles — notably the `.chain` head
// that anchors the recordings' tamper-evident hash chain — and any
// non-recording file, so a retention sweep can never corrupt the chain or touch
// an unrelated file.

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// recordingExts are the file extensions PruneRecordings will delete. Anything
// else in the directory (dotfiles like `.chain`, stray files) is left untouched.
//
// The list must name EVERY kind the recording directory holds — the API's
// recordingNameRe is the other copy, and TestRetentionCoversEveryRecordingKind
// holds the two together. It had stopped at the first three, so exec
// transcripts (.ssh.log, .k8s.log), forensic reconstructions and RDP/VNC
// recordings (.guac, Phase 258) were never pruned: PAM_RECORDING_RETENTION_DAYS
// silently did not apply to them.
var recordingExts = []string{".cast", ".winrm.log", ".ssh.log", ".k8s.log", ".forensics.log", ".sftp", ".guac"}

// IsRecording reports whether retention treats name as a recording.
func IsRecording(name string) bool { return isRecording(name) }

// isRecording reports whether name is a prunable recording file: a non-dotfile
// whose name ends in a known recording extension.
func isRecording(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") {
		return false
	}
	for _, ext := range recordingExts {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// PruneRecordings deletes recording files in dir whose modification time is
// before cutoff, returning how many were removed. A missing directory is not an
// error (nothing to prune). Errors deleting an individual file are collected and
// returned after the sweep completes, so one un-removable file does not abort the
// rest.
func PruneRecordings(dir string, cutoff time.Time) (int, error) {
	if dir == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	var firstErr error
	for _, e := range entries {
		if e.IsDir() || !isRecording(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !info.ModTime().Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		removed++
	}
	return removed, firstErr
}
