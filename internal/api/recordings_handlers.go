package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// --- session-recording playback (Phase 26) ---
//
// Recordings are written to disk by the SSH/WinRM/PostgreSQL proxies (asciicast
// .cast) and the WinRM run endpoint (.winrm.log transcripts); their SHA-256 is
// written to the audit trail as they close. These handlers are the replay side:
// list what is stored and serve one recording, recomputing its hash and
// reporting whether that hash appears in the audit trail — so a file tampered
// on disk is visibly flagged at playback.

// recordingMaxList caps the playback listing at the newest entries; the full
// archive stays on disk.
const recordingMaxList = 500

// recordingNameRe matches the filenames the recorders produce (the sanitized
// alphabet plus the .cast / .winrm.log suffixes). Anything else — a path
// separator, a dotfile like the .chain head — is refused, which also
// forecloses traversal: no accepted name can leave the recording directory.
var recordingNameRe = regexp.MustCompile(`^[A-Za-z0-9_@-][A-Za-z0-9._@-]*\.(cast|winrm\.log)$`)

// recordingInfo is one stored session recording in the playback listing.
type recordingInfo struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	Kind     string    `json:"kind"` // asciicast (timed replay) | transcript (plain text)
}

// recordingKind classifies a recording filename for the listing/player:
// asciicast files replay with timing, transcripts render at once.
func recordingKind(name string) string {
	if strings.HasSuffix(name, ".winrm.log") {
		return "transcript"
	}
	return "asciicast"
}

// listRecordings returns the stored session recordings, newest first. A missing
// or unconfigured recording directory lists as empty rather than erroring, so
// the console screen degrades gracefully on a fresh deploy. Requires CapReadAudit.
func (s *Server) listRecordings(w http.ResponseWriter, r *http.Request) {
	out := []recordingInfo{}
	entries, err := os.ReadDir(s.recordingDir)
	if err != nil {
		if s.recordingDir == "" || os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, out)
			return
		}
		writeError(w, http.StatusInternalServerError, "recordings unavailable")
		return
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !recordingNameRe.MatchString(e.Name()) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, recordingInfo{
			Name: e.Name(), Size: fi.Size(), Modified: fi.ModTime().UTC(), Kind: recordingKind(e.Name()),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Modified.After(out[j].Modified) })
	if len(out) > recordingMaxList {
		out = out[:recordingMaxList]
	}
	writeJSON(w, http.StatusOK, out)
}

// playRecording serves one stored recording for replay. Before any byte leaves,
// the file's SHA-256 is recomputed and checked against the audit trail (the
// value stamped by session.record / winrm.run when the recording was written) —
// the verdict travels in X-PAM-Recording-Audited so the player can flag a
// tampered or never-audited file — and the playback itself is audited
// (session.playback). The hash and the served body cover the same byte range,
// so a recording still being written replays as a consistent prefix. Requires
// CapReadAudit.
func (s *Server) playRecording(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !recordingNameRe.MatchString(name) {
		writeError(w, http.StatusUnprocessableEntity, "not a recording name")
		return
	}
	f, err := os.Open(filepath.Join(s.recordingDir, name))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such recording")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		writeError(w, http.StatusNotFound, "no such recording")
		return
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.NewSectionReader(f, 0, fi.Size())); err != nil {
		writeError(w, http.StatusInternalServerError, "recording unreadable")
		return
	}
	sum := hex.EncodeToString(hasher.Sum(nil))

	// Tamper evidence: does this exact hash appear in the audit trail? Proxied
	// sessions audit session.record; WinRM run transcripts audit winrm.run.
	audited := false
	for _, action := range []string{"session.record", "winrm.run"} {
		if ok, ferr := s.store.FindAuditDetail(r.Context(), action, "sha256:"+sum); ferr == nil && ok {
			audited = true
			break
		}
	}

	s.audit(r.Context(), "session.playback",
		fmt.Sprintf("file:%s bytes:%d sha256:%s audited:%t", name, fi.Size(), sum, audited))

	contentType := "application/x-asciicast; charset=utf-8"
	if recordingKind(name) == "transcript" {
		contentType = "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-PAM-Recording-SHA256", sum)
	w.Header().Set("X-PAM-Recording-Audited", strconv.FormatBool(audited))
	http.ServeContent(w, r, "", fi.ModTime(), io.NewSectionReader(f, 0, fi.Size()))
}
