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

	"github.com/morandeirachema/pamv1/internal/store"
	"time"

	"github.com/morandeirachema/pamv1/internal/recording"
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
// Target and Actor are resolved from the audit trail rather than parsed out of
// the file name (Phase 48): with PAM_RECORDING_OPAQUE_NAMES the name carries no
// metadata at all, so the audited session.record / winrm.run event is the only
// place that mapping exists. They are empty when no audit event names the file.
type recordingInfo struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	Kind     string    `json:"kind"` // asciicast (timed replay) | transcript (plain text)
	Target   string    `json:"target,omitempty"`
	Actor    string    `json:"actor,omitempty"`
}

// recordingOwners maps recording file names to the target and actor recorded in
// the audit trail. The recorders write `file:<path-or-name>` into
// session.record / winrm.run, so this reverses that: it reads a window of recent
// audit events and indexes by base name (the SSH proxy logs a full path, the DB
// proxy and WinRM log a bare name — indexing by base covers all three).
//
// `want` is the set of file names the listing actually needs. It lets the scan
// stop as soon as every one is resolved, which is the common case: the listing
// shows the newest recordings, and their audit events are the newest too. The
// window is bounded by store.MaxAuditPage so one console request can never pull
// an unbounded slice of the audit table into memory.
//
// The bound used to be a bare 2000, which was worse than it looked: pgstore
// silently answered any request above 500 with 100 events, so this resolved
// owners for the newest hundred events in production while resolving all 2000
// against the in-memory store the tests use. The store contract now pins those
// semantics (asking for more never returns less), so the bound here means what
// it says.
//
// Best-effort by design: a failed audit read returns an empty map so the
// listing still renders (degraded to names only) instead of erroring.
func (s *Server) recordingOwners(r *http.Request, want map[string]bool) map[string][2]string {
	out := map[string][2]string{}
	events, err := s.store.ListAudit(r.Context(), store.MaxAuditPage)
	if err != nil {
		return out
	}
	for _, e := range events {
		if len(want) > 0 && len(out) == len(want) {
			break // every listed recording is accounted for
		}
		if e.Action != "session.record" && e.Action != "winrm.run" {
			continue
		}
		var file, target string
		for _, f := range strings.Fields(e.Detail) {
			switch {
			case strings.HasPrefix(f, "file:"):
				file = filepath.Base(strings.TrimPrefix(f, "file:"))
			case strings.HasPrefix(f, "target:"):
				target = strings.TrimPrefix(f, "target:")
			}
		}
		// Newest-first: the first event naming a file wins, so a later re-use of
		// a name (which the timestamp prefix makes near-impossible) can't
		// relabel an older recording.
		if file == "" {
			continue
		}
		if len(want) > 0 && !want[file] {
			continue // an audit event for a recording this listing does not show
		}
		if _, seen := out[file]; !seen {
			out[file] = [2]string{target, e.Actor}
		}
	}
	return out
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
	// Resolve owners only for the recordings actually being returned, so the
	// audit scan can stop early instead of always walking the whole window.
	want := make(map[string]bool, len(out))
	for _, rec := range out {
		want[rec.Name] = true
	}
	owners := s.recordingOwners(r, want)
	for i := range out {
		who := owners[out[i].Name]
		out[i].Target, out[i].Actor = who[0], who[1]
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

	// A sealed recording (Phase 41) is decrypted on the way out. Detection is per
	// file, by its magic prefix, so recordings written before encryption was turned
	// on still replay — and the hash above still covers the STORED bytes, which is
	// what the audit trail attests to.
	head := make([]byte, recording.HeaderLen)
	if n, _ := f.ReadAt(head, 0); recording.IsSealed(head[:n]) {
		pr, oerr := recording.Open(r.Context(), io.NewSectionReader(f, 0, fi.Size()), s.vault, name)
		if oerr != nil {
			s.log.Error("recording decrypt", "file", name, "err", oerr)
			writeError(w, http.StatusInternalServerError, "recording could not be decrypted")
			return
		}
		w.Header().Set("X-PAM-Recording-Encrypted", "true")
		if _, cerr := io.Copy(w, pr); cerr != nil {
			// The prefix is already on the wire; log rather than rewrite the status.
			s.log.Warn("recording replay ended early", "file", name, "err", cerr)
		}
		return
	}
	http.ServeContent(w, r, "", fi.ModTime(), io.NewSectionReader(f, 0, fi.Size()))
}
