package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

	"github.com/morandeirachema/pamv1/internal/recording"
)

// --- session-recording playback (Phase 26) ---
//
// Recordings are written to disk by the SSH/WinRM/PostgreSQL proxies (asciicast
// .cast), the WinRM run endpoint (.winrm.log transcripts) and, with SFTP
// content capture on, per-transferred-file .sftp chunk logs (Phase 59); their
// SHA-256 is written to the audit trail as they close. These handlers are the
// replay side: list what is stored and serve one recording, recomputing its
// hash and reporting whether that hash appears in the audit trail — so a file
// tampered on disk is visibly flagged at playback. An .sftp artifact serves as
// the reconstructed file content by default (what actually moved), or as its
// raw chunk log with ?raw=1.

// recordingMaxList caps the playback listing at the newest entries; the full
// archive stays on disk.
const recordingMaxList = 500

// recordingNameRe matches the filenames the recorders produce (the sanitized
// alphabet plus the .cast / .winrm.log / .sftp suffixes). Anything else — a
// path separator, a dotfile like the .chain head — is refused, which also
// forecloses traversal: no accepted name can leave the recording directory.
var recordingNameRe = regexp.MustCompile(`^[A-Za-z0-9_@-][A-Za-z0-9._@-]*\.(cast|winrm\.log|sftp)$`)

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

// recordingOwnerWindow is how far back the recordings listing looks to attribute
// a file to a target and actor. Deliberately modest, and deliberately not
// store.MaxAuditPage: this runs on every console refresh, and reading five
// thousand rows with their full detail text to label at most five hundred
// entries is a poor trade for a screen that degrades gracefully.
const recordingOwnerWindow = 2000

// recordingOwners maps recording file names to the target and actor recorded in
// the audit trail. The recorders write `file:<path-or-name>` into
// session.record / winrm.run / sftp.file_recorded, so this reverses that: it
// reads a window of recent audit events and indexes by base name (the SSH proxy
// logs a full path, the DB proxy, WinRM and SFTP capture a bare name — indexing
// by base covers them all).
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
// semantics (asking for more never returns less), so the bound means what it
// says — which is exactly why it must be chosen deliberately rather than set to
// the maximum. The early exit only fires once EVERY listed name is resolved, so
// a single recording with no `session.record` event (pruned, or predating the
// feature) makes every request read the full window. A page an order of
// magnitude above the listing cap is enough to attribute the newest recordings
// while keeping the cost of a console refresh bounded; anything older degrades
// to a name with no target or actor, which is how this function has always
// failed.
//
// Best-effort by design: a failed audit read returns an empty map so the
// listing still renders (degraded to names only) instead of erroring.
func (s *Server) recordingOwners(r *http.Request, want map[string]bool) map[string][2]string {
	out := map[string][2]string{}
	events, err := s.store.ListAudit(r.Context(), recordingOwnerWindow)
	if err != nil {
		return out
	}
	for _, e := range events {
		if len(want) > 0 && len(out) == len(want) {
			break // every listed recording is accounted for
		}
		if e.Action != "session.record" && e.Action != "winrm.run" && e.Action != "sftp.file_recorded" {
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
// asciicast files replay with timing, transcripts render at once, and "file"
// entries are captured SFTP file content, offered as a download.
func recordingKind(name string) string {
	switch {
	case strings.HasSuffix(name, ".winrm.log"):
		return "transcript"
	case strings.HasSuffix(name, ".sftp"):
		return "file"
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
	// sessions audit session.record; WinRM run transcripts audit winrm.run; SFTP
	// content capture audits sftp.file_recorded.
	audited := false
	for _, action := range []string{"session.record", "winrm.run", "sftp.file_recorded"} {
		if ok, ferr := s.store.FindAuditDetail(r.Context(), action, "sha256:"+sum); ferr == nil && ok {
			audited = true
			break
		}
	}

	// Fail CLOSED, before a byte leaves. This is a read of KEK-protected material
	// — a sealed recording is everything the operator typed and saw, and since
	// Phase 59 a .sftp artifact reconstructs the actual content of a transferred
	// file, which can be a secret outright. Every other path that hands over
	// protected material refuses when the durable audit is unavailable (reveal,
	// checkout, app-secret, MFA enrolment, break-glass, token exchange, the
	// viewer's session start, both proxies' session start); playback was the one
	// that did not, so an audit outage made the whole recording archive readable
	// with no record of who read it. Invariant §6.4.
	if !s.mustAudit(w, r.Context(), "session.playback",
		fmt.Sprintf("file:%s bytes:%d sha256:%s audited:%t", name, fi.Size(), sum, audited)) {
		return
	}

	contentType := "application/x-asciicast; charset=utf-8"
	switch recordingKind(name) {
	case "transcript":
		contentType = "text/plain; charset=utf-8"
	case "file":
		contentType = "application/x-ndjson; charset=utf-8" // the raw chunk log (?raw=1)
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-PAM-Recording-SHA256", sum)
	w.Header().Set("X-PAM-Recording-Audited", strconv.FormatBool(audited))

	// Captured SFTP file content (Phase 59): by default serve the RECONSTRUCTED
	// bytes — what actually moved — decrypting the artifact if it is sealed;
	// ?raw=1 falls through to the generic paths below and serves the chunk log
	// itself (the full wire truth, including overlapping rewrites). Only an
	// affirmative value selects raw: reading "any value at all" made ?raw=0
	// mean raw, which is the opposite of what it says.
	if recordingKind(name) == "file" && !truthyParam(r.URL.Query().Get("raw")) {
		s.serveSFTPContent(w, r, f, fi.Size(), name)
		return
	}

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

// truthyParam reads an affirmative query-string flag. Deliberately explicit:
// a flag that treats "0" and "false" as set is a footgun in a URL an auditor
// types by hand.
func truthyParam(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// sftpReconstructMax bounds the size of a reconstructed SFTP file the API will
// assemble in memory; a larger capture is still fully available as its chunk
// log (?raw=1), which streams.
const sftpReconstructMax = 32 << 20 // 32 MiB

// sftpDecodeMax bounds the stored artifact size the reconstruction path will
// read: base64+JSON framing (and the seal) inflate content by roughly a third,
// so this comfortably covers any artifact whose reconstruction can succeed.
const sftpDecodeMax = 96 << 20 // 96 MiB

// serveSFTPContent serves a captured SFTP artifact as the reconstructed file
// bytes: the chunk log is decrypted if sealed, decoded, and replayed in order
// (later writes to a range win, as on the real file). ?dir=up|down picks the
// direction for the rare read+write handle; unset, uploads win when present.
// The response carries the remote path, direction, and whether the result has
// holes capture never saw (served as zeros) or a torn tail from a killed
// session — evidence is labeled, never silently smoothed over.
func (s *Server) serveSFTPContent(w http.ResponseWriter, r *http.Request, f *os.File, size int64, name string) {
	if size > sftpDecodeMax {
		writeError(w, http.StatusRequestEntityTooLarge, "artifact too large to reconstruct; fetch the chunk log with ?raw=1")
		return
	}
	pr, err := recording.Open(r.Context(), io.NewSectionReader(f, 0, size), s.vault, name)
	if err != nil {
		s.log.Error("sftp artifact decrypt", "file", name, "err", err)
		writeError(w, http.StatusInternalServerError, "artifact could not be decrypted")
		return
	}
	hdr, chunks, derr := recording.DecodeSFTPFile(pr)
	torn := errors.Is(derr, io.ErrUnexpectedEOF)
	if derr != nil && !torn {
		s.log.Error("sftp artifact decode", "file", name, "err", derr)
		writeError(w, http.StatusInternalServerError, "artifact unreadable")
		return
	}
	dir := ""
	switch r.URL.Query().Get("dir") {
	case "up":
		dir = "w"
	case "down":
		dir = "r"
	case "":
		// Elect the direction that actually carried bytes. Counting a
		// zero-length write as evidence of an upload let one empty WRITE on a
		// read+write handle serve an empty file by default and hide the
		// download — and the console never passes ?dir.
		dir = "r"
		for _, c := range chunks {
			if c.Dir == "w" && len(c.Data) > 0 {
				dir = "w"
				break
			}
		}
	default:
		writeError(w, http.StatusUnprocessableEntity, "dir must be up or down")
		return
	}
	content, sparse, rerr := recording.ReconstructSFTP(chunks, dir, sftpReconstructMax)
	if errors.Is(rerr, recording.ErrSFTPTooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "reconstruction exceeds the size bound; fetch the chunk log with ?raw=1")
		return
	}
	if rerr != nil {
		writeError(w, http.StatusInternalServerError, "artifact unreadable")
		return
	}
	direction := "down"
	if dir == "w" {
		direction = "up"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-PAM-SFTP-Path", headerSafe(hdr.Path))
	w.Header().Set("X-PAM-SFTP-Direction", direction)
	w.Header().Set("X-PAM-SFTP-Sparse", strconv.FormatBool(sparse))
	w.Header().Set("X-PAM-SFTP-Truncated", strconv.FormatBool(torn))
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	_, _ = w.Write(content)
}

// headerSafe makes a client-supplied string (a remote SFTP path) safe to echo
// in a response header: control bytes and non-ASCII are replaced, the length
// bounded — a filename must never be able to inject or split a header.
func headerSafe(s string) string {
	const maxLen = 300
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(b) < maxLen; i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		b = append(b, c)
	}
	return string(b)
}
