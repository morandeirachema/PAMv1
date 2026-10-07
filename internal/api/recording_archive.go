package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"crypto/sha256"
	"encoding/hex"

	"github.com/morandeirachema/pamv1/internal/recarchive"
	"github.com/morandeirachema/pamv1/internal/report"
)

// Portable recording archives (Phase 283). The audit trail is the index:
// every recording is stamped by exactly one row (session.record, winrm.run,
// sftp.file_recorded, rdp.record, vnc.record) naming its file, target,
// actor and SHA-256, so a selection by user, target, protocol and window is
// a query over those rows, and each archived file carries the row that
// vouches for it.

const defaultArchiveWindow = 30 * 24 * time.Hour

// recordingProtocol names the protocol a recording's stamping row records.
func recordingProtocol(action, detail, name string) string {
	switch action {
	case "rdp.record":
		return "rdp"
	case "vnc.record":
		return "vnc"
	case "winrm.run":
		return "winrm"
	case "sftp.file_recorded":
		return "sftp"
	}
	if p := report.Field(detail, "protocol"); p != "" {
		return p
	}
	if p := report.Field(detail, "proto"); p != "" {
		return p // the database proxies' rows
	}
	switch {
	case strings.HasSuffix(name, ".winrm.log"):
		return "winrm"
	case strings.HasSuffix(name, ".k8s.log"):
		return "kubernetes"
	}
	return "ssh"
}

// selectRecordings resolves the archive filter to manifest entries: the
// stamping row for each recording in [since, until), filtered, joined with
// the file still on disk and its current hash.
func (s *Server) selectRecordings(ctx context.Context, since, until time.Time, actor, target, protocol string) ([]recarchive.Entry, error) {
	events, err := s.store.ExportAuditActions(ctx, since, until, recordingAuditActionList)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []recarchive.Entry
	for _, e := range events {
		name := filepath.Base(report.Field(e.Detail, "file"))
		if name == "" || seen[name] || !recordingNameRe.MatchString(name) {
			continue
		}
		seen[name] = true // the first row is the one that stamped it
		proto := recordingProtocol(e.Action, e.Detail, name)
		tgt := report.Field(e.Detail, "target")
		if (actor != "" && e.Actor != actor) || (target != "" && tgt != target) || (protocol != "" && proto != protocol) {
			continue
		}
		path := filepath.Join(s.recordingDir, name)
		fi, err := os.Stat(path)
		if err != nil || !fi.Mode().IsRegular() {
			continue // pruned, or never on this replica's disk
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return nil, err
		}
		out = append(out, recarchive.Entry{
			Name: name, Kind: recordingKind(name), Size: fi.Size(), SHA256: sum, Modified: fi.ModTime().UTC(),
			Target: tgt, Actor: e.Actor, Protocol: proto,
			AuditAction: e.Action, AuditID: e.ID, AuditTime: e.TS.UTC(),
			Audited: report.Field(e.Detail, "sha256") == sum,
		})
	}
	return out, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the recording dir joined with a name matching recordingNameRe
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// exportRecordingArchive is GET /api/recordings/archive: the recordings
// stamped in a window (since/until, RFC 3339; default the last 30 days, at
// most 366), optionally only one actor's, one target's or one protocol's,
// as a tar with a manifest. The export is audited — with the manifest's
// SHA-256, which is how a later purge proves the archive was made here —
// before a byte leaves, and refused if it cannot be. Requires CapReadAudit,
// the gate of playback: an archive is many playbacks at once.
func (s *Server) exportRecordingArchive(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, err := parseTimeParam(q.Get("since"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "since must be RFC3339")
		return
	}
	until, err := parseTimeParam(q.Get("until"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "until must be RFC3339")
		return
	}
	if until.IsZero() {
		until = time.Now().UTC()
	}
	if since.IsZero() {
		since = until.Add(-defaultArchiveWindow)
	}
	if !since.Before(until) || until.Sub(since) > maxReportWindow {
		writeError(w, http.StatusUnprocessableEntity, "the window must be positive and at most 366 days")
		return
	}
	actor, target, protocol := q.Get("actor"), q.Get("target"), q.Get("protocol")
	if s.recordingDir == "" {
		writeError(w, http.StatusNotFound, "recordings are not configured")
		return
	}
	files, err := s.selectRecordings(r.Context(), since, until, actor, target, protocol)
	if err != nil {
		storeError(w, err)
		return
	}
	if len(files) == 0 {
		writeError(w, http.StatusNotFound, "no stored recording matches")
		return
	}
	filter := map[string]string{"since": since.UTC().Format(time.RFC3339), "until": until.UTC().Format(time.RFC3339)}
	for k, v := range map[string]string{"actor": actor, "target": target, "protocol": protocol} {
		if v != "" {
			filter[k] = v
		}
	}
	m := recarchive.Manifest{Format: recarchive.Format, CreatedAt: time.Now().UTC(), CreatedBy: actorFrom(r.Context()), Filter: filter, Files: files}
	_, digest, err := m.Encode()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "manifest")
		return
	}
	var total int64
	for _, f := range files {
		total += f.Size
	}
	if !s.mustAudit(w, r.Context(), "recording.archive", fmt.Sprintf("manifest_sha256:%s files:%d bytes:%d since:%s until:%s actor:%s target:%s protocol:%s",
		digest, len(files), total, filter["since"], filter["until"], auditField(orDash(actor), 64), auditField(orDash(target), 64), auditField(orDash(protocol), 16))) {
		return
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", `attachment; filename="pamv1-recordings-`+time.Now().UTC().Format("20060102T150405Z")+`.tar"`)
	w.Header().Set("X-PAM-Archive-Manifest-SHA256", digest)
	w.Header().Set("X-PAM-Archive-Files", strconv.Itoa(len(files)))
	open := func(name string) (io.ReadCloser, error) {
		return os.Open(filepath.Join(s.recordingDir, name)) // #nosec G304 -- names come from selectRecordings, each matching recordingNameRe
	}
	if err := recarchive.Write(w, m, open); err != nil {
		// The status is already on the wire; the truncated tar fails to read.
		s.log.Error("recording archive stream", "manifest", digest, "err", err)
		s.audit(context.WithoutCancel(r.Context()), "recording.archive_failed", "manifest_sha256:"+digest+" error:"+auditField(err.Error(), 200))
	}
}

func orDash(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

// maxArchiveImport bounds one uploaded archive.
const maxArchiveImport = 8 << 30

// importedFile is one archived file's outcome.
type importedFile struct {
	Name   string `json:"name"`
	Status string `json:"status"` // imported | exists | conflict | error
	Error  string `json:"error,omitempty"`
}

// importRecordingArchive is POST /api/recordings/archive: an archive made by
// GET /api/recordings/archive — here or on another deployment — is put back
// on disk for replay. Every file is verified against the manifest as it
// streams into a hidden temporary file, and nothing is promoted unless the
// whole archive verifies. A file already present with the same bytes is
// left alone; one present with DIFFERENT bytes is never overwritten (a
// conflict). Each imported file is audited recording.imported with its
// SHA-256, which is how playback tells an imported recording from one this
// deployment recorded itself: it says imported, never audited. Requires
// CapManageUsers — it writes into the evidence store.
func (s *Server) importRecordingArchive(w http.ResponseWriter, r *http.Request) {
	if s.recordingDir == "" {
		writeError(w, http.StatusNotFound, "recordings are not configured")
		return
	}
	ctx := r.Context()
	temps := map[string]string{} // name -> temp path
	cleanup := func() {
		for _, p := range temps {
			_ = os.Remove(p)
		}
	}
	m, digest, err := recarchive.Read(http.MaxBytesReader(w, r.Body, maxArchiveImport), recordingNameRe.MatchString,
		func(e recarchive.Entry, body io.Reader) error {
			f, err := os.CreateTemp(s.recordingDir, ".import-*")
			if err != nil {
				return err
			}
			temps[e.Name] = f.Name()
			if _, err := io.Copy(f, body); err != nil {
				f.Close()
				return err
			}
			return f.Close()
		})
	if err != nil {
		cleanup()
		writeError(w, http.StatusUnprocessableEntity, "archive: "+err.Error())
		return
	}
	if !s.mustAudit(w, ctx, "recording.import", fmt.Sprintf("manifest_sha256:%s files:%d source_by:%s source_at:%s",
		digest, len(m.Files), auditField(m.CreatedBy, 64), m.CreatedAt.UTC().Format(time.RFC3339))) {
		cleanup()
		return
	}
	out := make([]importedFile, 0, len(m.Files))
	counts := map[string]int{}
	for _, e := range m.Files {
		dst := filepath.Join(s.recordingDir, e.Name)
		res := importedFile{Name: e.Name}
		switch sum, err := fileSHA256(dst); {
		case err == nil && sum == e.SHA256:
			res.Status = "exists"
		case err == nil:
			res.Status, res.Error = "conflict", "a different recording with this name is already stored; not overwritten"
		case !os.IsNotExist(err):
			res.Status, res.Error = "error", "cannot read the stored recording"
		default:
			// Audit first: a recording that appears with no record of how it
			// arrived would replay as nobody's evidence.
			detail := fmt.Sprintf("file:%s sha256:%s manifest:%s source_actor:%s source_target:%s audited_at_source:%t",
				e.Name, e.SHA256, digest, auditField(orDash(e.Actor), 64), auditField(orDash(e.Target), 64), e.Audited)
			if aerr := s.auditAs(ctx, actorFrom(ctx), "recording.imported", detail); aerr != nil {
				res.Status, res.Error = "error", "audit unavailable"
			} else if rerr := os.Rename(temps[e.Name], dst); rerr != nil {
				res.Status, res.Error = "error", "could not store it"
			} else {
				delete(temps, e.Name)
				_ = os.Chtimes(dst, e.Modified, e.Modified)
				res.Status = "imported"
			}
		}
		counts[res.Status]++
		out = append(out, res)
	}
	cleanup()
	writeJSON(w, http.StatusOK, map[string]any{
		"manifest_sha256": digest, "created_by": m.CreatedBy, "created_at": m.CreatedAt,
		"imported": counts["imported"], "exists": counts["exists"], "conflicts": counts["conflict"], "errors": counts["error"], "files": out,
	})
}
