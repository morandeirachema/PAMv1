package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/recarchive"
	"github.com/morandeirachema/pamv1/internal/store"
)

// seedRecording writes a recording and the audit row that stamps it.
func seedRecording(t *testing.T, st store.Store, dir, name, body, actor, action, detail string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	h := hex.EncodeToString(sum[:])
	if err := st.AppendAudit(context.Background(), &store.AuditEvent{Actor: actor, Action: action, Detail: detail + " file:" + name + " sha256:" + h}); err != nil {
		t.Fatal(err)
	}
	return h
}

// getRaw fetches a URL and returns status, headers and body.
func getRaw(t *testing.T, url, key string) (int, http.Header, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-API-Key", key)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, b
}

func readArchive(t *testing.T, data []byte) (recarchive.Manifest, string, map[string]string) {
	t.Helper()
	got := map[string]string{}
	m, digest, err := recarchive.Read(bytes.NewReader(data), func(string) bool { return true }, func(e recarchive.Entry, r io.Reader) error {
		b, err := io.ReadAll(r)
		got[e.Name] = string(b)
		return err
	})
	if err != nil {
		t.Fatalf("archive does not read back: %v", err)
	}
	return m, digest, got
}

// TestRecordingArchiveExport proves Phase 283's export: a selection by
// actor, protocol and window comes back as a tar whose manifest names each
// file's stamping audit row and whether the stored bytes still match it;
// the export is audited with the manifest's SHA-256 before a byte leaves;
// a plain user is refused; an empty selection is 404.
func TestRecordingArchiveExport(t *testing.T) {
	dir := t.TempDir()
	srv, st := newTestServerOpts(t, nil, api.Options{RecordingDir: dir})
	seedRecording(t, st, dir, "100_web-01_alice.cast", "{\"version\":2}\n[0.1,\"o\",\"ls\"]\n", "alice", "session.record", "target:web-01 cred_user:root bytes:1")
	seedRecording(t, st, dir, "110_pg-01_bob.cast", "{\"version\":2}\n[0.1,\"o\",\"select 1\"]\n", "bob", "session.record", "proto:postgres target:pg-01")
	seedRecording(t, st, dir, "120_win-01_alice.guac", "4.sync,1.0;", "alice", "rdp.record", "target:win-01 cred_user:Administrator bytes:1")
	// Altered after it was stamped: archived, and marked as not matching.
	seedRecording(t, st, dir, "130_web-01_alice.cast", "original", "alice", "session.record", "target:web-01 cred_user:root bytes:1")
	if err := os.WriteFile(filepath.Join(dir, "130_web-01_alice.cast"), []byte("doctored"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, hdr, data := getRaw(t, srv.URL+"/api/recordings/archive?actor=alice", testAPIKey)
	if code != http.StatusOK || hdr.Get("Content-Type") != "application/x-tar" {
		t.Fatalf("export: %d %s", code, data)
	}
	m, digest, bodies := readArchive(t, data)
	if digest != hdr.Get("X-PAM-Archive-Manifest-SHA256") || len(m.Files) != 3 || m.Filter["actor"] != "alice" {
		t.Fatalf("manifest %+v digest %s header %s", m, digest, hdr.Get("X-PAM-Archive-Manifest-SHA256"))
	}
	byName := map[string]recarchive.Entry{}
	for _, f := range m.Files {
		byName[f.Name] = f
	}
	if e := byName["120_win-01_alice.guac"]; e.Protocol != "rdp" || e.AuditAction != "rdp.record" || !e.Audited || e.Target != "win-01" {
		t.Fatalf("rdp entry = %+v", e)
	}
	if e := byName["130_web-01_alice.cast"]; e.Audited || bodies["130_web-01_alice.cast"] != "doctored" {
		t.Fatalf("an altered recording must be archived as not matching its audit row: %+v", e)
	}
	auditHas(t, st, "recording.archive", "manifest_sha256:"+digest+" files:3")

	code, _, data = getRaw(t, srv.URL+"/api/recordings/archive?protocol=postgres", testAPIKey)
	if m, _, _ := readArchive(t, data); code != http.StatusOK || len(m.Files) != 1 || m.Files[0].Actor != "bob" {
		t.Fatalf("protocol filter: %d %+v", code, m.Files)
	}
	if code, _, _ := getRaw(t, srv.URL+"/api/recordings/archive?target=nowhere", testAPIKey); code != http.StatusNotFound {
		t.Fatalf("empty selection = %d, want 404", code)
	}
	if code, _, _ := getRaw(t, srv.URL+"/api/recordings/archive?since=yesterday", testAPIKey); code != http.StatusUnprocessableEntity {
		t.Fatalf("bad window = %d, want 422", code)
	}
	user := seedUser(t, srv, "plain", "user")
	if code, _, _ := getRaw(t, srv.URL+"/api/recordings/archive", user); code != http.StatusForbidden {
		t.Fatalf("a plain user = %d, want 403", code)
	}
}

// postTar uploads an archive to a route and returns status and the JSON.
func postTar(t *testing.T, url, key string, data []byte) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	req.Header.Set("X-API-Key", key)
	req.Header.Set("Content-Type", "application/x-tar")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// TestRecordingArchiveImport proves Phase 283's import: an archive exported
// from one deployment is put back on another's disk byte-exact, replays as
// IMPORTED (never as audited — no recording row vouches for it there),
// re-importing changes nothing, a stored recording with the same name but
// other bytes is never overwritten, a tampered archive writes nothing at
// all, and only an administrator may import.
func TestRecordingArchiveImport(t *testing.T) {
	srcDir := t.TempDir()
	src, srcSt := newTestServerOpts(t, nil, api.Options{RecordingDir: srcDir})
	cast := "{\"version\":2}\n[0.1,\"o\",\"whoami\"]\n"
	seedRecording(t, srcSt, srcDir, "100_web-01_alice.cast", cast, "alice", "session.record", "target:web-01 cred_user:root")
	seedRecording(t, srcSt, srcDir, "110_web-01_alice.cast", "second", "alice", "session.record", "target:web-01 cred_user:root")
	code, _, archive := getRaw(t, src.URL+"/api/recordings/archive", testAPIKey)
	if code != http.StatusOK {
		t.Fatalf("export: %d", code)
	}

	dstDir := t.TempDir()
	dst, dstSt := newTestServerOpts(t, nil, api.Options{RecordingDir: dstDir})
	// A different recording already stored under one of the names.
	if err := os.WriteFile(filepath.Join(dstDir, "110_web-01_alice.cast"), []byte("someone else's"), 0o600); err != nil {
		t.Fatal(err)
	}
	auditor := seedUser(t, dst, "aud", "auditor")
	if code, _ := postTar(t, dst.URL+"/api/recordings/archive", auditor, archive); code != http.StatusForbidden {
		t.Fatalf("an auditor imported: %d", code)
	}
	code, res := postTar(t, dst.URL+"/api/recordings/archive", testAPIKey, archive)
	if code != http.StatusOK || res["imported"] != float64(1) || res["conflicts"] != float64(1) {
		t.Fatalf("import: %d %v", code, res)
	}
	if b, _ := os.ReadFile(filepath.Join(dstDir, "110_web-01_alice.cast")); string(b) != "someone else's" {
		t.Fatal("a conflicting recording was overwritten")
	}
	auditHas(t, dstSt, "recording.import", "files:2")
	auditHas(t, dstSt, "recording.imported", "file:100_web-01_alice.cast")

	code2, body, sum, audited := playbackGet(t, dst.URL+"/api/recordings/100_web-01_alice.cast", testAPIKey)
	req, _ := http.NewRequest(http.MethodGet, dst.URL+"/api/recordings/100_web-01_alice.cast", nil)
	req.Header.Set("X-API-Key", testAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if code2 != http.StatusOK || string(body) != cast || audited != "false" || resp.Header.Get("X-PAM-Recording-Imported") != "true" || sum == "" {
		t.Fatalf("imported playback: %d audited=%s imported=%s body=%q", code2, audited, resp.Header.Get("X-PAM-Recording-Imported"), body)
	}

	if code, res := postTar(t, dst.URL+"/api/recordings/archive", testAPIKey, archive); code != http.StatusOK || res["imported"] != float64(0) || res["exists"] != float64(1) {
		t.Fatalf("re-import must change nothing: %d %v", code, res)
	}

	// Flip one byte of a recording's body inside the tar: nothing is written.
	tampered := bytes.Replace(archive, []byte("whoami"), []byte("whoamI"), 1)
	clean := t.TempDir()
	other, _ := newTestServerOpts(t, nil, api.Options{RecordingDir: clean})
	if code, res := postTar(t, other.URL+"/api/recordings/archive", testAPIKey, tampered); code != http.StatusUnprocessableEntity {
		t.Fatalf("tampered archive: %d %v", code, res)
	}
	if entries, _ := os.ReadDir(clean); len(entries) != 0 {
		t.Fatalf("a refused archive left files behind: %v", entries)
	}
}
