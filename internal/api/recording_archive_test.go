package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
