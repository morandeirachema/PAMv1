package api_test

// sftp_playback_test.go covers the replay side of Phase 59: a captured SFTP
// file artifact lists alongside session recordings (kind "file", attributed
// from its sftp.file_recorded audit event), serves as the RECONSTRUCTED
// transferred bytes by default with the hash verified against the audit trail,
// and serves its raw chunk log with ?raw=1. A reconstruction that would exceed
// the in-memory bound is refused with 413, not attempted.

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
	"github.com/morandeirachema/pamv1/internal/recording"
	"github.com/morandeirachema/pamv1/internal/store"
)

// writeSFTPArtifact writes a plaintext capture artifact exactly as the proxy
// produces it, returning its on-disk bytes.
func writeSFTPArtifact(t *testing.T, dir, name, path string, chunks []recording.SFTPChunk) []byte {
	t.Helper()
	var buf bytes.Buffer
	hdr, err := recording.EncodeSFTPHeader(recording.SFTPFileHeader{Path: path, OpenMode: "write", Time: 100})
	if err != nil {
		t.Fatal(err)
	}
	buf.Write(hdr)
	for _, c := range chunks {
		line, err := recording.EncodeSFTPChunk(c)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(line)
	}
	if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestSFTPArtifactPlayback proves the captured-file replay loop end to end
// against hand-built artifacts in the proxy's exact format.
func TestSFTPArtifactPlayback(t *testing.T) {
	dir := t.TempDir()
	srv, st := newTestServerOpts(t, nil, api.Options{RecordingDir: dir})
	ctx := context.Background()

	raw := writeSFTPArtifact(t, dir, "100_web-01_alice_f0.sftp", "/srv/report.csv", []recording.SFTPChunk{
		{Dir: "w", Offset: 6, Data: []byte("world!")},
		{Dir: "w", Offset: 0, Data: []byte("hello ")},
	})
	sum := sha256.Sum256(raw)
	sumHex := hex.EncodeToString(sum[:])
	if err := st.AppendAudit(ctx, &store.AuditEvent{
		Actor: "alice", Action: "sftp.file_recorded",
		Detail: `target:web-01 cred_user:root path:"/srv/report.csv" file:100_web-01_alice_f0.sftp open_mode:write bytes_up:12 bytes_down:0 sha256:` + sumHex + " chain:ab",
	}); err != nil {
		t.Fatal(err)
	}

	auditor := seedUser(t, srv, "sftp-auditor", "auditor")

	// Listing: kind "file", attributed to target and actor from the audit trail.
	code, data := do(t, srv, http.MethodGet, "/api/recordings", auditor, nil)
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, data)
	}
	var list []map[string]any
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0]["kind"] != "file" {
		t.Fatalf("listing = %s, want one kind:file entry", data)
	}
	if list[0]["target"] != "web-01" || list[0]["actor"] != "alice" {
		t.Fatalf("artifact must be attributed from sftp.file_recorded: %s", data)
	}

	// Default replay: the reconstructed transferred bytes, hash-verified.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/recordings/100_web-01_alice_f0.sftp", nil)
	req.Header.Set("X-API-Key", auditor)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || string(body) != "hello world!" {
		t.Fatalf("reconstructed playback: %d %q", res.StatusCode, body)
	}
	if res.Header.Get("X-PAM-Recording-Audited") != "true" {
		t.Fatal("artifact hash must verify against sftp.file_recorded")
	}
	if res.Header.Get("X-PAM-SFTP-Path") != "/srv/report.csv" || res.Header.Get("X-PAM-SFTP-Direction") != "up" {
		t.Fatalf("sftp headers: path=%q dir=%q", res.Header.Get("X-PAM-SFTP-Path"), res.Header.Get("X-PAM-SFTP-Direction"))
	}
	if res.Header.Get("X-PAM-SFTP-Sparse") != "false" {
		t.Fatal("fully covered content must not be flagged sparse")
	}

	// The replay was audited.
	if ok, err := st.FindAuditDetail(ctx, "session.playback", "file:100_web-01_alice_f0.sftp"); err != nil || !ok {
		t.Fatalf("sftp playback must audit session.playback: ok=%v err=%v", ok, err)
	}

	// ?raw=1 serves the chunk log itself, byte-exact.
	rc, rawBody := do(t, srv, http.MethodGet, "/api/recordings/100_web-01_alice_f0.sftp?raw=1", auditor, nil)
	if rc != http.StatusOK || !bytes.Equal(rawBody, raw) {
		t.Fatalf("raw chunk log: %d (equal=%v)", rc, bytes.Equal(rawBody, raw))
	}

	// A plain user may not fetch captured file content.
	user := seedUser(t, srv, "sftp-user", "user")
	if c, _ := do(t, srv, http.MethodGet, "/api/recordings/100_web-01_alice_f0.sftp", user, nil); c != http.StatusForbidden {
		t.Fatalf("plain user fetching captured content: want 403, got %d", c)
	}
}

// TestSFTPArtifactEmptyWriteDoesNotHideADownload proves two things a captured
// read+write handle depends on: an empty WRITE neither crashes the
// reconstruction nor wins the default direction election. Electing "up" on a
// zero-byte chunk served an empty file to an auditor who pressed 5 on the
// console — the exfiltrated bytes were still there, just invisible without a
// query parameter nobody would think to add.
func TestSFTPArtifactEmptyWriteDoesNotHideADownload(t *testing.T) {
	dir := t.TempDir()
	srv, _ := newTestServerOpts(t, nil, api.Options{RecordingDir: dir})
	writeSFTPArtifact(t, dir, "300_mixed_f0.sftp", "/srv/secrets.db", []recording.SFTPChunk{
		{Dir: "w", Offset: 1 << 20, Data: nil}, // an empty write, far past the end
		{Dir: "r", Offset: 0, Data: []byte("exfiltrated-bytes")},
	})
	auditor := seedUser(t, srv, "sftp-auditor3", "auditor")

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/recordings/300_mixed_f0.sftp", nil)
	req.Header.Set("X-API-Key", auditor)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("playback: %d %s", res.StatusCode, body)
	}
	if string(body) != "exfiltrated-bytes" {
		t.Fatalf("the downloaded content must be what is served by default, got %q", body)
	}
	if res.Header.Get("X-PAM-SFTP-Direction") != "down" {
		t.Fatalf("direction = %q, want down", res.Header.Get("X-PAM-SFTP-Direction"))
	}
}

// TestSFTPArtifactRawParamIsAffirmative proves ?raw=0 serves the reconstructed
// content, not the chunk log. Treating any value as "raw" made the flag mean
// the opposite of what it says for the one operator careful enough to write it
// out.
func TestSFTPArtifactRawParamIsAffirmative(t *testing.T) {
	dir := t.TempDir()
	srv, _ := newTestServerOpts(t, nil, api.Options{RecordingDir: dir})
	writeSFTPArtifact(t, dir, "400_flag_f0.sftp", "/srv/a.txt", []recording.SFTPChunk{
		{Dir: "w", Offset: 0, Data: []byte("content")},
	})
	auditor := seedUser(t, srv, "sftp-auditor4", "auditor")

	if c, body := do(t, srv, http.MethodGet, "/api/recordings/400_flag_f0.sftp?raw=0", auditor, nil); c != http.StatusOK || string(body) != "content" {
		t.Fatalf("?raw=0 must serve the reconstructed content: %d %q", c, body)
	}
	if c, body := do(t, srv, http.MethodGet, "/api/recordings/400_flag_f0.sftp?raw=true", auditor, nil); c != http.StatusOK || !bytes.Contains(body, []byte(`"sftp-file"`)) {
		t.Fatalf("?raw=true must serve the chunk log: %d %q", c, body)
	}
}

// TestSFTPArtifactReconstructBound proves a chunk log whose reconstruction
// would exceed the in-memory bound is refused with 413 — while its raw form
// stays fully retrievable.
func TestSFTPArtifactReconstructBound(t *testing.T) {
	dir := t.TempDir()
	srv, _ := newTestServerOpts(t, nil, api.Options{RecordingDir: dir})
	writeSFTPArtifact(t, dir, "200_far_f0.sftp", "/srv/huge.bin", []recording.SFTPChunk{
		{Dir: "w", Offset: 33 << 20, Data: []byte("x")}, // one byte past 32 MiB
	})
	auditor := seedUser(t, srv, "sftp-auditor2", "auditor")
	if c, body := do(t, srv, http.MethodGet, "/api/recordings/200_far_f0.sftp", auditor, nil); c != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized reconstruction: want 413, got %d %s", c, body)
	}
	if c, _ := do(t, srv, http.MethodGet, "/api/recordings/200_far_f0.sftp?raw=1", auditor, nil); c != http.StatusOK {
		t.Fatalf("raw form must stay retrievable, got %d", c)
	}
}
