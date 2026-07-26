package api_test

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// TestRecordingSealedAtRestButReplayable is the end-to-end proof of Phase 41: a
// recorded WinRM session leaves NOTHING readable on disk — not the command, not
// the output, not the target — yet an auditor replays it through the API and gets
// the transcript back, with the tamper-evidence verdict still saying the stored
// file is the one the audit trail attests to.
func TestRecordingSealedAtRestButReplayable(t *testing.T) {
	const marker = "S3CRET-OUTPUT-MARKER"
	fake := &fakeWinRM{result: winrm.Result{Stdout: marker + "\r\n", ExitCode: 0}}
	recDir := t.TempDir()
	srv, _ := newTestServerOpts(t, nil, api.Options{
		WinRM: fake, RecordingDir: recDir, EncryptRecordings: true,
	})

	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "win-sealed", "host": "10.0.0.8", "port": 5986, "os_type": "windows", "protocol": "winrm",
	})
	targetID := int64(jsonMap(t, td)["id"].(float64))
	if code, body := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": targetID, "username": "Administrator", "secret": "vaulted-pw",
	}); code != http.StatusCreated {
		t.Fatalf("seed credential: %d %s", code, body)
	}
	if code, body := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/winrm", targetID), testAPIKey,
		map[string]any{"command": "Get-Secret"}); code != http.StatusOK {
		t.Fatalf("winrm run: %d %s", code, body)
	}

	// Find the transcript on disk.
	entries, err := os.ReadDir(recDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no recording written: %v", err)
	}
	var name string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".winrm.log") {
			name = e.Name()
		}
	}
	if name == "" {
		t.Fatalf("no transcript among %v", entries)
	}
	onDisk, err := os.ReadFile(filepath.Join(recDir, name))
	if err != nil {
		t.Fatal(err)
	}

	// Sealed at rest: the payload is not recoverable by reading the file.
	if !strings.HasPrefix(string(onDisk), "#pamrec1 ") {
		t.Fatalf("recording is not sealed; it begins %q", string(onDisk[:min(24, len(onDisk))]))
	}
	for _, leak := range []string{marker, "Get-Secret", "win-sealed", "Administrator"} {
		if strings.Contains(string(onDisk), leak) {
			t.Fatalf("plaintext %q survived into the recording on disk", leak)
		}
	}

	// Replayable through the audited path, and still verified against the trail.
	code, body := do(t, srv, http.MethodGet, "/api/recordings/"+name, testAPIKey, nil)
	if code != http.StatusOK {
		t.Fatalf("playback: %d %s", code, body)
	}
	if !strings.Contains(string(body), marker) || !strings.Contains(string(body), "Get-Secret") {
		t.Fatalf("replayed transcript is missing its content: %s", body)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/recordings/"+name, nil)
	req.Header.Set("X-API-Key", testAPIKey)
	res2, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if got := res2.Header.Get("X-PAM-Recording-Audited"); got != "true" {
		t.Fatalf("X-PAM-Recording-Audited = %q, want true — the stored bytes must match the audited hash", got)
	}
	if got := res2.Header.Get("X-PAM-Recording-Encrypted"); got != "true" {
		t.Fatalf("X-PAM-Recording-Encrypted = %q, want true", got)
	}
}

// TestPlaintextRecordingStillReplaysWhenEncryptionIsOn proves the format is
// detected per file: turning encryption on does not orphan the recordings a
// deployment already had.
func TestPlaintextRecordingStillReplaysWhenEncryptionIsOn(t *testing.T) {
	recDir := t.TempDir()
	srv, _ := newTestServerOpts(t, nil, api.Options{RecordingDir: recDir, EncryptRecordings: true})

	const legacy = "{\"version\":2}\n[0.1,\"o\",\"legacy-session\"]\n"
	name := "1700000000_old_alice.cast"
	if err := os.WriteFile(filepath.Join(recDir, name), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	code, body := do(t, srv, http.MethodGet, "/api/recordings/"+name, testAPIKey, nil)
	if code != http.StatusOK {
		t.Fatalf("playback of a pre-encryption recording: %d %s", code, body)
	}
	if string(body) != legacy {
		t.Fatalf("replayed %q, want %q", body, legacy)
	}
}
