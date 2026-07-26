package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// stubKEK stands in for the vault's key-encryption key. Like the real vault it
// *authenticates* the AAD rather than storing it, so the AAD (which contains the
// recording's file name) never appears in the sealed file — otherwise this test's
// "no plaintext on disk" assertions would pass or fail for the wrong reason.
type stubKEK struct{ fail bool }

// aadTag is the stub's stand-in for authenticating the AAD without echoing it.
func aadTag(aad string) string {
	h := sha256.Sum256([]byte("stub-aad:" + aad))
	return hex.EncodeToString(h[:8])
}

// Encrypt wraps a data key reversibly, binding the AAD by its tag.
func (k stubKEK) Encrypt(_ context.Context, plaintext, aad string) (string, error) {
	if k.fail {
		return "", errors.New("kek down")
	}
	return "stub:" + aadTag(aad) + ":" + plaintext, nil
}

// Decrypt reverses Encrypt, refusing a token bound to a different AAD.
func (k stubKEK) Decrypt(_ context.Context, token, aad string) (string, error) {
	rest, ok := strings.CutPrefix(token, "stub:"+aadTag(aad)+":")
	if !ok {
		return "", errors.New("aad mismatch")
	}
	return rest, nil
}

// TestSessionRecordingIsSealedOnDisk proves the proxy's own recorder seals what it
// writes: the terminal output of a session is not recoverable by reading the
// .cast file. It also pins the coupling that makes the existing tamper-evidence
// keep working — the hash Close reports is over the bytes ON DISK, so the audited
// SHA-256 and the recording hash chain still describe the stored artifact.
func TestSessionRecordingIsSealedOnDisk(t *testing.T) {
	dir := t.TempDir()
	const typed = "cat /etc/shadow"

	rec, err := newRecording(context.Background(), dir, "sealed-sess", time.Now(), 0, stubKEK{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Write([]byte(typed)); err != nil {
		t.Fatal(err)
	}
	path, sum, _ := rec.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), "#pamrec1 ") {
		t.Fatalf("recording is not sealed: %q", string(raw[:min(24, len(raw))]))
	}
	if strings.Contains(string(raw), typed) {
		t.Fatal("the recorded session content is readable on disk")
	}
	if strings.Contains(string(raw), "sealed-sess") {
		t.Fatal("the asciicast title (target and user) is readable on disk")
	}

	// The reported hash covers the stored bytes, not the plaintext.
	h := sha256.Sum256(raw)
	if want := hex.EncodeToString(h[:]); sum != want {
		t.Fatalf("Close reported %s, but the file hashes to %s — playback would report it as never audited", sum, want)
	}
}

// TestRecordingFailsClosedWhenKEKIsDown proves a recorder that cannot seal writes
// nothing at all, so a session is never silently recorded in the clear.
func TestRecordingFailsClosedWhenKEKIsDown(t *testing.T) {
	dir := t.TempDir()
	if _, err := newRecording(context.Background(), dir, "nope", time.Now(), 0, stubKEK{fail: true}); err == nil {
		t.Fatal("expected an error when the KEK cannot wrap the data key")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a file was left behind after the failure: %v", entries)
	}
}
