package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/store"
)

// playbackGet fetches a recording with headers, which the shared do() helper
// discards. Returns status, body, and the two tamper-evidence headers.
func playbackGet(t *testing.T, url, apiKey string) (int, []byte, string, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", apiKey)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, body, res.Header.Get("X-PAM-Recording-SHA256"), res.Header.Get("X-PAM-Recording-Audited")
}

// TestRecordingPlayback proves the replay path end to end: stored recordings
// list newest-first, an audited recording serves byte-exact with its hash
// verified against the audit trail, a tampered/unaudited file is flagged, the
// replay itself is audited, and only read_audit roles may replay.
func TestRecordingPlayback(t *testing.T) {
	dir := t.TempDir()
	srv, st := newTestServerOpts(t, nil, api.Options{RecordingDir: dir})
	ctx := context.Background()

	// A recorded proxy session, exactly as the proxy leaves it: the asciicast on
	// disk and its SHA-256 stamped into a session.record audit event.
	cast := "{\"version\":2,\"width\":80,\"height\":24}\n[0.1,\"o\",\"$ ls\\r\\n\"]\n[0.6,\"o\",\"secrets.txt\\r\\n\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "100_web-01_alice.cast"), []byte(cast), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(cast))
	sumHex := hex.EncodeToString(sum[:])
	if err := st.AppendAudit(ctx, &store.AuditEvent{
		Actor: "alice", Action: "session.record",
		Detail: "target:web-01 cred_user:root file:100_web-01_alice.cast bytes:34 sha256:" + sumHex + " chain:ab",
	}); err != nil {
		t.Fatal(err)
	}
	// A recording whose hash was never audited (tampered on disk, or trimmed).
	if err := os.WriteFile(filepath.Join(dir, "200_web-01_mallory.cast"), []byte("{\"version\":2}\n[0,\"o\",\"rm -rf /\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The chain head must never appear in the listing.
	if err := os.WriteFile(filepath.Join(dir, ".chain"), []byte("aa"), 0o600); err != nil {
		t.Fatal(err)
	}

	auditor := seedUser(t, srv, "rec-auditor", "auditor")

	// Listing: both recordings, no dotfiles.
	code, data := do(t, srv, http.MethodGet, "/api/recordings", auditor, nil)
	if code != http.StatusOK {
		t.Fatalf("list recordings: %d %s", code, data)
	}
	var list []map[string]any
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("listing = %d entries, want 2: %s", len(list), data)
	}
	for _, e := range list {
		name := e["name"].(string)
		if strings.HasPrefix(name, ".") {
			t.Fatalf("dotfile leaked into the listing: %q", name)
		}
		if e["kind"] != "asciicast" {
			t.Fatalf("kind = %v, want asciicast", e["kind"])
		}
	}

	// Replaying the audited recording: byte-exact body, hash matches, verified.
	pc, body, gotSum, audited := playbackGet(t, srv.URL+"/api/recordings/100_web-01_alice.cast", auditor)
	if pc != http.StatusOK {
		t.Fatalf("playback: %d %s", pc, body)
	}
	if string(body) != cast {
		t.Fatalf("playback body differs from the stored recording")
	}
	if gotSum != sumHex {
		t.Fatalf("X-PAM-Recording-SHA256 = %q, want %q", gotSum, sumHex)
	}
	if audited != "true" {
		t.Fatalf("audited recording must verify: X-PAM-Recording-Audited = %q", audited)
	}

	// The replay itself hit the audit trail.
	if ok, err := st.FindAuditDetail(ctx, "session.playback", "file:100_web-01_alice.cast"); err != nil || !ok {
		t.Fatalf("playback must be audited session.playback: ok=%v err=%v", ok, err)
	}

	// The unaudited recording still replays, but is flagged.
	if _, _, _, audited := playbackGet(t, srv.URL+"/api/recordings/200_web-01_mallory.cast", auditor); audited != "false" {
		t.Fatalf("unaudited recording must be flagged: X-PAM-Recording-Audited = %q", audited)
	}

	// RBAC: replay needs read_audit — a plain user is refused.
	user := seedUser(t, srv, "rec-user", "user")
	if c, _ := do(t, srv, http.MethodGet, "/api/recordings", user, nil); c != http.StatusForbidden {
		t.Fatalf("user listing recordings: want 403, got %d", c)
	}
	if c, _, _, _ := playbackGet(t, srv.URL+"/api/recordings/100_web-01_alice.cast", user); c != http.StatusForbidden {
		t.Fatalf("user replaying a recording: want 403, got %d", c)
	}

	// Name hygiene: dotfiles and non-recording names are refused, missing is 404.
	if c, _ := do(t, srv, http.MethodGet, "/api/recordings/.chain", auditor, nil); c != http.StatusUnprocessableEntity {
		t.Fatalf("dotfile name: want 422, got %d", c)
	}
	if c, _ := do(t, srv, http.MethodGet, "/api/recordings/notes.txt", auditor, nil); c != http.StatusUnprocessableEntity {
		t.Fatalf("non-recording name: want 422, got %d", c)
	}
	if c, _ := do(t, srv, http.MethodGet, "/api/recordings/999_gone_bob.cast", auditor, nil); c != http.StatusNotFound {
		t.Fatalf("missing recording: want 404, got %d", c)
	}
}

// TestPlaybackAuditedNeedsTheStampingRow is the Phase 290 regression for the
// playback verdict. It used to ask whether `sha256:<hash>` appeared anywhere
// in a recording-stamping row, so (1) a hash typed as a WinRM command — the
// proxy audits the command, quoted — vouched for any file with that hash,
// spaces and a forged file: field included, and (2) two genuinely audited
// recordings swapped on disk each still replayed as audited. The verdict now
// needs one row whose own file: and sha256: fields name this file and hash.
func TestPlaybackAuditedNeedsTheStampingRow(t *testing.T) {
	dir := t.TempDir()
	srv, st := newTestServerOpts(t, nil, api.Options{RecordingDir: dir})
	ctx := context.Background()
	write := func(name, content string) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(content))
		return hex.EncodeToString(sum[:])
	}
	stamp := func(actor, action, detail string) {
		t.Helper()
		if err := st.AppendAudit(ctx, &store.AuditEvent{Actor: actor, Action: action, Detail: detail}); err != nil {
			t.Fatal(err)
		}
	}
	verdict := func(name string) string {
		t.Helper()
		code, body, _, audited := playbackGet(t, srv.URL+"/api/recordings/"+name, testAPIKey)
		if code != http.StatusOK {
			t.Fatalf("playback %s: %d %s", name, code, body)
		}
		return audited
	}

	// A file nobody recorded, vouched for only by rows an operator's own
	// command produced — the row internal/proxy writes for a WinRM command.
	forged := write("300_web-01_victim.cast", "{\"version\":2}\n[0,\"o\",\"nothing to see\"]\n")
	for _, cmd := range []string{
		"sha256:" + forged,
		"x sha256:" + forged + " y",
		"x file:300_web-01_victim.cast sha256:" + forged + " y",
	} {
		stamp("mallory", "winrm.run", fmt.Sprintf("target:win1 cred_user:svc via:proxy exit:1 cmd:%q", cmd))
	}
	if got := verdict("300_web-01_victim.cast"); got != "false" {
		t.Fatalf("a hash typed as a command vouched for a recording: audited = %q", got)
	}

	// Two genuine recordings, stamped the way the SSH proxy (a full path) and
	// the database proxies (a bare name) stamp them.
	sumA := write("400_web-01_alice.cast", "{\"version\":2}\n[0,\"o\",\"alice\"]\n")
	sumB := write("401_db-01_bob.cast", "{\"version\":2}\n[0,\"o\",\"bob\"]\n")
	stamp("alice", "session.record", "target:web-01 cred_user:root file:"+filepath.Join(dir, "400_web-01_alice.cast")+" bytes:30 sha256:"+sumA+" chain:aa")
	stamp("bob", "session.record", "proto:postgres target:db-01 file:401_db-01_bob.cast sha256:"+sumB+" bytes:28 chain:bb")
	if a, b := verdict("400_web-01_alice.cast"), verdict("401_db-01_bob.cast"); a != "true" || b != "true" {
		t.Fatalf("genuine recordings must verify: alice %q, bob %q", a, b)
	}
	// Swapped on disk: each file's bytes are audited — under the other name.
	write("400_web-01_alice.cast", "{\"version\":2}\n[0,\"o\",\"bob\"]\n")
	write("401_db-01_bob.cast", "{\"version\":2}\n[0,\"o\",\"alice\"]\n")
	if a, b := verdict("400_web-01_alice.cast"), verdict("401_db-01_bob.cast"); a != "false" || b != "false" {
		t.Fatalf("swapped recordings replayed as audited: alice %q, bob %q", a, b)
	}
}
