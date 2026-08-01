package proxy_test

// sftp_capture_test.go proves Phase 59 — SFTP per-file content recording — end
// to end with the same real client/server harness as sftp_test.go: genuine v3
// packets cross the proxy, and the tests assert on what landed on disk, what
// the audit trail attests, and what the target actually received. A passing
// upload test proves the captured artifact holds byte-for-byte what moved;
// a passing cap test proves bytes past the cap never reached the target.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/recording"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// startProxySFTPCapture serves a proxy with content capture configured,
// returning the store, proxy address, upstream, recording dir and vault (for
// unsealing artifacts in the encrypted test).
func startProxySFTPCapture(t *testing.T, capture proxy.SFTPCaptureMode, maxBytes int64, encrypt bool) (store.Store, string, *sftpUpstream, string, *vault.Vault) {
	t.Helper()
	up := startUpstreamSFTP(t)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, up.host, up.port)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	recDir := t.TempDir()
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey:             mustSigner(t),
		RecordingDir:        recDir,
		DialTimeout:         5 * time.Second,
		SFTPMode:            proxy.SFTPAllow,
		SFTPCapture:         capture,
		SFTPCaptureMaxBytes: maxBytes,
		EncryptRecordings:   encrypt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return st, serveProxy(t, px), up, recDir, v
}

// capturedArtifact is one decoded .sftp artifact for assertions.
type capturedArtifact struct {
	name   string
	sealed bool
	hdr    recording.SFTPFileHeader
	chunks []recording.SFTPChunk
}

// awaitArtifacts polls the recording dir until want .sftp artifacts exist (the
// proxy finalizes them asynchronously as the session tears down), then decodes
// each — unsealing with v when the file carries the seal magic.
func awaitArtifacts(t *testing.T, dir string, v *vault.Vault, want int) []capturedArtifact {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		names, _ := filepath.Glob(filepath.Join(dir, "*.sftp"))
		if len(names) >= want || time.Now().After(deadline) {
			if len(names) != want {
				t.Fatalf("artifacts on disk = %d, want %d (%v)", len(names), want, names)
			}
			var out []capturedArtifact
			for _, n := range names {
				raw, err := os.ReadFile(n)
				if err != nil {
					t.Fatal(err)
				}
				a := capturedArtifact{name: filepath.Base(n), sealed: recording.IsSealed(raw)}
				pr, err := recording.Open(context.Background(), bytes.NewReader(raw), v, a.name)
				if err != nil {
					t.Fatalf("open artifact %s: %v", a.name, err)
				}
				a.hdr, a.chunks, err = recording.DecodeSFTPFile(pr)
				if err != nil {
					t.Fatalf("decode artifact %s: %v", a.name, err)
				}
				out = append(out, a)
			}
			return out
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// awaitAudit polls for an audit event with the given action containing want —
// capture finalization runs on session teardown, after the client's Close
// returns, so a one-shot check would race it.
func awaitAudit(t *testing.T, st store.Store, action, want string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		events, err := st.ListAudit(context.Background(), 200)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if e.Action == action && strings.Contains(e.Detail, want) {
				return e.Detail
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no audit event action=%q containing %q after waiting", action, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// sha256Hex hashes b and returns the hex digest, for comparing audited hashes
// against files as stored on disk.
func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// auditFieldValue extracts `key:value` from an audit detail (values the proxy
// writes unquoted: hashes, counts, file names).
func auditFieldValue(detail, key string) string {
	for _, f := range strings.Fields(detail) {
		if strings.HasPrefix(f, key+":") {
			return strings.TrimPrefix(f, key+":")
		}
	}
	return ""
}

// TestSFTPCaptureUpload proves an upload's bytes are captured: two WRITEs sent
// out of order reconstruct to the exact content, the artifact's SHA-256 (as
// stored) is stamped into sftp.file_recorded with a chain position, and the
// transfer itself reached the target unchanged.
func TestSFTPCaptureUpload(t *testing.T) {
	st, addr, up, recDir, v := startProxySFTPCapture(t, proxy.SFTPCaptureAll, 0, false)
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused")
	}
	defer client.Close()
	initSFTP(t, ch)

	ch.Write(sftpPacket(tOpen, be32(1), sftpStr("/srv/report.csv"), be32(pWrite|pCreat|pTrunc), be32(0)))
	if typ, _, _ := readPacket(ch); typ != tHandle {
		t.Fatalf("open(write) should be forwarded → HANDLE, got type=%d", typ)
	}
	// Out of order: the tail first, then the head — capture must preserve both
	// with their offsets, and reconstruction must reassemble them correctly.
	off6 := make([]byte, 8)
	binary.BigEndian.PutUint64(off6, 6)
	ch.Write(sftpPacket(tWrite, be32(2), sftpStr("h"), off6, sftpStr("world!")))
	if typ, _, _ := readPacket(ch); typ != tStatus {
		t.Fatalf("write#1 status expected, got %d", typ)
	}
	ch.Write(sftpPacket(tWrite, be32(3), sftpStr("h"), make([]byte, 8), sftpStr("hello ")))
	if typ, _, _ := readPacket(ch); typ != tStatus {
		t.Fatalf("write#2 status expected, got %d", typ)
	}
	ch.Write(sftpPacket(tClose, be32(4), sftpStr("h")))
	if typ, _, _ := readPacket(ch); typ != tStatus {
		t.Fatal("close status expected")
	}
	// Both writes reached the target (capture must never eat the transfer).
	up.await(t) // open
	if got := up.await(t); got != "write:world!" {
		t.Fatalf("upstream write#1 = %q", got)
	}
	if got := up.await(t); got != "write:hello " {
		t.Fatalf("upstream write#2 = %q", got)
	}
	client.Close()

	detail := awaitAudit(t, st, "sftp.file_recorded", `path:"/srv/report.csv"`)
	arts := awaitArtifacts(t, recDir, v, 1)
	a := arts[0]
	if a.sealed {
		t.Fatal("artifact must be plaintext when encryption is off")
	}
	if a.hdr.Path != "/srv/report.csv" || a.hdr.OpenMode != "write" {
		t.Fatalf("artifact header: %+v", a.hdr)
	}
	content, sparse, err := recording.ReconstructSFTP(a.chunks, "w", 1<<20)
	if err != nil || sparse || string(content) != "hello world!" {
		t.Fatalf("reconstructed upload = %q sparse=%v err=%v", content, sparse, err)
	}

	// The audit event attests the artifact as stored: name, byte count, hash, chain.
	if got := auditFieldValue(detail, "file"); got != a.name {
		t.Fatalf("audited file = %q, artifact = %q", got, a.name)
	}
	if got := auditFieldValue(detail, "bytes_up"); got != "12" {
		t.Fatalf("audited bytes_up = %q, want 12", got)
	}
	raw, _ := os.ReadFile(filepath.Join(recDir, a.name))
	if got, want := auditFieldValue(detail, "sha256"), sha256Hex(raw); got != want {
		t.Fatalf("audited sha256 = %q, stored-file hash = %q", got, want)
	}
	if auditFieldValue(detail, "chain") == "" {
		t.Fatal("the artifact must join the recording hash chain")
	}
}

// TestSFTPCaptureDownload proves a download's bytes are captured from the DATA
// responses: the artifact carries an "r" chunk with the exact served content.
func TestSFTPCaptureDownload(t *testing.T) {
	st, addr, _, recDir, v := startProxySFTPCapture(t, proxy.SFTPCaptureAll, 0, false)
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused")
	}
	defer client.Close()
	initSFTP(t, ch)

	ch.Write(sftpPacket(tOpen, be32(1), sftpStr("/srv/secret.pem"), be32(pRead), be32(0)))
	if typ, _, _ := readPacket(ch); typ != tHandle {
		t.Fatal("open(read) should be forwarded → HANDLE")
	}
	ch.Write(sftpPacket(tRead, be32(2), sftpStr("h"), make([]byte, 8), be32(1024)))
	if typ, data, _ := readPacket(ch); typ != tData || !strings.Contains(string(data), "file-contents") {
		t.Fatalf("download must still flow, got type=%d", typ)
	}
	ch.Write(sftpPacket(tClose, be32(3), sftpStr("h")))
	if typ, _, _ := readPacket(ch); typ != tStatus {
		t.Fatal("close status expected")
	}
	client.Close()

	detail := awaitAudit(t, st, "sftp.file_recorded", `path:"/srv/secret.pem"`)
	if got := auditFieldValue(detail, "bytes_down"); got != "13" { // len("file-contents")
		t.Fatalf("audited bytes_down = %q, want 13", got)
	}
	arts := awaitArtifacts(t, recDir, v, 1)
	content, _, err := recording.ReconstructSFTP(arts[0].chunks, "r", 1<<20)
	if err != nil || string(content) != "file-contents" {
		t.Fatalf("reconstructed download = %q err=%v", content, err)
	}
}

// TestSFTPCaptureSealed proves the artifact is sealed at rest when recording
// encryption is on — the stored bytes carry the seal magic and only decrypt
// through the vault — and that the audited hash covers the SEALED bytes, so
// the tamper evidence describes the artifact exactly as it rests on disk.
func TestSFTPCaptureSealed(t *testing.T) {
	st, addr, _, recDir, v := startProxySFTPCapture(t, proxy.SFTPCaptureAll, 0, true)
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused")
	}
	defer client.Close()
	initSFTP(t, ch)

	ch.Write(sftpPacket(tOpen, be32(1), sftpStr("/srv/dump.sql"), be32(pWrite|pCreat), be32(0)))
	if typ, _, _ := readPacket(ch); typ != tHandle {
		t.Fatal("open should be forwarded")
	}
	ch.Write(sftpPacket(tWrite, be32(2), sftpStr("h"), make([]byte, 8), sftpStr("SELECT * FROM users;")))
	readPacket(ch)
	ch.Write(sftpPacket(tClose, be32(3), sftpStr("h")))
	readPacket(ch)
	client.Close()

	detail := awaitAudit(t, st, "sftp.file_recorded", `path:"/srv/dump.sql"`)
	arts := awaitArtifacts(t, recDir, v, 1)
	a := arts[0]
	if !a.sealed {
		t.Fatal("artifact must be sealed when PAM_RECORDING_ENCRYPT is on")
	}
	content, _, err := recording.ReconstructSFTP(a.chunks, "w", 1<<20)
	if err != nil || string(content) != "SELECT * FROM users;" {
		t.Fatalf("unsealed reconstruction = %q err=%v", content, err)
	}
	raw, _ := os.ReadFile(filepath.Join(recDir, a.name))
	if got, want := auditFieldValue(detail, "sha256"), sha256Hex(raw); got != want {
		t.Fatalf("audited hash must cover the sealed stored bytes: audit %q, disk %q", got, want)
	}
}

// TestSFTPCaptureCapRefuses proves the per-file cap REFUSES the transfer past
// the cap rather than letting it continue unrecorded: the crossing WRITE gets
// a synthesized permission-denied, never reaches the target, the refusal is
// audited, and the closing audit marks the artifact capped.
func TestSFTPCaptureCapRefuses(t *testing.T) {
	st, addr, up, recDir, v := startProxySFTPCapture(t, proxy.SFTPCaptureAll, 10, false)
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused")
	}
	defer client.Close()
	initSFTP(t, ch)

	ch.Write(sftpPacket(tOpen, be32(1), sftpStr("/srv/big.bin"), be32(pWrite|pCreat), be32(0)))
	if typ, _, _ := readPacket(ch); typ != tHandle {
		t.Fatal("open should be forwarded")
	}
	up.await(t) // open reached the target
	// 8 bytes fit under the 10-byte cap.
	ch.Write(sftpPacket(tWrite, be32(2), sftpStr("h"), make([]byte, 8), sftpStr("12345678")))
	if typ, _, _ := readPacket(ch); typ != tStatus {
		t.Fatal("first write should pass")
	}
	if got := up.await(t); got != "write:12345678" {
		t.Fatalf("first write must reach the target, got %q", got)
	}
	// 8 more would cross the cap: refused with SSH_FX_PERMISSION_DENIED.
	off8 := make([]byte, 8)
	binary.BigEndian.PutUint64(off8, 8)
	ch.Write(sftpPacket(tWrite, be32(3), sftpStr("h"), off8, sftpStr("87654321")))
	typ, body, err := readPacket(ch)
	if err != nil || typ != tStatus {
		t.Fatalf("capped write reply: type=%d err=%v", typ, err)
	}
	if code := binary.BigEndian.Uint32(body[4:8]); code != 3 {
		t.Fatalf("capped write status = %d, want 3 (permission denied)", code)
	}
	ch.Write(sftpPacket(tClose, be32(4), sftpStr("h")))
	readPacket(ch)
	client.Close()

	// The refused bytes never reached the target.
	select {
	case got := <-up.got:
		t.Fatalf("a write past the capture cap reached the target: %q", got)
	default:
	}
	assertAuditContains(t, st, "sftp.blocked", "reason:capture-limit")
	detail := awaitAudit(t, st, "sftp.file_recorded", `path:"/srv/big.bin"`)
	if !strings.Contains(detail, "capped:true") {
		t.Fatalf("closing audit must mark the artifact capped: %s", detail)
	}
	if got := auditFieldValue(detail, "bytes_up"); got != "8" {
		t.Fatalf("captured bytes_up = %q, want 8 (only what moved)", got)
	}
	arts := awaitArtifacts(t, recDir, v, 1)
	content, _, _ := recording.ReconstructSFTP(arts[0].chunks, "w", 1<<20)
	if string(content) != "12345678" {
		t.Fatalf("artifact must hold exactly what moved: %q", content)
	}
}

// TestSFTPCaptureUploadsOnly proves direction scoping: in uploads mode a
// download leaves no artifact (its open is never tracked), while an upload in
// the same session is captured.
func TestSFTPCaptureUploadsOnly(t *testing.T) {
	st, addr, _, recDir, v := startProxySFTPCapture(t, proxy.SFTPCaptureUploads, 0, false)
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused")
	}
	defer client.Close()
	initSFTP(t, ch)

	// A download: flows, but produces no artifact in uploads mode.
	ch.Write(sftpPacket(tOpen, be32(1), sftpStr("/srv/readme.txt"), be32(pRead), be32(0)))
	if typ, _, _ := readPacket(ch); typ != tHandle {
		t.Fatal("read open should be forwarded")
	}
	ch.Write(sftpPacket(tRead, be32(2), sftpStr("h"), make([]byte, 8), be32(64)))
	if typ, _, _ := readPacket(ch); typ != tData {
		t.Fatal("download must still flow")
	}
	ch.Write(sftpPacket(tClose, be32(3), sftpStr("h")))
	readPacket(ch)

	// An upload: captured.
	ch.Write(sftpPacket(tOpen, be32(4), sftpStr("/srv/up.txt"), be32(pWrite|pCreat), be32(0)))
	if typ, _, _ := readPacket(ch); typ != tHandle {
		t.Fatal("write open should be forwarded")
	}
	ch.Write(sftpPacket(tWrite, be32(5), sftpStr("h"), make([]byte, 8), sftpStr("payload")))
	readPacket(ch)
	ch.Write(sftpPacket(tClose, be32(6), sftpStr("h")))
	readPacket(ch)
	client.Close()

	detail := awaitAudit(t, st, "sftp.file_recorded", `path:"/srv/up.txt"`)
	if got := auditFieldValue(detail, "bytes_up"); got != "7" {
		t.Fatalf("bytes_up = %q, want 7", got)
	}
	arts := awaitArtifacts(t, recDir, v, 1) // exactly one: the upload, not the download
	if arts[0].hdr.Path != "/srv/up.txt" {
		t.Fatalf("the only artifact must be the upload, got %q", arts[0].hdr.Path)
	}
}

// TestSFTPCaptureDeferredClose proves the close-with-read-in-flight evasion is
// closed: a client that sends CLOSE while a READ is outstanding still has the
// late DATA captured — the artifact's finalization is deferred until the read
// resolves, so the downloaded bytes appear in the sealed evidence.
func TestSFTPCaptureDeferredClose(t *testing.T) {
	st, addr, up, recDir, v := startProxySFTPCapture(t, proxy.SFTPCaptureAll, 0, false)
	up.deferData.Store(true) // the upstream answers a READ only after it sees CLOSE
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused")
	}
	defer client.Close()
	initSFTP(t, ch)

	ch.Write(sftpPacket(tOpen, be32(1), sftpStr("/srv/late.txt"), be32(pRead), be32(0)))
	if typ, _, _ := readPacket(ch); typ != tHandle {
		t.Fatal("open should be forwarded")
	}
	// READ then CLOSE, without waiting: CLOSE reaches the proxy (and the server)
	// while the READ's DATA is still pending.
	ch.Write(sftpPacket(tRead, be32(2), sftpStr("h"), make([]byte, 8), be32(64)))
	ch.Write(sftpPacket(tClose, be32(3), sftpStr("h")))
	// The server then emits DATA (for the read) followed by the close's STATUS.
	if typ, data, _ := readPacket(ch); typ != tData || !strings.Contains(string(data), "late-data") {
		t.Fatalf("want the deferred DATA first, got type=%d", typ)
	}
	if typ, _, _ := readPacket(ch); typ != tStatus {
		t.Fatal("want the close STATUS after the data")
	}
	client.Close()

	awaitAudit(t, st, "sftp.file_recorded", `path:"/srv/late.txt"`)
	arts := awaitArtifacts(t, recDir, v, 1)
	content, _, err := recording.ReconstructSFTP(arts[0].chunks, "r", 1<<20)
	if err != nil || string(content) != "late-data" {
		t.Fatalf("late DATA must be captured despite the early CLOSE: %q err=%v", content, err)
	}
}

// TestSFTPCaptureFailsClosedOnGarbage proves the posture inversion: with
// capture ON, an unframable SFTP stream tears the session down (audited)
// instead of passing through opaquely — a client cannot move files uncaptured
// by declining to be parseable.
func TestSFTPCaptureFailsClosedOnGarbage(t *testing.T) {
	st, addr, _, _, _ := startProxySFTPCapture(t, proxy.SFTPCaptureAll, 0, false)
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused")
	}
	defer client.Close()
	initSFTP(t, ch)

	// A length prefix far beyond the 1 MiB packet bound: unframable.
	ch.Write(be32(0xFFFFFF00))
	// The proxy must fail the session closed: the channel ends rather than the
	// garbage being forwarded.
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 256)
	for {
		if _, err := ch.Read(buf); err != nil {
			break // torn down
		}
		if time.Now().After(deadline) {
			t.Fatal("session was not torn down after an unframable stream under capture")
		}
	}
	assertAuditContains(t, st, "sftp.parse_error", "fails closed")
}

// TestParseSFTPCaptureMode covers the config enum mapping, including the
// fail-loud unknown value.
func TestParseSFTPCaptureMode(t *testing.T) {
	for in, want := range map[string]proxy.SFTPCaptureMode{
		"": proxy.SFTPCaptureOff, "off": proxy.SFTPCaptureOff,
		"uploads": proxy.SFTPCaptureUploads, "downloads": proxy.SFTPCaptureDownloads, "all": proxy.SFTPCaptureAll,
	} {
		if got, err := proxy.ParseSFTPCaptureMode(in); err != nil || got != want {
			t.Fatalf("ParseSFTPCaptureMode(%q) = %q,%v; want %q", in, got, err, want)
		}
	}
	if _, err := proxy.ParseSFTPCaptureMode("everything"); err == nil {
		t.Fatal("an unknown capture mode must be rejected")
	}
}
