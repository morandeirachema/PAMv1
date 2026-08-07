package proxy

// sftpcapture_internal_test.go covers the capture engine's invariants at the
// unit level — the ones a wire-level test cannot reach directly: where an
// artifact is allowed to land, which auditor writes its attestation, how the
// per-file cap accounts for reads still in flight, and that the response
// watcher never hands a caller half a packet.

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// playbackNameRe mirrors api.recordingNameRe. Duplicated deliberately: the
// point of this test is that the two agree, so it must state the API's rule
// rather than import (and therefore inherit) it.
var playbackNameRe = regexp.MustCompile(`^[A-Za-z0-9_@-][A-Za-z0-9._@-]*\.(cast|winrm\.log|sftp)$`)

// captureHarness builds a capture with recorded audit output.
type captureHarness struct {
	c             *sftpCapture
	dir           string
	live, closing []string
	liveN, closeN int
}

func newCaptureHarness(t *testing.T, base string, mode SFTPCaptureMode, maxBytes int64) *captureHarness {
	t.Helper()
	h := &captureHarness{dir: t.TempDir()}
	h.c = newSFTPCapture(context.Background(), h.dir, base, nil, newRecordChain(h.dir), mode, maxBytes,
		func(action, detail string) { h.live = append(h.live, action+" "+detail); h.liveN++ },
		func(action, detail string) { h.closing = append(h.closing, action+" "+detail); h.closeN++ },
	)
	return h
}

// TestCaptureArtifactNameIsContained proves a hostile target or actor name in
// the session title cannot steer an artifact out of the recording directory,
// and cannot produce a name the playback allowlist refuses.
//
// Both halves matter. A traversing name would let an operator overwrite a file
// outside the recording volume with bytes of their choosing (the artifact is
// opened O_CREATE|O_TRUNC), and a merely unusual one — a space in a target
// name — would write evidence that lists nowhere, replays nowhere and is never
// archived, while retention still deletes it on schedule.
func TestCaptureArtifactNameIsContained(t *testing.T) {
	for _, base := range []string{
		"1700000000_../../etc/pwned_alice",
		"1700000000_web 01_alice",
		"1700000000_..%2f..%2fetc_alice",
		"../../../../tmp/evil",
	} {
		h := newCaptureHarness(t, base, SFTPCaptureAll, 0)
		if h.c.trackOpen(1, "/srv/x", false, true) {
			t.Fatalf("%q: the open should be tracked", base)
		}
		h.c.bindHandle(1, "handle")
		if h.c.gateWrite("handle", 0, []byte("operator-chosen bytes")) {
			t.Fatalf("%q: the write should be captured, not refused", base)
		}
		h.c.noteClose("handle")

		entries, err := os.ReadDir(h.dir)
		if err != nil {
			t.Fatal(err)
		}
		artifacts := 0
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".sftp") {
				continue
			}
			artifacts++
			if !playbackNameRe.MatchString(e.Name()) {
				t.Fatalf("%q produced %q, which the playback allowlist refuses", base, e.Name())
			}
			// Nothing escaped: the file resolves inside the recording dir.
			abs, _ := filepath.Abs(filepath.Join(h.dir, e.Name()))
			root, _ := filepath.Abs(h.dir)
			if filepath.Dir(abs) != root {
				t.Fatalf("%q wrote outside the recording directory: %s", base, abs)
			}
		}
		if artifacts != 1 {
			t.Fatalf("%q: want exactly one artifact, got %d", base, artifacts)
		}
		// And nothing was created above the recording directory.
		if _, err := os.Stat(filepath.Join(h.dir, "..", "pwned_alice_f0.sftp")); err == nil {
			t.Fatalf("%q escaped one level up", base)
		}
	}
}

// TestCaptureAttestationUsesTheClosingAuditor proves sftp.file_recorded is
// written through the teardown auditor, not the live one. A session drained by
// shutdown finalizes its artifacts with a cancelled context, and the chain head
// has already advanced on disk — an attestation lost there leaves a file whose
// hash appears nowhere, which playback reports exactly like tampering.
func TestCaptureAttestationUsesTheClosingAuditor(t *testing.T) {
	h := newCaptureHarness(t, "t_web-01_alice", SFTPCaptureAll, 0)
	h.c.trackOpen(1, "/srv/x", false, true)
	h.c.bindHandle(1, "handle")
	h.c.gateWrite("handle", 0, []byte("bytes"))
	h.c.noteClose("handle")

	if len(h.closing) != 1 || !strings.HasPrefix(h.closing[0], "sftp.file_recorded ") {
		t.Fatalf("the attestation must go through the closing auditor, got %v", h.closing)
	}
	for _, e := range h.live {
		if strings.HasPrefix(e, "sftp.file_recorded") {
			t.Fatalf("the attestation must not go through the live auditor: %q", e)
		}
	}
}

// TestCaptureCapCountsInFlightReads proves the per-file cap accounts for the
// bytes pipelined READs have already claimed. Counting only delivered bytes
// made the documented hard limit an upload-only control: a client with 64
// outstanding 256 KiB reads walks 16 MiB past a 1 MiB cap before the first
// refusal.
func TestCaptureCapCountsInFlightReads(t *testing.T) {
	const cap64 = 64 * 1024
	h := newCaptureHarness(t, "t_web-01_alice", SFTPCaptureAll, cap64)
	h.c.trackOpen(1, "/srv/big.bin", true, false)
	h.c.bindHandle(1, "handle")

	// Two 32 KiB reads exactly fill the cap; the third is refused even though
	// not a single byte has come back yet.
	if h.c.gateRead(10, "handle", 0, 32*1024) {
		t.Fatal("first read should be admitted")
	}
	if h.c.gateRead(11, "handle", 32*1024, 32*1024) {
		t.Fatal("second read should be admitted")
	}
	if !h.c.gateRead(12, "handle", 64*1024, 32*1024) {
		t.Fatal("a read beyond the cap must be refused while earlier reads are still in flight")
	}

	// A read that resolves with less than it asked for releases the remainder,
	// so the cap is not permanently consumed by an over-large request.
	h.c.noteData(10, make([]byte, 1024))
	if h.c.gateRead(13, "handle", 0, 16*1024) {
		t.Fatal("the unused part of a resolved read's claim must be released")
	}
}

// TestRespWatcherForwardsWholePackets proves the watcher hands the caller only
// complete packets. The request goroutine writes synthesized refusals to the
// same serialized writer, so forwarding a half-written DATA response would let
// a refusal land inside it and shift every later packet boundary — silently
// corrupting the transfer.
func TestRespWatcherForwardsWholePackets(t *testing.T) {
	h := newCaptureHarness(t, "t_web-01_alice", SFTPCaptureAll, 0)
	w := &sftpRespWatcher{cap: h.c}

	// One DATA packet: length | type | id | string(payload).
	payload := bytes.Repeat([]byte("x"), 4096)
	body := []byte{fxpData}
	body = binary.BigEndian.AppendUint32(body, 7)
	body = binary.BigEndian.AppendUint32(body, uint32(len(payload)))
	body = append(body, payload...)
	pkt := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	pkt = append(pkt, body...)

	// Split anywhere: nothing is forwarded until the packet is whole.
	for _, cut := range []int{1, 3, 4, 9, len(pkt) - 1} {
		w.buf.Reset()
		out, err := w.observe(pkt[:cut])
		if err != nil {
			t.Fatalf("cut %d: %v", cut, err)
		}
		if len(out) != 0 {
			t.Fatalf("cut %d: forwarded %d bytes of an incomplete packet", cut, len(out))
		}
		out, err = w.observe(pkt[cut:])
		if err != nil {
			t.Fatalf("cut %d (rest): %v", cut, err)
		}
		if !bytes.Equal(out, pkt) {
			t.Fatalf("cut %d: forwarded %d bytes, want the whole %d-byte packet", cut, len(out), len(pkt))
		}
	}
}

// TestRespWatcherReleasesEveryResponseKind proves ids are freed for the
// response types capture does not otherwise care about (NAME, ATTRS,
// EXTENDED_REPLY). Without that, an ordinary `ls`-heavy session leaks a slot
// per directory listing until the outstanding bound refuses honest work.
func TestRespWatcherReleasesEveryResponseKind(t *testing.T) {
	h := newCaptureHarness(t, "t_web-01_alice", SFTPCaptureAll, 0)
	w := &sftpRespWatcher{cap: h.c}

	for i, typ := range []byte{fxpName, fxpAttrs, fxpExtendedReply, fxpStatus} {
		id := uint32(100 + i)
		if h.c.noteRequest(id) {
			t.Fatalf("request %d should be claimable", id)
		}
		body := []byte{typ}
		body = binary.BigEndian.AppendUint32(body, id)
		pkt := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
		pkt = append(pkt, body...)
		if _, err := w.observe(pkt); err != nil {
			t.Fatalf("type %d: %v", typ, err)
		}
		if h.c.noteRequest(id) {
			t.Fatalf("type %d did not release request id %d", typ, id)
		}
	}
}

// TestCaptureRefusesReusedRequestID proves an id may name only one outstanding
// request while capture is on: a client that reuses one can otherwise make an
// unrelated response resolve a pending OPEN, after which the handle is
// untracked and its content moves uncaptured.
func TestCaptureRefusesReusedRequestID(t *testing.T) {
	h := newCaptureHarness(t, "t_web-01_alice", SFTPCaptureAll, 0)
	if h.c.noteRequest(7) {
		t.Fatal("first claim of id 7 should succeed")
	}
	if !h.c.noteRequest(7) {
		t.Fatal("a second in-flight request with id 7 must be refused")
	}
	h.c.releaseID(7)
	if h.c.noteRequest(7) {
		t.Fatal("id 7 must be reusable once its response has arrived")
	}
}

// TestCaptureBoundsTheTrackingTable proves the handle table cannot be grown
// without limit, which is the whole premise of the bounds block above it.
//
// The hole it closes: `seq` — the per-session artifact bound trackOpen enforces
// — only advances when an artifact is actually created, and creation stops once
// the open-artifact cap is reached. So past that point every further OPEN added
// a permanent entry that no bound covered, while the bind path rescanned the
// whole table each time, under the mutex both SFTP legs need for every packet.
// A real sftp-server self-limits at its descriptor ceiling; a compromised target
// answering every OPEN with a fresh handle does not.
//
// Verified to fail against the pre-fix code, where the table grew past the cap.
func TestCaptureBoundsTheTrackingTable(t *testing.T) {
	h := newCaptureHarness(t, "t_web-01_alice", SFTPCaptureAll, 0)
	// Fill the table with handles that are opened and never closed.
	for i := 0; i < sftpCaptureMaxOpen; i++ {
		id := uint32(i + 1)
		if h.c.trackOpen(id, "/srv/f", false, true) {
			t.Fatalf("open %d refused while the table still has room", i)
		}
		h.c.bindHandle(id, "handle-"+strconv.Itoa(i))
	}
	if got := len(h.c.files); got != sftpCaptureMaxOpen {
		t.Fatalf("tracked handles = %d, want %d", got, sftpCaptureMaxOpen)
	}
	// Every further OPEN is refused on the REQUEST leg, so no handle is ever
	// issued for it and no data can move against one capture is not tracking.
	for i := 0; i < 500; i++ {
		id := uint32(sftpCaptureMaxOpen + i + 1)
		if !h.c.trackOpen(id, "/srv/overflow", false, true) {
			t.Fatalf("open %d past the cap must be refused", i)
		}
	}
	if got := len(h.c.files); got != sftpCaptureMaxOpen {
		t.Fatalf("tracked handles grew to %d past the cap of %d", got, sftpCaptureMaxOpen)
	}
	if h.c.open != sftpCaptureMaxOpen {
		t.Fatalf("open-artifact count = %d, want %d", h.c.open, sftpCaptureMaxOpen)
	}
	// The refusal is audited once, not once per refused open.
	blocked := 0
	for _, a := range h.live {
		if strings.Contains(a, "reason:capture-backlog") {
			blocked++
		}
	}
	if blocked != 1 {
		t.Fatalf("capture-backlog audited %d times, want exactly 1", blocked)
	}
	// Closing a handle frees a slot, so an honest session recovers rather than
	// staying wedged for the rest of its life.
	h.c.noteClose("handle-0")
	if h.c.open != sftpCaptureMaxOpen-1 {
		t.Fatalf("closing a handle left open=%d, want %d", h.c.open, sftpCaptureMaxOpen-1)
	}
	if h.c.trackOpen(99999, "/srv/after-close", false, true) {
		t.Fatal("an open must be admitted again once a handle has closed")
	}
}
