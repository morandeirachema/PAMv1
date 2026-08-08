package guacd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

// clipFrames renders one complete Guacamole clipboard transfer (open, one or
// more blobs, end) as the wire frames the tunnel carries.
func clipFrames(stream, mimetype string, chunks ...string) [][]byte {
	out := [][]byte{[]byte(Instruction{Opcode: "clipboard", Args: []string{stream, mimetype}}.Encode())}
	for _, c := range chunks {
		out = append(out, []byte(Instruction{
			Opcode: "blob", Args: []string{stream, base64.StdEncoding.EncodeToString([]byte(c))},
		}.Encode()))
	}
	return append(out, []byte(Instruction{Opcode: "end", Args: []string{stream}}.Encode()))
}

// observeAll feeds frames to the watcher and collects completed transfers.
func observeAll(w *ClipWatcher, direction string, frames [][]byte) []ClipTransfer {
	var got []ClipTransfer
	for _, f := range frames {
		got = append(got, w.Observe(direction, f)...)
	}
	return got
}

// TestClipWatcherMetaMode proves the default: a clipboard transfer is
// reconstructed across its blob chunks and audited by direction, mimetype, size
// and digest — but the CONTENT is not recorded, because a privileged desktop's
// clipboard routinely carries a password the operator just copied.
func TestClipWatcherMetaMode(t *testing.T) {
	w := NewClipWatcher("meta")
	if w == nil {
		t.Fatal("meta mode must produce a watcher")
	}
	secret := "hunter2-copied-from-the-vault"
	got := observeAll(w, "out", clipFrames("1", "text/plain", "hunter2-", "copied-from-the-vault"))
	if len(got) != 1 {
		t.Fatalf("want 1 completed transfer, got %d", len(got))
	}
	tr := got[0]
	if tr.Direction != "out" || tr.Mimetype != "text/plain" || tr.Bytes != len(secret) {
		t.Fatalf("transfer = %+v", tr)
	}
	sum := sha256.Sum256([]byte(secret))
	if tr.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest covers the wrong bytes: %s", tr.SHA256)
	}
	if tr.Preview != "" || strings.Contains(tr.Detail(), secret) {
		t.Fatalf("meta mode leaked clipboard content into the audit detail: %q", tr.Detail())
	}
}

// TestClipWatcherFullMode proves the opt-in records content, flattened so one
// transfer stays one audit line and cannot forge a second.
func TestClipWatcherFullMode(t *testing.T) {
	w := NewClipWatcher("full")
	got := observeAll(w, "in", clipFrames("2", "text/plain", "line one\nrdp.clipboard forged"))
	if len(got) != 1 {
		t.Fatalf("want 1 transfer, got %d", len(got))
	}
	detail := got[0].Detail()
	if !strings.Contains(detail, "line one") {
		t.Fatalf("full mode did not record content: %q", detail)
	}
	if strings.Contains(detail, "\n") {
		t.Fatalf("newline survived into the audit detail (record injection): %q", detail)
	}
	if got[0].Direction != "in" {
		t.Fatalf("direction = %q, want in (paste into the target)", got[0].Direction)
	}
}

// TestClipWatcherOffIsNil proves auditing is off unless explicitly asked for —
// including for an unrecognized value, so a typo cannot silently start writing
// clipboard content into the trail.
func TestClipWatcherOffIsNil(t *testing.T) {
	for _, mode := range []string{"", "off", "nonsense", "FULLY"} {
		if w := NewClipWatcher(mode); w != nil {
			t.Fatalf("mode %q produced a watcher; want nil (auditing is opt-in)", mode)
		}
	}
	// A nil watcher observes nothing and does not panic on the hot path.
	var nilW *ClipWatcher
	if tr := nilW.Observe("out", []byte("9.clipboard,1.1,10.text/plain;")); tr != nil {
		t.Fatal("nil watcher reported a transfer")
	}
}

// TestClipWatcherIgnoresOtherStreams proves the watcher only reports clipboard
// transfers: an image/file stream's blob+end (the bulk of an RDP session) must
// not be mistaken for one.
func TestClipWatcherIgnoresOtherStreams(t *testing.T) {
	w := NewClipWatcher("meta")
	frames := [][]byte{
		[]byte(Instruction{Opcode: "img", Args: []string{"7", "12", "0", "image/png", "0", "0"}}.Encode()),
		[]byte(Instruction{Opcode: "blob", Args: []string{"7", base64.StdEncoding.EncodeToString([]byte("PNGDATA"))}}.Encode()),
		[]byte(Instruction{Opcode: "end", Args: []string{"7"}}.Encode()),
	}
	if got := observeAll(w, "out", frames); len(got) != 0 {
		t.Fatalf("non-clipboard stream reported as a clipboard transfer: %+v", got)
	}
}

// TestClipWatcherDirectionsAreIndependent proves a copy-out and a paste-in that
// happen to share a stream index are tracked separately — the two directions
// are distinct Guacamole streams and must not merge.
func TestClipWatcherDirectionsAreIndependent(t *testing.T) {
	w := NewClipWatcher("meta")
	out := observeAll(w, "out", clipFrames("1", "text/plain", "from-target"))
	in := observeAll(w, "in", clipFrames("1", "text/plain", "to-target-longer"))
	if len(out) != 1 || len(in) != 1 {
		t.Fatalf("out=%d in=%d, want 1 each", len(out), len(in))
	}
	if out[0].Bytes == in[0].Bytes || out[0].Direction == in[0].Direction {
		t.Fatalf("directions merged: out=%+v in=%+v", out[0], in[0])
	}
}

// TestClipWatcherTruncatesHugeTransfer proves a huge clipboard is still audited
// (flagged truncated) rather than buffered without limit. It arrives the way a
// real one does — many modest blob chunks, not one enormous element — since
// guacd chunks a stream and the decoder caps any single element at 1 MiB.
func TestClipWatcherTruncatesHugeTransfer(t *testing.T) {
	w := NewClipWatcher("meta")
	const chunk = 4096
	chunks := make([]string, clipStreamMax/chunk+2)
	for i := range chunks {
		chunks[i] = strings.Repeat("A", chunk)
	}
	got := observeAll(w, "in", clipFrames("3", "text/plain", chunks...))
	if len(got) != 1 {
		t.Fatalf("want 1 transfer, got %d", len(got))
	}
	if !got[0].Truncated {
		t.Fatal("oversized transfer was not flagged truncated")
	}
	if got[0].Bytes > clipStreamMax {
		t.Fatalf("buffered %d bytes, want at most %d", got[0].Bytes, clipStreamMax)
	}
}

// TestGuacdDecodeRoundTrip proves the decoder is the exact inverse of Encode,
// including values that contain the protocol's own delimiters — the reason the
// length prefixes, not the separators, are authoritative.
func TestGuacdDecodeRoundTrip(t *testing.T) {
	want := Instruction{Opcode: "clipboard", Args: []string{"1", "text/plain;charset=utf-8", "a,b;c"}}
	got, ok := Decode([]byte(want.Encode()))
	if !ok {
		t.Fatal("Decode rejected its own Encode output")
	}
	if got.Opcode != want.Opcode || len(got.Args) != len(want.Args) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want.Args {
		if got.Args[i] != want.Args[i] {
			t.Fatalf("arg %d = %q, want %q", i, got.Args[i], want.Args[i])
		}
	}
	// Malformed input is reported, never panics — the observer must forward
	// frames it cannot read rather than choke on them.
	for _, bad := range []string{"", "nonsense", "5.abc", "99999999999999.x;"} {
		if _, ok := Decode([]byte(bad)); ok {
			t.Fatalf("Decode accepted malformed input %q", bad)
		}
	}
}

// TestClipWatcherSeesBatchedInstructions proves a clipboard transfer is audited
// even when the whole thing arrives in ONE WebSocket message.
//
// The Guacamole protocol is a stream of self-delimiting instructions, and
// nothing requires one per message — a client may concatenate them, and the
// bridge forwards whatever it receives to guacd in full. The watcher used to
// decode only the FIRST instruction in a frame, so prefixing a batch with a
// harmless `nop` meant the clipboard and blob instructions behind it were
// forwarded to the target completely unexamined. Data left a privileged desktop
// with nothing in the audit trail, which is precisely what Phase 50 exists to
// prevent.
func TestClipWatcherSeesBatchedInstructions(t *testing.T) {
	w := NewClipWatcher("meta")

	// Everything in one frame, led by a decoy instruction.
	var batch []byte
	batch = append(batch, []byte(Instruction{Opcode: "nop"}.Encode())...)
	for _, f := range clipFrames("7", "text/plain", "exfiltrated-secret") {
		batch = append(batch, f...)
	}

	got := w.Observe("in", batch)
	if len(got) != 1 {
		t.Fatalf("a clipboard transfer batched into a single frame produced %d observations, want 1; prefixing a `nop` must not evade the clipboard audit", len(got))
	}
	if got[0].Direction != "in" {
		t.Fatalf("direction = %q, want %q", got[0].Direction, "in")
	}
	if got[0].Bytes != len("exfiltrated-secret") {
		t.Fatalf("bytes = %d, want %d", got[0].Bytes, len("exfiltrated-secret"))
	}
	if got[0].Mimetype != "text/plain" {
		t.Fatalf("mimetype = %q, want text/plain", got[0].Mimetype)
	}
}

// TestClipWatcherReportsEveryTransferInAFrame proves a frame that completes
// SEVERAL transfers reports all of them.
//
// Returning only the last was a subtler version of the evasion the batching fix
// closed: two clipboard streams concatenated into one WebSocket message meant
// the first transfer happened with no audit record of it at all. The fix that
// made the watcher decode every instruction still reported a single transfer,
// so the hole was narrower but not shut.
func TestClipWatcherReportsEveryTransferInAFrame(t *testing.T) {
	w := NewClipWatcher("meta")

	var batch []byte
	for _, f := range clipFrames("1", "text/plain", "first-secret") {
		batch = append(batch, f...)
	}
	for _, f := range clipFrames("2", "text/plain", "second-secret-longer") {
		batch = append(batch, f...)
	}

	got := w.Observe("in", batch)
	if len(got) != 2 {
		t.Fatalf("a frame completing two transfers reported %d; the others are absent from the audit trail entirely", len(got))
	}
	sizes := map[int]bool{got[0].Bytes: true, got[1].Bytes: true}
	if !sizes[len("first-secret")] || !sizes[len("second-secret-longer")] {
		t.Fatalf("reported sizes %v do not cover both transfers (%d and %d)",
			[]int{got[0].Bytes, got[1].Bytes}, len("first-secret"), len("second-secret-longer"))
	}
}

// TestGuacdDecodeAllStopsCleanly proves DecodeAll reads every instruction in a
// buffer and stops at the first unreadable one rather than looping or panicking.
// The observer must degrade to "saw what I could parse", never to a hang on the
// data path of a live desktop.
func TestGuacdDecodeAllStopsCleanly(t *testing.T) {
	two := Instruction{Opcode: "nop"}.Encode() +
		Instruction{Opcode: "clipboard", Args: []string{"1", "text/plain"}}.Encode()
	if got := DecodeAll([]byte(two)); len(got) != 2 || got[1].Opcode != "clipboard" {
		t.Fatalf("DecodeAll(two instructions) = %+v, want both", got)
	}
	// Trailing garbage: keep the clean prefix, discard the rest.
	if got := DecodeAll([]byte(two + "not-an-instruction")); len(got) != 2 {
		t.Fatalf("DecodeAll with trailing garbage returned %d instructions, want the 2 clean ones", len(got))
	}
	for _, bad := range []string{"", "nonsense", "5.abc", "99999999999999.x;"} {
		if got := DecodeAll([]byte(bad)); len(got) != 0 {
			t.Fatalf("DecodeAll(%q) = %+v, want none", bad, got)
		}
	}
}

// quotedSpan matches one Go-quoted string, so a test can strip the spans a
// quoting-aware reader would never parse fields out of.
var quotedSpan = regexp.MustCompile(`"(\\.|[^"\\])*"`)

// TestClipDetailResistsMimetypeForgery pins the sanitisation of the one field in
// a clipboard record that comes off the wire.
//
// The mimetype is `clipboard,<stream>,<mimetype>` — chosen by whoever is at the
// other end of the tunnel, which is the operator's browser or a compromised RDP
// host. It was interpolated raw, and it is the SECOND field of the detail, so a
// mimetype of `text/plain bytes:0 sha256:00…` put a forged byte count and digest
// AHEAD of the real ones. To a first-wins reader a megabyte of exfiltrated
// clipboard data then read as an empty transfer — in the single record whose
// entire purpose is to evidence that the copy happened.
func TestClipDetailResistsMimetypeForgery(t *testing.T) {
	const zero = "0000000000000000000000000000000000000000000000000000000000000000"
	w := NewClipWatcher(ClipAuditMeta)
	got := observeAll(w, "out", clipFrames("1", "text/plain bytes:0 sha256:"+zero, "secrets"))
	if len(got) != 1 {
		t.Fatalf("got %d transfers, want 1", len(got))
	}
	d := got[0].Detail()
	// Read it the way a quoting-aware consumer does: outside the quoted spans,
	// none of the forged text may survive as a field.
	outside := quotedSpan.ReplaceAllString(d, `""`)
	if strings.Contains(outside, "bytes:0 ") || strings.Contains(outside, zero) {
		t.Fatalf("a wire-supplied mimetype forged fields into the clipboard audit detail: %q", d)
	}
	// The truth still has to be there — the record is evidence, not just safe.
	if !strings.Contains(d, "bytes:7") {
		t.Fatalf("the real byte count is missing: %q", d)
	}
}

// TestClipDetailBoundsTheMimetype keeps a hostile client from choosing the size
// of an audit row. Clipboard transfers are repeatable at will, so an unbounded
// field here is an audit-flooding primitive.
func TestClipDetailBoundsTheMimetype(t *testing.T) {
	w := NewClipWatcher(ClipAuditMeta)
	got := observeAll(w, "out", clipFrames("1", strings.Repeat("A", 64*1024), "x"))
	if len(got) != 1 {
		t.Fatalf("got %d transfers, want 1", len(got))
	}
	if d := got[0].Detail(); len(d) > 512 {
		t.Fatalf("a 64KiB mimetype produced a %d-byte audit detail; it must be bounded", len(d))
	}
}
