package guacd

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func enc(op string, args ...string) string { return Instruction{Opcode: op, Args: args}.Encode() }

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// scanner flags anything containing EICAR, and errors on "boom".
func scanner(_ context.Context, data []byte) (bool, string, error) {
	switch {
	case strings.Contains(string(data), "boom"):
		return false, "", errors.New("icap down")
	case strings.Contains(string(data), "EICAR"):
		return false, "Eicar-Test-Signature", nil
	}
	return true, "", nil
}

func newTestGate(max int) *Gate {
	return NewGate(GateConfig{Files: true, Clipboard: true, MaxBytes: max, Scan: scanner})
}

func joined(frames [][]byte) string {
	var b strings.Builder
	for _, f := range frames {
		b.Write(f)
	}
	return b.String()
}

func TestNilGatePassesThrough(t *testing.T) {
	var g *Gate
	if NewGate(GateConfig{Scan: scanner}) != nil || NewGate(GateConfig{Files: true}) != nil {
		t.Fatal("a gate holding nothing, or with no scanner, must be nil")
	}
	out := g.Process(context.Background(), DirIn, []byte("anything"))
	if joined(out.Forward) != "anything" {
		t.Fatalf("nil gate forwarded %q", joined(out.Forward))
	}
}

// TestCleanUploadIsReleased: an upload is held — the browser gets the acks
// guacd would have sent — then released whole once clean, and guacd's own
// acks for it are swallowed.
func TestCleanUploadIsReleased(t *testing.T) {
	g := newTestGate(1 << 20)
	ctx := context.Background()
	open := enc("file", "3", "text/plain", "notes.txt")
	blob := enc("blob", "3", b64("hello"))
	end := enc("end", "3")

	o := g.Process(ctx, DirIn, []byte(enc("key", "65", "1")+open))
	if joined(o.Forward) != enc("key", "65", "1") || joined(o.Reply) != enc("ack", "3", "OK", "0") {
		t.Fatalf("open: forward %q reply %q", joined(o.Forward), joined(o.Reply))
	}
	o = g.Process(ctx, DirIn, []byte(blob))
	if len(o.Forward) != 0 || joined(o.Reply) != enc("ack", "3", "OK", "0") {
		t.Fatalf("blob: forward %q reply %q", joined(o.Forward), joined(o.Reply))
	}
	o = g.Process(ctx, DirIn, []byte(end))
	if joined(o.Forward) != open+blob+end || len(o.Done) != 1 || !o.Done[0].Released() || o.Done[0].Bytes != 5 || o.Done[0].Name != "notes.txt" {
		t.Fatalf("end: forward %q done %+v", joined(o.Forward), o.Done)
	}
	if joined(o.Reply) != "" {
		t.Fatalf("a released upload's end is acked by guacd, not the gate: %q", joined(o.Reply))
	}
	// guacd acks open and blob — swallowed, the browser had those — then the
	// end, which passes: the browser hears guacd's own verdict on the write.
	for i := 0; i < 2; i++ {
		if o := g.Process(ctx, DirOut, []byte(enc("ack", "3", "OK (DATA RECEIVED)", "0"))); len(o.Forward) != 0 {
			t.Fatalf("ack %d from guacd was not swallowed", i)
		}
	}
	if o := g.Process(ctx, DirOut, []byte(enc("ack", "3", "OK (STREAM END)", "0"))); len(o.Forward) != 1 {
		t.Fatal("guacd's end ack must reach the browser")
	}
}

// TestBlockedTransfers: an infected download, a scan error, an oversized
// upload and an infected paste never reach the other side.
func TestBlockedTransfers(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name, dir string
		frames    []string
		outcome   string
	}{
		{"infected download", DirOut, []string{enc("file", "7", "application/zip", "a.zip"), enc("blob", "7", b64("X5O!EICAR")), enc("end", "7")}, OutcomeInfected},
		{"scan error", DirOut, []string{enc("body", "1", "8", "text/plain", "b.txt"), enc("blob", "8", b64("boom")), enc("end", "8")}, OutcomeScanError},
		{"too large", DirIn, []string{enc("put", "2", "4", "text/plain", "big.bin"), enc("blob", "4", b64(strings.Repeat("x", 64))), enc("end", "4")}, OutcomeTooLarge},
		{"infected paste", DirIn, []string{enc("clipboard", "5", "text/plain"), enc("blob", "5", b64("EICAR")), enc("end", "5")}, OutcomeInfected},
	}
	for _, tc := range cases {
		g := newTestGate(32)
		var forwarded string
		var done []Verdict
		var replies string
		for _, f := range tc.frames {
			o := g.Process(ctx, tc.dir, []byte(f))
			forwarded += joined(o.Forward)
			replies += joined(o.Reply)
			done = append(done, o.Done...)
		}
		if forwarded != "" {
			t.Errorf("%s: %q crossed", tc.name, forwarded)
		}
		if len(done) != 1 || done[0].Outcome != tc.outcome || done[0].Released() {
			t.Errorf("%s: verdict %+v", tc.name, done)
		}
		if tc.dir == DirIn && tc.name != "infected paste" && !strings.Contains(replies, enc("ack", "4", "Blocked by content scan", "771")) {
			t.Errorf("%s: the browser must be told the upload was refused: %q", tc.name, replies)
		}
		if tc.name == "infected paste" && replies != "" {
			t.Errorf("a clipboard stream is not acked: %q", replies)
		}
	}
}

// TestSplitInstructionCannotBypass: an instruction cut across two messages
// is reassembled before it is judged, so a stream cannot be slipped past the
// gate by splitting its opening instruction.
func TestSplitInstructionCannotBypass(t *testing.T) {
	g := newTestGate(1 << 20)
	ctx := context.Background()
	open := enc("clipboard", "9", "text/plain")
	cut := len(open) / 2
	if o := g.Process(ctx, DirIn, []byte(open[:cut])); len(o.Forward) != 0 {
		t.Fatalf("half an instruction was forwarded: %q", joined(o.Forward))
	}
	g.Process(ctx, DirIn, []byte(open[cut:]+enc("blob", "9", b64("EICAR"))))
	o := g.Process(ctx, DirIn, []byte(enc("end", "9")))
	if joined(o.Forward) != "" || len(o.Done) != 1 || o.Done[0].Outcome != OutcomeInfected {
		t.Fatalf("split stream: forward %q done %+v", joined(o.Forward), o.Done)
	}
}

// TestUnheldStreamsPass: images, audio, directory listings, and clipboard
// when only files are held all pass untouched.
func TestUnheldStreamsPass(t *testing.T) {
	g := NewGate(GateConfig{Files: true, Scan: scanner})
	ctx := context.Background()
	for _, f := range []string{
		enc("img", "1", "14", "0", "image/png", "0", "0"), enc("blob", "1", b64("png")), enc("end", "1"),
		enc("body", "2", "6", streamIndexMime, "/"), enc("blob", "6", b64("{}")), enc("end", "6"),
		enc("clipboard", "4", "text/plain"), enc("blob", "4", b64("EICAR")), enc("end", "4"),
	} {
		if o := g.Process(ctx, DirOut, []byte(f)); joined(o.Forward) != f {
			t.Fatalf("%q was not passed through: %q", f, joined(o.Forward))
		}
	}
}

func TestVerdictDetailQuotes(t *testing.T) {
	v := Verdict{Direction: DirIn, Kind: KindFile, Name: "a b.txt outcome:clean", Mimetype: "text/plain", Outcome: OutcomeInfected, Reason: "Eicar"}
	d := v.Detail()
	if strings.Count(d, "outcome:") != 2 || !strings.Contains(d, "outcome:infected") || !strings.Contains(d, `"a b.txt outcome:clean"`) {
		t.Fatalf("detail = %s", d)
	}
}

func TestSplitInstructions(t *testing.T) {
	raw := enc("key", "65", "1") + enc("clipboard", "1", "text/plain; charset=ü")
	insts, tail, bad := splitInstructions([]byte(raw + "4.bl"))
	if bad || len(insts) != 2 || string(tail) != "4.bl" || insts[1].inst.Args[1] != "text/plain; charset=ü" {
		t.Fatalf("insts %+v tail %q bad %v", insts, tail, bad)
	}
	if _, _, bad := splitInstructions([]byte("x.key;")); !bad {
		t.Fatal("a non-numeric length is malformed")
	}
}

// TestGateFailsClosed (review of 274-280): a message the gate cannot frame —
// invalid UTF-8 inside an element, a zero-padded length, garbage — ends the
// session and forwards nothing, not even the instructions before it, because
// guacd may read those bytes differently and find a stream in them.
func TestGateFailsClosed(t *testing.T) {
	ctx := context.Background()
	file := enc("file", "1", "text/plain", "x") + enc("blob", "1", b64("EICAR")) + enc("end", "1")
	for name, msg := range map[string]string{
		"invalid utf-8": "4.nop\xc3A;" + file,
		"zero-padded":   "0003.nop;" + file,
		"garbage":       "hello;" + file,
	} {
		g := newTestGate(1 << 20)
		o := g.Process(ctx, DirIn, []byte(msg))
		if !o.Abort || len(o.Forward) != 0 || len(o.Done) != 0 {
			t.Errorf("%s: abort %v forward %q done %v", name, o.Abort, joined(o.Forward), o.Done)
		}
	}
}

// TestGateBoundsHeldTransfers (review of 274-280): past maxHeld concurrent
// held transfers a new one is refused outright and keeps nothing.
func TestGateBoundsHeldTransfers(t *testing.T) {
	ctx := context.Background()
	g := newTestGate(1 << 20)
	for i := 0; i < maxHeld; i++ {
		g.Process(ctx, DirIn, []byte(enc("file", itoa(i), "text/plain", "f")))
	}
	extra := itoa(maxHeld)
	g.Process(ctx, DirIn, []byte(enc("file", extra, "text/plain", "g")+enc("blob", extra, b64("clean"))))
	o := g.Process(ctx, DirIn, []byte(enc("end", extra)))
	if len(o.Forward) != 0 || len(o.Done) != 1 || o.Done[0].Outcome != OutcomeTooMany {
		t.Fatalf("a transfer past the bound: forward %q done %+v", joined(o.Forward), o.Done)
	}
}

// TestGuacdRefusalReachesTheBrowser (review of 274-280): after a released
// upload, an error ack from guacd (the drive is off, the write failed) is
// forwarded, not swallowed as one of the acks the gate already answered.
func TestGuacdRefusalReachesTheBrowser(t *testing.T) {
	ctx := context.Background()
	g := newTestGate(1 << 20)
	g.Process(ctx, DirIn, []byte(enc("file", "3", "text/plain", "a.txt")))
	g.Process(ctx, DirIn, []byte(enc("blob", "3", b64("hi"))))
	g.Process(ctx, DirIn, []byte(enc("end", "3")))
	refusal := enc("ack", "3", "File transfer unsupported", "256")
	if o := g.Process(ctx, DirOut, []byte(refusal)); joined(o.Forward) != refusal {
		t.Fatalf("guacd's refusal was swallowed: %q", joined(o.Forward))
	}
}

func itoa(i int) string { return string(rune('0' + i)) }
