package winrm

// A WinRM run's output is attacker-influenced — `type C:\big.iso`, Get-Content on
// a large log — and was collected into unbounded bytes.Buffers, then copied
// several times more into the transcript, the hash and the JSON response. A
// connect-capable operator or a broker agent could take the process to an OOM,
// and every live session with it.

import (
	"strings"
	"testing"
)

// TestLimitedBufferCapsAndMarks proves output is capped, that the writer still
// reports a full write (so the WinRM library does not see a short write as an IO
// error), and that a truncated transcript SAYS it was truncated — evidence that
// looks complete but is not would be worse than none.
func TestLimitedBufferCapsAndMarks(t *testing.T) {
	b := &limitedBuffer{max: 1024}
	chunk := strings.Repeat("A", 512)
	for i := 0; i < 100; i++ {
		n, err := b.Write([]byte(chunk))
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if n != len(chunk) {
			t.Fatalf("write %d reported %d of %d bytes; a short write reads as an IO error upstream", i, n, len(chunk))
		}
	}
	out := b.String()
	if len(out) > 1024+64 { // the cap plus the marker
		t.Fatalf("buffer grew to %d bytes despite a 1024-byte cap", len(out))
	}
	if !strings.Contains(out, "truncated") {
		t.Fatal("a truncated transcript does not say so")
	}
	// Count fill bytes in the PAYLOAD only, before the truncation marker — the
	// marker text ("[PAMv1: output truncated…]") itself contains an 'A', so a
	// naive Count over the whole string is off by one.
	payload := out
	if i := strings.Index(out, "\r\n["); i >= 0 {
		payload = out[:i]
	}
	if strings.Count(payload, "A") != 1024 {
		t.Fatalf("kept %d payload bytes, want exactly the 1024-byte cap", strings.Count(payload, "A"))
	}
}

// TestLimitedBufferUnderCapIsExact proves ordinary output is untouched.
func TestLimitedBufferUnderCapIsExact(t *testing.T) {
	b := &limitedBuffer{max: MaxOutputBytes}
	const want = "contoso\\svc\r\n"
	if _, err := b.Write([]byte(want)); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}
