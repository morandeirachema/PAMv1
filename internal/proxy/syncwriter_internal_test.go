package proxy

import (
	"bytes"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// splittingWriter models what makes concurrent writes to one SSH channel unsafe:
// the write is not atomic. It copies the payload out in two halves with a
// scheduling point between them, exactly as x/crypto/ssh's WriteExtended fills a
// pooled buffer and then flushes it — so two goroutines calling it without
// external serialization produce a spliced result.
//
// The earlier version of this test recorded each Write as one block under the
// destination's own lock, which made every block intact whether or not
// syncWriter serialized anything. That test passed with the mutex removed. This
// one does not.
type splittingWriter struct {
	mu  sync.Mutex // guards out only; deliberately NOT held across the two halves
	out []byte
}

// Write appends p in two halves with a yield in between, so an unsynchronized
// concurrent caller can interleave its own bytes into the gap.
func (b *splittingWriter) Write(p []byte) (int, error) {
	half := len(p) / 2
	b.mu.Lock()
	b.out = append(b.out, p[:half]...)
	b.mu.Unlock()

	runtime.Gosched() // the window a second writer slips through

	b.mu.Lock()
	b.out = append(b.out, p[half:]...)
	b.mu.Unlock()
	return len(p), nil
}

// bytes returns a copy of everything written so far.
func (b *splittingWriter) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.out...)
}

// TestSyncWriterKeepsPayloadsWhole proves concurrent writers cannot interleave.
//
// The operator's SSH channel has two writers: the session goroutine copying
// target output back, and the SFTP inspector answering a refusal with a status
// packet. Beyond the data race that x/crypto/ssh warns about — concurrent
// WriteExtended calls for one extended code share a pooled buffer — the
// practical damage is a status packet spliced into the middle of a split read
// response, which corrupts the client's SFTP stream.
//
// The property that matters is therefore not "no crash" but "every payload
// arrives whole", and the destination here is built so that an unserialized
// writer visibly violates it: removing the mutex from syncWriter must make this
// test fail, which was checked.
func TestSyncWriterKeepsPayloadsWhole(t *testing.T) {
	dst := &splittingWriter{}
	w := &syncWriter{w: dst}

	const rounds = 300
	output := []byte(strings.Repeat("O", 64))  // target output
	refusal := []byte(strings.Repeat("R", 64)) // an SFTP refusal packet

	var wg sync.WaitGroup
	wg.Add(2)
	for _, payload := range [][]byte{output, refusal} {
		go func(p []byte) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if _, err := w.Write(p); err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}(payload)
	}
	wg.Wait()

	// The result must be a sequence of whole 64-byte runs of one character each.
	// A splice shows up as a run that is not 64 long.
	got := dst.bytes()
	if len(got) != rounds*2*64 {
		t.Fatalf("wrote %d bytes, want %d", len(got), rounds*2*64)
	}
	for i := 0; i < len(got); i += 64 {
		run := got[i : i+64]
		for j := 1; j < len(run); j++ {
			if run[j] != run[0] {
				t.Fatalf("payload boundary at byte %d is spliced (%q): the two writers interleaved and the client's stream would be corrupt",
					i, string(run))
			}
		}
	}
}

// TestSFTPRefusalGoesToTheReplyWriter proves the inspector answers a refusal on
// the writer it was given, not by reaching for the channel directly.
//
// This is the structural half of the fix: the inspector runs on its own
// goroutine, so if it wrote to the channel itself no amount of locking elsewhere
// would serialize it. Taking an io.Writer is what lets the caller hand it a
// shared, synchronized view of the operator's channel.
func TestSFTPRefusalGoesToTheReplyWriter(t *testing.T) {
	var reply bytes.Buffer
	insp := newSFTPInspector(SFTPReadOnly, nil, func(action, detail string) {})
	insp.deny(&reply, 42)

	pkt := reply.Bytes()
	if len(pkt) < 9 {
		t.Fatalf("refusal packet is %d bytes, too short to be an SSH_FXP_STATUS", len(pkt))
	}
	if pkt[4] != fxpStatus {
		t.Fatalf("packet type = %d, want SSH_FXP_STATUS (%d)", pkt[4], fxpStatus)
	}
	// The request id must round-trip, or the client cannot match the refusal to
	// its request and hangs instead.
	if id := uint32(pkt[5])<<24 | uint32(pkt[6])<<16 | uint32(pkt[7])<<8 | uint32(pkt[8]); id != 42 {
		t.Fatalf("request id = %d, want 42", id)
	}
}

// TestAuditFieldCannotForgeFields proves untrusted text cannot invent audit
// fields or break the record onto a new line.
//
// Audit details are a space-separated `key:value` format read by humans and
// parsed by the SIEM forwarder. Interpolating client input raw lets the client
// author fields: an SFTP path of `x reason:allowed op:read` reads as three
// legitimate keys, and an embedded newline can make one event look like two.
// Every current consumer sanitizes on the way out, so this protects the raw
// column — which is the copy an investigator actually reads.
func TestAuditFieldCannotForgeFields(t *testing.T) {
	for _, hostile := range []string{
		`/tmp/x reason:allowed op:read`,
		"/tmp/x\nactor:admin action:approved",
		"/tmp/x\r\nfake:line",
		`/tmp/"quoted"`,
	} {
		got := auditField(hostile, 400)
		if strings.ContainsAny(got, "\n\r") {
			t.Fatalf("auditField(%q) = %s — a raw newline can split one audit event into two", hostile, got)
		}
		// Quoting is what contains the rest: the whole value is one token.
		if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
			t.Fatalf("auditField(%q) = %s, want a quoted single token", hostile, got)
		}
	}

	// Length is bounded, so a client cannot pad the trail with a huge value.
	long := strings.Repeat("A", 10_000)
	if got := auditField(long, 400); len(got) > 420 {
		t.Fatalf("auditField did not bound a %d-character value: got %d characters", len(long), len(got))
	}
}
