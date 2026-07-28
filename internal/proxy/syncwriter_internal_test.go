package proxy

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// blockWriter records each Write call separately, so a test can tell whether two
// concurrent writers' payloads were interleaved *within* a call — which is what
// corrupts an SFTP stream — rather than merely ordered differently.
type blockWriter struct {
	mu     sync.Mutex
	blocks []string
}

// Write appends the payload as one recorded block.
func (b *blockWriter) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blocks = append(b.blocks, string(p))
	return len(p), nil
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
// arrives whole", which is what this asserts.
func TestSyncWriterKeepsPayloadsWhole(t *testing.T) {
	dst := &blockWriter{}
	w := &syncWriter{w: dst}

	const rounds = 200
	outputPayload := []byte(strings.Repeat("O", 512))  // target output
	refusalPayload := []byte(strings.Repeat("R", 128)) // an SFTP refusal

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if _, err := w.Write(outputPayload); err != nil {
				t.Errorf("output write: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if _, err := w.Write(refusalPayload); err != nil {
				t.Errorf("refusal write: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	if len(dst.blocks) != rounds*2 {
		t.Fatalf("recorded %d blocks, want %d", len(dst.blocks), rounds*2)
	}
	// Every block must be one payload entire — never a mixture of the two.
	for i, b := range dst.blocks {
		switch {
		case b == string(outputPayload) || b == string(refusalPayload):
		default:
			t.Fatalf("block %d is neither payload intact (len %d, %q…): the two writers interleaved and the client stream would be corrupt",
				i, len(b), b[:min(24, len(b))])
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
