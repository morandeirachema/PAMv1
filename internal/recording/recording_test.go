package recording

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// fakeKEK wraps a data key the way the vault does — reversibly, binding the AAD —
// without pulling the real vault into this package's tests.
type fakeKEK struct{ fail bool }

// Encrypt returns a reversible token that carries the AAD, so a mismatched AAD is
// detectable on the way back.
func (f fakeKEK) Encrypt(_ context.Context, plaintext, aad string) (string, error) {
	if f.fail {
		return "", errors.New("kek unavailable")
	}
	return "fake:" + aad + ":" + plaintext, nil
}

// Decrypt reverses Encrypt and refuses a token whose AAD does not match.
func (f fakeKEK) Decrypt(_ context.Context, token, aad string) (string, error) {
	rest, ok := strings.CutPrefix(token, "fake:"+aad+":")
	if !ok {
		return "", errors.New("aad mismatch or corrupt token")
	}
	return rest, nil
}

// seal is a test helper: seals payload as name and returns the on-disk bytes.
func seal(t *testing.T, name string, payload ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	s, err := NewSealer(context.Background(), &buf, fakeKEK{}, name)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range payload {
		if n, err := s.Write([]byte(p)); err != nil || n != len(p) {
			t.Fatalf("write: n=%d err=%v", n, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestSealRoundTrip proves a sealed recording decrypts back to exactly what was
// written, and that the plaintext is genuinely absent from the file on disk.
func TestSealRoundTrip(t *testing.T) {
	const secretish = `{"version":2,"title":"root@web-01"}` + "\n"
	const frame = `[0.5,"o","hunter2\r\n"]` + "\n"
	sealed := seal(t, "sess.cast", secretish, frame)

	if !IsSealed(sealed[:HeaderLen]) {
		t.Fatal("sealed output is not detected as sealed")
	}
	if bytes.Contains(sealed, []byte("hunter2")) || bytes.Contains(sealed, []byte("root@web-01")) {
		t.Fatal("plaintext survived into the sealed file")
	}

	r, err := Open(context.Background(), bytes.NewReader(sealed), fakeKEK{}, "sess.cast")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != secretish+frame {
		t.Fatalf("round-trip = %q, want %q", got, secretish+frame)
	}
}

// TestPlaintextPassesThrough proves a recording written before encryption was
// enabled still replays: detection is by content, not by configuration.
func TestPlaintextPassesThrough(t *testing.T) {
	plain := []byte("{\"version\":2}\n[0.1,\"o\",\"hello\"]\n")
	r, err := Open(context.Background(), bytes.NewReader(plain), fakeKEK{}, "old.cast")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("passthrough = %q, want %q", got, plain)
	}
}

// TestTamperedChunkFailsAuthentication proves a single flipped byte in the
// ciphertext is caught rather than silently replayed as corrupt output.
func TestTamperedChunkFailsAuthentication(t *testing.T) {
	sealed := seal(t, "sess.cast", "first\n", "second\n")
	tampered := append([]byte{}, sealed...)
	tampered[len(tampered)-1] ^= 0x01 // flip a bit in the last chunk's tag

	r, err := Open(context.Background(), bytes.NewReader(tampered), fakeKEK{}, "sess.cast")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err == nil {
		t.Fatal("a tampered chunk must not decrypt cleanly")
	}
	if !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("error = %v, want an authentication failure", err)
	}
	// The untampered prefix is still recoverable — a damaged tail must not cost
	// the auditor the part of the session that is intact.
	if !bytes.Contains(got, []byte("first")) {
		t.Fatalf("prefix before the damage was lost: %q", got)
	}
}

// TestChunkCannotBeSplicedFromAnotherRecording proves the per-chunk AAD binds a
// chunk to its own recording and position, so a chunk lifted from elsewhere (or
// reordered) fails.
func TestChunkCannotBeSplicedFromAnotherRecording(t *testing.T) {
	a := seal(t, "a.cast", "aaaa\n")
	// The same bytes, presented as a different recording, must not decrypt.
	r, err := Open(context.Background(), bytes.NewReader(a), fakeKEK{}, "b.cast")
	if err == nil {
		if _, err = io.ReadAll(r); err == nil {
			t.Fatal("a recording opened under another name must not decrypt")
		}
	}
}

// TestTruncatedRecordingReadsUpToLastCompleteChunk proves a killed session — or
// one still being written — replays as a consistent prefix instead of failing whole.
func TestTruncatedRecordingReadsUpToLastCompleteChunk(t *testing.T) {
	sealed := seal(t, "sess.cast", "kept\n", "lost-tail\n")
	cut := sealed[:len(sealed)-8] // chop into the final chunk

	r, err := Open(context.Background(), bytes.NewReader(cut), fakeKEK{}, "sess.cast")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r) // an error is expected; the prefix is what matters
	if !bytes.Contains(got, []byte("kept")) {
		t.Fatalf("the complete prefix was not recovered: %q", got)
	}
}

// TestKEKFailureIsLoud proves a recording is never written unsealed when the KEK
// is unavailable — the caller gets an error and can fail the session closed.
func TestKEKFailureIsLoud(t *testing.T) {
	var buf bytes.Buffer
	if _, err := NewSealer(context.Background(), &buf, fakeKEK{fail: true}, "sess.cast"); err == nil {
		t.Fatal("expected an error when the KEK cannot wrap the data key")
	}
	if buf.Len() != 0 {
		t.Fatalf("bytes were written despite the failure: %q", buf.Bytes())
	}
}
