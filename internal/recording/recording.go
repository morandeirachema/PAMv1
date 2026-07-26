// Package recording encrypts session recordings at rest.
//
// The vault protects credentials; a recording is the other high-value artifact —
// it holds everything an operator typed and saw, which can include a secret typed
// by hand, a query result, or a file listed on screen. Before this it was
// protected by file permissions alone, so anyone with volume, backup or snapshot
// access could read it. This seals it with the same root of trust as the vault.
//
// # Format
//
// A sealed recording is a header line followed by a sequence of AEAD chunks:
//
//	#pamrec1 <vault-wrapped data key>\n
//	[4-byte big-endian length][12-byte nonce][AES-256-GCM ciphertext+tag]
//	…
//
// The data key is random per recording and wrapped by the configured KEK (local,
// Vault Transit, AWS KMS or a PKCS#11 HSM), so the recording inherits whatever
// root of trust the deployment already uses for secrets.
//
// It is a *stream* of chunks rather than one sealed blob because a session can be
// killed, hit its size cap, or die with the process: a partial file must still
// decrypt up to the point it stops. Each chunk's additional authenticated data
// binds it to the recording's name and its index, so chunks cannot be reordered,
// dropped from the middle, or spliced in from another recording without the
// decryption failing.
//
// Detection is by the magic prefix, not by configuration: a deployment that turns
// encryption on keeps replaying the plaintext recordings it already had.
package recording

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// magic marks a sealed recording. It is ASCII and starts with '#' so a stray
// plaintext reader shows something intelligible rather than binary noise.
const magic = "#pamrec1 "

// maxChunk bounds both the writer's chunking and the reader's allocation, so a
// corrupt or hostile length prefix cannot make the reader allocate wildly.
const maxChunk = 1 << 20 // 1 MiB

// KeyWrapper wraps and unwraps a recording's data key using the deployment's KEK.
// *vault.Vault satisfies it; the recording package deliberately depends on this
// two-method view rather than the whole vault.
type KeyWrapper interface {
	Encrypt(ctx context.Context, plaintext, aad string) (string, error)
	Decrypt(ctx context.Context, token, aad string) (string, error)
}

// keyAAD binds a wrapped data key to the recording it belongs to, so a key
// envelope lifted from one recording cannot be pasted onto another.
func keyAAD(name string) string { return "recording:" + name }

// chunkAAD binds a chunk to its recording and position in the stream.
func chunkAAD(name string, index int) []byte {
	return []byte(name + "|" + strconv.Itoa(index))
}

// Sealer encrypts everything written to it into the chunk stream described in
// the package documentation. It is an io.WriteCloser; each Write becomes one
// chunk (writes larger than maxChunk are split).
type Sealer struct {
	w     io.Writer
	aead  cipher.AEAD
	name  string
	index int
}

// NewSealer generates a fresh data key, wraps it with kw, writes the header to w,
// and returns a Sealer that encrypts subsequent writes. name identifies the
// recording (its file name) and is authenticated into every chunk.
func NewSealer(ctx context.Context, w io.Writer, kw KeyWrapper, name string) (*Sealer, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("recording: data key: %w", err)
	}
	token, err := kw.Encrypt(ctx, base64.StdEncoding.EncodeToString(key), keyAAD(name))
	if err != nil {
		return nil, fmt.Errorf("recording: wrap data key: %w", err)
	}
	if strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("recording: wrapped key contains a newline")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w, magic+token+"\n"); err != nil {
		return nil, err
	}
	return &Sealer{w: w, aead: aead, name: name}, nil
}

// Write seals p into one or more chunks. It reports len(p) written on success,
// matching io.Writer semantics for callers that check short writes.
func (s *Sealer) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxChunk {
			n = maxChunk
		}
		if err := s.seal(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// seal encrypts one chunk and frames it onto the underlying writer.
func (s *Sealer) seal(p []byte) error {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := s.aead.Seal(nil, nonce, p, chunkAAD(s.name, s.index))
	s.index++
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(nonce)+len(ct)))
	if _, err := s.w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := s.w.Write(nonce); err != nil {
		return err
	}
	_, err := s.w.Write(ct)
	return err
}

// Close releases the Sealer. The underlying writer is the caller's to close —
// a Sealer holds no buffered plaintext, since every Write is sealed immediately.
func (s *Sealer) Close() error { return nil }

// IsSealed reports whether the bytes look like a sealed recording. Callers use it
// to keep replaying the plaintext recordings written before encryption was turned
// on: format detection is by content, never by current configuration.
func IsSealed(head []byte) bool {
	return len(head) >= len(magic) && string(head[:len(magic)]) == magic
}

// HeaderLen is how many bytes a caller needs to read to decide with IsSealed.
const HeaderLen = len(magic)

// Open returns a reader over the plaintext of r. If r is not a sealed recording
// its bytes are returned unchanged, so a caller can serve both formats through
// one path. name must match the name the recording was sealed under.
//
// Decryption is lazy: chunks are decrypted as the caller reads, so replaying a
// large recording does not hold the whole session in memory. A truncated file
// (a session that was killed, or one still being written) decrypts up to its last
// complete chunk and then reports io.ErrUnexpectedEOF, so a partial recording is
// still readable rather than lost.
func Open(ctx context.Context, r io.Reader, kw KeyWrapper, name string) (io.Reader, error) {
	br := &peekReader{r: r}
	head, err := br.peek(len(magic))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if !IsSealed(head) {
		return br, nil // plaintext recording, pass through untouched
	}
	if _, err := br.discard(len(magic)); err != nil {
		return nil, err
	}
	token, err := br.readLine()
	if err != nil {
		return nil, fmt.Errorf("recording: header: %w", err)
	}
	keyB64, err := kw.Decrypt(ctx, token, keyAAD(name))
	if err != nil {
		return nil, fmt.Errorf("recording: unwrap data key: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("recording: data key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &opener{r: br, aead: aead, name: name}, nil
}

// opener decrypts the chunk stream on demand.
type opener struct {
	r     io.Reader
	aead  cipher.AEAD
	name  string
	index int
	buf   []byte // decrypted bytes not yet handed to the caller
	done  bool
	err   error
}

// Read returns decrypted bytes, decrypting one more chunk whenever the buffer runs dry.
func (o *opener) Read(p []byte) (int, error) {
	for len(o.buf) == 0 {
		if o.err != nil {
			return 0, o.err
		}
		if o.done {
			return 0, io.EOF
		}
		if err := o.next(); err != nil {
			o.err = err
			if len(o.buf) == 0 {
				return 0, err
			}
		}
	}
	n := copy(p, o.buf)
	o.buf = o.buf[n:]
	return n, nil
}

// next decrypts the following chunk into the buffer.
func (o *opener) next() error {
	var hdr [4]byte
	if _, err := io.ReadFull(o.r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) {
			o.done = true
			return io.EOF
		}
		return io.ErrUnexpectedEOF
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < uint32(o.aead.NonceSize()+o.aead.Overhead()) || n > maxChunk+uint32(o.aead.NonceSize()+o.aead.Overhead()) {
		return fmt.Errorf("recording: chunk %d has an implausible length %d", o.index, n)
	}
	frame := make([]byte, n)
	if _, err := io.ReadFull(o.r, frame); err != nil {
		return io.ErrUnexpectedEOF
	}
	ns := o.aead.NonceSize()
	pt, err := o.aead.Open(nil, frame[:ns], frame[ns:], chunkAAD(o.name, o.index))
	if err != nil {
		return fmt.Errorf("recording: chunk %d failed authentication (tampered, reordered or from another recording)", o.index)
	}
	o.index++
	o.buf = append(o.buf, pt...)
	return nil
}

// peekReader adds the small amount of lookahead Open needs without pulling in a
// buffered reader whose buffer would swallow bytes the pass-through path needs.
type peekReader struct {
	r    io.Reader
	head []byte
	off  int
}

// peek reads up to n bytes into the lookahead buffer and returns them.
func (p *peekReader) peek(n int) ([]byte, error) {
	for len(p.head)-p.off < n {
		b := make([]byte, n-(len(p.head)-p.off))
		m, err := p.r.Read(b)
		p.head = append(p.head, b[:m]...)
		if err != nil {
			return p.head[p.off:], err
		}
	}
	return p.head[p.off : p.off+n], nil
}

// discard drops n buffered bytes.
func (p *peekReader) discard(n int) (int, error) {
	if len(p.head)-p.off < n {
		return 0, io.ErrUnexpectedEOF
	}
	p.off += n
	return n, nil
}

// readLine reads through the next '\n', returning the line without it.
func (p *peekReader) readLine() (string, error) {
	var b []byte
	one := make([]byte, 1)
	for {
		n, err := p.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				return string(b), nil
			}
			b = append(b, one[0])
			if len(b) > 4096 {
				return "", errors.New("recording: header line too long")
			}
			continue
		}
		if err != nil {
			return "", err
		}
	}
}

// Read serves buffered lookahead first, then the underlying reader.
func (p *peekReader) Read(b []byte) (int, error) {
	if p.off < len(p.head) {
		n := copy(b, p.head[p.off:])
		p.off += n
		return n, nil
	}
	return p.r.Read(b)
}
