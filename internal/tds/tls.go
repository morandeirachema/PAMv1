package tds

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// TDS carries the TLS handshake INSIDE TDS packets: every handshake record
// travels as the payload of a PRELOGIN-typed (0x12) packet, and only once the
// handshake completes do TLS records go on the wire directly (TDS packets then
// become the TLS payload rather than its envelope). Go's crypto/tls does all
// the cryptography; the shim below only supplies the framing during those few
// round trips.
//
// The subtle parts, which is where hand-rolled implementations break:
//
//   - Writes are BUFFERED into an in-progress packet instead of being flushed
//     per call, because Go's TLS stack writes one flight in several Write calls.
//   - The buffered packet is finished (EOM set, bytes flushed) on the next
//     READ, since TLS writes a flight and then waits for the peer. This
//     flush-on-read handoff is the crux: without it the peer waits forever for
//     a packet whose end-of-message never arrives.
//   - A server flight may span several packets, so a read continues within the
//     current packet's payload before pulling another header.
//
// handshakePacketSize bounds each packet the handshake shim writes. 4096 is the
// TDS default and the smallest buffer a client is likely to have during the
// handshake, when nothing has been negotiated yet.
const handshakePacketSize = 4096

type handshakeConn struct {
	conn net.Conn

	mu    sync.Mutex
	out   []byte // buffered handshake bytes not yet framed
	in    []byte // remaining payload of the packet being consumed
	done  bool   // handshake finished: stop framing, pass bytes through
	outID byte
}

// newHandshakeConn wraps conn so the TLS handshake is framed in TDS packets.
func newHandshakeConn(conn net.Conn) *handshakeConn {
	return &handshakeConn{conn: conn}
}

// Write buffers handshake bytes (they are framed and flushed on the next Read),
// or writes straight through once the handshake is done.
func (h *handshakeConn) Write(b []byte) (int, error) {
	h.mu.Lock()
	if h.done {
		h.mu.Unlock()
		return h.conn.Write(b)
	}
	h.out = append(h.out, b...)
	h.mu.Unlock()
	return len(b), nil
}

// flush frames whatever is buffered as PRELOGIN-typed packets, EOM on the last.
//
// The flight MUST be split at the packet size, not written as one giant packet:
// a TDS client sizes its read buffer from the negotiated packet size (4096 by
// default) and rejects any packet larger than it — during the handshake, before
// anything has been negotiated. A server flight with an ordinary RSA
// certificate chain exceeds 4096, so an unsplit write is refused by real
// clients while still passing a test whose peer is this same shim.
func (h *handshakeConn) flush() error {
	if len(h.out) == 0 {
		return nil
	}
	body := h.out
	h.out = nil
	const chunk = handshakePacketSize - HeaderSize
	for first := true; first || len(body) > 0; first = false {
		n := len(body)
		if n > chunk {
			n = chunk
		}
		part := body[:n]
		body = body[n:]
		var hb [HeaderSize]byte
		hb[0] = PacketPreLogin
		if len(body) == 0 {
			hb[1] = StatusEOM
		}
		binary.BigEndian.PutUint16(hb[2:4], uint16(HeaderSize+n))
		hb[6] = h.outID
		h.outID++
		if _, err := h.conn.Write(append(hb[:], part...)); err != nil {
			return err
		}
	}
	return nil
}

// Read returns handshake bytes, unwrapping them from TDS packets: it first
// flushes any buffered outbound flight, then serves from the packet currently
// being consumed, pulling another packet when that is exhausted.
func (h *handshakeConn) Read(b []byte) (int, error) {
	h.mu.Lock()
	if h.done {
		// Serve anything left from the handshake's last packet before going to
		// the raw connection, or a record split across that boundary is lost.
		if len(h.in) > 0 {
			n := copy(b, h.in)
			h.in = h.in[n:]
			h.mu.Unlock()
			return n, nil
		}
		h.mu.Unlock()
		return h.conn.Read(b)
	}
	if err := h.flush(); err != nil {
		h.mu.Unlock()
		return 0, err
	}
	for len(h.in) == 0 {
		var hb [HeaderSize]byte
		if _, err := io.ReadFull(h.conn, hb[:]); err != nil {
			h.mu.Unlock()
			return 0, err
		}
		if hb[0] != PacketPreLogin {
			h.mu.Unlock()
			return 0, errors.New("tds: expected a prelogin-framed TLS record")
		}
		length := int(binary.BigEndian.Uint16(hb[2:4]))
		if length < HeaderSize {
			h.mu.Unlock()
			return 0, errors.New("tds: bad packet length during the TLS handshake")
		}
		payload := make([]byte, length-HeaderSize)
		if _, err := io.ReadFull(h.conn, payload); err != nil {
			h.mu.Unlock()
			return 0, err
		}
		h.in = payload
	}
	n := copy(b, h.in)
	h.in = h.in[n:]
	h.mu.Unlock()
	return n, nil
}

// finish ends the framing phase: the last flight is flushed and subsequent
// traffic passes through untouched. Anything still buffered in the current
// packet is KEPT and served first — with TLS 1.3 the server's session tickets
// arrive in the same packet as Finished, and a peer's packet boundary can also
// split a post-handshake record, so discarding the remainder would make the
// next raw read start in the middle of a TLS record.
func (h *handshakeConn) finish() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.flush(); err != nil {
		return err
	}
	h.done = true
	return nil
}

// Close closes the underlying connection.
func (h *handshakeConn) Close() error { return h.conn.Close() }

// LocalAddr reports the local network address.
func (h *handshakeConn) LocalAddr() net.Addr { return h.conn.LocalAddr() }

// RemoteAddr reports the remote network address.
func (h *handshakeConn) RemoteAddr() net.Addr { return h.conn.RemoteAddr() }

// SetDeadline sets the read and write deadlines.
func (h *handshakeConn) SetDeadline(t time.Time) error { return h.conn.SetDeadline(t) }

// SetReadDeadline sets the read deadline.
func (h *handshakeConn) SetReadDeadline(t time.Time) error { return h.conn.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline.
func (h *handshakeConn) SetWriteDeadline(t time.Time) error { return h.conn.SetWriteDeadline(t) }

// ServerHandshake completes a TLS handshake as the SERVER on conn, framing the
// handshake in TDS packets. It returns the encrypted connection, on which the
// rest of the TDS conversation (LOGIN7 onwards) then runs.
func ServerHandshake(conn net.Conn, cfg *tls.Config) (net.Conn, error) {
	h := newHandshakeConn(conn)
	tconn := tls.Server(h, cfg)
	if err := tconn.Handshake(); err != nil {
		return nil, err
	}
	if err := h.finish(); err != nil {
		return nil, err
	}
	return tconn, nil
}

// ClientHandshake completes a TLS handshake as the CLIENT on conn, framing the
// handshake in TDS packets — the upstream leg, where the vaulted credential is
// about to travel.
func ClientHandshake(conn net.Conn, cfg *tls.Config) (net.Conn, error) {
	h := newHandshakeConn(conn)
	tconn := tls.Client(h, cfg)
	if err := tconn.Handshake(); err != nil {
		return nil, err
	}
	if err := h.finish(); err != nil {
		return nil, err
	}
	return tconn, nil
}
