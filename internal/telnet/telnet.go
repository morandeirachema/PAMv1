// Package telnet is the client half of the TELNET protocol (RFC 854/855)
// that PAMv1 needs to broker a telnet target (Phase 279): an NVT byte
// stream with option negotiation stripped out of what the caller reads,
// and IAC/CR escaping applied to what it writes.
//
// Negotiation is deliberately small. The client agrees to the server
// echoing and suppressing go-ahead (character mode, what every interactive
// device expects), offers a terminal type and its window size when asked,
// and refuses every other option. Telnet carries everything — the
// credential PAMv1 injects included — in the clear; that is why the proxy
// only brokers it when PAM_TELNET_ENABLED says the operator accepts it.
package telnet

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"sync"
)

// Protocol bytes (RFC 854) and the options this client understands.
const (
	iac  = 255
	dont = 254
	do   = 253
	wont = 252
	will = 251
	sb   = 250
	se   = 240

	optEcho  = 1
	optSGA   = 3
	optTType = 24
	optNAWS  = 31

	ttypeIs   = 0
	ttypeSend = 1
)

// Conn is a telnet client connection. Read returns only data; Write sends
// data. Both are safe to call from different goroutines (one reader, any
// number of writers).
type Conn struct {
	c  net.Conn
	br *bufio.Reader

	wmu        sync.Mutex // serialises every write to c: data and replies
	smu        sync.Mutex
	nawsOn     bool
	cols, rows uint16
	termType   string
	// answered remembers the reply already sent per (verb, option), so a
	// server that repeats itself does not start a negotiation loop.
	answered map[[2]byte]bool
}

// New wraps an established connection. termType is offered when the server
// asks (e.g. "xterm"); cols/rows are the initial window size.
func New(c net.Conn, termType string, cols, rows uint16) *Conn {
	if termType == "" {
		termType = "xterm"
	}
	return &Conn{c: c, br: bufio.NewReader(c), termType: termType, cols: cols, rows: rows, answered: map[[2]byte]bool{}}
}

// Close closes the underlying connection.
func (t *Conn) Close() error { return t.c.Close() }

func (t *Conn) raw(b []byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	_, err := t.c.Write(b)
	return err
}

// reply sends IAC verb opt once per (verb, opt).
func (t *Conn) reply(verb, opt byte) error {
	t.smu.Lock()
	k := [2]byte{verb, opt}
	if t.answered[k] {
		t.smu.Unlock()
		return nil
	}
	t.answered[k] = true
	t.smu.Unlock()
	return t.raw([]byte{iac, verb, opt})
}

// Read returns the next data bytes, handling any negotiation that precedes
// them. It blocks until at least one data byte or an error.
func (t *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := 0
	for n == 0 || (n < len(p) && t.br.Buffered() > 0) {
		b, err := t.br.ReadByte()
		if err != nil {
			if n > 0 {
				return n, nil
			}
			return 0, err
		}
		if b != iac {
			p[n] = b
			n++
			continue
		}
		cmd, err := t.br.ReadByte()
		if err != nil {
			return n, err
		}
		switch cmd {
		case iac: // an escaped 0xFF is data
			p[n] = iac
			n++
		case will, wont, do, dont:
			opt, err := t.br.ReadByte()
			if err != nil {
				return n, err
			}
			if err := t.negotiate(cmd, opt); err != nil {
				return n, err
			}
		case sb:
			if err := t.subnegotiation(); err != nil {
				return n, err
			}
		default:
			// NOP, GA, DM, BRK, IP, AO, AYT, EC, EL: nothing for a client to do.
		}
	}
	return n, nil
}

func (t *Conn) negotiate(cmd, opt byte) error {
	switch cmd {
	case will:
		if opt == optEcho || opt == optSGA {
			return t.reply(do, opt)
		}
		return t.reply(dont, opt)
	case do:
		switch opt {
		case optTType:
			return t.reply(will, opt)
		case optNAWS:
			if err := t.reply(will, opt); err != nil {
				return err
			}
			t.smu.Lock()
			t.nawsOn = true
			t.smu.Unlock()
			return t.sendNAWS()
		case optSGA:
			return t.reply(will, opt)
		}
		return t.reply(wont, opt)
	}
	// WONT/DONT: the server declines or retracts; nothing to answer.
	return nil
}

// subnegotiation reads up to IAC SE and answers TTYPE SEND.
func (t *Conn) subnegotiation() error {
	var buf []byte
	for {
		b, err := t.br.ReadByte()
		if err != nil {
			return err
		}
		if b == iac {
			nb, err := t.br.ReadByte()
			if err != nil {
				return err
			}
			if nb == se {
				break
			}
			if nb == iac {
				buf = append(buf, iac)
			}
			continue
		}
		if len(buf) < 64 {
			buf = append(buf, b)
		}
	}
	if len(buf) >= 2 && buf[0] == optTType && buf[1] == ttypeSend {
		msg := []byte{iac, sb, optTType, ttypeIs}
		msg = append(msg, t.termType...)
		msg = append(msg, iac, se)
		return t.raw(msg)
	}
	return nil
}

// SetWindowSize records the operator's window and, once the server asked
// for NAWS, tells it.
func (t *Conn) SetWindowSize(cols, rows uint16) error {
	t.smu.Lock()
	t.cols, t.rows = cols, rows
	on := t.nawsOn
	t.smu.Unlock()
	if !on {
		return nil
	}
	return t.sendNAWS()
}

func (t *Conn) sendNAWS() error {
	t.smu.Lock()
	var sz [4]byte
	binary.BigEndian.PutUint16(sz[0:], t.cols)
	binary.BigEndian.PutUint16(sz[2:], t.rows)
	t.smu.Unlock()
	msg := []byte{iac, sb, optNAWS}
	for _, b := range sz {
		msg = append(msg, b)
		if b == iac {
			msg = append(msg, iac)
		}
	}
	return t.raw(append(msg, iac, se))
}

// Write sends data: 0xFF doubled, and a carriage return not followed by a
// line feed sent as CR NUL (RFC 854's NVT rule — an operator's Enter key
// arrives as a bare CR).
func (t *Conn) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(p)+8)
	for i, b := range p {
		switch {
		case b == iac:
			out = append(out, iac, iac)
		case b == '\r' && (i+1 >= len(p) || p[i+1] != '\n'):
			out = append(out, '\r', 0)
		default:
			out = append(out, b)
		}
	}
	if err := t.raw(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

var _ io.ReadWriteCloser = (*Conn)(nil)
