package telnet

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// pair returns a client Conn and the raw server side of a pipe.
func pair(t *testing.T) (*Conn, net.Conn) {
	t.Helper()
	cs, ss := net.Pipe()
	t.Cleanup(func() { cs.Close(); ss.Close() })
	return New(cs, "xterm", 80, 24), ss
}

// readN reads exactly n bytes from the server side, failing on a stall.
func readN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("server read %d bytes: %v (got %v)", n, err, b)
	}
	return b
}

func TestNegotiationAndData(t *testing.T) {
	cl, srv := pair(t)
	go func() {
		// WILL ECHO, WILL SGA, WILL LINEMODE(34), DO TTYPE, DO NAWS, DO
		// ENVIRON(39), then data with an escaped 0xFF, then TTYPE SEND.
		_, _ = srv.Write([]byte{iac, will, optEcho, iac, will, optSGA, iac, will, 34, iac, do, optTType, iac, do, optNAWS, iac, do, 39,
			'l', 'o', 'g', iac, iac, 'i', 'n', ':',
			iac, sb, optTType, ttypeSend, iac, se})
	}()
	got := make(chan []byte, 1)
	go func() {
		var all []byte
		buf := make([]byte, 64)
		for len(all) < 6 {
			n, err := cl.Read(buf)
			if err != nil {
				break
			}
			all = append(all, buf[:n]...)
		}
		got <- all
	}()
	want := [][]byte{
		{iac, do, optEcho}, {iac, do, optSGA}, {iac, dont, 34}, {iac, will, optTType},
		{iac, will, optNAWS}, {iac, sb, optNAWS, 0, 80, 0, 24, iac, se}, {iac, wont, 39},
	}
	for _, w := range want {
		if b := readN(t, srv, len(w)); !bytes.Equal(b, w) {
			t.Fatalf("reply = %v, want %v", b, w)
		}
	}
	// The TTYPE SEND arrived in the same read as the data, so the client
	// answers it before that read returns.
	ttype := append([]byte{iac, sb, optTType, ttypeIs}, "xterm"...)
	ttype = append(ttype, iac, se)
	if b := readN(t, srv, len(ttype)); !bytes.Equal(b, ttype) {
		t.Fatalf("TTYPE IS = %v", b)
	}
	if d := <-got; string(d) != "log\xffin:" {
		t.Fatalf("data = %q", d)
	}
}

func TestNoNegotiationLoop(t *testing.T) {
	cl, srv := pair(t)
	go func() {
		_, _ = srv.Write([]byte{iac, will, optEcho, iac, will, optEcho, iac, will, optEcho, 'x'})
	}()
	go func() { b := make([]byte, 8); _, _ = cl.Read(b) }()
	if b := readN(t, srv, 3); !bytes.Equal(b, []byte{iac, do, optEcho}) {
		t.Fatalf("reply = %v", b)
	}
	_ = srv.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _ := srv.Read(make([]byte, 3)); n != 0 {
		t.Fatal("a repeated WILL ECHO was answered again")
	}
}

func TestWriteEscapes(t *testing.T) {
	cl, srv := pair(t)
	go func() { _, _ = cl.Write([]byte("a\xffb\rc\r\n")) }()
	want := []byte{'a', iac, iac, 'b', '\r', 0, 'c', '\r', '\n'}
	if b := readN(t, srv, len(want)); !bytes.Equal(b, want) {
		t.Fatalf("wire = %v, want %v", b, want)
	}
}

func TestWindowSizeAfterNAWS(t *testing.T) {
	cl, srv := pair(t)
	if err := cl.SetWindowSize(100, 40); err != nil { // before DO NAWS: nothing sent
		t.Fatal(err)
	}
	go func() { _, _ = srv.Write([]byte{iac, do, optNAWS, 'x'}) }()
	go func() { b := make([]byte, 8); _, _ = cl.Read(b) }()
	want := []byte{iac, will, optNAWS, iac, sb, optNAWS, 0, 100, 0, 40, iac, se}
	if b := readN(t, srv, len(want)); !bytes.Equal(b, want) {
		t.Fatalf("NAWS = %v", b)
	}
	go func() { _ = cl.SetWindowSize(255, 50) }()
	want = []byte{iac, sb, optNAWS, 0, iac, iac, 0, 50, iac, se}
	if b := readN(t, srv, len(want)); !bytes.Equal(b, want) {
		t.Fatalf("NAWS with 255 = %v", b)
	}
}

// TestSubnegotiationIsBounded (review of 274-280): escaped 0xFF bytes inside
// a subnegotiation no longer grow the buffer without limit; the data after
// it still arrives.
func TestSubnegotiationIsBounded(t *testing.T) {
	cl, srv := pair(t)
	go func() {
		msg := []byte{iac, sb, optTType}
		for i := 0; i < 100000; i++ {
			msg = append(msg, iac, iac)
		}
		msg = append(msg, iac, se, 'o', 'k')
		_, _ = srv.Write(msg)
	}()
	buf := make([]byte, 8)
	n, err := cl.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("read %q %v", buf[:n], err)
	}
}
