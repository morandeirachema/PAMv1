package icap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
)

// fakeICAPServer starts a minimal ICAP responder: it reads one RESPMOD
// request (headers, the encapsulated synthetic HTTP response, and the
// chunked body our own Client always sends) and replies with the given
// status/headers — a real socket-level round trip against Client's actual
// wire encoding, not a mock of its methods.
func fakeICAPServer(t *testing.T, status int, headers map[string]string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeICAP(conn, status, headers)
		}
	}()
	return ln.Addr().String()
}

func serveFakeICAP(conn net.Conn, status int, headers map[string]string) {
	defer conn.Close()
	r := textproto.NewReader(bufio.NewReader(conn))
	if _, err := r.ReadLine(); err != nil { // RESPMOD request line
		return
	}
	if _, err := r.ReadMIMEHeader(); err != nil { // ICAP headers
		return
	}
	if _, err := r.ReadLine(); err != nil { // encapsulated "HTTP/1.1 200 OK"
		return
	}
	if _, err := r.ReadLine(); err != nil { // blank line ending it
		return
	}
	for { // chunked body, terminated by a zero-length chunk
		sizeLine, err := r.ReadLine()
		if err != nil {
			return
		}
		n, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 64)
		if err != nil {
			return
		}
		if n == 0 {
			r.ReadLine() // the final blank line after "0"
			break
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r.R, buf); err != nil {
			return
		}
		r.ReadLine() // trailing CRLF after this chunk's data
	}
	fmt.Fprintf(conn, "ICAP/1.0 %d status\r\n", status)
	for k, v := range headers {
		fmt.Fprintf(conn, "%s: %s\r\n", k, v)
	}
	fmt.Fprint(conn, "\r\n")
}

func TestNewClient(t *testing.T) {
	if c, err := NewClient(""); c != nil || err != nil {
		t.Fatalf("empty URL must disable: got %v, %v", c, err)
	}
	if c, err := NewClient(""); c.Enabled() {
		t.Fatalf("a nil client must report disabled: %v", c)
	} else if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient("http://host/respmod"); err == nil {
		t.Fatal("a non-icap:// scheme must be rejected")
	}
	if _, err := NewClient("icap://host"); err == nil {
		t.Fatal("a URL with no service path must be rejected")
	}
	if _, err := NewClient("not a url at all://%%%"); err == nil {
		t.Fatal("an unparsable URL must be rejected")
	}
	c, err := NewClient("icap://scanner.example/respmod")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Enabled() {
		t.Fatal("a configured client must report enabled")
	}
	if c.addr != "scanner.example:1344" {
		t.Fatalf("default port not applied: addr = %q", c.addr)
	}
	c2, err := NewClient("icap://scanner.example:9999/avscan")
	if err != nil {
		t.Fatal(err)
	}
	if c2.addr != "scanner.example:9999" {
		t.Fatalf("explicit port not honored: addr = %q", c2.addr)
	}
}

func TestScanRespmodClean(t *testing.T) {
	addr := fakeICAPServer(t, 204, nil)
	c, err := NewClient("icap://" + addr + "/respmod")
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.ScanRespmod(context.Background(), []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Clean {
		t.Fatalf("204 must report clean: %+v", res)
	}
}

func TestScanRespmodFlaggedWithVendorHeader(t *testing.T) {
	addr := fakeICAPServer(t, 200, map[string]string{"X-Infection-Found": "Type=0; Resolution=2; Threat=Eicar-Test-Signature;"})
	c, err := NewClient("icap://" + addr + "/respmod")
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.ScanRespmod(context.Background(), []byte("fake eicar content"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Clean {
		t.Fatal("200 must report flagged, not clean")
	}
	if !strings.Contains(res.Reason, "Eicar-Test-Signature") {
		t.Fatalf("reason should surface the vendor header: %q", res.Reason)
	}
}

func TestScanRespmodFlaggedNoVendorHeader(t *testing.T) {
	addr := fakeICAPServer(t, 200, nil)
	c, err := NewClient("icap://" + addr + "/respmod")
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.ScanRespmod(context.Background(), []byte("something"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Clean || res.Reason == "" {
		t.Fatalf("200 with no vendor header must still flag, with a generic reason: %+v", res)
	}
}

func TestScanRespmodUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // now a dead endpoint — connection refused
	c, err := NewClient("icap://" + addr + "/respmod")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ScanRespmod(context.Background(), []byte("x")); err == nil {
		t.Fatal("an unreachable ICAP server must error, not report clean (fail closed)")
	}
}

func TestScanRespmodUnexpectedStatus(t *testing.T) {
	addr := fakeICAPServer(t, 500, nil)
	c, err := NewClient("icap://" + addr + "/respmod")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ScanRespmod(context.Background(), []byte("x")); err == nil {
		t.Fatal("a 500 ICAP status must be reported as an error, not silently treated as clean or flagged")
	}
}
