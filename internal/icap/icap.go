// Package icap implements a minimal RFC 3507 ICAP 1.0 client, scoped to
// exactly what whole-object file scanning needs: submit a complete
// in-memory buffer as a RESPMOD request and report whether the server
// signaled clean or flagged.
//
// Deliberately not attempted: OPTIONS negotiation, Preview, and persistent
// (keep-alive) connections. RFC 3507 §4.6 makes OPTIONS a SHOULD, not a
// MUST — a bare RESPMOD carrying "Allow: 204" and a byte-exact
// "Encapsulated:" header is wire-valid against a real ICAP server (c-icap,
// and the major commercial AV/DLP gateways) without it. One TCP connection
// per scan, closed afterward with "Connection: close" — simpler than
// connection reuse, and a file scan is not latency-sensitive the way the
// per-packet SFTP relay it feeds is.
package icap

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// scanTimeout bounds one ICAP round trip. Longer than the quick webhook
// idiom used elsewhere (internal/vendor, internal/ticket: 8s): a whole-file
// AV/DLP scan of a large buffer takes materially longer than a yes/no
// attestation check, and the caller's own capture-byte cap already bounds
// how large that buffer can be.
const scanTimeout = 30 * time.Second

// defaultPort is ICAP's registered port (RFC 3507 §4.1), used when a
// configured URL omits one.
const defaultPort = "1344"

// vendorThreatHeaders are the header names real ICAP AV/DLP gateways use to
// name what they found, checked in order. None is standardized by RFC
// 3507; these are the ones in wide use (c-icap/ClamAV, Symantec, McAfee,
// Forcepoint/Websense). A 200 response with none of them present still
// reports Clean:false, just with a generic Reason.
var vendorThreatHeaders = []string{
	"X-Infection-Found",
	"X-Virus-ID",
	"X-Violations-Found",
	"X-Blocked-Reason",
	"X-Attribute-Names",
}

// Result is one buffer's scan outcome.
type Result struct {
	Clean  bool
	Reason string // populated when !Clean: a vendor header's value if one was present, else a generic reason
}

// Client scans buffers against one configured ICAP service.
type Client struct {
	addr    string // host:port to dial
	service string // ICAP request-URI path, e.g. "respmod" or "avscan" — vendor-specific, never guessed
}

// NewClient parses an icap://host[:port]/service URL. An empty raw URL
// returns (nil, nil): ICAP scanning is disabled, and Enabled/ScanRespmod on
// the nil result are safe to call. Port defaults to 1344 when omitted.
func NewClient(raw string) (*Client, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("icap: invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "icap" {
		return nil, fmt.Errorf("icap: %q must use the icap:// scheme", raw)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("icap: %q has no host", raw)
	}
	port := u.Port()
	if port == "" {
		port = defaultPort
	}
	service := strings.TrimPrefix(u.Path, "/")
	if service == "" {
		return nil, fmt.Errorf("icap: %q has no service path (e.g. icap://host:1344/respmod)", raw)
	}
	return &Client{addr: net.JoinHostPort(host, port), service: service}, nil
}

// Enabled reports whether ICAP scanning is configured. A nil *Client is
// always disabled, so callers can check unconditionally.
func (c *Client) Enabled() bool { return c != nil }

// ScanRespmod submits data as a whole-object RESPMOD scan and reports the
// verdict. It dials fresh, sends one request, reads one response and
// closes — see the package doc for why. A network failure, a malformed
// response, or any ICAP status other than 204/200 is reported as an error:
// the caller decides how to treat "the scan itself did not work", which is
// a different fact from "the scan found something".
func (c *Client) ScanRespmod(ctx context.Context, data []byte) (Result, error) {
	deadline := time.Now().Add(scanTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return Result{}, fmt.Errorf("icap: dial %s: %w", c.addr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return Result{}, fmt.Errorf("icap: set deadline: %w", err)
	}
	if _, err := conn.Write(buildRespmod(c.addr, c.service, data)); err != nil {
		return Result{}, fmt.Errorf("icap: write request: %w", err)
	}
	code, header, err := readResponse(conn)
	if err != nil {
		return Result{}, fmt.Errorf("icap: read response: %w", err)
	}
	switch code {
	case 204:
		return Result{Clean: true}, nil
	case 200:
		for _, name := range vendorThreatHeaders {
			if v := header.Get(name); v != "" {
				return Result{Clean: false, Reason: v}, nil
			}
		}
		return Result{Clean: false, Reason: "content modified by ICAP server"}, nil
	default:
		return Result{}, fmt.Errorf("icap: unexpected status %d", code)
	}
}

// buildRespmod encodes a single-chunk RESPMOD request carrying data as the
// body of a synthetic "HTTP/1.1 200 OK" response — the encapsulated object
// the ICAP server is asked to inspect. Deliberately no encapsulated
// req-hdr (the original request that produced this "response"): RFC 3507
// does not require one for RESPMOD, and omitting it avoids ever embedding
// an attacker-influenced remote path into a hand-built wire header, a
// CRLF-injection surface an included req-hdr would otherwise open. The
// trade-off — some AV gateways use a request's filename/extension as an
// additional heuristic — is a real, minor v1 limitation: content/signature
// scanning still runs in full.
func buildRespmod(addr, service string, data []byte) []byte {
	const resHdr = "HTTP/1.1 200 OK\r\n\r\n"
	var b bytes.Buffer
	fmt.Fprintf(&b, "RESPMOD icap://%s/%s ICAP/1.0\r\n", addr, service)
	fmt.Fprintf(&b, "Host: %s\r\n", addr)
	b.WriteString("Allow: 204\r\n")
	fmt.Fprintf(&b, "Encapsulated: res-hdr=0, res-body=%d\r\n", len(resHdr))
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	b.WriteString(resHdr)
	// The encapsulated body is always HTTP-chunked, independent of anything
	// claimed in resHdr — that chunking IS the ICAP body framing (RFC 3507
	// §4.4.1), not an HTTP concern. One chunk: the caller already holds the
	// whole file in memory, so there is no streaming benefit to splitting it.
	fmt.Fprintf(&b, "%x\r\n", len(data))
	b.Write(data)
	b.WriteString("\r\n0\r\n\r\n")
	return b.Bytes()
}

// readResponse reads the ICAP status line and header block (RFC 822-style,
// terminated by a blank line — the same shape textproto already parses for
// HTTP/SMTP/etc). It deliberately does not read past the headers: the
// caller closes the connection immediately after, so any encapsulated body
// in a 200 response is simply never read, not mis-framed.
func readResponse(conn net.Conn) (code int, header textproto.MIMEHeader, err error) {
	r := textproto.NewReader(bufio.NewReader(conn))
	line, err := r.ReadLine()
	if err != nil {
		return 0, nil, err
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "ICAP/") {
		return 0, nil, fmt.Errorf("malformed status line %q", line)
	}
	code, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, fmt.Errorf("malformed status code in %q: %w", line, err)
	}
	header, err = r.ReadMIMEHeader()
	// ReadMIMEHeader returns io.EOF alongside a valid header when the
	// connection closes right after the blank line (no encapsulated body
	// followed, e.g. a 204) — that is a normal, fully-read response, not a
	// failure.
	if err != nil && header == nil {
		return 0, nil, err
	}
	return code, header, nil
}
