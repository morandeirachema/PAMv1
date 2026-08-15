package proxy_test

// sftp_icap_test.go proves Phase 143 — ICAP-based file-transfer scanning —
// end to end, on the same real client/server harness as sftp_capture_test.go:
// a real upload crosses the proxy, a real (if minimal) ICAP responder scans
// the finalized artifact, and the tests assert on the resulting audit trail.
// TestSFTPCaptureICAPScanFailedStillReachesTarget is the load-bearing proof
// of this phase's honest scope: ICAP scanning DETECTS, it does not BLOCK —
// the file is already on the target by the time any verdict exists.

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
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/icap"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// fakeICAP starts a minimal RESPMOD responder — the same wire-level fake
// internal/icap's own tests use — returning status for every scan and
// recording each scanned buffer's exact bytes for the test to inspect.
type fakeICAPServer struct {
	addr    string
	status  int
	headers map[string]string
	scanned chan []byte
}

func startFakeICAP(t *testing.T, status int, headers map[string]string) *fakeICAPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeICAPServer{addr: ln.Addr().String(), status: status, headers: headers, scanned: make(chan []byte, 16)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

func (f *fakeICAPServer) serve(conn net.Conn) {
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
	var data []byte
	for {
		sizeLine, err := r.ReadLine()
		if err != nil {
			return
		}
		n, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 64)
		if err != nil {
			return
		}
		if n == 0 {
			r.ReadLine()
			break
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r.R, buf); err != nil {
			return
		}
		data = append(data, buf...)
		r.ReadLine()
	}
	f.scanned <- data
	fmt.Fprintf(conn, "ICAP/1.0 %d status\r\n", f.status)
	for k, v := range f.headers {
		fmt.Fprintf(conn, "%s: %s\r\n", k, v)
	}
	fmt.Fprint(conn, "\r\n")
}

// startProxySFTPCaptureICAP mirrors startProxySFTPCapture with an ICAP
// client wired in; every non-ICAP capture test keeps using the original,
// unchanged.
func startProxySFTPCaptureICAP(t *testing.T, maxBytes int64, icapClient *icap.Client) (store.Store, string, *sftpUpstream, string) {
	t.Helper()
	up := startUpstreamSFTP(t)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, up.host, up.port)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	recDir := t.TempDir()
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey:             mustSigner(t),
		RecordingDir:        recDir,
		DialTimeout:         5 * time.Second,
		SFTPMode:            proxy.SFTPAllow,
		SFTPCapture:         proxy.SFTPCaptureAll,
		SFTPCaptureMaxBytes: maxBytes,
		ICAPClient:          icapClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	return st, serveProxy(t, px), up, recDir
}

// uploadOneFile drives one small upload over an already-open SFTP channel,
// waiting for it to reach the target.
func uploadOneFile(t *testing.T, ch ssh.Channel, up *sftpUpstream, path, content string) {
	t.Helper()
	initSFTP(t, ch)
	ch.Write(sftpPacket(tOpen, be32(1), sftpStr(path), be32(pWrite|pCreat|pTrunc), be32(0)))
	if typ, _, _ := readPacket(ch); typ != tHandle {
		t.Fatalf("open(write) should be forwarded, path=%s", path)
	}
	ch.Write(sftpPacket(tWrite, be32(2), sftpStr("h"), make([]byte, 8), sftpStr(content)))
	if typ, _, _ := readPacket(ch); typ != tStatus {
		t.Fatal("write status expected")
	}
	ch.Write(sftpPacket(tClose, be32(3), sftpStr("h")))
	if typ, _, _ := readPacket(ch); typ != tStatus {
		t.Fatal("close status expected")
	}
	up.await(t) // open
	if got := up.await(t); got != "write:"+content {
		t.Fatalf("upstream write = %q, want %q", got, content)
	}
}

// TestSFTPCaptureICAPFlagsUpload proves a file ICAP flags produces a loud
// sftp.icap_flagged audit event naming the vendor's own reason.
func TestSFTPCaptureICAPFlagsUpload(t *testing.T) {
	fake := startFakeICAP(t, 200, map[string]string{"X-Infection-Found": "Type=0; Resolution=2; Threat=Eicar-Test-Signature;"})
	icapClient, err := icap.NewClient("icap://" + fake.addr + "/respmod")
	if err != nil {
		t.Fatal(err)
	}
	st, addr, up, _ := startProxySFTPCaptureICAP(t, 0, icapClient)
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused")
	}
	defer client.Close()
	uploadOneFile(t, ch, up, "/srv/eicar.txt", "eicar-payload")
	client.Close()

	detail := awaitAudit(t, st, "sftp.icap_flagged", `path:"/srv/eicar.txt"`)
	if !strings.Contains(detail, "Eicar-Test-Signature") {
		t.Fatalf("flagged audit should carry the vendor's reason: %s", detail)
	}
	select {
	case scanned := <-fake.scanned:
		if string(scanned) != "eicar-payload" {
			t.Fatalf("ICAP server received %q, want the exact uploaded content", scanned)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the ICAP server never received a scan request")
	}
}

// TestSFTPCaptureICAPCleanUploadIsQuiet proves a clean verdict (204) does
// NOT get its own audit event — only sftp.file_recorded, matching the
// deliberate choice not to audit every clean scan.
func TestSFTPCaptureICAPCleanUploadIsQuiet(t *testing.T) {
	fake := startFakeICAP(t, 204, nil)
	icapClient, err := icap.NewClient("icap://" + fake.addr + "/respmod")
	if err != nil {
		t.Fatal(err)
	}
	st, addr, up, _ := startProxySFTPCaptureICAP(t, 0, icapClient)
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused")
	}
	defer client.Close()
	uploadOneFile(t, ch, up, "/srv/clean.txt", "nothing to see here")
	client.Close()

	awaitAudit(t, st, "sftp.file_recorded", `path:"/srv/clean.txt"`)
	select {
	case <-fake.scanned:
	case <-time.After(3 * time.Second):
		t.Fatal("the ICAP server never received a scan request")
	}
	// Give any (wrongly emitted) event a moment to land, then confirm none did.
	time.Sleep(100 * time.Millisecond)
	assertNoAuditAction(t, st, "sftp.icap_flagged")
	assertNoAuditAction(t, st, "sftp.icap_scan_failed")
}

// TestSFTPCaptureICAPScanFailedStillReachesTarget is the load-bearing proof
// of this phase's honest scope: with the ICAP server unreachable, the scan
// fails loudly (sftp.icap_scan_failed) — but the file was ALREADY on the
// target before finalization ever ran, exactly as documented. ICAP scanning
// detects; it was never able to block a transfer already in flight.
func TestSFTPCaptureICAPScanFailedStillReachesTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	ln.Close() // dead endpoint: connection refused
	icapClient, err := icap.NewClient("icap://" + deadAddr + "/respmod")
	if err != nil {
		t.Fatal(err)
	}
	st, addr, up, _ := startProxySFTPCaptureICAP(t, 0, icapClient)
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused")
	}
	defer client.Close()
	// uploadOneFile itself already asserts the write reached the target
	// (up.await) BEFORE the session even closes, let alone before any scan
	// could run — the property this test exists to prove.
	uploadOneFile(t, ch, up, "/srv/unscannable.txt", "already delivered")
	client.Close()

	detail := awaitAudit(t, st, "sftp.icap_scan_failed", `path:"/srv/unscannable.txt"`)
	if !strings.Contains(detail, "error:") {
		t.Fatalf("scan-failed audit should carry the error: %s", detail)
	}
}

// TestSFTPCaptureICAPSkipsCappedFile proves a file that hit the capture
// byte cap is not submitted for scanning at all — it would be a false
// negative reported as if it were a complete, clean result.
func TestSFTPCaptureICAPSkipsCappedFile(t *testing.T) {
	fake := startFakeICAP(t, 204, nil)
	icapClient, err := icap.NewClient("icap://" + fake.addr + "/respmod")
	if err != nil {
		t.Fatal(err)
	}
	st, addr, up, _ := startProxySFTPCaptureICAP(t, 4, icapClient) // cap smaller than the write below
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused")
	}
	defer client.Close()
	initSFTP(t, ch)
	ch.Write(sftpPacket(tOpen, be32(1), sftpStr("/srv/toobig.bin"), be32(pWrite|pCreat), be32(0)))
	if typ, _, _ := readPacket(ch); typ != tHandle {
		t.Fatal("open should be forwarded")
	}
	up.await(t)
	ch.Write(sftpPacket(tWrite, be32(2), sftpStr("h"), make([]byte, 8), sftpStr("12345678"))) // 8 bytes > 4-byte cap
	readPacket(ch)                                                                            // permission-denied, capped
	ch.Write(sftpPacket(tClose, be32(3), sftpStr("h")))
	readPacket(ch)
	client.Close()

	detail := awaitAudit(t, st, "sftp.icap_skipped", `path:"/srv/toobig.bin"`)
	if !strings.Contains(detail, "reason:over-capture-limit") {
		t.Fatalf("skip reason should name the cap: %s", detail)
	}
	select {
	case <-fake.scanned:
		t.Fatal("a capped (incomplete) artifact must never be submitted for scanning")
	case <-time.After(200 * time.Millisecond):
	}
}

// assertNoAuditAction fails the test if any audit event of the given action
// exists — the negative-space counterpart to awaitAudit/assertAuditContains.
func assertNoAuditAction(t *testing.T, st store.Store, action string) {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == action {
			t.Fatalf("unexpected audit event: %s %s", e.Action, e.Detail)
		}
	}
}
