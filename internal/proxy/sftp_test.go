package proxy_test

// sftp_test.go proves the Phase 32 file-transfer control end to end with a real
// SFTP conversation (no third-party SFTP library): a minimal but genuine SFTP
// client speaks the wire protocol through the proxy to a minimal but genuine SFTP
// server standing in for the target. The security-critical path — the proxy's
// parse/audit/block of the operator→target leg — is exercised by actual SFTP
// packets, not a mock.

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/cmdguard"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"golang.org/x/crypto/ssh"
)

// SFTP v3 packet types used by the test client/server.
const (
	tInit     = 1
	tVersion  = 2
	tOpen     = 3
	tClose    = 4
	tRead     = 5
	tWrite    = 6
	tRemove   = 13
	tRename   = 18
	tStatus   = 101
	tHandle   = 102
	tData     = 103
	tExtended = 200
)

// pflag bits.
const (
	pRead  = 0x00000001
	pWrite = 0x00000002
	pCreat = 0x00000008
	pTrunc = 0x00000010
)

// --- wire helpers -----------------------------------------------------------

func be32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func sftpStr(s string) []byte { return append(be32(uint32(len(s))), s...) }

// sftpPacket frames a type byte + payload with the 4-byte length prefix.
func sftpPacket(typ byte, payload ...[]byte) []byte {
	body := []byte{typ}
	for _, p := range payload {
		body = append(body, p...)
	}
	return append(be32(uint32(len(body))), body...)
}

// readPacket reads one length-prefixed SFTP packet, returning its type and the
// payload after the type byte.
func readPacket(r io.Reader) (byte, []byte, error) {
	var lb [4]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(lb[:])
	if n == 0 {
		return 0, nil, io.ErrUnexpectedEOF
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return body[0], body[1:], nil
}

func readStr(b []byte) (string, []byte, bool) {
	if len(b) < 4 {
		return "", b, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint32(len(b)-4) < n {
		return "", b, false
	}
	return string(b[4 : 4+n]), b[4+n:], true
}

func subsystemName(payload []byte) string {
	var m struct{ Name string }
	_ = ssh.Unmarshal(payload, &m)
	return m.Name
}

// --- a real minimal SFTP upstream ------------------------------------------

// sftpUpstream records what actually reached the target: file names opened, bytes
// written via SSH_FXP_WRITE, and removes — so a test can assert whether a
// mutating op passed the proxy. It serves a fixed file on read for downloads.
// With deferData set, a READ is answered only after the CLOSE for its handle
// arrives (DATA first, then the close's STATUS) — the response ordering that
// exercises capture's deferred-finalize path deterministically.
type sftpUpstream struct {
	host      string
	port      int
	got       chan string // "open:<name>", "write:<data>", "remove:<path>"
	deferData atomic.Bool
}

// startUpstreamSFTP launches an sshd that accepts (upstreamUser/upstreamSecret)
// and serves the SFTP subsystem with a genuine (if minimal) v3 responder.
func startUpstreamSFTP(t *testing.T) *sftpUpstream {
	t.Helper()
	up := &sftpUpstream{got: make(chan string, 32)}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == upstreamUser && string(pass) == upstreamSecret {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("upstream: auth denied")
		},
	}
	cfg.AddHostKey(mustSigner(t))
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
			go up.serve(conn, cfg)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	up.host = h
	up.port, _ = strconv.Atoi(p)
	return up
}

func (up *sftpUpstream) serve(conn net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range chReqs {
				ok := req.Type == "subsystem" && subsystemName(req.Payload) == "sftp"
				if req.WantReply {
					req.Reply(ok, nil)
				}
				if ok {
					up.serveSFTP(ch)
				}
			}
		}()
	}
}

// serveSFTP is a minimal SSH_FXP responder: it answers INIT, OPEN, WRITE, READ,
// CLOSE and REMOVE just enough for the client to complete a transfer, recording
// the operations it actually received.
func (up *sftpUpstream) serveSFTP(ch ssh.Channel) {
	served := false
	pendingRead := uint32(0) // a READ withheld under deferData, released by CLOSE
	havePending := false
	for {
		typ, body, err := readPacket(ch)
		if err != nil {
			return
		}
		switch typ {
		case tInit:
			ch.Write(sftpPacket(tVersion, be32(3)))
		case tOpen:
			id := binary.BigEndian.Uint32(body[:4])
			name, _, _ := readStr(body[4:])
			up.got <- "open:" + name
			ch.Write(sftpPacket(tHandle, be32(id), sftpStr("h")))
		case tWrite:
			id := binary.BigEndian.Uint32(body[:4])
			_, rest, _ := readStr(body[4:]) // handle
			data, _, _ := readStr(rest[8:]) // skip the uint64 offset
			up.got <- "write:" + data
			ch.Write(sftpPacket(tStatus, be32(id), be32(0), sftpStr("ok"), sftpStr("")))
		case tRead:
			id := binary.BigEndian.Uint32(body[:4])
			if up.deferData.Load() {
				pendingRead, havePending = id, true // answered when CLOSE arrives
				continue
			}
			if !served {
				served = true
				ch.Write(sftpPacket(tData, be32(id), sftpStr("file-contents")))
			} else {
				ch.Write(sftpPacket(tStatus, be32(id), be32(1), sftpStr("eof"), sftpStr(""))) // SSH_FX_EOF
			}
		case tRemove:
			id := binary.BigEndian.Uint32(body[:4])
			name, _, _ := readStr(body[4:])
			up.got <- "remove:" + name
			ch.Write(sftpPacket(tStatus, be32(id), be32(0), sftpStr("ok"), sftpStr("")))
		case tClose:
			id := binary.BigEndian.Uint32(body[:4])
			if havePending {
				// Responses may legally be reordered: the withheld READ's DATA
				// goes out first, then this close's STATUS.
				ch.Write(sftpPacket(tData, be32(pendingRead), sftpStr("late-data")))
				havePending = false
			}
			ch.Write(sftpPacket(tStatus, be32(id), be32(0), sftpStr("ok"), sftpStr("")))
		default:
			if len(body) >= 4 {
				id := binary.BigEndian.Uint32(body[:4])
				ch.Write(sftpPacket(tStatus, be32(id), be32(0), sftpStr("ok"), sftpStr("")))
			}
		}
	}
}

// await returns the next operation the target received, failing on timeout.
func (up *sftpUpstream) await(t *testing.T) string {
	t.Helper()
	select {
	case s := <-up.got:
		return s
	case <-time.After(3 * time.Second):
		t.Fatal("timed out awaiting an upstream SFTP operation")
		return ""
	}
}

// --- test harness -----------------------------------------------------------

// startProxySFTP seeds the SFTP upstream as target "web-01" and serves a proxy
// with the given SFTP mode, returning the store, the proxy address, and the
// upstream (for asserting what actually reached the target).
func startProxySFTP(t *testing.T, mode proxy.SFTPMode) (store.Store, string, *sftpUpstream) {
	t.Helper()
	return startProxySFTPPaths(t, mode, nil)
}

// startProxySFTPPaths is startProxySFTP with an SFTP path denylist (Phase 51).
func startProxySFTPPaths(t *testing.T, mode proxy.SFTPMode, denyPatterns []string) (store.Store, string, *sftpUpstream) {
	t.Helper()
	up := startUpstreamSFTP(t)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, up.host, up.port)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	var pathGuard *cmdguard.Guard
	if len(denyPatterns) > 0 {
		pathGuard, err = cmdguard.New(denyPatterns)
		if err != nil {
			t.Fatal(err)
		}
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey:       mustSigner(t),
		RecordingDir:  t.TempDir(),
		DialTimeout:   5 * time.Second,
		SFTPMode:      mode,
		SFTPPathGuard: pathGuard,
	})
	if err != nil {
		t.Fatal(err)
	}
	return st, serveProxy(t, px), up
}

// openSFTPChannel dials the proxy, opens a session channel and requests the sftp
// subsystem. ok reports whether the subsystem request was accepted.
func openSFTPChannel(t *testing.T, addr string) (client *ssh.Client, ch ssh.Channel, ok bool) {
	t.Helper()
	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		client.Close()
		t.Fatalf("open channel: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	ok, err = ch.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"}))
	if err != nil {
		client.Close()
		t.Fatalf("subsystem request: %v", err)
	}
	return client, ch, ok
}

// initSFTP performs the INIT/VERSION handshake.
func initSFTP(t *testing.T, ch ssh.Channel) {
	t.Helper()
	if _, err := ch.Write(sftpPacket(tInit, be32(3))); err != nil {
		t.Fatalf("send INIT: %v", err)
	}
	if typ, _, err := readPacket(ch); err != nil || typ != tVersion {
		t.Fatalf("want VERSION, got type=%d err=%v", typ, err)
	}
}

// --- the tests --------------------------------------------------------------

// TestSFTPAllowAudits proves the default mode forwards a transfer to the target
// AND now audits each operation (previously the SFTP stream was opaque).
func TestSFTPAllowAudits(t *testing.T) {
	st, addr, up := startProxySFTP(t, proxy.SFTPAllow)
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused in allow mode")
	}
	defer client.Close()
	initSFTP(t, ch)

	// Upload: OPEN(write) → HANDLE, WRITE → STATUS.
	ch.Write(sftpPacket(tOpen, be32(1), sftpStr("/srv/report.csv"), be32(pWrite|pCreat|pTrunc), be32(0)))
	if typ, _, _ := readPacket(ch); typ != tHandle {
		t.Fatalf("open(write) in allow mode should be forwarded → HANDLE, got type=%d", typ)
	}
	ch.Write(sftpPacket(tWrite, be32(2), sftpStr("h"), make([]byte, 8), sftpStr("secret-exfil")))
	if typ, _, _ := readPacket(ch); typ != tStatus {
		t.Fatalf("write status expected, got type=%d", typ)
	}
	// The bytes actually reached the target.
	if got := up.await(t); got != "open:/srv/report.csv" {
		t.Fatalf("upstream first op = %q", got)
	}
	if got := up.await(t); got != "write:secret-exfil" {
		t.Fatalf("upload did not reach the target, got %q", got)
	}
	client.Close()

	assertAuditContains(t, st, "sftp.session", "mode:allow")
	assertAuditContains(t, st, "sftp.open", `path:"/srv/report.csv" mode:write`)
}

// TestSFTPReadOnlyBlocksWrites proves read-only mode refuses an upload and a
// delete before they reach the target, yet still permits (and audits) a download.
func TestSFTPReadOnlyBlocksWrites(t *testing.T) {
	st, addr, up := startProxySFTP(t, proxy.SFTPReadOnly)
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused in readonly mode")
	}
	defer client.Close()
	initSFTP(t, ch)

	// Upload attempt: OPEN(write) must come back as a permission-denied STATUS the
	// proxy synthesized — never a HANDLE — and never reach the target.
	ch.Write(sftpPacket(tOpen, be32(1), sftpStr("/srv/evil.sh"), be32(pWrite|pCreat|pTrunc), be32(0)))
	typ, body, err := readPacket(ch)
	if err != nil {
		t.Fatalf("read open reply: %v", err)
	}
	if typ != tStatus {
		t.Fatalf("readonly open(write) should be refused with STATUS, got type=%d", typ)
	}
	if code := binary.BigEndian.Uint32(body[4:8]); code != 3 { // SSH_FX_PERMISSION_DENIED
		t.Fatalf("refusal code = %d, want 3 (permission denied)", code)
	}

	// A delete is likewise blocked.
	ch.Write(sftpPacket(tRemove, be32(2), sftpStr("/srv/report.csv")))
	if typ, _, _ := readPacket(ch); typ != tStatus {
		t.Fatalf("remove reply type = %d, want STATUS(denied)", typ)
	}

	// A read-only OPEN + READ still works (forwarded to the target).
	ch.Write(sftpPacket(tOpen, be32(3), sftpStr("/srv/report.csv"), be32(pRead), be32(0)))
	if typ, _, _ := readPacket(ch); typ != tHandle {
		t.Fatalf("readonly open(read) should be forwarded → HANDLE, got type=%d", typ)
	}
	ch.Write(sftpPacket(tRead, be32(4), sftpStr("h"), make([]byte, 8), be32(1024)))
	if typ, data, _ := readPacket(ch); typ != tData || !strings.Contains(string(data), "file-contents") {
		t.Fatalf("download did not return DATA, got type=%d", typ)
	}
	client.Close()

	// Only the read-only open reached the target — no write, no remove.
	for {
		select {
		case got := <-up.got:
			if strings.HasPrefix(got, "write:") || strings.HasPrefix(got, "remove:") {
				t.Fatalf("a mutating op reached the target in readonly mode: %q", got)
			}
			continue
		default:
		}
		break
	}
	assertAuditContains(t, st, "sftp.blocked", `op:open path:"/srv/evil.sh" reason:readonly`)
	assertAuditContains(t, st, "sftp.blocked", `op:remove path:"/srv/report.csv" reason:readonly`)
	assertAuditContains(t, st, "sftp.open", "mode:read")
}

// TestSFTPDenyRefusesSubsystem proves deny mode refuses the SFTP subsystem
// outright (the operator keeps a shell but cannot transfer files) and audits it.
func TestSFTPDenyRefusesSubsystem(t *testing.T) {
	st, addr, _ := startProxySFTP(t, proxy.SFTPDeny)
	client, _, ok := openSFTPChannel(t, addr)
	defer client.Close()
	if ok {
		t.Fatal("deny mode must refuse the sftp subsystem")
	}
	client.Close()
	assertAuditContains(t, st, "sftp.denied", "web-01")
}

// TestParseSFTPMode covers the config enum mapping.
func TestParseSFTPMode(t *testing.T) {
	for in, want := range map[string]proxy.SFTPMode{
		"": proxy.SFTPAllow, "allow": proxy.SFTPAllow, "readonly": proxy.SFTPReadOnly, "deny": proxy.SFTPDeny,
	} {
		if got, err := proxy.ParseSFTPMode(in); err != nil || got != want {
			t.Fatalf("ParseSFTPMode(%q) = %q,%v; want %q", in, got, err, want)
		}
	}
	if _, err := proxy.ParseSFTPMode("nonsense"); err == nil {
		t.Fatal("an unknown SFTP mode must be rejected")
	}
}

// TestSFTPPathDenyBlocksReadAndWrite proves the Phase 51 path policy against a
// real SFTP conversation: a denied path is refused in ALLOW mode — the mode that
// permits everything else — for a DOWNLOAD as well as an upload, because a path
// you deny that can still be fetched is not denied at all. Nothing reaches the
// target, the refusal is a proper permission-denied status, the audit names the
// matched pattern, and an undenied path in the same session still works.
func TestSFTPPathDenyBlocksReadAndWrite(t *testing.T) {
	st, addr, up := startProxySFTPPaths(t, proxy.SFTPAllow, []string{`^/etc/shadow$`, `\.pem$`})
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused in allow mode")
	}
	defer client.Close()
	initSFTP(t, ch)

	// A READ of a denied path is refused, even though the mode allows writes.
	ch.Write(sftpPacket(tOpen, be32(1), sftpStr("/etc/shadow"), be32(pRead), be32(0)))
	typ, body, err := readPacket(ch)
	if err != nil {
		t.Fatalf("read open reply: %v", err)
	}
	if typ != tStatus {
		t.Fatalf("denied-path open(read) should be refused with STATUS, got type=%d", typ)
	}
	if code := binary.BigEndian.Uint32(body[4:8]); code != 3 { // SSH_FX_PERMISSION_DENIED
		t.Fatalf("refusal code = %d, want 3 (permission denied)", code)
	}

	// A WRITE to a path matching the second pattern is refused too.
	ch.Write(sftpPacket(tOpen, be32(2), sftpStr("/srv/keys/server.pem"), be32(pWrite|pCreat), be32(0)))
	if typ, _, _ := readPacket(ch); typ != tStatus {
		t.Fatalf("denied-path open(write) reply type = %d, want STATUS(denied)", typ)
	}
	// A delete of a denied path is refused by the path policy, not the mode.
	ch.Write(sftpPacket(tRemove, be32(3), sftpStr("/etc/shadow")))
	if typ, _, _ := readPacket(ch); typ != tStatus {
		t.Fatalf("denied-path remove reply type = %d, want STATUS(denied)", typ)
	}

	// An allowed path in the same session is unaffected.
	ch.Write(sftpPacket(tOpen, be32(4), sftpStr("/srv/report.csv"), be32(pRead), be32(0)))
	if typ, _, _ := readPacket(ch); typ != tHandle {
		t.Fatalf("allowed path should be forwarded → HANDLE, got type=%d", typ)
	}
	client.Close()

	// Only the allowed open reached the target: no denied path was ever named to it.
	for {
		select {
		case got := <-up.got:
			if strings.Contains(got, "shadow") || strings.Contains(got, ".pem") {
				t.Fatalf("a denied path reached the target: %q", got)
			}
			continue
		default:
		}
		break
	}
	assertAuditContains(t, st, "sftp.blocked", `op:open path:"/etc/shadow" reason:path-denied pattern:"^/etc/shadow$"`)
	assertAuditContains(t, st, "sftp.blocked", `op:open path:"/srv/keys/server.pem" reason:path-denied`)
	assertAuditContains(t, st, "sftp.blocked", `op:remove path:"/etc/shadow" reason:path-denied`)
	assertAuditContains(t, st, "sftp.open", `path:"/srv/report.csv"`)
}

// TestSFTPPathDenyCoversBothRenameSides proves a rename cannot launder a denied
// path in either direction: neither moving a denied file to an allowed name nor
// moving an allowed file onto a denied one is permitted.
func TestSFTPPathDenyCoversBothRenameSides(t *testing.T) {
	st, addr, up := startProxySFTPPaths(t, proxy.SFTPAllow, []string{`^/etc/shadow$`})
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused")
	}
	defer client.Close()
	initSFTP(t, ch)

	// Denied → allowed.
	ch.Write(sftpPacket(tRename, be32(1), sftpStr("/etc/shadow"), sftpStr("/tmp/harmless")))
	if typ, _, _ := readPacket(ch); typ != tStatus {
		t.Fatalf("rename FROM a denied path: type=%d, want STATUS(denied)", typ)
	}
	// Allowed → denied.
	ch.Write(sftpPacket(tRename, be32(2), sftpStr("/tmp/harmless"), sftpStr("/etc/shadow")))
	if typ, _, _ := readPacket(ch); typ != tStatus {
		t.Fatalf("rename TO a denied path: type=%d, want STATUS(denied)", typ)
	}
	client.Close()

	for {
		select {
		case got := <-up.got:
			if strings.Contains(got, "shadow") {
				t.Fatalf("a denied rename reached the target: %q", got)
			}
			continue
		default:
		}
		break
	}
	assertAuditContains(t, st, "sftp.blocked", `op:rename path:"/etc/shadow" reason:path-denied`)
}

// TestSFTPExtendedRenameGoverned proves the OpenSSH `posix-rename@openssh.com`
// extension — which a modern sftp client uses INSTEAD of SSH_FXP_RENAME
// whenever the server advertises it — obeys the same policy as the classic
// packet, and that `hardlink@openssh.com` cannot give a denied path a second,
// undenied name. Before Phase 59 both slid past the read-only refusal and the
// path denylist, which only parsed the classic packet types.
func TestSFTPExtendedRenameGoverned(t *testing.T) {
	// Read-only mode: a posix-rename is a mutation and must be refused.
	st, addr, up := startProxySFTP(t, proxy.SFTPReadOnly)
	client, ch, ok := openSFTPChannel(t, addr)
	if !ok {
		t.Fatal("sftp subsystem refused")
	}
	defer client.Close()
	initSFTP(t, ch)
	ch.Write(sftpPacket(tExtended, be32(1), sftpStr("posix-rename@openssh.com"), sftpStr("/srv/a"), sftpStr("/srv/b")))
	typ, body, err := readPacket(ch)
	if err != nil || typ != tStatus {
		t.Fatalf("readonly posix-rename reply: type=%d err=%v, want STATUS", typ, err)
	}
	if code := binary.BigEndian.Uint32(body[4:8]); code != 3 {
		t.Fatalf("readonly posix-rename status = %d, want 3 (permission denied)", code)
	}
	client.Close()
	select {
	case got := <-up.got:
		t.Fatalf("a readonly posix-rename reached the target: %q", got)
	default:
	}
	assertAuditContains(t, st, "sftp.blocked", "op:posix-rename")

	// Allow mode + path denylist: both extension renames are checked on both
	// sides, exactly like the classic packet.
	st2, addr2, up2 := startProxySFTPPaths(t, proxy.SFTPAllow, []string{`^/etc/shadow$`})
	client2, ch2, ok2 := openSFTPChannel(t, addr2)
	if !ok2 {
		t.Fatal("sftp subsystem refused")
	}
	defer client2.Close()
	initSFTP(t, ch2)
	ch2.Write(sftpPacket(tExtended, be32(1), sftpStr("posix-rename@openssh.com"), sftpStr("/etc/shadow"), sftpStr("/tmp/laundered")))
	if typ, _, _ := readPacket(ch2); typ != tStatus {
		t.Fatalf("denied-path posix-rename reply type = %d, want STATUS(denied)", typ)
	}
	ch2.Write(sftpPacket(tExtended, be32(2), sftpStr("hardlink@openssh.com"), sftpStr("/etc/shadow"), sftpStr("/tmp/alias")))
	if typ, _, _ := readPacket(ch2); typ != tStatus {
		t.Fatalf("denied-path hardlink reply type = %d, want STATUS(denied)", typ)
	}
	// An extension pamv1 does not govern still flows (audited nothing, refused
	// nothing): statvfs reaches the target as before.
	ch2.Write(sftpPacket(tExtended, be32(3), sftpStr("statvfs@openssh.com"), sftpStr("/srv")))
	if typ, _, _ := readPacket(ch2); typ != tStatus { // the fake upstream acks unknowns with ok
		t.Fatalf("ungoverned extension should be forwarded, got type=%d", typ)
	}
	client2.Close()
	for {
		select {
		case got := <-up2.got:
			if strings.Contains(got, "shadow") {
				t.Fatalf("a denied extension rename reached the target: %q", got)
			}
			continue
		default:
		}
		break
	}
	assertAuditContains(t, st2, "sftp.blocked", `op:posix-rename path:"/etc/shadow" reason:path-denied`)
	assertAuditContains(t, st2, "sftp.blocked", `op:hardlink path:"/etc/shadow" reason:path-denied`)
}
