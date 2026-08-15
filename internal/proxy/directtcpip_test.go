package proxy_test

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// startForwardingUpstream is startUpstream's twin: the same password-gated
// fake target, but its channel-accept loop also honors client-initiated
// direct-tcpip requests (RFC 4254 §7.2), dialing whatever destination is
// asked for and bridging bytes — exactly what a real target's own sshd does
// when it allows TCP forwarding, which pamv1 does not control. The
// same-target-only restriction this phase adds lives entirely on pamv1's
// side (handleDirectTCPIP), not here, so this fake upstream deliberately
// does NOT validate the destination — proving that restriction requires
// showing pamv1 refuses before ever asking the upstream to dial at all.
func startForwardingUpstream(t *testing.T, wantUser, wantPass string) (host string, port int) {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == wantUser && string(pass) == wantPass {
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
			go serveForwardingUpstream(conn, cfg)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(p)
	return h, pn
}

func serveForwardingUpstream(conn net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		var d struct {
			DestAddr string
			DestPort uint32
			SrcAddr  string
			SrcPort  uint32
		}
		_ = ssh.Unmarshal(nc.ExtraData(), &d)
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(chReqs)
		up, err := net.Dial("tcp", net.JoinHostPort(d.DestAddr, strconv.Itoa(int(d.DestPort))))
		if err != nil {
			ch.Close()
			continue
		}
		go func() { io.Copy(ch, up); ch.Close() }()
		go func() { io.Copy(up, ch); up.Close() }()
	}
}

// TestDirectTCPIPSameHostForwards proves the core Phase 141 property: a
// client-initiated direct-tcpip channel (ssh -L) is admitted when its
// destination is the connected target's own host — including via the
// "localhost" alias real `ssh -L X:localhost:Y` usage relies on — and on a
// DIFFERENT port than the target's SSH port, which is the actual point:
// reaching some other service (a database, an internal web UI) on the same
// box. Proven against a real upstream sshd end to end, data included, not
// just the gate decision.
func TestDirectTCPIPSameHostForwards(t *testing.T) {
	const backendReply = "backend-says-hi\n"
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()
	go func() {
		for {
			c, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.WriteString(c, backendReply) }()
		}
	}()
	_, backendPortStr, _ := net.SplitHostPort(backendLn.Addr().String())
	backendPort, _ := strconv.Atoi(backendPortStr)

	host, port := startForwardingUpstream(t, upstreamUser, upstreamSecret)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port) // web-01, SSH "port" above

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		PortForward: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, upstreamUser+"@"+target.Name, proxyAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Exact-host form: the target's own literal address, a different port
	// than its SSH port.
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", target.Host, backendPort))
	if err != nil {
		t.Fatalf("forward to the target's own host:otherport should be admitted: %v", err)
	}
	got := make([]byte, len(backendReply))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read from forwarded connection: %v", err)
	}
	conn.Close()
	if string(got) != backendReply {
		t.Fatalf("forwarded data = %q, want %q", got, backendReply)
	}

	// The "localhost" alias form real ssh -L usage relies on: from the
	// target's own network position, localhost IS the target.
	conn2, err := client.Dial("tcp", fmt.Sprintf("localhost:%d", backendPort))
	if err != nil {
		t.Fatalf("forward to localhost:otherport should be admitted: %v", err)
	}
	conn2.Close()
}

// TestDirectTCPIPRefusesOtherHost proves the actual scope limit: even
// though the fake upstream sshd would happily dial anywhere (it doesn't
// know or care about pamv1's policy), a forward naming a DIFFERENT host is
// refused by pamv1 itself, before the upstream is ever asked to dial it —
// the SSRF-pivot path this phase deliberately closes.
func TestDirectTCPIPRefusesOtherHost(t *testing.T) {
	elsewhereLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer elsewhereLn.Close()
	dialed := make(chan struct{}, 1)
	go func() {
		c, err := elsewhereLn.Accept()
		if err != nil {
			return
		}
		dialed <- struct{}{}
		c.Close()
	}()
	_, elsewherePortStr, _ := net.SplitHostPort(elsewhereLn.Addr().String())
	elsewherePort, _ := strconv.Atoi(elsewherePortStr)

	host, port := startForwardingUpstream(t, upstreamUser, upstreamSecret)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port)

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		PortForward: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, upstreamUser+"@"+target.Name, proxyAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// 127.0.0.2 is not the seeded target's host (127.0.0.1) and is not a
	// recognized loopback alias for it — same subnet is not "same host".
	if _, err := client.Dial("tcp", fmt.Sprintf("127.0.0.2:%d", elsewherePort)); err == nil {
		t.Fatal("forwarding to a different host must be refused")
	}
	select {
	case <-dialed:
		t.Fatal("the elsewhere listener must never be reached — pamv1 must refuse before the upstream dials anything")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestDirectTCPIPDisabledByConfig proves PAM_SSH_PORT_FORWARD=false (wired
// as proxy.Config.PortForward) refuses every forward outright, independent
// of destination.
func TestDirectTCPIPDisabledByConfig(t *testing.T) {
	host, port := startForwardingUpstream(t, upstreamUser, upstreamSecret)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port)

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		PortForward: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, upstreamUser+"@"+target.Name, proxyAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.Dial("tcp", fmt.Sprintf("%s:%d", target.Host, port)); err == nil {
		t.Fatal("forwarding must be refused when PortForward is false, even to the target's own host")
	}
}

// TestDirectTCPIPRefusedInObserverMode proves an observer (read-only,
// supervisor-watching) session cannot use forwarding as a side door into a
// full bidirectional data path — the one property no existing mechanism
// covers automatically, since the read-only enforcement lives inside
// handleSession's client→upstream request pump, a place a direct-tcpip
// channel never passes through.
func TestDirectTCPIPRefusedInObserverMode(t *testing.T) {
	host, port := startForwardingUpstream(t, upstreamUser, upstreamSecret)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port)

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		PortForward: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, upstreamUser+"@"+target.Name+"+observe", proxyAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.Dial("tcp", fmt.Sprintf("%s:%d", target.Host, port)); err == nil {
		t.Fatal("forwarding must be refused in an observer session")
	}
}

// TestDirectTCPIPRefusedWhenSupervisionRequired proves forwarding is
// refused outright while PAM_REQUIRE_LIVE_SUPERVISION is configured — a
// forward has no supervision-wait mechanism to inherit (that machinery
// lives entirely inside handleSession), so this fails closed rather than
// silently admitting an unsupervised data path a deployment specifically
// turned this flag on to prevent.
func TestDirectTCPIPRefusedWhenSupervisionRequired(t *testing.T) {
	host, port := startForwardingUpstream(t, upstreamUser, upstreamSecret)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port)

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		PortForward: true, RequireSupervision: true, SupervisionTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, upstreamUser+"@"+target.Name, proxyAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.Dial("tcp", fmt.Sprintf("%s:%d", target.Host, port)); err == nil {
		t.Fatal("forwarding must be refused while live supervision is required")
	}
}

// TestDirectTCPIPRefusedWhenRecordingRequired proves forwarding is refused
// outright while PAM_REQUIRE_RECORDING is configured — forwarded bytes are
// opaque and can never be recorded the way an interactive session's
// asciicast is, so "required" means refused, not silently unrecorded.
func TestDirectTCPIPRefusedWhenRecordingRequired(t *testing.T) {
	host, port := startForwardingUpstream(t, upstreamUser, upstreamSecret)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port)

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		PortForward: true, RequireRecording: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, upstreamUser+"@"+target.Name, proxyAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.Dial("tcp", fmt.Sprintf("%s:%d", target.Host, port)); err == nil {
		t.Fatal("forwarding must be refused while session recording is required")
	}
}
