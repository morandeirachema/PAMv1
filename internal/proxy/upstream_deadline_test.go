package proxy_test

// net.Dialer.Timeout and ssh.ClientConfig.Timeout bound only the TCP connect —
// x/crypto documents the latter as such. So a target that completed the three-way
// handshake and then went SILENT parked the handling goroutine forever, holding
// the just-decrypted plaintext credential in memory. Worse, that happens in the
// window between the concurrent-session cap check and Register, so such a
// connection was counted by no cap, listed by no GET /api/sessions and killable by
// nothing: an operator retrying a "slow" target accumulated them without limit.

import (
	"net"

	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// blackHole accepts TCP connections and then says nothing at all, which is the
// behaviour of a wedged host or a middlebox that swallows the payload.
func blackHole(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			// Hold it open, read nothing, write nothing.
			t.Cleanup(func() { c.Close() })
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

// TestUpstreamHandshakeIsBounded proves a session attempt against a target that
// accepts and then goes silent FAILS within the dial timeout instead of hanging.
func TestUpstreamHandshakeIsBounded(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	host, port := blackHole(t)
	seedTarget(t, st, v, host, port)
	addr := startProxy(t, st, v, t.TempDir())

	done := make(chan error, 1)
	go func() {
		client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
			User:            "root@web-01",
			Auth:            []ssh.AuthMethod{ssh.Password(proxyAPIKey)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         30 * time.Second,
		})
		if err == nil {
			session, serr := client.NewSession()
			if serr == nil {
				session.Close()
			}
			client.Close()
			done <- nil
			return
		}
		done <- err
	}()

	// The proxy's own dial timeout is what must fire. Generous ceiling so this is
	// not a flaky timing test: without a bound it never returns at all.
	select {
	case <-done:
		// Either an error or a refused session — both mean the attempt terminated.
	case <-time.After(60 * time.Second):
		t.Fatal("the session attempt never returned: the upstream handshake is unbounded, so a goroutine is parked holding a decrypted credential")
	}
}
