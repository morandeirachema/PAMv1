package proxy_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// startTelnetDevice is an in-process telnet "router": it negotiates echo,
// asks for a login and a password, accepts ONLY upstreamUser and
// upstreamSecret, then runs a line loop answering "ran:<line>" until
// "exit". A session that reaches the loop proves the vaulted password was
// typed by the proxy — the operator never had it.
func startTelnetDevice(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go telnetDevice(c)
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

// readTelnetLine reads one line, dropping IAC negotiation and the NUL of
// CR NUL.
func readTelnetLine(r *bufio.Reader) (string, error) {
	var b []byte
	for {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		switch {
		case c == 255:
			v, _ := r.ReadByte()
			if v >= 251 && v <= 254 {
				_, _ = r.ReadByte()
			}
		case c == 0:
		case c == '\r' || c == '\n':
			if len(b) > 0 {
				return string(b), nil
			}
		default:
			b = append(b, c)
		}
	}
}

func telnetDevice(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	_, _ = c.Write([]byte{255, 251, 1, 255, 251, 3})
	_, _ = io.WriteString(c, "Router\r\nlogin: ")
	if u, err := readTelnetLine(r); err != nil || u != upstreamUser {
		_, _ = io.WriteString(c, "Login incorrect\r\n")
		return
	}
	_, _ = io.WriteString(c, "Password: ")
	if p, err := readTelnetLine(r); err != nil || p != upstreamSecret {
		_, _ = io.WriteString(c, "\r\nLogin incorrect\r\n")
		return
	}
	_, _ = io.WriteString(c, "\r\nLast login: never\r\nrouter# ")
	for {
		l, err := readTelnetLine(r)
		if err != nil || l == "exit" {
			return
		}
		_, _ = io.WriteString(c, "\r\nran:"+l+"\r\nrouter# ")
	}
}

func telnetProxy(t *testing.T, st store.Store, v *vault.Vault, enabled bool) (string, string) {
	t.Helper()
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	recDir := t.TempDir()
	px, err := proxy.New(st, v, resolver, proxy.Config{HostKey: mustSigner(t), RecordingDir: recDir,
		DialTimeout: 5 * time.Second, TelnetEnabled: enabled, ScenarioStepTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return serveProxy(t, px), recDir
}

// shellUntil opens a PTY shell through the proxy and returns its stdin and
// a function reading the output until it contains want.
func shellUntil(t *testing.T, addr string) (io.WriteCloser, func(want string) string, *ssh.Session, *ssh.Client) {
	t.Helper()
	client, err := dialProxy(t, addr, "sw-01", proxyAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm", 40, 120, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	in, _ := sess.StdinPipe()
	outR, _ := sess.StdoutPipe()
	errR, _ := sess.StderrPipe()
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	all := make(chan []byte, 64)
	pump := func(r io.Reader) {
		buf := make([]byte, 1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				all <- append([]byte(nil), buf[:n]...)
			}
			if err != nil {
				return
			}
		}
	}
	go pump(outR)
	go pump(errR)
	var got strings.Builder
	until := func(want string) string {
		deadline := time.After(5 * time.Second)
		for !strings.Contains(got.String(), want) {
			select {
			case b := <-all:
				got.Write(b)
			case <-deadline:
				t.Fatalf("never saw %q in %q", want, got.String())
			}
		}
		return got.String()
	}
	return in, until, sess, client
}

// TestTelnetTarget proves Phase 279 end to end against a device that
// accepts only the vaulted password: the default scenario logs in, the
// operator lands at the device prompt without ever seeing the login
// dialogue, commands run, and the recording holds the session but neither
// the dialogue nor the secret.
func TestTelnetTarget(t *testing.T) {
	host, port := startTelnetDevice(t)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port)
	target.Name, target.Protocol = "sw-01", "telnet"
	if err := st.UpdateTarget(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	addr, recDir := telnetProxy(t, st, v, true)

	in, until, sess, client := shellUntil(t, addr)
	first := until("router# ")
	if strings.Contains(first, "Router\r\n") || strings.Contains(first, "Password") || strings.Contains(first, upstreamSecret) {
		t.Fatalf("the login dialogue reached the operator: %q", first)
	}
	_, _ = io.WriteString(in, "show version\r")
	until("ran:show version")
	_, _ = io.WriteString(in, "exit\r")
	_ = sess.Wait()
	client.Close()

	waitForAuditDetail(t, st, "session.scenario", "target:sw-01 cred_user:"+upstreamUser+" protocol:telnet steps:4 outcome:ok")
	waitForAuditDetail(t, st, "session.record", "target:sw-01")
	if !hasAuditReason(t, st, "session.start", "protocol:telnet") {
		t.Fatal("session.start must name the telnet protocol")
	}
	entries, _ := os.ReadDir(recDir)
	var cast string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".cast") {
			b, _ := os.ReadFile(filepath.Join(recDir, e.Name()))
			cast += string(b)
		}
	}
	if !strings.Contains(cast, "ran:show version") || !strings.Contains(cast, "by its startup scenario (4 steps)") {
		t.Fatalf("recording lacks the session: %q", cast)
	}
	if strings.Contains(cast, upstreamSecret) || strings.Contains(cast, "Router\\r\\n") || strings.Contains(cast, "Password") {
		t.Fatalf("recording holds the login dialogue or the secret: %q", cast)
	}
}

// TestTelnetScenarioFailsClosed proves a scenario that never sees its
// prompt ends the session with the reason, audited, and that telnet is
// refused outright when PAM_TELNET_ENABLED is off.
func TestTelnetScenarioFailsClosed(t *testing.T) {
	host, port := startTelnetDevice(t)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port)
	target.Name, target.Protocol = "sw-01", "telnet"
	// The device closes after "Login incorrect"; the scenario waits for a
	// prompt that never comes.
	target.Scenario = "expect ogin:\nsend nobody\nexpect assword:\nsend x\nexpect router#"
	if err := st.UpdateTarget(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	addr, _ := telnetProxy(t, st, v, true)
	_, until, sess, client := shellUntil(t, addr)
	until("did not complete")
	_ = sess.Wait()
	client.Close()
	waitForAuditDetail(t, st, "session.scenario", "target:sw-01 cred_user:"+upstreamUser+" protocol:telnet steps:5 outcome:closed")

	off, _ := telnetProxy(t, st, v, false)
	c, err := dialProxy(t, off, "sw-01", proxyAPIKey)
	if err == nil {
		if s, err := c.NewSession(); err == nil {
			if err := s.Shell(); err == nil {
				t.Fatal("a telnet session opened while telnet is disabled")
			}
		}
		c.Close()
	}
	if !hasAuditReason(t, st, "session.denied", "target:sw-01") {
		t.Fatal("the refusal must be audited")
	}
}
