package proxy_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// startShellUpstream is an sshd with a real line-oriented shell: "$ "
// prompt, `sudo -i` asks for a password and accepts ONLY upstreamSecret
// (then the prompt is "root# "), any other line answers "ran:<line>". An
// exec answers "exec:<command>".
func startShellUpstream(t *testing.T) (string, int) {
	t.Helper()
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if c.User() == upstreamUser && string(pass) == upstreamSecret {
			return &ssh.Permissions{}, nil
		}
		return nil, fmt.Errorf("denied")
	}}
	cfg.AddHostKey(mustSigner(t))
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
			go serveShell(c, cfg)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(p)
	return h, pn
}

func serveShell(c net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func(ch ssh.Channel, creqs <-chan *ssh.Request) {
			defer ch.Close()
			for req := range creqs {
				switch req.Type {
				case "exec":
					var m struct{ Command string }
					_ = ssh.Unmarshal(req.Payload, &m)
					_ = req.Reply(true, nil)
					_, _ = io.WriteString(ch, "exec:"+m.Command)
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{0}))
					return
				case "shell":
					_ = req.Reply(true, nil)
					go ssh.DiscardRequests(creqs)
					shellLoop(ch)
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{0}))
					return
				default:
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				}
			}
		}(ch, creqs)
	}
}

func shellLoop(ch ssh.Channel) {
	r := bufio.NewReader(ch)
	prompt := "$ "
	_, _ = io.WriteString(ch, "Welcome\r\n"+prompt)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		switch line {
		case "exit":
			return
		case "sudo -i":
			_, _ = io.WriteString(ch, "[sudo] password for root: ")
			pw, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if strings.TrimRight(pw, "\r\n") == upstreamSecret {
				prompt = "root# "
				_, _ = io.WriteString(ch, "\r\n"+prompt)
			} else {
				_, _ = io.WriteString(ch, "\r\nSorry, try again.\r\n"+prompt)
			}
		default:
			_, _ = io.WriteString(ch, "ran:"+line+"\r\n"+prompt)
		}
	}
}

// TestSSHStartupScenario proves Phase 279's scripted first step on SSH: a
// target whose scenario runs `sudo -i` and answers the password prompt with
// the vaulted secret drops the operator straight at the root prompt, the
// operator's keystrokes wait for the scenario, the dialogue and the secret
// are in neither the operator's stream nor the recording — and an exec on
// the same target is not a shell, so it runs unscripted.
func TestSSHStartupScenario(t *testing.T) {
	host, port := startShellUpstream(t)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port)
	target.Scenario = "expect $\nsend sudo -i\nexpect password for\nsend ${password}\nexpect root#"
	if err := st.UpdateTarget(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	recDir := t.TempDir()
	addr := startProxy(t, st, v, recDir)

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	in, _ := sess.StdinPipe()
	outR, _ := sess.StdoutPipe()
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	// Typed at once, before the scenario can have finished: the gate must
	// hold it, or it would answer the password prompt.
	_, _ = io.WriteString(in, "id\n")
	var got strings.Builder
	buf := make([]byte, 512)
	for !strings.Contains(got.String(), "ran:id") {
		n, err := outR.Read(buf)
		if err != nil {
			t.Fatalf("read: %v (so far %q)", err, got.String())
		}
		got.Write(buf[:n])
	}
	if !strings.Contains(got.String(), "root# ") {
		t.Fatalf("the operator did not land at the root prompt: %q", got.String())
	}
	if strings.Contains(got.String(), "[sudo]") || strings.Contains(got.String(), upstreamSecret) || strings.Contains(got.String(), "Welcome") {
		t.Fatalf("the scenario's dialogue reached the operator: %q", got.String())
	}
	_, _ = io.WriteString(in, "exit\n")
	_ = sess.Wait()

	waitForAuditDetail(t, st, "session.scenario", "target:web-01 cred_user:"+upstreamUser+" protocol:ssh steps:5 outcome:ok")

	// An exec is not a shell: it runs as it always did, unscripted.
	es, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := es.Output("uptime")
	if err != nil || string(out) != "exec:uptime" {
		t.Fatalf("exec on a scenario target: %q %v", out, err)
	}
	if n := countAudit(t, st, "session.scenario"); n != 1 {
		t.Fatalf("the scenario ran %d times; an exec must not run it", n)
	}
	client.Close()

	waitForAuditDetail(t, st, "session.record", "target:web-01")
	entries, _ := os.ReadDir(recDir)
	var cast string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".cast") {
			b, _ := os.ReadFile(filepath.Join(recDir, e.Name()))
			cast += string(b)
		}
	}
	if !strings.Contains(cast, "ran:id") || !strings.Contains(cast, "startup scenario ran in the shell (5 steps)") {
		t.Fatalf("recording lacks the session: %q", cast)
	}
	if strings.Contains(cast, upstreamSecret) || strings.Contains(cast, "[sudo]") {
		t.Fatalf("recording holds the scenario dialogue or the secret: %q", cast)
	}
}
