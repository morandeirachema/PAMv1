package proxy_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// fakeWinRMRunner returns canned output for any command, capturing the last one.
type fakeWinRMRunner struct {
	out     string
	lastCmd string
}

func (f *fakeWinRMRunner) Run(_ context.Context, _ string, _ int, _, _, cmd string) (winrm.Result, error) {
	f.lastCmd = cmd
	return winrm.Result{Stdout: f.out}, nil
}

func seedWinRMTarget(t *testing.T, st store.Store, v *vault.Vault) {
	t.Helper()
	ctx := context.Background()
	target := &store.Target{Name: "win-01", Host: "10.0.0.20", Port: 5986, OSType: "windows", Protocol: "winrm"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	cred := &store.Credential{TargetID: target.ID, Username: "Administrator", SecretType: "password"}
	if err := st.CreateCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	enc, err := v.Encrypt(ctx, "S3cret", store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateCredentialSecretEnc(ctx, cred.ID, enc); err != nil {
		t.Fatal(err)
	}
}

// TestWinRMShellThroughProxy proves the proxy brokers an interactive WinRM
// command loop: a shell request opens a prompt, each operator line runs as a
// WinRM command (JIT credential), and the output streams back.
func TestWinRMShellThroughProxy(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	seedWinRMTarget(t, st, v)
	runner := &fakeWinRMRunner{out: "contoso\\Administrator\r\n"}

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		WinRMRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, "win-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}
	io.WriteString(stdin, "whoami\r\nexit\r\n")
	data, _ := io.ReadAll(stdout)
	_ = sess.Wait()

	got := string(data)
	if !strings.Contains(got, "contoso\\Administrator") {
		t.Fatalf("shell output missing command result: %q", got)
	}
	if runner.lastCmd != "whoami" {
		t.Fatalf("winrm ran %q, want whoami", runner.lastCmd)
	}
}

// TestWinRMShellLiveMonitor proves a WinRM session through the proxy streams to
// the live-monitoring hub (Phase 16 follow-on): a supervisor subscribed to the
// session id sees the echoed command and its output as they happen, the way
// they already could for SSH and PostgreSQL sessions. Before this, a WinRM
// session was listable and killable but silent on the watch stream.
func TestWinRMShellLiveMonitor(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	seedWinRMTarget(t, st, v)
	runner := &fakeWinRMRunner{out: "contoso\\Administrator\r\n"}

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	reg := session.NewRegistry()
	hub := session.NewHub()
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		WinRMRunner: runner, Sessions: reg, Live: hub,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, "win-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}

	// The session registers on connect; find its id and watch it BEFORE the
	// command is sent, so the subscription sees the echo and the output.
	var sid string
	for i := 0; i < 200 && sid == ""; i++ {
		if ls := reg.List(); len(ls) > 0 {
			if ls[0].Protocol != "winrm" {
				t.Fatalf("registered protocol = %q, want winrm", ls[0].Protocol)
			}
			sid = ls[0].ID
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if sid == "" {
		t.Fatal("winrm session was not registered")
	}
	frames, cancel := hub.Subscribe(sid)
	defer cancel()

	if _, err := io.WriteString(stdin, "whoami\r\n"); err != nil {
		t.Fatal(err)
	}
	// Collect frames until both the echoed command and its output have streamed.
	var acc string
	deadline := time.After(3 * time.Second)
	for !strings.Contains(acc, "whoami") || !strings.Contains(acc, "contoso\\Administrator") {
		select {
		case b := <-frames:
			acc += string(b)
		case <-deadline:
			t.Fatalf("live stream missing echo or output; saw %q", acc)
		}
	}

	io.WriteString(stdin, "exit\r\n")
	io.ReadAll(stdout)
	_ = sess.Wait()
}
