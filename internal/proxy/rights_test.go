package proxy_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestSubprotocolRights proves Phase 270 on the SSH proxy against the real
// in-process upstream: a target whose rights name only the shell refuses
// exec, the sftp subsystem and a port forward — each audited with the right
// it lacked — while a target with no set admits them all; and a grant that
// narrows the target's set to exec then refuses the shell for that subject.
func TestSubprotocolRights(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second, PortForward: true})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)
	ctx := context.Background()

	setRights := func(rights string) {
		t.Helper()
		target.Rights = rights
		if err := st.UpdateTarget(ctx, target); err != nil {
			t.Fatal(err)
		}
	}
	dial := func() *ssh.Client {
		t.Helper()
		c, err := dialProxy(t, addr, "web-01", proxyAPIKey)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		return c
	}
	execOK := func(c *ssh.Client) bool {
		sess, err := c.NewSession()
		if err != nil {
			return false
		}
		defer sess.Close()
		out, err := sess.Output("whoami")
		return err == nil && string(out) == targetOutput
	}
	sftpOK := func(c *ssh.Client) bool {
		ch, reqs, err := c.OpenChannel("session", nil)
		if err != nil {
			return false
		}
		defer ch.Close()
		go ssh.DiscardRequests(reqs)
		ok, err := ch.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"}))
		return err == nil && ok
	}
	shellOK := func(c *ssh.Client) bool {
		ch, reqs, err := c.OpenChannel("session", nil)
		if err != nil {
			return false
		}
		defer ch.Close()
		go ssh.DiscardRequests(reqs)
		ok, err := ch.SendRequest("shell", true, nil)
		return err == nil && ok
	}
	forwardOK := func(c *ssh.Client) bool {
		conn, err := c.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}

	// No set: everything the deployment allows. The plain test upstream does
	// not serve direct-tcpip, so the forward is admitted past every gate and
	// then fails at the upstream dial — which is the audit row that proves
	// the rights gate let it through.
	c := dial()
	if !execOK(c) {
		t.Fatal("exec refused with no rights set")
	}
	_ = forwardOK(c)
	c.Close()
	waitForAuditDetail(t, st, "forward.refused", "reason:dial-failed")

	// Shell only: exec, sftp and the forward are refused, each audited.
	setRights(store.RightSSHShell)
	c = dial()
	if execOK(c) {
		t.Fatal("exec admitted against a shell-only target")
	}
	if sftpOK(c) {
		t.Fatal("sftp admitted against a shell-only target")
	}
	if forwardOK(c) {
		t.Fatal("forward admitted against a shell-only target")
	}
	c.Close()
	for _, right := range []string{store.RightSSHExec, store.RightSSHSFTP, store.RightSSHForward} {
		waitForAuditDetail(t, st, "session.right_denied", "target:web-01 cred_user:"+upstreamUser+" right:"+right)
	}

	// A grant narrowing an open target to exec: the admin's own role grant
	// matches the bootstrap principal, so exec passes and the shell is refused.
	setRights("")
	if err := st.CreateTargetGrant(ctx, &store.TargetGrant{TargetID: target.ID, SubjectType: "role", Subject: "admin", Rights: store.RightSSHExec, CreatedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	c = dial()
	if !execOK(c) {
		t.Fatal("exec refused although the grant allows it")
	}
	if shellOK(c) {
		t.Fatal("shell admitted although the grant narrows to exec")
	}
	c.Close()
	waitForAuditDetail(t, st, "session.right_denied", "right:"+store.RightSSHShell)
}
