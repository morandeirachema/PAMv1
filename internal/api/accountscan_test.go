package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// accountScanSSHServer is an in-process upstream accepting exactly one
// (user, password) pair and answering every exec with a fixed /etc/passwd
// body — a minimal server built for this test (internal/rotate's own
// sshServer test helper is unexported to that package and cannot be reused
// here, and it doesn't write exec output back to the channel anyway; this
// scan's parser needs real output, not just a captured stdin).
type accountScanSSHServer struct {
	host string
	port int
}

func startAccountScanSSHServer(t *testing.T, wantUser, wantPass, passwdOutput string) *accountScanSSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == wantUser && string(pass) == wantPass {
				return &ssh.Permissions{}, nil
			}
			return nil, io.EOF
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go serveAccountScanSSH(conn, cfg, passwdOutput)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(p)
	return &accountScanSSHServer{host: h, port: port}
}

func serveAccountScanSSH(conn net.Conn, cfg *ssh.ServerConfig, passwdOutput string) {
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
				if req.Type != "exec" {
					if req.WantReply {
						req.Reply(true, nil)
					}
					continue
				}
				if req.WantReply {
					req.Reply(true, nil)
				}
				ch.Write([]byte(passwdOutput))
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{0}))
				ch.Close()
			}
		}()
	}
}

// fakeAccountScanWinRM is a command-aware fake winrm.Runner: unlike the
// shared fakeWinRM helper (one canned result for every call), this scan
// issues two different commands in one run (`net user`, then
// `net localgroup Administrators`) and needs a distinct answer for each.
type fakeAccountScanWinRM struct {
	mu      sync.Mutex
	byCmd   map[string]winrm.Result
	gotCmds []string
	gotUser string
	gotPass string
}

func (f *fakeAccountScanWinRM) Run(_ context.Context, _ string, _ int, user, password, command string) (winrm.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotCmds = append(f.gotCmds, command)
	f.gotUser, f.gotPass = user, password
	return f.byCmd[command], nil
}

const samplePasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
deploy:x:1000:1000:deploy,,,:/home/deploy:/bin/bash
shadow_admin:x:1001:1001::/home/shadow_admin:/bin/bash
`

const sampleNetUser = `User accounts for \\WIN-01

-------------------------------------------------------------------------------
Administrator            svc_backup               rogue_admin
The command completed successfully.
`

const sampleNetLocalGroupAdmins = `Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
rogue_admin
The command completed successfully.
`

// TestDiscoverAccountsSSH proves the end-to-end scan against a real SSH
// upstream: root and the vaulted "deploy" account are found managed, and
// "shadow_admin" — an account the target has but pamv1 never vaulted a
// credential for — is flagged unmanaged. This is the core finding the whole
// phase exists to surface, so it is proven against a real server, not mocked.
func TestDiscoverAccountsSSH(t *testing.T) {
	upstream := startAccountScanSSHServer(t, "deploy", "s3cret", samplePasswd)
	srv, _ := newTestServerOpts(t, nil, api.Options{})

	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "acct-ssh-01", "host": upstream.host, "port": upstream.port, "os_type": "linux", "protocol": "ssh",
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	if status, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "deploy", "secret": "s3cret",
	}); status != http.StatusCreated {
		t.Fatalf("seed credential: %d %s", status, d)
	}

	status, data := do(t, srv, http.MethodPost, "/api/targets/"+strconv.FormatInt(tid, 10)+"/discover-accounts", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("discover-accounts: %d %s", status, data)
	}
	var out struct {
		Accounts []struct {
			Username   string `json:"username"`
			Privileged bool   `json:"privileged"`
		} `json:"accounts"`
		UnmanagedCount      int `json:"unmanaged_count"`
		PrivilegedUnmanaged int `json:"privileged_unmanaged_count"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Accounts) != 3 {
		t.Fatalf("expected 3 accounts (root, deploy, shadow_admin), got %d: %s", len(out.Accounts), data)
	}
	if out.UnmanagedCount != 2 {
		// root has no vaulted credential named "root" either — only "deploy" is managed.
		t.Fatalf("expected 2 unmanaged (root, shadow_admin), got %d: %s", out.UnmanagedCount, data)
	}
	if out.PrivilegedUnmanaged != 1 {
		t.Fatalf("expected 1 privileged-unmanaged (root), got %d: %s", out.PrivilegedUnmanaged, data)
	}
}

// TestDiscoverAccountsWinRM proves both fixed commands run and are parsed and
// cross-referenced correctly: only svc_backup has a vaulted credential, so
// both Administrator and rogue_admin — each an admin-group member — come
// back privileged AND unmanaged, the highest-severity finding.
func TestDiscoverAccountsWinRM(t *testing.T) {
	fake := &fakeAccountScanWinRM{byCmd: map[string]winrm.Result{
		"net user":                      {Stdout: sampleNetUser},
		"net localgroup Administrators": {Stdout: sampleNetLocalGroupAdmins},
	}}
	srv, _ := newTestServerOpts(t, nil, api.Options{WinRM: fake})

	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "acct-winrm-01", "host": "10.0.0.9", "port": 5985, "os_type": "windows", "protocol": "winrm",
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	if status, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "svc_backup", "secret": "s3cret",
	}); status != http.StatusCreated {
		t.Fatalf("seed credential: %d %s", status, d)
	}

	status, data := do(t, srv, http.MethodPost, "/api/targets/"+strconv.FormatInt(tid, 10)+"/discover-accounts", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("discover-accounts: %d %s", status, data)
	}
	var out struct {
		Accounts []struct {
			Username   string `json:"username"`
			Privileged bool   `json:"privileged"`
		} `json:"accounts"`
		UnmanagedCount      int `json:"unmanaged_count"`
		PrivilegedUnmanaged int `json:"privileged_unmanaged_count"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Accounts) != 3 {
		t.Fatalf("expected 3 accounts, got %d: %s", len(out.Accounts), data)
	}
	if out.UnmanagedCount != 2 || out.PrivilegedUnmanaged != 2 {
		t.Fatalf("expected 2 unmanaged / 2 privileged-unmanaged (Administrator, rogue_admin), got %d/%d: %s",
			out.UnmanagedCount, out.PrivilegedUnmanaged, data)
	}
	if len(fake.gotCmds) != 2 {
		t.Fatalf("expected both fixed commands to run, got %v", fake.gotCmds)
	}
}

// TestDiscoverAccountsRejectsUnsupportedProtocol proves RDP/VNC/DB targets —
// which have no command-execution surface at all — are refused up front
// rather than attempting a connection that could never work.
func TestDiscoverAccountsRejectsUnsupportedProtocol(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "rdp-01", "host": "10.0.0.5", "port": 3389, "os_type": "windows", "protocol": "rdp",
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	status, data := do(t, srv, http.MethodPost, "/api/targets/"+strconv.FormatInt(tid, 10)+"/discover-accounts", testAPIKey, nil)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for rdp target, got %d: %s", status, data)
	}
}

// TestDiscoverAccountsNoCredential proves a target with nothing vaulted yet
// is refused with a clear reason rather than attempting to dial with no
// account at all.
func TestDiscoverAccountsNoCredential(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "bare-01", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	status, data := do(t, srv, http.MethodPost, "/api/targets/"+strconv.FormatInt(tid, 10)+"/discover-accounts", testAPIKey, nil)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for credential-less target, got %d: %s", status, data)
	}
}

// TestDiscoverAccountsCommandBlocked proves the fixed enumeration command is
// not exempt from an operator-configured deny policy — Phase 38's "every
// path where a discrete command is visible obeys one policy" principle
// applies to pamv1's own generated commands too, not just operator input.
func TestDiscoverAccountsCommandBlocked(t *testing.T) {
	upstream := startAccountScanSSHServer(t, "deploy", "s3cret", samplePasswd)
	opts := api.Options{}
	opts.CommandGuard = denyGuard(t, `cat\s+/etc/passwd`)
	srv, _ := newTestServerOpts(t, nil, opts)

	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "acct-blocked-01", "host": upstream.host, "port": upstream.port, "os_type": "linux", "protocol": "ssh",
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "deploy", "secret": "s3cret",
	})

	status, data := do(t, srv, http.MethodPost, "/api/targets/"+strconv.FormatInt(tid, 10)+"/discover-accounts", testAPIKey, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for a blocked command, got %d: %s", status, data)
	}
}
