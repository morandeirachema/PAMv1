package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// This file is the end-to-end proof that PAMv1 does the thing a PAM exists to
// do: an operator gets a session on a protected host WITHOUT ever holding that
// host's credential, and evidence of what happened survives.
//
// Everything else in the suite tests a layer. `internal/proxy.TestJITInjection`
// proves injection in-process, building a memstore, a vault and the proxy
// directly — it never goes through config.Load, the REST API, or the
// recording/audit wiring. `TestRunServesAndShutsDownGracefully` boots the whole
// server but only asks whether /healthz answers. Between them sat the property
// that matters most, proven by hand and by nothing else.
//
// Two lessons from proving it by hand are built into this file:
//
//   - The manual run set PAM_SSH_LISTEN_ADDR, which does not exist. The real
//     name is PAM_SSH_ADDR, the value was ignored, and the proxy came up on its
//     default port — a mistake no unit test could have caught, because the
//     mistake was in the wiring between config and listener.
//   - The throwaway upstream answered `exit 0` to EVERY command, which made a
//     failed credential rotation look successful. An upstream that cannot fail
//     makes the test that uses it unable to fail. This one refuses commands it
//     does not know.

const (
	e2eVaultUser   = "dbadmin"
	e2eVaultSecret = "vaulted-secret-the-operator-never-sees-9f3a"
	e2eKnownCmd    = "whoami"
	e2eMarker      = "REAL-TARGET-OUTPUT-8c21"
	e2eDeniedCmd   = "cat /etc/shadow"
)

// TestEndToEndPrivilegedAccess boots the real server and drives it exactly as an
// operator and an administrator would: over the REST API and over the SSH proxy.
//
// The subtests share one running server on purpose — that is how the system is
// actually used, and it lets later steps observe the evidence earlier ones left.
// They therefore run in order and are not parallel.
func TestEndToEndPrivilegedAccess(t *testing.T) {
	upHost, upPort := startFaithfulUpstream(t)

	setMinimalEnv(t)
	apiAddr, sshAddr := freeAddr(t), freeAddr(t)
	t.Setenv("PAM_LISTEN_ADDR", apiAddr)
	t.Setenv("PAM_SSH_ADDR", sshAddr) // NOT PAM_SSH_LISTEN_ADDR; see the note above
	t.Setenv("PAM_SSH_HOST_KEY", filepath.Join(t.TempDir(), "host.pem"))
	t.Setenv("PAM_AUDIT_HMAC_KEY", b64Bytes(t, 32))
	t.Setenv("PAM_COMMAND_DENY_FILE", writeTemp(t, "deny.txt", e2eDeniedCmd+"\n"))
	recordingDir := os.Getenv("PAM_RECORDING_DIR")
	adminKey := os.Getenv("PAM_API_KEY")

	done := make(chan error, 1)
	go func() { done <- run() }()
	base := "http://" + apiAddr
	waitHealthz(t, http.DefaultClient, base+"/healthz")
	defer shutDown(t, done)

	call := func(method, path, key string, body any) (int, []byte) {
		t.Helper()
		return apiCall(t, base+path, method, key, body)
	}

	// --- provisioning, as an administrator ------------------------------------
	code, resp := call(http.MethodPost, "/api/targets", adminKey, map[string]any{
		"name": "prod-db", "host": upHost, "port": upPort,
		"os_type": "linux", "protocol": "ssh",
	})
	if code != http.StatusCreated {
		t.Fatalf("create target: %d %s", code, resp)
	}
	targetID := jsonInt(t, resp, "id")
	code, resp = call(http.MethodPost, "/api/credentials", adminKey, map[string]any{
		"target_id": targetID, "username": e2eVaultUser,
		"secret_type": "password", "secret": e2eVaultSecret,
	})
	if code != http.StatusCreated {
		t.Fatalf("create credential: %d %s", code, resp)
	}
	credID := jsonInt(t, resp, "id")

	// --- 1. the property that makes this a PAM --------------------------------
	t.Run("just-in-time injection", func(t *testing.T) {
		// The operator authenticates with the PAM API key. The upstream accepts
		// ONLY the vaulted secret. So reaching it proves the secret was injected
		// and never handed over.
		out, err := sshExec(sshAddr, e2eVaultUser+"@prod-db", adminKey, e2eKnownCmd)
		if err != nil {
			t.Fatalf("connect through the proxy: %v", err)
		}
		if !strings.Contains(out, e2eMarker) {
			t.Fatalf("did not reach the protected host; output = %q", out)
		}
	})

	// --- 2. the secret must not survive anywhere a reader can get at it -------
	t.Run("the secret leaks nowhere", func(t *testing.T) {
		_, auditBody := call(http.MethodGet, "/api/audit?limit=500", adminKey, nil)
		if bytes.Contains(auditBody, []byte(e2eVaultSecret)) {
			t.Error("the vaulted secret appears in the audit trail")
		}
		entries, err := os.ReadDir(recordingDir)
		if err != nil {
			t.Fatalf("read recordings: %v", err)
		}
		var files int
		for _, e := range entries {
			b, err := os.ReadFile(filepath.Join(recordingDir, e.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", e.Name(), err)
			}
			files++
			if bytes.Contains(b, []byte(e2eVaultSecret)) {
				t.Errorf("the vaulted secret appears in %s", e.Name())
			}
		}
		// Without this the check passes on an empty directory, which is the
		// state where nothing was recorded at all.
		if files == 0 {
			t.Fatal("no recording or chain file was written; the leak check proved nothing")
		}
	})

	// --- 3. authorization ------------------------------------------------------
	t.Run("rbac", func(t *testing.T) {
		_, body := call(http.MethodPost, "/api/users", adminKey,
			map[string]any{"username": "olivia", "role": "user"})
		userTok := jsonString(t, body, "token")

		if code, _ := call(http.MethodGet, "/api/targets", "", nil); code != http.StatusUnauthorized {
			t.Errorf("no key: got %d, want 401", code)
		}
		if code, _ := call(http.MethodGet, "/api/targets", "not-a-real-key", nil); code != http.StatusUnauthorized {
			t.Errorf("bad key: got %d, want 401", code)
		}
		if code, _ := call(http.MethodPost, "/api/targets", userTok, map[string]any{
			"name": "nope", "host": "h", "port": 22, "os_type": "linux", "protocol": "ssh",
		}); code != http.StatusForbidden {
			t.Errorf("user creating a target: got %d, want 403", code)
		}
		if code, _ := call(http.MethodPost,
			fmt.Sprintf("/api/credentials/%d/reveal", credID), userTok, nil); code != http.StatusForbidden {
			t.Errorf("user revealing a secret: got %d, want 403", code)
		}
		// ...but a `user` is exactly who is meant to connect, so that must work.
		if _, err := sshExec(sshAddr, e2eVaultUser+"@prod-db", userTok, e2eKnownCmd); err != nil {
			t.Errorf("a `user` could not connect, which is the one thing the role is for: %v", err)
		}
	})

	// --- 4. the approval gate covers EVERY path to the secret ------------------
	t.Run("approval gate", func(t *testing.T) {
		if code, resp := call(http.MethodPut, fmt.Sprintf("/api/targets/%d", targetID), adminKey, map[string]any{
			"name": "prod-db", "host": upHost, "port": upPort,
			"os_type": "linux", "protocol": "ssh", "require_approval": true,
		}); code != http.StatusOK {
			t.Fatalf("require approval: %d %s", code, resp)
		}
		_, body := call(http.MethodPost, "/api/users", adminKey,
			map[string]any{"username": "rita", "role": "user"})
		ritaTok := jsonString(t, body, "token")

		if _, err := sshExec(sshAddr, e2eVaultUser+"@prod-db", ritaTok, e2eKnownCmd); err == nil {
			t.Error("connected to an approval-gated target with no approval")
		}
		// The gate is not only on the proxy: revealing the secret is another way
		// to the same credential, and it is refused too.
		if code, _ := call(http.MethodPost,
			fmt.Sprintf("/api/credentials/%d/reveal", credID), adminKey, nil); code == http.StatusOK {
			t.Error("revealed an approval-gated credential with no approval")
		}

		_, body = call(http.MethodPost, "/api/access-requests", ritaTok,
			map[string]any{"target_id": targetID, "reason": "incident 4412"})
		reqID := jsonInt(t, body, "id")
		if code, _ := call(http.MethodPost,
			fmt.Sprintf("/api/access-requests/%d/approve", reqID), ritaTok, nil); code != http.StatusForbidden {
			t.Errorf("four-eyes: rita approved her own request (%d)", code)
		}
		if code, resp := call(http.MethodPost,
			fmt.Sprintf("/api/access-requests/%d/approve", reqID), adminKey, nil); code != http.StatusOK {
			t.Fatalf("admin approve: %d %s", code, resp)
		}
		if _, err := sshExec(sshAddr, e2eVaultUser+"@prod-db", ritaTok, e2eKnownCmd); err != nil {
			t.Errorf("connect after approval: %v", err)
		}

		if code, _ := call(http.MethodPut, fmt.Sprintf("/api/targets/%d", targetID), adminKey, map[string]any{
			"name": "prod-db", "host": upHost, "port": upPort,
			"os_type": "linux", "protocol": "ssh", "require_approval": false,
		}); code != http.StatusOK {
			t.Fatalf("clearing require_approval failed; later subtests would be misled")
		}
	})

	// --- 5. tamper-evidence, in BOTH directions --------------------------------
	t.Run("recording tamper detection", func(t *testing.T) {
		name := newestRecording(t, recordingDir)
		// The untouched file must verify. Asserting only the tampered case would
		// pass against a check that always answers "false", which is the failure
		// mode of every integrity control that is never exercised clean.
		if got := recordingAudited(t, base, adminKey, name); got != "true" {
			t.Fatalf("an untouched recording reported audited=%q, want true", got)
		}
		f, err := os.OpenFile(filepath.Join(recordingDir, name), os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatalf("open recording: %v", err)
		}
		if _, err := f.WriteString("\n[99.0,\"o\",\"output that never happened\"]\n"); err != nil {
			t.Fatalf("tamper: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		if got := recordingAudited(t, base, adminKey, name); got != "false" {
			t.Fatalf("a TAMPERED recording still reported audited=%q, want false", got)
		}
	})

	// --- 6. command control ----------------------------------------------------
	t.Run("denied command is refused and audited", func(t *testing.T) {
		if _, err := sshExec(sshAddr, e2eVaultUser+"@prod-db", adminKey, e2eDeniedCmd); err == nil {
			t.Fatal("a denied command ran")
		}
		_, body := call(http.MethodGet, "/api/audit?limit=50", adminKey, nil)
		if !bytes.Contains(body, []byte("command.blocked")) {
			t.Error("the blocked command left no command.blocked audit event")
		}
	})
}

// startFaithfulUpstream is the protected host: an SSH server that accepts
// EXACTLY ONE password — the one PAMv1 vaults — and refuses any command it does
// not recognise.
//
// Both halves matter. Accepting only the vaulted secret is what makes a
// successful connection evidence of injection rather than of nothing. Refusing
// unknown commands is the lesson from a throwaway harness that answered `exit 0`
// to everything and thereby reported a failed operation as a success.
func startFaithfulUpstream(t *testing.T) (host string, port int) {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == e2eVaultUser && string(pass) == e2eVaultSecret {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("upstream: only the vaulted credential is accepted")
		},
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("upstream host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("upstream signer: %v", err)
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFaithfulUpstream(conn, cfg)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(p)
	return h, pn
}

// serveFaithfulUpstream answers one connection, succeeding only for the command
// it knows.
func serveFaithfulUpstream(conn net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range chReqs {
				switch req.Type {
				case "pty-req", "shell":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				case "exec":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					var payload struct{ Command string }
					_ = ssh.Unmarshal(req.Payload, &payload)
					code := uint32(0)
					if strings.TrimSpace(payload.Command) == e2eKnownCmd {
						_, _ = io.WriteString(ch, e2eMarker+"\n")
					} else {
						_, _ = io.WriteString(ch, "upstream: unknown command\n")
						code = 127
					}
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{code}))
					return
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		}()
	}
}

// sshExec runs one command through an SSH listener with password auth, which is
// how an operator reaches the proxy: the PAM key is the password.
func sshExec(addr, user, password, cmd string) (string, error) {
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 -- a test dialling its own listener
		Timeout:         20 * time.Second,
	})
	if err != nil {
		return "", err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	return string(out), err
}

// apiCall performs one REST call, returning the status and body. An empty key
// sends no header at all, which is the unauthenticated case.
func apiCall(t *testing.T, url, method, key string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, out
}

// recordingAudited returns the X-Pam-Recording-Audited header for one recording
// — the server's verdict on whether the bytes on disk match what was audited
// when the session was recorded.
func recordingAudited(t *testing.T, base, key, name string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+"/api/recordings/"+name, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("X-API-Key", key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("play recording: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("play recording: status %d", resp.StatusCode)
	}
	return resp.Header.Get("X-Pam-Recording-Audited")
}

// newestRecording returns the most recent .cast file, which is the session the
// caller just created.
func newestRecording(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read recordings: %v", err)
	}
	var name string
	var newest time.Time
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".cast") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(newest) {
			newest, name = info.ModTime(), e.Name()
		}
	}
	if name == "" {
		t.Fatal("no .cast recording was written")
	}
	return name
}

// jsonInt and jsonString pull one field out of a JSON object body.
func jsonInt(t *testing.T, body []byte, field string) int64 {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal %s: %v (%s)", field, err, body)
	}
	f, ok := m[field].(float64)
	if !ok {
		t.Fatalf("field %q missing from %s", field, body)
	}
	return int64(f)
}

func jsonString(t *testing.T, body []byte, field string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal %s: %v (%s)", field, err, body)
	}
	s, ok := m[field].(string)
	if !ok {
		t.Fatalf("field %q missing from %s", field, body)
	}
	return s
}
