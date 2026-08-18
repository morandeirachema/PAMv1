package rotate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/winrm"
	"golang.org/x/crypto/ssh"
)

// TestGeneratePassword checks generated passwords are unique across many draws,
// correctly sized, category-complete and free of shell-unsafe characters.
func TestGeneratePassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		pw, err := GeneratePassword(PasswordPolicy{MinLength: 24})
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != 24 {
			t.Fatalf("len = %d, want 24", len(pw))
		}
		if seen[pw] {
			t.Fatalf("duplicate password generated: %q", pw)
		}
		seen[pw] = true
		if !strings.ContainsAny(pw, lowers) || !strings.ContainsAny(pw, uppers) ||
			!strings.ContainsAny(pw, digits) || !strings.ContainsAny(pw, symbols) {
			t.Fatalf("password %q missing a required category", pw)
		}
		// Must be shell-safe: no spaces, quotes or newlines that could break a
		// `net user` command line or stdin payload.
		if strings.ContainsAny(pw, " \t\n\r\"'`\\") {
			t.Fatalf("password %q contains an unsafe character", pw)
		}
	}
}

// TestGeneratePasswordMinLength checks a requested length below 12 is clamped up.
func TestGeneratePasswordMinLength(t *testing.T) {
	pw, err := GeneratePassword(PasswordPolicy{MinLength: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) < 12 {
		t.Fatalf("short length was not clamped up: %d", len(pw))
	}
}

// TestGeneratePasswordZeroPolicy checks the zero value of PasswordPolicy
// generates the exact same shape as DefaultPasswordPolicy (Phase 120) — a
// caller that forgets to set a policy must not get a degenerate password.
func TestGeneratePasswordZeroPolicy(t *testing.T) {
	pw, err := GeneratePassword(PasswordPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 24 {
		t.Fatalf("len = %d, want 24 (the default)", len(pw))
	}
}

// TestGeneratePasswordPerClassMinimums checks a policy asking for MORE than
// one of a class actually gets that many, not just "at least one" (Phase 120).
func TestGeneratePasswordPerClassMinimums(t *testing.T) {
	policy := PasswordPolicy{MinLength: 40, MinLower: 10, MinUpper: 10, MinDigit: 10, MinSymbol: 10}
	for i := 0; i < 50; i++ {
		pw, err := GeneratePassword(policy)
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != 40 {
			t.Fatalf("len = %d, want 40", len(pw))
		}
		var nLower, nUpper, nDigit, nSymbol int
		for _, c := range pw {
			switch {
			case strings.ContainsRune(lowers, c):
				nLower++
			case strings.ContainsRune(uppers, c):
				nUpper++
			case strings.ContainsRune(digits, c):
				nDigit++
			case strings.ContainsRune(symbols, c):
				nSymbol++
			default:
				t.Fatalf("password %q contains a character outside every class: %q", pw, c)
			}
		}
		if nLower < 10 || nUpper < 10 || nDigit < 10 || nSymbol < 10 {
			t.Fatalf("password %q class counts = lower:%d upper:%d digit:%d symbol:%d, want >= 10 each", pw, nLower, nUpper, nDigit, nSymbol)
		}
	}
}

// TestGeneratePasswordMinimumsExceedLength checks a policy whose class
// minimums sum to more than MinLength grows the password to fit rather than
// silently dropping a required character (Phase 120).
func TestGeneratePasswordMinimumsExceedLength(t *testing.T) {
	policy := PasswordPolicy{MinLength: 12, MinLower: 10, MinUpper: 10, MinDigit: 10, MinSymbol: 10}
	pw, err := GeneratePassword(policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 40 {
		t.Fatalf("len = %d, want 40 (grown to fit the 4x10 minimums)", len(pw))
	}
}

// --- SSH connector against an in-process SSH server ---

// TestSSHConnectorVerifyAndRotate exercises Verify (valid and wrong secret) and
// Rotate against an in-process SSH server, asserting the exact chpasswd stdin.
func TestSSHConnectorVerifyAndRotate(t *testing.T) {
	const user, oldPass = "svc-pam", "old-Secret.1"
	srv := startSSHServer(t, user, oldPass)

	target := store.Target{Host: srv.host, Port: srv.port, Protocol: "ssh"}
	conn := SSHConnector{}

	// Verify: the current secret authenticates.
	if err := conn.Verify(context.Background(), target, user, oldPass); err != nil {
		t.Fatalf("verify with valid secret: %v", err)
	}
	// Verify: a wrong secret is reported as drift.
	if err := conn.Verify(context.Background(), target, user, "wrong"); err == nil {
		t.Fatal("verify with wrong secret should fail")
	}

	// Rotate: run chpasswd with a new password; assert the server received the
	// exact "user:newpass" payload on stdin.
	newPass, err := GeneratePassword(PasswordPolicy{MinLength: 20})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Rotate(context.Background(), target, user, oldPass, newPass); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	got := srv.lastStdin()
	if want := user + ":" + newPass + "\n"; got != want {
		t.Fatalf("chpasswd stdin = %q, want %q", got, want)
	}
}

// TestSSHConnectorExec proves the one-shot ssh_exec primitive: it authenticates
// and runs a command (exit 0) with the valid secret, and fails auth on a wrong
// one.
func TestSSHConnectorExec(t *testing.T) {
	const user, pass = "svc-pam", "old-Secret.1"
	srv := startSSHServer(t, user, pass)
	target := store.Target{Host: srv.host, Port: srv.port, Protocol: "ssh"}
	conn := SSHConnector{}

	res, err := conn.Exec(context.Background(), target, user, pass, "whoami")
	if err != nil {
		t.Fatalf("exec with valid secret: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", res.ExitCode)
	}
	if _, err := conn.Exec(context.Background(), target, user, "wrong", "whoami"); err == nil {
		t.Fatal("exec with wrong secret should fail auth")
	}
}

// startExecOutputServer starts the in-process SSH server used by the
// output-bounding tests: every exec request answers with out and then exits
// with code, so a test can make a "remote command" print an arbitrary number of
// bytes.
func startExecOutputServer(t *testing.T, user, pass string, out []byte, code uint32) *sshServer {
	t.Helper()
	srv := startSSHServer(t, user, pass)
	srv.setOutput(out, code)
	return srv
}

// TestSSHExecTruncatesOversizeOutput proves Exec cannot be used to pull an
// unbounded amount of remote output into pam-server's heap: a command printing
// well past the cap comes back capped, flagged, and honest about it. Before the
// cap existed this was a memory-exhaustion vector reachable through a normal,
// policy-allowed ssh_exec ("cat /var/log/huge").
func TestSSHExecTruncatesOversizeOutput(t *testing.T) {
	const user, pass = "svc-pam", "old-Secret.1"
	huge := bytes.Repeat([]byte("a"), maxOutputBytes+1<<20) // 1 MiB past the cap
	srv := startExecOutputServer(t, user, pass, huge, 0)
	target := store.Target{Host: srv.host, Port: srv.port, Protocol: "ssh"}

	res, err := (SSHConnector{}).Exec(context.Background(), target, user, pass, "cat /var/log/huge")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !res.Truncated {
		t.Fatal("Truncated = false, want true for output past the cap")
	}
	if want := maxOutputBytes + len(truncationMarker); len(res.Output) != want {
		t.Fatalf("output length = %d, want %d (cap plus marker)", len(res.Output), want)
	}
	if !strings.HasSuffix(res.Output, truncationMarker) {
		t.Fatal("truncated output must SAY it was truncated; marker missing")
	}
	if kept := res.Output[:maxOutputBytes]; kept != string(huge[:maxOutputBytes]) {
		t.Fatal("the kept prefix is not the remote output byte-for-byte")
	}
}

// TestSSHExecKeepsSmallOutputIntact proves the common case is untouched:
// ordinary output is returned byte-for-byte with no marker and no flag, so the
// cap changes nothing about normal transcripts.
func TestSSHExecKeepsSmallOutputIntact(t *testing.T) {
	const user, pass = "svc-pam", "old-Secret.1"
	out := []byte("root:x:0:0:root:/root:/bin/bash\nsvc-pam:x:1001:1001::/home/svc-pam:/bin/sh\n")
	srv := startExecOutputServer(t, user, pass, out, 0)
	target := store.Target{Host: srv.host, Port: srv.port, Protocol: "ssh"}

	res, err := (SSHConnector{}).Exec(context.Background(), target, user, pass, "cat /etc/passwd")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if res.Truncated {
		t.Fatal("Truncated = true for output well under the cap")
	}
	if res.Output != string(out) {
		t.Fatalf("output = %q, want it byte-for-byte identical to %q", res.Output, out)
	}
	if strings.Contains(res.Output, "truncated") {
		t.Fatalf("untruncated output must carry no marker: %q", res.Output)
	}
}

// TestSSHExecTruncatedKeepsExitCode proves truncation does not change the
// error contract: a non-zero remote exit is still a RESULT carrying the code,
// never a transport error, even when the command's output had to be cut.
func TestSSHExecTruncatedKeepsExitCode(t *testing.T) {
	const user, pass = "svc-pam", "old-Secret.1"
	huge := bytes.Repeat([]byte("z"), maxOutputBytes+4096)
	srv := startExecOutputServer(t, user, pass, huge, 7)
	target := store.Target{Host: srv.host, Port: srv.port, Protocol: "ssh"}

	res, err := (SSHConnector{}).Exec(context.Background(), target, user, pass, "journalctl --no-pager")
	if err != nil {
		t.Fatalf("a non-zero remote exit must be a result, not an error: %v", err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7", res.ExitCode)
	}
	if !res.Truncated {
		t.Fatal("Truncated = false, want true")
	}
}

// TestLimitedBufferBoundary checks the exact-cap edge directly: output that
// fills the cap precisely is complete, not truncated, so the marker never
// appears on a transcript that lost nothing.
func TestLimitedBufferBoundary(t *testing.T) {
	b := &limitedBuffer{max: 8}
	n, err := b.Write([]byte("12345678"))
	if err != nil || n != 8 {
		t.Fatalf("Write = (%d, %v), want (8, nil)", n, err)
	}
	if b.String() != "12345678" {
		t.Fatalf("output = %q, want %q", b.String(), "12345678")
	}
	// One more byte: dropped, reported as written, and now flagged.
	if n, err := b.Write([]byte("9")); err != nil || n != 1 {
		t.Fatalf("over-cap Write = (%d, %v), want (1, nil) so the copy loop finishes", n, err)
	}
	if got, want := b.String(), "12345678"+truncationMarker; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

// TestSSHConnectorRejectsUnsafeUsername checks Rotate refuses a username
// containing ':' (or newlines) that could corrupt the chpasswd payload.
// TestSSHConnectorRotateKey proves ssh_key rotation: authenticate with the old
// key, install the freshly generated public key, and confirm exactly that key is
// written to authorized_keys.
func TestSSHConnectorRotateKey(t *testing.T) {
	oldPriv, err := GenerateSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	oldSigner, err := ssh.ParsePrivateKey([]byte(oldPriv))
	if err != nil {
		t.Fatal(err)
	}
	srv := startSSHServerPubkey(t, "svc-pam", oldSigner.PublicKey())
	target := store.Target{Host: srv.host, Port: srv.port, Protocol: "ssh"}

	newPriv, err := GenerateSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := (SSHConnector{}).RotateKey(context.Background(), target, "svc-pam", oldPriv, newPriv); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	newSigner, err := ssh.ParsePrivateKey([]byte(newPriv))
	if err != nil {
		t.Fatal(err)
	}
	want := string(ssh.MarshalAuthorizedKey(newSigner.PublicKey()))
	if got := srv.lastStdin(); got != want {
		t.Fatalf("installed authorized_keys = %q, want %q", got, want)
	}
}

// TestSSHConnectorVerifySSHKey proves Verify authenticates an ssh_key credential
// with public-key auth (not by presenting the PEM as a password), so key
// credentials reconcile as in-sync instead of reporting false drift.
func TestSSHConnectorVerifySSHKey(t *testing.T) {
	priv, err := GenerateSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(priv))
	if err != nil {
		t.Fatal(err)
	}
	srv := startSSHServerPubkey(t, "svc-pam", signer.PublicKey())
	target := store.Target{Host: srv.host, Port: srv.port, Protocol: "ssh"}
	if err := (SSHConnector{}).Verify(context.Background(), target, "svc-pam", priv); err != nil {
		t.Fatalf("Verify with ssh_key credential: %v", err)
	}
}

// TestSSHConnectorRejectsUnsafeUsername proves a username containing ':' or a
// newline is refused before it reaches chpasswd.
//
// The SSH connector feeds "user:newpassword\n" on stdin, so a colon would split
// the field and a newline would start a second entry — letting a crafted
// username set the password of an account other than the one being rotated.
// (Contrast the WinRM connector, whose username lands on a cmd.exe command line
// and therefore needs a full allowlist; see
// TestWinRMConnectorRejectsInjectableUsername.)
func TestSSHConnectorRejectsUnsafeUsername(t *testing.T) {
	conn := SSHConnector{}
	err := conn.Rotate(context.Background(), store.Target{Host: "127.0.0.1", Port: 1}, "bad:user", "old", "new")
	if err == nil || !strings.Contains(err.Error(), "unsafe username") {
		t.Fatalf("expected unsafe-username error, got %v", err)
	}
}

// --- WinRM connector via a fake runner ---

type fakeRunner struct {
	lastCmd  string
	lastUser string
	lastPass string
	exit     int
	err      error
}

// Run records the command and credentials it was called with, then returns the
// configured exit code or error.
func (f *fakeRunner) Run(_ context.Context, _ string, _ int, user, pass, cmd string) (winrm.Result, error) {
	f.lastCmd, f.lastUser, f.lastPass = cmd, user, pass
	if f.err != nil {
		return winrm.Result{}, f.err
	}
	return winrm.Result{ExitCode: f.exit}, nil
}

// TestWinRMConnectorRotate checks Rotate issues the expected `net user` command
// and authenticates with the old secret.
func TestWinRMConnectorRotate(t *testing.T) {
	fr := &fakeRunner{}
	conn := WinRMConnector{Runner: fr}
	target := store.Target{Host: "win01", Port: 5986, Protocol: "winrm"}
	if err := conn.Rotate(context.Background(), target, "Administrator", "old", "N3w-Pass_1"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if fr.lastCmd != "net user Administrator N3w-Pass_1 /y" {
		t.Fatalf("command = %q (missing /y auto-confirm?)", fr.lastCmd)
	}
	if fr.lastPass != "old" {
		t.Fatalf("authenticated with %q, want old secret", fr.lastPass)
	}
}

// TestWinRMConnectorVerify checks a zero exit passes and a non-zero exit is
// reported as drift.
func TestWinRMConnectorVerify(t *testing.T) {
	conn := WinRMConnector{Runner: &fakeRunner{exit: 0}}
	if err := conn.Verify(context.Background(), store.Target{Protocol: "winrm"}, "u", "s"); err != nil {
		t.Fatalf("verify exit 0: %v", err)
	}
	conn = WinRMConnector{Runner: &fakeRunner{exit: 5}}
	if err := conn.Verify(context.Background(), store.Target{Protocol: "winrm"}, "u", "s"); err == nil {
		t.Fatal("verify with non-zero exit should fail")
	}
}

// --- in-process SSH test server ---

type sshServer struct {
	host string
	port int
	mu   sync.Mutex
	last string
	out  []byte // canned stdout written back for every exec request
	exit uint32 // exit status reported for every exec request
}

// setOutput makes every exec request reply with out and then exit with code.
// It takes the mutex because serve reads these fields from another goroutine.
func (s *sshServer) setOutput(out []byte, code uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out, s.exit = out, code
}

// output returns the canned exec reply set by setOutput (nil, 0 by default).
func (s *sshServer) output() ([]byte, uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.out, s.exit
}

// lastStdin returns the stdin the server last captured from an exec channel.
func (s *sshServer) lastStdin() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// startSSHServer starts an in-process SSH server that accepts only
// (wantUser, wantPass) and records exec stdin for later inspection.
// startSSHServerCfg listens on an ephemeral port and serves connections with cfg.
func startSSHServerCfg(t *testing.T, cfg *ssh.ServerConfig) *sshServer {
	t.Helper()
	srv := &sshServer{}
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
			go srv.serve(conn, cfg)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	srv.host = h
	srv.port, _ = strconv.Atoi(p)
	return srv
}

// startSSHServer starts a mock upstream accepting one password credential.
func startSSHServer(t *testing.T, wantUser, wantPass string) *sshServer {
	t.Helper()
	return startSSHServerCfg(t, &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == wantUser && string(pass) == wantPass {
				return &ssh.Permissions{}, nil
			}
			return nil, io.EOF
		},
	})
}

// startSSHServerPubkey starts a mock upstream accepting one public key.
func startSSHServerPubkey(t *testing.T, wantUser string, wantKey ssh.PublicKey) *sshServer {
	t.Helper()
	return startSSHServerCfg(t, &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == wantUser && bytes.Equal(key.Marshal(), wantKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, io.EOF
		},
	})
}

// serve handles one connection, capturing the stdin of exec requests and
// replying with exit-status 0.
func (s *sshServer) serve(conn net.Conn, cfg *ssh.ServerConfig) {
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
					if req.WantReply {
						req.Reply(true, nil)
					}
					data, _ := io.ReadAll(ch)
					s.mu.Lock()
					s.last = string(data)
					s.mu.Unlock()
					out, code := s.output()
					if len(out) > 0 {
						_, _ = ch.Write(out)
					}
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{code}))
					ch.Close()
				default:
					if req.WantReply {
						req.Reply(true, nil)
					}
				}
			}
		}()
	}
}

// mustSigner returns a fresh ed25519 SSH signer or fails the test.
func mustSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// TestWinRMConnectorRejectsInjectableUsername proves the account name cannot
// carry a second command into `net user`. The name reaches an UNQUOTED cmd.exe
// command line, where `&` chains without needing surrounding space — so the
// earlier blocklist (space, quote, CR, LF) was insufficient and an allowlist
// replaced it. Nothing must reach the runner when the name is rejected.
func TestWinRMConnectorRejectsInjectableUsername(t *testing.T) {
	target := store.Target{Host: "win01", Port: 5985, Protocol: "winrm"}
	for _, bad := range []string{
		`svc&calc`,               // chains a second command
		`svc|whoami`,             // pipes into another
		`svc^&calc`,              // caret-escaped chain
		`svc>out.txt`,            // redirects
		`svc<in.txt`,             // reads
		`svc(1)`,                 // grouping
		`%USERNAME%`,             // environment expansion
		`svc calc`,               // argument split (caught before, kept covered)
		`svc"x`,                  // quote break (caught before, kept covered)
		"svc\ncalc",              // newline
		"svc\rcalc",              // carriage return
		"",                       // empty
		strings.Repeat("a", 105), // beyond the length bound
	} {
		fr := &fakeRunner{}
		conn := WinRMConnector{Runner: fr}
		if err := conn.Rotate(context.Background(), target, bad, "old", "N3w-Pass_1"); err == nil {
			t.Fatalf("username %q was accepted; it must be refused", bad)
		}
		if fr.lastCmd != "" {
			t.Fatalf("username %q reached the runner as %q — nothing may execute", bad, fr.lastCmd)
		}
	}

	// Legitimate Windows account shapes still rotate.
	for _, ok := range []string{"Administrator", "svc_backup", "svc-1", "CORP\\svcaccount", "svc@corp.example", "gMSA$"} {
		fr := &fakeRunner{}
		conn := WinRMConnector{Runner: fr}
		if err := conn.Rotate(context.Background(), target, ok, "old", "N3w-Pass_1"); err != nil {
			t.Fatalf("legitimate username %q was refused: %v", ok, err)
		}
	}
}

// hangingSSHServer accepts a session and an exec request but never replies with
// an exit status, so a client blocks in CombinedOutput exactly as it would
// against a wedged target or a command that simply does not finish. It reports
// when the channel it is holding is closed from the client side.
func hangingSSHServer(t *testing.T, wantUser, wantPass string) (*sshServer, <-chan struct{}) {
	t.Helper()
	closed := make(chan struct{}, 1)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == wantUser && string(pass) == wantPass {
				return &ssh.Permissions{}, nil
			}
			return nil, io.EOF
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
			go func(conn net.Conn) {
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
					_, chReqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						for req := range chReqs {
							if req.WantReply {
								req.Reply(true, nil)
							}
							// Deliberately no exit-status and no Close: the
							// "command" runs forever.
						}
						// chReqs closes when the client tears the channel down.
						select {
						case closed <- struct{}{}:
						default:
						}
					}()
				}
			}(conn)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(p)
	return &sshServer{host: h, port: port}, closed
}

// TestSSHExecStopsWhenContextIsCancelled proves that cancelling the context
// stops a running remote command, rather than merely abandoning it.
//
// This is the difference between a kill and a look-away. The session supervisor
// terminates a run by cancelling its context, and execGuard used to close the
// SSH session only when the deadline expired — a plain cancellation did
// nothing. An `ssh_exec` killed from the console therefore reported "session
// terminated" to the operator while the command kept running on the target, for
// as long as it liked. A kill that only stops you watching is not a kill.
//
// The test asserts BOTH halves: that Exec returns promptly on cancellation
// (rather than hanging for the full 15-second connector timeout), and that the
// SSH channel to the target was actually torn down.
func TestSSHExecStopsWhenContextIsCancelled(t *testing.T) {
	const user, pass = "svc-pam", "old-Secret.1"
	srv, channelClosed := hangingSSHServer(t, user, pass)
	target := store.Target{Host: srv.host, Port: srv.port, Protocol: "ssh"}
	conn := SSHConnector{Timeout: 15 * time.Second} // far longer than this test

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := conn.Exec(ctx, target, user, pass, "sleep forever")
		done <- err
	}()

	// Let the command get going, then kill it.
	time.Sleep(300 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Returned promptly, which is the point; the error value itself is a
		// transport error and not interesting.
	case <-time.After(5 * time.Second):
		t.Fatal("Exec did not return within 5s of cancellation; the command is still running on the target and only the caller gave up")
	}
	select {
	case <-channelClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("the SSH channel to the target was never closed, so the remote command was abandoned rather than stopped")
	}
}
