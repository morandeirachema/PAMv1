// Package rotate implements the credential-lifecycle connectors: changing a
// privileged account's secret on the real target (rotation) and checking that a
// vaulted secret still authenticates (reconciliation). Both operations run over
// the same secure protocols the session proxy uses (SSH, WinRM) so a rotation is
// verifiable end-to-end.
//
// A Rotator sets a new secret on the target; a Verifier proves a secret still
// works. The SSH and WinRM connectors implement both. Password generation lives
// here too, producing strong secrets from a shell-safe alphabet so an injected
// password can never break the command that sets it.
package rotate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/winrm"
	"golang.org/x/crypto/ssh"
)

// Rotator changes username's secret on target from oldSecret to newSecret.
// Implementations authenticate with oldSecret (the account rotating itself must
// be privileged enough to set its own password).
type Rotator interface {
	Rotate(ctx context.Context, target store.Target, username, oldSecret, newSecret string) error
}

// Verifier reports whether secret still authenticates username to target
// (nil = in sync). A non-nil error is drift or an unreachable target.
type Verifier interface {
	Verify(ctx context.Context, target store.Target, username, secret string) error
}

// --- password generation ---

// Password alphabets. Symbols are restricted to characters that are safe both
// on a shell command line (WinRM `net user`) and in an SSH stdin payload, so a
// generated password can never inject into the rotation command.
const (
	lowers  = "abcdefghijkmnopqrstuvwxyz"
	uppers  = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	digits  = "23456789"
	symbols = "-_.~"
	allPw   = lowers + uppers + digits + symbols
)

// PasswordPolicy configures a generated password's length and per-class
// minimums (Phase 120). A zero value is not directly usable — pass it through
// Normalized first, or use DefaultPasswordPolicy — because a caller-supplied
// zero must never silently generate a 0-length password.
type PasswordPolicy struct {
	MinLength                               int
	MinLower, MinUpper, MinDigit, MinSymbol int
}

// DefaultPasswordPolicy reproduces the hardcoded behavior every password had
// before PasswordPolicy existed: 24 characters, at least one of each class.
var DefaultPasswordPolicy = PasswordPolicy{MinLength: 24, MinLower: 1, MinUpper: 1, MinDigit: 1, MinSymbol: 1}

// Normalized fills in zero fields from DefaultPasswordPolicy and then grows
// MinLength, if necessary, to fit the sum of the four class minimums — a
// policy asking for more required characters than its own length is a
// misconfiguration GeneratePassword resolves rather than fails on, since the
// alternative (refusing to rotate a credential at all) is worse than a
// password slightly longer than PAM_PASSWORD_MIN_LENGTH requested.
func (p PasswordPolicy) Normalized() PasswordPolicy {
	if p.MinLength <= 0 {
		p.MinLength = DefaultPasswordPolicy.MinLength
	}
	if p.MinLower <= 0 {
		p.MinLower = DefaultPasswordPolicy.MinLower
	}
	if p.MinUpper <= 0 {
		p.MinUpper = DefaultPasswordPolicy.MinUpper
	}
	if p.MinDigit <= 0 {
		p.MinDigit = DefaultPasswordPolicy.MinDigit
	}
	if p.MinSymbol <= 0 {
		p.MinSymbol = DefaultPasswordPolicy.MinSymbol
	}
	if p.MinLength < 12 {
		p.MinLength = 12
	}
	if required := p.MinLower + p.MinUpper + p.MinDigit + p.MinSymbol; p.MinLength < required {
		p.MinLength = required
	}
	return p
}

// GeneratePassword returns a cryptographically strong password satisfying
// policy (see PasswordPolicy.Normalized for how a partial or zero policy is
// filled in) — at least MinLength characters, containing at least MinLower
// lowercase, MinUpper uppercase, MinDigit digit and MinSymbol symbol
// characters, satisfying typical Windows/Linux complexity policies.
func GeneratePassword(policy PasswordPolicy) (string, error) {
	policy = policy.Normalized()
	out := make([]byte, policy.MinLength)
	idx := 0
	for _, class := range []struct {
		set string
		min int
	}{{lowers, policy.MinLower}, {uppers, policy.MinUpper}, {digits, policy.MinDigit}, {symbols, policy.MinSymbol}} {
		for i := 0; i < class.min; i++ {
			c, err := pick(class.set)
			if err != nil {
				return "", err
			}
			out[idx] = c
			idx++
		}
	}
	// Fill the rest from the full set.
	for ; idx < policy.MinLength; idx++ {
		c, err := pick(allPw)
		if err != nil {
			return "", err
		}
		out[idx] = c
	}
	// Shuffle so the guaranteed characters are not always at the front.
	if err := shuffle(out); err != nil {
		return "", err
	}
	return string(out), nil
}

// pick returns a cryptographically random byte drawn from set.
func pick(set string) (byte, error) {
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[idx.Int64()], nil
}

// shuffle performs a crypto-random Fisher–Yates shuffle in place.
func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		ji := int(j.Int64())
		b[i], b[ji] = b[ji], b[i]
	}
	return nil
}

// GenerateSSHKey returns a fresh ed25519 private key in OpenSSH PEM format,
// suitable for vaulting as a new ssh_key credential.
func GenerateSSHKey() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(block)), nil
}

// --- SSH connector (Linux/Unix targets) ---

// SSHConnector rotates and verifies password credentials over SSH. Rotation
// runs RotateCommand (default "chpasswd") and feeds it "user:newpass\n" on
// stdin — the new password never appears on the command line, so it cannot be
// shell-injected. The rotating account must be able to set its own password
// (root, or a sudoer with an appropriate RotateCommand such as "sudo chpasswd").
type SSHConnector struct {
	// RotateCommand reads "username:newpassword\n" on stdin. Default "chpasswd".
	RotateCommand string
	// Timeout bounds the dial + command. Default 15s.
	Timeout time.Duration
	// HostKeyCallback pins the upstream host key. Default InsecureIgnoreHostKey
	// (documented gap; supply a known_hosts callback for production).
	HostKeyCallback ssh.HostKeyCallback
}

// timeout returns the configured dial+command timeout, or 15s when unset.
func (c SSHConnector) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 15 * time.Second
	}
	return c.Timeout
}

// dialAuth opens an SSH client to the target as username with the given auth
// method, applying the configured host-key callback (InsecureIgnoreHostKey by
// default).
func (c SSHConnector) dialAuth(target store.Target, username string, auth ssh.AuthMethod) (*ssh.Client, error) {
	cb := c.HostKeyCallback
	if cb == nil {
		cb = ssh.InsecureIgnoreHostKey() // #nosec G106 -- documented trust-any default; pin with PAM_SSH_KNOWN_HOSTS
	}
	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: cb,
		Timeout:         c.timeout(),
	}
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), cfg)
}

// dial opens an SSH client to the target as username using password auth.
func (c SSHConnector) dial(target store.Target, username, secret string) (*ssh.Client, error) {
	return c.dialAuth(target, username, ssh.Password(secret))
}

// authMethod picks public-key auth when secret is a PEM private key (an ssh_key
// credential) and password auth otherwise, so Verify works for both credential
// types instead of always presenting an ssh_key as a password.
func authMethod(secret string) (ssh.AuthMethod, error) {
	if strings.Contains(secret, "PRIVATE KEY") {
		signer, err := ssh.ParsePrivateKey([]byte(secret))
		if err != nil {
			return nil, fmt.Errorf("parse ssh key: %w", err)
		}
		return ssh.PublicKeys(signer), nil
	}
	return ssh.Password(secret), nil
}

// execGuard bounds a remote command by c.timeout() AND by the caller's context,
// closing the session to unblock a CombinedOutput that a wedged target would
// otherwise hang on forever. The returned func stops the guard and must be
// deferred.
//
// Both triggers matter, and only one of them used to work. The previous version
// derived a timeout context and closed the session only when ctx.Err() was
// DeadlineExceeded — so a *cancellation* did nothing. That is the case that
// matters most: the session supervisor kills a run by cancelling the context, and
// an `ssh_exec` killed from the console would return to the operator as
// terminated while the command kept running on the target. A kill that only
// stops you watching is not a kill.
//
// The reason cancellation was excluded is real, though: the returned stop func
// itself cancelled the derived context, so treating cancellation as a trigger
// would have closed the session on every NORMAL completion too. The fix is to
// separate the two signals rather than conflate them — a timer for the timeout,
// the caller's context for a kill, and a `done` channel that the stop func
// closes when the command finished on its own.
func (c SSHConnector) execGuard(ctx context.Context, sess io.Closer) func() {
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(c.timeout())
	done := make(chan struct{})
	go func() {
		defer timer.Stop()
		select {
		case <-timer.C:
			sess.Close() // wedged target: unblock the read
		case <-ctx.Done():
			sess.Close() // killed or client gone: stop the command on the target
		case <-done:
			// finished normally; leave the session to the caller's defer
		}
	}()
	return func() { close(done) }
}

// Verify dials the target and completes an SSH handshake with secret (a password
// or an ssh_key PEM); success means the credential still authenticates.
func (c SSHConnector) Verify(_ context.Context, target store.Target, username, secret string) error {
	auth, err := authMethod(secret)
	if err != nil {
		return err
	}
	client, err := c.dialAuth(target, username, auth)
	if err != nil {
		return fmt.Errorf("ssh auth failed: %w", err)
	}
	_ = client.Close()
	return nil
}

// Rotate connects with oldSecret and sets the password to newSecret via
// RotateCommand.
func (c SSHConnector) Rotate(ctx context.Context, target store.Target, username, oldSecret, newSecret string) error {
	if strings.ContainsAny(username, ":\n\r") {
		return fmt.Errorf("rotate: unsafe username")
	}
	client, err := c.dial(target, username, oldSecret)
	if err != nil {
		return fmt.Errorf("ssh auth failed: %w", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer sess.Close()
	defer c.execGuard(ctx, sess)()

	cmd := c.RotateCommand
	if cmd == "" {
		cmd = "chpasswd"
	}
	sess.Stdin = strings.NewReader(username + ":" + newSecret + "\n")
	if out, _, err := runLimited(sess, cmd); err != nil {
		return fmt.Errorf("rotate command failed: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// maxOutputBytes caps how much of a single remote command's combined output
// (stdout and stderr together) is kept in memory. Generous for real
// administrative output, small enough that a runaway command cannot exhaust the
// heap of the PAM host itself. It deliberately matches the WinRM connector's
// own cap (internal/winrm.MaxOutputBytes) so the two one-shot execution paths
// behave the same; the constant is duplicated rather than imported because
// rotate has no other reason to depend on the WinRM package.
const maxOutputBytes = 4 << 20 // 4 MiB

// truncationMarker is appended to output that hit the cap. It is written in the
// output itself, not merely reported alongside it, and that is the point:
// these transcripts are hash-chained into the audit trail and replayed from the
// console, so output that was silently cut short would read, forever after, as
// a complete record of what a command printed. Evidence that admits it is
// partial is worth much more than evidence that quietly lies about it.
const truncationMarker = "\n[pamv1: output truncated at 4 MiB]\n"

// limitedBuffer is an io.Writer (Go's "something you can write bytes to",
// roughly Python's file-like object) that collects at most max bytes and then
// throws the rest away, remembering that it did so. Compare bytes.Buffer, which
// grows without limit — that unbounded growth is exactly the problem this type
// exists to remove.
//
// It carries a mutex because a single limitedBuffer is wired to BOTH the remote
// stdout and the remote stderr of one session, and the SSH library copies those
// two streams from two separate goroutines (Go's lightweight threads). Without
// the lock those concurrent writes would be a data race.
type limitedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	max       int
	truncated bool
}

// Write appends p up to the buffer's byte cap and marks the buffer truncated
// once the cap is reached. It always reports the full len(p) as written, even
// for the bytes it dropped, so the SSH library's copy loop runs to completion:
// returning a short count would surface as an I/O error and turn a merely
// oversized command into a failed one. Dropping output is the intended
// outcome; failing the command is not.
func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) <= room {
			return b.buf.Write(p)
		}
		_, _ = b.buf.Write(p[:room])
	}
	b.truncated = true
	return len(p), nil
}

// String returns the collected output, with truncationMarker appended when
// anything was dropped. Output that fit under the cap comes back byte-for-byte
// unchanged, marker-free — the common case must not be altered.
func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.truncated {
		return b.buf.String() + truncationMarker
	}
	return b.buf.String()
}

// runLimited runs command on an already-opened SSH session and returns its
// combined stdout+stderr (capped at maxOutputBytes), whether that output was
// truncated, and the session error.
//
// It replaces golang.org/x/crypto/ssh's Session.CombinedOutput, which is
// otherwise identical but buffers the remote output with no bound at all — one
// `cat /var/log/huge` on a target would be copied wholesale into pam-server's
// heap. Every one-shot SSH execution in this package goes through here, so no
// individual caller has to remember the cap.
//
// The error contract is CombinedOutput's, unchanged: a non-zero remote exit
// comes back as an *ssh.ExitError for the caller to interpret, and it is the
// caller (see Exec) that decides that is a result rather than a failure.
func runLimited(sess *ssh.Session, command string) (string, bool, error) {
	buf := &limitedBuffer{max: maxOutputBytes}
	sess.Stdout = buf
	sess.Stderr = buf
	err := sess.Run(command)
	out := buf.String()
	buf.mu.Lock()
	truncated := buf.truncated
	buf.mu.Unlock()
	return out, truncated, err
}

// ExecResult is the outcome of a one-shot remote command.
//
// Truncated reports that the remote command printed more than maxOutputBytes
// and the surplus was dropped. The same fact is visible in Output (it ends with
// truncationMarker), but it is exposed as a field as well so a caller that
// wants to record or display "this output was cut" can test a boolean instead
// of substring-matching text inside output the remote command controls.
type ExecResult struct {
	ExitCode  int
	Output    string
	Truncated bool
}

// Exec dials the target as username with secret (an ssh_key PEM or a password),
// runs a single non-interactive command, and returns its combined output and
// exit code. It is the broker's ssh_exec primitive: one-shot, no PTY/shell,
// bounded by the connector timeout. A non-zero remote exit is a result, not a
// transport error; only dial/session failures return err.
//
// The output is also bounded in size: at most maxOutputBytes is kept, and a
// command that printed more comes back with Truncated set and the truncation
// marker at the end of Output. Truncation never turns a result into an error.
func (c SSHConnector) Exec(ctx context.Context, target store.Target, username, secret, command string) (ExecResult, error) {
	auth, err := authMethod(secret)
	if err != nil {
		return ExecResult{}, err
	}
	client, err := c.dialAuth(target, username, auth)
	if err != nil {
		return ExecResult{}, fmt.Errorf("ssh auth failed: %w", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return ExecResult{}, fmt.Errorf("ssh session: %w", err)
	}
	defer sess.Close()
	defer c.execGuard(ctx, sess)()

	out, truncated, err := runLimited(sess, command)
	res := ExecResult{Output: out, Truncated: truncated}
	if err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitStatus()
			return res, nil
		}
		return res, fmt.Errorf("ssh exec failed: %w", err)
	}
	return res, nil
}

// KeyRotator rotates an SSH **key** credential: it authenticates with the old
// private key and installs a freshly generated public key, so the old key stops
// working. Only the SSH connector implements it.
type KeyRotator interface {
	RotateKey(ctx context.Context, target store.Target, username, oldPrivPEM, newPrivPEM string) error
}

// RotateKey connects with the old private key and replaces the account's
// authorized_keys with the public key derived from newPrivPEM (the new private
// key is what the vault will store). The old key no longer authenticates.
func (c SSHConnector) RotateKey(ctx context.Context, target store.Target, username, oldPrivPEM, newPrivPEM string) error {
	oldSigner, err := ssh.ParsePrivateKey([]byte(oldPrivPEM))
	if err != nil {
		return fmt.Errorf("parse current ssh key: %w", err)
	}
	newSigner, err := ssh.ParsePrivateKey([]byte(newPrivPEM))
	if err != nil {
		return fmt.Errorf("parse new ssh key: %w", err)
	}
	authLine := ssh.MarshalAuthorizedKey(newSigner.PublicKey())                           // "ssh-ed25519 AAAA...\n"
	oldLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(oldSigner.PublicKey()))) // base64 blob only alphabet — shell-safe in single quotes

	client, err := c.dialAuth(target, username, ssh.PublicKeys(oldSigner))
	if err != nil {
		return fmt.Errorf("ssh auth failed: %w", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer sess.Close()
	defer c.execGuard(ctx, sess)()

	// Remove only the OLD PAM key line and append the new one from stdin, so any
	// other keys on the account (operator, emergency, automation) are preserved.
	sess.Stdin = strings.NewReader(string(authLine))
	cmd := fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && "+
		"{ grep -vF '%s' ~/.ssh/authorized_keys; cat; } > ~/.ssh/authorized_keys.pamnew && "+
		"mv ~/.ssh/authorized_keys.pamnew ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", oldLine)
	if out, _, err := runLimited(sess, cmd); err != nil {
		return fmt.Errorf("install authorized_keys failed: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// --- WinRM connector (Windows targets) ---

// WinRMConnector rotates and verifies password credentials over WinRM using a
// winrm.Runner. Rotation runs `net user <user> <newpass>`; the generated
// password is drawn from a shell-safe alphabet so it is safe on the cmd line.
type WinRMConnector struct {
	Runner winrm.Runner
}

// Verify runs a trivial command; a clean exit means the credential authenticates.
func (c WinRMConnector) Verify(ctx context.Context, target store.Target, username, secret string) error {
	res, err := c.Runner.Run(ctx, target.Host, target.Port, username, secret, "cmd /c ver")
	if err != nil {
		return fmt.Errorf("winrm auth failed: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("winrm verify exit %d", res.ExitCode)
	}
	return nil
}

// winrmSafeUsername is an ALLOWLIST for the account name, because `net user`
// takes it on a cmd.exe command line UNQUOTED. A blocklist was tried and was
// wrong: it caught space, quote, CR and LF but not `&`, `|`, `^`, `<`, `>`,
// `(`, `)` or `%`, and in cmd.exe `&` needs no surrounding space to chain a
// second command. A Windows account name legitimately needs letters, digits,
// and a handful of separators (DOMAIN\user, user@realm, service$) — nothing
// a shell can act on. Contrast SSHConnector.Rotate, which needs almost no
// screening because it feeds `user:pass` on stdin rather than a command line.
var winrmSafeUsername = regexp.MustCompile(`^[A-Za-z0-9._@\\$-]{1,104}$`)

// Rotate sets the account's password with `net user` (the account must be able
// to change its own password, or the connector account must be privileged).
func (c WinRMConnector) Rotate(ctx context.Context, target store.Target, username, oldSecret, newSecret string) error {
	if !winrmSafeUsername.MatchString(username) {
		return fmt.Errorf("rotate: unsafe username")
	}
	// /y auto-confirms net.exe's ">14 characters ... continue? (Y/N)" prompt,
	// which a 24-char generated password always triggers and which would otherwise
	// hang a non-interactive WinRM session.
	cmd := fmt.Sprintf("net user %s %s /y", username, newSecret)
	res, err := c.Runner.Run(ctx, target.Host, target.Port, username, oldSecret, cmd)
	if err != nil {
		return fmt.Errorf("winrm rotate failed: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("net user exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}
