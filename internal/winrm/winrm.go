// Package winrm runs commands on Windows targets over WinRM (WS-Management),
// with the credential injected just-in-time by the caller. The Runner interface
// is the seam tests inject a fake through; Client is the real implementation.
package winrm

import (
	"bytes"
	"context"
	"time"

	mw "github.com/masterzen/winrm"
)

// Result is the outcome of a remote command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Runner executes a command on a Windows host over WinRM.
type Runner interface {
	Run(ctx context.Context, host string, port int, user, password, command string) (Result, error)
}

// Client is the real WinRM runner (masterzen/winrm). Use HTTPS in production;
// Insecure skips TLS verification (dev only). NTLM selects NTLMv2 transport,
// which most AD-joined hosts require (basic auth is often disabled).
type Client struct {
	HTTPS    bool
	Insecure bool
	NTLM     bool
	Timeout  time.Duration
}

// Run executes command on host:port over WinRM as user/password and returns the
// captured output. A non-zero remote exit is reported in Result.ExitCode; the
// returned error signals only transport or authentication failures.
func (c Client) Run(ctx context.Context, host string, port int, user, password, command string) (Result, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	endpoint := mw.NewEndpoint(host, port, c.HTTPS, c.Insecure, nil, nil, nil, timeout)
	client, err := c.newClient(endpoint, user, password)
	if err != nil {
		return Result{}, err
	}
	// Capped. A run's output is attacker-influenced — `type C:\big.iso`, or
	// Get-Content on a large log — and it was collected into unbounded buffers and
	// then copied several times more on the way into the transcript, the hash and
	// the JSON response. A connect-capable operator, or a broker agent, could take
	// the process to an OOM and every live session with it.
	stdout := &limitedBuffer{max: MaxOutputBytes}
	stderr := &limitedBuffer{max: MaxOutputBytes}
	// A non-zero exit code is returned without an error; err is only for
	// transport/auth failures.
	code, err := client.RunWithContext(ctx, command, stdout, stderr)
	if err != nil {
		return Result{}, err
	}
	return Result{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: code}, nil
}

// newClient builds a masterzen/winrm client, selecting the NTLMv2 transport when
// NTLM is set via per-call parameters so the library's shared defaults are never
// mutated.
func (c Client) newClient(endpoint *mw.Endpoint, user, password string) (*mw.Client, error) {
	if !c.NTLM {
		return mw.NewClient(endpoint, user, password)
	}
	params := mw.NewParameters("PT60S", "en-US", 153600)
	params.TransportDecorator = func() mw.Transporter { return &mw.ClientNTLM{} }
	return mw.NewClientWithParameters(endpoint, user, password, params)
}

// MaxOutputBytes caps how much of a single WinRM run's stdout or stderr is kept.
// Generous for real administrative output, small enough that a runaway command
// cannot exhaust the heap.
const MaxOutputBytes = 4 << 20 // 4 MiB

// limitedBuffer collects up to max bytes and then records that it truncated,
// discarding the rest rather than growing. The marker matters: a truncated
// transcript that looks complete is worse evidence than one that says so.
type limitedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

// Write appends p up to the buffer's byte cap, marking the buffer truncated
// once the cap is reached. It always reports the full len(p) as written so the
// caller's copy loop runs to completion — the excess is dropped, not an error,
// because a transcript that says it was truncated is better evidence than a
// stalled command.
func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) <= room {
			return b.buf.Write(p)
		}
		_, _ = b.buf.Write(p[:room])
	}
	b.truncated = true
	// Report the full length: the caller wrote it, we simply did not keep it, and
	// returning short would look like an IO error to the WinRM library.
	return len(p), nil
}

// String returns the collected output, with a marker when it was truncated.
func (b *limitedBuffer) String() string {
	if b.truncated {
		return b.buf.String() + "\r\n[pamv1: output truncated at 4 MiB]\r\n"
	}
	return b.buf.String()
}
