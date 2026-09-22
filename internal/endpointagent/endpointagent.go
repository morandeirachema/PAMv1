// Package endpointagent is the OUTBOUND-ONLY connectivity agent that runs on a
// target endpoint PAMv1 cannot dial into — a NAT'd branch box, a CGNAT'd
// contractor laptop, an unattended host behind a firewall that admits nothing
// inbound (Phase 153, BeyondTrust "Jump Client"-style; the binary is
// cmd/pam-agent). It inverts PAMv1's usual direction for that one endpoint:
// the agent dials OUT to pam-server's SSH listener as "endpoint-agent:<name>"
// with its bearer key, asks for a reverse forward (RFC 4254 §7, the real
// `ssh -R` mechanism, which golang.org/x/crypto/ssh already implements
// client-side as (*Client).Listen), and from then on every stream pam-server
// opens back through that connection is piped to ONE local address the agent
// itself is configured with — normally the endpoint's own sshd on
// 127.0.0.1:22. The proxy runs its ordinary upstream SSH handshake over that
// stream, so JIT credential injection, recording, live monitoring and every
// admission gate are exactly as for a directly dialed target.
//
// Security posture, in the order it matters:
//   - The agent is the authority on what it exposes. pam-server never tells it
//     where to dial; it can only open a stream that lands on the configured
//     LocalAddr. A compromised pam-server therefore cannot use an agent as a
//     pivot into the endpoint's network.
//   - The agent opens NO channels toward pam-server and requests nothing but
//     the one forward and keepalives; the server refuses anything else.
//   - The server's SSH host key is verified (Config.HostKey is required — a
//     wrong or missing key refuses to run rather than trust-on-first-use), so a
//     network attacker cannot impersonate pam-server to harvest the agent key.
//   - Nothing about the credential the operator will use ever reaches the
//     agent: the tunnel carries the proxy's own SSH client handshake to the
//     local sshd, and the secret is inside that encrypted handshake.
//
// The agent holds one tunnel per configured server address: an HA pam-server
// deployment lists every replica, since an agent's TCP connection terminates
// on exactly one process and each replica must be able to reach the endpoint.
//
// Probe mode (Phase 266, Config.Mode = ModeProbe) keeps everything above —
// the same login, the same pinned host key, the same "opens nothing toward
// PAMv1" — and replaces the reverse forward with the session probe of
// internal/probe: instead of a tunnel the connection carries one channel
// pam-server opens toward the agent, on which the agent reports the
// processes and connections of the Windows logon session it runs in and
// enforces the block rules pam-server pushes. A probe registers no tunnel, so
// it never becomes a target's dial; the server refuses the other request
// either way, by the agent row's kind.
package endpointagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/probe"
)

// LoginPrefix mirrors proxy.EndpointAgentLoginPrefix: the SSH username an
// agent authenticates with is LoginPrefix + Name.
const LoginPrefix = "endpoint-agent:"

// The two agent modes.
const (
	ModeTunnel = "tunnel"
	ModeProbe  = "probe"
)

// Config configures Run.
type Config struct {
	// Mode is ModeTunnel (the default: hold a reverse tunnel to LocalAddr) or
	// ModeProbe (run the session probe; LocalAddr is unused).
	Mode string
	// Probe configures probe mode: the Platform is required there (main
	// resolves it with probe.NewPlatform), Interval defaults inside probe.
	Probe probe.Options
	// ProbePlatform is the OS seam the probe reports and enforces through.
	ProbePlatform probe.Platform
	// Version is reported in the probe's Hello (informational).
	Version string
	// Servers are pam-server SSH listener addresses (host:port), one tunnel
	// each. At least one is required.
	Servers []string
	// Name is the agent's registered name; the SSH login is "endpoint-agent:<Name>".
	Name string
	// Key is the agent's bearer key (returned once when the agent was created).
	Key string
	// LocalAddr is the ONE address every tunneled stream is delivered to,
	// e.g. "127.0.0.1:22". Required.
	LocalAddr string
	// HostKey verifies pam-server's SSH host key. Required — see FixedHostKey.
	HostKey ssh.HostKeyCallback
	// Logger receives operational logs; nil discards them.
	Logger *slog.Logger
	// DialTimeout bounds each connect + handshake (default 15s).
	DialTimeout time.Duration
	// KeepAlive is the interval between keepalive@openssh.com requests that
	// detect a silently dropped connection (default 30s).
	KeepAlive time.Duration
	// MinBackoff/MaxBackoff bound the reconnect delay (default 1s / 60s).
	MinBackoff, MaxBackoff time.Duration
	// OnTunnel, if set, is called each time a tunnel is (re)established with a
	// server — tests wait on it; production leaves it nil.
	OnTunnel func(server string)
}

// FixedHostKey parses an authorized_keys-format public key line (what
// `ssh-keyscan -p 2222 pam-host` prints, minus the host column) into a
// callback that accepts exactly that key. This is how PAM_AGENT_SERVER_HOST_KEY
// is consumed.
func FixedHostKey(line string) (ssh.HostKeyCallback, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(line)))
	if err != nil {
		return nil, fmt.Errorf("parse server host key: %w", err)
	}
	return ssh.FixedHostKey(pub), nil
}

// validate applies defaults and refuses an unusable configuration.
func (c *Config) validate() error {
	if len(c.Servers) == 0 {
		return errors.New("endpoint agent: at least one server address is required")
	}
	for _, s := range c.Servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			return fmt.Errorf("endpoint agent: server %q must be host:port: %w", s, err)
		}
	}
	if c.Name == "" || strings.ContainsAny(c.Name, ":\r\n") {
		return errors.New("endpoint agent: a name without ':' is required")
	}
	if c.Key == "" {
		return errors.New("endpoint agent: key is required")
	}
	switch c.Mode {
	case "":
		c.Mode = ModeTunnel
	case ModeTunnel, ModeProbe:
	default:
		return fmt.Errorf("endpoint agent: mode %q must be %q or %q", c.Mode, ModeTunnel, ModeProbe)
	}
	if c.Mode == ModeProbe {
		if c.ProbePlatform == nil {
			return errors.New("endpoint agent: probe mode needs a platform (" + probe.ErrUnsupported.Error() + ")")
		}
	} else if _, _, err := net.SplitHostPort(c.LocalAddr); err != nil {
		return fmt.Errorf("endpoint agent: local address %q must be host:port: %w", c.LocalAddr, err)
	}
	if c.HostKey == nil {
		return errors.New("endpoint agent: server host key verification is required")
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 15 * time.Second
	}
	if c.KeepAlive <= 0 {
		c.KeepAlive = 30 * time.Second
	}
	if c.MinBackoff <= 0 {
		c.MinBackoff = time.Second
	}
	if c.MaxBackoff < c.MinBackoff {
		c.MaxBackoff = 60 * time.Second
	}
	return nil
}

// Run keeps one tunnel to every configured server open until ctx is done,
// reconnecting with exponential backoff after any failure. It returns only
// when ctx is cancelled (or the configuration is invalid).
func Run(ctx context.Context, cfg Config) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	var wg sync.WaitGroup
	for _, server := range cfg.Servers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			runOne(ctx, cfg, server)
		}(server)
	}
	wg.Wait()
	return ctx.Err()
}

// runOne is the reconnect loop for a single server.
func runOne(ctx context.Context, cfg Config, server string) {
	log := cfg.Logger.With("server", server, "agent", cfg.Name)
	backoff := cfg.MinBackoff
	for {
		if ctx.Err() != nil {
			return
		}
		established, err := serveTunnel(ctx, cfg, server, log)
		if ctx.Err() != nil {
			return
		}
		// A tunnel that was fully established is not a failing one: the next
		// delay restarts from the minimum instead of continuing an exponential
		// run-up left over from an earlier outage.
		if established {
			backoff = cfg.MinBackoff
		}
		if err != nil {
			log.Warn("tunnel ended", "err", err, "retry_in", backoff)
		} else {
			log.Info("tunnel ended; reconnecting", "retry_in", backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > cfg.MaxBackoff {
			backoff = cfg.MaxBackoff
		}
	}
}

// serveTunnel dials one server, authenticates, requests the reverse forward
// and serves tunneled streams until the connection ends. established reports
// whether the forward was accepted at all; err explains why the tunnel ended
// (nil for a clean server-side close).
func serveTunnel(ctx context.Context, cfg Config, server string, log *slog.Logger) (established bool, err error) {
	dialer := net.Dialer{Timeout: cfg.DialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return false, fmt.Errorf("dial: %w", err)
	}
	// Bound the handshake the way the proxy bounds its own upstream dials: a
	// server that accepts TCP and then says nothing must not park us forever.
	_ = raw.SetDeadline(time.Now().Add(cfg.DialTimeout))
	sconn, chans, reqs, err := ssh.NewClientConn(raw, server, &ssh.ClientConfig{
		User:            LoginPrefix + cfg.Name,
		Auth:            []ssh.AuthMethod{ssh.Password(cfg.Key)},
		HostKeyCallback: cfg.HostKey,
		Timeout:         cfg.DialTimeout,
	})
	if err != nil {
		raw.Close()
		return false, fmt.Errorf("handshake: %w", err)
	}
	_ = raw.SetDeadline(time.Time{})
	client := ssh.NewClient(sconn, chans, reqs)
	defer client.Close()

	if cfg.Mode == ModeProbe {
		return serveProbe(ctx, client, cfg, server, log)
	}

	// The reverse forward. The address is only a label the server echoes back
	// on each channel; port 0 lets the server assign the (equally nominal)
	// port. What the streams actually reach is decided HERE, by LocalAddr.
	ln, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false, fmt.Errorf("reverse forward refused: %w", err)
	}
	defer ln.Close()
	log.Info("tunnel established", "local", cfg.LocalAddr)
	if cfg.OnTunnel != nil {
		cfg.OnTunnel(server)
	}

	stop := keepalive(ctx, client, cfg, log)
	defer stop()

	var streams sync.WaitGroup
	defer streams.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) {
				return true, nil
			}
			return true, fmt.Errorf("accept: %w", err)
		}
		streams.Add(1)
		go func() {
			defer streams.Done()
			pipe(cfg, conn, log)
		}()
	}
}

// keepalive starts the keepalive@openssh.com ticker that detects a connection
// which died without a FIN (NAT timeouts, pulled cables): a failed request
// closes the client, which ends whatever the caller is blocked on. It also
// closes the client when ctx ends. The returned stop ends the ticker.
func keepalive(ctx context.Context, client *ssh.Client, cfg Config, log *slog.Logger) (stop func()) {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(cfg.KeepAlive)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				client.Close()
				return
			case <-t.C:
				if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
					log.Warn("keepalive failed; dropping connection", "err", err)
					client.Close()
					return
				}
			}
		}
	}()
	return func() { close(done) }
}

// serveProbe is probe mode's half of serveTunnel: announce the session with
// one probe@pamv1 request, accept the one pam-probe@pamv1 channel the server
// opens back, and run the probe on it until the channel or connection ends.
// The channel handler is registered BEFORE the request so the server's open
// cannot race ahead of it and be refused.
func serveProbe(ctx context.Context, client *ssh.Client, cfg Config, server string, log *slog.Logger) (established bool, err error) {
	opens := client.HandleChannelOpen(probe.ChannelType)
	if opens == nil {
		return false, errors.New("probe channel handler already registered")
	}
	hello, err := cfg.ProbePlatform.Identity()
	if err != nil {
		return false, fmt.Errorf("probe identity: %w", err)
	}
	hello.Version = cfg.Version
	payload, err := json.Marshal(hello)
	if err != nil {
		return false, err
	}
	ok, _, err := client.SendRequest(probe.RequestType, true, payload)
	if err != nil {
		return false, fmt.Errorf("probe request: %w", err)
	}
	if !ok {
		return false, errors.New("probe refused by server (is the agent registered as a probe?)")
	}
	stop := keepalive(ctx, client, cfg, log)
	defer stop()
	var nc ssh.NewChannel
	select {
	case nc = <-opens:
		if nc == nil {
			return false, errors.New("connection ended before the probe channel opened")
		}
	case <-ctx.Done():
		return false, ctx.Err()
	case <-time.After(cfg.DialTimeout):
		return false, errors.New("server accepted the probe but opened no channel")
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return false, fmt.Errorf("accept probe channel: %w", err)
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)
	// Any further opens (a second channel) are refused: one probe, one channel.
	go func() {
		for extra := range opens {
			_ = extra.Reject(ssh.Prohibited, "one probe channel per connection")
		}
	}()
	log.Info("probe established", "host", hello.Hostname, "user", hello.User, "session", hello.SessionID)
	if cfg.OnTunnel != nil {
		cfg.OnTunnel(server)
	}
	opts := cfg.Probe
	opts.Logger = log
	if err := probe.Serve(ctx, ch, cfg.ProbePlatform, opts); err != nil && ctx.Err() == nil {
		return true, fmt.Errorf("probe: %w", err)
	}
	return true, nil
}

// pipe delivers one tunneled stream to LocalAddr and copies bytes both ways
// until either side closes.
func pipe(cfg Config, tunnel net.Conn, log *slog.Logger) {
	defer tunnel.Close()
	local, err := net.DialTimeout("tcp", cfg.LocalAddr, cfg.DialTimeout)
	if err != nil {
		log.Warn("local dial failed", "local", cfg.LocalAddr, "err", err)
		return
	}
	defer local.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(local, tunnel); done <- struct{}{} }()
	go func() { _, _ = io.Copy(tunnel, local); done <- struct{}{} }()
	<-done
	// Closing both (deferred) unblocks the other copy.
}
