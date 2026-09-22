package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auditfmt"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/probe"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// EndpointAgentLoginPrefix is the SSH username prefix an outbound-only endpoint
// agent (cmd/pam-agent, Phase 153) authenticates with: "endpoint-agent:<name>",
// password = the agent's bearer key. Like the "join:<token>" login form it
// carries a colon, which target names refuse (Phase 77), so it can never be
// mistaken for an operator's "creduser@target" login.
const EndpointAgentLoginPrefix = "endpoint-agent:"

// endpointAgentActor is the audit actor for events an agent connection itself
// produces (connect/disconnect/refusal) — never a human principal.
func endpointAgentActor(name string) string { return EndpointAgentLoginPrefix + name }

// authenticateEndpointAgent is the agent-class branch of authenticate: the
// login is "endpoint-agent:<name>" and the password is the agent's bearer key,
// looked up by SHA-256 hash (never compared in the clear — the digest is the
// database key, the same posture as user/agent/app/SCIM keys). It never calls
// the human resolver: an operator's key presented under this login form is
// refused, and an agent's key presented as an operator password resolves to
// nothing, so the two identity kinds cannot be swapped for one another. Every
// refusal is audited with its reason; the returned permissions carry only the
// agent's identity — no roles, no capabilities, no target name to parse.
func (p *Proxy) authenticateEndpointAgent(c ssh.ConnMetadata, name string, key []byte) (*ssh.Permissions, error) {
	ctx := context.Background()
	remote := c.RemoteAddr().String()
	refuse := func(reason string) (*ssh.Permissions, error) {
		p.log.Warn("endpoint agent authentication failed", "agent", auditField(name, 64), "remote", remote, "reason", reason)
		p.audit(ctx, endpointAgentActor(auditField(name, 64)), "endpoint_agent.auth_failed", "remote:"+remote+" reason:"+reason)
		return nil, fmt.Errorf("PAMv1: authentication failed")
	}
	if p.endpointAgents == nil {
		return refuse("disabled")
	}
	a, err := p.store.GetEndpointAgentByKeyHash(ctx, auth.TokenHash(string(key)))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return refuse("unknown-key")
		}
		p.log.Error("endpoint agent lookup failed", "err", err)
		return nil, fmt.Errorf("PAMv1: authentication failed")
	}
	if !a.Active() {
		return refuse("revoked")
	}
	if a.Name != name {
		return refuse("name-mismatch")
	}
	kind := a.Kind
	if kind == "" {
		kind = store.EndpointAgentTunnel
	}
	return &ssh.Permissions{Extensions: map[string]string{
		"login":                 c.User(),
		"endpoint_agent":        strconv.FormatInt(a.ID, 10),
		"endpoint_agent_name":   a.Name,
		"endpoint_agent_target": strconv.FormatInt(a.TargetID, 10),
		"endpoint_agent_kind":   kind,
	}}, nil
}

// tcpipForwardRequest is the RFC 4254 §7.1 "tcpip-forward" global-request
// payload: the address and port the client asks the server to listen on. Here
// the server never binds a socket — the "listener" is the registration in
// session.EndpointAgents — but the fields are echoed back on every channel the
// server later opens, because the client library matches incoming
// forwarded-tcpip channels against the address it asked for.
type tcpipForwardRequest struct {
	Addr string
	Port uint32
}

// forwardedTCPIPPayload is the RFC 4254 §7.2 "forwarded-tcpip" channel-open
// payload: which forward this stream belongs to, and who originated it.
type forwardedTCPIPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

// endpointTunnel is the session.TunnelOpener for one connected agent: every
// OpenTunnel opens a fresh forwarded-tcpip channel back through the agent's
// own SSH connection, which the agent answers by dialing its configured local
// address and piping bytes.
type endpointTunnel struct {
	conn *ssh.ServerConn
	addr string
	port uint32
}

// OpenTunnel opens one stream through the agent (see endpointTunnel).
func (t *endpointTunnel) OpenTunnel() (net.Conn, error) {
	// The originator fields are nominal — PAMv1 itself is the originator —
	// but the client library parses them as a real IP:port and refuses port
	// 0, so a valid placeholder is required.
	ch, reqs, err := t.conn.OpenChannel("forwarded-tcpip", ssh.Marshal(forwardedTCPIPPayload{
		Addr: t.addr, Port: t.port, OriginAddr: "127.0.0.1", OriginPort: 1,
	}))
	if err != nil {
		return nil, fmt.Errorf("open tunnel through endpoint agent: %w", err)
	}
	go ssh.DiscardRequests(reqs)
	return &channelConn{Channel: ch, local: t.conn.LocalAddr(), remote: t.conn.RemoteAddr()}, nil
}

// Close ends the agent's connection.
func (t *endpointTunnel) Close() error { return t.conn.Close() }

// channelConn adapts an ssh.Channel to net.Conn so dialUpstream can run the
// ordinary upstream SSH handshake over it. Deadlines are unsupported on an SSH
// channel (the same answer x/crypto's own tunneled conns give), which is why
// dialUpstream bounds the handshake with a watchdog rather than SetDeadline.
type channelConn struct {
	ssh.Channel
	local, remote net.Addr
}

// LocalAddr / RemoteAddr report the agent connection's addresses.
func (c *channelConn) LocalAddr() net.Addr  { return c.local }
func (c *channelConn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline and friends are not supported on an SSH channel.
func (c *channelConn) SetDeadline(time.Time) error {
	return errors.New("ssh channel: deadline not supported")
}
func (c *channelConn) SetReadDeadline(time.Time) error {
	return errors.New("ssh channel: deadline not supported")
}
func (c *channelConn) SetWriteDeadline(time.Time) error {
	return errors.New("ssh channel: deadline not supported")
}

// serveEndpointAgent runs an authenticated agent-class connection until it
// ends. An agent may open NO channels toward PAMv1 (every one is refused —
// its connection only ever carries streams PAMv1 opens toward it), and only
// four global requests mean anything: one "tcpip-forward" (a TUNNEL agent
// registers its link; a second is refused), "cancel-tcpip-forward"
// (unregisters it), one "probe@pamv1" (a PROBE agent announces its logon
// session and is handed the probe channel; Phase 266) and
// "keepalive@openssh.com". The agent row's kind decides which of the two
// registrations is admitted — the other is refused and audited, so a probe
// key can never become a target's dial and a tunnel key can never feed
// telemetry. Connect and disconnect are audited under the agent's own actor,
// and the store's last-seen stamp is refreshed at both.
func (p *Proxy) serveEndpointAgent(ctx context.Context, sconn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, agentID, targetID int64, name, kind, remote string) {
	actor := endpointAgentActor(name)
	go rejectAll(chans, ssh.Prohibited, "PAMv1: an endpoint agent may not open channels")
	if err := p.store.TouchEndpointAgent(ctx, agentID, time.Now()); err != nil {
		p.log.Warn("endpoint agent last-seen update failed", "agent", name, "err", err)
	}
	p.log.Info("endpoint agent connected", "agent", name, "target_id", targetID, "kind", kind, "remote", remote)

	var release func()
	registered := false
	probing := make(chan struct{}) // closed when the probe goroutine ends
	probeStarted := false
	for req := range reqs {
		switch req.Type {
		case probe.RequestType:
			if kind != store.EndpointAgentProbe || p.probeHub == nil || probeStarted || len(req.Payload) > probe.MaxHello {
				reason := "not-a-probe"
				switch {
				case p.probeHub == nil:
					reason = "disabled"
				case probeStarted:
					reason = "already-probing"
				case len(req.Payload) > probe.MaxHello:
					reason = "hello-too-large"
				}
				p.audit(ctx, actor, "probe.refused", fmt.Sprintf("agent:%d target:%d reason:%s", agentID, targetID, reason))
				_ = req.Reply(false, nil)
				continue
			}
			var hello probe.Hello
			if err := json.Unmarshal(req.Payload, &hello); err != nil {
				p.audit(ctx, actor, "probe.refused", fmt.Sprintf("agent:%d target:%d reason:malformed-hello", agentID, targetID))
				_ = req.Reply(false, nil)
				continue
			}
			target, err := p.store.GetTarget(ctx, targetID)
			if err != nil {
				p.log.Error("probe target lookup failed", "agent", name, "err", err)
				_ = req.Reply(false, nil)
				continue
			}
			probeStarted = true
			_ = req.Reply(true, nil)
			link := probe.Link{AgentID: agentID, AgentName: name, TargetID: targetID, TargetName: target.Name, Remote: remote, Hello: sanitizeHello(hello)}
			go func() {
				defer close(probing)
				p.serveProbe(ctx, sconn, link, actor)
			}()
		case "tcpip-forward":
			var fwd tcpipForwardRequest
			if err := ssh.Unmarshal(req.Payload, &fwd); err != nil || registered {
				_ = req.Reply(false, nil)
				continue
			}
			if kind != store.EndpointAgentTunnel {
				p.audit(ctx, actor, "endpoint_agent.refused", fmt.Sprintf("agent:%d target:%d reason:not-a-tunnel", agentID, targetID))
				_ = req.Reply(false, nil)
				continue
			}
			port := fwd.Port
			var replyPayload []byte
			if port == 0 {
				// The client asked us to pick; there is no real socket, so any
				// port number serves — it is only the key the client matches
				// forwarded-tcpip channels against.
				port = 1
				replyPayload = ssh.Marshal(struct{ Port uint32 }{port})
			}
			// Reply first, then register: the client only starts accepting
			// forwarded-tcpip channels for this address once it has our reply,
			// so a tunnel opened in between would be refused at its end. Until
			// the registration lands an operator simply sees "offline".
			_ = req.Reply(true, replyPayload)
			release = p.endpointAgents.Register(session.EndpointAgentLink{
				AgentID: agentID, Name: name, TargetID: targetID, Remote: remote, Connected: time.Now(),
			}, &endpointTunnel{conn: sconn, addr: fwd.Addr, port: port})
			registered = true
			p.audit(ctx, actor, "endpoint_agent.connected",
				fmt.Sprintf("agent:%d target:%d remote:%s", agentID, targetID, remote))
		case "cancel-tcpip-forward":
			if registered {
				release()
				registered = false
			}
			_ = req.Reply(true, nil)
		case "keepalive@openssh.com":
			_ = req.Reply(true, nil)
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
	if registered {
		release()
	}
	if probeStarted {
		<-probing
	}
	if err := p.store.TouchEndpointAgent(ctx, agentID, time.Now()); err != nil && !errors.Is(err, store.ErrNotFound) {
		p.log.Warn("endpoint agent last-seen update failed", "agent", name, "err", err)
	}
	p.log.Info("endpoint agent disconnected", "agent", name, "target_id", targetID, "remote", remote)
	p.auditClosing(ctx, actor, "endpoint_agent.disconnected",
		fmt.Sprintf("agent:%d target:%d remote:%s", agentID, targetID, remote))
}

// killRegistered ends a registered session through the registry (its kill
// closes the connection); a session with no registration is left to the
// caller's own refusal. Used by a kill restriction (Phase 275).
func (p *Proxy) killRegistered(sid string) {
	if sid != "" && p.sessions != nil {
		p.sessions.Kill(sid)
	}
}

// serveProbe opens the one pam-probe@pamv1 channel toward a probe agent and
// runs the hub's side of the protocol on it until it ends. Every enforcement
// the probe reports is audited under the agent's actor with the session it
// concerns; connect and disconnect bracket it. A refused open (the agent did
// not register the handler) or an unreadable policy is audited and the
// connection is dropped, so the agent retries with backoff.
func (p *Proxy) serveProbe(ctx context.Context, sconn *ssh.ServerConn, link probe.Link, actor string) {
	detail := fmt.Sprintf("agent:%d target:%s host:%s user:%s session:%d remote:%s",
		link.AgentID, link.TargetName, auditfmt.Value(link.Hello.Hostname, 64), auditfmt.Value(link.Hello.User, 128), link.Hello.SessionID, link.Remote)
	ch, reqs, err := sconn.OpenChannel(probe.ChannelType, nil)
	if err != nil {
		p.audit(ctx, actor, "probe.refused", fmt.Sprintf("agent:%d target:%s reason:channel-refused", link.AgentID, link.TargetName))
		sconn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	p.audit(ctx, actor, "probe.connected", detail)
	p.log.Info("session probe connected", "agent", link.AgentName, "target", link.TargetName, "user", link.Hello.User, "session", link.Hello.SessionID)
	err = p.probeHub.Serve(ctx, link, ch, func(action, d string) { p.audit(ctx, actor, action, d) })
	if err != nil {
		p.log.Warn("session probe ended", "agent", link.AgentName, "err", err)
		p.audit(ctx, actor, "probe.error", fmt.Sprintf("agent:%d target:%s error:%s", link.AgentID, link.TargetName, auditField(err.Error(), 128)))
		sconn.Close()
	}
	p.auditClosing(ctx, actor, "probe.disconnected", detail)
}

// sanitizeHello bounds the free-text fields a probe declares about itself
// before they reach the API or the hub (which quotes them again for the
// audit trail); they stay literal here because the user is matched against
// a credential's username.
func sanitizeHello(h probe.Hello) probe.Hello {
	h.Hostname = probe.Clean(h.Hostname, 64)
	h.OS = probe.Clean(h.OS, 16)
	h.User = probe.Clean(h.User, 128)
	h.Version = probe.Clean(h.Version, 32)
	return h
}

// endpointAgentFor reports the unrevoked endpoint agent bound to target, or nil
// when the target is dialed directly. A store error other than not-found is
// returned so the caller fails closed rather than silently dialing direct.
func (p *Proxy) endpointAgentFor(ctx context.Context, targetID int64) (*store.EndpointAgent, error) {
	a, err := p.store.GetEndpointAgentForTarget(ctx, targetID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return a, err
}

// endpointAgentLogin splits an "endpoint-agent:<name>" SSH login into its
// name; ok is false for every other login form.
func endpointAgentLogin(login string) (name string, ok bool) {
	name, ok = strings.CutPrefix(login, EndpointAgentLoginPrefix)
	return name, ok && name != ""
}
