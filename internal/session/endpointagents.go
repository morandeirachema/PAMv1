package session

import (
	"errors"
	"net"
	"sort"
	"sync"
	"time"
)

// ErrEndpointAgentOffline is returned by EndpointAgents.Dial when the target's
// agent is not connected to THIS replica right now.
var ErrEndpointAgentOffline = errors.New("endpoint agent is not connected")

// TunnelOpener is what a connected endpoint agent's link can do for the
// proxy: open one fresh byte stream that lands on the agent's configured
// local address (the endpoint's own sshd, typically). The proxy then runs its
// ordinary upstream SSH handshake over that stream — JIT credential injection,
// recording and every gate are exactly as for a directly dialed target.
type TunnelOpener interface {
	// OpenTunnel opens a new stream through the agent's connection.
	OpenTunnel() (net.Conn, error)
	// Close tears the agent's connection down (used when a newer connection
	// from the same agent supersedes it, and on revocation).
	Close() error
}

// EndpointAgentLink is the live view of one connected agent.
type EndpointAgentLink struct {
	AgentID   int64
	Name      string
	TargetID  int64
	Remote    string
	Connected time.Time
}

// EndpointAgents is the in-process registry of connected outbound-only
// endpoint agents (Phase 153), keyed by target: the proxy registers a link
// when an agent's reverse-forward request is accepted, dials through it when
// an operator connects to that target, and removes it when the agent's
// connection ends. The API layer reads it for live status. It is per-replica
// by design — an agent's TCP connection terminates on exactly one process —
// which is why cmd/pam-agent accepts a LIST of servers and holds one tunnel
// to each replica, so every replica can reach the endpoint. A nil
// *EndpointAgents is a safe no-op (the feature is disabled): Dial reports
// offline, Register closes the link it is handed.
type EndpointAgents struct {
	mu    sync.Mutex
	links map[int64]*endpointLink // by target ID
}

type endpointLink struct {
	EndpointAgentLink
	opener TunnelOpener
}

// NewEndpointAgents returns an empty registry.
func NewEndpointAgents() *EndpointAgents {
	return &EndpointAgents{links: make(map[int64]*endpointLink)}
}

// Register records a connected agent for its target and returns a release
// function the caller must invoke when that connection ends. If another link
// for the same target is already registered (an agent reconnecting after a
// network blip the server has not yet noticed, or a second install racing
// the first), the older link is closed and replaced: the newest connection
// is the one most likely to be alive. The release function only removes THIS
// registration, never a newer one that superseded it.
func (e *EndpointAgents) Register(link EndpointAgentLink, opener TunnelOpener) (release func()) {
	if e == nil {
		_ = opener.Close()
		return func() {}
	}
	l := &endpointLink{EndpointAgentLink: link, opener: opener}
	e.mu.Lock()
	if old, ok := e.links[link.TargetID]; ok {
		_ = old.opener.Close()
	}
	e.links[link.TargetID] = l
	e.mu.Unlock()
	return func() {
		e.mu.Lock()
		if cur, ok := e.links[link.TargetID]; ok && cur == l {
			delete(e.links, link.TargetID)
		}
		e.mu.Unlock()
	}
}

// Dial opens a stream to targetID through its connected agent, or
// ErrEndpointAgentOffline.
func (e *EndpointAgents) Dial(targetID int64) (net.Conn, error) {
	if e == nil {
		return nil, ErrEndpointAgentOffline
	}
	e.mu.Lock()
	l, ok := e.links[targetID]
	e.mu.Unlock()
	if !ok {
		return nil, ErrEndpointAgentOffline
	}
	return l.opener.OpenTunnel()
}

// Lookup returns the live link for a target, if any.
func (e *EndpointAgents) Lookup(targetID int64) (EndpointAgentLink, bool) {
	if e == nil {
		return EndpointAgentLink{}, false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	l, ok := e.links[targetID]
	if !ok {
		return EndpointAgentLink{}, false
	}
	return l.EndpointAgentLink, true
}

// List returns every connected link, ordered by agent ID.
func (e *EndpointAgents) List() []EndpointAgentLink {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	out := make([]EndpointAgentLink, 0, len(e.links))
	for _, l := range e.links {
		out = append(out, l.EndpointAgentLink)
	}
	e.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	return out
}

// Kick closes the live connection of agentID, if it is connected here (used
// on revocation so a revoked agent does not linger until it reconnects). It
// reports whether a link was found.
func (e *EndpointAgents) Kick(agentID int64) bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	var victim *endpointLink
	for tid, l := range e.links {
		if l.AgentID == agentID {
			victim = l
			delete(e.links, tid)
			break
		}
	}
	e.mu.Unlock()
	if victim == nil {
		return false
	}
	_ = victim.opener.Close()
	return true
}
