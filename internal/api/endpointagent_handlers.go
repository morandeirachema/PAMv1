package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/morandeirachema/pamv1/internal/probe"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// endpointAgentIn is the body of POST /api/endpoint-agents.
type endpointAgentIn struct {
	Name     string `json:"name"`
	TargetID int64  `json:"target_id"`
	// Kind is "tunnel" (default) or "probe" (Phase 266).
	Kind string `json:"kind"`
}

// endpointAgentOut is one row of GET /api/endpoint-agents: the durable record
// plus this replica's live view of the connection.
type endpointAgentOut struct {
	store.EndpointAgent
	TargetName     string     `json:"target_name"`
	Connected      bool       `json:"connected"`
	ConnectedSince *time.Time `json:"connected_since,omitempty"`
	Remote         string     `json:"remote,omitempty"`
	// Probes is how many operator sessions are running this probe agent right
	// now (Phase 266); 0 for a tunnel.
	Probes int `json:"probes,omitempty"`
}

// createEndpointAgent registers an outbound-only endpoint agent and returns
// its bearer key exactly once — only the SHA-256 hash is stored, the same
// shape as every other non-human key. A TUNNEL agent binds an SSH target
// (the tunnel carries the proxy's own upstream SSH handshake and nothing
// else), and from this moment that target is reached ONLY through it (see
// store.EndpointAgent), so an administrator creating one is making a routing
// decision, not adding an option: the response says so. A PROBE agent (Phase
// 266) binds the target whose operators' logon sessions it will report from
// — an RDP target, normally — and changes nothing about how the target is
// reached. One live agent per (target, kind).
func (s *Server) createEndpointAgent(w http.ResponseWriter, r *http.Request) {
	var in endpointAgentIn
	if !readJSON(w, r, &in) {
		return
	}
	if !checkName(w, "name", in.Name) {
		return
	}
	switch in.Kind {
	case "":
		in.Kind = store.EndpointAgentTunnel
	case store.EndpointAgentTunnel, store.EndpointAgentProbe:
	default:
		writeError(w, http.StatusUnprocessableEntity, `kind must be "tunnel" or "probe"`)
		return
	}
	target, err := s.store.GetTarget(r.Context(), in.TargetID)
	if err != nil {
		storeError(w, err)
		return
	}
	if in.Kind == store.EndpointAgentTunnel && target.Protocol != "ssh" {
		writeError(w, http.StatusUnprocessableEntity, "tunnel endpoint agents reach SSH targets only (v1)")
		return
	}
	if in.Kind == store.EndpointAgentProbe && s.probeHub == nil {
		writeError(w, http.StatusNotFound, "session probes are disabled")
		return
	}
	key, err := generateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	a := store.EndpointAgent{Name: in.Name, TargetID: target.ID, Kind: in.Kind, KeyHash: hashHex(key), CreatedBy: actorFrom(r.Context())}
	if err := s.store.CreateEndpointAgent(r.Context(), &a); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "this target already has an active endpoint agent of this kind (revoke it first)")
			return
		}
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "endpoint_agent.create", fmt.Sprintf("agent:%d name:%s target:%s kind:%s", a.ID, a.Name, target.Name, a.Kind))
	note := "Give this key to pam-agent on the endpoint (PAM_AGENT_KEY); only its hash is stored. " +
		"From now on this target is reached only through the agent — never dialed directly."
	if a.Kind == store.EndpointAgentProbe {
		note = "Give this key to pam-agent on the Windows server (PAM_AGENT_KEY, PAM_AGENT_MODE=probe), launched at logon inside each " +
			"operator's session with that user's own token; only its hash is stored. The probe reports and enforces within that session only."
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": a.ID, "name": a.Name, "target_id": a.TargetID, "target_name": target.Name, "kind": a.Kind, "key": key,
		"login": "endpoint-agent:" + a.Name,
		"note":  note,
	})
}

// listEndpointAgents returns every endpoint agent with this replica's live
// connection status (never a key hash).
func (s *Server) listEndpointAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.store.ListEndpointAgents(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	names := map[int64]string{}
	if targets, err := s.store.ListTargets(r.Context(), 0, 0); err == nil {
		for _, t := range targets {
			names[t.ID] = t.Name
		}
	}
	live := map[int64]session.EndpointAgentLink{}
	for _, l := range s.endpointAgents.List() {
		live[l.AgentID] = l
	}
	// A probe agent is "connected" while any operator session on its target
	// is running the probe; the count says how many.
	probes := map[int64][]probe.Status{}
	for _, st := range s.probeHub.List() {
		probes[st.AgentID] = append(probes[st.AgentID], st)
	}
	out := make([]endpointAgentOut, 0, len(agents))
	for _, a := range agents {
		row := endpointAgentOut{EndpointAgent: a, TargetName: names[a.TargetID]}
		if l, ok := live[a.ID]; ok {
			since := l.Connected
			row.Connected, row.ConnectedSince, row.Remote = true, &since, l.Remote
		}
		if ps := probes[a.ID]; len(ps) > 0 {
			oldest := ps[len(ps)-1]
			since := oldest.Connected
			row.Connected, row.ConnectedSince, row.Remote, row.Probes = true, &since, oldest.Remote, len(ps)
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, out)
}

// revokeEndpointAgent revokes an agent: its key stops authenticating, its live
// tunnel on this replica is dropped at once (not left to linger until the
// next reconnect), and the target reverts to being reachable only by a fresh
// agent — or directly, once no unrevoked agent row remains. Idempotent.
func (s *Server) revokeEndpointAgent(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.RevokeEndpointAgent(r.Context(), id, time.Now()); err != nil {
		storeError(w, err)
		return
	}
	kicked := s.endpointAgents.Kick(id)
	if n := s.probeHub.Kick(id); n > 0 {
		kicked = true
	}
	s.audit(r.Context(), "endpoint_agent.revoke", fmt.Sprintf("agent:%d kicked:%t", id, kicked))
	w.WriteHeader(http.StatusNoContent)
}
