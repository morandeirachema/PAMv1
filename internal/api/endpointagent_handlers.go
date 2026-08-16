package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// endpointAgentIn is the body of POST /api/endpoint-agents.
type endpointAgentIn struct {
	Name     string `json:"name"`
	TargetID int64  `json:"target_id"`
}

// endpointAgentOut is one row of GET /api/endpoint-agents: the durable record
// plus this replica's live view of the connection.
type endpointAgentOut struct {
	store.EndpointAgent
	TargetName     string     `json:"target_name"`
	Connected      bool       `json:"connected"`
	ConnectedSince *time.Time `json:"connected_since,omitempty"`
	Remote         string     `json:"remote,omitempty"`
}

// createEndpointAgent registers an outbound-only endpoint agent for an SSH
// target and returns its bearer key exactly once — only the SHA-256 hash is
// stored, the same shape as every other non-human key. From this moment the
// target is reached ONLY through the agent (see store.EndpointAgent), so an
// administrator creating one is making a routing decision, not adding an
// option: the response says so. SSH targets only in v1 — the tunnel carries
// the proxy's own upstream SSH handshake and nothing else yet.
func (s *Server) createEndpointAgent(w http.ResponseWriter, r *http.Request) {
	var in endpointAgentIn
	if !readJSON(w, r, &in) {
		return
	}
	if !checkName(w, "name", in.Name) {
		return
	}
	target, err := s.store.GetTarget(r.Context(), in.TargetID)
	if err != nil {
		storeError(w, err)
		return
	}
	if target.Protocol != "ssh" {
		writeError(w, http.StatusUnprocessableEntity, "endpoint agents reach SSH targets only (v1)")
		return
	}
	key, err := generateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	a := store.EndpointAgent{Name: in.Name, TargetID: target.ID, KeyHash: hashHex(key), CreatedBy: actorFrom(r.Context())}
	if err := s.store.CreateEndpointAgent(r.Context(), &a); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "this target already has an active endpoint agent (revoke it first)")
			return
		}
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "endpoint_agent.create", fmt.Sprintf("agent:%d name:%s target:%s", a.ID, a.Name, target.Name))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": a.ID, "name": a.Name, "target_id": a.TargetID, "target_name": target.Name, "key": key,
		"login": "endpoint-agent:" + a.Name,
		"note": "Give this key to pam-agent on the endpoint (PAM_AGENT_KEY); only its hash is stored. " +
			"From now on this target is reached only through the agent — never dialed directly.",
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
	out := make([]endpointAgentOut, 0, len(agents))
	for _, a := range agents {
		row := endpointAgentOut{EndpointAgent: a, TargetName: names[a.TargetID]}
		if l, ok := live[a.ID]; ok {
			since := l.Connected
			row.Connected, row.ConnectedSince, row.Remote = true, &since, l.Remote
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
	s.audit(r.Context(), "endpoint_agent.revoke", fmt.Sprintf("agent:%d kicked:%t", id, kicked))
	w.WriteHeader(http.StatusNoContent)
}
