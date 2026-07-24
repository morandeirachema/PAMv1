package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/store"
)

// maxToolCallBytes bounds a tool-call request body.
const maxToolCallBytes = 64 << 10

// agentHandler is an HTTP handler that has already resolved the agent identity.
type agentHandler func(w http.ResponseWriter, r *http.Request, id *agentid.Identity)

// agentAuth authenticates an agent bearer credential (static key or, later, an
// SVID) and invokes next with the verified identity, or returns 401.
func (s *Server) agentAuth(next agentHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := s.agentVerifier.Verify(r.Context(), bearerToken(r))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or missing agent credential")
			return
		}
		// Per-agent rate limit (keyed by agent name) bounds tool-call volume.
		if s.brokerLimiter != nil && !s.brokerLimiter.Allow(id.AgentName) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "agent rate limit exceeded; try again shortly")
			return
		}
		// Put the agent principal in the request context so reused helpers (e.g.
		// execWinRM's s.audit) attribute the sensitive action to the agent, not the
		// "unknown" fallback, and the access log records the agent.
		r = r.WithContext(withPrincipal(r.Context(), id.Principal()))
		setActor(r.Context(), id.AgentName)
		next(w, r, id)
	}
}

// bearerToken extracts a Bearer token from the Authorization header.
func bearerToken(r *http.Request) string {
	const p = "Bearer "
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

type toolCallIn struct {
	SessionID string         `json:"session_id"`
	Tool      string         `json:"tool"`
	Args      map[string]any `json:"args"`
}

// processToolCall runs an agent tool call through the broker's policy loop. It
// always returns HTTP 200: the decision is in the body's status field (per the
// broker contract, transport failures are the only non-200 responses).
func (s *Server) processToolCall(w http.ResponseWriter, r *http.Request, id *agentid.Identity) {
	r.Body = http.MaxBytesReader(w, r.Body, maxToolCallBytes)
	var in toolCallIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Tool == "" {
		writeError(w, http.StatusUnprocessableEntity, "tool is required")
		return
	}
	out := s.broker.ProcessCall(r.Context(), id, broker.Call{SessionID: in.SessionID, Tool: in.Tool, Args: in.Args})
	// Surface broker activity in the unified audit trail too; the hash chain
	// remains the authoritative, verifiable record.
	s.auditAs(r.Context(), id.AgentName, "broker.tool_call",
		fmt.Sprintf("tool:%s status:%s call:%s", in.Tool, out.Status, out.CallID))
	writeJSON(w, http.StatusOK, out)
}

// getToolCall returns the status of a call id. It is a poll for the outcome's
// state (pending → executed/denied/failed) and deliberately never returns the
// result body: a result is delivered exactly once — in the original call
// response, or via the single-use resume token — so a secret-bearing
// reveal_credential result can't be re-read by polling this endpoint.
func (s *Server) getToolCall(w http.ResponseWriter, r *http.Request, _ *agentid.Identity) {
	out, ok := s.broker.Lookup(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown call id")
		return
	}
	out.Result = nil
	out.ResumeToken = "" // never re-serve the single-use token on the status poll
	writeJSON(w, http.StatusOK, out)
}

type resumeIn struct {
	Token string `json:"token"`
}

// resumeToolCall spends the single-use resume token and returns the parked call's
// post-approval outcome exactly once. The token is the ticket; the path id must
// match the call it unlocks.
func (s *Server) resumeToolCall(w http.ResponseWriter, r *http.Request, id *agentid.Identity) {
	var in resumeIn
	if !readJSON(w, r, &in) {
		return
	}
	out, ok := s.broker.Resume(r.Context(), in.Token)
	if !ok || out.CallID != r.PathValue("id") {
		writeError(w, http.StatusNotFound, "invalid, expired, or already-used resume token")
		return
	}
	s.auditAs(r.Context(), id.AgentName, "broker.tool_call.resumed",
		fmt.Sprintf("call:%s status:%s", out.CallID, out.Status))
	writeJSON(w, http.StatusOK, out)
}

// listBrokerApprovals returns the tool calls parked awaiting a human decision.
func (s *Server) listBrokerApprovals(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.broker.PendingApprovals())
}

type decisionIn struct {
	Approve bool `json:"approve"`
}

// decideBrokerApproval records an approver's decision on a parked tool call. On
// approve the broker executes the call server-side (JIT) and returns the result;
// on reject it becomes denied. Separation of duties (Phase 27): the decider must
// belong to one of the rule's approver groups (or be an admin), else 403.
func (s *Server) decideBrokerApproval(w http.ResponseWriter, r *http.Request) {
	var in decisionIn
	if !readJSON(w, r, &in) {
		return
	}
	p := principalFrom(r.Context())
	approver := actorFrom(r.Context())
	// Four-eyes: the human who owns the agent may not approve their own agent's
	// call (mirrors the human access-request self-approval refusal).
	if owner, ok := s.broker.ApprovalOwner(r.PathValue("id")); ok && owner != "" && strings.EqualFold(owner, approver) {
		writeError(w, http.StatusForbidden, "cannot approve a call for an agent you own (four-eyes)")
		return
	}
	out, ok, err := s.broker.Decide(r.Context(), r.PathValue("id"),
		broker.Approver{Name: approver, Groups: p.ApproverGroups(), IsAdmin: p.IsAdmin()}, in.Approve)
	if errors.Is(err, broker.ErrNotApprover) {
		s.audit(r.Context(), "broker.approval.refused", fmt.Sprintf("call:%s reason:not-in-approver-group", r.PathValue("id")))
		writeError(w, http.StatusForbidden, "you are not a member of this call's approver group (separation of duties)")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "unknown or already-decided approval")
		return
	}
	s.audit(r.Context(), "broker.approval."+map[bool]string{true: "granted", false: "denied"}[in.Approve],
		fmt.Sprintf("call:%s status:%s", out.CallID, out.Status))
	writeJSON(w, http.StatusOK, out)
}

type agentKeyIn struct {
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

// createAgentKey mints a new agent identity key for an admin; the token is shown
// once and only its SHA-256 hash is stored.
func (s *Server) createAgentKey(w http.ResponseWriter, r *http.Request) {
	var in agentKeyIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	token, err := generateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	k := store.AgentKey{Name: in.Name, Owner: in.Owner, TokenHash: hashHex(token)}
	if err := s.store.CreateAgentKey(r.Context(), &k); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "agent.create", fmt.Sprintf("%s owner:%s", k.Name, k.Owner))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": k.ID, "name": k.Name, "owner": k.Owner, "token": token,
		"note": "Give this token to the agent; only its hash is stored.",
	})
}

// listAgentKeys returns the registered agent identities (never their token hash).
func (s *Server) listAgentKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListAgentKeys(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

// deleteAgentKey revokes an agent identity so its bearer token stops resolving.
func (s *Server) deleteAgentKey(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteAgentKey(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "agent.revoke", fmt.Sprintf("agent:%d", id))
	w.WriteHeader(http.StatusNoContent)
}

// listBrokerAudit returns recent broker audit events (oldest-first, chain order).
func (s *Server) listBrokerAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil {
			limit = n
		}
	}
	// Clamp so the HTTP listing can't request the entire chain in one response
	// (limit<=0 makes the store return everything); chain verification has its own
	// endpoints (/v1/audit/verify, /v1/audit/head).
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	events, err := s.store.ListBrokerAudit(r.Context(), limit)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// verifyBrokerAudit walks the broker audit chain and reports whether it is intact:
// the HMAC chain reproduces, every in-chain signed checkpoint verifies against a
// trusted key, and — when ?min_entries=N is supplied (from a previously archived
// checkpoint count) — the chain has not been tail-truncated below that floor.
func (s *Server) verifyBrokerAudit(w http.ResponseWriter, r *http.Request) {
	var minEntries int64
	if q := r.URL.Query().Get("min_entries"); q != "" {
		n, err := strconv.ParseInt(q, 10, 64)
		if err != nil || n < 0 {
			writeError(w, http.StatusUnprocessableEntity, "min_entries must be a non-negative integer")
			return
		}
		minEntries = n
	}
	res, err := s.auditChain.VerifyFloor(r.Context(), minEntries)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// brokerAuditJWKS publishes the ed25519 public keys trusted to sign audit
// checkpoints (current + rotated-out predecessors) as a JWKS, so an external
// auditor can verify an archived checkpoint's signature across a signing-key
// rotation. Requires CapReadAudit.
func (s *Server) brokerAuditJWKS(w http.ResponseWriter, r *http.Request) {
	keys := s.auditChain.TrustedKeys()
	jwks := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		jwks = append(jwks, map[string]any{
			"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
			"kid": auditchain.KeyID(k),
			"x":   base64.RawURLEncoding.EncodeToString(k),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": jwks})
}

// brokerAuditHead returns a signed checkpoint anchoring the chain, for offline
// truncation detection.
func (s *Server) brokerAuditHead(w http.ResponseWriter, r *http.Request) {
	cp, err := s.auditChain.Head(r.Context(), time.Now())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cp)
}
