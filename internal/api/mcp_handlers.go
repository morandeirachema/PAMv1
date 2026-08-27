package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/mcp"
)

// serveMCP handles POST /mcp: a JSON-RPC 2.0 endpoint exposing the broker's tools
// to MCP clients. Auth is the same agentAuth as REST, and tools/call routes
// through the same broker.ProcessCall, so policy and audit are identical across
// the two transports. When ?session= names an open SSE stream (Phase 27), a body
// that is a JSON-RPC RESPONSE is routed as an elicitation answer instead of being
// dispatched as a request.
func (s *Server) serveMCP(w http.ResponseWriter, r *http.Request, id *agentid.Identity) {
	r.Body = http.MaxBytesReader(w, r.Body, maxToolCallBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "request body too large or unreadable")
		return
	}
	sess := s.mcpSessions.get(r.URL.Query().Get("session"))
	if sess != nil && !sess.ownedBy(id) {
		// The session id travels in the query string (access logs, proxies); only the
		// agent that opened the stream may drive it, so a leaked id can't be used to
		// prompt or route into another agent's session.
		sess = nil
	}
	if sess != nil && s.routeElicitationResponse(sess, body) {
		w.WriteHeader(http.StatusAccepted) // an elicitation answer, delivered to the waiting call
		return
	}
	resp, ok := s.mcpDispatcher(id, sess).Handle(r.Context(), body)
	if !ok {
		w.WriteHeader(http.StatusNoContent) // JSON-RPC notification: no response body
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// routeElicitationResponse detects a JSON-RPC response body (an id, a
// result/error, and no method) answering a server elicitation/create, and
// delivers it to the waiting elicit call. Returns false for anything else (a
// normal request), which the caller dispatches.
func (s *Server) routeElicitationResponse(sess *mcpSession, body []byte) bool {
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Result *struct {
			Action  string         `json:"action"`
			Content map[string]any `json:"content"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	// A response has an id and no method; it carries either a result or an error.
	if err := json.Unmarshal(body, &msg); err != nil || msg.Method != "" || len(msg.ID) == 0 {
		return false
	}
	if msg.Result == nil && len(msg.Error) == 0 {
		return false // neither result nor error: not a response
	}
	var reqID string
	if json.Unmarshal(msg.ID, &reqID) != nil {
		return false
	}
	// A JSON-RPC error answer (the client rejected elicitation/create) is treated
	// as a decline, so the waiting call resolves immediately instead of hanging
	// until the elicitation timeout.
	res := elicitResult{Action: "decline"}
	if msg.Result != nil {
		res = elicitResult{Action: msg.Result.Action, Content: msg.Result.Content}
	}
	return sess.resolveElicit(reqID, res)
}

// mcpRunID returns the correlation id for tool calls arriving over MCP: the
// protocol session the client opened. MCP has no per-call run field, so the
// session IS the run — every call on one stream belongs to one agent
// conversation. A bare POST /mcp with no SSE stream has no session, hence "".
func mcpRunID(sess *mcpSession) string {
	if sess == nil {
		return ""
	}
	return sess.id
}

// mcpClient returns the client software the peer declared at `initialize`, or ""
// if it declared none (or there is no session).
//
// The comma-ok assertion on atomic.Value is required in Go: Load returns an
// empty interface, which is nil until something is stored, so asserting it to a
// string without the second return value would panic on a session that never
// saw an initialize.
func mcpClient(sess *mcpSession) string {
	if sess == nil {
		return ""
	}
	v, _ := sess.client.Load().(string)
	return v
}

// mcpDispatcher builds the JSON-RPC method table bound to the authenticated agent
// and (optionally) its open SSE session, which enables server-initiated
// elicitation on approval-gated calls.
func (s *Server) mcpDispatcher(id *agentid.Identity, sess *mcpSession) mcp.Dispatcher {
	return mcp.Dispatcher{
		"initialize": func(_ context.Context, params json.RawMessage) (any, *mcp.Error) {
			// Note whether the client advertised elicitation support so a later
			// approval-gated tool call can prompt the running user over the SSE stream.
			if sess != nil {
				var p struct {
					Capabilities struct {
						Elicitation *json.RawMessage `json:"elicitation"`
					} `json:"capabilities"`
					ClientInfo struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					} `json:"clientInfo"`
				}
				if json.Unmarshal(params, &p) == nil {
					if p.Capabilities.Elicitation != nil {
						sess.elicitCapable.Store(true)
					}
					// Keep the client's self-description for the audit trail. MCP
					// puts provenance here, once per session, rather than on each
					// call — so this is the only chance to learn what software is
					// driving the agent, and it is recorded as declared, never
					// checked.
					if p.ClientInfo.Name != "" {
						sess.client.Store(strings.TrimSuffix(p.ClientInfo.Name+"/"+p.ClientInfo.Version, "/"))
					}
				}
			}
			return map[string]any{
				"protocolVersion": mcp.Version,
				"capabilities": map[string]any{
					"tools":       map[string]any{},
					"logging":     map[string]any{},
					"elicitation": map[string]any{},
				},
				"serverInfo": map[string]any{"name": "pamv1-broker", "version": "27"},
			}, nil
		},
		"ping": func(context.Context, json.RawMessage) (any, *mcp.Error) {
			return map[string]any{}, nil
		},
		"tools/list": func(context.Context, json.RawMessage) (any, *mcp.Error) {
			// Narrowed to what policy could ever allow THIS identity (Phase 204).
			// The unfiltered registry told every agent that winrm_exec and
			// reveal_credential exist even when no rule would ever let it near
			// them — a map of the surface, handed out for free. tools/call is
			// unchanged and still evaluates policy in full.
			tools := s.broker.ToolsFor(id)
			out := make([]map[string]any, 0, len(tools))
			for _, t := range tools {
				out = append(out, map[string]any{
					"name":        t.Name(),
					"description": t.Description(),
					"inputSchema": jsonSchema(t.InputSchema()),
				})
			}
			return map[string]any{"tools": out}, nil
		},
		"tools/call": func(ctx context.Context, params json.RawMessage) (any, *mcp.Error) {
			var p struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
				return nil, mcp.Errorf(mcp.CodeInvalidParams, "tools/call requires a name")
			}
			// The MCP transport has no per-call session field, so the run id is the
			// protocol session the client established at `initialize`, and the client
			// provenance is the `clientInfo` it declared there — the same two facts
			// the REST caller passes explicitly, taken from where MCP puts them.
			// The same cumulative budget the REST path enforces: a limit that
			// only one transport honours is not a limit, and MCP is the transport
			// an agent framework actually speaks.
			refusal, spend := s.budgetRefusal(ctx, id, p.Name)
			if refusal != nil {
				s.auditAs(ctx, id.AgentName, broker.ActionFor(refusal.Status),
					fmt.Sprintf("tool:%s status:%s reason:budget via:mcp", auditField(p.Name, 64), refusal.Status))
				return toolResult(*refusal), nil
			}
			in := toolCallIn{SessionID: mcpRunID(sess), Client: mcpClient(sess), Tool: p.Name, Args: p.Arguments}
			out := s.broker.ProcessCall(ctx, id, broker.Call{SessionID: in.SessionID, Client: in.Client, Tool: in.Tool, Args: in.Args})
			s.settleSpend(ctx, spend, out)
			s.auditAs(ctx, id.AgentName, broker.ActionFor(out.Status), brokerCallDetail(id, in, out)+" via:mcp")
			// Elicitation (Phase 27): if the call parked for approval and the client
			// declared elicitation support, ask the running user to confirm over the
			// SSE stream. A decline WITHDRAWS the requester's own pending call (no
			// four-eyes needed to cancel what you asked for); an accept only records
			// intent — the human approver gate is unchanged (four-eyes preserved).
			if out.Status == broker.StatusPendingApproval && sess != nil && sess.elicitCapable.Load() {
				schema := map[string]any{
					"type":       "object",
					"properties": map[string]any{"confirm": map[string]any{"type": "boolean", "description": "proceed with this privileged request"}},
					"required":   []string{"confirm"},
				}
				res, gotAnswer := sess.elicit(ctx, fmt.Sprintf("Confirm privileged request %q on your behalf (still needs a separate human approver).", p.Name), schema)
				switch {
				case gotAnswer && (res.Action == "decline" || res.Action == "cancel"):
					// Withdraw only succeeds if the call is still parked. If a human
					// approver decided it during the elicitation window, Withdraw fails
					// (ok=false) — return the ORIGINAL outcome (which carries the agent's
					// only copy of the resume token) rather than an empty one, so the
					// already-executed result stays collectable.
					if wout, ok := s.broker.Withdraw(ctx, out.CallID, id); ok {
						s.settleParkedSpend(ctx, out.CallID, false) // withdrawn: never executed
						s.auditAs(ctx, id.AgentName, "broker.elicit.declined", fmt.Sprintf("tool:%s call:%s via:mcp", p.Name, out.CallID))
						return toolResult(wout), nil
					}
				case gotAnswer && res.Action == "accept":
					s.auditAs(ctx, id.AgentName, "broker.elicit.accepted", fmt.Sprintf("tool:%s call:%s via:mcp", p.Name, out.CallID))
				}
			}
			return toolResult(out), nil
		},
		"broker/resume": func(ctx context.Context, params json.RawMessage) (any, *mcp.Error) {
			var p struct {
				Token string `json:"token"`
			}
			if err := json.Unmarshal(params, &p); err != nil || p.Token == "" {
				return nil, mcp.Errorf(mcp.CodeInvalidParams, "broker/resume requires a token")
			}
			out, ok := s.broker.Resume(ctx, id, p.Token, "") // MCP resume has no path id to check against
			if !ok {
				return nil, mcp.Errorf(mcp.CodeInvalidParams, "invalid, expired, or already-used resume token")
			}
			s.auditAs(ctx, id.AgentName, broker.ActionToolCallResumed, resumeDetail(id, out)+" via:mcp")
			return toolResult(out), nil
		},
	}
}

// jsonSchema converts a tool's field->type map into a minimal JSON Schema object
// for MCP tools/list.
func jsonSchema(fields map[string]string) map[string]any {
	props := map[string]any{}
	var required []string
	for name, spec := range broker.ParseSchema(fields) {
		jt := "string"
		switch spec.Type {
		case "int":
			jt = "integer"
		case "bool":
			jt = "boolean"
		}
		props[name] = map[string]any{"type": jt}
		if spec.Required {
			required = append(required, name)
		}
	}
	// Sorted because JSON Schema's `required` is a list and Go map iteration is
	// deliberately randomised: without this the same toolset would advertise a
	// different-looking schema on every call, which breaks client-side caching and
	// makes two captures of the same server look like two different servers.
	sort.Strings(required)
	out := map[string]any{"type": "object", "properties": props}
	// Emitted only when there is something to require — an empty `required: []`
	// is legal JSON Schema but reads to a client author as "nothing is required"
	// stated deliberately, which for a tool with no arguments at all is noise.
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

// toolResult renders a broker outcome as an MCP tools/call result: the outcome as
// a JSON text block plus structured content, flagged isError when the call did
// not do what was asked.
//
// A DENIAL counts (Phase 163). It previously did not, so an MCP client was told
// `isError: false` for a policy refusal — and a client that trusts that flag,
// which is what the flag is for, reads a refusal as a successful call that
// happened to return some text. An agent looping on "did that work?" would
// conclude yes. A denial is a real outcome, not an error in the transport sense,
// but the question the flag answers is "did the tool do the thing", and there
// the honest answer is no.
//
// `pending_approval` is deliberately NOT an error: the call has not failed, it is
// waiting for a human, and the agent has a resume token to collect it with.
func toolResult(out broker.Outcome) map[string]any {
	raw, _ := json.Marshal(out)
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": string(raw)}},
		"structuredContent": out,
		"isError":           out.Status == broker.StatusFailed || out.Status == broker.StatusDenied,
	}
}
