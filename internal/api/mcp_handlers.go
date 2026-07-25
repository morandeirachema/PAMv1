package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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
				}
				if json.Unmarshal(params, &p) == nil && p.Capabilities.Elicitation != nil {
					sess.elicitCapable.Store(true)
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
			tools := s.broker.Tools()
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
			out := s.broker.ProcessCall(ctx, id, broker.Call{Tool: p.Name, Args: p.Arguments})
			s.auditAs(ctx, id.AgentName, "broker.tool_call", fmt.Sprintf("tool:%s status:%s call:%s via:mcp", p.Name, out.Status, out.CallID))
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
			out, ok := s.broker.Resume(ctx, p.Token, "") // MCP resume has no path id to check against
			if !ok {
				return nil, mcp.Errorf(mcp.CodeInvalidParams, "invalid, expired, or already-used resume token")
			}
			s.auditAs(ctx, id.AgentName, "broker.tool_call.resumed", fmt.Sprintf("call:%s status:%s via:mcp", out.CallID, out.Status))
			return toolResult(out), nil
		},
	}
}

// jsonSchema converts a tool's field->type map into a minimal JSON Schema object
// for MCP tools/list.
func jsonSchema(fields map[string]string) map[string]any {
	props := map[string]any{}
	for name, typ := range fields {
		jt := "string"
		switch typ {
		case "int":
			jt = "integer"
		case "bool":
			jt = "boolean"
		}
		props[name] = map[string]any{"type": jt}
	}
	return map[string]any{"type": "object", "properties": props}
}

// toolResult renders a broker outcome as an MCP tools/call result: the outcome as
// a JSON text block plus structured content, flagged isError only on a failure.
func toolResult(out broker.Outcome) map[string]any {
	raw, _ := json.Marshal(out)
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": string(raw)}},
		"structuredContent": out,
		"isError":           out.Status == broker.StatusFailed,
	}
}
