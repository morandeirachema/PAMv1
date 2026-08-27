// Package mcp is a minimal, hand-rolled JSON-RPC 2.0 core for PAMv1's Model
// Context Protocol endpoint. It handles framing and method dispatch only — the
// actual methods (initialize, tools/list, tools/call, ping, broker/resume) are
// supplied by the api layer and share the broker's one policy loop, so an MCP
// tool call is authorized and audited exactly like a REST call. stdlib only.
package mcp

import (
	"context"
	"encoding/json"
)

// Latest is the newest MCP protocol revision this server speaks; Supported
// lists every revision it negotiates, newest first (Phase 226 — until then the
// server answered every initialize with 2024-11-05 and never read what the
// client asked for).
//
// What "speaks" means here, revision by revision, is the message layer PAMv1
// actually implements: initialize/ping/tools/list/tools/call, the server-sent
// elicitation/create exchange (whose message/requestedSchema/action shape is
// the 2025-06-18 one), JSON-RPC batches received (2025-03-26 requires it;
// 2025-06-18 forbids sending them, which this server never does), and the
// MCP-Protocol-Version header on the HTTP transport (2025-06-18). The
// transport itself stays the HTTP+SSE pair every revision keeps for backwards
// compatibility; the Streamable HTTP transport is not offered.
const Latest = "2025-06-18"

// Supported is the negotiable set, newest first.
var Supported = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// IsSupported reports whether v is a revision this server speaks.
func IsSupported(v string) bool {
	for _, s := range Supported {
		if s == v {
			return true
		}
	}
	return false
}

// Negotiate answers an initialize request's protocolVersion the way every
// revision's lifecycle section prescribes: the client's revision when the
// server speaks it, otherwise the server's latest — after which the client
// decides whether it can proceed. An absent version is answered with the
// latest for the same reason.
func Negotiate(requested string) string {
	if IsSupported(requested) {
		return requested
	}
	return Latest
}

// Request is a JSON-RPC 2.0 request. A request with no id is a notification and
// gets no response.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is a JSON-RPC 2.0 error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Error implements error so a Method can return it directly.
func (e *Error) Error() string { return e.Message }

// Standard JSON-RPC 2.0 error codes.
const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
)

// Errorf builds an *Error with a code and message.
func Errorf(code int, message string) *Error { return &Error{Code: code, Message: message} }

// Method handles one JSON-RPC method: given the raw params, it returns a result
// or a JSON-RPC error.
type Method func(ctx context.Context, params json.RawMessage) (any, *Error)

// Dispatcher routes JSON-RPC method names to handlers.
type Dispatcher map[string]Method

// isNotification reports whether the request is a notification (absent or null
// id), which per JSON-RPC 2.0 must not be answered.
func isNotification(id json.RawMessage) bool {
	return len(id) == 0 || string(id) == "null"
}

// Handle parses a single JSON-RPC request and dispatches it. It returns the
// response to send and whether there is one (notifications produce ok=false, so
// the caller can reply 204/empty). JSON-RPC-level problems (bad JSON, unknown
// method) become error responses, never transport errors.
func (d Dispatcher) Handle(ctx context.Context, body []byte) (Response, bool) {
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		return errorResponse(nil, Errorf(CodeParse, "parse error")), true
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		if isNotification(req.ID) {
			return Response{}, false
		}
		return errorResponse(req.ID, Errorf(CodeInvalidRequest, "invalid request")), true
	}
	method, ok := d[req.Method]
	if !ok {
		if isNotification(req.ID) {
			return Response{}, false // unknown notification: ignore
		}
		return errorResponse(req.ID, Errorf(CodeMethodNotFound, "method not found: "+req.Method)), true
	}
	result, rpcErr := method(ctx, req.Params)
	if isNotification(req.ID) {
		return Response{}, false // notifications get no response even on error
	}
	if rpcErr != nil {
		return errorResponse(req.ID, rpcErr), true
	}
	return Response{JSONRPC: "2.0", ID: req.ID, Result: result}, true
}

// HandleBatch dispatches a body that is either one JSON-RPC request or a batch
// — a JSON array of them, which the 2025-03-26 revision requires a server to
// accept. It returns what to send (a Response, or a []Response for a batch
// with the notifications omitted) and whether there is anything to send at
// all: a lone notification, or a batch made only of notifications, yields
// ok=false. An empty array is one invalid-request error, per JSON-RPC 2.0.
func (d Dispatcher) HandleBatch(ctx context.Context, body []byte) (any, bool) {
	trimmed := bytesTrimLeft(body)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return d.Handle(ctx, body)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(body, &items); err != nil {
		return errorResponse(nil, Errorf(CodeParse, "parse error")), true
	}
	if len(items) == 0 {
		return errorResponse(nil, Errorf(CodeInvalidRequest, "invalid request: empty batch")), true
	}
	out := make([]Response, 0, len(items))
	for _, item := range items {
		if resp, ok := d.Handle(ctx, item); ok {
			out = append(out, resp)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// bytesTrimLeft drops leading JSON whitespace so the batch check sees the
// first significant byte.
func bytesTrimLeft(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	return b
}

// errorResponse builds a JSON-RPC error response with the given id (null when nil).
func errorResponse(id json.RawMessage, e *Error) Response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return Response{JSONRPC: "2.0", ID: id, Error: e}
}
