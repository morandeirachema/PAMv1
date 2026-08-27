package mcp_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/morandeirachema/pamv1/internal/mcp"
)

// TestDispatcherHandle covers the JSON-RPC 2.0 framing: success, method errors,
// unknown methods, parse errors, and that notifications get no response.
func TestDispatcherHandle(t *testing.T) {
	d := mcp.Dispatcher{
		"echo": func(_ context.Context, params json.RawMessage) (any, *mcp.Error) {
			return map[string]any{"params": string(params)}, nil
		},
		"boom": func(context.Context, json.RawMessage) (any, *mcp.Error) {
			return nil, mcp.Errorf(mcp.CodeInternal, "boom")
		},
	}
	ctx := context.Background()

	// Success: id echoed, no error.
	resp, ok := d.Handle(ctx, []byte(`{"jsonrpc":"2.0","id":1,"method":"echo","params":{"x":1}}`))
	if !ok || resp.Error != nil || string(resp.ID) != "1" {
		t.Fatalf("echo: ok=%v resp=%+v", ok, resp)
	}

	// A method-level error becomes a JSON-RPC error response (still ok=true).
	resp, ok = d.Handle(ctx, []byte(`{"jsonrpc":"2.0","id":2,"method":"boom"}`))
	if !ok || resp.Error == nil || resp.Error.Code != mcp.CodeInternal {
		t.Fatalf("boom: %+v", resp)
	}

	// Unknown method → -32601.
	resp, _ = d.Handle(ctx, []byte(`{"jsonrpc":"2.0","id":3,"method":"nope"}`))
	if resp.Error == nil || resp.Error.Code != mcp.CodeMethodNotFound {
		t.Fatalf("unknown method: %+v", resp)
	}

	// Bad JSON → parse error.
	resp, _ = d.Handle(ctx, []byte(`{bad`))
	if resp.Error == nil || resp.Error.Code != mcp.CodeParse {
		t.Fatalf("parse: %+v", resp)
	}

	// Wrong jsonrpc version → invalid request.
	resp, _ = d.Handle(ctx, []byte(`{"jsonrpc":"1.0","id":4,"method":"echo"}`))
	if resp.Error == nil || resp.Error.Code != mcp.CodeInvalidRequest {
		t.Fatalf("bad version: %+v", resp)
	}

	// A notification (no id) produces no response.
	if _, ok := d.Handle(ctx, []byte(`{"jsonrpc":"2.0","method":"echo"}`)); ok {
		t.Fatal("notification should produce no response")
	}
	// An unknown notification is also silently ignored.
	if _, ok := d.Handle(ctx, []byte(`{"jsonrpc":"2.0","method":"nope"}`)); ok {
		t.Fatal("unknown notification should produce no response")
	}
}

// TestNegotiate pins the lifecycle rule every revision states: a revision the
// server speaks is echoed, anything else — including nothing — gets the
// server's latest, and the client decides from there.
func TestNegotiate(t *testing.T) {
	for _, v := range mcp.Supported {
		if got := mcp.Negotiate(v); got != v {
			t.Fatalf("Negotiate(%q) = %q, want it echoed", v, got)
		}
	}
	for _, v := range []string{"", "2099-01-01", "1.0", "2024-11-05 "} {
		if got := mcp.Negotiate(v); got != mcp.Latest {
			t.Fatalf("Negotiate(%q) = %q, want the latest %q", v, got, mcp.Latest)
		}
	}
	if mcp.Supported[0] != mcp.Latest {
		t.Fatalf("Supported must list the latest first: %v", mcp.Supported)
	}
}

// TestDispatcherHandleBatch covers the batch framing the 2025-03-26 revision
// requires a server to accept: each element answered in order, notifications
// omitted, an all-notification batch answered with nothing, an empty batch
// with one invalid-request error, and a non-array body handled as before.
func TestDispatcherHandleBatch(t *testing.T) {
	d := mcp.Dispatcher{
		"echo": func(_ context.Context, params json.RawMessage) (any, *mcp.Error) {
			return map[string]any{"params": string(params)}, nil
		},
	}
	ctx := context.Background()
	out, ok := d.HandleBatch(ctx, []byte(` [{"jsonrpc":"2.0","id":1,"method":"echo"},{"jsonrpc":"2.0","method":"echo"},{"jsonrpc":"2.0","id":2,"method":"nope"}]`))
	if !ok {
		t.Fatal("a batch with requests must produce a response")
	}
	resps, isBatch := out.([]mcp.Response)
	if !isBatch || len(resps) != 2 {
		t.Fatalf("batch: want 2 responses (the notification omitted), got %T %+v", out, out)
	}
	if string(resps[0].ID) != "1" || resps[0].Error != nil || string(resps[1].ID) != "2" || resps[1].Error == nil || resps[1].Error.Code != mcp.CodeMethodNotFound {
		t.Fatalf("batch order/content: %+v", resps)
	}
	if _, ok := d.HandleBatch(ctx, []byte(`[{"jsonrpc":"2.0","method":"echo"}]`)); ok {
		t.Fatal("a batch of notifications only must produce no response")
	}
	out, ok = d.HandleBatch(ctx, []byte(`[]`))
	if r, isOne := out.(mcp.Response); !ok || !isOne || r.Error == nil || r.Error.Code != mcp.CodeInvalidRequest {
		t.Fatalf("empty batch: want one invalid-request error, got %+v", out)
	}
	out, _ = d.HandleBatch(ctx, []byte(`[{"jsonrpc":"2.0","id":1,"method":"echo"}`))
	if r, isOne := out.(mcp.Response); !isOne || r.Error == nil || r.Error.Code != mcp.CodeParse {
		t.Fatalf("truncated batch: want a parse error, got %+v", out)
	}
	out, ok = d.HandleBatch(ctx, []byte(`{"jsonrpc":"2.0","id":7,"method":"echo"}`))
	if r, isOne := out.(mcp.Response); !ok || !isOne || string(r.ID) != "7" {
		t.Fatalf("single request through HandleBatch: %+v", out)
	}
}
