package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/morandeirachema/pamv1/internal/mcp"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// Phase 226 — the MCP protocol revision is negotiated, not pinned. The server
// had answered every initialize with 2024-11-05 regardless of what the client
// asked for, advertised a `logging` capability it never implemented and an
// `elicitation` one that is the client's to declare, rejected the batches the
// 2025-03-26 revision requires a server to accept, and ignored the
// MCP-Protocol-Version header the 2025-06-18 revision puts on HTTP requests.

func mcpServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, brokerRules))
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-mcpv", "owner": "alice"})
	tok, _ := jsonMap(t, ad)["token"].(string)
	return srv, tok
}

// mcpPost sends a raw body to /mcp with optional extra headers and returns the
// status and body.
func mcpPost(t *testing.T, srv *httptest.Server, tok string, body []byte, headers map[string]string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return res.StatusCode, data
}

func initializeWith(t *testing.T, srv *httptest.Server, tok string, params map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize"}
	if params != nil {
		body["params"] = params
	}
	b, _ := json.Marshal(body)
	st, data := mcpPost(t, srv, tok, b, nil)
	if st != http.StatusOK {
		t.Fatalf("initialize: %d %s", st, data)
	}
	var resp struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(data, &resp); err != nil || resp.Result == nil {
		t.Fatalf("initialize result: %s", data)
	}
	return resp.Result
}

// TestMCPNegotiatesProtocolVersion: a supported revision is echoed, an unknown
// or absent one is answered with the latest, and the capabilities advertised
// are the ones that exist.
func TestMCPNegotiatesProtocolVersion(t *testing.T) {
	srv, tok := mcpServer(t)
	for _, v := range mcp.Supported {
		if got := initializeWith(t, srv, tok, map[string]any{"protocolVersion": v})["protocolVersion"]; got != v {
			t.Fatalf("initialize(%s) answered %v, want the client's own revision echoed", v, got)
		}
	}
	if got := initializeWith(t, srv, tok, map[string]any{"protocolVersion": "2099-01-01"})["protocolVersion"]; got != mcp.Latest {
		t.Fatalf("an unknown revision must be answered with the latest %s, got %v", mcp.Latest, got)
	}
	res := initializeWith(t, srv, tok, nil)
	if got := res["protocolVersion"]; got != mcp.Latest {
		t.Fatalf("an initialize without a version must be answered with the latest %s, got %v", mcp.Latest, got)
	}
	caps, _ := res["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Fatalf("the tools capability must be advertised: %v", caps)
	}
	for _, phantom := range []string{"logging", "elicitation"} {
		if _, ok := caps[phantom]; ok {
			t.Fatalf("%q must not be advertised as a server capability (nothing implements it, or it is the client's to declare): %v", phantom, caps)
		}
	}
}

// TestMCPProtocolVersionHeader: the 2025-06-18 HTTP rule — a header naming a
// revision this server does not speak is refused at the transport; a
// supported one, or none, is served.
func TestMCPProtocolVersionHeader(t *testing.T) {
	srv, tok := mcpServer(t)
	ping := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if st, data := mcpPost(t, srv, tok, ping, map[string]string{"MCP-Protocol-Version": "1999-01-01"}); st != http.StatusBadRequest {
		t.Fatalf("unsupported MCP-Protocol-Version: want 400, got %d %s", st, data)
	}
	for _, v := range mcp.Supported {
		if st, data := mcpPost(t, srv, tok, ping, map[string]string{"MCP-Protocol-Version": v}); st != http.StatusOK {
			t.Fatalf("MCP-Protocol-Version %s: want 200, got %d %s", v, st, data)
		}
	}
	if st, _ := mcpPost(t, srv, tok, ping, nil); st != http.StatusOK {
		t.Fatalf("no header (a pre-2025-06-18 client): want 200, got %d", st)
	}
}

// TestMCPBatchOverHTTP: a JSON-RPC batch is answered element by element, with
// the notification omitted, and a batch of only notifications gets 204.
func TestMCPBatchOverHTTP(t *testing.T) {
	srv, tok := mcpServer(t)
	st, data := mcpPost(t, srv, tok, []byte(`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`), nil)
	if st != http.StatusOK {
		t.Fatalf("batch: %d %s", st, data)
	}
	var resps []struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &resps); err != nil || len(resps) != 2 {
		t.Fatalf("batch: want an array of 2 responses, got %s", data)
	}
	if string(resps[0].ID) != "1" || string(resps[1].ID) != "2" || len(resps[1].Result) == 0 {
		t.Fatalf("batch responses: %s", data)
	}
	if st, _ := mcpPost(t, srv, tok, []byte(`[{"jsonrpc":"2.0","method":"notifications/initialized"}]`), nil); st != http.StatusNoContent {
		t.Fatalf("a batch of notifications: want 204, got %d", st)
	}
}
