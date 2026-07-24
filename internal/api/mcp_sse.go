package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/mcp"
)

// mcpStreamHeartbeat is how often an idle SSE stream emits a comment ping so
// intermediaries don't drop the connection.
const mcpStreamHeartbeat = 15 * time.Second

// mcpElicitTimeout bounds how long a server-initiated elicitation waits for the
// running user's answer before the broker call falls back to its parked state.
const mcpElicitTimeout = 30 * time.Second

// elicitResult is a client's answer to a server elicitation/create request.
type elicitResult struct {
	Action  string         // "accept" | "decline" | "cancel"
	Content map[string]any // fields the client returned (only on accept)
}

// mcpSession is one open MCP SSE connection (Phase 27). Server-initiated
// messages (notifications, elicitation requests) are pushed over out; pending
// holds the reply channels for in-flight elicitations keyed by request id.
type mcpSession struct {
	id            string
	out           chan []byte
	closed        chan struct{}
	elicitCapable atomic.Bool
	mu            sync.Mutex
	pending       map[string]chan elicitResult
}

// mcpSessionRegistry tracks open MCP SSE sessions by id so a POST /mcp?session=
// can route an elicitation response back to the waiting stream.
type mcpSessionRegistry struct {
	mu sync.Mutex
	m  map[string]*mcpSession
}

// newMCPSessionRegistry returns an empty session registry.
func newMCPSessionRegistry() *mcpSessionRegistry {
	return &mcpSessionRegistry{m: map[string]*mcpSession{}}
}

// open registers a new session with a random id.
func (r *mcpSessionRegistry) open() *mcpSession {
	var b [12]byte
	_, _ = rand.Read(b[:])
	s := &mcpSession{id: hex.EncodeToString(b[:]), out: make(chan []byte, 16), closed: make(chan struct{}), pending: map[string]chan elicitResult{}}
	r.mu.Lock()
	r.m[s.id] = s
	r.mu.Unlock()
	return s
}

// get returns the session with id, or nil.
func (r *mcpSessionRegistry) get(id string) *mcpSession {
	if id == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[id]
}

// close removes a session and unblocks any waiting elicitations.
func (r *mcpSessionRegistry) close(s *mcpSession) {
	r.mu.Lock()
	delete(r.m, s.id)
	r.mu.Unlock()
	close(s.closed)
}

// elicit pushes an elicitation/create request to the client and waits for its
// answer (or a timeout / stream close). It implements the MCP elicitation server
// role: the running user is asked to confirm a sensitive action out of band of
// the tool result. ok=false means no usable answer arrived.
func (s *mcpSession) elicit(ctx context.Context, message string, schema map[string]any) (elicitResult, bool) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	reqID := "elicit-" + hex.EncodeToString(b[:])
	ch := make(chan elicitResult, 1)
	s.mu.Lock()
	s.pending[reqID] = ch
	s.mu.Unlock()
	cleanup := func() {
		s.mu.Lock()
		delete(s.pending, reqID)
		s.mu.Unlock()
	}

	params, _ := json.Marshal(map[string]any{"message": message, "requestedSchema": schema})
	req := mcp.Request{JSONRPC: "2.0", ID: json.RawMessage(`"` + reqID + `"`), Method: "elicitation/create", Params: params}
	frame := sseFrame("message", mustJSON(req))
	select {
	case s.out <- frame:
	case <-ctx.Done():
		cleanup()
		return elicitResult{}, false
	case <-s.closed:
		cleanup()
		return elicitResult{}, false
	}

	timer := time.NewTimer(mcpElicitTimeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		return res, true
	case <-timer.C:
		cleanup()
		return elicitResult{}, false
	case <-ctx.Done():
		cleanup()
		return elicitResult{}, false
	case <-s.closed:
		return elicitResult{}, false
	}
}

// resolveElicit routes a client's elicitation response (from POST /mcp) to the
// waiting elicit call. Returns false if no elicitation with that id is pending.
func (s *mcpSession) resolveElicit(reqID string, res elicitResult) bool {
	s.mu.Lock()
	ch, ok := s.pending[reqID]
	if ok {
		delete(s.pending, reqID)
	}
	s.mu.Unlock()
	if !ok {
		return false
	}
	ch <- res
	return true
}

// serveMCPStream is the MCP SSE transport (GET /mcp). It opens an event stream,
// emits the `endpoint` event naming the message-POST URL (per the 2024-11-05 MCP
// HTTP+SSE transport), then relays server-initiated messages and heartbeats until
// the client disconnects. Auth is the same agent bearer as POST /mcp.
func (s *Server) serveMCPStream(w http.ResponseWriter, r *http.Request, _ *agentid.Identity) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	sess := s.mcpSessions.open()
	defer s.mcpSessions.close(sess)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	// The `endpoint` event tells the client where to POST JSON-RPC messages for
	// this session; the session id lets a server elicitation's response route back.
	if _, err := fmt.Fprintf(w, "event: endpoint\ndata: /mcp?session=%s\n\n", sess.id); err != nil {
		return
	}
	flusher.Flush()

	ticker := time.NewTicker(mcpStreamHeartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case frame := <-sess.out:
			if _, err := w.Write(frame); err != nil {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// sseFrame formats a named SSE event carrying a single-line JSON payload.
func sseFrame(event string, data []byte) []byte {
	return []byte("event: " + event + "\ndata: " + string(data) + "\n\n")
}

// mustJSON marshals v, returning "null" on the (unreachable for our types) error.
func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("null")
	}
	return b
}
