package api_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/guacd"
)

// fakeVNCGuacd plays guacd for a VNC connection: it advertises the parameter
// names guacd 1.5.5 really advertises for VNC (note "enable-sftp" instead of
// RDP's "enable-drive", and no "security"/"ignore-cert"), reports the protocol
// it was asked to select, and hands back the connect arguments.
func fakeVNCGuacd(t *testing.T, selectCh chan<- string, connectCh chan<- []string, argNames []string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		sel, err := readFakeInst(r)
		if err != nil {
			return
		}
		if len(sel.args) > 0 {
			selectCh <- sel.args[0]
		}
		conn.Write([]byte(guacd.Instruction{Opcode: "args", Args: append([]string{"VERSION_1_5_0"}, argNames...)}.Encode()))
		for {
			inst, err := readFakeInst(r)
			if err != nil {
				return
			}
			if inst.op == "connect" {
				connectCh <- inst.args
				break
			}
		}
		conn.Write([]byte(guacd.Instruction{Opcode: "ready", Args: []string{"$vnc-conn"}}.Encode()))
		io.Copy(io.Discard, r)
	}()
	return ln.Addr().String()
}

// vncArgNames is what guacd 1.5.5 advertises for VNC, trimmed to what this
// connector uses (taken from guacamole-server's GUAC_VNC_CLIENT_ARGS).
var vncArgNames = []string{"hostname", "port", "username", "password", "disable-copy", "disable-paste", "enable-sftp"}

// seedVNCTarget creates a vnc target plus its credential and returns the id.
func seedVNCTarget(t *testing.T, srv *httptest.Server, name, secret string) int64 {
	t.Helper()
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": name, "host": "10.0.0.60", "port": 5900, "os_type": "linux", "protocol": "vnc",
	})
	id := int64(jsonMap(t, data)["id"].(float64))
	if code, body := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": id, "username": "vnc", "secret": secret,
	}); code != http.StatusCreated {
		t.Fatalf("seed credential: %d %s", code, body)
	}
	return id
}

// TestVNCTunnelEndToEnd proves the VNC viewer brokers a session exactly as the
// RDP one does: guacd is asked to select "vnc", the vaulted secret is injected
// into guacd's handshake (the browser never sends it), VNC's file-transfer
// channel is forced off, and the tunnel opens.
func TestVNCTunnelEndToEnd(t *testing.T) {
	selectCh := make(chan string, 1)
	connectCh := make(chan []string, 1)
	addr := fakeVNCGuacd(t, selectCh, connectCh, vncArgNames)

	srv, _ := newTestServerOpts(t, nil, api.Options{GuacdAddr: addr})
	const secret = "DemoVnc1"
	id := seedVNCTarget(t, srv, "vnc-01", secret)

	status, data := do(t, srv, http.MethodPost, "/api/vnc-token", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("vnc-token status %d: %s", status, data)
	}
	tok, _ := jsonMap(t, data)["token"].(string)
	if tok == "" {
		t.Fatalf("no vnc token returned: %s", data)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/targets/" + strconv.FormatInt(id, 10) + "/vnc?token=" + tok
	if c, _, derr := websocket.Dial(ctx, wsURL, &websocket.DialOptions{Subprotocols: []string{"guacamole"}}); derr == nil {
		defer c.Close(websocket.StatusNormalClosure, "")
	}

	select {
	case got := <-selectCh:
		if got != "vnc" {
			t.Fatalf("guacd was asked to select %q, want vnc", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guacd never received the select")
	}
	select {
	case args := <-connectCh:
		// Order mirrors the advertised args: VERSION, hostname, port, username,
		// password, disable-copy, disable-paste, enable-sftp.
		if len(args) != len(vncArgNames)+1 {
			t.Fatalf("connect args = %v (len %d)", args, len(args))
		}
		if args[1] != "10.0.0.60" || args[2] != "5900" {
			t.Fatalf("host/port on the wire = %q/%q", args[1], args[2])
		}
		if args[4] != secret {
			t.Fatalf("vaulted secret not injected: password arg = %q", args[4])
		}
		if args[7] != "false" {
			t.Fatalf("enable-sftp = %q, want false (VNC's file-transfer channel must be off)", args[7])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guacd never received the connect")
	}
}

// TestVNCClipboardPolicyReachesGuacd proves the clipboard gate covers VNC too:
// a global deny arrives as disable-copy/disable-paste on the VNC wire.
func TestVNCClipboardPolicyReachesGuacd(t *testing.T) {
	selectCh := make(chan string, 1)
	connectCh := make(chan []string, 1)
	addr := fakeVNCGuacd(t, selectCh, connectCh, vncArgNames)

	srv, _ := newTestServerOpts(t, nil, api.Options{GuacdAddr: addr, RDPClipboard: "deny"})
	id := seedVNCTarget(t, srv, "vnc-clip", "DemoVnc1")

	_, data := do(t, srv, http.MethodPost, "/api/vnc-token", testAPIKey, nil)
	tok, _ := jsonMap(t, data)["token"].(string)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/targets/" + strconv.FormatInt(id, 10) + "/vnc?token=" + tok
	if c, _, derr := websocket.Dial(ctx, wsURL, &websocket.DialOptions{Subprotocols: []string{"guacamole"}}); derr == nil {
		defer c.Close(websocket.StatusNormalClosure, "")
	}
	<-selectCh

	select {
	case args := <-connectCh:
		if args[5] != "true" || args[6] != "true" {
			t.Fatalf("deny policy on VNC: disable-copy=%q disable-paste=%q, want true/true", args[5], args[6])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guacd never received the connect")
	}
}

// TestViewerRefusedWhenClipboardUnenforceable proves the fail-closed check: if
// guacd does not advertise the parameters the clipboard policy is enforced
// through, a non-permissive policy refuses the session rather than rendering an
// ungated desktop while the portal reports the policy as in force.
func TestViewerRefusedWhenClipboardUnenforceable(t *testing.T) {
	selectCh := make(chan string, 1)
	connectCh := make(chan []string, 1)
	// An old (or differently built) guacd: no clipboard knobs at all.
	addr := fakeVNCGuacd(t, selectCh, connectCh, []string{"hostname", "port", "username", "password"})

	srv, st := newTestServerOpts(t, nil, api.Options{GuacdAddr: addr, RDPClipboard: "deny"})
	id := seedVNCTarget(t, srv, "vnc-nogate", "DemoVnc1")

	_, data := do(t, srv, http.MethodPost, "/api/vnc-token", testAPIKey, nil)
	tok, _ := jsonMap(t, data)["token"].(string)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/targets/" + strconv.FormatInt(id, 10) + "/vnc?token=" + tok
	c, _, derr := websocket.Dial(ctx, wsURL, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	if derr == nil {
		c.Close(websocket.StatusNormalClosure, "")
		t.Fatal("the tunnel opened even though guacd cannot enforce the clipboard policy")
	}

	// And it is on the record, with the parameter that was missing.
	auditHas(t, st, "vnc.refused", "clipboard-unenforceable")
}

// TestVNCTokenIsTunnelScoped proves a VNC viewer token is useless anywhere but a
// viewer tunnel — the property that makes it safe to put in a WebSocket URL.
// Missing the scope from auth.IsViewerScope would silently hand out a full API
// token in a query string.
func TestVNCTokenIsTunnelScoped(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{GuacdAddr: "127.0.0.1:1"})
	_, data := do(t, srv, http.MethodPost, "/api/vnc-token", testAPIKey, nil)
	tok, _ := jsonMap(t, data)["token"].(string)
	if tok == "" {
		t.Fatalf("no token minted: %s", data)
	}
	for _, path := range []string{"/api/targets", "/api/me"} {
		if code, body := do(t, srv, http.MethodGet, path, tok, nil); code != http.StatusForbidden {
			t.Fatalf("GET %s with a VNC tunnel token: %d %s, want 403", path, code, body)
		}
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/vnc-token", tok, nil); code != http.StatusForbidden {
		t.Fatal("a VNC tunnel token could re-mint itself")
	}
}
