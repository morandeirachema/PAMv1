package api_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/guacd"
	"github.com/morandeirachema/pamv1/internal/session"
)

// joinGuacd is a fake guacd that serves one owner connection and any number
// of joining users. The owner gets a render stream; a joiner gets a "current
// display" instruction. It reports each handshake (select + connect args) and
// every instruction a joiner sends, so a test can prove what a watcher's
// browser could and could not reach guacd with.
type joinGuacd struct {
	addr       string
	handshakes chan [2][]string // [select args, connect args]
	joinerSent chan string      // opcodes received from joining users
	ownerSent  chan string
}

const ownerBlob = "owner-desktop-paint"

func newJoinGuacd(t *testing.T, paintLen int) *joinGuacd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &joinGuacd{addr: ln.Addr().String(), handshakes: make(chan [2][]string, 8), joinerSent: make(chan string, 64), ownerSent: make(chan string, 64)}
	var wg sync.WaitGroup
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				r := bufio.NewReader(conn)
				sel, err := readFakeInst(r)
				if err != nil || len(sel.args) == 0 {
					return
				}
				join := strings.HasPrefix(sel.args[0], "$")
				conn.Write([]byte(guacd.Instruction{Opcode: "args", Args: []string{"VERSION_1_5_0", "hostname", "username", "password", "read-only"}}.Encode()))
				var connect []string
				for {
					inst, err := readFakeInst(r)
					if err != nil {
						return
					}
					if inst.op == "connect" {
						connect = inst.args
						break
					}
				}
				g.handshakes <- [2][]string{sel.args, connect}
				if join {
					conn.Write([]byte(guacd.Instruction{Opcode: "ready", Args: []string{"$watcher"}}.Encode()))
					conn.Write([]byte(guacd.Instruction{Opcode: "size", Args: []string{"0", "1024", "768"}}.Encode()))
				} else {
					conn.Write([]byte(guacd.Instruction{Opcode: "ready", Args: []string{"$owner-conn"}}.Encode()))
					conn.Write([]byte(guacd.Instruction{Opcode: "size", Args: []string{"0", "1024", "768"}}.Encode()))
					conn.Write([]byte(guacd.Instruction{Opcode: "blob", Args: []string{"0", ownerBlob + strings.Repeat("A", paintLen)}}.Encode()))
					conn.Write([]byte(guacd.Instruction{Opcode: "sync", Args: []string{"1000"}}.Encode()))
				}
				sink := g.ownerSent
				if join {
					sink = g.joinerSent
				}
				for {
					inst, err := readFakeInst(r)
					if err != nil {
						return
					}
					select {
					case sink <- inst.op:
					default:
					}
				}
			}()
		}
	}()
	return g
}

func (g *joinGuacd) nextHandshake(t *testing.T) [2][]string {
	t.Helper()
	select {
	case h := <-g.handshakes:
		return h
	case <-time.After(5 * time.Second):
		t.Fatal("guacd saw no handshake")
	}
	return [2][]string{}
}

// TestGraphicalSessionWatchAndReplay drives Phase 258 end to end: an operator's
// RDP desktop is recorded by the portal and audited with its hash; a
// supervisor mints a single-use watch token and joins the live session
// read-only, and nothing but keep-alive reaches guacd from the watcher's
// browser; the watch ends with the session; and the recording lists, replays
// and verifies against the audit trail.
func TestGraphicalSessionWatchAndReplay(t *testing.T) {
	g := newJoinGuacd(t, 0)
	recDir := t.TempDir()
	srv, st := newTestServerOpts(t, nil, api.Options{GuacdAddr: g.addr, RecordingDir: recDir, Sessions: session.NewRegistry()})

	_, data := do(t, srv, "POST", "/api/targets", testAPIKey, map[string]any{
		"name": "win-rdp", "host": "10.0.0.9", "port": 3389, "os_type": "windows", "protocol": "rdp",
	})
	id := int64(jsonMap(t, data)["id"].(float64))
	do(t, srv, "POST", "/api/credentials", testAPIKey, map[string]any{"target_id": id, "username": "Administrator", "secret": "Rdp-S3cret!"})
	_, data = do(t, srv, "POST", "/api/rdp-token", testAPIKey, nil)
	tok := jsonMap(t, data)["token"].(string)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	wsBase := "ws" + strings.TrimPrefix(srv.URL, "http")
	owner, _, err := websocket.Dial(ctx, wsBase+"/api/targets/"+itoa(id)+"/rdp?token="+tok, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatalf("owner dial: %v", err)
	}
	defer owner.Close(websocket.StatusNormalClosure, "")
	g.nextHandshake(t)
	readUntil := func(c *websocket.Conn, want string) {
		t.Helper()
		for {
			_, b, err := c.Read(ctx)
			if err != nil {
				t.Fatalf("waiting for %q: %v", want, err)
			}
			if strings.Contains(string(b), want) {
				return
			}
		}
	}
	readUntil(owner, ownerBlob)

	// The live session is listed; find its id.
	_, data = do(t, srv, "GET", "/api/sessions", testAPIKey, nil)
	var live []struct {
		ID       string `json:"id"`
		Protocol string `json:"protocol"`
	}
	if err := json.Unmarshal(data, &live); err != nil || len(live) != 1 || live[0].Protocol != "rdp" {
		t.Fatalf("sessions = %s", data)
	}
	sid := live[0].ID

	// Minting: an auditor may watch; a plain user may not; an unknown id is 404.
	auditorTok := seedUser(t, srv, "theo", "auditor")
	userTok := seedUser(t, srv, "uma", "user")
	if code, _ := do(t, srv, "POST", "/api/sessions/"+sid+"/view-token", userTok, nil); code != http.StatusForbidden {
		t.Errorf("a user minting a watch token: want 403, got %d", code)
	}
	if code, _ := do(t, srv, "POST", "/api/sessions/nope/view-token", auditorTok, nil); code != http.StatusNotFound {
		t.Errorf("watch token for an unknown session: want 404, got %d", code)
	}
	code, data := do(t, srv, "POST", "/api/sessions/"+sid+"/view-token", auditorTok, nil)
	if code != http.StatusOK {
		t.Fatalf("auditor mints a watch token: %d %s", code, data)
	}
	watchTok := jsonMap(t, data)["token"].(string)

	// The watch token is refused as an API key, and opens no desktop.
	if code, _ := do(t, srv, "GET", "/api/sessions", watchTok, nil); code != http.StatusForbidden {
		t.Errorf("watch token as an API key: want 403, got %d", code)
	}
	auditHas(t, st, "authz.denied", "reason:watch-only-token")
	if _, resp, err := websocket.Dial(ctx, wsBase+"/api/targets/"+itoa(id)+"/rdp?token="+watchTok, &websocket.DialOptions{Subprotocols: []string{"guacamole"}}); err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("watch token at the RDP tunnel must be refused with 403, got err=%v", err)
	}
	// And the RDP token is not a watch token.
	_, data = do(t, srv, "POST", "/api/rdp-token", testAPIKey, nil)
	rdpTok := jsonMap(t, data)["token"].(string)
	if _, resp, err := websocket.Dial(ctx, wsBase+"/api/sessions/"+sid+"/view?token="+rdpTok, &websocket.DialOptions{Subprotocols: []string{"guacamole"}}); err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("an RDP token at the watch door must be refused with 403, got err=%v", err)
	}

	// Join: guacd is asked to add a READ-ONLY user to the owner's connection.
	watcher, _, err := websocket.Dial(ctx, wsBase+"/api/sessions/"+sid+"/view?token="+watchTok, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatalf("watcher dial: %v", err)
	}
	defer watcher.Close(websocket.StatusNormalClosure, "")
	h := g.nextHandshake(t)
	if h[0][0] != "$owner-conn" {
		t.Fatalf("watcher selected %q, want the owner's connection id", h[0][0])
	}
	// args: VERSION, hostname, username, password, read-only
	if h[1][1] != "" || h[1][2] != "" || h[1][3] != "" || h[1][4] != "true" {
		t.Fatalf("watcher connect args = %v, want no credential and read-only=true", h[1])
	}
	readUntil(watcher, "size")
	auditHas(t, st, "session.monitor", "session:"+sid+" protocol:rdp target:win-rdp actor:bootstrap-admin mode:read-only")

	// The token is spent.
	if _, resp, err := websocket.Dial(ctx, wsBase+"/api/sessions/"+sid+"/view?token="+watchTok, nil); err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a spent watch token: want 401, got err=%v", err)
	}

	// Input: the watcher's keys, mouse and clipboard never reach guacd; its
	// sync does — sent in one batch, so a filter that looked only at the first
	// instruction would fail here.
	batch := guacd.Instruction{Opcode: "key", Args: []string{"65", "1"}}.Encode() +
		guacd.Instruction{Opcode: "mouse", Args: []string{"1", "1", "1"}}.Encode() +
		guacd.Instruction{Opcode: "clipboard", Args: []string{"0", "text/plain"}}.Encode() +
		guacd.Instruction{Opcode: "sync", Args: []string{"1000"}}.Encode()
	if err := watcher.Write(ctx, websocket.MessageText, []byte(batch)); err != nil {
		t.Fatal(err)
	}
	select {
	case op := <-g.joinerSent:
		if op != "sync" {
			t.Fatalf("guacd received %q from the watcher, want only sync", op)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher's sync never reached guacd")
	}
	select {
	case op := <-g.joinerSent:
		t.Fatalf("guacd received a second instruction %q from the watcher", op)
	case <-time.After(200 * time.Millisecond):
	}

	// The owner leaves: the watch ends with the session, and the recording is audited.
	owner.Close(websocket.StatusNormalClosure, "")
	wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
	defer wcancel()
	for {
		if _, _, err := watcher.Read(wctx); err != nil {
			if wctx.Err() != nil {
				t.Fatal("the watch did not end when the watched session did")
			}
			break
		}
	}
	var recFile, recSum string
	deadline := time.Now().Add(5 * time.Second)
	for recFile == "" && time.Now().Before(deadline) {
		events, _ := st.ListAudit(context.Background(), 200)
		for _, e := range events {
			if e.Action != "rdp.record" {
				continue
			}
			for _, f := range strings.Fields(e.Detail) {
				switch {
				case strings.HasPrefix(f, "file:"):
					recFile = filepath.Base(strings.TrimPrefix(f, "file:"))
				case strings.HasPrefix(f, "sha256:"):
					recSum = strings.TrimPrefix(f, "sha256:")
				}
			}
		}
		if recFile == "" {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !strings.HasSuffix(recFile, ".guac") || len(recSum) != 64 {
		t.Fatalf("rdp.record = file %q sha %q", recFile, recSum)
	}
	raw, err := os.ReadFile(filepath.Join(recDir, recFile))
	if err != nil || !strings.Contains(string(raw), ownerBlob) || !strings.HasPrefix(string(raw), "4.size,") {
		t.Fatalf("recording on disk = %q, %v; want the instruction stream from its first display instruction", raw, err)
	}

	// Listed as a Guacamole recording with its owner; replayed and verified.
	_, data = do(t, srv, "GET", "/api/recordings", auditorTok, nil)
	var recs []struct{ Name, Kind, Target, Actor string }
	if err := json.Unmarshal(data, &recs); err != nil || len(recs) != 1 || recs[0].Kind != "guacamole" || recs[0].Target != "win-rdp" || recs[0].Actor != "bootstrap-admin" {
		t.Fatalf("recordings = %s", data)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/api/recordings/"+recFile, nil)
	req.Header.Set("X-API-Key", auditorTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("X-PAM-Recording-Audited") != "true" || resp.Header.Get("X-PAM-Recording-SHA256") != recSum || string(body) != string(raw) {
		t.Fatalf("playback: %d audited=%q sha=%q", resp.StatusCode, resp.Header.Get("X-PAM-Recording-Audited"), resp.Header.Get("X-PAM-Recording-SHA256"))
	}
}

// TestGraphicalRecordingCapEndsSession proves PAM_MAX_RECORDING_MB binds a
// desktop as it binds an SSH session: past the cap the session ends rather
// than continuing unrecorded, and what was recorded is still audited.
func TestGraphicalRecordingCapEndsSession(t *testing.T) {
	g := newJoinGuacd(t, 64<<10)
	recDir := t.TempDir()
	srv, st := newTestServerOpts(t, nil, api.Options{GuacdAddr: g.addr, RecordingDir: recDir, MaxRecordingBytes: 16 << 10, Sessions: session.NewRegistry()})
	_, data := do(t, srv, "POST", "/api/targets", testAPIKey, map[string]any{
		"name": "win-rdp", "host": "10.0.0.9", "port": 3389, "os_type": "windows", "protocol": "rdp",
	})
	id := int64(jsonMap(t, data)["id"].(float64))
	do(t, srv, "POST", "/api/credentials", testAPIKey, map[string]any{"target_id": id, "username": "Administrator", "secret": "x"})
	_, data = do(t, srv, "POST", "/api/rdp-token", testAPIKey, nil)
	tok := jsonMap(t, data)["token"].(string)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/api/targets/"+itoa(id)+"/rdp?token="+tok, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	c.SetReadLimit(1 << 20)
	for {
		_, b, err := c.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				t.Fatal("the session outlived its recording cap")
			}
			break
		}
		if strings.Contains(string(b), ownerBlob) {
			t.Fatal("an instruction past the cap reached the operator unrecorded")
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		events, _ := st.ListAudit(context.Background(), 200)
		for _, e := range events {
			if e.Action == "rdp.record" {
				auditHas(t, st, "session.record_limit", "target:win-rdp cred_user:Administrator reason:recording-size-cap protocol:rdp")
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("a capped session must still audit its recording")
}

// TestGraphicalRecordingSealed proves a desktop recording written with
// PAM_ENCRYPT_RECORDINGS is ciphertext on disk, that its audited hash covers
// the STORED bytes, and that playback decrypts it back to the instruction
// stream.
func TestGraphicalRecordingSealed(t *testing.T) {
	g := newJoinGuacd(t, 0)
	recDir := t.TempDir()
	srv, st := newTestServerOpts(t, nil, api.Options{GuacdAddr: g.addr, RecordingDir: recDir, EncryptRecordings: true, Sessions: session.NewRegistry()})
	_, data := do(t, srv, "POST", "/api/targets", testAPIKey, map[string]any{
		"name": "vnc-01", "host": "10.0.0.8", "port": 5900, "os_type": "linux", "protocol": "vnc",
	})
	id := int64(jsonMap(t, data)["id"].(float64))
	do(t, srv, "POST", "/api/credentials", testAPIKey, map[string]any{"target_id": id, "username": "vnc", "secret": "x"})
	_, data = do(t, srv, "POST", "/api/vnc-token", testAPIKey, nil)
	tok := jsonMap(t, data)["token"].(string)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/api/targets/"+itoa(id)+"/vnc?token="+tok, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatal(err)
	}
	for {
		_, b, err := c.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "sync") {
			break
		}
	}
	c.Close(websocket.StatusNormalClosure, "")

	var recFile string
	for deadline := time.Now().Add(5 * time.Second); recFile == "" && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		events, _ := st.ListAudit(context.Background(), 200)
		for _, e := range events {
			if e.Action == "vnc.record" {
				for _, f := range strings.Fields(e.Detail) {
					if strings.HasPrefix(f, "file:") {
						recFile = filepath.Base(strings.TrimPrefix(f, "file:"))
					}
				}
			}
		}
	}
	if recFile == "" {
		t.Fatal("no vnc.record event")
	}
	raw, err := os.ReadFile(filepath.Join(recDir, recFile))
	if err != nil || strings.Contains(string(raw), ownerBlob) {
		t.Fatalf("a sealed recording must not hold the stream in the clear (err %v)", err)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/api/recordings/"+recFile, nil)
	req.Header.Set("X-API-Key", testAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("X-PAM-Recording-Audited") != "true" || resp.Header.Get("X-PAM-Recording-Encrypted") != "true" || !strings.Contains(string(body), ownerBlob) {
		t.Fatalf("sealed playback: %d audited=%q encrypted=%q body=%q", resp.StatusCode, resp.Header.Get("X-PAM-Recording-Audited"), resp.Header.Get("X-PAM-Recording-Encrypted"), body)
	}
}
