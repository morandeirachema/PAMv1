package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/guacd"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// desktopEnv is a live RDP session against the fake guacd, with bob holding a
// redeemed view_control share of it — the common ground of the desktop
// findings in the review of 250–262.
type desktopEnv struct {
	t      *testing.T
	ctx    context.Context
	srv    string
	st     store.Store
	g      *joinGuacd
	sid    string
	owner  *websocket.Conn
	bobTok string
	bobID  int64
	key    string
	dial   func(path string) (*websocket.Conn, *http.Response, error)
}

func newDesktopEnv(t *testing.T) *desktopEnv {
	t.Helper()
	g := newJoinGuacd(t, 0)
	reg := session.NewRegistry()
	srv, st := newTestServerOpts(t, nil, api.Options{
		GuacdAddr: g.addr, Sessions: reg, Live: session.NewHub(), Shares: session.NewShareRegistry(),
		ShareInviteTTL: time.Minute, ShareGuestSessionTTL: time.Minute,
	})
	_, data := do(t, srv, "POST", "/api/targets", testAPIKey, map[string]any{
		"name": "win-rdp", "host": "10.0.0.9", "port": 3389, "os_type": "windows", "protocol": "rdp",
	})
	id := int64(jsonMap(t, data)["id"].(float64))
	do(t, srv, "POST", "/api/credentials", testAPIKey, map[string]any{"target_id": id, "username": "Administrator", "secret": "x"})
	_, data = do(t, srv, "POST", "/api/rdp-token", testAPIKey, nil)
	tok := jsonMap(t, data)["token"].(string)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	wsBase := "ws" + strings.TrimPrefix(srv.URL, "http")
	e := &desktopEnv{t: t, ctx: ctx, srv: srv.URL, st: st, g: g}
	e.dial = func(path string) (*websocket.Conn, *http.Response, error) {
		return websocket.Dial(ctx, wsBase+path, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	}
	owner, _, err := e.dial("/api/targets/" + itoa(id) + "/rdp?token=" + tok)
	if err != nil {
		t.Fatalf("owner dial: %v", err)
	}
	t.Cleanup(func() { owner.Close(websocket.StatusNormalClosure, "") })
	e.owner = owner
	g.nextHandshake(t)
	for {
		_, b, err := owner.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), ownerBlob) {
			break
		}
	}
	e.sid = reg.List()[0].ID
	e.bobID, e.bobTok = seedUserWithID(t, srv, "bob", "user")
	patTok := seedUser(t, srv, "pat", "approver")
	code, d := do(t, srv, "POST", "/api/sessions/"+e.sid+"/share", testAPIKey, map[string]any{"mode": "view_control", "kind": "internal", "invitee": "bob"})
	if code != http.StatusCreated {
		t.Fatalf("invite: %d %s", code, d)
	}
	code, d = do(t, srv, "POST", "/api/share-invites/"+itoa(int64(jsonMap(t, d)["id"].(float64)))+"/approve", patTok, nil)
	if code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, d)
	}
	code, d = do(t, srv, "POST", "/api/share/desktop/redeem", e.bobTok, map[string]any{"token": jsonMap(t, d)["token"]})
	if code != http.StatusOK {
		t.Fatalf("redeem: %d %s", code, d)
	}
	e.key = jsonMap(t, d)["key"].(string)
	return e
}

func (e *desktopEnv) api(method, path, tok string, body any) (int, []byte) {
	e.t.Helper()
	var buf strings.Builder
	if body != nil {
		b, _ := json.Marshal(body)
		buf.Write(b)
	}
	req, _ := http.NewRequestWithContext(e.ctx, method, e.srv+path, strings.NewReader(buf.String()))
	req.Header.Set("X-API-Key", tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out strings.Builder
	b := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(b)
		out.Write(b[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, []byte(out.String())
}

var keyPress = []byte(guacd.Instruction{Opcode: "key", Args: []string{"65", "1"}}.Encode())

// expectNothing fails if guacd receives an instruction on ch within a short window.
func expectNothing(t *testing.T, ch <-chan string, what string) {
	t.Helper()
	select {
	case op := <-ch:
		t.Fatalf("%s: guacd received %q", what, op)
	case <-time.After(300 * time.Millisecond):
	}
}

func expectOp(t *testing.T, ch <-chan string, want, what string) {
	t.Helper()
	select {
	case op := <-ch:
		if op != want {
			t.Fatalf("%s: guacd received %q, want %q", what, op, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: guacd never received %q", what, want)
	}
}

// TestDesktopShareKickCutsEveryConnection proves a kick ends EVERY WebSocket
// opened with the kicked key. The roster tracked one entry per key, so a
// second connection replaced the first's kick channel: the supervisor saw
// {"kicked":true} and an empty roster while the first socket kept the
// keyboard of a privileged desktop.
func TestDesktopShareKickCutsEveryConnection(t *testing.T) {
	e := newDesktopEnv(t)
	first, _, err := e.dial("/api/share/desktop?key=" + e.key)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close(websocket.StatusNormalClosure, "")
	e.g.nextHandshake(t)
	second, _, err := e.dial("/api/share/desktop?key=" + e.key)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(websocket.StatusNormalClosure, "")
	e.g.nextHandshake(t)

	_, d := e.api("GET", "/api/sessions/"+e.sid+"/share/roster", testAPIKey, nil)
	var roster []session.JoinedParty
	if err := json.Unmarshal(d, &roster); err != nil || len(roster) != 1 {
		t.Fatalf("roster = %s", d)
	}
	// Closing the newer connection must not take the roster entry with it.
	second.Close(websocket.StatusNormalClosure, "")
	time.Sleep(200 * time.Millisecond)
	_, d = e.api("GET", "/api/sessions/"+e.sid+"/share/roster", testAPIKey, nil)
	if err := json.Unmarshal(d, &roster); err != nil || len(roster) != 1 {
		t.Fatalf("the first connection is still attached, but the roster is %s", d)
	}
	if code, d := e.api("POST", "/api/sessions/"+e.sid+"/share/kick", testAPIKey, map[string]any{"join_id": roster[0].JoinID}); code != http.StatusOK {
		t.Fatalf("kick: %d %s", code, d)
	}
	rctx, cancel := context.WithTimeout(e.ctx, 3*time.Second)
	defer cancel()
	for {
		if _, _, err := first.Read(rctx); err != nil {
			if rctx.Err() != nil {
				t.Fatal("the first connection survived the kick")
			}
			break
		}
	}
}

// TestDesktopSuspendFreezesInput proves suspending an RDP session does what
// it reports. Since Phase 260 a desktop has a share-registry entry, so the
// suspend call answered 200 and audited session.suspended — and froze
// nothing, because a desktop's input never passed through that registry.
func TestDesktopSuspendFreezesInput(t *testing.T) {
	e := newDesktopEnv(t)
	sharer, _, err := e.dial("/api/share/desktop?key=" + e.key)
	if err != nil {
		t.Fatal(err)
	}
	defer sharer.Close(websocket.StatusNormalClosure, "")
	e.g.nextHandshake(t)

	if code, d := e.api("POST", "/api/sessions/"+e.sid+"/suspend", testAPIKey, map[string]any{}); code != http.StatusOK {
		t.Fatalf("suspend: %d %s", code, d)
	}
	sync := []byte(guacd.Instruction{Opcode: "sync", Args: []string{"7"}}.Encode())
	if err := e.owner.Write(e.ctx, websocket.MessageText, append(append([]byte{}, keyPress...), sync...)); err != nil {
		t.Fatal(err)
	}
	expectOp(t, e.g.ownerSent, "sync", "suspended owner") // keep-alive still flows; the key did not
	expectNothing(t, e.g.ownerSent, "suspended owner")
	if err := sharer.Write(e.ctx, websocket.MessageText, keyPress); err != nil {
		t.Fatal(err)
	}
	expectNothing(t, e.g.joinerSent, "suspended view_control sharer")

	if code, d := e.api("POST", "/api/sessions/"+e.sid+"/resume", testAPIKey, map[string]any{}); code != http.StatusOK {
		t.Fatalf("resume: %d %s", code, d)
	}
	if err := e.owner.Write(e.ctx, websocket.MessageText, keyPress); err != nil {
		t.Fatal(err)
	}
	expectOp(t, e.g.ownerSent, "key", "resumed owner")
}

// TestDesktopShareKeyFollowsTheUsersStanding proves an internal invitee's
// join key is only as good as the user behind it: once bob is locked, or
// loses connect on a view_control share, the key he redeemed opens nothing.
// The SSH join re-authenticates on every connection; the desktop key checked
// nothing for up to PAM_SESSION_SHARE_GUEST_TTL_MIN.
func TestDesktopShareKeyFollowsTheUsersStanding(t *testing.T) {
	e := newDesktopEnv(t)
	c, _, err := e.dial("/api/share/desktop?key=" + e.key)
	if err != nil {
		t.Fatalf("bob in good standing: %v", err)
	}
	c.Close(websocket.StatusNormalClosure, "")
	e.g.nextHandshake(t)

	if code, d := e.api("PUT", fmt.Sprintf("/api/users/%d", e.bobID), testAPIKey, map[string]any{"role": "auditor"}); code != http.StatusOK {
		t.Fatalf("demote bob: %d %s", code, d)
	}
	if _, resp, err := e.dial("/api/share/desktop?key=" + e.key); err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("view_control without connect: want 403, got err=%v", err)
	}
	auditHas(t, e.st, "session.share_join_denied", "reason:no-connect-capability")
}
