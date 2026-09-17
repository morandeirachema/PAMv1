package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/guacd"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestDesktopShare drives Phase 260 end to end against a fake guacd: an
// operator's live RDP session is shared through the Phase 116 invite
// workflow. An internal view_control invite is redeemed in the portal by its
// invitee (a wrong user burns it), joins guacd WITH input, and only keyboard,
// mouse and keep-alive pass — never a clipboard stream; the text-stream
// guest routes refuse a desktop; the join is on the roster and a kick ends
// it and revokes its key. An external view_only guest redeems the emailed
// token and is joined read-only.
func TestDesktopShare(t *testing.T) {
	g := newJoinGuacd(t, 0)
	reg, shares := session.NewRegistry(), session.NewShareRegistry()
	srv, st := newTestServerOpts(t, nil, api.Options{
		GuacdAddr: g.addr, Sessions: reg, Live: session.NewHub(), Shares: shares,
		ShareInviteTTL: time.Minute, ShareGuestSessionTTL: time.Minute,
	})
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
	gdial := func(path string) (*websocket.Conn, *http.Response, error) {
		return websocket.Dial(ctx, wsBase+path, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	}
	owner, _, err := gdial("/api/targets/" + itoa(id) + "/rdp?token=" + tok)
	if err != nil {
		t.Fatalf("owner dial: %v", err)
	}
	defer owner.Close(websocket.StatusNormalClosure, "")
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
	live := reg.List()
	if len(live) != 1 {
		t.Fatalf("live sessions = %+v", live)
	}
	sid := live[0].ID

	bobTok := seedUser(t, srv, "bob", "user")
	carlTok := seedUser(t, srv, "carl", "user")
	patTok := seedUser(t, srv, "pat", "approver")
	mintInternal := func(mode string) string {
		t.Helper()
		code, d := do(t, srv, "POST", "/api/sessions/"+sid+"/share", testAPIKey, map[string]any{"mode": mode, "kind": "internal", "invitee": "bob"})
		if code != http.StatusCreated {
			t.Fatalf("file invite: %d %s", code, d)
		}
		invID := int64(jsonMap(t, d)["id"].(float64))
		code, d = do(t, srv, "POST", "/api/share-invites/"+itoa(invID)+"/approve", patTok, nil)
		if code != http.StatusOK {
			t.Fatalf("approve invite: %d %s", code, d)
		}
		return jsonMap(t, d)["token"].(string)
	}

	// A wrong user redeeming burns the token: bob cannot use it afterwards.
	burned := mintInternal("view_control")
	if code, _ := do(t, srv, "POST", "/api/share/desktop/redeem", carlTok, map[string]any{"token": burned}); code != http.StatusForbidden {
		t.Fatalf("wrong invitee: want 403, got %d", code)
	}
	auditHas(t, st, "session.share_join_denied", "reason:invitee-mismatch")
	if code, _ := do(t, srv, "POST", "/api/share/desktop/redeem", bobTok, map[string]any{"token": burned}); code != http.StatusForbidden {
		t.Fatalf("a burned token: want 403, got %d", code)
	}

	// bob redeems his own view_control invite.
	code, d := do(t, srv, "POST", "/api/share/desktop/redeem", bobTok, map[string]any{"token": mintInternal("view_control")})
	if code != http.StatusOK {
		t.Fatalf("redeem: %d %s", code, d)
	}
	var red struct{ Key, Mode, Protocol string }
	_ = json.Unmarshal(d, &red)
	if red.Key == "" || red.Mode != "view_control" || red.Protocol != "rdp" {
		t.Fatalf("redeem = %s", d)
	}
	auditHas(t, st, "session.share_joined", "session:"+sid+" mode:view_control")

	// The text-stream guest routes refuse a desktop rather than hang on it.
	if code, _ := do(t, srv, "GET", "/api/share/stream?key="+red.Key, "", nil); code != http.StatusConflict {
		t.Errorf("text stream for a desktop: want 409, got %d", code)
	}
	if code, _ := do(t, srv, "POST", "/api/share/input?key="+red.Key, "", nil); code != http.StatusConflict {
		t.Errorf("text input for a desktop: want 409, got %d", code)
	}

	sharer, _, err := gdial("/api/share/desktop?key=" + red.Key)
	if err != nil {
		t.Fatalf("sharer dial: %v", err)
	}
	defer sharer.Close(websocket.StatusNormalClosure, "")
	h := g.nextHandshake(t)
	if h[0][0] != "$owner-conn" || h[1][4] != "" || h[1][3] != "" {
		t.Fatalf("control join: select %v connect %v; want the owner's connection, no read-only, no credential", h[0], h[1])
	}
	auditHas(t, st, "session.monitor", "session:"+sid+" protocol:rdp target:win-rdp actor:bootstrap-admin via:share mode:view_control")

	batch := guacd.Instruction{Opcode: "key", Args: []string{"65", "1"}}.Encode() +
		guacd.Instruction{Opcode: "clipboard", Args: []string{"3", "text/plain"}}.Encode() +
		guacd.Instruction{Opcode: "blob", Args: []string{"3", "c2VjcmV0"}}.Encode() +
		guacd.Instruction{Opcode: "mouse", Args: []string{"5", "5", "0"}}.Encode() +
		guacd.Instruction{Opcode: "sync", Args: []string{"1000"}}.Encode()
	if err := sharer.Write(ctx, websocket.MessageText, []byte(batch)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"key", "mouse", "sync"} {
		select {
		case op := <-g.joinerSent:
			if op != want {
				t.Fatalf("guacd received %q from the control sharer, want %q", op, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("guacd never received %q", want)
		}
	}
	select {
	case op := <-g.joinerSent:
		t.Fatalf("guacd received an extra %q (a clipboard stream must not pass)", op)
	case <-time.After(200 * time.Millisecond):
	}

	// On the roster; a kick ends the join and revokes the key.
	code, d = do(t, srv, "GET", "/api/sessions/"+sid+"/share/roster", testAPIKey, nil)
	var roster []session.JoinedParty
	if err := json.Unmarshal(d, &roster); code != http.StatusOK || err != nil || len(roster) != 1 || roster[0].Actor != "bob" || roster[0].Mode != "view_control" {
		t.Fatalf("roster = %d %s", code, d)
	}
	if code, d := do(t, srv, "POST", "/api/sessions/"+sid+"/share/kick", testAPIKey, map[string]any{"join_id": roster[0].JoinID}); code != http.StatusOK {
		t.Fatalf("kick: %d %s", code, d)
	}
	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	defer rcancel()
	for {
		if _, _, err := sharer.Read(rctx); err != nil {
			if rctx.Err() != nil {
				t.Fatal("a kicked sharer's WebSocket stayed open")
			}
			break
		}
	}
	if _, resp, err := gdial("/api/share/desktop?key=" + red.Key); err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a kicked key: want 401, got err=%v", err)
	}

	// An external guest, view only: redeemed from the emailed token, joined read-only.
	const guestToken = "external-desktop-token"
	inv := store.SessionShareInvite{SessionID: sid, Mode: "view_only", Kind: "external", Email: "vendor@example.com", Status: "pending", Requester: "bootstrap-admin"}
	if err := st.CreateSessionShareInvite(context.Background(), &inv); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Minute)
	if err := st.DecideSessionShareInvite(context.Background(), inv.ID, "approved", "pat", time.Now(), auth.TokenHash(guestToken), &exp); err != nil {
		t.Fatal(err)
	}
	code, d = do(t, srv, "POST", "/api/share/redeem/"+guestToken, "", nil)
	var guest struct{ Key, Protocol string }
	if _ = json.Unmarshal(d, &guest); code != http.StatusOK || guest.Protocol != "rdp" {
		t.Fatalf("guest redeem: %d %s", code, d)
	}
	viewer, _, err := gdial("/api/share/desktop?key=" + guest.Key)
	if err != nil {
		t.Fatalf("guest dial: %v", err)
	}
	defer viewer.Close(websocket.StatusNormalClosure, "")
	if h := g.nextHandshake(t); h[1][4] != "true" {
		t.Fatalf("a view_only guest must join read-only: %v", h[1])
	}
	auditHas(t, st, "session.monitor", "actor:bootstrap-admin via:share mode:view_only")
	if err := viewer.Write(ctx, websocket.MessageText, []byte(guacd.Instruction{Opcode: "key", Args: []string{"65", "1"}}.Encode()+guacd.Instruction{Opcode: "sync", Args: []string{"1"}}.Encode())); err != nil {
		t.Fatal(err)
	}
	select {
	case op := <-g.joinerSent:
		if op != "sync" {
			t.Fatalf("a view_only guest sent %q to guacd", op)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the guest's sync never reached guacd")
	}

	// The session ends: the share ends with it, and its keys stop resolving.
	owner.Close(websocket.StatusNormalClosure, "")
	vctx, vcancel := context.WithTimeout(ctx, 5*time.Second)
	defer vcancel()
	for {
		if _, _, err := viewer.Read(vctx); err != nil {
			if vctx.Err() != nil {
				t.Fatal("the share outlived the session")
			}
			break
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, _, _, ok := shares.ResolveGuestKey(guest.Key); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a guest key still resolves after its session ended")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
