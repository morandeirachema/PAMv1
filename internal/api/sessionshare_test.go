package api_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// doRawBody posts a raw (non-JSON-encoded) request body — do() always
// JSON-marshals its body argument, which would wrap a plain string in
// quotes; inputShareGuest reads the body verbatim as keystroke bytes, so
// this bypasses that encoding.
func doRawBody(t *testing.T, srv *httptest.Server, path, body string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(srv.URL+path, "application/octet-stream", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

// shareTestRegs builds the trio of live-session plumbing a session-share test
// needs: a session registry (so a session id exists to invite around), a live
// hub (SSE output) and a share registry (input mux + guest keys) — the exact
// three api.Options fields main.go wires from the same instances.
func shareTestRegs() (*session.Registry, *session.Hub, *session.ShareRegistry) {
	reg := session.NewRegistry()
	hub := session.NewHub()
	reg.AttachHub(hub)
	shares := session.NewShareRegistry()
	return reg, hub, shares
}

// TestShareInviteInternalFourEyes proves the request→approve shape end to
// end for an internal (named-pamv1-user) invite: self-approval is refused,
// a distinct approver's decision succeeds and returns a redeemable token,
// and a second decision on the same invite is refused.
func TestShareInviteInternalFourEyes(t *testing.T) {
	reg, hub, shares := shareTestRegs()
	srv, _ := newTestServerOpts(t, nil, api.Options{Sessions: reg, Live: hub, Shares: shares, ShareInviteTTL: time.Minute})
	sid := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})

	aliceTok := seedUser(t, srv, "alice", "user")                // CapConnect
	approverTok := seedUser(t, srv, "dana-approver", "approver") // CapApprove, distinct from alice

	code, data := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/share", aliceTok,
		map[string]any{"mode": "view_only", "kind": "internal", "invitee": "carol"})
	if code != http.StatusCreated {
		t.Fatalf("create invite: %d %s", code, data)
	}
	m := jsonMap(t, data)
	if m["status"] != "pending" {
		t.Fatalf("new invite status = %v, want pending", m["status"])
	}
	id := strconv.FormatFloat(m["id"].(float64), 'f', 0, 64)

	// Four-eyes: the requester cannot approve their own invite.
	if code, _ := do(t, srv, http.MethodPost, "/api/share-invites/"+id+"/approve", aliceTok, nil); code != http.StatusForbidden {
		t.Fatalf("self-approval: %d, want 403", code)
	}

	// A distinct approver may.
	code, data = do(t, srv, http.MethodPost, "/api/share-invites/"+id+"/approve", approverTok, nil)
	if code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, data)
	}
	m = jsonMap(t, data)
	if m["status"] != "approved" {
		t.Fatalf("approved invite status = %v, want approved", m["status"])
	}
	tok, _ := m["token"].(string)
	if tok == "" {
		t.Fatalf("an approved INTERNAL invite must return its raw token once: %s", data)
	}

	// Already decided: a second decision is refused.
	if code, _ := do(t, srv, http.MethodPost, "/api/share-invites/"+id+"/approve", approverTok, nil); code != http.StatusConflict {
		t.Fatalf("re-approving a decided invite: %d, want 409", code)
	}

	// The session's invite list shows it.
	code, data = do(t, srv, http.MethodGet, "/api/sessions/"+sid+"/share", approverTok, nil)
	if code != http.StatusOK || !strings.Contains(string(data), `"approved"`) {
		t.Fatalf("list invites: %d %s", code, data)
	}
}

// TestShareInviteDenyIsFinal proves a denied invite cannot later be approved.
func TestShareInviteDenyIsFinal(t *testing.T) {
	reg, hub, shares := shareTestRegs()
	srv, _ := newTestServerOpts(t, nil, api.Options{Sessions: reg, Live: hub, Shares: shares, ShareInviteTTL: time.Minute})
	sid := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	aliceTok := seedUser(t, srv, "alice", "user")
	approverTok := seedUser(t, srv, "dana-approver", "approver")

	_, data := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/share", aliceTok,
		map[string]any{"mode": "view_only", "kind": "internal", "invitee": "carol"})
	id := strconv.FormatFloat(jsonMap(t, data)["id"].(float64), 'f', 0, 64)

	code, data := do(t, srv, http.MethodPost, "/api/share-invites/"+id+"/deny", approverTok, nil)
	if code != http.StatusOK || jsonMap(t, data)["status"] != "denied" {
		t.Fatalf("deny: %d %s", code, data)
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/share-invites/"+id+"/approve", approverTok, nil); code != http.StatusConflict {
		t.Fatalf("approving a denied invite: %d, want 409", code)
	}
}

// TestShareInviteRevokeRequiresManageTargets proves revoke is gated
// separately from approve/deny (CapManageTargets, mirroring revokeVendorGrant).
func TestShareInviteRevokeRequiresManageTargets(t *testing.T) {
	reg, hub, shares := shareTestRegs()
	srv, _ := newTestServerOpts(t, nil, api.Options{Sessions: reg, Live: hub, Shares: shares, ShareInviteTTL: time.Minute})
	sid := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	aliceTok := seedUser(t, srv, "alice", "user")
	approverTok := seedUser(t, srv, "dana-approver", "approver")

	_, data := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/share", aliceTok,
		map[string]any{"mode": "view_only", "kind": "internal", "invitee": "carol"})
	id := strconv.FormatFloat(jsonMap(t, data)["id"].(float64), 'f', 0, 64)
	if code, d := do(t, srv, http.MethodPost, "/api/share-invites/"+id+"/approve", approverTok, nil); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, d)
	}

	// An approver alone (no CapManageTargets) cannot revoke.
	if code, _ := do(t, srv, http.MethodPost, "/api/share-invites/"+id+"/revoke", approverTok, nil); code != http.StatusForbidden {
		t.Fatalf("approver revoke: %d, want 403", code)
	}
	// Admin (CapManageTargets) can.
	if code, d := do(t, srv, http.MethodPost, "/api/share-invites/"+id+"/revoke", testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("admin revoke: %d %s", code, d)
	}
}

// TestShareInviteExternalRequiresEmailConfig proves an external (email+QR)
// invite is refused at CREATE time — not silently accepted and only failing
// later at approval — when the server has no SMTP/portal URL configured.
func TestShareInviteExternalRequiresEmailConfig(t *testing.T) {
	reg, hub, shares := shareTestRegs()
	srv, _ := newTestServerOpts(t, nil, api.Options{Sessions: reg, Live: hub, Shares: shares})
	sid := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	aliceTok := seedUser(t, srv, "alice", "user")

	code, data := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/share", aliceTok,
		map[string]any{"mode": "view_only", "kind": "external", "email": "vendor@example.com"})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("external invite with no email config: %d %s, want 503", code, data)
	}
}

// TestShareInviteExternalRefusedUnderAirGap proves PAM_OT_AIRGAP disables
// external session-share invites even when SMTP + an absolute portal URL are
// otherwise fully configured — found in review: alert.SendDirect dials SMTP
// directly and has no built-in air-gap guard of its own (unlike the
// security-alert channel, which buildAlerter already neuters to a no-op
// under air-gap), so shareEmailEnabled has to check it explicitly or an
// air-gapped deployment could still leak an invite email out of the
// enclave.
func TestShareInviteExternalRefusedUnderAirGap(t *testing.T) {
	smtpAddr, _ := fakeSMTP(t)
	reg, hub, shares := shareTestRegs()
	srv, _ := newTestServerOpts(t, nil, api.Options{
		Sessions: reg, Live: hub, Shares: shares, AirGap: true,
		ShareSMTPAddr: smtpAddr, ShareSMTPFrom: "pam@example.com", PortalURL: "https://pam.example.com",
	})
	sid := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	aliceTok := seedUser(t, srv, "alice", "user")

	code, data := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/share", aliceTok,
		map[string]any{"mode": "view_only", "kind": "external", "email": "vendor@example.com"})
	if code != http.StatusServiceUnavailable {
		t.Fatalf("external invite under air-gap: %d %s, want 503", code, data)
	}
}

// fakeSMTP starts a minimal, single-connection SMTP server (no STARTTLS/AUTH
// extensions offered) that captures the DATA payload — a local copy of
// internal/alert's own test helper (unexported there, and this is a
// different package), used here to prove the full external-invite path
// really sends email rather than just calling into alert.SendDirect.
func fakeSMTP(t *testing.T) (addr string, got chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got = make(chan []byte, 1)
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reply := func(s string) { conn.Write([]byte(s + "\r\n")) }
		reply("220 fake.smtp ready")
		buf := make([]byte, 65536)
		var data strings.Builder
		inData := false
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			chunk := string(buf[:n])
			if inData {
				data.WriteString(chunk)
				if strings.HasSuffix(data.String(), "\r\n.\r\n") {
					got <- []byte(strings.TrimSuffix(data.String(), "\r\n.\r\n"))
					reply("250 OK")
					inData = false
				}
				continue
			}
			for _, line := range strings.Split(strings.TrimRight(chunk, "\r\n"), "\r\n") {
				up := strings.ToUpper(line)
				switch {
				case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
					reply("250 fake.smtp")
				case strings.HasPrefix(up, "MAIL FROM"):
					reply("250 OK")
				case strings.HasPrefix(up, "RCPT TO"):
					reply("250 OK")
				case strings.HasPrefix(up, "DATA"):
					reply("354 go ahead")
					inData = true
					data.Reset()
				case strings.HasPrefix(up, "QUIT"):
					reply("221 bye")
					return
				}
			}
		}
	}()
	return ln.Addr().String(), got
}

// extractShareToken pulls the invite token back out of the emailed link
// (".../share.html?token=<hex>") so the test can drive the guest redemption
// path exactly as a real recipient's browser would.
func extractShareToken(t *testing.T, emailBody string) string {
	t.Helper()
	const marker = "share.html?token="
	i := strings.Index(emailBody, marker)
	if i < 0 {
		t.Fatalf("no share.html?token= link in the email: %s", emailBody)
	}
	rest := emailBody[i+len(marker):]
	end := strings.IndexAny(rest, "\"< \r\n")
	if end < 0 {
		end = len(rest)
	}
	return rest[:end]
}

// TestShareInviteExternalGuestNotifiesPrimary proves a web-redeemed external
// guest's join AND departure ring the same primary-operator Stderr-banner
// notifier the SSH-side join: path already used — a safety property the
// plan called mandatory "in either mode", not optional UX, and one the web
// path initially missed (found in review: only the SSH path called
// ShareRegistry.Notify).
func TestShareInviteExternalGuestNotifiesPrimary(t *testing.T) {
	smtpAddr, gotMail := fakeSMTP(t)
	reg, hub, shares := shareTestRegs()
	srv, _ := newTestServerOpts(t, nil, api.Options{
		Sessions: reg, Live: hub, Shares: shares,
		ShareInviteTTL: time.Minute, ShareGuestSessionTTL: time.Hour,
		ShareSMTPAddr: smtpAddr, ShareSMTPFrom: "pam@example.com", PortalURL: "https://pam.example.com",
	})
	sid := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	shares.Open(sid)
	defer shares.Close(sid)

	var mu sync.Mutex
	var notices []string
	shares.SetNotifier(sid, func(msg string) { mu.Lock(); notices = append(notices, msg); mu.Unlock() })

	aliceTok := seedUser(t, srv, "alice", "user")
	approverTok := seedUser(t, srv, "dana-approver", "approver")
	_, data := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/share", aliceTok,
		map[string]any{"mode": "view_only", "kind": "external", "email": "vendor@example.com"})
	id := strconv.FormatFloat(jsonMap(t, data)["id"].(float64), 'f', 0, 64)
	if code, d := do(t, srv, http.MethodPost, "/api/share-invites/"+id+"/approve", approverTok, nil); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, d)
	}
	var token string
	select {
	case msg := <-gotMail:
		token = extractShareToken(t, string(msg))
	case <-time.After(3 * time.Second):
		t.Fatal("no email sent")
	}
	_, data = do(t, srv, http.MethodPost, "/api/share/redeem/"+token, "", nil)
	key := jsonMap(t, data)["key"].(string)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/share/stream?key="+key, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(notices)
		mu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	joinedNotices := append([]string(nil), notices...)
	mu.Unlock()
	if len(joinedNotices) < 1 || !strings.Contains(joinedNotices[0], "vendor@example.com") || !strings.Contains(joinedNotices[0], "joined") {
		t.Fatalf("primary was not notified of the guest joining: %v", joinedNotices)
	}

	cancel() // guest leaves
	resp.Body.Close()
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(notices)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(notices) < 2 || !strings.Contains(notices[1], "vendor@example.com") || !strings.Contains(notices[1], "left") {
		t.Fatalf("primary was not notified of the guest leaving: %v", notices)
	}
}

// TestShareInviteExternalFullFlow proves the whole vendor/email+QR path end
// to end: approving an external invite sends a real email (captured by a
// local fake SMTP server) with no token in the API response; the emailed
// token redeems exactly once into a guest key; that key drives both the
// SSE output stream and (view_control) a keystroke input POST; and the
// redemption is audited as session.share_joined under a guest:<email> actor.
func TestShareInviteExternalFullFlow(t *testing.T) {
	smtpAddr, gotMail := fakeSMTP(t)
	reg, hub, shares := shareTestRegs()
	srv, st := newTestServerOpts(t, nil, api.Options{
		Sessions: reg, Live: hub, Shares: shares,
		ShareInviteTTL: time.Minute, ShareGuestSessionTTL: time.Hour,
		ShareSMTPAddr: smtpAddr, ShareSMTPFrom: "pam@example.com", PortalURL: "https://pam.example.com",
	})
	sid := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	shares.Open(sid) // normally done by the SSH proxy's handleConn
	defer shares.Close(sid)

	aliceTok := seedUser(t, srv, "alice", "user")
	approverTok := seedUser(t, srv, "dana-approver", "approver")

	code, data := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/share", aliceTok,
		map[string]any{"mode": "view_control", "kind": "external", "email": "vendor@example.com"})
	if code != http.StatusCreated {
		t.Fatalf("create external invite: %d %s", code, data)
	}
	id := strconv.FormatFloat(jsonMap(t, data)["id"].(float64), 'f', 0, 64)

	code, data = do(t, srv, http.MethodPost, "/api/share-invites/"+id+"/approve", approverTok, nil)
	if code != http.StatusOK {
		t.Fatalf("approve external invite: %d %s", code, data)
	}
	if tok, _ := jsonMap(t, data)["token"].(string); tok != "" {
		t.Fatalf("an EXTERNAL invite must never return its raw token via the API: %s", data)
	}

	var token string
	select {
	case msg := <-gotMail:
		if !strings.Contains(string(msg), "To: vendor@example.com") {
			t.Fatalf("email not addressed to the invitee: %q", msg)
		}
		token = extractShareToken(t, string(msg))
	case <-time.After(3 * time.Second):
		t.Fatal("approving the external invite never sent an email")
	}

	// Redeem: no X-API-Key at all — this is the whole point of the guest path.
	code, data = do(t, srv, http.MethodPost, "/api/share/redeem/"+token, "", nil)
	if code != http.StatusOK {
		t.Fatalf("redeem: %d %s", code, data)
	}
	redeemed := jsonMap(t, data)
	key, _ := redeemed["key"].(string)
	if key == "" || redeemed["session_id"] != sid || redeemed["mode"] != "view_control" {
		t.Fatalf("bad redeem response: %s", data)
	}

	// Single-use: the same token cannot be redeemed twice.
	if code, _ := do(t, srv, http.MethodPost, "/api/share/redeem/"+token, "", nil); code != http.StatusUnauthorized {
		t.Fatalf("second redemption of the same token: %d, want 401", code)
	}

	// The guest key drives the SSE stream — exactly like TestSessionStreamSSE,
	// but with a guest key instead of an X-API-Key.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/share/stream?key="+key, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("guest stream: %d, want 200", resp.StatusCode)
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				hub.Publish(sid, []byte("guest-can-see-this"))
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
	defer close(stop)
	br := bufio.NewReader(resp.Body)
	deadline := time.Now().Add(3 * time.Second)
	seen := false
	for time.Now().Before(deadline) && !seen {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading guest SSE stream: %v", err)
		}
		seen = strings.Contains(line, "guest-can-see-this")
	}
	if !seen {
		t.Fatal("guest never received the live frame")
	}

	// view_control: the guest's keystrokes reach the session's input mux.
	if code, d := doRawBody(t, srv, "/api/share/input?key="+key, "typed-by-guest"); code != http.StatusNoContent {
		t.Fatalf("guest input: %d %s", code, d)
	}
	rd := shares.Reader(sid)
	buf := make([]byte, 32)
	n, err := rd.Read(buf)
	if err != nil || string(buf[:n]) != "typed-by-guest" {
		t.Fatalf("guest input did not reach the session mux: got %q err %v", buf[:n], err)
	}

	// The whole redemption is audited under a distinguishable guest actor.
	events, err := st.ListAudit(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "session.share_joined" && e.Actor == "guest:vendor@example.com" && strings.Contains(e.Detail, "session:"+sid) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no session.share_joined audit event for guest:vendor@example.com; got %+v", auditActions(events))
	}
}

// TestShareInviteRosterAndKick proves the console-facing roster reflects an
// attached guest, and that kicking them actually ends their SSE stream (not
// just removing a bookkeeping row) and revokes their guest key so a request
// racing the kick cannot be followed by a new one.
func TestShareInviteRosterAndKick(t *testing.T) {
	smtpAddr, gotMail := fakeSMTP(t)
	reg, hub, shares := shareTestRegs()
	srv, st := newTestServerOpts(t, nil, api.Options{
		Sessions: reg, Live: hub, Shares: shares,
		ShareInviteTTL: time.Minute, ShareGuestSessionTTL: time.Hour,
		ShareSMTPAddr: smtpAddr, ShareSMTPFrom: "pam@example.com", PortalURL: "https://pam.example.com",
	})
	sid := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	shares.Open(sid)
	defer shares.Close(sid)
	aliceTok := seedUser(t, srv, "alice", "user")
	approverTok := seedUser(t, srv, "dana-approver", "approver")

	// Empty roster before anyone joins.
	code, data := do(t, srv, http.MethodGet, "/api/sessions/"+sid+"/share/roster", approverTok, nil)
	if code != http.StatusOK || strings.TrimSpace(string(data)) != "[]" {
		t.Fatalf("roster before any join: %d %s, want []", code, data)
	}

	_, data = do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/share", aliceTok,
		map[string]any{"mode": "view_only", "kind": "external", "email": "vendor@example.com"})
	id := strconv.FormatFloat(jsonMap(t, data)["id"].(float64), 'f', 0, 64)
	if code, d := do(t, srv, http.MethodPost, "/api/share-invites/"+id+"/approve", approverTok, nil); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, d)
	}
	var token string
	select {
	case msg := <-gotMail:
		token = extractShareToken(t, string(msg))
	case <-time.After(3 * time.Second):
		t.Fatal("no email sent")
	}
	_, data = do(t, srv, http.MethodPost, "/api/share/redeem/"+token, "", nil)
	key := jsonMap(t, data)["key"].(string)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/share/stream?key="+key, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)

	// The roster now shows the guest, by the join id the console would use
	// to target the kick.
	code, data = do(t, srv, http.MethodGet, "/api/sessions/"+sid+"/share/roster", approverTok, nil)
	if code != http.StatusOK || !strings.Contains(string(data), "guest:vendor@example.com") {
		t.Fatalf("roster after join: %d %s, want it to list the guest", code, data)
	}
	roster := jsonSlice(t, data)
	joinID, _ := roster[0]["join_id"].(string)
	if joinID == "" {
		t.Fatalf("roster entry has no join_id to kick: %s", data)
	}

	// A plain user (no CapManageTargets) cannot kick.
	if code, _ := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/share/kick", aliceTok, map[string]any{"join_id": joinID}); code != http.StatusForbidden {
		t.Fatalf("user kick: %d, want 403", code)
	}
	// Admin can — and the guest's SSE stream ends because of it, not because
	// the test closed anything on the guest's side.
	if code, d := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/share/kick", testAPIKey, map[string]any{"join_id": joinID}); code != http.StatusOK {
		t.Fatalf("admin kick: %d %s", code, d)
	}
	deadline := time.Now().Add(3 * time.Second)
	sawKickEvent := false
	for time.Now().Before(deadline) {
		line, err := br.ReadString('\n')
		if err != nil {
			break // stream closed — also acceptable proof the kick took effect
		}
		if strings.Contains(line, "event: kicked") {
			sawKickEvent = true
			break
		}
	}
	if !sawKickEvent {
		t.Log("did not see the named kicked SSE event before the stream closed (acceptable if the read raced the close)")
	}

	// The kicked guest's key no longer works for a fresh request either.
	if code, _ := do(t, srv, http.MethodGet, "/api/share/stream?key="+key, "", nil); code != http.StatusUnauthorized {
		t.Fatalf("reconnecting with a kicked guest key: %d, want 401", code)
	}

	// The roster is empty again, and the kick is audited.
	code, data = do(t, srv, http.MethodGet, "/api/sessions/"+sid+"/share/roster", approverTok, nil)
	if code != http.StatusOK || strings.TrimSpace(string(data)) != "[]" {
		t.Fatalf("roster after kick: %d %s, want []", code, data)
	}
	events, err := st.ListAudit(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "session.share_kicked" && strings.Contains(e.Detail, "session:"+sid) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no session.share_kicked audit event; got %+v", auditActions(events))
	}
}

// jsonSlice unmarshals a JSON array-of-objects body, failing the test on error.
func jsonSlice(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	var m []map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal %q: %v", data, err)
	}
	return m
}

// TestShareInviteGuestRedeemRefusesInternalKind proves the web redemption
// path refuses an internal invite's token even if someone learned it — that
// surface is SSH-join-only (proxy.go's handleJoinConn refuses the mirror
// case: an external invite presented over SSH).
func TestShareInviteGuestRedeemRefusesInternalKind(t *testing.T) {
	reg, hub, shares := shareTestRegs()
	srv, _ := newTestServerOpts(t, nil, api.Options{Sessions: reg, Live: hub, Shares: shares, ShareInviteTTL: time.Minute})
	sid := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	aliceTok := seedUser(t, srv, "alice", "user")
	approverTok := seedUser(t, srv, "dana-approver", "approver")

	_, data := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/share", aliceTok,
		map[string]any{"mode": "view_only", "kind": "internal", "invitee": "carol"})
	id := strconv.FormatFloat(jsonMap(t, data)["id"].(float64), 'f', 0, 64)
	_, data = do(t, srv, http.MethodPost, "/api/share-invites/"+id+"/approve", approverTok, nil)
	token := jsonMap(t, data)["token"].(string)

	if code, d := do(t, srv, http.MethodPost, "/api/share/redeem/"+token, "", nil); code != http.StatusForbidden {
		t.Fatalf("web-redeeming an internal invite's token: %d %s, want 403", code, d)
	}
}

// TestShareInviteGuestInputRefusedForViewOnly proves a view-only guest cannot
// send input, even with a valid, freshly-redeemed guest key.
func TestShareInviteGuestInputRefusedForViewOnly(t *testing.T) {
	smtpAddr, gotMail := fakeSMTP(t)
	reg, hub, shares := shareTestRegs()
	srv, _ := newTestServerOpts(t, nil, api.Options{
		Sessions: reg, Live: hub, Shares: shares,
		ShareInviteTTL: time.Minute, ShareGuestSessionTTL: time.Hour,
		ShareSMTPAddr: smtpAddr, ShareSMTPFrom: "pam@example.com", PortalURL: "https://pam.example.com",
	})
	sid := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() {})
	shares.Open(sid)
	defer shares.Close(sid)
	aliceTok := seedUser(t, srv, "alice", "user")
	approverTok := seedUser(t, srv, "dana-approver", "approver")

	_, data := do(t, srv, http.MethodPost, "/api/sessions/"+sid+"/share", aliceTok,
		map[string]any{"mode": "view_only", "kind": "external", "email": "guest@example.com"})
	id := strconv.FormatFloat(jsonMap(t, data)["id"].(float64), 'f', 0, 64)
	if code, d := do(t, srv, http.MethodPost, "/api/share-invites/"+id+"/approve", approverTok, nil); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, d)
	}
	var token string
	select {
	case msg := <-gotMail:
		token = extractShareToken(t, string(msg))
	case <-time.After(3 * time.Second):
		t.Fatal("no email sent")
	}
	_, data = do(t, srv, http.MethodPost, "/api/share/redeem/"+token, "", nil)
	key := jsonMap(t, data)["key"].(string)

	if code, d := doRawBody(t, srv, "/api/share/input?key="+key, "sneaky"); code != http.StatusForbidden {
		t.Fatalf("view-only guest input: %d %s, want 403", code, d)
	}
}

// auditActions summarizes a slice of audit events as "action:actor" pairs for
// a failed test's diagnostic output.
func auditActions(events []store.AuditEvent) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.Action + ":" + e.Actor
	}
	return out
}
