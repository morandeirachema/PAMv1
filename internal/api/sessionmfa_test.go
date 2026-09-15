package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/mfa"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// smfaDo is do() with a session-MFA ticket in its own header ("" sends none).
func smfaDo(t *testing.T, srv *httptest.Server, method, path, apiKey, ticket string, body any) (int, map[string]any) {
	t.Helper()
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", apiKey)
	if ticket != "" {
		req.Header.Set("X-PAM-Session-MFA", ticket)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	_ = json.Unmarshal(data, &m)
	return resp.StatusCode, m
}

// smfaTarget creates a target as the bootstrap admin, extra overriding the
// defaults, and returns its id.
func smfaTarget(t *testing.T, srv *httptest.Server, name, protocol string, extra map[string]any) int64 {
	t.Helper()
	body := map[string]any{"name": name, "host": "10.0.0.5", "os_type": "linux", "protocol": protocol}
	for k, v := range extra {
		body[k] = v
	}
	code, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, body)
	if code != http.StatusCreated {
		t.Fatalf("create target %s: %d %s", name, code, data)
	}
	return int64(jsonMap(t, data)["id"].(float64))
}

// smfaCred vaults a credential for targetID and returns its id.
func smfaCred(t *testing.T, srv *httptest.Server, targetID int64, user, secret string) int64 {
	t.Helper()
	code, data := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey,
		map[string]any{"target_id": targetID, "username": user, "secret": secret})
	if code != http.StatusCreated {
		t.Fatalf("create credential: %d %s", code, data)
	}
	return int64(jsonMap(t, data)["id"].(float64))
}

// smfaTicket writes the ticket row a verified mint writes, so a test can hold
// as many tickets as it needs without spending a TOTP step per ticket.
func smfaTicket(t *testing.T, st store.Store, user, role string, targetID int64) string {
	t.Helper()
	tok := "ticket-" + user + "-" + itoa(targetID) + "-" + itoa(time.Now().UnixNano())
	if err := st.CreateSession(context.Background(), &store.Session{Username: user, Role: role, Scope: auth.SessionScopeSessionMFA,
		TokenHash: auth.TokenHash(tok), ExpiresAt: time.Now().Add(2 * time.Minute), TargetID: &targetID}); err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestSessionMFATicketMint proves POST /api/session-mfa (Phase 244) mints a
// ticket only for a real target and a right, unspent code — a TOTP code once
// per step, a recovery code once ever — audits both outcomes, tells a user with
// no one-time-code factor where to go instead, and that the ticket it returns
// is refused as an API key everywhere, its own mint route included.
func TestSessionMFATicketMint(t *testing.T) {
	ctx := context.Background()
	srv, st := newTestServerOpts(t, nil, api.Options{})
	tid := smfaTarget(t, srv, "web-01", "ssh", nil)
	aliceTok := seedUser(t, srv, "alice", "user")
	secret := enrollMFA(t, srv, aliceTok) // confirming the factor spends the current time step

	mint := func(tok string, body map[string]any) (int, map[string]any) {
		t.Helper()
		return smfaDo(t, srv, http.MethodPost, "/api/session-mfa", tok, "", body)
	}
	if code, m := mint(aliceTok, map[string]any{"otp": "123456"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("no target: %d %v", code, m)
	}
	if code, m := mint(aliceTok, map[string]any{"target": "nope", "otp": "123456"}); code != http.StatusNotFound {
		t.Fatalf("unknown target: %d %v", code, m)
	}
	if code, m := mint(aliceTok, map[string]any{"target": "web-01"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("no code: %d %v", code, m)
	}
	if code, m := mint(aliceTok, map[string]any{"target": "web-01", "otp": "not-a-code"}); code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d %v", code, m)
	}
	auditHas(t, st, "session.mfa_failed", "target:web-01 factor:otp")

	next, err := mfa.Code(secret, time.Now().Add(30*time.Second)) // the next step, inside the skew window
	if err != nil {
		t.Fatal(err)
	}
	code, m := mint(aliceTok, map[string]any{"target": "web-01", "otp": next})
	if code != http.StatusCreated || m["factor"] != "totp" || m["target_id"] != float64(tid) {
		t.Fatalf("mint: %d %v", code, m)
	}
	ticket, _ := m["ticket"].(string)
	if ticket == "" {
		t.Fatal("no ticket returned")
	}
	auditHas(t, st, "session.mfa_ticket", "target:web-01 factor:totp ttl:2m0s")
	if code, _ := mint(aliceTok, map[string]any{"target": "web-01", "otp": next}); code != http.StatusUnauthorized {
		t.Fatalf("a replayed code minted a second ticket: %d", code)
	}

	// A ticket is not an API key: not for inventory, not for /me, not to mint
	// its own successor.
	for _, path := range []string{"/api/targets", "/api/me"} {
		if code, _ := do(t, srv, http.MethodGet, path, ticket, nil); code != http.StatusForbidden {
			t.Fatalf("ticket as X-API-Key on %s: %d, want 403", path, code)
		}
	}
	if code, _ := mint(ticket, map[string]any{"target": "web-01", "otp": next}); code != http.StatusForbidden {
		t.Fatalf("a ticket minting a ticket: %d, want 403", code)
	}
	auditHas(t, st, "authz.denied", "reason:session-mfa-ticket")

	// A recovery code stands in for the TOTP code — once.
	const recovery = "abcdef-ghijkl-mnopqr-stuvwx"
	if err := st.ReplaceMFARecoveryCodes(ctx, "alice", []string{auth.TokenHash(recovery)}); err != nil {
		t.Fatal(err)
	}
	if code, m := mint(aliceTok, map[string]any{"target": "web-01", "otp": recovery}); code != http.StatusCreated || m["factor"] != "recovery" {
		t.Fatalf("recovery code: %d %v", code, m)
	}
	auditHas(t, st, "mfa.recovery_used", "user:alice")
	if code, _ := mint(aliceTok, map[string]any{"target": "web-01", "otp": recovery}); code != http.StatusUnauthorized {
		t.Fatalf("a spent recovery code minted again: %d", code)
	}

	// No one-time-code factor: told to use a security key instead.
	bobTok := seedUser(t, srv, "bob", "user")
	if code, m := mint(bobTok, map[string]any{"target": "web-01", "otp": "123456"}); code != http.StatusUnprocessableEntity ||
		!strings.Contains(m["error"].(string), "webauthn") {
		t.Fatalf("bob with no factor: %d %v", code, m)
	}
}

// TestSessionMFAEnrollOnlyCannotMint proves an enrollment-only session — the
// one narrow scope `authenticated` admits — cannot trade a freshly confirmed
// factor for a ticket, which resolves to the user's FULL role.
func TestSessionMFAEnrollOnlyCannotMint(t *testing.T) {
	srv, _ := newTestServerOpts(t, fakeAuthenticator{username: "ad-alice", password: "pw", role: auth.RoleUser},
		api.Options{MFARequired: true})
	smfaTarget(t, srv, "web-01", "ssh", nil)
	_, data := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "pw"})
	enrollTok, _ := jsonMap(t, data)["token"].(string)
	secret := enrollMFA(t, srv, enrollTok)
	next, _ := mfa.Code(secret, time.Now().Add(30*time.Second))
	if code, m := smfaDo(t, srv, http.MethodPost, "/api/session-mfa", enrollTok, "", map[string]any{"target": "web-01", "otp": next}); code != http.StatusForbidden {
		t.Fatalf("enroll-only mint: %d %v, want 403", code, m)
	}
}

// TestSessionMFARESTAccessPaths proves the REST paths that hand access to a
// target take the gate between target authorization and approval: reveal and
// checkout refuse without a ticket (403 with session_mfa_required, audited
// under the path's own action) and deliver with one — once; a ticket for
// another target is refused and burned; another identity's ticket is refused
// and left alone; break-glass bypasses; a WinRM run neither runs nor reaches
// the runner without one; and a target that does not require it is untouched.
func TestSessionMFARESTAccessPaths(t *testing.T) {
	ctx := context.Background()
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	srv, st := newTestServerOpts(t, nil, api.Options{WinRM: fake, RecordingDir: t.TempDir()})
	guarded := smfaTarget(t, srv, "db-01", "ssh", map[string]any{"require_session_mfa": true})
	open := smfaTarget(t, srv, "db-02", "ssh", nil)
	gcred := smfaCred(t, srv, guarded, "root", secretPassword)
	ocred := smfaCred(t, srv, open, "root", secretPassword)
	aliceTok := seedUser(t, srv, "alice", "admin")
	reveal := func(key string, cid int64, ticket string) (int, map[string]any) {
		t.Helper()
		return smfaDo(t, srv, http.MethodPost, "/api/credentials/"+itoa(cid)+"/reveal", key, ticket, nil)
	}

	code, m := reveal(aliceTok, gcred, "")
	if code != http.StatusForbidden || m["session_mfa_required"] != true || m["reason"] != "session-mfa-required" {
		t.Fatalf("reveal with no ticket: %d %v", code, m)
	}
	auditHas(t, st, "credential.reveal_denied", "target:db-01 reason:session-mfa-required")

	ticket := smfaTicket(t, st, "alice", "admin", guarded)
	if code, m := reveal(aliceTok, gcred, ticket); code != http.StatusOK || m["secret"] != secretPassword {
		t.Fatalf("reveal with a ticket: %d %v", code, m)
	}
	auditHas(t, st, "session.mfa_verified", "target:db-01 factor:ticket path:credential.reveal")
	if code, m := reveal(aliceTok, gcred, ticket); code != http.StatusForbidden || m["reason"] != "session-mfa-ticket-invalid" {
		t.Fatalf("a spent ticket: %d %v", code, m)
	}

	wrong := smfaTicket(t, st, "alice", "admin", open)
	if code, m := reveal(aliceTok, gcred, wrong); code != http.StatusForbidden || m["reason"] != "session-mfa-ticket-target" {
		t.Fatalf("another target's ticket: %d %v", code, m)
	}
	if _, err := st.GetSessionByTokenHash(ctx, auth.TokenHash(wrong)); err == nil {
		t.Fatal("a ticket shown to the wrong target must be burned")
	}
	bobs := smfaTicket(t, st, "bob", "admin", guarded)
	if code, m := reveal(aliceTok, gcred, bobs); code != http.StatusForbidden || m["reason"] != "session-mfa-ticket-invalid" {
		t.Fatalf("another identity's ticket: %d %v", code, m)
	}
	if _, err := st.GetSessionByTokenHash(ctx, auth.TokenHash(bobs)); err != nil {
		t.Fatalf("a caller must not be able to spend someone else's ticket: %v", err)
	}

	if code, m := reveal(aliceTok, ocred, ""); code != http.StatusOK {
		t.Fatalf("a target that does not require it: %d %v", code, m)
	}
	if code, m := reveal(breakGlassKey, gcred, ""); code != http.StatusOK {
		t.Fatalf("break-glass: %d %v", code, m)
	}

	checkout := "/api/credentials/" + itoa(gcred) + "/checkout"
	if code, m := smfaDo(t, srv, http.MethodPost, checkout, aliceTok, "", map[string]any{}); code != http.StatusForbidden {
		t.Fatalf("checkout with no ticket: %d %v", code, m)
	}
	auditHas(t, st, "credential.checkout_denied", "target:db-01 reason:session-mfa-required")
	if code, m := smfaDo(t, srv, http.MethodPost, checkout, aliceTok, smfaTicket(t, st, "alice", "admin", guarded), map[string]any{}); code != http.StatusCreated || m["secret"] != secretPassword {
		t.Fatalf("checkout with a ticket: %d %v", code, m)
	}

	win := smfaTarget(t, srv, "win-01", "winrm", map[string]any{"os_type": "windows", "port": 5986, "require_session_mfa": true})
	smfaCred(t, srv, win, "Administrator", "Win-S3cret!")
	winrmPath := "/api/targets/" + itoa(win) + "/winrm"
	if code, m := smfaDo(t, srv, http.MethodPost, winrmPath, aliceTok, "", map[string]any{"command": "whoami"}); code != http.StatusForbidden {
		t.Fatalf("winrm with no ticket: %d %v", code, m)
	}
	auditHas(t, st, "winrm.denied", "target:win-01 reason:session-mfa-required")
	if fake.gotCmd != "" {
		t.Fatalf("the command reached the runner without a factor: %q", fake.gotCmd)
	}
	if code, m := smfaDo(t, srv, http.MethodPost, winrmPath, aliceTok, smfaTicket(t, st, "alice", "admin", win), map[string]any{"command": "whoami"}); code != http.StatusOK {
		t.Fatalf("winrm with a ticket: %d %v", code, m)
	}
	auditHas(t, st, "session.mfa_verified", "target:win-01 factor:ticket path:winrm")
}

// TestSessionMFAPolicySources proves the three sources the fold reads, through
// the API: PAM_SESSION_MFA binds a target with no flag of its own, a safe's
// flag binds the targets placed in it, and both flags round-trip and land in
// the audit trail when set.
func TestSessionMFAPolicySources(t *testing.T) {
	ctx := context.Background()
	srv, _ := newTestServerOpts(t, nil, api.Options{SessionMFA: true})
	cid := smfaCred(t, srv, smfaTarget(t, srv, "t1", "ssh", nil), "root", secretPassword)
	if code, m := smfaDo(t, srv, http.MethodPost, "/api/credentials/"+itoa(cid)+"/reveal", testAPIKey, "", nil); code != http.StatusForbidden {
		t.Fatalf("PAM_SESSION_MFA must bind a target with no flag of its own: %d %v", code, m)
	}

	srv2, st2 := newTestServerOpts(t, nil, api.Options{})
	code, data := do(t, srv2, http.MethodPost, "/api/safes", testAPIKey, map[string]any{"name": "prod", "require_session_mfa": true})
	if code != http.StatusCreated || jsonMap(t, data)["require_session_mfa"] != true {
		t.Fatalf("create safe: %d %s", code, data)
	}
	safeID := int64(jsonMap(t, data)["id"].(float64))
	auditHas(t, st2, "safe.create", "require_session_mfa:true")
	tid := smfaTarget(t, srv2, "t2", "ssh", nil)
	cid2 := smfaCred(t, srv2, tid, "root", secretPassword)
	revealPath := "/api/credentials/" + itoa(cid2) + "/reveal"
	if code, m := smfaDo(t, srv2, http.MethodPost, revealPath, testAPIKey, "", nil); code != http.StatusOK {
		t.Fatalf("before the safe: %d %v", code, m)
	}
	if err := st2.AssignTargetSafe(ctx, tid, &safeID); err != nil {
		t.Fatal(err)
	}
	if code, m := smfaDo(t, srv2, http.MethodPost, revealPath, testAPIKey, "", nil); code != http.StatusForbidden {
		t.Fatalf("the safe's flag must bind its target: %d %v", code, m)
	}

	code, data = do(t, srv2, http.MethodPut, "/api/targets/"+itoa(tid), testAPIKey,
		map[string]any{"name": "t2", "host": "10.0.0.5", "os_type": "linux", "protocol": "ssh", "require_session_mfa": true})
	if code != http.StatusOK || jsonMap(t, data)["require_session_mfa"] != true {
		t.Fatalf("update target: %d %s", code, data)
	}
	auditHas(t, st2, "target.update", "require_session_mfa:true")
}

// TestSessionMFAViewer proves the RDP/VNC viewer takes the gate: a caller that
// names the target is told before opening the tunnel, a plain viewer token is
// refused AT the tunnel regardless, and a ticket opens the desktop — with the
// vaulted credential injected into guacd — exactly once.
func TestSessionMFAViewer(t *testing.T) {
	connectCh := make(chan []string, 1)
	inputCh := make(chan string, 1)
	guacdAddr := fakeGuacd(t, connectCh, inputCh)
	srv, st := newTestServerOpts(t, nil, api.Options{GuacdAddr: guacdAddr, SessionMFA: true})
	id := smfaTarget(t, srv, "win-rdp", "rdp", map[string]any{"os_type": "windows", "port": 3389})
	smfaCred(t, srv, id, "Administrator", "Rdp-S3cret!")

	if code, m := smfaDo(t, srv, http.MethodPost, "/api/rdp-token", testAPIKey, "", map[string]any{"target_id": id}); code != http.StatusForbidden || m["session_mfa_required"] != true {
		t.Fatalf("mint naming a target that requires it: %d %v", code, m)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wsURL := func(tok string) string {
		return "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/targets/" + itoa(id) + "/rdp?token=" + tok
	}
	dial := func(tok string) (*websocket.Conn, error) {
		c, _, err := websocket.Dial(ctx, wsURL(tok), &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
		return c, err
	}

	_, data := do(t, srv, http.MethodPost, "/api/rdp-token", testAPIKey, nil)
	plain, _ := jsonMap(t, data)["token"].(string)
	if c, err := dial(plain); err == nil {
		c.Close(websocket.StatusNormalClosure, "")
		t.Fatal("a plain viewer token opened a desktop that requires session MFA")
	}
	auditHas(t, st, "rdp.refused", "target:win-rdp reason:session-mfa-required")

	seedUser(t, srv, "alice", "admin")
	ticket := smfaTicket(t, st, "alice", "admin", id)
	c, err := dial(ticket)
	if err != nil {
		t.Fatalf("ticket: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	select {
	case args := <-connectCh:
		if len(args) != 5 || args[4] != "Rdp-S3cret!" {
			t.Fatalf("connect args = %v, want the injected credential", args)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guacd never received the connect")
	}
	auditHas(t, st, "session.mfa_verified", "target:win-rdp factor:ticket path:rdp")
	if c2, err := dial(ticket); err == nil {
		c2.Close(websocket.StatusNormalClosure, "")
		t.Fatal("a spent ticket opened a second desktop")
	}
}

// TestSessionMFAWebAuthnTicket proves a user whose second factor is a security
// key mints a ticket through a real assertion ceremony, that the ceremony's
// challenge is single-use, and that a ceremony begun for one target cannot
// mint a ticket for another.
func TestSessionMFAWebAuthnTicket(t *testing.T) {
	w := newTestWebAuthn(t)
	srv, st := newTestServerOpts(t, nil, api.Options{WebAuthn: w})
	smfaTarget(t, srv, "web-01", "ssh", nil)
	smfaTarget(t, srv, "web-02", "ssh", nil)
	aliceTok := seedUser(t, srv, "alice", "user")
	key := newTestAuthenticator(t)
	registerCredential(t, srv, aliceTok, key, "yubikey")

	begin := func(target string) protocol.CredentialAssertionResponse {
		t.Helper()
		code, data := do(t, srv, http.MethodPost, "/api/session-mfa/webauthn/begin", aliceTok, map[string]any{"target": target})
		if code != http.StatusOK {
			t.Fatalf("begin: %d %s", code, data)
		}
		var assertion protocol.CredentialAssertion
		if err := json.Unmarshal(data, &assertion); err != nil {
			t.Fatal(err)
		}
		key.counter++
		authData := key.authData(t, false)
		cdj := clientDataJSON("webauthn.get", assertion.Response.Challenge)
		return protocol.CredentialAssertionResponse{
			PublicKeyCredential: protocol.PublicKeyCredential{
				Credential: protocol.Credential{ID: base64.RawURLEncoding.EncodeToString(key.credID), Type: "public-key"},
				RawID:      protocol.URLEncodedBase64(key.credID),
			},
			AssertionResponse: protocol.AuthenticatorAssertionResponse{
				AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: protocol.URLEncodedBase64(cdj)},
				AuthenticatorData:     protocol.URLEncodedBase64(authData),
				Signature:             protocol.URLEncodedBase64(key.sign(t, authData, cdj)),
			},
		}
	}

	resp := begin("web-01")
	code, data := do(t, srv, http.MethodPost, "/api/session-mfa/webauthn/finish?target=web-01", aliceTok, resp)
	if code != http.StatusCreated || jsonMap(t, data)["factor"] != "webauthn" || jsonMap(t, data)["ticket"] == "" {
		t.Fatalf("finish: %d %s", code, data)
	}
	auditHas(t, st, "session.mfa_ticket", "target:web-01 factor:webauthn")
	if code, _ := do(t, srv, http.MethodPost, "/api/session-mfa/webauthn/finish?target=web-01", aliceTok, resp); code != http.StatusUnauthorized {
		t.Fatalf("the same ceremony finished twice: %d", code)
	}

	resp = begin("web-01")
	if code, _ := do(t, srv, http.MethodPost, "/api/session-mfa/webauthn/finish?target=web-02", aliceTok, resp); code != http.StatusUnauthorized {
		t.Fatalf("a ceremony begun for web-01 minted for web-02: %d", code)
	}
	auditHas(t, st, "session.mfa_failed", "target:web-02 factor:webauthn reason:challenge-expired")
}
