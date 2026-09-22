package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/radius/radiustest"
)

func radiusLoginPolicy(user, pass string, state []byte) (byte, []radiustest.Attr) {
	switch {
	case user == "rae" && pass == "radius-pw":
		return radiustest.CodeAccessAccept, []radiustest.Attr{{Type: radiustest.AttrClass, Value: "pam-auditors"}}
	case user == "bob" && pass == "bob-pw" && len(state) == 0:
		return radiustest.CodeAccessChallenge, []radiustest.Attr{{Type: radiustest.AttrState, Value: "st-7"}, {Type: radiustest.AttrReplyMessage, Value: "Enter token"}}
	case user == "bob" && pass == "246810" && string(state) == "st-7":
		return radiustest.CodeAccessAccept, nil
	case user == "alice" && pass == "135791": // alice's OTP, second-factor mode
		return radiustest.CodeAccessAccept, nil
	}
	return radiustest.CodeAccessReject, nil
}

func newRADIUSForTest(t *testing.T) (*radiustest.Server, *auth.RADIUSAuthenticator) {
	t.Helper()
	srv := radiustest.New(t, "s3cret", radiusLoginPolicy).Start()
	ra, err := auth.NewRADIUSAuthenticator(auth.RADIUSConfig{
		Addr: srv.Addr(), Secret: "s3cret", NASIdentifier: "pamv1-test",
		ClassRoleMap: map[string]auth.Role{"pam-auditors": auth.RoleAuditor},
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, ra
}

// TestRADIUSLoginMode: RADIUS as a login source behind the directory in the
// chain. A directory user still logs in; a RADIUS-only user logs in with the
// role its Class maps to; a challenge comes back as mfa_required with a
// state, and answering it with the code (no password) mints the session; a
// wrong code or forged state is refused and audited.
func TestRADIUSLoginMode(t *testing.T) {
	_, ra := newRADIUSForTest(t)
	dir := fakeAuthenticator{username: "alice", password: "dir-pw", role: auth.RoleUser}
	srv, st := newTestServerOpts(t, auth.NewChain(dir, ra), api.Options{RADIUS: ra})

	status, body := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "alice", "password": "dir-pw"})
	if status != http.StatusCreated {
		t.Fatalf("directory login: %d %s", status, body)
	}
	status, body = do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "rae", "password": "radius-pw"})
	var out struct {
		Token string `json:"token"`
		Role  string `json:"role"`
	}
	_ = json.Unmarshal(body, &out)
	if status != http.StatusCreated || out.Token == "" || out.Role != "auditor" {
		t.Fatalf("radius login: %d %s", status, body)
	}
	// The minted session carries the mapped role: audit readable, targets not manageable.
	if s, _ := do(t, srv, http.MethodGet, "/api/audit", out.Token, nil); s != http.StatusOK {
		t.Fatalf("auditor session reading audit: %d", s)
	}
	if s, _ := do(t, srv, http.MethodPost, "/api/targets", out.Token, map[string]any{"name": "x", "host": "h", "port": 22}); s != http.StatusForbidden {
		t.Fatalf("auditor session creating a target: %d", s)
	}

	// Challenge round trip.
	status, body = do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "bob", "password": "bob-pw"})
	var ch struct {
		MFARequired bool   `json:"mfa_required"`
		State       string `json:"radius_state"`
		Message     string `json:"message"`
	}
	_ = json.Unmarshal(body, &ch)
	if status != http.StatusUnauthorized || !ch.MFARequired || ch.State == "" || !strings.Contains(ch.Message, "Enter token") {
		t.Fatalf("challenge: %d %s", status, body)
	}
	if s, b := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "bob", "otp": "000000", "radius_state": ch.State}); s != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d %s", s, b)
	}
	if s, b := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "bob", "otp": "246810", "radius_state": "not base64!"}); s != http.StatusBadRequest {
		t.Fatalf("bad state encoding: %d %s", s, b)
	}
	status, body = do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "bob", "otp": "246810", "radius_state": ch.State})
	_ = json.Unmarshal(body, &out)
	if status != http.StatusCreated || out.Token == "" || out.Role != "user" {
		t.Fatalf("challenge answered: %d %s", status, body)
	}
	if s, _ := do(t, srv, http.MethodGet, "/api/me", out.Token, nil); s != http.StatusOK {
		t.Fatalf("session from a challenge login: %d", s)
	}

	events, _ := st.ListAudit(t.Context(), 50)
	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Action+"|"+e.Actor] = true
	}
	for _, w := range []string{"login.challenge|\"bob\"", "login|bob", "login|rae", "login.failed|\"bob\""} {
		if !seen[w] {
			t.Fatalf("missing audit %q in %v", w, seen)
		}
	}
}

// TestRADIUSSecondFactorMode: the directory vouches for the password, the
// RADIUS server for the code. No code → mfa_required; a wrong code → refused;
// the right one → a session; the server unreachable → 503, never a session.
func TestRADIUSSecondFactorMode(t *testing.T) {
	_, ra := newRADIUSForTest(t)
	dir := fakeAuthenticator{username: "alice", password: "dir-pw", role: auth.RoleAdmin}
	srv, st := newTestServerOpts(t, dir, api.Options{RADIUS: ra, RADIUSSecondFactor: true})

	status, body := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "alice", "password": "dir-pw"})
	var ch struct {
		MFARequired bool   `json:"mfa_required"`
		State       string `json:"radius_state"`
	}
	_ = json.Unmarshal(body, &ch)
	if status != http.StatusUnauthorized || !ch.MFARequired || ch.State != "" {
		t.Fatalf("no code: %d %s", status, body)
	}
	if s, b := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "alice", "password": "dir-pw", "otp": "999999"}); s != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d %s", s, b)
	}
	if s, b := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "alice", "password": "wrong", "otp": "135791"}); s != http.StatusUnauthorized {
		t.Fatalf("wrong password with a right code: %d %s", s, b)
	}
	status, body = do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "alice", "password": "dir-pw", "otp": "135791"})
	var out struct {
		Token string `json:"token"`
		Role  string `json:"role"`
	}
	_ = json.Unmarshal(body, &out)
	if status != http.StatusCreated || out.Token == "" || out.Role != "admin" {
		t.Fatalf("both factors: %d %s", status, body)
	}
	// A RADIUS-only user cannot log in at all in this mode: RADIUS is not a source.
	if s, _ := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "rae", "password": "radius-pw", "otp": "1"}); s != http.StatusUnauthorized {
		t.Fatalf("radius-only user in second-factor mode: %d", s)
	}
	events, _ := st.ListAudit(t.Context(), 50)
	var mfaFail bool
	for _, e := range events {
		if e.Action == "login.failed" && strings.Contains(e.Detail, "reason:mfa source:radius") {
			mfaFail = true
		}
	}
	if !mfaFail {
		t.Fatal("expected a login.failed reason:mfa source:radius audit row")
	}

	// Server down: fail closed with 503, not a session and not "invalid code".
	down, err := auth.NewRADIUSAuthenticator(auth.RADIUSConfig{Addr: "127.0.0.1:1", Secret: "x"})
	if err != nil {
		t.Fatal(err)
	}
	srv2, _ := newTestServerOpts(t, dir, api.Options{RADIUS: down, RADIUSSecondFactor: true})
	if s, b := do(t, srv2, http.MethodPost, "/api/login", "", map[string]any{"username": "alice", "password": "dir-pw", "otp": "135791"}); s != http.StatusServiceUnavailable {
		t.Fatalf("server down: %d %s", s, b)
	}
}
