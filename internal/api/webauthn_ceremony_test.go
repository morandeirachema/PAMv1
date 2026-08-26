package api_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
)

// multiUserAuthenticator is a fixed username->password map, for tests that
// need more than one distinct logged-in identity (fakeAuthenticator only
// ever accepts one).
type multiUserAuthenticator map[string]string

func (m multiUserAuthenticator) Authenticate(_ context.Context, u, p string) (*auth.Principal, error) {
	if pw, ok := m[u]; ok && pw == p {
		return &auth.Principal{Name: u, Role: auth.RoleUser}, nil
	}
	return nil, auth.ErrUnauthorized
}

// testRPID/testRPOrigin are the fixed values every test's *webauthn.WebAuthn
// and hand-crafted authenticator responses agree on. The library checks RPID
// and Origin independently against whatever it was configured with — it does
// not require Origin to be "related to" RPID the way a real browser would
// have enforced before ever calling out to an authenticator — so an
// httptest.Server's http://127.0.0.1:PORT origin paired with an unrelated
// RPID string is fine for a server-side-only test like this one.
const (
	testRPID     = "localhost"
	testRPOrigin = "https://localhost"
)

func newTestWebAuthn(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	w, err := webauthn.New(&webauthn.Config{
		RPID:          testRPID,
		RPDisplayName: "PAMv1 test",
		RPOrigins:     []string{testRPOrigin},
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	return w
}

// testAuthenticator is a minimal, hand-rolled software FIDO2 authenticator:
// one ES256 (P-256) key pair, enough to produce a real "none"-format
// attestation object at registration and a real signed assertion at login.
// This is the same "dial a real thing, not a mock" posture the SSH proxy's
// own JIT-injection test takes — there is no lower-level way to prove the
// go-webauthn integration actually verifies a signature correctly than to
// hand it one, since a browser+hardware key cannot run in CI.
type testAuthenticator struct {
	key     *ecdsa.PrivateKey
	credID  []byte
	counter uint32
}

func newTestAuthenticator(t *testing.T) *testAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("generate credential id: %v", err)
	}
	return &testAuthenticator{key: key, credID: credID, counter: 1}
}

// coseKey CBOR-encodes the public key as a COSE_Key EC2/ES256 map — the exact
// shape webauthncose.ParsePublicKey expects inside attestedCredentialData.
func (a *testAuthenticator) coseKey(t *testing.T) []byte {
	t.Helper()
	// Bytes() is the SEC1 uncompressed point: 0x04 || X(32) || Y(32) for
	// P-256 — the non-deprecated way to get the coordinates (pub.X/.Y are
	// deprecated since Go 1.26; see crypto/ecdsa's own doc comment).
	uncompressed, err := a.key.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("public key bytes: %v", err)
	}
	x, y := uncompressed[1:33], uncompressed[33:65]
	m := map[int]any{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: x,
		-3: y,
	}
	b, err := cbor.Marshal(m)
	if err != nil {
		t.Fatalf("cbor marshal cose key: %v", err)
	}
	return b
}

// authData builds the WebAuthn authenticatorData structure (§6.1): rpIdHash
// (32) + flags (1) + signCount (4) + attestedCredentialData (registration
// only: AAGUID(16) + credIdLen(2) + credId + COSE public key).
func (a *testAuthenticator) authData(t *testing.T, attested bool) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(testRPID))
	var flags byte = 0x01 | 0x04 // UP | UV
	if attested {
		flags |= 0x40 // AT
	}
	out := append([]byte{}, rpHash[:]...)
	out = append(out, flags)
	ctr := make([]byte, 4)
	binary.BigEndian.PutUint32(ctr, a.counter)
	out = append(out, ctr...)
	if attested {
		out = append(out, make([]byte, 16)...) // AAGUID, all-zero is valid
		l := make([]byte, 2)
		binary.BigEndian.PutUint16(l, uint16(len(a.credID)))
		out = append(out, l...)
		out = append(out, a.credID...)
		out = append(out, a.coseKey(t)...)
	}
	return out
}

// attestationObject CBOR-encodes a "none"-format attestation object — the
// simplest conformant format, carrying no attestation signature of its own
// (the credential's OWN public key inside authData is still fully real and
// still verified at every later login).
func (a *testAuthenticator) attestationObject(t *testing.T) []byte {
	t.Helper()
	obj := map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": a.authData(t, true),
	}
	b, err := cbor.Marshal(obj)
	if err != nil {
		t.Fatalf("cbor marshal attestation object: %v", err)
	}
	return b
}

// sign produces a real ECDSA-P256-SHA256 signature over authData||clientDataHash,
// DER/ASN.1-encoded exactly as WebAuthn assertions require.
func (a *testAuthenticator) sign(t *testing.T, authData, clientDataJSON []byte) []byte {
	t.Helper()
	cdHash := sha256.Sum256(clientDataJSON)
	msg := append(append([]byte{}, authData...), cdHash[:]...)
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return sig
}

// clientDataJSON reproduces what a browser would build for the given
// ceremony, referencing the server-issued challenge byte-for-byte.
func clientDataJSON(ceremonyType string, challenge []byte) []byte {
	cd := map[string]string{
		"type":      ceremonyType,
		"challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin":    testRPOrigin,
	}
	b, _ := json.Marshal(cd)
	return b
}

// registerCredential drives the full registration ceremony over HTTP —
// begin, hand-craft a real attestation response, finish — and returns the
// credential id the server assigned.
func registerCredential(t *testing.T, srv *httptest.Server, sessTok string, a *testAuthenticator, name string) int64 {
	t.Helper()
	status, data := do(t, srv, http.MethodPost, "/api/webauthn/register/begin", sessTok, nil)
	if status != http.StatusOK {
		t.Fatalf("register/begin = %d: %s", status, data)
	}
	var creation protocol.CredentialCreation
	if err := json.Unmarshal(data, &creation); err != nil {
		t.Fatalf("unmarshal creation options: %v", err)
	}
	cdj := clientDataJSON("webauthn.create", creation.Response.Challenge)
	resp := protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{ID: base64.RawURLEncoding.EncodeToString(a.credID), Type: "public-key"},
			RawID:      protocol.URLEncodedBase64(a.credID),
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: protocol.URLEncodedBase64(cdj)},
			AttestationObject:     protocol.URLEncodedBase64(a.attestationObject(t)),
		},
	}
	status, data = do(t, srv, http.MethodPost, "/api/webauthn/register/finish?name="+url.QueryEscape(name), sessTok, resp)
	if status != http.StatusCreated {
		t.Fatalf("register/finish = %d: %s", status, data)
	}
	m := jsonMap(t, data)
	id, _ := m["id"].(float64)
	return int64(id)
}

func TestWebAuthnRegisterAndLoginEndToEnd(t *testing.T) {
	w := newTestWebAuthn(t)
	srv, _ := newTestServerOpts(t, fakeAuthenticator{username: "ad-alice", password: "pw", role: auth.RoleUser}, api.Options{WebAuthn: w})

	_, data := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "pw"})
	sessTok, _ := jsonMap(t, data)["token"].(string)
	if sessTok == "" {
		t.Fatalf("password-only login did not return a token: %s", data)
	}

	auth1 := newTestAuthenticator(t)
	credID := registerCredential(t, srv, sessTok, auth1, "test key")
	if credID == 0 {
		t.Fatal("registration did not return a credential id")
	}

	// A fresh login now: password alone must NOT issue a full session — it
	// must announce webauthn_required and hand back an MFAPending token good
	// for nothing but the WebAuthn ceremony endpoints.
	status, data := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "pw"})
	if status != http.StatusOK {
		t.Fatalf("password-only login (2nd) = %d, want 200: %s", status, data)
	}
	m := jsonMap(t, data)
	if m["webauthn_required"] != true {
		t.Fatalf("expected webauthn_required=true: %s", data)
	}
	pendingTok, _ := m["token"].(string)
	if pendingTok == "" {
		t.Fatal("no MFAPending token returned")
	}

	// The pending token must be refused by the API middleware — this checks
	// /api/me as the representative route. It is NOT a proof of "everywhere":
	// the viewer tunnel resolves its own principal and was, until the 2026-08-26
	// audit, the one surface this token could open a desktop through. That
	// surface has its own test now (TestViewerTunnelRefusesNarrowScopes); a
	// comment claiming "everywhere" over a single-route check is how the gap
	// stayed invisible.
	if status, _ := do(t, srv, http.MethodGet, "/api/me", pendingTok, nil); status != http.StatusForbidden {
		t.Fatalf("GET /api/me with a pending token = %d, want 403", status)
	}

	status, data = do(t, srv, http.MethodPost, "/api/webauthn/login/begin", pendingTok, nil)
	if status != http.StatusOK {
		t.Fatalf("login/begin = %d: %s", status, data)
	}
	var assertion protocol.CredentialAssertion
	if err := json.Unmarshal(data, &assertion); err != nil {
		t.Fatalf("unmarshal assertion options: %v", err)
	}

	auth1.counter++ // a real authenticator's counter strictly increases between uses
	authData := auth1.authData(t, false)
	cdj := clientDataJSON("webauthn.get", assertion.Response.Challenge)
	resp := protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{ID: base64.RawURLEncoding.EncodeToString(auth1.credID), Type: "public-key"},
			RawID:      protocol.URLEncodedBase64(auth1.credID),
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: protocol.URLEncodedBase64(cdj)},
			AuthenticatorData:     protocol.URLEncodedBase64(authData),
			Signature:             protocol.URLEncodedBase64(auth1.sign(t, authData, cdj)),
		},
	}
	status, data = do(t, srv, http.MethodPost, "/api/webauthn/login/finish", pendingTok, resp)
	if status != http.StatusCreated {
		t.Fatalf("login/finish = %d: %s", status, data)
	}
	fullTok, _ := jsonMap(t, data)["token"].(string)
	if fullTok == "" {
		t.Fatal("no full session token returned after a successful WebAuthn login")
	}

	// The new token must be a REAL, unrestricted session — prove it by using
	// it for something an MFAPending token was just refused for.
	if status, _ := do(t, srv, http.MethodGet, "/api/me", fullTok, nil); status != http.StatusOK {
		t.Fatalf("GET /api/me with the post-WebAuthn token = %d, want 200", status)
	}

	// The registered credential is still exactly one row — login does not
	// accidentally create or duplicate a credential, only verify one.
	status, data = do(t, srv, http.MethodGet, "/api/webauthn/credentials", fullTok, nil)
	if status != http.StatusOK {
		t.Fatalf("list credentials = %d: %s", status, data)
	}
	creds, _ := jsonMap(t, data)["credentials"].([]any)
	if len(creds) != 1 {
		t.Fatalf("expected exactly 1 registered credential, got %d: %s", len(creds), data)
	}
}

// TestWebAuthnCredentialDeleteScopedToOwner proves one user cannot delete
// another user's registered authenticator by guessing its id.
func TestWebAuthnCredentialDeleteScopedToOwner(t *testing.T) {
	w := newTestWebAuthn(t)
	authn := multiUserAuthenticator{"alice": "pw1", "bob": "pw2"}
	srv, _ := newTestServerOpts(t, authn, api.Options{WebAuthn: w})

	_, data := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "alice", "password": "pw1"})
	aliceTok, _ := jsonMap(t, data)["token"].(string)
	credID := registerCredential(t, srv, aliceTok, newTestAuthenticator(t), "alice's key")

	_, data = do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "bob", "password": "pw2"})
	bobTok, _ := jsonMap(t, data)["token"].(string)

	status, _ := do(t, srv, http.MethodDelete, "/api/webauthn/credentials/"+itoa(credID), bobTok, nil)
	if status != http.StatusNotFound {
		t.Fatalf("bob deleting alice's credential = %d, want 404", status)
	}
	status, _ = do(t, srv, http.MethodDelete, "/api/webauthn/credentials/"+itoa(credID), aliceTok, nil)
	if status != http.StatusNoContent {
		t.Fatalf("alice deleting her own credential = %d, want 204", status)
	}
}
