package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// postForm issues an RFC 8693 form POST with a Bearer credential.
func postForm(t *testing.T, srv *httptest.Server, path, token string, values url.Values) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return res.StatusCode, data
}

// TestTokenExchangeEndToEnd proves Phase 57 through the API: an SVID-bearing
// agent exchanges for its sub-agent at POST /v1/token, and the DELEGATED TOKEN
// IS THEN USED to make a real tool call — which is the only proof that matters,
// since a minted token nothing accepts would be theatre. It also pins the audit
// record, the RFC 6749-shaped refusals, and the published JWKS.
func TestTokenExchangeEndToEnd(t *testing.T) {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]any{
		{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": b64(pub)}}})
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, jwks, 0o600); err != nil {
		t.Fatal(err)
	}
	const td, aud = "example.org", "pam-broker"
	verifier, err := agentid.NewSVIDVerifier(path, td, aud, 2)
	if err != nil {
		t.Fatal(err)
	}
	// The broker's own issuer key, trusted at ingress exactly as main wires it.
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	if err := verifier.TrustIssuer(agentid.KeyID(signPub), signPub); err != nil {
		t.Fatal(err)
	}

	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	opts := brokerOpts(t, fake, toolsetRules) // list_targets needs no grant
	opts.BrokerSVIDVerifier = verifier
	opts.BrokerTokenSignKey = signPriv
	opts.BrokerAudience = aud
	opts.BrokerMaxDelegation = 2
	opts.BrokerExchangeTTL = 5 * time.Minute
	srv, st := newTestServerOpts(t, nil, opts)

	mint := func(sub string, exp time.Time) string {
		hdr := b64([]byte(`{"alg":"EdDSA","kid":"k1","typ":"JWT"}`))
		claims, _ := json.Marshal(map[string]any{
			"sub": "spiffe://example.org/" + sub, "aud": aud, "exp": exp.Unix()})
		signing := hdr + "." + b64(claims)
		return signing + "." + b64(ed25519.Sign(priv, []byte(signing)))
	}
	planner := mint("planner", time.Now().Add(time.Hour))
	worker := mint("worker", time.Now().Add(time.Hour))

	code, body := postForm(t, srv, "/v1/token", planner, url.Values{
		"grant_type":  {agentid.ExchangeGrantType},
		"actor_token": {worker},
	})
	if code != http.StatusOK {
		t.Fatalf("exchange: %d %s", code, body)
	}
	out := jsonMap(t, body)
	delegated, _ := out["access_token"].(string)
	if delegated == "" || out["issued_token_type"] != agentid.TokenTypeJWT {
		t.Fatalf("exchange response missing the issued token: %s", body)
	}
	if exp, _ := out["expires_in"].(float64); exp <= 0 || exp > 300 {
		t.Fatalf("expires_in = %v, want (0,300]", out["expires_in"])
	}

	// The delegated token WORKS: a real tool call authenticates with it.
	tc, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", delegated,
		map[string]any{"tool": "list_targets"})
	if tc != http.StatusOK || jsonMap(t, data)["status"] != "executed" {
		t.Fatalf("tool call with the delegated token: %d %s", tc, data)
	}

	// The exchange is on the record, naming both ends and the chain.
	events, err := st.ListAudit(t.Context(), 200)
	if err != nil {
		t.Fatal(err)
	}
	var exchanged string
	for _, e := range events {
		if e.Action == "broker.token.exchanged" {
			exchanged = e.Detail
		}
	}
	if !strings.Contains(exchanged, "actor:spiffe://example.org/worker") ||
		!strings.Contains(exchanged, "delegator:spiffe://example.org/planner") {
		t.Fatalf("broker.token.exchanged detail = %q; want both ends of the delegation", exchanged)
	}

	// Refusals are RFC 6749 §5.2-shaped, not the broker's 200-with-status contract.
	code, body = postForm(t, srv, "/v1/token", planner, url.Values{
		"grant_type": {agentid.ExchangeGrantType}, // no actor_token = impersonation
	})
	if code != http.StatusBadRequest || jsonMap(t, body)["error"] != "invalid_request" {
		t.Fatalf("impersonation attempt: %d %s, want 400 invalid_request", code, body)
	}
	code, body = postForm(t, srv, "/v1/token", planner, url.Values{
		"grant_type": {"client_credentials"}, "actor_token": {worker},
	})
	if code != http.StatusBadRequest || jsonMap(t, body)["error"] != "unsupported_grant_type" {
		t.Fatalf("wrong grant type: %d %s, want 400 unsupported_grant_type", code, body)
	}
	// An unauthenticated caller never reaches the minter.
	if code, _ := postForm(t, srv, "/v1/token", "not-a-token", url.Values{
		"grant_type": {agentid.ExchangeGrantType}, "actor_token": {worker},
	}); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated exchange: want 401, got %d", code)
	}

	// The signing key is published for an auditor holding a delegated token.
	code, body = do(t, srv, http.MethodGet, "/v1/token/jwks", testAPIKey, nil)
	if code != http.StatusOK || !strings.Contains(string(body), agentid.KeyID(signPub)) {
		t.Fatalf("token JWKS: %d %s", code, body)
	}
	if code, _ := do(t, srv, http.MethodGet, "/v1/token/jwks", seedUser(t, srv, "tj-user", "user"), nil); code != http.StatusForbidden {
		t.Fatalf("a plain user read the token JWKS: want 403, got %d", code)
	}
}

// TestTokenExchangeDisabled proves the endpoint is inert without a signing key:
// the broker still runs, and the exchange 404s rather than minting under some
// implicit key.
func TestTokenExchangeDisabled(t *testing.T) {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]any{
		{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": b64(pub)}}})
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, jwks, 0o600); err != nil {
		t.Fatal(err)
	}
	verifier, err := agentid.NewSVIDVerifier(path, "example.org", "pam-broker", 2)
	if err != nil {
		t.Fatal(err)
	}
	opts := brokerOpts(t, &fakeWinRM{}, toolsetRules)
	opts.BrokerSVIDVerifier = verifier
	srv, _ := newTestServerOpts(t, nil, opts)

	hdr := b64([]byte(`{"alg":"EdDSA","kid":"k1","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"sub": "spiffe://example.org/planner", "aud": "pam-broker", "exp": time.Now().Add(time.Hour).Unix()})
	signing := hdr + "." + b64(claims)
	agent := signing + "." + b64(ed25519.Sign(priv, []byte(signing)))

	if code, body := postForm(t, srv, "/v1/token", agent, url.Values{
		"grant_type": {agentid.ExchangeGrantType}, "actor_token": {agent},
	}); code != http.StatusNotFound {
		t.Fatalf("exchange with no signing key: want 404, got %d %s", code, body)
	}
	if code, _ := do(t, srv, http.MethodGet, "/v1/token/jwks", testAPIKey, nil); code != http.StatusNotFound {
		t.Fatalf("token JWKS with no signing key: want 404, got %d", code)
	}
}
