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
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/jwtutil"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// popServer builds a broker whose SVIDs the test mints itself, optionally with
// PAM_BROKER_REQUIRE_POP on. It returns the server, its store, a mint function
// (an empty cnf means an ordinary unbound token) and the trust domain's key.
func popServer(t *testing.T, requirePoP bool) (*httptest.Server, store.Store, func(cnf string) string, ed25519.PrivateKey) {
	t.Helper()
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]any{
		{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": b64(pub)}}})
	jwksPath := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(jwksPath, jwks, 0o600); err != nil {
		t.Fatal(err)
	}
	const aud = "pam-broker"
	verifier, err := agentid.NewSVIDVerifier(jwksPath, "example.org", aud, 2)
	if err != nil {
		t.Fatal(err)
	}
	opts := brokerOpts(t, &fakeWinRM{result: winrm.Result{Stdout: "ok"}}, toolsetRules)
	opts.BrokerSVIDVerifier = verifier
	opts.BrokerAudience = aud
	opts.BrokerRequirePoP = requirePoP
	srv, st := newTestServerOpts(t, nil, opts)

	mint := func(cnf string) string {
		claims := map[string]any{"sub": "spiffe://example.org/worker", "aud": aud,
			"exp": time.Now().Add(time.Hour).Unix()}
		if cnf != "" {
			claims["cnf"] = map[string]any{"jkt": cnf}
		}
		body, _ := json.Marshal(claims)
		signing := b64([]byte(`{"alg":"EdDSA","kid":"k1","typ":"JWT"}`)) + "." + b64(body)
		return signing + "." + b64(ed25519.Sign(priv, []byte(signing)))
	}
	return srv, st, mint, priv
}

// TestProofOfPossessionEndToEnd is the assertion that matters for this phase, and
// it is deliberately shaped so a pass cannot be faked: the SAME delegated token
// is presented twice — once by a "thief" holding only the token, and once by the
// legitimate holder who also has the private key. The thief is refused and the
// holder executes a real tool call. Anything less (asserting only that a header
// is checked) would leave the actual claim — a stolen token is useless —
// untested.
func TestProofOfPossessionEndToEnd(t *testing.T) {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]any{
		{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": b64(pub)}}})
	jwksPath := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(jwksPath, jwks, 0o600); err != nil {
		t.Fatal(err)
	}
	const td, aud = "example.org", "pam-broker"
	verifier, err := agentid.NewSVIDVerifier(jwksPath, td, aud, 2)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	if err := verifier.TrustIssuer(agentid.KeyID(signPub), signPub); err != nil {
		t.Fatal(err)
	}

	opts := brokerOpts(t, &fakeWinRM{result: winrm.Result{Stdout: "ok"}}, toolsetRules)
	opts.BrokerSVIDVerifier = verifier
	opts.BrokerTokenSignKey = signPriv
	opts.BrokerAudience = aud
	opts.BrokerMaxDelegation = 2
	opts.BrokerExchangeTTL = 5 * time.Minute
	srv, st := newTestServerOpts(t, nil, opts)

	mint := func(sub string) string {
		hdr := b64([]byte(`{"alg":"EdDSA","kid":"k1","typ":"JWT"}`))
		claims, _ := json.Marshal(map[string]any{
			"sub": "spiffe://example.org/" + sub, "aud": aud, "exp": time.Now().Add(time.Hour).Unix()})
		signing := hdr + "." + b64(claims)
		return signing + "." + b64(ed25519.Sign(priv, []byte(signing)))
	}

	// The sub-agent's own key: the thing a captured token is worthless without.
	subPub, subPriv, _ := ed25519.GenerateKey(rand.Reader)
	jkt, err := agentid.JWKThumbprint(jwtutil.JWK{Kty: "OKP", Crv: "Ed25519", X: b64(subPub)})
	if err != nil {
		t.Fatal(err)
	}

	code, body := postForm(t, srv, "/v1/token", mint("planner"), url.Values{
		"grant_type":  {agentid.ExchangeGrantType},
		"actor_token": {mint("worker")},
		"cnf_jkt":     {jkt},
	})
	if code != http.StatusOK {
		t.Fatalf("exchange: %d %s", code, body)
	}
	delegated, _ := jsonMap(t, body)["access_token"].(string)
	if delegated == "" {
		t.Fatalf("no token issued: %s", body)
	}

	call := map[string]any{"tool": "list_targets"}

	// 1. THE THIEF. It holds the token and nothing else — exactly what leaks out
	//    of a log, an env dump or a proxy — and gets a 401.
	if sc, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", delegated, call); sc != http.StatusUnauthorized {
		t.Fatalf("a bound token was accepted with no proof: %d %s", sc, data)
	}

	// 2. THE HOLDER. Same token, plus a proof signed by the bound key.
	toolCallsURI := srv.URL + "/v1/tool-calls"
	proof := signProof(t, subPriv, subPub, http.MethodPost, toolCallsURI, delegated, "p1")
	sc, data := doProof(t, srv, http.MethodPost, "/v1/tool-calls", delegated, proof, call)
	if sc != http.StatusOK || jsonMap(t, data)["status"] != "executed" {
		t.Fatalf("the key holder was refused: %d %s", sc, data)
	}

	// 3. THE REPLAYED PROOF. Headers are not secret, so the pair (token, proof)
	//    can be captured together. A proof is single-use.
	if sc, data := doProof(t, srv, http.MethodPost, "/v1/tool-calls", delegated, proof, call); sc != http.StatusUnauthorized {
		t.Fatalf("a replayed proof was accepted: %d %s", sc, data)
	}

	// 4. A PROOF MADE FOR A DIFFERENT TOKEN. `ath` binds the two together, so a
	//    fresh, perfectly valid proof cannot be carried over to another token.
	otherToken := mint("worker")
	wrongATH := signProof(t, subPriv, subPub, http.MethodPost, toolCallsURI, otherToken, "p2")
	if sc, data := doProof(t, srv, http.MethodPost, "/v1/tool-calls", delegated, wrongATH, call); sc != http.StatusUnauthorized {
		t.Fatalf("a proof bound to another token was accepted: %d %s", sc, data)
	}

	// 5. A PROOF FOR ANOTHER ENDPOINT. `htu`/`htm` stop a proof captured on one
	//    route from being spent on a more powerful one.
	elsewhere := signProof(t, subPriv, subPub, http.MethodGet, srv.URL+"/v1/tool-calls/1", delegated, "p3")
	if sc, data := doProof(t, srv, http.MethodPost, "/v1/tool-calls", delegated, elsewhere, call); sc != http.StatusUnauthorized {
		t.Fatalf("a proof for another endpoint was accepted: %d %s", sc, data)
	}

	// 6. SOMEBODY ELSE'S KEY. A well-formed proof signed by a key the token was
	//    not bound to is the attack this whole mechanism exists to refuse.
	imposterPub, imposterPriv, _ := ed25519.GenerateKey(rand.Reader)
	imposter := signProof(t, imposterPriv, imposterPub, http.MethodPost, toolCallsURI, delegated, "p4")
	if sc, data := doProof(t, srv, http.MethodPost, "/v1/tool-calls", delegated, imposter, call); sc != http.StatusUnauthorized {
		t.Fatalf("a proof signed by an unbound key was accepted: %d %s", sc, data)
	}

	// The refusals are on the record with the reason, while the CALLER was told
	// only "invalid or missing agent credential" — the responder learns why, the
	// attacker does not.
	events, err := st.ListAudit(t.Context(), 300)
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]bool{}
	for _, e := range events {
		if e.Action == "agent.pop_denied" {
			for _, f := range strings.Fields(e.Detail) {
				if r, ok := strings.CutPrefix(f, "reason:"); ok {
					reasons[strings.Trim(r, `"`)] = true
				}
			}
		}
	}
	for _, want := range []string{
		"proof-header-missing", "proof-replayed", "proof-not-bound-to-this-token",
		"proof-method-mismatch", "proof-key-is-not-the-bound-key",
	} {
		if !reasons[want] {
			t.Errorf("no agent.pop_denied recorded reason %q; got %v", want, reasons)
		}
	}
}

// TestUnboundTokenIsUnaffected is the compatibility half, and it is the one that
// decides whether this phase is safe to ship into an existing deployment: a
// token minted WITHOUT a binding must keep working exactly as before, with no
// proof header anywhere. If this failed, every agent already in the field would
// stop at upgrade.
func TestUnboundTokenIsUnaffected(t *testing.T) {
	srv, _, mint, _ := popServer(t, false)
	sc, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", mint(""), map[string]any{"tool": "list_targets"})
	if sc != http.StatusOK {
		t.Fatalf("an unbound token was refused: %d %s", sc, data)
	}
}

// TestRequirePoPRefusesAnUnboundSVID pins PAM_BROKER_REQUIRE_POP: with it on, a
// perfectly valid SVID that simply carries no binding is refused, which is the
// difference between "binding is available" and "binding is the rule".
func TestRequirePoPRefusesAnUnboundSVID(t *testing.T) {
	srv, _, mint, _ := popServer(t, true)
	sc, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", mint(""), map[string]any{"tool": "list_targets"})
	if sc != http.StatusUnauthorized {
		t.Fatalf("an unbound SVID passed with PAM_BROKER_REQUIRE_POP on: %d %s", sc, data)
	}

	// A STATIC agent key is exempt by construction — it has no claims and so can
	// carry no confirmation — and the setting must not turn that identity kind
	// off by a side door. This is the behaviour Options.BrokerRequirePoP
	// documents, asserted rather than left to the doc comment.
	srvKey, st, _, _ := popServer(t, true)
	const staticToken = "static-agent-bearer-key"
	k := store.AgentKey{Name: "batch-agent", Owner: "ops", TokenHash: auth.TokenHash(staticToken)}
	if err := st.CreateAgentKey(t.Context(), &k); err != nil {
		t.Fatal(err)
	}
	sc, data = doBearer(t, srvKey, http.MethodPost, "/v1/tool-calls", staticToken, map[string]any{"tool": "list_targets"})
	if sc != http.StatusOK {
		t.Fatalf("a static agent key was refused by PAM_BROKER_REQUIRE_POP: %d %s", sc, data)
	}
}

// doProof issues an agent request carrying both the token and its RFC 9449 proof.
func doProof(t *testing.T, srv *httptest.Server, method, path, token, proof string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, srv.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	// The DPoP authorization scheme, which is what a real sender-constrained
	// client sends; the server must accept it as readily as Bearer.
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set(agentid.ProofHeader, proof)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return res.StatusCode, data
}

// signProof builds an RFC 9449 proof for one request with one access token.
func signProof(t *testing.T, key ed25519.PrivateKey, pub ed25519.PublicKey, method, uri, token, jti string) string {
	t.Helper()
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	hdr, _ := json.Marshal(map[string]any{
		"typ": "dpop+jwt", "alg": "EdDSA",
		"jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64(pub)},
	})
	claims, _ := json.Marshal(map[string]any{
		"jti": jti, "htm": method, "htu": uri,
		"iat": time.Now().Unix(), "ath": agentid.AccessTokenHash(token),
	})
	signing := b64(hdr) + "." + b64(claims)
	return signing + "." + b64(ed25519.Sign(key, []byte(signing)))
}
