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
	// Per-value quoted: the record is read by a parser that splits on spaces, so
	// every field carries its own quotes rather than the whole detail carrying one
	// pair. See TestTokenExchangeAuditResistsForgery for why that distinction is
	// load-bearing and not cosmetic.
	if !strings.Contains(exchanged, `actor:"spiffe://example.org/worker"`) ||
		!strings.Contains(exchanged, `delegator:"spiffe://example.org/planner"`) {
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

// TestMayActPinsTheNextHop is Phase 181's round trip: PAMv1 has enforced RFC
// 8693 §4.4 `may_act` since Phase 57 and never emitted it, so the check existed
// with nothing to read — from the second hop onward, nobody could pin who was
// allowed to act for whom.
//
// Now a delegator names the parties permitted to act for the token it mints,
// and the NEXT exchange refuses anyone else. Emission and enforcement finally
// meet, which is the only state in which either is worth anything.
func TestMayActPinsTheNextHop(t *testing.T) {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]any{
		{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": b64(pub)}}})
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, jwks, 0o600); err != nil {
		t.Fatal(err)
	}
	const td, aud = "example.org", "pam-broker"
	verifier, err := agentid.NewSVIDVerifier(path, td, aud, 3)
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
	opts.BrokerMaxDelegation = 3
	opts.BrokerExchangeTTL = 5 * time.Minute
	srv, _ := newTestServerOpts(t, nil, opts)

	mint := func(sub string) string {
		hdr := b64([]byte(`{"alg":"EdDSA","kid":"k1","typ":"JWT"}`))
		claims, _ := json.Marshal(map[string]any{
			"sub": "spiffe://example.org/" + sub, "aud": aud, "exp": time.Now().Add(time.Hour).Unix()})
		signing := hdr + "." + b64(claims)
		return signing + "." + b64(ed25519.Sign(priv, []byte(signing)))
	}
	planner, worker := mint("planner"), mint("worker")
	helper, stranger := mint("helper"), mint("stranger")

	// Hop 1: the planner delegates to the worker, and pins that only the helper
	// may go on to act for that token.
	code, body := postForm(t, srv, "/v1/token", planner, url.Values{
		"grant_type":  {agentid.ExchangeGrantType},
		"actor_token": {worker},
		"may_act":     {"spiffe://example.org/helper"},
	})
	if code != http.StatusOK {
		t.Fatalf("hop 1: %d %s", code, body)
	}
	delegated, _ := jsonMap(t, body)["access_token"].(string)
	if delegated == "" {
		t.Fatalf("no delegated token: %s", body)
	}

	// Hop 2 by the pinned party succeeds...
	if code, body := postForm(t, srv, "/v1/token", delegated, url.Values{
		"grant_type":  {agentid.ExchangeGrantType},
		"actor_token": {helper},
	}); code != http.StatusOK {
		t.Fatalf("the pinned actor should be able to act: %d %s", code, body)
	}
	// ...and by anyone else is refused, which is the whole point: before this
	// phase the minted token carried no may_act, so this call succeeded.
	code, body = postForm(t, srv, "/v1/token", delegated, url.Values{
		"grant_type":  {agentid.ExchangeGrantType},
		"actor_token": {stranger},
	})
	if code == http.StatusOK {
		t.Fatalf("an actor the token does not name must not be delegated to: %s", body)
	}
	if !strings.Contains(string(body), "may_act") {
		t.Fatalf("the refusal should name the claim that refused it: %s", body)
	}

	// The pin is on the trail, so an investigator can answer "who was this token
	// allowed to be handed to" without holding the token.
	_, aud2 := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if !strings.Contains(string(aud2), "may_act:") || !strings.Contains(string(aud2), "helper") {
		t.Fatalf("the issued token's may_act should be audited: %s", aud2)
	}

	// A party outside the trust domain cannot be pinned at all — a token naming
	// a foreign actor as permitted is either a mistake or an attempt to make
	// PAMv1's own enforcement read as though somebody outside had been vouched
	// for.
	if code, _ := postForm(t, srv, "/v1/token", planner, url.Values{
		"grant_type":  {agentid.ExchangeGrantType},
		"actor_token": {worker},
		"may_act":     {"spiffe://evil.example/helper"},
	}); code == http.StatusOK {
		t.Fatal("may_act must not name an out-of-domain party")
	}
}

// TestDelegatedCallJoinsItsMintAndShowsItsChain covers Phase 183: the two halves
// of a delegation were both on the trail with nothing linking them, and the
// human approving a call could not see it had arrived through one.
//
// `broker.token.exchanged` has carried the minted token's `jti` since Phase 161;
// the calls made with that token carried no token id at all, so an investigator
// could see a token issued and calls arriving and could not prove they were the
// same token. And `PendingApproval` named the calling agent without saying on
// whose authority, through how many hands.
func TestDelegatedCallJoinsItsMintAndShowsItsChain(t *testing.T) {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]any{
		{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": b64(pub)}}})
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, jwks, 0o600); err != nil {
		t.Fatal(err)
	}
	const td, aud = "example.org", "pam-broker"
	verifier, err := agentid.NewSVIDVerifier(path, td, aud, 3)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	if err := verifier.TrustIssuer(agentid.KeyID(signPub), signPub); err != nil {
		t.Fatal(err)
	}
	opts := brokerOpts(t, &fakeWinRM{result: winrm.Result{Stdout: "ok"}}, approvalRules)
	opts.BrokerSVIDVerifier = verifier
	opts.BrokerTokenSignKey = signPriv
	opts.BrokerAudience = aud
	opts.BrokerMaxDelegation = 3
	opts.BrokerExchangeTTL = 5 * time.Minute
	srv, _ := newTestServerOpts(t, nil, opts)
	seedWinRMTarget(t, srv, "win-chain-view", "pw")

	mint := func(sub string) string {
		hdr := b64([]byte(`{"alg":"EdDSA","kid":"k1","typ":"JWT"}`))
		claims, _ := json.Marshal(map[string]any{
			"sub": "spiffe://example.org/" + sub, "aud": aud,
			"exp": time.Now().Add(time.Hour).Unix(), "jti": "src-" + sub})
		signing := hdr + "." + b64(claims)
		return signing + "." + b64(ed25519.Sign(priv, []byte(signing)))
	}
	planner, worker := mint("planner"), mint("worker")

	code, body := postForm(t, srv, "/v1/token", planner, url.Values{
		"grant_type":  {agentid.ExchangeGrantType},
		"actor_token": {worker},
	})
	if code != http.StatusOK {
		t.Fatalf("exchange: %d %s", code, body)
	}
	delegated, _ := jsonMap(t, body)["access_token"].(string)

	// A call with the delegated token parks for approval.
	_, pd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", delegated,
		map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-chain-view", "command": "id"}})
	if jsonMap(t, pd)["status"] != "pending_approval" {
		t.Fatalf("want pending_approval: %s", pd)
	}

	// The approver sees the chain, not just the calling agent.
	_, ld := do(t, srv, http.MethodGet, "/v1/approvals", testAPIKey, nil)
	if !strings.Contains(string(ld), "actor_chain") ||
		!strings.Contains(string(ld), "spiffe://example.org/planner") {
		t.Fatalf("the approval queue should carry the delegation chain: %s", ld)
	}

	// And the trail joins the mint to the call made with it: the exchange row's
	// jti and the call row's svid_jti are the same token.
	_, aud2 := do(t, srv, http.MethodGet, "/api/audit?limit=80", testAPIKey, nil)
	trail := string(aud2)
	if !strings.Contains(trail, "svid_jti:") {
		t.Fatalf("a call made with a delegated token should record its token id: %s", trail)
	}
	minted := jtiFrom(t, trail, "broker.token.exchanged", "jti:")
	used := jtiFrom(t, trail, "broker.tool_call.pending_approval", "svid_jti:")
	if minted == "" || minted != used {
		t.Fatalf("the minted token id %q should be the one the call used %q", minted, used)
	}
}

// jtiFrom pulls a quoted id out of the audit row for action, by field prefix.
func jtiFrom(t *testing.T, trail, action, field string) string {
	t.Helper()
	for _, line := range strings.Split(trail, "{") {
		if !strings.Contains(line, action) {
			continue
		}
		i := strings.Index(line, field)
		if i < 0 {
			continue
		}
		rest := line[i+len(field):]
		rest = strings.TrimPrefix(rest, `\"`)
		if j := strings.Index(rest, `\"`); j > 0 {
			return rest[:j]
		}
	}
	return ""
}
