package agentid_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
)

// exchangeFixture builds a trust domain, a verifier that also trusts the
// broker's own issuer key, and the exchanger — the exact wiring main does, so
// the tests prove the round trip that matters: a MINTED token must verify at the
// ingress that minted it.
func exchangeFixture(t *testing.T, maxDepth int, ttl time.Duration) (
	*agentid.SVIDVerifier, *agentid.Exchanger, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	path := edJWKS(t, pub, "k1")
	const td, aud = "example.org", "pam-broker"
	v, err := agentid.NewSVIDVerifier(path, td, aud, maxDepth)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	if err := v.TrustIssuer(agentid.KeyID(signPub), signPub); err != nil {
		t.Fatal(err)
	}
	x, err := agentid.NewExchanger(agentid.ExchangerConfig{
		SignKey: signPriv, Audience: aud, TTL: ttl, MaxDepth: maxDepth, Verifier: v,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v, x, priv, aud
}

// svid mints a trust-domain SVID for a workload path.
func svid(t *testing.T, priv ed25519.PrivateKey, aud, path string, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"sub": "spiffe://example.org/" + path,
		"aud": aud,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	return makeEdDSA(t, priv, "k1", claims)
}

// form builds an RFC 8693 request from key/value pairs.
func form(kv ...string) map[string][]string {
	out := map[string][]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = append(out[kv[i]], kv[i+1])
	}
	return out
}

// TestExchangeMintsAUsableDelegation is the flagship: a delegator exchanges for
// its sub-agent, and the minted token VERIFIES at the ingress — carrying the
// sub-agent as the subject, the delegator in the actor chain, and the original
// accountable party still at the end of it.
func TestExchangeMintsAUsableDelegation(t *testing.T) {
	ctx := context.Background()
	v, x, priv, aud := exchangeFixture(t, 3, 5*time.Minute)

	delegatorToken := svid(t, priv, aud, "planner", nil)
	delegator, err := v.Verify(ctx, delegatorToken)
	if err != nil {
		t.Fatalf("delegator SVID: %v", err)
	}
	actorToken := svid(t, priv, aud, "worker", nil)

	req, err := agentid.ParseExchangeForm(form(
		"grant_type", agentid.ExchangeGrantType,
		"actor_token", actorToken,
		"subject_token", delegatorToken,
	))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	issued, err := x.Exchange(ctx, req, delegator)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if issued.ExpiresIn <= 0 || issued.ExpiresIn > 300 {
		t.Fatalf("expires_in = %d, want (0,300]", issued.ExpiresIn)
	}

	// The minted token is usable: it verifies at the same ingress.
	id, err := v.Verify(ctx, issued.Token)
	if err != nil {
		t.Fatalf("the minted token does not verify at the ingress that minted it: %v", err)
	}
	if id.SPIFFEID != "spiffe://example.org/worker" {
		t.Fatalf("minted sub = %q, want the ACTOR (SPIFFE keeps sub = presenter)", id.SPIFFEID)
	}
	want := []string{"spiffe://example.org/worker", "spiffe://example.org/planner"}
	if len(id.ActorChain) != 2 || id.ActorChain[0] != want[0] || id.ActorChain[1] != want[1] {
		t.Fatalf("actor chain = %v, want %v", id.ActorChain, want)
	}
	if id.OnBehalfOf != "spiffe://example.org/planner" {
		t.Fatalf("on behalf of = %q, want the delegator", id.OnBehalfOf)
	}
	if issued.Audit == "" {
		t.Fatal("the exchange recorded no audit detail")
	}
}

// TestExchangeChainGrowsAndCaps proves a re-delegation adds exactly one link and
// that the depth cap stops the chain at MINT time — not merely on presentation,
// so a runaway spawn cannot produce tokens at all.
func TestExchangeChainGrowsAndCaps(t *testing.T) {
	ctx := context.Background()
	v, x, priv, aud := exchangeFixture(t, 2, 5*time.Minute)

	first, _ := v.Verify(ctx, svid(t, priv, aud, "planner", nil))
	req, _ := agentid.ParseExchangeForm(form(
		"grant_type", agentid.ExchangeGrantType,
		"actor_token", svid(t, priv, aud, "worker", nil)))
	issued, err := x.Exchange(ctx, req, first)
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}

	// The worker now re-delegates using the token it was just issued.
	worker, err := v.Verify(ctx, issued.Token)
	if err != nil {
		t.Fatalf("minted token: %v", err)
	}
	req2, _ := agentid.ParseExchangeForm(form(
		"grant_type", agentid.ExchangeGrantType,
		"actor_token", svid(t, priv, aud, "helper", nil)))
	if _, err := x.Exchange(ctx, req2, worker); err == nil {
		t.Fatal("a third link was minted despite PAM_BROKER_MAX_DELEGATION_DEPTH=2")
	}

	// With room for three links, the same re-delegation succeeds and the chain
	// grows by exactly one, keeping the original delegator accountable at the end.
	dv, dx, dpriv, daud := exchangeFixture(t, 3, 5*time.Minute)
	planner, _ := dv.Verify(ctx, svid(t, dpriv, daud, "planner", nil))
	r1, _ := agentid.ParseExchangeForm(form(
		"grant_type", agentid.ExchangeGrantType,
		"actor_token", svid(t, dpriv, daud, "worker", nil)))
	i1, err := dx.Exchange(ctx, r1, planner)
	if err != nil {
		t.Fatalf("deep first exchange: %v", err)
	}
	w, _ := dv.Verify(ctx, i1.Token)
	r2, _ := agentid.ParseExchangeForm(form(
		"grant_type", agentid.ExchangeGrantType,
		"actor_token", svid(t, dpriv, daud, "helper", nil)))
	i2, err := dx.Exchange(ctx, r2, w)
	if err != nil {
		t.Fatalf("deep re-delegation: %v", err)
	}
	h, err := dv.Verify(ctx, i2.Token)
	if err != nil {
		t.Fatalf("the re-delegated token does not verify: %v", err)
	}
	want := []string{"spiffe://example.org/helper", "spiffe://example.org/worker", "spiffe://example.org/planner"}
	if len(h.ActorChain) != 3 {
		t.Fatalf("chain = %v, want 3 links %v", h.ActorChain, want)
	}
	for i := range want {
		if h.ActorChain[i] != want[i] {
			t.Fatalf("chain = %v, want %v", h.ActorChain, want)
		}
	}
	if h.OnBehalfOf != want[2] {
		t.Fatalf("on behalf of = %q, want the original delegator %q", h.OnBehalfOf, want[2])
	}
}

// TestExchangeRefusals covers every refusal that carries a security argument.
func TestExchangeRefusals(t *testing.T) {
	ctx := context.Background()
	v, x, priv, aud := exchangeFixture(t, 3, 5*time.Minute)
	delegatorToken := svid(t, priv, aud, "planner", nil)
	delegator, _ := v.Verify(ctx, delegatorToken)
	actorToken := svid(t, priv, aud, "worker", nil)

	cases := []struct {
		name string
		kv   []string
		want string
	}{
		{"impersonation (no actor token) is unsupported",
			[]string{"grant_type", agentid.ExchangeGrantType}, "invalid_request"},
		{"a foreign grant type",
			[]string{"grant_type", "client_credentials", "actor_token", actorToken}, "unsupported_grant_type"},
		{"scope is refused, not silently dropped",
			[]string{"grant_type", agentid.ExchangeGrantType, "actor_token", actorToken, "scope", "admin"}, "invalid_scope"},
		{"another audience is not issuable",
			[]string{"grant_type", agentid.ExchangeGrantType, "actor_token", actorToken, "audience", "some-other-service"}, "invalid_target"},
		{"an unsupported requested token type",
			[]string{"grant_type", agentid.ExchangeGrantType, "actor_token", actorToken,
				"requested_token_type", "urn:ietf:params:oauth:token-type:access_token"}, "invalid_request"},
		{"an unverifiable actor token",
			[]string{"grant_type", agentid.ExchangeGrantType, "actor_token", "not.a.token"}, "invalid_request"},
		{"delegating to yourself",
			[]string{"grant_type", agentid.ExchangeGrantType, "actor_token", delegatorToken}, "invalid_request"},
	}
	for _, tc := range cases {
		req, perr := agentid.ParseExchangeForm(form(tc.kv...))
		if perr == nil {
			_, perr = x.Exchange(ctx, req, delegator)
		}
		if perr == nil {
			t.Fatalf("%s: the exchange succeeded", tc.name)
		}
		ee, ok := perr.(*agentid.ExchangeError)
		if !ok || ee.Code != tc.want {
			t.Fatalf("%s: error = %v, want code %q", tc.name, perr, tc.want)
		}
	}

	// A subject_token naming someone ELSE is the exchange that must never work:
	// a party holding two captured tokens must not be able to mint a delegation
	// between them.
	other := svid(t, priv, aud, "someone-else", nil)
	req, _ := agentid.ParseExchangeForm(form(
		"grant_type", agentid.ExchangeGrantType,
		"actor_token", actorToken,
		"subject_token", other))
	if _, err := x.Exchange(ctx, req, delegator); err == nil {
		t.Fatal("an agent delegated authority it had not authenticated with")
	}

	// A repeated parameter is ambiguous and refused rather than last-wins.
	if _, err := agentid.ParseExchangeForm(map[string][]string{
		"grant_type":  {agentid.ExchangeGrantType},
		"actor_token": {actorToken, other},
	}); err == nil {
		t.Fatal("a repeated actor_token was accepted")
	}
}

// TestExchangeMayAct proves RFC 8693 §4.4: a delegator whose own token pins
// may_act can only delegate to the actor(s) it names.
func TestExchangeMayAct(t *testing.T) {
	ctx := context.Background()
	v, x, priv, aud := exchangeFixture(t, 3, 5*time.Minute)

	pinned, err := v.Verify(ctx, svid(t, priv, aud, "planner", map[string]any{
		"may_act": map[string]any{"sub": "spiffe://example.org/blessed"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(pinned.MayAct) != 1 || pinned.MayAct[0] != "spiffe://example.org/blessed" {
		t.Fatalf("may_act = %v, want the single pinned subject", pinned.MayAct)
	}
	refused, _ := agentid.ParseExchangeForm(form(
		"grant_type", agentid.ExchangeGrantType,
		"actor_token", svid(t, priv, aud, "worker", nil)))
	if _, err := x.Exchange(ctx, refused, pinned); err == nil {
		t.Fatal("an actor outside may_act was delegated to")
	}
	allowed, _ := agentid.ParseExchangeForm(form(
		"grant_type", agentid.ExchangeGrantType,
		"actor_token", svid(t, priv, aud, "blessed", nil)))
	if _, err := x.Exchange(ctx, allowed, pinned); err != nil {
		t.Fatalf("the pinned actor was refused: %v", err)
	}

	// A list form is accepted too.
	listPinned, _ := v.Verify(ctx, svid(t, priv, aud, "planner2", map[string]any{
		"may_act": map[string]any{"sub": []string{"spiffe://example.org/a", "spiffe://example.org/blessed"}},
	}))
	if _, err := x.Exchange(ctx, allowed, listPinned); err != nil {
		t.Fatalf("a listed may_act actor was refused: %v", err)
	}
}

// TestExchangeNeverOutlivesItsSource proves the delegated token's expiry is
// capped by the delegator's own, and that an expiring delegator cannot mint.
func TestExchangeNeverOutlivesItsSource(t *testing.T) {
	ctx := context.Background()
	v, x, priv, aud := exchangeFixture(t, 3, time.Hour) // a long TTL...

	// ...but a delegator with only ~90s left. (The verifier allows 60s of leeway
	// on expiry, so this stays inside a valid token's life.)
	shortLived := makeEdDSA(t, priv, "k1", map[string]any{
		"sub": "spiffe://example.org/planner", "aud": aud,
		"exp": time.Now().Add(90 * time.Second).Unix(),
	})
	delegator, err := v.Verify(ctx, shortLived)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := agentid.ParseExchangeForm(form(
		"grant_type", agentid.ExchangeGrantType,
		"actor_token", svid(t, priv, aud, "worker", nil)))
	issued, err := x.Exchange(ctx, req, delegator)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if issued.ExpiresIn > 95 {
		t.Fatalf("expires_in = %d: delegated authority outlived the token it came from", issued.ExpiresIn)
	}

	// An already-expired delegator mints nothing.
	stale := &agentid.Identity{SPIFFEID: "spiffe://example.org/planner",
		ActorChain: []string{"spiffe://example.org/planner"},
		ExpiresAt:  time.Now().Add(-time.Minute)}
	if _, err := x.Exchange(ctx, req, stale); err == nil {
		t.Fatal("an expired delegator minted a token")
	}
	// A static-key agent (no SPIFFE identity) cannot delegate at all.
	static := &agentid.Identity{AgentName: "legacy-agent", OnBehalfOf: "alice"}
	if _, err := x.Exchange(ctx, req, static); err == nil {
		t.Fatal("a static-key agent delegated")
	}
}

// TestTrustIssuerRefusesKidCollision proves the ingress will not let the
// broker's own key shadow a trust-domain key — a substitution nobody could see.
func TestTrustIssuerRefusesKidCollision(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	path := edJWKS(t, pub, "k1")
	v, err := agentid.NewSVIDVerifier(path, "example.org", "pam-broker", 2)
	if err != nil {
		t.Fatal(err)
	}
	signPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := v.TrustIssuer("k1", signPub); err == nil {
		t.Fatal("the broker's key was allowed to shadow a trust-domain kid")
	}
	if err := v.TrustIssuer("", signPub); err == nil {
		t.Fatal("an empty kid was accepted")
	}
}

// TestExchangerConstructionFailsClosed: no key, no audience, no verifier — each
// is fatal rather than a silently permissive minter.
func TestExchangerConstructionFailsClosed(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	v, _, _, _ := exchangeFixture(t, 2, time.Minute)
	for _, tc := range []struct {
		name string
		cfg  agentid.ExchangerConfig
	}{
		{"no signing key", agentid.ExchangerConfig{Audience: "a", Verifier: v}},
		{"no audience", agentid.ExchangerConfig{SignKey: priv, Verifier: v}},
		{"no verifier", agentid.ExchangerConfig{SignKey: priv, Audience: "a"}},
	} {
		if _, err := agentid.NewExchanger(tc.cfg); err == nil {
			t.Fatalf("%s: an exchanger was built anyway", tc.name)
		}
	}
}

// TestExchangeAuditResistsFieldForgery pins the shape of the delegation record —
// the evidence for who an agent token was minted for.
//
// The record used to be assembled unquoted and quoted as ONE string by the API
// handler. That stops a value breaking out of the record, and it is not enough:
// the console un-quotes a detail and then splits it on spaces, so an inner
// `key:value` still became a field, and that parser takes last-wins. An
// on_behalf_of of `ops-team actor:spiffe://trusted/root` therefore made the
// console display an actor the token was never minted for — a forged identity in
// exactly the record an investigator opens to answer "which agent did this".
//
// OnBehalfOf is reachable: for a static broker key it is the key's Owner, set
// when the agent was registered, and for an SVID it is the tail of the presented
// delegation chain.
func TestExchangeAuditResistsFieldForgery(t *testing.T) {
	ctx := context.Background()
	v, x, priv, aud := exchangeFixture(t, 3, 5*time.Minute)

	delegator, err := v.Verify(ctx, svid(t, priv, aud, "planner", nil))
	if err != nil {
		t.Fatalf("delegator SVID: %v", err)
	}
	delegator.OnBehalfOf = "ops-team actor:spiffe://trusted/root on_behalf_of:ceo"

	req, err := agentid.ParseExchangeForm(form(
		"grant_type", agentid.ExchangeGrantType,
		"actor_token", svid(t, priv, aud, "worker", nil),
		"subject_token", svid(t, priv, aud, "planner", nil),
	))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	issued, err := x.Exchange(ctx, req, delegator)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Read it the way the console does: outside the quoted spans, none of the
	// injected text may survive as a field.
	outside := quotedSpan.ReplaceAllString(issued.Audit, `""`)
	for _, forged := range []string{"actor:spiffe://trusted/root", "on_behalf_of:ceo"} {
		if strings.Contains(outside, forged) {
			t.Fatalf("a hostile on_behalf_of forged %q into the delegation record: %q", forged, issued.Audit)
		}
	}
	// The real actor must still be readable — this is evidence, not just safety.
	if !strings.Contains(issued.Audit, `actor:"spiffe://example.org/worker"`) {
		t.Fatalf("the real actor is missing from the record: %q", issued.Audit)
	}
}

// quotedSpan matches one Go-quoted string, so a test can strip the spans a
// quoting-aware reader would never parse fields out of.
var quotedSpan = regexp.MustCompile(`"(\\.|[^"\\])*"`)
