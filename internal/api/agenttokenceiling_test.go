package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// TestTokenCeilingIsPerToken is the assertion the whole phase rests on, and it
// is deliberately shaped so a pass cannot be faked by a counter that simply
// counts calls: the SAME agent, over the SAME connection, spends its ceiling
// with one token and then keeps working with a second one obtained from the
// exchange.
//
// If the ceiling were keyed on the agent it would refuse the second token too;
// if it were keyed on the caller-declared `session:` the first token would never
// have been stopped at all, because the test could simply have changed the
// string. Only a ceiling keyed on the ISSUER-chosen `jti` produces both
// outcomes.
func TestTokenCeilingIsPerToken(t *testing.T) {
	const ceiling = 2
	srv, st, mint, exchange := ceilingServer(t, ceiling)

	first := exchange(t, srv, mint("planner"), mint("worker"))
	call := map[string]any{"tool": "list_targets"}

	// The ceiling is spent, not merely configured: two calls succeed.
	for i := range ceiling {
		sc, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", first, call)
		if sc != http.StatusOK || jsonMap(t, data)["status"] != "executed" {
			t.Fatalf("call %d of the ceiling was refused: %d %s", i+1, sc, data)
		}
	}

	// The next one is refused — and refused as a DENIAL with a reason, not as a
	// 401: the token is still perfectly valid, it has simply spent its allowance,
	// and telling the agent that is the difference between a control it can act
	// on and one that looks like a broken credential.
	sc, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", first, call)
	out := jsonMap(t, data)
	if sc != http.StatusOK || out["status"] != "denied" {
		t.Fatalf("the over-ceiling call was not denied: %d %s", sc, data)
	}
	if reason, _ := out["reason"].(string); !strings.Contains(reason, "spent its ceiling") {
		t.Fatalf("reason = %q, want it to name the ceiling", reason)
	}

	// A SECOND token, minted through the exchange, starts clean. This is the
	// property that makes the ceiling a blast-radius bound rather than a quota:
	// the agent is not punished, the credential is retired.
	second := exchange(t, srv, mint("planner"), mint("worker"))
	if second == first {
		t.Fatal("the exchange returned the same token twice; the test proves nothing")
	}
	if sc, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", second, call); sc != http.StatusOK ||
		jsonMap(t, data)["status"] != "executed" {
		t.Fatalf("a freshly minted token did not start a new ceiling: %d %s", sc, data)
	}

	// The refusal is on the record under its own action, carrying the token it
	// was about — so an investigator can join it to the calls that spent it and
	// to the `broker.token.exchanged` row that issued it.
	events, err := st.ListAudit(t.Context(), 300)
	if err != nil {
		t.Fatal(err)
	}
	var detail string
	for _, e := range events {
		if e.Action == "agent.token_budget_exhausted" {
			detail = e.Detail
		}
	}
	if detail == "" {
		t.Fatal("no agent.token_budget_exhausted event was recorded")
	}
	for _, want := range []string{"used:2", "limit:2", "svid_jti:"} {
		if !strings.Contains(detail, want) {
			t.Errorf("audit detail %q is missing %q", detail, want)
		}
	}
}

// TestTokenCeilingLeavesOtherIdentitiesAlone asserts the behaviour an operator
// is promised: a static agent key keeps working past the per-token ceiling,
// because it has no token to have a ceiling on. "This control does not apply to
// that identity kind" is exactly the thing an operator must not discover by
// experiment.
//
// **What this test does NOT prove, stated because the mutation check said so.**
// The exemption survives deleting BOTH explicit guards — the early return in
// tokenCeilingRefusal and the empty-jti short-circuit in the store. It is held
// structurally, one layer further down: a static key never causes an
// `svid_jti:` field to be WRITTEN, so no search for one can ever match it. The
// two guards are therefore belt to that braces, and they earn their place by
// making the intent readable and by skipping a pointless store round-trip on
// every call — not by being what stops the miscount. A test that claimed to pin
// them would be claiming coverage it does not have.
func TestTokenCeilingLeavesOtherIdentitiesAlone(t *testing.T) {
	srv, st, _, _ := ceilingServer(t, 1)

	// A static agent key carries no token id at all. Its ceiling is the per-day
	// budget on its own row, so it must keep working past the per-token limit.
	const staticToken = "static-agent-bearer-key"
	k := store.AgentKey{Name: "batch-agent", Owner: "ops", TokenHash: auth.TokenHash(staticToken)}
	if err := st.CreateAgentKey(t.Context(), &k); err != nil {
		t.Fatal(err)
	}
	call := map[string]any{"tool": "list_targets"}
	for i := range 3 {
		if sc, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", staticToken, call); sc != http.StatusOK {
			t.Fatalf("static key call %d refused by the per-token ceiling: %d %s", i+1, sc, data)
		}
	}
}

// ceilingServer builds a broker with a per-token ceiling, an SVID verifier and
// the token exchange mounted, plus helpers to mint trust-domain SVIDs and to run
// a real exchange through the HTTP endpoint.
func ceilingServer(t *testing.T, ceiling int) (
	srv *httptest.Server, st store.Store,
	mint func(sub string) string,
	exchange func(t *testing.T, srv *httptest.Server, delegator, actor string) string,
) {
	return ceilingServerWithRules(t, ceiling, toolsetRules)
}

// ceilingServerWithRules is ceilingServer with the policy chosen by the caller,
// so a test can park calls for approval and prove the ceiling counts them.
func ceilingServerWithRules(t *testing.T, ceiling int, rules string) (
	srv *httptest.Server, st store.Store,
	mint func(sub string) string,
	exchange func(t *testing.T, srv *httptest.Server, delegator, actor string) string,
) {
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
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	if err := verifier.TrustIssuer(agentid.KeyID(signPub), signPub); err != nil {
		t.Fatal(err)
	}

	opts := brokerOpts(t, &fakeWinRM{result: winrm.Result{Stdout: "ok"}}, rules)
	opts.BrokerSVIDVerifier = verifier
	opts.BrokerTokenSignKey = signPriv
	opts.BrokerAudience = aud
	opts.BrokerMaxDelegation = 2
	opts.BrokerExchangeTTL = 5 * time.Minute
	opts.BrokerMaxCallsPerToken = ceiling
	s, store2 := newTestServerOpts(t, nil, opts)

	mint = func(sub string) string {
		hdr := b64([]byte(`{"alg":"EdDSA","kid":"k1","typ":"JWT"}`))
		claims, _ := json.Marshal(map[string]any{
			"sub": "spiffe://example.org/" + sub, "aud": aud,
			"exp": time.Now().Add(time.Hour).Unix(),
			// A distinct jti per mint, the way a real issuer stamps one. Without
			// it every trust-domain SVID would share the empty id and the
			// ceiling would silently not apply to any of them.
			"jti": b64(randBytes(t, 8)),
		})
		signing := hdr + "." + b64(claims)
		return signing + "." + b64(ed25519.Sign(priv, []byte(signing)))
	}
	exchange = func(t *testing.T, srv *httptest.Server, delegator, actor string) string {
		t.Helper()
		code, body := postForm(t, srv, "/v1/token", delegator, url.Values{
			"grant_type":  {agentid.ExchangeGrantType},
			"actor_token": {actor},
		})
		if code != http.StatusOK {
			t.Fatalf("exchange: %d %s", code, body)
		}
		tok, _ := jsonMap(t, body)["access_token"].(string)
		if tok == "" {
			t.Fatalf("exchange issued no token: %s", body)
		}
		return tok
	}
	return s, store2, mint, exchange
}

// randBytes returns n random bytes, failing the test rather than returning an
// error nobody would check.
func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestTokenCeilingCountsResumedWork is the regression test for the 2026-08-26
// audit's finding T-1, the one functional defect this session introduced.
//
// The ceiling counts executed AND resumed rows — but the resume handlers never
// wrote the `svid_jti:` field the count searches for, so a resumed row could
// never match. An agent whose calls required approval therefore did all its
// work through the approval path and charged nothing against its token — the
// precise loophole the daily budget's own doc says must not exist.
//
// The proof is end to end and cannot be satisfied by the fixture alone: a real
// SVID makes a real require_approval call, a human approves it, the agent
// resumes — and the NEXT call must be refused as over-ceiling. Before the fix
// that call was admitted, because the resumed row was invisible to the count.
func TestTokenCeilingCountsResumedWork(t *testing.T) {
	const ceiling = 1
	srv, st, mint, exchange := ceilingServerWithRules(t, ceiling, approvalRules)
	seedWinRMTarget(t, srv, "win-ceil", "vault-pw")
	// The exchange is how a delegated token acquires a pamv1-minted jti; the
	// trust-domain SVIDs the fixture mints carry one too, but a delegated token
	// is the realistic subject of a per-token ceiling.
	token := exchange(t, srv, mint("planner"), mint("worker"))
	// Four-eyes (Phases 170/176) resolves the accountable owner of EVERY link
	// in a delegated token's actor chain, so both the worker and the planner
	// that delegated to it need a recorded owner. A fixture requirement, not
	// the property under test.
	for _, sub := range []string{"worker", "planner"} {
		if sc, d := do(t, srv, http.MethodPost, "/v1/agents/identities", testAPIKey,
			map[string]any{"spiffe_id": "spiffe://example.org/" + sub, "owner": "carol"}); sc != http.StatusCreated {
			t.Fatalf("register %s owner: %d %s", sub, sc, d)
		}
	}

	// 1. Park a call for approval. This spends nothing yet.
	_, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", token,
		map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-ceil", "command": "whoami"}})
	m := jsonMap(t, data)
	if m["status"] != "pending_approval" {
		t.Fatalf("want pending_approval: %s", data)
	}
	callID, _ := m["call_id"].(string)
	resume, _ := m["resume_token"].(string)

	// 2. A human approves; the work executes server-side.
	if sc, dd := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey,
		map[string]any{"approve": true}); sc != http.StatusOK {
		t.Fatalf("approve: %d %s", sc, dd)
	}
	// 3. The agent collects the result. THIS is the row that must charge the
	//    ceiling, and the row the handlers used to write without svid_jti.
	if sc, rd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls/"+callID+"/resume", token,
		map[string]any{"token": resume}); sc != http.StatusOK || jsonMap(t, rd)["status"] != "executed" {
		t.Fatalf("resume: %d %s", sc, rd)
	}

	// 4. The ceiling of 1 is now spent — by approval-path work. The next call
	//    is refused. Before the fix this returned pending_approval again.
	_, data = doBearer(t, srv, http.MethodPost, "/v1/tool-calls", token,
		map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-ceil", "command": "whoami"}})
	out := jsonMap(t, data)
	if out["status"] != "denied" {
		t.Fatalf("a token that spent its ceiling through the approval path was not refused: %s", data)
	}
	if reason, _ := out["reason"].(string); !strings.Contains(reason, "spent its ceiling") {
		t.Fatalf("reason = %q, want the ceiling named", reason)
	}

	// 5. And the resumed row on the trail carries the field the count needs, so
	//    an investigator can join it the same way as an executed row.
	events, err := st.ListAudit(t.Context(), 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == "broker.tool_call.resumed" {
			if !strings.Contains(e.Detail, "svid_jti:") {
				t.Fatalf("the resumed row carries no svid_jti, so the ceiling cannot see it: %s", e.Detail)
			}
			return
		}
	}
	t.Fatal("no broker.tool_call.resumed row was recorded")
}
