package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// seedNamedTarget creates a WinRM target with its own credential username and
// returns the target's id. Distinct usernames are what make a credential
// listing attributable to one target, which is what the scoping assertions rest
// on.
func seedNamedTarget(t *testing.T, srv *httptest.Server, name, username, secret string) int64 {
	t.Helper()
	st, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": name, "host": "10.0.0.9", "port": 5985, "os_type": "windows", "protocol": "winrm",
	})
	if st != http.StatusCreated {
		t.Fatalf("seed target %s: %d %s", name, st, td)
	}
	id := int64(jsonMap(t, td)["id"].(float64))
	if st, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": id, "username": username, "secret": secret,
	}); st != http.StatusCreated {
		t.Fatalf("seed credential for %s: %d %s", name, st, d)
	}
	return id
}

// grantTarget grants one named subject access to a target, which also GATES the
// target: a target with no grants at all is ungated and open to everyone
// (auth.CanConnectTarget), so a scoping test that did not grant would prove
// nothing.
func grantTarget(t *testing.T, srv *httptest.Server, targetID int64, subject string) {
	t.Helper()
	if st, d := do(t, srv, http.MethodPost, "/api/targets/"+itoa(targetID)+"/grants", testAPIKey,
		map[string]any{"subject_type": "user", "subject": subject}); st != http.StatusCreated {
		t.Fatalf("grant %s: %d %s", subject, st, d)
	}
}

// TestBrokerInventoryToolsScopedToGrants pins Phase 169's second half: the two
// broker inventory tools answer for the targets the calling agent may reach, and
// for nothing else.
//
// Before it, list_targets discarded the principal outright — an agent with zero
// grants was handed every hostname, OS and protocol in the estate, and
// list_credentials handed it every login name on them. That is reconnaissance
// given free to the least-trusted actor in the system, and it was the one place
// in broker_tools.go that ignored the grants every acting tool enforces.
func TestBrokerInventoryToolsScopedToGrants(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, toolsetRules))

	mine := seedNamedTarget(t, srv, "win-mine", "svc-mine", "pw-mine")
	theirs := seedNamedTarget(t, srv, "win-theirs", "svc-theirs", "pw-theirs")
	// Both targets are gated, so neither is visible by the "no grants ⇒ open"
	// rule; only the grant tells them apart.
	grantTarget(t, srv, mine, "bot-scope")
	grantTarget(t, srv, theirs, "some-other-agent")

	_, tok := mintAgent(t, srv, "bot-scope", "alice", nil)

	_, td := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "list_targets"})
	if m := jsonMap(t, td); m["status"] != "executed" {
		t.Fatalf("list_targets: %s", td)
	}
	if !strings.Contains(string(td), "win-mine") {
		t.Fatalf("the granted target must be listed: %s", td)
	}
	if strings.Contains(string(td), "win-theirs") {
		t.Fatalf("list_targets leaked a target the agent has no grant on: %s", td)
	}

	// The unfiltered credential listing is narrowed the same way.
	_, cd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "list_credentials"})
	if m := jsonMap(t, cd); m["status"] != "executed" {
		t.Fatalf("list_credentials: %s", cd)
	}
	if !strings.Contains(string(cd), "svc-mine") || strings.Contains(string(cd), "svc-theirs") {
		t.Fatalf("list_credentials must show only the granted target's accounts: %s", cd)
	}

	// Naming an ungranted target is refused rather than answered with an empty
	// list: "you may not" and "there is nothing" are different facts.
	_, fd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok,
		map[string]any{"tool": "list_credentials", "args": map[string]any{"target": "win-theirs"}})
	if m := jsonMap(t, fd); m["status"] == "executed" {
		t.Fatalf("listing credentials on an ungranted target must not execute: %s", fd)
	}
	if !strings.Contains(string(fd), "not authorized") {
		t.Fatalf("refusal should say why: %s", fd)
	}
}

// TestAgentQuarantineFollowsDelegationChain pins Phase 169's first half: an
// agent presenting a DELEGATED token is stopped when any actor in that token's
// chain is quarantined, not only when its own subject is.
//
// The hole this closes: quarantine was checked against the presenter's subject
// alone, while a delegated SVID names its root only in the RFC 8693 `act` chain.
// Quarantining a compromised root therefore left every sub-agent token it had
// already minted working until its TTL expired — an incident responder pressing
// the stop button and watching the compromise carry on for the rest of the
// token's life.
func TestAgentQuarantineFollowsDelegationChain(t *testing.T) {
	const (
		root = "spiffe://example.org/ns/prod/sa/planner"
		sub  = "spiffe://example.org/ns/prod/sa/worker"
	)
	svid, verifier := mintDelegatedSVID(t, sub, root)

	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	opts := brokerOpts(t, fake, toolsetRules)
	opts.BrokerSVIDVerifier = verifier
	srv, _ := newTestServerOpts(t, nil, opts)
	seedWinRMTarget(t, srv, "win-chain", "pw")

	call := func() int {
		st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", svid, map[string]any{"tool": "list_targets"})
		return st
	}
	if st := call(); st != http.StatusOK {
		t.Fatalf("baseline delegated call: want 200, got %d", st)
	}

	// Quarantine the ROOT, which is not the subject presenting the token.
	status, qd := do(t, srv, http.MethodPost, "/v1/agents/quarantine", testAPIKey,
		map[string]any{"subject": root, "reason": "compromised planner, INC-5012"})
	if status != http.StatusCreated {
		t.Fatalf("quarantine root: %d %s", status, qd)
	}
	qid := int64(jsonMap(t, qd)["id"].(float64))

	if st := call(); st != http.StatusUnauthorized {
		t.Fatalf("a token delegated FROM a quarantined root must be refused, got %d", st)
	}
	// The trail names the chain member that did the stopping, so a responder is
	// not left wondering why an agent they never quarantined went quiet.
	_, adata := do(t, srv, http.MethodGet, "/api/audit?limit=80", testAPIKey, nil)
	if !strings.Contains(string(adata), "agent.quarantine_refused") || !strings.Contains(string(adata), root) {
		t.Fatalf("the refusal should be on the trail, naming the quarantined root: %s", adata)
	}

	// Releasing the root restores the sub-agent: the quarantine was the only
	// thing stopping it, and it is per subject rather than a blanket halt.
	if st, _ := do(t, srv, http.MethodDelete, "/v1/agents/quarantine/"+itoa(qid), testAPIKey, nil); st != http.StatusNoContent {
		t.Fatal("release should succeed")
	}
	if st := call(); st != http.StatusOK {
		t.Fatalf("after release the delegated call should work again, got %d", st)
	}
}

// mintDelegatedSVID returns a signed JWT-SVID for subject that carries an RFC
// 8693 `act` claim naming actor (its delegator), plus the verifier that trusts
// it. Written here rather than reused from broker_svid_test.go because that
// fixture deliberately runs at maxDepth 1 — no delegation at all — and the
// delegation chain is the whole point of this test.
func mintDelegatedSVID(t *testing.T, subject, actor string) (string, *agentid.SVIDVerifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	jwks, err := json.Marshal(map[string]any{"keys": []map[string]any{
		{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": b64(pub)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, jwks, 0o600); err != nil {
		t.Fatal(err)
	}
	verifier, err := agentid.NewSVIDVerifier(path, "example.org", "pam-broker", 3)
	if err != nil {
		t.Fatal(err)
	}
	hdr := b64([]byte(`{"alg":"EdDSA","kid":"k1","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"sub": subject, "aud": "pam-broker", "exp": 4102444800,
		"act": map[string]any{"sub": actor},
	})
	if err != nil {
		t.Fatal(err)
	}
	signing := hdr + "." + b64(claims)
	return signing + "." + b64(ed25519.Sign(priv, []byte(signing))), verifier
}
