package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/sshca"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// TestBrokerExecHonoursCredentialScopedGrant proves an agent whose only grant
// on a target is scoped to ONE credential (Phase 252) cannot run a broker
// exec tool as a different one. Until the review of 250–262 both exec tools
// authorized at target level — which any grant satisfies — and then logged in
// as the target's FIRST credential, so a grant to `deploy` executed as
// the target's first account.
func TestBrokerExecHonoursCredentialScopedGrant(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, brokerRules))
	seedWinRMTarget(t, srv, "win-01", "admin-pw") // first credential: svc
	_, tl := do(t, srv, http.MethodGet, "/api/targets", testAPIKey, nil)
	var targets []struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(tl, &targets); err != nil || len(targets) != 1 {
		t.Fatalf("targets: %s", tl)
	}
	tid := targets[0].ID
	code, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{"target_id": tid, "username": "deploy", "secret": "deploy-pw"})
	if code != http.StatusCreated {
		t.Fatalf("second credential: %d %s", code, d)
	}
	deployID := int64(jsonMap(t, d)["id"].(float64))
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot", "owner": "alice"})
	agentTok, _ := jsonMap(t, ad)["token"].(string)
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", tid), testAPIKey, map[string]any{
		"subject_type": "user", "subject": "bot", "credential_id": deployID,
	}); code != http.StatusCreated {
		t.Fatalf("scoped grant: %d %s", code, d)
	}

	status, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", agentTok, map[string]any{
		"tool": "winrm_exec", "args": map[string]any{"target": "win-01", "command": "whoami"},
	})
	if status != http.StatusOK || jsonMap(t, data)["status"] != "executed" {
		t.Fatalf("the agent is granted `deploy` and must be able to run as it: %d %s", status, data)
	}
	if fake.gotUser != "deploy" || fake.gotPass != "deploy-pw" {
		t.Fatalf("executed as %q — a grant scoped to `deploy` must never log in as another credential", fake.gotUser)
	}
}

// TestOperatorCertHonoursCredentialScopedGrant proves a user whose only grant
// on a target is scoped to `deploy` (Phase 252) cannot have the CA sign an
// operator certificate for `root` on it. The principal IS a credential on the
// target, so the credential was known — and the gate was still handed nil,
// which any grant satisfies. A certificate is the worst place for that gap:
// it works off-proxy, unrecorded.
func TestOperatorCertHonoursCredentialScopedGrant(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{CA: sshca.New(mustTestSigner(t))})
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-op", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	var deployID int64
	for _, u := range []string{"root", "deploy"} {
		code, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{"target_id": tid, "username": u, "secret": "pw"})
		if code != http.StatusCreated {
			t.Fatalf("credential %s: %d %s", u, code, d)
		}
		deployID = int64(jsonMap(t, d)["id"].(float64))
	}
	aliceTok := seedUser(t, srv, "alice", "user")
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", tid), testAPIKey, map[string]any{
		"subject_type": "user", "subject": "alice", "credential_id": deployID,
	}); code != http.StatusCreated {
		t.Fatalf("scoped grant: %d %s", code, d)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	sshPub, _ := ssh.NewPublicKey(pub)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	sign := func(principal string) int {
		t.Helper()
		_, chd := do(t, srv, http.MethodPost, "/api/ca/ssh/challenge", aliceTok, map[string]any{})
		ch, _ := jsonMap(t, chd)["challenge"].(string)
		sig, _ := signer.Sign(rand.Reader, []byte(ch))
		code, _ := do(t, srv, http.MethodPost, "/api/ca/ssh/sign", aliceTok, map[string]any{
			"public_key": pubLine, "challenge": ch, "signature": base64.StdEncoding.EncodeToString(ssh.Marshal(sig)),
			"target": "web-op", "principal": principal,
		})
		return code
	}
	if code := sign("deploy"); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("a cert for the granted credential: want success, got %d", code)
	}
	if code := sign("root"); code != http.StatusForbidden {
		t.Fatalf("a cert for a credential outside the grant: want 403, got %d", code)
	}
}

// TestManagementCredentialHonoursCredentialScopedGrant proves the reveal bar
// on a dependency's management credential is asked about THAT credential: a
// caller whose grant on dc-01 covers only `deploy` cannot name the Domain
// Admin credential beside it and have PAMv1 present its password to a host
// the caller chose.
func TestManagementCredentialHonoursCredentialScopedGrant(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{})
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "dc-01", "host": "10.0.0.5", "port": 5985, "os_type": "windows", "protocol": "winrm",
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	ids := map[string]int64{}
	for _, u := range []string{"CONTOSO\\Domain Admin", "deploy"} {
		code, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{"target_id": tid, "username": u, "secret": "pw-" + u})
		if code != http.StatusCreated {
			t.Fatalf("credential %s: %d %s", u, code, d)
		}
		ids[u] = int64(jsonMap(t, d)["id"].(float64))
	}
	labCredID := seedTargetCred(t, srv, "ssh", "", "lab-secret")
	tok := seedProfileUser(t, srv, "revealer", "rv", "manage_credentials", "reveal_secret", "read_inventory")
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", tid), testAPIKey, map[string]any{
		"subject_type": "user", "subject": "rv", "credential_id": ids["deploy"],
	}); code != http.StatusCreated {
		t.Fatalf("scoped grant: %d %s", code, d)
	}
	declare := func(mgmt int64, name string) int {
		code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/dependencies", labCredID), tok, map[string]any{
			"kind": "windows_service", "host": "attacker.example.com", "name": name, "management_credential_id": mgmt,
		})
		return code
	}
	if code := declare(ids["CONTOSO\\Domain Admin"], "Svc1"); code != http.StatusForbidden {
		t.Fatalf("a management credential outside the grant: want 403, got %d", code)
	}
	auditHas(t, st, "dependency.create_denied", "reason:target-policy")
	if code := declare(ids["deploy"], "Svc2"); code != http.StatusCreated {
		t.Fatalf("the granted credential as management credential: want 201, got %d", code)
	}
}

// TestTieredApprovalWithARowlessApprover proves a chain can progress past an
// approver who has no local user row — a directory identity, or the bootstrap
// admin used here. Role tiers re-derived every past approver's role from the
// users table at each decision, so such an approver satisfied a tier in the
// response to their own approval and then silently stopped counting: the
// next tier's approver was told the request was still waiting on tier 1, and
// the request could never be granted.
func TestTieredApprovalWithARowlessApprover(t *testing.T) {
	srv, _ := newTestServerStore(t)
	tid := createTestTarget(t, srv, "prod-db", "10.0.0.7")
	if code, d := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d", tid), testAPIKey, map[string]any{
		"name": "prod-db", "host": "10.0.0.7", "port": 22, "os_type": "linux", "protocol": "ssh", "approval_tiers": "admin; approver",
	}); code != http.StatusOK {
		t.Fatalf("set tiers: %d %s", code, d)
	}
	aliceTok := seedUser(t, srv, "alice", "user")
	patTok := seedUser(t, srv, "pat", "approver")
	code, d := do(t, srv, http.MethodPost, "/api/access-requests", aliceTok, map[string]any{"target_id": tid, "reason": "deploy"})
	if code != http.StatusCreated {
		t.Fatalf("request: %d %s", code, d)
	}
	rid := int64(jsonMap(t, d)["id"].(float64))
	url := fmt.Sprintf("/api/access-requests/%d/approve", rid)
	if code, d := do(t, srv, http.MethodPost, url, testAPIKey, nil); code != http.StatusOK || jsonMap(t, d)["status"] != "pending" {
		t.Fatalf("the bootstrap admin satisfies tier 1: %d %s", code, d)
	}
	code, d = do(t, srv, http.MethodPost, url, patTok, nil)
	if code != http.StatusOK || jsonMap(t, d)["status"] != "approved" {
		t.Fatalf("tier 1 was satisfied by an identity with no user row; tier 2 must complete the chain: %d %s", code, d)
	}
}

// TestCredentialScopeRefusalSpendsNothing proves a caller refused for the
// CREDENTIAL (Phase 252) keeps their one-time approval. The REST access paths
// chose the credential after the approval gate had already consumed it, so a
// session that was never going to open still cost the caller the approval.
func TestCredentialScopeRefusalSpendsNothing(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	srv, _ := newTestServerOpts(t, nil, api.Options{WinRM: fake})
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "win-01", "host": "10.0.0.9", "port": 5985, "os_type": "windows", "protocol": "winrm", "require_approval": true,
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	var deployID int64
	for _, u := range []string{"Administrator", "deploy"} {
		code, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{"target_id": tid, "username": u, "secret": "pw"})
		if code != http.StatusCreated {
			t.Fatalf("credential %s: %d %s", u, code, d)
		}
		deployID = int64(jsonMap(t, d)["id"].(float64))
	}
	aliceTok := seedUser(t, srv, "alice", "user")
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", tid), testAPIKey, map[string]any{
		"subject_type": "user", "subject": "alice", "credential_id": deployID,
	}); code != http.StatusCreated {
		t.Fatalf("scoped grant: %d %s", code, d)
	}
	code, d := do(t, srv, http.MethodPost, "/api/access-requests", aliceTok, map[string]any{"target_id": tid, "reason": "patch", "one_time": true})
	if code != http.StatusCreated {
		t.Fatalf("request: %d %s", code, d)
	}
	rid := int64(jsonMap(t, d)["id"].(float64))
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", rid), testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, d)
	}
	// The REST WinRM path runs as the target's first credential, which alice's
	// grant does not cover.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/winrm", tid), aliceTok, map[string]any{"command": "whoami"}); code != http.StatusForbidden {
		t.Fatalf("a credential outside the grant: want 403, got %d %s", code, d)
	}
	if fake.gotCmd != "" {
		t.Fatalf("the command ran: %q", fake.gotCmd)
	}
	_, d = do(t, srv, http.MethodGet, "/api/access-requests?status=approved", testAPIKey, nil)
	var reqs []map[string]any
	if err := json.Unmarshal(d, &reqs); err != nil || len(reqs) != 1 {
		t.Fatalf("approved requests = %s", d)
	}
	if reqs[0]["consumed_at"] != nil {
		t.Fatalf("the refusal consumed the one-time approval: %s", d)
	}
}
