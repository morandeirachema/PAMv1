package api_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/k8s"
	"github.com/morandeirachema/pamv1/internal/store"
)

// kubeToken is the credential pamv1 vaults for the cluster. The fake API server
// below accepts ONLY this token, and no operator ever sees it: the tests hand
// it to POST /api/credentials once and then only ever call the broker.
const kubeToken = "sa-token-only-the-vault-has"

// fakeCluster is an in-process TLS Kubernetes API server that accepts only
// kubeToken, plus what the last request carried — the two halves a JIT-injection
// proof needs.
type fakeCluster struct {
	srv        *httptest.Server
	host       string
	port       int
	lastAuth   string
	lastPath   string
	lastMethod string
	calls      int
}

// startFakeCluster launches the fake API server; reply answers an authenticated
// request (nil answers a small PodList).
func startFakeCluster(t *testing.T, reply func(w http.ResponseWriter, r *http.Request)) *fakeCluster {
	t.Helper()
	fc := &fakeCluster{}
	fc.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fc.calls++
		fc.lastAuth, fc.lastPath, fc.lastMethod = r.Header.Get("Authorization"), r.URL.Path, r.Method
		if r.Header.Get("Authorization") != "Bearer "+kubeToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"kind":"Status","code":401}`))
			return
		}
		if reply != nil {
			reply(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"kind":"PodList","items":[{"metadata":{"name":"web-0"}}]}`))
	}))
	t.Cleanup(fc.srv.Close)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(fc.srv.URL, "https://"))
	fc.host = host
	fc.port, _ = strconv.Atoi(port)
	return fc
}

// kubeServer wires a PAM server whose Kubernetes broker talks to fc (trusting
// its test certificate through the httptest client), seeds a `kubernetes`
// target pointing at it and vaults the cluster token, and returns the server,
// the recording directory and the target id.
func kubeServer(t *testing.T, fc *fakeCluster, opts api.Options) (*httptest.Server, store.Store, int64) {
	t.Helper()
	opts.K8s = k8s.Config{HTTPClient: fc.srv.Client()}
	opts.RecordingDir = t.TempDir()
	srv, st := newTestServerOpts(t, nil, opts)
	status, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "cluster-01", "host": fc.host, "port": fc.port, "os_type": "linux", "protocol": "kubernetes",
	})
	if status != http.StatusCreated {
		t.Fatalf("create target: %d %s", status, td)
	}
	tid := int64(jsonMap(t, td)["id"].(float64))
	if status, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "pam-broker", "secret_type": "k8s_token", "secret": kubeToken,
	}); status != http.StatusCreated {
		t.Fatalf("seed k8s credential: %d %s", status, d)
	}
	return srv, st, tid
}

// kubectl posts one brokered operation.
func kubectl(t *testing.T, srv *httptest.Server, tid int64, key string, body map[string]any) (int, []byte) {
	t.Helper()
	return do(t, srv, http.MethodPost, "/api/targets/"+strconv.FormatInt(tid, 10)+"/kubectl", key, body)
}

// fieldAfter pulls the value that follows `key` in a space-separated audit
// detail (`file:/path sha256:abc…`).
func fieldAfter(detail, key string) string {
	for _, f := range strings.Fields(detail) {
		if v, ok := strings.CutPrefix(f, key); ok {
			return v
		}
	}
	return ""
}

// TestKubectlJITInjection is this phase's flagship proof, the Kubernetes twin
// of the SSH one: the fake cluster accepts ONLY the vaulted service-account
// token, the operator authenticates to pamv1 with their own API key and never
// possesses that token, yet the operation runs — so the credential can only have
// come from the vault, injected just-in-time. It then checks everything that
// must accompany a brokered privileged operation: the canonical command string,
// the durable `k8s.run` audit row, and a transcript on disk whose SHA-256
// matches the one audited.
func TestKubectlJITInjection(t *testing.T) {
	fc := startFakeCluster(t, nil)
	srv, _, tid := kubeServer(t, fc, api.Options{})

	status, data := kubectl(t, srv, tid, testAPIKey, map[string]any{
		"verb": "get", "resource": "pods", "namespace": "prod",
	})
	if status != http.StatusOK {
		t.Fatalf("kubectl get: %d %s", status, data)
	}
	var out struct {
		Target, Command, Path, Method, Body string
		Status                              int
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Status != http.StatusOK || !strings.Contains(out.Body, "web-0") {
		t.Fatalf("cluster answer not returned: %+v", out)
	}
	if out.Command != "kubectl get pods -n prod" || out.Path != "/api/v1/namespaces/prod/pods" {
		t.Fatalf("envelope does not describe the call: %+v", out)
	}
	if fc.lastAuth != "Bearer "+kubeToken {
		t.Fatalf("the vaulted token was not injected: authorization = %q", fc.lastAuth)
	}
	// The operator's own key must never reach the cluster.
	if strings.Contains(fc.lastAuth, testAPIKey) {
		t.Fatal("the operator's PAM key reached the cluster")
	}

	// Audit: one k8s.run row naming the command, the status and the transcript.
	_, adata := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	var events []struct{ Action, Detail, Actor string }
	if err := json.Unmarshal(adata, &events); err != nil {
		t.Fatal(err)
	}
	var run string
	for _, e := range events {
		if e.Action == "k8s.run" {
			run = e.Detail
		}
	}
	if run == "" {
		t.Fatalf("no k8s.run audit row: %s", adata)
	}
	for _, want := range []string{"target:cluster-01", "cred_user:pam-broker", "status:200", "kubectl get pods -n prod"} {
		if !strings.Contains(run, want) {
			t.Fatalf("k8s.run detail %q missing %q", run, want)
		}
	}
	// The transcript exists and its on-disk hash is the audited one.
	file, sum := fieldAfter(run, "file:"), fieldAfter(run, "sha256:")
	if file == "" || sum == "" {
		t.Fatalf("k8s.run did not register a transcript: %s", run)
	}
	if filepath.Ext(file) != ".log" || !strings.Contains(file, ".k8s.") {
		t.Fatalf("unexpected transcript name %q", file)
	}
	raw, err := os.ReadFile(file) // #nosec G304 -- test-owned path from the audit row
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(raw); hex.EncodeToString(got[:]) != sum {
		t.Fatalf("transcript hash mismatch: file=%x audit=%s", got, sum)
	}
	if !strings.Contains(string(raw), "kubectl get pods -n prod") || !strings.Contains(string(raw), "web-0") {
		t.Fatalf("transcript does not carry the command and its result:\n%s", raw)
	}
	// And the secret is nowhere in the artifact a reviewer will read.
	if strings.Contains(string(raw), kubeToken) {
		t.Fatal("the vaulted token leaked into the transcript")
	}
}

// TestKubectlClusterRefusalIsAnAnswer proves a cluster-side RBAC refusal comes
// back to the operator as the cluster's own 403 inside a 200 envelope — the
// answer they asked for — and is audited with that status, exactly as a
// non-zero WinRM exit code is.
func TestKubectlClusterRefusalIsAnAnswer(t *testing.T) {
	fc := startFakeCluster(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"kind":"Status","reason":"Forbidden","message":"secrets is forbidden"}`))
	})
	srv, _, tid := kubeServer(t, fc, api.Options{})
	status, data := kubectl(t, srv, tid, testAPIKey, map[string]any{
		"verb": "get", "resource": "secrets", "namespace": "prod",
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d %s", status, data)
	}
	if m := jsonMap(t, data); int(m["status"].(float64)) != http.StatusForbidden ||
		!strings.Contains(m["body"].(string), "forbidden") {
		t.Fatalf("cluster refusal not surfaced: %s", data)
	}
	_, adata := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if !strings.Contains(string(adata), "status:403") {
		t.Fatalf("the refusal should be audited with its status: %s", adata)
	}
}

// TestKubectlCommandControl proves Phase 38's principle reaches Kubernetes: the
// same deny file that blocks `rm -rf` on SSH blocks `kubectl delete` here,
// before any credential is decrypted, and the attempt is audited and
// transcribed rather than silently dropped.
func TestKubectlCommandControl(t *testing.T) {
	fc := startFakeCluster(t, nil)
	srv, _, tid := kubeServer(t, fc, api.Options{CommandGuard: denyGuard(t, `(?i)^kubectl delete`)})

	status, data := kubectl(t, srv, tid, testAPIKey, map[string]any{
		"verb": "delete", "resource": "pods", "name": "web-0", "namespace": "prod",
	})
	if status != http.StatusForbidden {
		t.Fatalf("a blocked command must be refused: %d %s", status, data)
	}
	if fc.calls != 0 {
		t.Fatal("a blocked command still reached the cluster")
	}
	_, adata := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if !strings.Contains(string(adata), "command.blocked") || !strings.Contains(string(adata), "path:kubernetes") {
		t.Fatalf("the refusal should be audited as command.blocked: %s", adata)
	}
	// A `get` is still allowed by the same guard.
	if status, d := kubectl(t, srv, tid, testAPIKey, map[string]any{
		"verb": "get", "resource": "pods", "namespace": "prod",
	}); status != http.StatusOK {
		t.Fatalf("an allowed command should still run: %d %s", status, d)
	}
}

// TestKubectlRequestValidation pins the refusals that keep a brokered operation
// describable: an unknown verb, a name that would escape its collection, a
// collection delete, and logs of something that has none. None may reach the
// cluster.
func TestKubectlRequestValidation(t *testing.T) {
	fc := startFakeCluster(t, nil)
	srv, _, tid := kubeServer(t, fc, api.Options{})
	for name, body := range map[string]map[string]any{
		"unknown verb":       {"verb": "exec", "resource": "pods", "name": "web-0", "namespace": "prod"},
		"path traversal":     {"verb": "get", "resource": "pods", "name": "../../secrets/db", "namespace": "prod"},
		"namespace escape":   {"verb": "get", "resource": "pods", "namespace": "prod/../kube-system"},
		"collection delete":  {"verb": "delete", "resource": "pods", "namespace": "prod"},
		"logs of a non-pod":  {"verb": "logs", "resource": "deployments", "name": "web", "namespace": "prod"},
		"apply with no name": {"verb": "apply", "resource": "pods", "namespace": "prod", "manifest": "kind: Pod"},
	} {
		t.Run(name, func(t *testing.T) {
			fc.calls = 0
			if status, d := kubectl(t, srv, tid, testAPIKey, body); status != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d %s", status, d)
			}
			if fc.calls != 0 {
				t.Fatal("a malformed request reached the cluster")
			}
		})
	}
}

// TestKubectlAuthorization covers the gates around the operation: the wrong
// protocol, a target with no bearer credential, a role without CapConnect, and
// the protocol policy switch.
func TestKubectlAuthorization(t *testing.T) {
	fc := startFakeCluster(t, nil)
	srv, st, tid := kubeServer(t, fc, api.Options{})
	get := map[string]any{"verb": "get", "resource": "pods", "namespace": "prod"}

	// An auditor holds no CapConnect: refused by the middleware, before the handler.
	auditor := seedUser(t, srv, "kube-auditor", "auditor")
	if status, _ := kubectl(t, srv, tid, auditor, get); status != http.StatusForbidden {
		t.Fatalf("auditor should be refused: %d", status)
	}
	// A non-kubernetes target refuses the route.
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "ssh-01", "host": "10.0.0.4", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	sshID := int64(jsonMap(t, td)["id"].(float64))
	if status, _ := kubectl(t, srv, sshID, testAPIKey, get); status != http.StatusUnprocessableEntity {
		t.Fatalf("ssh target should refuse kubectl: %d", status)
	}
	// A kubernetes target with no k8s_token credential is refused with a clear
	// reason rather than sending some other secret as a bearer token.
	_, td = do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "cluster-02", "host": fc.host, "port": fc.port, "os_type": "linux", "protocol": "kubernetes",
	})
	bare := int64(jsonMap(t, td)["id"].(float64))
	status, d := kubectl(t, srv, bare, testAPIKey, get)
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(d), "k8s_token") {
		t.Fatalf("expected a no-credential refusal: %d %s", status, d)
	}
	// Policy: a second server on the SAME store, with kubernetes excluded from
	// PAM_ALLOWED_PROTOCOLS, refuses the route — the target already exists (it
	// was created while the protocol was allowed), which is exactly the case the
	// handler's own policy check exists for, since target validation can only
	// refuse a protocol at creation time.
	restricted, _ := newTestServerStoreOpts(t, nil, st, api.Options{
		AllowedProtocols: []string{"ssh"}, K8s: k8s.Config{HTTPClient: fc.srv.Client()},
	})
	fc.calls = 0
	if status, d := kubectl(t, restricted, tid, testAPIKey, get); status != http.StatusForbidden {
		t.Fatalf("protocol policy should refuse: %d %s", status, d)
	}
	if fc.calls != 0 {
		t.Fatal("a policy-refused request reached the cluster")
	}
}

// TestKubernetesTargetAndCredentialRules pins the store-shaped rules the new
// protocol brings: the default port, that a k8s_token only lives on a
// kubernetes target, and — the pre-existing hole this phase's call-site review
// turned up — that a protocol change can no longer strand a protocol-bound
// credential, in EITHER direction.
func TestKubernetesTargetAndCredentialRules(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})
	// The port defaults to the API server's, not to SSH's 22.
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "cluster-a", "host": "10.0.0.10", "os_type": "linux", "protocol": "kubernetes",
	})
	m := jsonMap(t, td)
	if int(m["port"].(float64)) != 6443 {
		t.Fatalf("kubernetes port default = %v, want 6443", m["port"])
	}
	kid := int64(m["id"].(float64))
	// A k8s_token belongs only on a kubernetes target.
	_, td = do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "ssh-a", "host": "10.0.0.11", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	sid := int64(jsonMap(t, td)["id"].(float64))
	if status, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": sid, "username": "sa", "secret_type": "k8s_token", "secret": "t",
	}); status != http.StatusUnprocessableEntity || !strings.Contains(string(d), "kubernetes") {
		t.Fatalf("k8s_token on an ssh target: %d %s", status, d)
	}
	if status, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": kid, "username": "sa", "secret_type": "k8s_token", "secret": "t",
	}); status != http.StatusCreated {
		t.Fatalf("k8s_token on a kubernetes target: %d %s", status, d)
	}
	// Changing that target's protocol would strand the credential: refused.
	if status, d := do(t, srv, http.MethodPut, "/api/targets/"+strconv.FormatInt(kid, 10), testAPIKey, map[string]any{
		"name": "cluster-a", "host": "10.0.0.10", "port": 22, "os_type": "linux", "protocol": "ssh",
	}); status != http.StatusUnprocessableEntity || !strings.Contains(string(d), "k8s_token") {
		t.Fatalf("stranding a k8s_token should be refused: %d %s", status, d)
	}
	// The same rule, in the direction that used to be wrong: a db_zsp credential
	// is valid on postgres AND mssql, so postgres → mssql must be ALLOWED, while
	// postgres → ssh (which would strand it) must be refused. Before this phase
	// the check keyed off "is the new protocol ssh", so it got both backwards.
	_, td = do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "db-a", "host": "10.0.0.12", "port": 5432, "os_type": "linux", "protocol": "postgres",
	})
	did := int64(jsonMap(t, td)["id"].(float64))
	if status, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": did, "username": "app", "secret_type": "db_zsp",
	}); status != http.StatusCreated {
		t.Fatalf("db_zsp on a postgres target: %d %s", status, d)
	}
	if status, d := do(t, srv, http.MethodPut, "/api/targets/"+strconv.FormatInt(did, 10), testAPIKey, map[string]any{
		"name": "db-a", "host": "10.0.0.12", "port": 1433, "os_type": "linux", "protocol": "mssql",
	}); status != http.StatusOK {
		t.Fatalf("postgres -> mssql keeps db_zsp valid and must be allowed: %d %s", status, d)
	}
	if status, d := do(t, srv, http.MethodPut, "/api/targets/"+strconv.FormatInt(did, 10), testAPIKey, map[string]any{
		"name": "db-a", "host": "10.0.0.12", "port": 22, "os_type": "linux", "protocol": "ssh",
	}); status != http.StatusUnprocessableEntity || !strings.Contains(string(d), "db_zsp") {
		t.Fatalf("mssql -> ssh would strand db_zsp and must be refused: %d %s", status, d)
	}
}
