package k8s_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/k8s"
)

const clusterToken = "sa-token-the-operator-never-sees"

// recordedRequest is what the fake API server saw.
type recordedRequest struct {
	Method, Path, Query, Auth, ContentType, Accept, Body string
}

// fakeAPIServer starts an in-process TLS Kubernetes API server that accepts
// ONLY clusterToken — so a test that gets a 2xx out of it has proved the
// vaulted token reached the cluster, and nothing else did. It records the last
// request and answers from `reply`.
func fakeAPIServer(t *testing.T, reply func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, *recordedRequest) {
	t.Helper()
	last := &recordedRequest{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0)
		if r.Body != nil {
			buf := make([]byte, 4096)
			n, _ := r.Body.Read(buf)
			body = buf[:n]
		}
		*last = recordedRequest{
			Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery,
			Auth: r.Header.Get("Authorization"), ContentType: r.Header.Get("Content-Type"),
			Accept: r.Header.Get("Accept"), Body: string(body),
		}
		if r.Header.Get("Authorization") != "Bearer "+clusterToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure","code":401}`))
			return
		}
		reply(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, last
}

// newClient builds a Client pointed at srv, trusting its test certificate via
// the httptest client (which carries the server's cert pool).
func newClient(t *testing.T, srv *httptest.Server, token string) *k8s.Client {
	t.Helper()
	c, err := k8s.New(k8s.Config{Server: srv.URL, Token: token, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("k8s.New: %v", err)
	}
	return c
}

// TestNewValidation pins the construction rules: https required (a bearer token
// must never travel in the clear), server and token required.
func TestNewValidation(t *testing.T) {
	for name, cfg := range map[string]k8s.Config{
		"no server":    {Token: "t"},
		"no token":     {Server: "https://api.example:6443"},
		"plaintext":    {Server: "http://api.example:6443", Token: "t"},
		"not a url":    {Server: "://nope", Token: "t"},
		"no host":      {Server: "https://", Token: "t"},
		"empty scheme": {Server: "api.example:6443", Token: "t"},
	} {
		if _, err := k8s.New(cfg); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := k8s.New(k8s.Config{Server: "https://api.example:6443/", Token: "t"}); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
}

// TestRequestPathsAndCommands walks every brokered verb against the fake API
// server and pins BOTH halves that must agree: the HTTP request actually sent
// (method, path, query, content type) and the canonical `kubectl …` command
// string command control matches, the transcript records and the audit trail
// carries.
func TestRequestPathsAndCommands(t *testing.T) {
	srv, last := fakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"kind":"PodList","items":[]}`))
	})
	c := newClient(t, srv, clusterToken)
	ctx := context.Background()

	cases := []struct {
		name    string
		req     k8s.Request
		method  string
		path    string
		query   string
		command string
	}{
		{
			name:    "list core pods in a namespace",
			req:     k8s.Request{Verb: k8s.VerbGet, Resource: "pods", Namespace: "prod"},
			method:  http.MethodGet,
			path:    "/api/v1/namespaces/prod/pods",
			command: "kubectl get pods -n prod",
		},
		{
			name:    "list across all namespaces (no namespace = the cluster-wide collection)",
			req:     k8s.Request{Verb: k8s.VerbGet, Resource: "pods"},
			method:  http.MethodGet,
			path:    "/api/v1/pods",
			command: "kubectl get pods",
		},
		{
			name:    "one named object in a group",
			req:     k8s.Request{Verb: k8s.VerbGet, APIVersion: "apps/v1", Resource: "deployments", Name: "web", Namespace: "prod"},
			method:  http.MethodGet,
			path:    "/apis/apps/v1/namespaces/prod/deployments/web",
			command: "kubectl get deployments.apps web -n prod",
		},
		{
			name:    "label selector rides the query, not the path",
			req:     k8s.Request{Verb: k8s.VerbGet, Resource: "pods", Namespace: "prod", Selector: "app=web,tier!=db"},
			method:  http.MethodGet,
			path:    "/api/v1/namespaces/prod/pods",
			query:   "labelSelector=app%3Dweb%2Ctier%21%3Ddb",
			command: "kubectl get pods -l app=web,tier!=db -n prod",
		},
		{
			name:    "a CRD needs no discovery, only its api version",
			req:     k8s.Request{Verb: k8s.VerbGet, APIVersion: "example.com/v1alpha1", Resource: "widgets", Namespace: "prod"},
			method:  http.MethodGet,
			path:    "/apis/example.com/v1alpha1/namespaces/prod/widgets",
			command: "kubectl get widgets.example.com -n prod",
		},
		{
			name:    "logs default to a bounded tail",
			req:     k8s.Request{Verb: k8s.VerbLogs, Name: "web-0", Namespace: "prod"},
			method:  http.MethodGet,
			path:    "/api/v1/namespaces/prod/pods/web-0/log",
			query:   "tailLines=200",
			command: "kubectl logs web-0 --tail=200 -n prod",
		},
		{
			name:    "logs of one container of many",
			req:     k8s.Request{Verb: k8s.VerbLogs, Name: "web-0", Namespace: "prod", Container: "sidecar", TailLines: 10},
			method:  http.MethodGet,
			path:    "/api/v1/namespaces/prod/pods/web-0/log",
			query:   "container=sidecar&tailLines=10",
			command: "kubectl logs web-0 -c sidecar --tail=10 -n prod",
		},
		{
			name:    "delete by name",
			req:     k8s.Request{Verb: k8s.VerbDelete, Resource: "pods", Name: "web-0", Namespace: "prod"},
			method:  http.MethodDelete,
			path:    "/api/v1/namespaces/prod/pods/web-0",
			command: "kubectl delete pods web-0 -n prod",
		},
		{
			name: "apply is a server-side-apply PATCH carrying the manifest verbatim",
			req: k8s.Request{Verb: k8s.VerbApply, APIVersion: "apps/v1", Resource: "deployments", Name: "web",
				Namespace: "prod", Manifest: []byte("apiVersion: apps/v1\nkind: Deployment\n")},
			method:  http.MethodPatch,
			path:    "/apis/apps/v1/namespaces/prod/deployments/web",
			query:   "fieldManager=pamv1&force=true",
			command: "kubectl apply -f - deployments.apps/web -n prod",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The command string is rendered from the NORMALIZED request, the
			// same way Do renders it — otherwise the audited command could
			// describe something other than what was sent.
			norm := tc.req
			norm.Normalize()
			if got := norm.Command(); got != tc.command {
				t.Errorf("command = %q, want %q", got, tc.command)
			}
			res, err := c.Do(ctx, tc.req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if !res.OK() {
				t.Fatalf("status = %d, body %s", res.Status, res.Body)
			}
			if last.Method != tc.method || last.Path != tc.path {
				t.Fatalf("sent %s %s, want %s %s", last.Method, last.Path, tc.method, tc.path)
			}
			if last.Query != tc.query {
				t.Fatalf("query = %q, want %q", last.Query, tc.query)
			}
			if last.Auth != "Bearer "+clusterToken {
				t.Fatalf("authorization header = %q", last.Auth)
			}
			if tc.req.Verb == k8s.VerbApply {
				if last.ContentType != "application/apply-patch+yaml" {
					t.Fatalf("apply content type = %q", last.ContentType)
				}
				if last.Body != string(tc.req.Manifest) {
					t.Fatalf("manifest was rewritten: %q", last.Body)
				}
			}
			if res.Path != tc.path || res.Method != tc.method {
				t.Fatalf("result does not describe the call made: %+v", res)
			}
		})
	}
}

// TestWrongTokenRefused is the credential half of the proof: the fake API
// server accepts only the vaulted token, so a client holding anything else
// gets 401 — the same shape as a cluster refusing a stale service account.
func TestWrongTokenRefused(t *testing.T) {
	srv, _ := fakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	res, err := newClient(t, srv, "not-the-token").Do(context.Background(),
		k8s.Request{Verb: k8s.VerbGet, Resource: "pods", Namespace: "prod"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if res.Status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.Status)
	}
}

// TestClusterRefusalIsAResultNotAnError proves the contract that matters for a
// PAM: the cluster's own RBAC refusing the vaulted credential comes back as a
// 403 result the operator sees and the audit trail records, not as an opaque
// pamv1 error.
func TestClusterRefusalIsAResultNotAnError(t *testing.T) {
	srv, _ := fakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"kind":"Status","reason":"Forbidden","code":403}`))
	})
	res, err := newClient(t, srv, clusterToken).Do(context.Background(),
		k8s.Request{Verb: k8s.VerbDelete, Resource: "secrets", Name: "db", Namespace: "prod"})
	if err != nil {
		t.Fatalf("a cluster refusal must not be a transport error: %v", err)
	}
	if res.Status != http.StatusForbidden || res.OK() || !strings.Contains(res.Body, "Forbidden") {
		t.Fatalf("result = %+v", res)
	}
}

// TestPathInjectionRefused is the security core of this package: every value
// that becomes a URL path segment is validated first, so a name, namespace,
// resource, group or version cannot aim the request somewhere other than what
// the audited command string describes.
func TestPathInjectionRefused(t *testing.T) {
	srv, last := fakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	c := newClient(t, srv, clusterToken)
	for name, req := range map[string]k8s.Request{
		"traversal in name":        {Verb: k8s.VerbGet, Resource: "pods", Namespace: "prod", Name: "../../secrets/db"},
		"slash in namespace":       {Verb: k8s.VerbGet, Resource: "pods", Namespace: "prod/../kube-system"},
		"traversal in resource":    {Verb: k8s.VerbGet, Resource: "../secrets", Namespace: "prod"},
		"traversal in group":       {Verb: k8s.VerbGet, APIVersion: "../../apis/v1", Resource: "pods"},
		"bogus version":            {Verb: k8s.VerbGet, APIVersion: "apps/../v1", Resource: "deployments"},
		"encoded traversal":        {Verb: k8s.VerbGet, Resource: "pods", Name: "%2e%2e%2fsecrets"},
		"newline in name":          {Verb: k8s.VerbGet, Resource: "pods", Name: "web\nactor:admin"},
		"newline in selector":      {Verb: k8s.VerbGet, Resource: "pods", Selector: "app=web\nactor:admin"},
		"uppercase name":           {Verb: k8s.VerbGet, Resource: "pods", Name: "Web-0"},
		"consecutive dots in name": {Verb: k8s.VerbGet, Resource: "pods", Name: "web..0"},
		"unknown verb":             {Verb: k8s.VerbGet + "-all", Resource: "pods"},
		"empty resource":           {Verb: k8s.VerbGet},
	} {
		t.Run(name, func(t *testing.T) {
			*last = recordedRequest{}
			if _, err := c.Do(context.Background(), req); err == nil {
				t.Fatalf("accepted a hostile request")
			}
			if last.Path != "" {
				t.Fatalf("a refused request still reached the cluster: %s", last.Path)
			}
		})
	}
}

// TestPerVerbRules pins the per-verb requirements — the places where a missing
// field would otherwise widen the blast radius (a delete with no name is a
// collection delete; logs need a pod and a namespace; apply needs a manifest
// and the name the audited command claims).
func TestPerVerbRules(t *testing.T) {
	srv, _ := fakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	c := newClient(t, srv, clusterToken)
	for name, req := range map[string]k8s.Request{
		"delete without a name":      {Verb: k8s.VerbDelete, Resource: "pods", Namespace: "prod"},
		"logs without a namespace":   {Verb: k8s.VerbLogs, Name: "web-0"},
		"logs without a name":        {Verb: k8s.VerbLogs, Namespace: "prod"},
		"logs of a non-pod":          {Verb: k8s.VerbLogs, Resource: "deployments", Name: "web", Namespace: "prod"},
		"logs with a huge tail":      {Verb: k8s.VerbLogs, Name: "web-0", Namespace: "prod", TailLines: 100000},
		"apply without a manifest":   {Verb: k8s.VerbApply, Resource: "pods", Name: "web-0", Namespace: "prod"},
		"apply without a name":       {Verb: k8s.VerbApply, Resource: "pods", Namespace: "prod", Manifest: []byte("kind: Pod")},
		"apply with a selector":      {Verb: k8s.VerbApply, Resource: "pods", Name: "web-0", Selector: "app=web", Manifest: []byte("kind: Pod")},
		"get with name AND selector": {Verb: k8s.VerbGet, Resource: "pods", Name: "web-0", Selector: "app=web"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := c.Do(context.Background(), req); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

// TestResponseCapFailsClosed proves an oversized response is an error, not a
// truncation: half a JSON object (or half a log) presented as a result is
// exactly the silent-corruption failure this project refuses elsewhere.
func TestResponseCapFailsClosed(t *testing.T) {
	big := strings.Repeat("x", 4096)
	srv, _ := fakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(big)) })
	c, err := k8s.New(k8s.Config{Server: srv.URL, Token: clusterToken, HTTPClient: srv.Client(), MaxResponseBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), k8s.Request{Verb: k8s.VerbLogs, Name: "web-0", Namespace: "prod"}); err == nil {
		t.Fatal("an over-cap response must fail closed")
	}
	// Exactly at the cap is fine — the reader must not mistake "at" for "over".
	c2, err := k8s.New(k8s.Config{Server: srv.URL, Token: clusterToken, HTTPClient: srv.Client(), MaxResponseBytes: int64(len(big))})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c2.Do(context.Background(), k8s.Request{Verb: k8s.VerbLogs, Name: "web-0", Namespace: "prod"})
	if err != nil || len(res.Body) != len(big) {
		t.Fatalf("at-cap response: %d bytes, err %v", len(res.Body), err)
	}
}
