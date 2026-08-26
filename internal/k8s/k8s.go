// Package k8s is the narrow Kubernetes API client behind PAMv1's brokered
// kubectl-shaped operations (Phase 155). It speaks the Kubernetes REST API
// directly — plain HTTPS + JSON — and deliberately does NOT vendor
// k8s.io/client-go: what PAMv1 needs is four discrete request shapes
// (`get`, `logs`, `apply`, `delete`), and client-go would pull in hundreds of
// packages, its own scheme/codec machinery and a release cadence tied to the
// cluster's, to reach the same four HTTP calls. That is the same reasoning
// behind every other hand-rolled protocol client in this tree (`internal/tds`,
// `internal/winrm`, `internal/guacd`, `internal/oidc`): the bar for reaching
// for a library here is "cryptographic verification we should not own"
// (`go-webauthn`, `crewjam/saml`), and an authenticated JSON request over TLS
// is not that.
//
// # What is brokered, and what is not
//
// kubectl's operations split cleanly in two. Discrete verb+resource calls are
// ordinary synchronous HTTPS requests — one call in, one audited result out —
// which is exactly the shape `POST /api/targets/{id}/winrm` already proves out
// end to end. Those are brokered here. `exec`, `attach` and `port-forward`
// upgrade the connection to a multiplexed SPDY/WebSocket stream whose framing
// would need its own audit parser (nothing in this codebase generalizes to it);
// they are deliberately out of scope, documented rather than half-built.
//
// # No discovery: the caller names the API version
//
// kubectl maps `deployments` → `/apis/apps/v1/...` by querying the cluster's
// discovery endpoints (`/api`, `/apis`, `/apis/{group}/{version}`), which is
// N+2 requests per operation unless a cache with its own staleness semantics is
// introduced. PAMv1 instead takes the API version explicitly (defaulting to
// core `v1`), so a request names exactly the API it will call: one HTTP request
// per operation, no cache to go stale, CRDs work on day one
// (`resource:"widgets", api_version:"example.com/v1"`), and the audited command
// string is unambiguous about what was touched.
//
// # Path safety
//
// Every path segment (namespace, name, resource, group, version) is validated
// against the Kubernetes naming rules BEFORE it is interpolated, and escaped
// again on the way in. A name like `../../secrets/db` is refused outright
// rather than escaping the intended collection — a hostile or fat-fingered
// value must not be able to aim the request somewhere the audited command
// string does not describe.
package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The verbs PAMv1 brokers. Anything else is refused by Validate — an unknown
// verb must never fall through to a request nobody described.
const (
	VerbGet    = "get"
	VerbLogs   = "logs"
	VerbApply  = "apply"
	VerbDelete = "delete"
)

// DefaultAPIVersion is the core group's version, used when a request does not
// name one — it covers pods, services, configmaps, secrets, nodes, namespaces
// and the rest of `/api/v1`.
const DefaultAPIVersion = "v1"

// FieldManager identifies PAMv1 as the owner of the fields it applies
// (Kubernetes server-side apply requires a field manager, and records it on the
// object). Seeing `PAMv1` in `metadata.managedFields` on a cluster object is
// itself a useful audit signal.
const FieldManager = "pamv1"

// defaultTailLines bounds a `logs` read that does not ask for a specific
// number. A pod's log is unbounded; a brokered, audited, transcript-recorded
// operation is not the place to stream one, so the default is a tail.
const defaultTailLines = 200

// applyContentType is the media type Kubernetes server-side apply expects. The
// manifest travels as the operator wrote it (YAML or JSON — the API server
// accepts both under this type), so PAMv1 never re-serializes what it is about
// to apply.
const applyContentType = "application/apply-patch+yaml"

// ErrTooLarge reports a response bigger than the configured cap. It is an
// error, not a truncation: half a JSON object read as a result is worse than no
// result, and an operator acting on a silently cut log is exactly the failure
// this project refuses elsewhere (the SFTP capture cap has the same posture).
var ErrTooLarge = errors.New("k8s: response exceeds the configured size cap")

// Kubernetes naming rules, applied before anything is interpolated into a URL
// path. These are the upstream rules, not an approximation:
//   - names are DNS subdomains: lowercase alphanumerics, '-' and '.', each
//     dot-separated part starting and ending alphanumeric, ≤253 chars;
//   - namespaces are DNS labels: the same without dots, ≤63 chars;
//   - resources are lowercase plurals; groups are DNS subdomains; versions are
//     `v1`, `v1beta1`, `v2alpha1` and friends.
var (
	nameRe      = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	labelRe     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	resourceRe  = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	versionRe   = regexp.MustCompile(`^v[0-9]+((alpha|beta)[0-9]+)?$`)
	containerRe = labelRe
	// A label selector is a query parameter, not a path segment, so it cannot
	// aim the request — but it is still bounded and charset-checked so it
	// cannot smuggle newlines into the audited command string either.
	selectorRe = regexp.MustCompile(`^[A-Za-z0-9_./=!,()-]([A-Za-z0-9_./=!,() -]*[A-Za-z0-9_./=!,()-])?$`)
)

// Config describes one cluster connection. Server and Token are per-request
// (the token is the target's vaulted credential, decrypted just-in-time by the
// caller and never stored here beyond the life of the client); the TLS and
// bound settings come from the deployment's configuration.
type Config struct {
	// Server is the API server base URL, e.g. "https://10.0.0.5:6443". HTTPS
	// is required: a bearer token on a plaintext hop is a harvested token.
	Server string
	// Token is the service-account (or user) bearer token. It is sent as
	// `Authorization: Bearer …` and never logged, returned or recorded.
	Token string
	// CAs verifies the API server's certificate. Nil uses the system roots,
	// which is right for a managed cluster with a publicly-rooted endpoint and
	// wrong for the usual private CA — hence PAM_K8S_CA_FILE.
	CAs *x509.CertPool
	// InsecureSkipVerify disables that verification entirely (demos, kind).
	// It is a deliberate, loudly documented opt-in, never a default.
	InsecureSkipVerify bool
	// Timeout bounds one request end to end (default 30s).
	Timeout time.Duration
	// MaxResponseBytes caps a response body (default 1 MiB); over it, Do fails
	// with ErrTooLarge rather than returning a truncated result.
	MaxResponseBytes int64
	// HTTPClient replaces the constructed client (tests point this at an
	// httptest TLS server); when set, the TLS fields above are the caller's
	// business, not this package's.
	HTTPClient *http.Client
}

// Client is a configured connection to one cluster. It holds no mutable state,
// so it is safe for concurrent use, and it is cheap enough to build per
// operation — which is what the API layer does, since each operation carries
// its own just-in-time-decrypted token.
type Client struct {
	server   string
	token    string
	hc       *http.Client
	maxBytes int64
}

// New validates cfg and returns a Client. A non-HTTPS server URL is refused
// outright: every request carries a bearer token that a plaintext hop would
// hand to anyone on the path.
func New(cfg Config) (*Client, error) {
	if cfg.Server == "" {
		return nil, errors.New("k8s: server url is required")
	}
	u, err := url.Parse(cfg.Server)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("k8s: server url %q is not a URL", cfg.Server)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("k8s: server url must be https (got %q) — a bearer token must not travel in the clear", u.Scheme)
	}
	if cfg.Token == "" {
		return nil, errors.New("k8s: bearer token is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	maxBytes := cfg.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{ // #nosec G402 -- InsecureSkipVerify is an explicit, documented opt-in (PAM_K8S_INSECURE_SKIP_VERIFY), default false; MinVersion is pinned
					MinVersion:         tls.VersionTLS12,
					RootCAs:            cfg.CAs,
					InsecureSkipVerify: cfg.InsecureSkipVerify,
				},
			},
		}
	}
	return &Client{
		server:   strings.TrimRight(cfg.Server, "/"),
		token:    cfg.Token,
		hc:       hc,
		maxBytes: maxBytes,
	}, nil
}

// Request is one brokered operation. It is the whole vocabulary: what the
// caller cannot express here, PAMv1 does not do to a cluster.
type Request struct {
	// Verb is get, logs, apply or delete.
	Verb string
	// APIVersion is "v1" (core) or "group/version" (e.g. "apps/v1"). Empty
	// defaults to core v1.
	APIVersion string
	// Resource is the lowercase plural ("pods", "deployments"). Required for
	// get, apply and delete; implied "pods" for logs.
	Resource string
	// Name is the object name. Required for logs and delete; optional for get
	// (absent = list the collection) and for apply (absent = taken from the
	// manifest by the caller, which validates the two agree).
	Name string
	// Namespace scopes the request. Empty means the cluster-scoped path, which
	// for a namespaced resource is Kubernetes' own "across all namespaces"
	// collection — the cluster's RBAC decides whether that is permitted.
	Namespace string
	// Selector is an optional label selector for a get (`app=web,tier!=db`).
	Selector string
	// Container selects one container's log in a multi-container pod.
	Container string
	// TailLines bounds a logs read (default 200).
	TailLines int
	// Manifest is the apply body, exactly as the operator supplied it (YAML or
	// JSON); PAMv1 never rewrites it.
	Manifest []byte
}

// Result is one brokered operation's outcome. Status is the cluster's own HTTP
// status — including 403 when the cluster's RBAC refuses the vaulted
// credential, which is an answer, not a PAMv1 failure — and Body is the
// response as the API server sent it, capped.
type Result struct {
	Status int    `json:"status"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   string `json:"body"`
}

// OK reports whether the cluster answered 2xx.
func (r Result) OK() bool { return r.Status >= 200 && r.Status < 300 }

// group and version split an APIVersion into its parts ("apps/v1" → "apps",
// "v1"; "v1" → "", "v1").
func (r Request) group() string {
	if i := strings.Index(r.APIVersion, "/"); i >= 0 {
		return r.APIVersion[:i]
	}
	return ""
}

func (r Request) version() string {
	if i := strings.Index(r.APIVersion, "/"); i >= 0 {
		return r.APIVersion[i+1:]
	}
	return r.APIVersion
}

// Normalize fills in the defaults a caller may omit. It is called by Do, and
// exported behavior depends on it, so Command() reflects what will actually be
// sent rather than what was typed.
func (r *Request) Normalize() {
	r.Verb = strings.ToLower(strings.TrimSpace(r.Verb))
	r.APIVersion = strings.TrimSpace(r.APIVersion)
	r.Resource = strings.ToLower(strings.TrimSpace(r.Resource))
	r.Name = strings.TrimSpace(r.Name)
	r.Namespace = strings.TrimSpace(r.Namespace)
	r.Selector = strings.TrimSpace(r.Selector)
	r.Container = strings.TrimSpace(r.Container)
	if r.APIVersion == "" {
		r.APIVersion = DefaultAPIVersion
	}
	if r.Verb == VerbLogs {
		if r.Resource == "" {
			r.Resource = "pods"
		}
		if r.TailLines <= 0 {
			r.TailLines = defaultTailLines
		}
	}
}

// Validate applies every rule before a URL is built: known verb, per-verb
// required fields, and the Kubernetes naming rules on every value that becomes
// a path segment. A returned error is safe to show a caller — it names the
// field, never the token.
func (r Request) Validate() error {
	switch r.Verb {
	case VerbGet, VerbLogs, VerbApply, VerbDelete:
	default:
		return fmt.Errorf("k8s: verb must be one of get, logs, apply, delete (got %q)", r.Verb)
	}
	if r.Resource == "" || !resourceRe.MatchString(r.Resource) {
		return fmt.Errorf("k8s: resource %q is not a lowercase plural resource name", r.Resource)
	}
	if g := r.group(); g != "" && (!nameRe.MatchString(g) || len(g) > 253) {
		return fmt.Errorf("k8s: api group %q is not a DNS subdomain", g)
	}
	if v := r.version(); !versionRe.MatchString(v) {
		return fmt.Errorf("k8s: api version %q is not a Kubernetes version (v1, v1beta1, …)", v)
	}
	if r.Name != "" && (!nameRe.MatchString(r.Name) || len(r.Name) > 253) {
		return fmt.Errorf("k8s: name %q is not a valid object name", r.Name)
	}
	if r.Namespace != "" && (!labelRe.MatchString(r.Namespace) || len(r.Namespace) > 63) {
		return fmt.Errorf("k8s: namespace %q is not a valid namespace", r.Namespace)
	}
	if r.Selector != "" && (!selectorRe.MatchString(r.Selector) || len(r.Selector) > 253) {
		return fmt.Errorf("k8s: selector %q contains characters a label selector cannot", r.Selector)
	}
	if r.Container != "" && (!containerRe.MatchString(r.Container) || len(r.Container) > 63) {
		return fmt.Errorf("k8s: container %q is not a valid container name", r.Container)
	}
	switch r.Verb {
	case VerbLogs:
		switch {
		case r.APIVersion != DefaultAPIVersion || r.Resource != "pods":
			return errors.New("k8s: logs are only available for core v1 pods")
		case r.Name == "":
			return errors.New("k8s: logs require a pod name")
		case r.Namespace == "":
			return errors.New("k8s: logs require a namespace")
		case r.TailLines <= 0 || r.TailLines > 10000:
			return errors.New("k8s: tail_lines must be 1-10000")
		}
	case VerbDelete:
		if r.Name == "" {
			// Kubernetes can delete a whole collection; PAMv1 will not offer a
			// verb whose blast radius is "everything the selector matched".
			return errors.New("k8s: delete requires a name (collection deletes are not brokered)")
		}
	case VerbApply:
		switch {
		case len(r.Manifest) == 0:
			return errors.New("k8s: apply requires a manifest")
		case r.Name == "":
			return errors.New("k8s: apply requires the object name")
		case r.Selector != "":
			return errors.New("k8s: apply does not take a selector")
		}
	case VerbGet:
		if r.Name != "" && r.Selector != "" {
			return errors.New("k8s: a selector filters a collection; drop the name or the selector")
		}
	}
	return nil
}

// resourceLabel renders `resource` or `resource.group` — how kubectl itself
// disambiguates a resource that exists in more than one group, and what the
// audited command string carries.
func (r Request) resourceLabel() string {
	if g := r.group(); g != "" {
		return r.Resource + "." + g
	}
	return r.Resource
}

// Command renders the canonical `kubectl …` line for this request. It is not
// decoration: it is the string command control matches its deny/allow patterns
// against (so `kubectl delete` can be forbidden fleet-wide exactly like `rm
// -rf` is on SSH), the line echoed to a supervisor watching live, and the text
// written into the transcript and the audit trail. It therefore has to describe
// what will actually be sent — which is why Do normalizes first and renders
// from the normalized request.
func (r Request) Command() string {
	var b strings.Builder
	b.WriteString("kubectl ")
	b.WriteString(r.Verb)
	switch r.Verb {
	case VerbLogs:
		b.WriteString(" " + r.Name)
		if r.Container != "" {
			b.WriteString(" -c " + r.Container)
		}
		b.WriteString(" --tail=" + strconv.Itoa(r.TailLines))
	case VerbApply:
		b.WriteString(" -f - " + r.resourceLabel() + "/" + r.Name)
	default:
		b.WriteString(" " + r.resourceLabel())
		if r.Name != "" {
			b.WriteString(" " + r.Name)
		}
		if r.Selector != "" {
			b.WriteString(" -l " + r.Selector)
		}
	}
	if r.Namespace != "" {
		b.WriteString(" -n " + r.Namespace)
	}
	return b.String()
}

// prefix is the API root for this request's group/version: `/api/v1` for the
// core group, `/apis/<group>/<version>` for every other.
func (r Request) prefix() string {
	if g := r.group(); g != "" {
		return "/apis/" + url.PathEscape(g) + "/" + url.PathEscape(r.version())
	}
	return "/api/" + url.PathEscape(r.version())
}

// path builds the request path from already-validated segments. Each is escaped
// on the way in as well: validation makes escaping a no-op today, and keeps it
// a no-op if the rules are ever loosened.
func (r Request) path() string {
	var b strings.Builder
	b.WriteString(r.prefix())
	if r.Namespace != "" {
		b.WriteString("/namespaces/" + url.PathEscape(r.Namespace))
	}
	b.WriteString("/" + url.PathEscape(r.Resource))
	if r.Name != "" {
		b.WriteString("/" + url.PathEscape(r.Name))
	}
	if r.Verb == VerbLogs {
		b.WriteString("/log")
	}
	return b.String()
}

// build turns a validated request into the HTTP call to make.
func (r Request) build() (method, path string, query url.Values, body []byte, contentType, accept string) {
	query = url.Values{}
	path = r.path()
	switch r.Verb {
	case VerbGet:
		method, accept = http.MethodGet, "application/json"
		if r.Selector != "" {
			query.Set("labelSelector", r.Selector)
		}
	case VerbLogs:
		method, accept = http.MethodGet, "text/plain"
		query.Set("tailLines", strconv.Itoa(r.TailLines))
		if r.Container != "" {
			query.Set("container", r.Container)
		}
	case VerbDelete:
		method, accept = http.MethodDelete, "application/json"
	case VerbApply:
		// Server-side apply: one idempotent PATCH that creates the object if it
		// does not exist and reconciles it if it does, with PAMv1 recorded as
		// the field manager. `force` resolves conflicts with fields another
		// manager owns — brokered, audited administrative access is exactly the
		// case where the operator means it, and the alternative (a 409 an
		// operator cannot act on through this API) is worse.
		method, accept, contentType = http.MethodPatch, "application/json", applyContentType
		body = r.Manifest
		query.Set("fieldManager", FieldManager)
		query.Set("force", "true")
	}
	return method, path, query, body, contentType, accept
}

// Do executes one operation and returns the cluster's answer. A non-2xx status
// is NOT an error: the cluster refusing (403), not finding (404) or rejecting
// (422) something is a result the operator must see and the audit trail must
// record. An error means the request never got an answer — it was invalid, the
// connection failed, or the response was too large to return honestly.
func (c *Client) Do(ctx context.Context, r Request) (Result, error) {
	r.Normalize()
	if err := r.Validate(); err != nil {
		return Result{}, err
	}
	method, path, query, body, contentType, accept := r.build()
	target := c.server + path
	if q := query.Encode(); q != "" {
		target += "?" + q
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("k8s: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "PAMv1")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("k8s: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := readCapped(resp.Body, c.maxBytes)
	if err != nil {
		return Result{}, fmt.Errorf("k8s: %s %s: %w", method, path, err)
	}
	return Result{Status: resp.StatusCode, Method: method, Path: path, Body: string(raw)}, nil
}

// readCapped reads at most max bytes, returning ErrTooLarge if there was more.
// It reads max+1 so "exactly at the cap" is not mistaken for "over it".
func readCapped(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrTooLarge
	}
	return b, nil
}
