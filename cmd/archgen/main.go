// Command archgen regenerates docs/ARCHITECTURE-DIAGRAMS.md from the source, so
// the architecture diagrams cannot drift from the code. It derives three views
// directly from the Go sources:
//
//   - a package dependency graph (from each package's intra-module imports),
//   - the domain data model as an ER diagram (from the structs in internal/store),
//   - the REST route → capability map (from internal/api/server.go's mux wiring).
//
// Output is deterministic (everything is sorted, no timestamps), so CI can run
// `go run ./cmd/archgen` and fail on any diff — that is what keeps the diagrams
// current on every change.
//
//go:generate go run .
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// main regenerates docs/ARCHITECTURE-DIAGRAMS.md from the source tree.
//
// The diagrams are generated rather than hand-drawn so they cannot drift from
// the code: CI runs this and fails if the committed file differs, which turns
// "the diagram is out of date" from a thing nobody notices into a build failure.
func main() {
	root, module, err := moduleRoot()
	if err != nil {
		fatal(err)
	}
	var b strings.Builder
	writeHeader(&b)
	if err := writePackageGraph(&b, root, module); err != nil {
		fatal(err)
	}
	if err := writeDataModel(&b, root); err != nil {
		fatal(err)
	}
	if err := writeRouteMap(&b, root); err != nil {
		fatal(err)
	}
	out := filepath.Join(root, "docs", "ARCHITECTURE-DIAGRAMS.md")
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		fatal(err)
	}
	rel, _ := filepath.Rel(root, out)
	fmt.Println("wrote", rel)
}

// fatal prints err and exits non-zero. Used for the unrecoverable setup errors
// of a developer tool, where a stack trace would add nothing.
func fatal(err error) {
	fmt.Fprintln(os.Stderr, "archgen:", err)
	os.Exit(1)
}

// moduleRoot walks up from the working directory to the directory holding go.mod
// and returns it plus the module path, so archgen works from any CWD.
func moduleRoot() (root, module string, err error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", "", err
	}
	for {
		gomod := filepath.Join(dir, "go.mod")
		if data, e := os.ReadFile(gomod); e == nil { // #nosec G304 -- build-time doc generator walking up to the repo go.mod
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "module ") {
					return dir, strings.TrimSpace(strings.TrimPrefix(line, "module ")), nil
				}
			}
			return dir, "", fmt.Errorf("no module line in go.mod")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", "", fmt.Errorf("go.mod not found from working directory")
		}
		dir = parent
	}
}

// writeHeader writes the generated file's preamble, including the warning not to
// edit it by hand and the command that regenerates it — so someone who opens the
// file and wants to change something is told immediately where to go instead.
func writeHeader(b *strings.Builder) {
	b.WriteString(`# PAMv1 — Architecture Diagrams (generated)

> **Do not edit by hand.** This file is regenerated from the source by
> ` + "`go run ./cmd/archgen`" + ` (or ` + "`go generate ./...`" + `). CI runs the
> generator and fails if the committed copy is stale, so these diagrams stay in
> step with the code on every change. Conceptual flows (trust zones, the JIT
> proxy sequence, deployment) live in the hand-authored
> [High-Level Architecture](ARCHITECTURE-HIGH-LEVEL.md) and
> [Low-Level Architecture](ARCHITECTURE-LOW-LEVEL.md).

Rendering: these are [Mermaid](https://mermaid.js.org/) diagrams; GitHub renders
them inline.

`)
}

// --- package dependency graph -------------------------------------------------

// pkgLayer groups packages into architectural layers for readable subgraphs. A
// package not listed here falls into the "Other" bucket, so new packages still
// appear (just ungrouped) — the edges are always derived from real imports.
var pkgLayer = []struct {
	name string
	pkgs []string
}{
	{"Entry point", []string{"pam-server", "archgen"}},
	{"Interface", []string{"api", "web", "proxy"}},
	{"Identity & authz", []string{"auth", "oidc", "mfa"}},
	{"Secrets", []string{"vault", "shamir"}},
	{"Persistence", []string{"store", "memstore", "pgstore", "storetest"}},
	{"Connectors", []string{"winrm", "guacd", "tds", "rotate", "discovery"}},
	{"Agent broker", []string{"broker", "policy", "agentid", "auditchain", "mcp"}},
	{"Platform", []string{"config", "logging", "metrics", "alert", "session", "maint"}},
}

// layerOf returns the architectural layer a package belongs to (core security,
// front doors, identity, and so on), or "" when it is unclassified. The layers
// are what give the generated package diagram its shape; without them it would
// be an unreadable mesh of every import edge in the tree.
func layerOf(pkg string) string {
	for _, l := range pkgLayer {
		for _, p := range l.pkgs {
			if p == pkg {
				return l.name
			}
		}
	}
	return "Other"
}

// writePackageGraph parses every package under internal/ and cmd/ and emits a
// Mermaid flowchart of the intra-module import edges, grouped by layer.
func writePackageGraph(b *strings.Builder, root, module string) error {
	dirs, err := packageDirs(root)
	if err != nil {
		return err
	}
	nodes := map[string]bool{}
	edges := map[string]bool{} // "from|to"
	for _, dir := range dirs {
		short := shortName(dir)
		nodes[short] = true
		imps, err := packageImports(filepath.Join(root, dir))
		if err != nil {
			return err
		}
		for _, imp := range imps {
			if !strings.HasPrefix(imp, module+"/") {
				continue // external dependency: out of scope for the internal graph
			}
			to := shortName(strings.TrimPrefix(imp, module+"/"))
			if to == short {
				continue
			}
			nodes[to] = true
			edges[short+"|"+to] = true
		}
	}

	b.WriteString("## 1. Package dependency graph\n\n")
	b.WriteString("Every Go package in the module and the imports between them. Arrows point from a package to the packages it imports.\n\n")
	b.WriteString("```mermaid\nflowchart LR\n")

	// Emit nodes inside per-layer subgraphs (deterministic order).
	grouped := map[string][]string{}
	for n := range nodes {
		grouped[layerOf(n)] = append(grouped[layerOf(n)], n)
	}
	order := make([]string, 0, len(pkgLayer)+1)
	for _, l := range pkgLayer {
		order = append(order, l.name)
	}
	order = append(order, "Other")
	for _, layer := range order {
		ns := grouped[layer]
		if len(ns) == 0 {
			continue
		}
		sort.Strings(ns)
		fmt.Fprintf(b, "  subgraph %s[%q]\n", nodeID(layer), layer)
		for _, n := range ns {
			fmt.Fprintf(b, "    %s[%s]\n", nodeID(n), n)
		}
		b.WriteString("  end\n")
	}

	es := make([]string, 0, len(edges))
	for e := range edges {
		es = append(es, e)
	}
	sort.Strings(es)
	for _, e := range es {
		parts := strings.SplitN(e, "|", 2)
		fmt.Fprintf(b, "  %s --> %s\n", nodeID(parts[0]), nodeID(parts[1]))
	}
	b.WriteString("```\n\n")
	return nil
}

// packageDirs returns the module-relative directories of every Go package under
// internal/ and cmd/, sorted.
func packageDirs(root string) ([]string, error) {
	var dirs []string
	for _, base := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, base), func(path string, d os.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return err
			}
			hasGo, e := dirHasGo(path)
			if e != nil {
				return e
			}
			if hasGo {
				rel, _ := filepath.Rel(root, path)
				dirs = append(dirs, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(dirs)
	return dirs, nil
}

// dirHasGo reports whether dir contains any .go file, so directories that merely
// hold sub-packages (or assets) are not drawn as packages themselves.
func dirHasGo(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			return true, nil
		}
	}
	return false, nil
}

// packageImports returns the unique import paths of the non-test Go files in dir.
// It parses each file directly (parser.ParseFile) rather than the deprecated
// parser.ParseDir, which does not consider build tags.
func packageImports(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ImportsOnly)
		if err != nil {
			return nil, err
		}
		for _, imp := range file.Imports {
			seen[strings.Trim(imp.Path.Value, `"`)] = true
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// shortName is the last path element (e.g. "internal/store" -> "store",
// "cmd/pam-server" -> "pam-server").
func shortName(rel string) string {
	rel = strings.TrimSuffix(rel, "/")
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[i+1:]
	}
	return rel
}

var nonID = regexp.MustCompile(`[^A-Za-z0-9_]`)

// nodeID turns an arbitrary name into a Mermaid-safe node identifier: everything
// outside [A-Za-z0-9_] becomes an underscore, with an "n_" prefix so an
// identifier never starts with a digit.
func nodeID(s string) string { return "n_" + nonID.ReplaceAllString(s, "_") }

// --- data model (ER) ----------------------------------------------------------

// writeDataModel emits a Mermaid ER diagram of the domain structs declared in
// internal/store/store.go, inferring relationships from <Entity>ID fields.
func writeDataModel(b *strings.Builder, root string) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(root, "internal", "store", "store.go"), nil, 0)
	if err != nil {
		return err
	}
	type field struct{ typ, name string }
	entities := map[string][]field{}
	var names []string
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || !ts.Name.IsExported() {
				continue
			}
			var fields []field
			for _, f := range st.Fields.List {
				if len(f.Names) == 0 || !f.Names[0].IsExported() {
					continue
				}
				if f.Tag != nil && strings.Contains(f.Tag.Value, `json:"-"`) {
					continue // never-serialized (e.g. SecretEnc, TokenHash)
				}
				fields = append(fields, field{typ: mermaidType(f.Type), name: f.Names[0].Name})
			}
			if len(fields) > 0 {
				entities[ts.Name.Name] = fields
				names = append(names, ts.Name.Name)
			}
		}
	}
	sort.Strings(names)

	b.WriteString("## 2. Domain data model\n\n")
	b.WriteString("Entities are the exported structs in `internal/store/store.go` (never-serialized fields such as `SecretEnc`/`TokenHash` are omitted). Relationships are inferred from `<Entity>ID` foreign keys.\n\n")
	b.WriteString("```mermaid\nerDiagram\n")
	for _, name := range names {
		fmt.Fprintf(b, "  %s {\n", name)
		for _, f := range entities[name] {
			fmt.Fprintf(b, "    %s %s\n", f.typ, f.name)
		}
		b.WriteString("  }\n")
	}
	// Relationships: a field named <X>ID whose <X> is another entity.
	var rels []string
	for _, name := range names {
		for _, f := range entities[name] {
			if !strings.HasSuffix(f.name, "ID") || f.name == "ID" {
				continue
			}
			base := strings.TrimSuffix(f.name, "ID")
			if _, ok := entities[base]; ok {
				rels = append(rels, fmt.Sprintf("  %s ||--o{ %s : %q", base, name, "has"))
			}
		}
	}
	sort.Strings(rels)
	for _, r := range rels {
		b.WriteString(r + "\n")
	}
	b.WriteString("```\n\n")
	return nil
}

// mermaidType renders a Go type as a Mermaid-safe attribute type (alphanumerics
// and underscores only).
func mermaidType(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "ptr_" + mermaidType(t.X)
	case *ast.SelectorExpr:
		return mermaidType(t.X) + "_" + t.Sel.Name
	case *ast.ArrayType:
		return "arr_" + mermaidType(t.Elt)
	case *ast.MapType:
		return "map_" + mermaidType(t.Key) + "_" + mermaidType(t.Value)
	default:
		return "value"
	}
}

// --- REST route map -----------------------------------------------------------

var (
	reRoute = regexp.MustCompile(`s\.mux\.Handle(?:Func)?\("([A-Z]+) ([^"]+)",\s*(.*)$`)
	reCap   = regexp.MustCompile(`auth\.Cap(\w+)`)
)

// guardByWrapper maps a registration's middleware to the label the route table
// shows, in match order. Every authentication scheme PAMv1 puts on the mux has to
// appear here — see routeGuard for what happens when one does not.
var guardByWrapper = []struct{ needle, label string }{
	{"authenticated(", "authenticated"},
	{"agentAuth(", "agent credential"},
	{"scimAuth(", "SCIM client key"},
	{"appAuth(", "application key"},
	// A pre-authentication token that is NOT yet a session: mfaPendingOnly
	// resolves the presented key and refuses an invalid one, so these routes are
	// credential-checked even though the sign-in is only half done.
	{"mfaPendingOnly(", "MFA-pending token"},
	// The graphical viewer tunnels authenticate from a query-string token
	// (browsers cannot set headers on a WebSocket handshake), so they carry no
	// middleware wrapper for the route table to read off.
	{"rdpTunnel", "token (query)"},
	{"vncTunnel", "token (query)"},
	// The guest pages (session share, magic-link approval) authenticate a
	// single-use token inside the handler, for the same reason: the caller has no
	// PAMv1 login at all — that is the feature.
	{"previewApprovalInvite", "token (single-use link)"},
	{"redeemApprovalInvite", "token (single-use link)"},
	{"redeemShareInvite", "token (single-use link)"},
	{"streamShareGuest", "token (single-use link)"},
	{"inputShareGuest", "token (single-use link)"},
	// Slack's own request signature (v0 HMAC-SHA256) is the authentication
	// for its interactivity callback — the caller (Slack's servers) has no
	// PAMv1 credential at all, verified inside the handler before anything
	// else runs, the same shape as the token-authenticated guest routes
	// above.
	{"slackInteractivity", "Slack request signature (HMAC)"},
}

// publicRoutes is the allowlist of routes that genuinely carry NO credential,
// each with the reason it does not. It is what makes the classifier fail-closed:
// "public" has to be claimed here, never inferred from a wrapper the generator
// happens not to recognise.
var publicRoutes = map[string]string{
	"GET /healthz":                        "liveness probe, read by the container HEALTHCHECK",
	"GET /readyz":                         "readiness probe (store reachable)",
	"GET /metrics":                        "Prometheus exposition; bind it where only your scraper reaches",
	"GET /{$}":                            "the 5250 portal shell; every call it makes is authenticated",
	"GET /static/guacamole-common.min.js": "vendored RDP viewer client, a static asset",
	"GET /approve.html":                   "magic-link approval guest page; the decision itself needs the token",
	"GET /share.html":                     "session-share guest page; the session itself needs the token",
}

// withRateLimit annotates a real scheme with the throttle wrapped around it, so
// the table shows both facts instead of letting one hide the other.
func withRateLimit(label string, limited bool) string {
	if limited {
		return label + " (rate-limited)"
	}
	return label
}

// routeGuard names what protects one route, and REFUSES to guess.
//
// It used to fall back to "public" for any registration it could not classify,
// which is a fail-open default in the one document whose job is to say what
// guards each route. Three schemes were added to the mux after the classifier
// was written — agentAuth, scimAuth, appAuth — and every route behind them was
// published as "public": the whole AI-agent tool-call surface and the whole SCIM
// user-provisioning surface, which creates and deletes users. The routes were
// never unprotected; the security map said they were.
//
// So an unrecognised wrapper is now an ERROR that stops the generator, and CI
// runs the generator. Adding a new authentication scheme to the mux without
// teaching this table about it fails the build instead of quietly publishing the
// routes as unauthenticated. A genuinely credential-free route says so out loud
// in publicRoutes, with its reason.
func routeGuard(method, path, registration string) (string, error) {
	// rateLimit is a MODIFIER, not a scheme, and must be recognised as one. It
	// used to sit in guardByWrapper, and because the scan returns on first match
	// it swallowed whatever it wrapped: `s.rateLimit(s.mfaPendingOnly(...))`
	// classified as "public (rate-limited)", so both WebAuthn login routes were
	// published as unauthenticated even though mfaPendingOnly resolves the
	// presented key and refuses an invalid one. That is the very failure this
	// generator was rewritten to prevent, reintroduced by the shape of the scan
	// rather than by a missing entry — so the modifier is now peeled off first
	// and the thing it wraps is classified on its own.
	rateLimited := strings.Contains(registration, "rateLimit(")
	if c := reCap.FindStringSubmatch(registration); c != nil {
		return withRateLimit("Cap"+c[1], rateLimited), nil
	}
	for _, g := range guardByWrapper {
		if strings.Contains(registration, g.needle) {
			return withRateLimit(g.label, rateLimited), nil
		}
	}
	// Nothing inside it: a genuinely pre-authentication route (login, the SSO
	// callbacks, break-glass unseal) that is throttled precisely because anyone
	// may call it.
	if rateLimited {
		return "public (rate-limited)", nil
	}
	if _, ok := publicRoutes[method+" "+path]; ok {
		return "public", nil
	}
	return "", fmt.Errorf(
		"%s %s has no recognised auth wrapper and is not in publicRoutes (registration: %s) "+
			"— add its middleware to guardByWrapper, or, if it really takes no credential, add "+
			"it to publicRoutes with the reason; do not let it default to \"public\", which is "+
			"how the broker and SCIM surfaces came to be documented as unauthenticated",
		method, path, strings.TrimSpace(registration))
}

// writeRouteMap parses the mux wiring in internal/api/server.go into a table of
// method, path, and the capability (or guard) each route enforces.
func writeRouteMap(b *strings.Builder, root string) error {
	data, err := os.ReadFile(filepath.Join(root, "internal", "api", "server.go")) // #nosec G304 -- build-time doc generator reading a fixed repo source path
	if err != nil {
		return err
	}
	type route struct{ method, path, guard string }
	var routes []route
	for _, line := range strings.Split(string(data), "\n") {
		m := reRoute.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		guard, err := routeGuard(m[1], m[2], m[3])
		if err != nil {
			return err
		}
		routes = append(routes, route{m[1], m[2], guard})
	}
	sort.SliceStable(routes, func(i, j int) bool {
		if routes[i].path != routes[j].path {
			return routes[i].path < routes[j].path
		}
		return routes[i].method < routes[j].method
	})

	b.WriteString("## 3. REST API surface\n\n")
	fmt.Fprintf(b, "The %d routes registered on the API mux, with the capability or guard each enforces (see `internal/auth` for the role → capability matrix).\n\n", len(routes))
	b.WriteString("| Method | Path | Guard |\n|---|---|---|\n")
	for _, r := range routes {
		fmt.Fprintf(b, "| %s | `%s` | %s |\n", r.method, r.path, r.guard)
	}
	b.WriteString("\n")
	return nil
}
