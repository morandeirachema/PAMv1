package blast

import (
	"fmt"
	"sort"
	"strings"
)

// EdgeKind classifies a relationship between two principals. PIVOT edges expand
// an attacker's reach (compromising the source lets them act as/through the
// target); CONTAINMENT edges are structural/read-only and do NOT expand reach.
type EdgeKind string

const (
	// Pivot edges — a compromise of `from` yields control of/through `to`.
	CanAssume     EdgeKind = "can_assume"      // sts:AssumeRole, Okta app-as, etc.
	MemberOf      EdgeKind = "member_of"       // a group's privileges flow to members
	CanEscalateTo EdgeKind = "can_escalate_to" // a known privilege-escalation primitive
	CredentialFor EdgeKind = "credential_for"  // holds a credential/secret for `to`
	// Containment edges — structural, not a pivot.
	Contains EdgeKind = "contains" // an account/org contains a principal
	Reads    EdgeKind = "reads"    // read-only visibility, no control
)

// pivotKinds is the set of edges that expand blast radius.
var pivotKinds = map[EdgeKind]bool{CanAssume: true, MemberOf: true, CanEscalateTo: true, CredentialFor: true}

// IsPivot reports whether an edge expands reach.
func (k EdgeKind) IsPivot() bool { return pivotKinds[k] }

// Principal is one identity node (a user, role, group, or service identity),
// possibly carrying the IAM inputs the evaluator needs.
type Principal struct {
	ID       string            `json:"id"`       // globally unique, e.g. "aws:user/alice"
	Kind     string            `json:"kind"`     // user | role | group | service
	Provider string            `json:"provider"` // aws | okta | github | google | oauth
	Labels   map[string]string `json:"labels,omitempty"`
	// Identity/SCP/Boundary policies (AWS). Optional; used by the IAM evaluator and
	// by findings that key on effective admin.
	Identity []Policy `json:"identity,omitempty"`
	SCPs     []Policy `json:"scps,omitempty"`
	Boundary []Policy `json:"boundary,omitempty"`
	Admin    bool     `json:"admin,omitempty"` // pre-classified effective-admin (or derived)
}

// Edge is a directed relationship from one principal to another.
type Edge struct {
	From         string   `json:"from"`
	To           string   `json:"to"`
	Kind         EdgeKind `json:"kind"`
	Via          string   `json:"via,omitempty"` // the policy/grant that enables it (for remediation)
	HasCondition bool     `json:"has_condition,omitempty"`
}

// Graph is a normalized identity graph produced by an ingester and consumed by
// the engine. It is provider-agnostic: cross-provider edges are ordinary edges.
type Graph struct {
	Principals []Principal `json:"principals"`
	Edges      []Edge      `json:"edges"`
}

// index builds fast lookup maps and validates references. It returns an error if
// an edge references an unknown principal (fail-loud on a malformed graph).
func (g *Graph) index() (map[string]*Principal, map[string][]Edge, error) {
	byID := make(map[string]*Principal, len(g.Principals))
	for i := range g.Principals {
		p := &g.Principals[i]
		if p.ID == "" {
			return nil, nil, fmt.Errorf("blast: a principal has no id")
		}
		if _, dup := byID[p.ID]; dup {
			return nil, nil, fmt.Errorf("blast: duplicate principal id %q", p.ID)
		}
		byID[p.ID] = p
	}
	out := make(map[string][]Edge, len(g.Principals))
	for _, e := range g.Edges {
		if byID[e.From] == nil || byID[e.To] == nil {
			return nil, nil, fmt.Errorf("blast: edge %s -> %s references an unknown principal", e.From, e.To)
		}
		out[e.From] = append(out[e.From], e)
	}
	return byID, out, nil
}

// Reach is one reachable principal and the path (pivot edges) that reaches it.
type Reach struct {
	Principal string     `json:"principal"`
	Uncertain bool       `json:"uncertain"` // a conditional edge lies on the path
	Path      []PathEdge `json:"path"`
}

// PathEdge is one hop on a reachability path.
type PathEdge struct {
	From string   `json:"from"`
	To   string   `json:"to"`
	Kind EdgeKind `json:"kind"`
	Via  string   `json:"via,omitempty"`
}

// BlastRadius returns every principal reachable from source by following PIVOT
// edges transitively (BFS, shortest path first). The source is not included.
// Containment/read edges are ignored — an edge in the result means control that
// really transfers. An unknown source yields an empty result.
func (g *Graph) BlastRadius(source string) ([]Reach, error) {
	byID, adj, err := g.index()
	if err != nil {
		return nil, err
	}
	if byID[source] == nil {
		return nil, nil
	}
	type state struct {
		id        string
		path      []PathEdge
		uncertain bool
	}
	seen := map[string]bool{source: true}
	queue := []state{{id: source}}
	var out []Reach
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		edges := append([]Edge(nil), adj[cur.id]...)
		sort.Slice(edges, func(i, j int) bool { return edges[i].To < edges[j].To })
		for _, e := range edges {
			if !e.Kind.IsPivot() || seen[e.To] {
				continue
			}
			seen[e.To] = true
			path := append(append([]PathEdge(nil), cur.path...), PathEdge{From: e.From, To: e.To, Kind: e.Kind, Via: e.Via})
			unc := cur.uncertain || e.HasCondition
			out = append(out, Reach{Principal: e.To, Uncertain: unc, Path: path})
			queue = append(queue, state{id: e.To, path: path, uncertain: unc})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Principal < out[j].Principal })
	return out, nil
}

// WhoCanReach returns every principal that can reach target via pivot edges (the
// reverse query — who is in the blast radius that lands on target).
func (g *Graph) WhoCanReach(target string) ([]string, error) {
	byID, _, err := g.index()
	if err != nil {
		return nil, err
	}
	if byID[target] == nil {
		return nil, nil
	}
	var out []string
	for id := range byID {
		if id == target {
			continue
		}
		reach, _ := g.BlastRadius(id)
		for _, r := range reach {
			if r.Principal == target {
				out = append(out, id)
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// Severity is a finding's derived severity.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
)

// Finding is a toxic-combination result: a source principal whose blast radius
// reaches something it should not.
type Finding struct {
	Source      string      `json:"source"`
	Target      string      `json:"target"`
	Severity    Severity    `json:"severity"`
	Title       string      `json:"title"`
	Uncertain   bool        `json:"uncertain"`
	Path        []PathEdge  `json:"path"`
	Remediation Remediation `json:"remediation"`
}

// Remediation is the reviewable fix for a finding: cut the EARLIEST pivot edge on
// the path (closest to the source), which breaks it with the least disruption.
type Remediation struct {
	CutEdge     PathEdge `json:"cut_edge"`
	Action      string   `json:"action"`       // human-readable instruction
	NeedsReview bool     `json:"needs_review"` // the cut edge (or path) is conditional/uncertain
}

// Findings computes toxic-combination findings over the graph: a non-admin (or
// low-privilege) principal that can pivot to an effective-admin principal, and
// any cross-provider pivot (lateral movement across trust domains). Each finding
// carries a remediation cutting the earliest pivot edge. Deterministic ordering.
func (g *Graph) Findings() ([]Finding, error) {
	byID, _, err := g.index()
	if err != nil {
		return nil, err
	}
	var out []Finding
	for i := range g.Principals {
		src := &g.Principals[i]
		if isAdmin(src) {
			continue // an admin reaching admin is not an escalation
		}
		reach, _ := g.BlastRadius(src.ID)
		for _, r := range reach {
			dst := byID[r.Principal]
			escalation := isAdmin(dst)
			crossProvider := dst.Provider != "" && src.Provider != "" && dst.Provider != src.Provider
			if !escalation && !crossProvider {
				continue
			}
			f := Finding{Source: src.ID, Target: r.Principal, Uncertain: r.Uncertain, Path: r.Path}
			switch {
			case escalation && crossProvider:
				f.Severity, f.Title = SevCritical, "cross-provider privilege escalation to an effective admin"
			case escalation:
				f.Severity, f.Title = SevHigh, "privilege escalation to an effective admin"
			default:
				f.Severity, f.Title = SevMedium, "cross-provider lateral movement"
			}
			f.Remediation = remediate(r.Path, r.Uncertain)
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Target < out[j].Target
	})
	return out, nil
}

// remediate proposes cutting the earliest pivot edge on a path.
func remediate(path []PathEdge, uncertain bool) Remediation {
	if len(path) == 0 {
		return Remediation{}
	}
	cut := path[0]
	via := cut.Via
	if via == "" {
		via = fmt.Sprintf("the %s edge", cut.Kind)
	}
	return Remediation{
		CutEdge:     cut,
		Action:      fmt.Sprintf("Remove %s (%s %s → %s) to break this path at its source.", via, cut.Kind, cut.From, cut.To),
		NeedsReview: uncertain,
	}
}

// isAdmin reports whether a principal is an effective admin: pre-classified
// (Admin flag or an "admin"/"priv:high" label), or derivable from an identity
// policy that allows "*" on "*".
func isAdmin(p *Principal) bool {
	if p == nil {
		return false
	}
	if p.Admin || strings.EqualFold(p.Labels["priv"], "high") || strings.EqualFold(p.Labels["admin"], "true") {
		return true
	}
	ev := Evaluator{Identity: p.Identity, SCPs: p.SCPs, Boundary: p.Boundary}
	// An identity that can do "*" on "*" is effective-admin (unless a ceiling caps it).
	return ev.Evaluate("*", "*").Decision == Allowed
}

// Stats summarizes a graph for the analysis response.
type Stats struct {
	Principals int `json:"principals"`
	Edges      int `json:"edges"`
	PivotEdges int `json:"pivot_edges"`
	Admins     int `json:"admins"`
}

// Summary returns graph statistics.
func (g *Graph) Summary() Stats {
	s := Stats{Principals: len(g.Principals), Edges: len(g.Edges)}
	for i := range g.Principals {
		if isAdmin(&g.Principals[i]) {
			s.Admins++
		}
	}
	for _, e := range g.Edges {
		if e.Kind.IsPivot() {
			s.PivotEdges++
		}
	}
	return s
}
