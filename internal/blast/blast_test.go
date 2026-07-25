package blast

import "testing"

// driftGraph builds a canonical multi-hop, cross-provider escalation chain (the
// Salesloft-Drift-shaped scenario): a low-privilege GitHub app credential leads,
// hop by hop, to an AWS admin role.
//
//	gh:app/drift --credential_for--> okta:user/svc --member_of--> okta:group/eng
//	   --can_assume(cond)--> aws:role/deploy --can_escalate_to--> aws:role/admin(*:*)
func driftGraph() Graph {
	return Graph{
		Principals: []Principal{
			{ID: "gh:app/drift", Kind: "service", Provider: "github", Labels: map[string]string{"priv": "low"}},
			{ID: "okta:user/svc", Kind: "user", Provider: "okta"},
			{ID: "okta:group/eng", Kind: "group", Provider: "okta"},
			{ID: "aws:role/deploy", Kind: "role", Provider: "aws"},
			{ID: "aws:role/admin", Kind: "role", Provider: "aws",
				Identity: []Policy{pol(Allow, []string{"*"}, []string{"*"}, false)}},
			{ID: "aws:user/intern", Kind: "user", Provider: "aws", Labels: map[string]string{"priv": "low"}},
		},
		Edges: []Edge{
			{From: "gh:app/drift", To: "okta:user/svc", Kind: CredentialFor, Via: "github-oauth-grant"},
			{From: "okta:user/svc", To: "okta:group/eng", Kind: MemberOf},
			{From: "okta:group/eng", To: "aws:role/deploy", Kind: CanAssume, Via: "okta-aws-federation", HasCondition: true},
			{From: "aws:role/deploy", To: "aws:role/admin", Kind: CanEscalateTo, Via: "iam:PassRole+lambda"},
			// A read-only edge that must NOT expand blast radius.
			{From: "aws:user/intern", To: "aws:role/admin", Kind: Reads},
		},
	}
}

// TestBlastRadiusTraversal proves pivot edges expand reach transitively and
// containment/read edges do not, with the conditional edge marking the path
// uncertain.
func TestBlastRadiusTraversal(t *testing.T) {
	g := driftGraph()
	reach, err := g.BlastRadius("gh:app/drift")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range reach {
		got[r.Principal] = true
	}
	for _, want := range []string{"okta:user/svc", "okta:group/eng", "aws:role/deploy", "aws:role/admin"} {
		if !got[want] {
			t.Fatalf("blast radius missing %q: %+v", want, reach)
		}
	}
	// The full chain to admin passes through a conditional edge → uncertain.
	for _, r := range reach {
		if r.Principal == "aws:role/admin" && !r.Uncertain {
			t.Fatal("the path to admin crosses a conditional edge; it must be uncertain")
		}
	}

	// A read-only edge does not create reach: the intern reaches nothing.
	if r, _ := g.BlastRadius("aws:user/intern"); len(r) != 0 {
		t.Fatalf("a read-only edge must not expand blast radius: %+v", r)
	}
}

// TestWhoCanReach proves the reverse query lists every principal that can pivot
// to a target.
func TestWhoCanReach(t *testing.T) {
	g := driftGraph()
	who, err := g.WhoCanReach("aws:role/admin")
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, w := range who {
		set[w] = true
	}
	for _, want := range []string{"gh:app/drift", "okta:user/svc", "okta:group/eng", "aws:role/deploy"} {
		if !set[want] {
			t.Fatalf("who-can-reach(admin) missing %q: %v", want, who)
		}
	}
	if set["aws:user/intern"] {
		t.Fatal("the intern reaches admin only via a read edge; must not be listed")
	}
}

// TestFindingsAndRemediation proves the toxic-combination scan flags the
// cross-provider escalation as critical, marks it needs-review (a conditional
// hop), and remediates by cutting the EARLIEST pivot edge.
func TestFindingsAndRemediation(t *testing.T) {
	g := driftGraph()
	findings, err := g.Findings()
	if err != nil {
		t.Fatal(err)
	}
	var crit *Finding
	for i := range findings {
		if findings[i].Source == "gh:app/drift" && findings[i].Target == "aws:role/admin" {
			crit = &findings[i]
		}
	}
	if crit == nil {
		t.Fatalf("expected a drift→admin finding: %+v", findings)
	}
	if crit.Severity != SevCritical {
		t.Fatalf("cross-provider escalation to admin should be critical, got %s", crit.Severity)
	}
	if !crit.Uncertain || !crit.Remediation.NeedsReview {
		t.Fatal("a conditional path must be flagged uncertain / needs-review")
	}
	// The earliest cut is the first pivot edge out of the source.
	if crit.Remediation.CutEdge.From != "gh:app/drift" || crit.Remediation.CutEdge.To != "okta:user/svc" {
		t.Fatalf("remediation should cut the earliest edge, got %+v", crit.Remediation.CutEdge)
	}
}

// TestMalformedGraphRejected proves an edge to an unknown principal is a
// fail-loud error rather than a silent miss.
func TestMalformedGraphRejected(t *testing.T) {
	g := Graph{
		Principals: []Principal{{ID: "a"}},
		Edges:      []Edge{{From: "a", To: "ghost", Kind: CanAssume}},
	}
	if _, err := g.Findings(); err == nil {
		t.Fatal("an edge to an unknown principal must be rejected")
	}
}

// TestCertainPathPreferredOverConditional proves a node reachable by BOTH a
// shorter conditional path and a longer unconditional path is reported CERTAIN
// (not uncertain) — a definite escalation isn't softened to "needs review".
func TestCertainPathPreferredOverConditional(t *testing.T) {
	g := Graph{
		Principals: []Principal{
			{ID: "s", Provider: "aws"},
			{ID: "m", Provider: "aws"},
			{ID: "adm", Provider: "aws", Admin: true},
		},
		Edges: []Edge{
			{From: "s", To: "adm", Kind: CanAssume, HasCondition: true}, // shorter, conditional
			{From: "s", To: "m", Kind: MemberOf},                        // longer, unconditional...
			{From: "m", To: "adm", Kind: CanEscalateTo},                 // ...path to adm
		},
	}
	reach, err := g.BlastRadius("s")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reach {
		if r.Principal == "adm" {
			if r.Uncertain {
				t.Fatal("adm has an all-unconditional path (s→m→adm); it must be certain, not uncertain")
			}
			if len(r.Path) != 2 { // the certain path is the 2-hop one
				t.Fatalf("expected the certain (2-hop) path, got %d hops", len(r.Path))
			}
		}
	}
}

// TestIsAdminCountsConditionalStar proves a principal whose only *:* allow is
// conditional is still treated as an effective admin (escalation to it is flagged).
func TestIsAdminCountsConditionalStar(t *testing.T) {
	g := Graph{
		Principals: []Principal{
			{ID: "u", Provider: "aws", Labels: map[string]string{"priv": "low"}},
			{ID: "condadm", Provider: "aws", Identity: []Policy{pol(Allow, []string{"*"}, []string{"*"}, true)}},
		},
		Edges: []Edge{{From: "u", To: "condadm", Kind: CanEscalateTo}},
	}
	findings, err := g.Findings()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Source == "u" && f.Target == "condadm" {
			found = true
		}
	}
	if !found {
		t.Fatalf("escalation to a conditional-*:* admin must be flagged: %+v", findings)
	}
}
