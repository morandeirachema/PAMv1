package blast_test

import (
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/blast"
)

// TestTerraformRendersTheCut proves the HCL names the edge the engine chose to
// cut, carries the enabling grant, and is deterministic — a reviewer must be
// able to diff two runs and see only real change.
func TestTerraformRendersTheCut(t *testing.T) {
	g := &blast.Graph{
		Principals: []blast.Principal{
			{ID: "aws:user/bob", Kind: "user", Provider: "aws"},
			{ID: "aws:role/deploy", Kind: "role", Provider: "aws"},
			{ID: "aws:role/admin", Kind: "role", Provider: "aws", Admin: true},
		},
		Edges: []blast.Edge{
			{From: "aws:user/bob", To: "aws:role/deploy", Kind: blast.CanAssume, Via: "trust-policy/deploy"},
			{From: "aws:role/deploy", To: "aws:role/admin", Kind: blast.CanEscalateTo, Via: "iam:PassRole"},
		},
	}
	findings, err := g.Findings()
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("no findings to render")
	}
	hcl := blast.Terraform(findings, g)
	for _, want := range []string{
		"aws_iam_role",        // the trust-policy narrowing for the can_assume cut
		"aws:user/bob",        // who is being cut off
		"trust-policy/deploy", // the grant that enabled it
		"re-run the analysis", // the honest caveat about edge-disjoint paths
	} {
		if !strings.Contains(hcl, want) {
			t.Fatalf("rendered HCL is missing %q:\n%s", want, hcl)
		}
	}
	if again := blast.Terraform(findings, g); again != hcl {
		t.Fatal("two renders of the same findings differ; the output is not deterministic")
	}
	// A clean graph renders nothing rather than a header over an empty document.
	if out := blast.Terraform(nil, g); out != "" {
		t.Fatalf("no findings rendered %q, want empty", out)
	}
}

// TestTerraformEscapesHostileIdentifiers is the security test: the graph is
// submitted by a caller and the output is meant to be applied, so an id
// carrying a quote, a newline or a Terraform interpolation marker must not be
// able to close a string, end a comment, or be evaluated at plan time.
func TestTerraformEscapesHostileIdentifiers(t *testing.T) {
	const hostile = `aws:user/"evil` + "\n" + `resource "null_resource" "pwn" {}` + "\n" + `${file("/etc/passwd")}`
	g := &blast.Graph{
		Principals: []blast.Principal{
			{ID: hostile, Kind: "user", Provider: "aws"},
			{ID: "aws:role/admin", Kind: "role", Provider: "aws", Admin: true},
		},
		Edges: []blast.Edge{
			{From: hostile, To: "aws:role/admin", Kind: blast.CanAssume, Via: "\"; injected = true\n"},
		},
	}
	findings, err := g.Findings()
	if err != nil {
		t.Fatal(err)
	}
	hcl := blast.Terraform(findings, g)
	if hcl == "" {
		t.Fatal("nothing rendered")
	}
	// The injected resource block must never appear at the start of a line: that
	// is what "escaped into configuration" looks like.
	for _, line := range strings.Split(hcl, "\n") {
		if strings.HasPrefix(line, `resource "null_resource"`) {
			t.Fatalf("an injected resource block reached the output:\n%s", hcl)
		}
	}
	// Terraform evaluates `${...}` and escapes it as `$${...}`. Every occurrence
	// of the marker must therefore be part of an escaped one — counting is the
	// check, since the escaped form naturally contains the raw form.
	raw, escaped := strings.Count(hcl, "${file("), strings.Count(hcl, "$${file(")
	if raw != escaped {
		t.Fatalf("%d interpolation markers survived unescaped:\n%s", raw-escaped, hcl)
	}
	// Every rendered line either is a comment or contains no raw injected quote
	// sequence — the two escapes that matter, checked where they matter.
	if strings.Contains(hcl, `= "aws:user/"evil`) {
		t.Fatalf("an unescaped quote broke out of an HCL string:\n%s", hcl)
	}
}

// TestTerraformCoversEveryPivotKind proves each pivot edge kind has a real
// generator rather than falling through to the "no generator" stub, and that a
// cross-provider principal is flagged instead of silently receiving AWS syntax.
func TestTerraformCoversEveryPivotKind(t *testing.T) {
	kinds := []blast.EdgeKind{blast.CanAssume, blast.MemberOf, blast.CanEscalateTo, blast.CredentialFor}
	for _, k := range kinds {
		g := &blast.Graph{
			Principals: []blast.Principal{
				{ID: "okta:user/carol", Kind: "user", Provider: "okta"},
				{ID: "aws:role/admin", Kind: "role", Provider: "aws", Admin: true},
			},
			Edges: []blast.Edge{{From: "okta:user/carol", To: "aws:role/admin", Kind: k, Via: "grant-1"}},
		}
		findings, err := g.Findings()
		if err != nil {
			t.Fatal(err)
		}
		hcl := blast.Terraform(findings, g)
		if strings.Contains(hcl, "No generator") {
			t.Fatalf("%s has no remediation generator:\n%s", k, hcl)
		}
		if !strings.Contains(hcl, "okta:user/carol") {
			t.Fatalf("%s: rendering does not name the source:\n%s", k, hcl)
		}
		// An okta identity receiving AWS-shaped output must be told so.
		if strings.Contains(hcl, "aws_iam_") && !strings.Contains(hcl, "okta identity") {
			t.Fatalf("%s: AWS syntax emitted for an okta principal with no note:\n%s", k, hcl)
		}
	}
}
