package blast

// terraform.go renders a finding's remediation as reviewable Terraform.
//
// WHY. Phase 31 already computes the right cut — the earliest pivot edge on the
// path — and returns it as a sentence: "Remove <via> (can_assume aws:role/x →
// aws:role/y) to break this path at its source." A sentence is a finding; a
// plan is a fix. Rendering the same decision as HCL puts the remediation
// through the review path every other infrastructure change in this repo goes
// through (it is IaC-only by project rule), so a reviewer sees the diff, an
// approver approves it, and the apply is recorded — instead of an engineer
// clicking through a console and nobody knowing exactly what changed.
//
// WHAT IT IS NOT. This is a STARTING POINT, not an applyable plan, and it says
// so in its own header. PAMv1's normalized graph deliberately carries less than
// a provider export does — an edge knows the policy or grant that enables it
// (`via`), not the ARN, the condition block or the group's full membership — so
// each emitted stanza names the object to change and leaves the provider
// specifics for the reviewer to complete against their own state. Emitting
// invented ARNs to make the output look applyable would be the dishonest
// version of this feature.
//
// ESCAPING IS A SECURITY CONTROL HERE, not formatting. The graph is submitted
// by a caller (POST /api/blast/analyze), so every id, label and `via` string in
// it is attacker-influenced, and this output is meant to be pasted into a file
// somebody runs `terraform apply` on. An id containing a quote or a newline
// could otherwise close the string and inject configuration; `${...}` and
// `%{...}` are interpolation markers Terraform evaluates at plan time, which is
// a path to reading files or running provider calls the reviewer never saw. All
// three are neutralized below — identifiers by reduction to [A-Za-z0-9_],
// values by escaping, comments by newline stripping.

import (
	"fmt"
	"sort"
	"strings"
)

// hclName reduces an arbitrary node id to a Terraform resource LABEL. A label
// is an HCL identifier, so this must be total: everything outside [A-Za-z0-9_]
// becomes "_", and an id that reduces to nothing becomes "_".
func hclName(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

// hclString escapes a value for use inside an HCL double-quoted string: the
// quote and backslash that would break out of it, the two interpolation markers
// Terraform would otherwise evaluate, and the newlines that would end the line.
func hclString(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		"${", "$${",
		"%{", "%%{",
		"\r", `\r`,
		"\n", `\n`,
	)
	return r.Replace(s)
}

// hclComment neutralizes an untrusted string bound for a `#` comment: newlines,
// so a value carrying one cannot end the comment and inject configuration after
// it, and the interpolation markers.
//
// HCL does not interpolate inside comments, so escaping the markers here is
// belt-and-braces — deliberately. It makes the invariant global and checkable in
// one line ("no untrusted `${` reaches the output unescaped") instead of one a
// reader has to re-derive from where each string landed, and it survives the
// refactor that moves a comment string into a value.
func hclComment(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ", "${", "$${", "%{", "%%{").Replace(s)
}

// Terraform renders the remediations for a set of findings as one HCL document,
// one stanza per distinct cut edge (several findings often share a cut — the
// same over-broad grant reaches many things — and applying it twice is a
// conflict, not a stronger fix). Findings whose path is empty carry no cut and
// are skipped. An empty result yields "" rather than a header with nothing
// under it.
func Terraform(findings []Finding, g *Graph) string {
	type item struct {
		key  string
		body string
	}
	var items []item
	seen := map[string]bool{}
	for _, f := range findings {
		if len(f.Path) == 0 {
			continue
		}
		cut := f.Remediation.CutEdge
		key := string(cut.Kind) + "|" + cut.From + "|" + cut.To + "|" + cut.Via
		if seen[key] {
			continue
		}
		seen[key] = true
		items = append(items, item{key: key, body: terraformFor(f, g)})
	}
	if len(items) == 0 {
		return ""
	}
	// Deterministic output: the same graph must render byte-identical HCL, or a
	// reviewer cannot tell a real change from reordering.
	sort.Slice(items, func(i, j int) bool { return items[i].key < items[j].key })
	var b strings.Builder
	b.WriteString(`# PAMv1 identity blast-radius — proposed remediation
#
# Each block below cuts the EARLIEST pivot edge on a reported escalation path:
# the change closest to the source, which breaks that path with the least
# disruption. Read every one before applying — this is generated from a
# normalized identity graph, so it names the object to change but cannot know
# your provider layout, existing conditions, or whether the access is
# legitimate. Complete the provider specifics against your own state.
#
# Cutting an edge breaks the REPORTED path only. If a source reaches its target
# by a second, edge-disjoint path, the escalation persists — re-run the analysis
# after applying to confirm no residual path remains.

`)
	for i, it := range items {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(it.body)
	}
	return b.String()
}

// terraformFor renders one finding's remediation.
func terraformFor(f Finding, g *Graph) string {
	cut := f.Remediation.CutEdge
	src, dst := g.Principal(cut.From), g.Principal(cut.To)
	header := fmt.Sprintf(`# %s: %s -> %s (severity %s)
# Cut: %s %s -> %s%s
%s`,
		hclComment(f.Title), hclComment(f.Source), hclComment(f.Target), hclComment(string(f.Severity)),
		hclComment(string(cut.Kind)), hclComment(cut.From), hclComment(cut.To),
		viaComment(cut.Via), reviewComment(f))
	switch cut.Kind {
	case CanAssume:
		return header + assumeFix(cut, src, dst)
	case MemberOf:
		return header + membershipFix(cut, src, dst)
	case CanEscalateTo:
		return header + escalationFix(cut, src, dst)
	case CredentialFor:
		return header + credentialFix(cut, src, dst)
	default:
		return header + fmt.Sprintf("# No generator for a %q edge; remove it by hand.\n",
			hclComment(string(cut.Kind)))
	}
}

// viaComment names the grant that enables the edge, when the ingester recorded one.
func viaComment(via string) string {
	if via == "" {
		return ""
	}
	return "\n# Enabled by: " + hclComment(via)
}

// reviewComment flags a cut that a human must judge before applying: the path
// crosses a conditional edge, so whether it actually holds depends on runtime
// context the evaluator could not resolve.
func reviewComment(f Finding) string {
	if !f.Remediation.NeedsReview {
		return ""
	}
	return "# NEEDS REVIEW: this path crosses a CONDITIONAL grant — confirm the\n" +
		"# condition really allows it before removing anything.\n"
}

// assumeFix narrows the trust policy of the role being assumed. The trust
// policy is the right lever: it lives with the role being protected, so one
// edit covers every principal that could assume it, rather than chasing each
// caller's identity policy.
func assumeFix(cut PathEdge, src, dst *Principal) string {
	return fmt.Sprintf(`# Narrow %s's trust policy so %s can no longer assume it.
# Replace the principal list with the identities that legitimately need it.
resource "aws_iam_role" "%s" {
  name = "%s"

  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { AWS = [] } # was: ["%s"]
      },
    ]
  })
}
%s`,
		hclComment(cut.To), hclComment(cut.From),
		hclName(cut.To), hclString(shortName(cut.To)), hclString(cut.From),
		providerNote("aws", src, dst))
}

// membershipFix removes a group membership. Terraform models a membership as a
// resource, so the fix is a deletion — expressed as the address to remove,
// because emitting a resource block would ADD one.
func membershipFix(cut PathEdge, src, dst *Principal) string {
	return fmt.Sprintf(`# %s inherits privileges by belonging to %s. Remove the membership:
# delete the resource that grants it, then plan.
#
#   terraform state list | grep %s
#   # remove the membership resource from your configuration, e.g.
#   #   aws_iam_user_group_membership.%s
#   #   okta_group_memberships.%s
#
# Deleting a membership is reversible and blast-free; prefer it to editing the
# group's policy, which would change what EVERY member can do.
%s`,
		hclComment(cut.From), hclComment(cut.To),
		hclName(shortName(cut.From)), hclName(cut.From), hclName(cut.To),
		providerNote("aws", src, dst))
}

// escalationFix bounds a principal with a permissions boundary. An escalation
// primitive (pass-role, policy attachment, key creation) is rarely removable
// without breaking the job it exists for, so the boundary caps what the
// escalation can reach instead of forbidding the action.
func escalationFix(cut PathEdge, src, dst *Principal) string {
	return fmt.Sprintf(`# %s holds a privilege-escalation primitive reaching %s.
# Cap it with a permissions boundary rather than removing the action: the
# boundary bounds what any escalated identity can do, including via paths not
# yet in the graph.
resource "aws_iam_policy" "%s_boundary" {
  name = "%s-boundary"

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyPrivilegeEscalation"
        Effect   = "Deny"
        Action   = ["iam:*", "sts:AssumeRole"]
        Resource = "*"
      },
      # Add the Allow statements this identity legitimately needs.
    ]
  })
}

# Attach it to the principal (aws_iam_user / aws_iam_role):
#   permissions_boundary = aws_iam_policy.%s_boundary.arn
%s`,
		hclComment(cut.From), hclComment(cut.To),
		hclName(cut.From), hclString(shortName(cut.From)),
		hclName(cut.From), providerNote("aws", src, dst))
}

// credentialFix cuts a held credential. Removing read access is the durable
// half; rotating is what makes it retroactive, and the order matters — rotating
// first leaves the holder able to read the new secret.
func credentialFix(cut PathEdge, src, dst *Principal) string {
	return fmt.Sprintf(`# %s holds a credential for %s. Two steps, in this order:
#   1. remove the read access (below), then
#   2. ROTATE the credential — until it is rotated, a copy already taken still
#      works, so step 1 alone is not a fix. In PAMv1 that is
#      POST /api/credentials/{id}/rotate.
resource "aws_iam_policy" "%s_deny_secret" {
  name = "%s-deny-secret-read"

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Sid      = "DenySecretRead"
        Effect   = "Deny"
        Action   = ["secretsmanager:GetSecretValue", "ssm:GetParameter"]
        Resource = "*" # narrow to the secret backing %s
      },
    ]
  })
}

# An explicit Deny cannot be overridden by any later Allow, so this holds even
# if someone widens the identity policy afterwards.
%s`,
		hclComment(cut.From), hclComment(cut.To),
		hclName(cut.From), hclString(shortName(cut.From)), hclComment(cut.To),
		providerNote("aws", src, dst))
}

// providerNote warns when the emitted stanza assumes a provider that one of the
// principals it names does not belong to. The graph is cross-provider by design
// — the whole point of the engine is that an Okta or GitHub identity can reach
// an AWS role — so AWS-shaped output must say when one end of the edge is not
// AWS, or a reviewer would paste a stanza that cannot resolve. One note per
// distinct foreign provider, in the order the principals were given.
func providerNote(assumed string, ps ...*Principal) string {
	if assumed == "" {
		return ""
	}
	var b strings.Builder
	seen := map[string]bool{}
	for _, p := range ps {
		if p == nil || p.Provider == "" || p.Provider == assumed || seen[p.Provider] {
			continue
		}
		seen[p.Provider] = true
		fmt.Fprintf(&b, "# NOTE: %s names a %s identity; the block above is %s-shaped.\n"+
			"# Translate it to the matching %s provider resource.\n",
			hclComment(p.ID), hclComment(p.Provider), assumed, hclComment(p.Provider))
	}
	return b.String()
}

// shortName is the last path segment of an id ("aws:role/admin" -> "admin"),
// used for a readable resource name. Escaping still applies at the call site.
func shortName(id string) string {
	if i := strings.LastIndexAny(id, "/:"); i >= 0 && i+1 < len(id) {
		return id[i+1:]
	}
	return id
}
