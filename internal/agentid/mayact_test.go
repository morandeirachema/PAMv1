package agentid

import (
	"strings"
	"testing"
)

// TestValidateMayActBounds pins the rules an emitted may_act must satisfy. They
// are all narrowing rules: a pin that names everybody, a party outside the trust
// domain, or the token's own subject would each turn a constraint into
// decoration.
func TestValidateMayActBounds(t *testing.T) {
	const subject = "spiffe://example.org/ns/prod/sa/worker"
	for _, tc := range []struct {
		name      string
		requested []string
		want      []string
		wantErr   string
	}{
		{"unpinned stays unpinned", nil, nil, ""},
		{
			"in-domain parties are kept in order, de-duplicated",
			[]string{"spiffe://example.org/a", "spiffe://example.org/b", "spiffe://example.org/a"},
			[]string{"spiffe://example.org/a", "spiffe://example.org/b"}, "",
		},
		{
			"a foreign party is refused",
			[]string{"spiffe://evil.example/a"}, nil, "inside the trust domain",
		},
		{
			"the token's own subject is refused",
			[]string{subject}, nil, "own subject",
		},
		{
			"a list nobody could audit is refused",
			[]string{"spiffe://example.org/1", "spiffe://example.org/2", "spiffe://example.org/3",
				"spiffe://example.org/4", "spiffe://example.org/5", "spiffe://example.org/6",
				"spiffe://example.org/7", "spiffe://example.org/8", "spiffe://example.org/9"},
			nil, "too many parties",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateMayAct(tc.requested, subject)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Description, tc.wantErr) {
					t.Fatalf("want an error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestTrustDomainPrefix covers the derivation the validation rests on: the
// domain comes from the ACTOR's already-verified SPIFFE ID, so it cannot drift
// from whatever the verifier was configured with.
func TestTrustDomainPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"spiffe://example.org/ns/prod/sa/x": "spiffe://example.org/",
		"spiffe://example.org/a":            "spiffe://example.org/",
		"spiffe://example.org":              "", // no path: not a usable prefix
		"https://example.org/x":             "",
		"":                                  "",
	} {
		if got := trustDomainPrefix(in); got != want {
			t.Fatalf("trustDomainPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}
