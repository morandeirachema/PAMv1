package proxy

import "testing"

// TestPGQuoteIdent and TestPGQuoteLiteral are defense-in-depth: every actual
// caller only ever passes pamv1-generated hex (never client input), but the
// escaping itself is still verified correct against the standard SQL
// double-the-quote-character rule.
func TestPGQuoteIdent(t *testing.T) {
	cases := map[string]string{
		"pamv1_zsp_abc123": `"pamv1_zsp_abc123"`,
		`weird"name`:       `"weird""name"`,
	}
	for in, want := range cases {
		if got := pgQuoteIdent(in); got != want {
			t.Errorf("pgQuoteIdent(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPGQuoteLiteral(t *testing.T) {
	cases := map[string]string{
		"simple":    `'simple'`,
		"o'brien":   `'o''brien'`,
		"'; DROP--": `'''; DROP--'`,
	}
	for in, want := range cases {
		if got := pgQuoteLiteral(in); got != want {
			t.Errorf("pgQuoteLiteral(%q) = %q, want %q", in, got, want)
		}
	}
}
