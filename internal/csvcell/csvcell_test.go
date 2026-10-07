package csvcell

import "testing"

func TestNeutralizeRestore(t *testing.T) {
	for _, tc := range []struct{ in, out string }{
		{"", ""},
		{"web-01", "web-01"},
		{"=HYPERLINK(\"x\")", "'=HYPERLINK(\"x\")"},
		{"+1", "'+1"},
		{"-cmd", "'-cmd"},
		{"@SUM(A1)", "'@SUM(A1)"},
		{"\tx", "'\tx"},
		{"'plain", "'plain"},
	} {
		if got := Neutralize(tc.in); got != tc.out {
			t.Errorf("Neutralize(%q) = %q, want %q", tc.in, got, tc.out)
		}
		if got := Restore(Neutralize(tc.in)); got != tc.in {
			t.Errorf("Restore(Neutralize(%q)) = %q", tc.in, got)
		}
	}
}
