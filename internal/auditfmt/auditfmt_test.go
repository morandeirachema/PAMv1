package auditfmt

import "testing"

// TestFieldQuotesAndBounds proves Field makes an untrusted value safe for an
// audit detail: it quotes so an embedded newline or forged key:value pair cannot
// restructure the record, and it bounds the length so an attacker cannot choose
// the row size.
func TestFieldQuotesAndBounds(t *testing.T) {
	// A forged pair and a newline survive only as escaped text inside one quoted
	// token — never as free-standing structure.
	got := Field("alice target:prod action:approved\nx", 200)
	if got == "" || got[0] != '"' || got[len(got)-1] != '"' {
		t.Fatalf("Field must return a quoted string, got %q", got)
	}
	for _, r := range got[1 : len(got)-1] {
		if r == '\n' || r == '\r' {
			t.Fatalf("Field left a raw control character in %q", got)
		}
	}

	// Bounding: a value longer than the limit is truncated (with an ellipsis) so
	// the rendered field cannot grow without bound.
	long := make([]byte, 500)
	for i := range long {
		long[i] = 'A'
	}
	bounded := Field(string(long), 64)
	if len([]rune(bounded)) > 64+3 { // 64 bytes + ellipsis + two quotes
		t.Fatalf("Field did not bound length: %d runes", len([]rune(bounded)))
	}
}

// TestOneLine proves OneLine flattens CR and LF to spaces so an untrusted value
// cannot inject an extra line into a line-oriented sink.
func TestOneLine(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"plain", "plain"},
		{"a\nb", "a b"},
		{"a\r\nb", "a  b"},
		{"trailing\n", "trailing "},
		{"", ""},
	} {
		if got := OneLine(tc.in); got != tc.want {
			t.Errorf("OneLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
