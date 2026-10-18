package api

import (
	"net/http/httptest"
	"testing"
)

// TestQueryLimit pins the clamp every ?limit= listing shares: the default
// stands in for anything absent, unparsable, non-positive or above the max —
// never the max itself, and never zero, which several store list methods read
// as "every row".
func TestQueryLimit(t *testing.T) {
	cases := []struct {
		query string
		want  int
	}{
		{"", 100},
		{"?limit=50", 50},
		{"?limit=1", 1},
		{"?limit=500", 500},
		{"?limit=501", 100},
		{"?limit=0", 100},
		{"?limit=-5", 100},
		{"?limit=abc", 100},
		{"?limit=", 100},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/x"+c.query, nil)
		if got := queryLimit(r, 100, 500); got != c.want {
			t.Errorf("queryLimit(%q) = %d, want %d", c.query, got, c.want)
		}
	}
}
