package timeframe

import (
	"testing"
	"time"
)

// at builds an instant on a known weekday: 2026-09-07 is a Monday.
func at(day int, hh, mm int, loc *time.Location) time.Time {
	return time.Date(2026, 9, 7+day, hh, mm, 0, 0, loc) // day 0 = Monday
}

func TestParseRejects(t *testing.T) {
	for _, bad := range []string{"Mon-Fri", "Mon-Fri 8-18", "Mon-Fri 08:00-18:00 Nowhere/Zone", "Fun 08:00-18:00", "Mon 24:00-06:00", "Mon 08:60-18:00", "Mon 08:00-18:00 UTC extra"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

func TestContainsAndEnd(t *testing.T) {
	madrid, err := time.LoadLocation("Europe/Madrid")
	if err != nil {
		t.Skip("tzdata unavailable")
	}
	cases := []struct {
		frame   string
		when    time.Time
		in      bool
		wantEnd time.Time
	}{
		{"Mon-Fri 08:00-18:00", at(0, 9, 0, time.UTC), true, at(0, 18, 0, time.UTC)},
		{"Mon-Fri 08:00-18:00", at(0, 7, 59, time.UTC), false, time.Time{}},
		{"Mon-Fri 08:00-18:00", at(0, 18, 0, time.UTC), false, time.Time{}}, // end is exclusive
		{"Mon-Fri 08:00-18:00", at(5, 12, 0, time.UTC), false, time.Time{}}, // Saturday
		{"Sat,Sun 00:00-24:00", at(6, 23, 59, time.UTC), true, at(7, 0, 0, time.UTC)},
		{"* 00:00-24:00", at(3, 12, 0, time.UTC), true, at(4, 0, 0, time.UTC)},
		{"Fri-Mon 08:00-18:00", at(6, 12, 0, time.UTC), true, at(6, 18, 0, time.UTC)}, // wrapped range includes Sunday
		{"Fri-Mon 08:00-18:00", at(2, 12, 0, time.UTC), false, time.Time{}},           // ...but not Wednesday
		// Overnight: Monday-Friday nights 22:00 -> 06:00 next morning.
		{"Mon-Fri 22:00-06:00", at(0, 23, 0, time.UTC), true, at(1, 6, 0, time.UTC)},
		{"Mon-Fri 22:00-06:00", at(1, 5, 0, time.UTC), true, at(1, 6, 0, time.UTC)},
		{"Mon-Fri 22:00-06:00", at(1, 12, 0, time.UTC), false, time.Time{}},
		{"Mon-Fri 22:00-06:00", at(5, 5, 0, time.UTC), true, at(5, 6, 0, time.UTC)}, // Saturday morning: Friday's night
		{"Mon-Fri 22:00-06:00", at(5, 23, 0, time.UTC), false, time.Time{}},         // Saturday night: not listed
		// Zone: 09:00 Madrid is 07:00 UTC in September.
		{"Mon-Fri 08:00-18:00 Europe/Madrid", at(0, 7, 0, time.UTC), true, at(0, 18, 0, madrid)},
		{"Mon-Fri 08:00-18:00 Europe/Madrid", at(0, 5, 30, time.UTC), false, time.Time{}},
	}
	for _, c := range cases {
		f, err := Parse(c.frame)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.frame, err)
		}
		if got := f.Contains(c.when); got != c.in {
			t.Errorf("%q Contains(%s) = %v, want %v", c.frame, c.when, got, c.in)
		}
		end, ok := f.End(c.when)
		if ok != c.in {
			t.Errorf("%q End(%s) ok = %v, want %v", c.frame, c.when, ok, c.in)
		}
		if ok && !end.Equal(c.wantEnd) {
			t.Errorf("%q End(%s) = %s, want %s", c.frame, c.when, end, c.wantEnd)
		}
	}
}

func TestZeroFrame(t *testing.T) {
	var f Frame
	if !f.IsZero() || !f.Contains(time.Now()) {
		t.Fatal("zero frame must contain everything")
	}
	if _, ok := f.End(time.Now()); ok {
		t.Fatal("zero frame has no edge")
	}
	if p, err := Parse("  "); err != nil || !p.IsZero() {
		t.Fatalf("blank parses to zero: %v %v", p, err)
	}
}
