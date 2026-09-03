// Package timeframe parses and evaluates the recurring weekly window a
// standing grant may carry (Phase 240): "Mon-Fri 08:00-18:00 Europe/Madrid".
//
// A frame is days × a daily clock window × a zone. It answers two questions a
// connect gate needs — is the grant usable NOW, and when does the current
// window END — so a session admitted inside a window can be given a
// deadline at its edge rather than outliving the authorization that admitted
// it. Nothing here touches a clock: every function takes the instant it is
// asked about, so tests and the gates pass the same "now".
//
// Grammar (fields separated by whitespace):
//
//	<days> <HH:MM-HH:MM> [<IANA zone>]
//
// days is a comma-separated list of names or ranges — "Mon-Fri", "Sat,Sun",
// "Mon,Wed-Fri", "Sun-Tue" (a range may wrap the week) — or "*" / "daily" for
// every day. The clock window is inclusive of its start and exclusive of its
// end; "00:00-24:00" is a whole day, and an end at or before the start is an
// OVERNIGHT window that starts on a listed day and runs into the next one
// ("Mon-Fri 22:00-06:00" covers Monday 22:00 through Tuesday 06:00, and so
// on, Friday night included). The zone defaults to UTC.
package timeframe

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Frame is a parsed recurring window. The zero Frame is "no restriction".
type Frame struct {
	days  [7]bool // indexed by time.Weekday
	start int     // minutes after local midnight, inclusive
	end   int     // minutes after local midnight, exclusive; <= start means overnight; 1440 is midnight
	loc   *time.Location
	src   string
}

var dayNames = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// Parse parses s; an empty string is the zero Frame (no restriction).
func Parse(s string) (Frame, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Frame{}, nil
	}
	fields := strings.Fields(s)
	if len(fields) < 2 || len(fields) > 3 {
		return Frame{}, fmt.Errorf("time frame must be \"<days> <HH:MM-HH:MM> [zone]\", got %q", s)
	}
	f := Frame{src: s, loc: time.UTC}
	if err := f.parseDays(fields[0]); err != nil {
		return Frame{}, err
	}
	if err := f.parseHours(fields[1]); err != nil {
		return Frame{}, err
	}
	if len(fields) == 3 {
		loc, err := time.LoadLocation(fields[2])
		if err != nil {
			return Frame{}, fmt.Errorf("time frame zone %q: %w", fields[2], err)
		}
		f.loc = loc
	}
	return f, nil
}

func (f *Frame) parseDays(spec string) error {
	if spec == "*" || strings.EqualFold(spec, "daily") || strings.EqualFold(spec, "all") {
		for i := range f.days {
			f.days[i] = true
		}
		return nil
	}
	for _, tok := range strings.Split(spec, ",") {
		lo, hi, ok := strings.Cut(tok, "-")
		from, err := parseDay(lo)
		if err != nil {
			return err
		}
		to := from
		if ok {
			if to, err = parseDay(hi); err != nil {
				return err
			}
		}
		for d := from; ; d = (d + 1) % 7 {
			f.days[d] = true
			if d == to {
				break
			}
		}
	}
	return nil
}

func parseDay(s string) (time.Weekday, error) {
	d, ok := dayNames[strings.ToLower(strings.TrimSpace(s))]
	if !ok {
		return 0, fmt.Errorf("time frame day %q: want Mon..Sun", s)
	}
	return d, nil
}

func (f *Frame) parseHours(spec string) error {
	lo, hi, ok := strings.Cut(spec, "-")
	if !ok {
		return fmt.Errorf("time frame hours %q: want HH:MM-HH:MM", spec)
	}
	start, err := parseClock(lo)
	if err != nil {
		return err
	}
	end, err := parseClock(hi)
	if err != nil {
		return err
	}
	if start == 1440 {
		return fmt.Errorf("time frame hours %q: a window cannot start at 24:00", spec)
	}
	f.start, f.end = start, end
	return nil
}

func parseClock(s string) (int, error) {
	h, m, ok := strings.Cut(s, ":")
	if !ok {
		return 0, fmt.Errorf("time frame clock %q: want HH:MM", s)
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hh < 0 || hh > 24 || mm < 0 || mm > 59 || (hh == 24 && mm != 0) {
		return 0, fmt.Errorf("time frame clock %q: want HH:MM (00:00..24:00)", s)
	}
	return hh*60 + mm, nil
}

// IsZero reports whether f is the unrestricted zero Frame.
func (f Frame) IsZero() bool { return f.src == "" }

// String returns the source text the frame was parsed from.
func (f Frame) String() string { return f.src }

// overnight reports whether the daily window crosses midnight.
func (f Frame) overnight() bool { return f.end <= f.start }

// Contains reports whether t falls inside the frame. The zero Frame contains
// every instant.
func (f Frame) Contains(t time.Time) bool {
	if f.IsZero() {
		return true
	}
	lt := t.In(f.loc)
	m := lt.Hour()*60 + lt.Minute()
	d := lt.Weekday()
	if !f.overnight() {
		return f.days[d] && m >= f.start && m < f.end
	}
	if f.days[d] && m >= f.start {
		return true // the evening leg, on a listed day
	}
	prev := (d + 6) % 7
	return f.days[prev] && m < f.end // the morning leg, spilling over from a listed day
}

// End returns the instant the window containing t closes. ok is false when t
// is outside the frame, or the frame is the zero Frame (no edge to report).
func (f Frame) End(t time.Time) (end time.Time, ok bool) {
	if f.IsZero() || !f.Contains(t) {
		return time.Time{}, false
	}
	lt := t.In(f.loc)
	y, mo, d := lt.Date()
	midnight := time.Date(y, mo, d, 0, 0, 0, 0, f.loc)
	m := lt.Hour()*60 + lt.Minute()
	switch {
	case !f.overnight():
		return midnight.Add(time.Duration(f.end) * time.Minute), true
	case m >= f.start:
		// Evening leg: the window ends tomorrow at f.end.
		return midnight.AddDate(0, 0, 1).Add(time.Duration(f.end) * time.Minute), true
	default:
		// Morning leg: the window ends today at f.end.
		return midnight.Add(time.Duration(f.end) * time.Minute), true
	}
}
