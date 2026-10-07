package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/auditfmt"
	"github.com/morandeirachema/pamv1/internal/store"
)

// digestListCap bounds every list in the digest, so a busy day produces a
// readable mail rather than a dump; the full data stays one API call away.
const digestListCap = 25

// CriticalConnects reads the target.critical_connect rows (Phase 277) out of
// events, in input order.
func CriticalConnects(events []store.AuditEvent) []Connection {
	var out []Connection
	for _, e := range events {
		if e.Action != "target.critical_connect" {
			continue
		}
		out = append(out, Connection{TS: e.TS, User: e.Actor, Target: Field(e.Detail, "target"), Protocol: Field(e.Detail, "protocol")})
	}
	return out
}

// Digest renders the daily report mail: the day's connection statistics,
// every connection to a critical target, and the unused users and targets
// over unusedDays. Every value that came from the trail goes through
// auditfmt.OneLine, because an actor name is not a validated identifier and
// a newline in one must not forge a line of the report.
func Digest(day string, st Stats, critical []Connection, unused Unused, unusedDays int) (subject, body string) {
	subject = fmt.Sprintf("[PAMv1] Daily report %s: %d connections, %d to critical targets", day, st.Total, len(critical))
	var b strings.Builder
	fmt.Fprintf(&b, "PAMv1 daily report for %s\n", day)
	fmt.Fprintf(&b, "Window: %s to %s (UTC)\n\n", st.Since.Format(time.RFC3339), st.Until.Format(time.RFC3339))

	fmt.Fprintf(&b, "CONNECTIONS: %d\n", st.Total)
	for _, g := range []struct {
		title string
		rows  []Count
	}{{"By protocol", st.ByProtocol}, {"Top users", st.ByUser}, {"Top targets", st.ByTarget}} {
		if len(g.rows) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  %s:\n", g.title)
		for i, c := range g.rows {
			if i == digestListCap {
				fmt.Fprintf(&b, "    ... and %d more\n", len(g.rows)-i)
				break
			}
			fmt.Fprintf(&b, "    %-32s %d\n", auditfmt.OneLine(c.Key), c.N)
		}
	}

	fmt.Fprintf(&b, "\nCONNECTIONS TO CRITICAL TARGETS: %d\n", len(critical))
	for i, c := range critical {
		if i == digestListCap {
			fmt.Fprintf(&b, "  ... and %d more\n", len(critical)-i)
			break
		}
		fmt.Fprintf(&b, "  %s  %s -> %s (%s)\n", c.TS.UTC().Format(time.RFC3339),
			auditfmt.OneLine(c.User), auditfmt.OneLine(c.Target), auditfmt.OneLine(c.Protocol))
	}

	fmt.Fprintf(&b, "\nUNUSED IN THE LAST %d DAYS: %d users, %d targets\n", unusedDays, len(unused.Users), len(unused.Targets))
	for i, u := range unused.Users {
		if i == digestListCap {
			fmt.Fprintf(&b, "  ... and %d more users\n", len(unused.Users)-i)
			break
		}
		fmt.Fprintf(&b, "  user   %s (%s)\n", auditfmt.OneLine(u.Username), u.Role)
	}
	for i, t := range unused.Targets {
		if i == digestListCap {
			fmt.Fprintf(&b, "  ... and %d more targets\n", len(unused.Targets)-i)
			break
		}
		mark := ""
		if t.Critical {
			mark = ", critical"
		}
		fmt.Fprintf(&b, "  target %s (%s%s)\n", t.Name, t.Protocol, mark)
	}
	if unused.TooNewUsers+unused.TooNewTargets > 0 {
		fmt.Fprintf(&b, "  (not judged, created inside the window: %d users, %d targets)\n", unused.TooNewUsers, unused.TooNewTargets)
	}
	b.WriteString("\nFull reports: GET /api/reports/connections and /api/reports/unused, or console menu 36.\n")
	return subject, b.String()
}
