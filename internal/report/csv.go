package report

import (
	"encoding/csv"
	"io"
	"strings"
	"time"
)

// WriteConnectionsCSV writes one row per connection — ts (RFC 3339, UTC),
// user, target, protocol — under a header row. Every cell goes through
// csvCell, so a value a spreadsheet would execute as a formula is neutralised.
func WriteConnectionsCSV(w io.Writer, conns []Connection) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"ts", "user", "target", "protocol"}); err != nil {
		return err
	}
	for _, c := range conns {
		row := []string{c.TS.UTC().Format(time.RFC3339), csvCell(c.User), csvCell(c.Target), csvCell(c.Protocol)}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvCell defuses CSV/formula injection (CWE-1236). The user column is an
// actor name, which for a guest or a directory identity is not a validated
// identifier; a cell beginning with = + - @ or a tab/CR is read as a formula
// by common spreadsheets, so it is prefixed with a single quote, the OWASP
// recommendation. encoding/csv already quotes commas, quotes and newlines.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
