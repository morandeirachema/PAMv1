package tds

import "testing"

// The three Parse* entry points read bytes straight off an operator's SQL Server
// client connection — untrusted, attacker-influenced input the proxy must survive.
// These fuzz targets assert the security-critical property of any wire parser:
// it never panics and always terminates, on any input. A crash or an infinite
// loop here is a denial of service on the whole SQL Server proxy. The corpus
// (testdata/fuzz/) is replayed as a normal test on every CI run, so a regression
// that reintroduces a crasher fails the build even without an explicit fuzz run.

// FuzzParsePreLogin fuzzes the PRELOGIN option-table parser — the first packet a
// client sends, whose option entries carry attacker-chosen offsets and lengths
// into the payload.
func FuzzParsePreLogin(f *testing.F) {
	f.Add([]byte{0xFF})                                     // bare terminator (the minimal valid table)
	f.Add([]byte{0x00, 0x00, 0x06, 0x00, 0x01, 0xFF, 0x42}) // one option pointing at a 1-byte value
	f.Add([]byte{0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})       // an offset/length past the payload
	f.Add([]byte{})                                         // empty (unterminated)
	f.Fuzz(func(t *testing.T, data []byte) {
		pl, err := ParsePreLogin(data)
		if err != nil {
			return
		}
		// A successful parse must round-trip through Encode without panicking and
		// must re-parse to an equal option set — the parser and encoder cannot
		// disagree about the wire shape.
		if pl == nil {
			t.Fatal("ParsePreLogin returned nil, nil")
		}
		again, err := ParsePreLogin(pl.Encode())
		if err != nil {
			t.Fatalf("re-parsing an encoded prelogin failed: %v", err)
		}
		if len(again.Order) != len(pl.Order) {
			t.Fatalf("round-trip changed the option count: %d -> %d", len(pl.Order), len(again.Order))
		}
	})
}

// FuzzParseSQLBatch fuzzes the SQL-batch parser (header stream + UCS-2 statement
// text), the path every plain `SELECT`/`INSERT` takes to the audit trail.
func FuzzParseSQLBatch(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})                                  // a zero-length header stream, no SQL
	f.Add([]byte{0x16, 0x00, 0x00, 0x00, 'S', 0x00, 'E', 0x00, 'L', 0x00}) // a header + partial UCS-2 text
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseSQLBatch(data)
	})
}

// FuzzParseRPC fuzzes the RPC parser — the most complex path, walking batched
// stored-procedure calls and recovering SQL from typed parameters, all
// length-prefixed with attacker-chosen counts.
func FuzzParseRPC(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})                         // empty header stream, no calls
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x0A, 0x00}) // a ProcID call header
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseRPC(data)
	})
}
