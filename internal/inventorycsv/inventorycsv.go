// Package inventorycsv is the file format of the bulk inventory export and
// import (Phase 278, Tier 10 row 9): one CSV per object class, a header row
// naming the columns, objects referenced by NAME rather than by database id
// so a file moves between deployments.
//
// It is format only. Validation of a row's values belongs to the API's own
// create handlers, which the import replays every row through — a value this
// package passes is not thereby valid, it is merely well-formed CSV under a
// known header.
//
// Secrets are never exported. The credentials class carries a `secret`
// column so an export doubles as an import template, and it is always empty
// on the way out.
package inventorycsv

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/morandeirachema/pamv1/internal/csvcell"
)

// MaxRows bounds one import. A bastion's inventory is thousands of rows, not
// millions, and each row is a full create with its own audit row; a larger
// load belongs in several files.
const MaxRows = 5000

// Class is one importable/exportable object class.
type Class struct {
	Name string
	// Columns is the header, in export order.
	Columns []string
	// Required are the columns an import file must carry.
	Required []string
}

// The classes, in the order an import of a whole inventory must follow:
// safes and targets first, then what refers to them.
var (
	Safes = Class{Name: "safes",
		Columns:  []string{"name", "description", "require_approval", "min_approvers", "require_session_mfa", "approval_tiers"},
		Required: []string{"name"}}
	Targets = Class{Name: "targets",
		Columns: []string{"name", "host", "port", "os_type", "protocol", "require_approval", "require_session_mfa", "critical",
			"labels", "approval_tiers", "rights", "rdp_clipboard", "rdp_clipboard_audit"},
		Required: []string{"name", "host", "os_type", "protocol"}}
	Credentials = Class{Name: "credentials",
		Columns:  []string{"target", "username", "secret_type", "provisioner", "secret"},
		Required: []string{"target", "username"}}
	Users = Class{Name: "users",
		Columns:  []string{"username", "role", "ip_allowlist", "device_fingerprint", "slack_user_id", "manager", "token_ttl_hours"},
		Required: []string{"username", "role"}}
	Grants = Class{Name: "grants",
		Columns:  []string{"target", "subject_type", "subject", "credential_user", "expires_at", "time_frame", "rights"},
		Required: []string{"target", "subject_type", "subject"}}
)

// All is every class in dependency order.
var All = []Class{Safes, Targets, Credentials, Users, Grants}

// Row is one data row of an import, keyed by column name.
type Row struct {
	// Line is the 1-based line of the row in the file (the header is 1),
	// which is what an operator fixing the file needs.
	Line   int
	Fields map[string]string
}

// Get returns a column's value, "" when the file does not carry it.
func (r Row) Get(col string) string { return r.Fields[col] }

// Read parses an import file for class c. The header must name only columns
// of c, each once, and every required one; an empty file, an unknown column,
// a ragged row or more than MaxRows rows is an error for the whole file —
// nothing is imported from a file that does not parse. Cells are trimmed and
// a csvcell.Neutralize prefix is removed, so an export imports back as it was.
func Read(c Class, r io.Reader) ([]Row, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = 0 // every row as wide as the header
	header, err := cr.Read()
	if errors.Is(err, io.EOF) {
		return nil, errors.New("empty file: a header row is required")
	}
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	known := map[string]bool{}
	for _, col := range c.Columns {
		known[col] = true
	}
	seen := map[string]bool{}
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))
		switch {
		case !known[h]:
			return nil, fmt.Errorf("unknown column %q for %s (columns: %s)", h, c.Name, strings.Join(c.Columns, ","))
		case seen[h]:
			return nil, fmt.Errorf("column %q appears twice", h)
		}
		seen[h] = true
		header[i] = h
	}
	for _, req := range c.Required {
		if !seen[req] {
			return nil, fmt.Errorf("missing required column %q", req)
		}
	}
	var rows []Row
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		line, _ := cr.FieldPos(0)
		if len(rows) == MaxRows {
			return nil, fmt.Errorf("more than %d rows; split the file", MaxRows)
		}
		f := make(map[string]string, len(header))
		blank := true
		for i, v := range rec {
			v = csvcell.Restore(strings.TrimSpace(v))
			f[header[i]] = v
			if v != "" {
				blank = false
			}
		}
		if blank {
			continue // a trailing empty line from a spreadsheet is not a row
		}
		rows = append(rows, Row{Line: line, Fields: f})
	}
	return rows, nil
}

// Write emits c's header and rows (each in c.Columns order), every cell
// neutralised against formula execution.
func Write(w io.Writer, c Class, rows [][]string) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(c.Columns); err != nil {
		return err
	}
	for _, row := range rows {
		if len(row) != len(c.Columns) {
			return fmt.Errorf("%s row has %d cells, want %d", c.Name, len(row), len(c.Columns))
		}
		out := make([]string, len(row))
		for i, v := range row {
			out[i] = csvcell.Neutralize(v)
		}
		if err := cw.Write(out); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// Bool parses a boolean cell: empty, false, no and 0 are false; true, yes
// and 1 are true (any case). Anything else is an error rather than a guess,
// because these columns are security policy.
func Bool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "", "false", "no", "0":
		return false, nil
	case "true", "yes", "1":
		return true, nil
	}
	return false, fmt.Errorf("%q is not a boolean (true/false)", s)
}

// Int parses an integer cell; empty is 0.
func Int(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a whole number", s)
	}
	return n, nil
}

// FormatBool renders a boolean cell the way Bool reads it back.
func FormatBool(b bool) string { return strconv.FormatBool(b) }
