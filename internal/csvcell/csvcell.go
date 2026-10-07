// Package csvcell defuses CSV/formula injection (CWE-1236) in one place, for
// every CSV PAMv1 writes and reads back: the connection report (Phase 277)
// and the inventory export/import (Phase 278).
//
// A cell beginning with = + - @ or a tab/CR is executed as a formula by
// common spreadsheets, so Neutralize prefixes it with a single quote — the
// OWASP recommendation. Restore undoes exactly that prefix on import, so a
// file exported here and imported back yields the original value; a value
// that merely starts with a quote is left alone.
package csvcell

const formulaLeads = "=+-@\t\r"

func isFormulaLead(b byte) bool {
	for i := 0; i < len(formulaLeads); i++ {
		if formulaLeads[i] == b {
			return true
		}
	}
	return false
}

// Neutralize returns s safe to place in a spreadsheet cell.
func Neutralize(s string) string {
	if s != "" && isFormulaLead(s[0]) {
		return "'" + s
	}
	return s
}

// Restore reverses Neutralize: a quote followed by a formula lead is dropped.
func Restore(s string) string {
	if len(s) >= 2 && s[0] == '\'' && isFormulaLead(s[1]) {
		return s[1:]
	}
	return s
}
