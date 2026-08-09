// Package auditfmt formats untrusted values for the audit trail.
//
// An audit detail is a space-separated `key:value` string, read by humans in the
// console and parsed by the SIEM forwarder. Interpolating raw input into one lets
// whoever controls that input invent fields: a login of
// `alice target:prod-db action:approved` reads as three legitimate keys, and a
// clipboard mimetype of `text/plain bytes:0` makes a megabyte of exfiltrated data
// read as an empty transfer.
//
// This package exists because the fix kept being written per-package. Two
// byte-identical copies of Field lived in internal/api and internal/proxy, and
// internal/guacd — which also writes audit details — had neither, so the
// clipboard's mimetype went to the trail unquoted straight off the wire. A
// sanitiser that has to be re-typed in every package that needs it will be
// missing from the next one.
package auditfmt

import (
	"strconv"
	"strings"
)

// OneLine replaces CR and LF with spaces so an untrusted field cannot inject an
// extra line into a line-oriented sink — a syslog record, an SMTP header, a CEF
// or LEEF event. It is the flattening twin of Field: Field quotes a value going
// into pamv1's own audit detail, OneLine flattens one going out to an external
// line protocol. Callers that also need metacharacter escaping (CEF's \ and |)
// layer it on top.
func OneLine(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// Field makes an untrusted string safe to place in an audit detail or actor:
// bounded in length and quoted, so embedded newlines, quotes and forged
// `key:value` pairs cannot restructure the record around it.
//
// Bounding matters as much as quoting. A quoted field is unforgeable but still
// unbounded, and an audit row whose size an attacker chooses is an audit trail
// they can flood.
//
// The limit is in bytes, so a multi-byte rune can be cut in half; strconv.Quote
// renders the remainder as \xNN escapes, which is safe and visibly truncated.
func Field(s string, limit int) string {
	if len(s) > limit {
		s = s[:limit] + "…"
	}
	return strconv.Quote(s)
}
