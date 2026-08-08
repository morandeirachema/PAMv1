package api

import (
	"fmt"
	"net/http"
	"unicode"
)

// nameMaxLen bounds every human-chosen name the API accepts.
//
// The bound is not about storage — Postgres would take far more — but about the
// audit trail. A name is copied into audit details, alert payloads and SIEM
// records, and a value whose length the submitter chooses is a row whose size
// they choose. 128 characters is longer than any real target, safe or user name
// and short enough that a record stays readable.
const nameMaxLen = 128

// validName reports why s is unfit to be a name, or nil if it is fine.
//
// Two characters are refused, and only two, because a name is a human label and
// the point is to stay permissive:
//
//   - **Control characters**, including newline, carriage return and tab. A
//     newline inside a name splits one audit record into what reads as two, and
//     no legitimate name contains one.
//   - **The colon.** Audit details are space-separated `key:value` text parsed by
//     the console and the SIEM forwarder, so a name carrying a colon can invent
//     fields in the record of *other people's* sessions — a target named
//     `prod-db action:approved reason:emergency` appears in every operator's
//     session events on that target, not just its creator's.
//
// Everything else is allowed: spaces, dots, hyphens, slashes, accents, CJK. A
// name with a space but no colon cannot forge a `key:value` pair, so there is no
// reason to forbid "Prod DB 01".
//
// This is the boundary half of the fix. Values that legitimately contain colons
// — an IPv6 host, a SPIFFE ID — cannot be validated this way and are quoted at
// their sinks with auditfmt.Field instead. See docs/SECURITY-GAPS.md finding BD.
func validName(s string) error {
	if s == "" {
		return fmt.Errorf("must not be empty")
	}
	if len(s) > nameMaxLen {
		return fmt.Errorf("must be at most %d bytes (got %d)", nameMaxLen, len(s))
	}
	for _, r := range s {
		switch {
		case r == ':':
			return fmt.Errorf("must not contain \":\" — it separates fields in the audit trail")
		case unicode.IsControl(r):
			return fmt.Errorf("must not contain control characters")
		}
	}
	return nil
}

// checkName validates one named field and writes the 422 itself, so a handler
// reads as one line per field. It reports whether the value is acceptable.
//
// Empty is rejected here too, which means it also replaces the "X is required"
// check at every call site rather than sitting behind one.
func checkName(w http.ResponseWriter, field, value string) bool {
	if err := validName(value); err != nil {
		writeError(w, http.StatusUnprocessableEntity, field+" "+err.Error())
		return false
	}
	return true
}

// checkOptionalName is checkName for a field that may be left unset. An empty
// value passes; a present one is held to the same rule.
func checkOptionalName(w http.ResponseWriter, field, value string) bool {
	if value == "" {
		return true
	}
	return checkName(w, field, value)
}
