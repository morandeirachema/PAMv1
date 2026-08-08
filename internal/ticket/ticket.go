// Package ticket validates an ITSM change/incident ticket reference before
// privileged access is granted (Phase 20) — the "no access without an approved
// change ticket" control.
//
// Validation composes two optional checks: a regular-expression format (a
// ServiceNow/Jira number shape) and a live lookup through a Provider. A nil
// Validator accepts any ticket (validation disabled), so callers can hold one
// unconditionally.
//
// Phase 84 added the Provider layer and, with it, the thing the control was
// missing: the ticket is now checked against the PERSON using it. A generic
// webhook could only answer "does this ticket exist", so a valid change number
// admitted anyone who knew one — the gate proved a ticket was valid, never that
// it was yours.
package ticket

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// Validator checks a ticket reference against a format pattern and/or a live
// ITSM lookup.
type Validator struct {
	pattern  *regexp.Regexp
	provider Provider
}

// New builds a Validator from an optional regex pattern and an optional
// provider. When neither is set it returns (nil, nil) — validation is disabled.
func New(pattern string, provider Provider) (*Validator, error) {
	if pattern == "" && provider == nil {
		return nil, nil
	}
	v := &Validator{provider: provider}
	if pattern != "" {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("PAM_TICKET_PATTERN %q: %w", pattern, err)
		}
		v.pattern = re
	}
	return v, nil
}

// Enabled reports whether any validation is configured.
func (v *Validator) Enabled() bool { return v != nil }

// Provider reports the configured provider's name, or "" when only a format
// check is configured. Used for audit details and the startup log.
func (v *Validator) Provider() string {
	if v == nil || v.provider == nil {
		return ""
	}
	return v.provider.Name()
}

// Validate returns nil if ticket authorises actor, else an error describing why.
// A nil Validator accepts any ticket.
//
// The actor is passed even when a provider ignores it, so that turning on a
// first-class connector later is a configuration change and not a code change —
// the value is already threaded through every call site.
func (v *Validator) Validate(ctx context.Context, ticket, actor string) error {
	if v == nil {
		return nil
	}
	if v.pattern != nil && !v.pattern.MatchString(ticket) {
		return fmt.Errorf("ticket %q does not match the required format", ticket)
	}
	if v.provider == nil {
		return nil
	}
	return v.provider.Check(ctx, ticket, actor, time.Now().UTC())
}
