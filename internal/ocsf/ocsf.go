// Package ocsf maps pamv1 audit events to the Open Cybersecurity Schema
// Framework (OCSF) so the trail can be forwarded to a SIEM in a vendor-neutral
// shape (Phase 27). It is a faithful SUBSET: routine actions become API Activity
// events (class 6003, category 6) and security-relevant ones — denials, blocked
// commands, break-glass, flagged risk — become Detection Findings (class 2004,
// category 2). The mapping is a pure, table-driven function so it is unit-tested
// without any I/O.
//
// Reference: https://schema.ocsf.io/ (API Activity 6003, Detection Finding 2004).
package ocsf

import (
	"strings"

	"github.com/morandeirachema/pamv1/internal/store"
)

// OCSF category and class identifiers used by this mapping.
const (
	CategoryFindings            = 2
	CategoryApplicationActivity = 6
	ClassDetectionFinding       = 2004
	ClassAPIActivity            = 6003

	// SchemaVersion is the OCSF schema version this output targets.
	SchemaVersion = "1.1.0"
)

// findingActions are audit actions surfaced as OCSF Detection Findings rather
// than routine API Activity: authorization failures, blocked commands,
// emergency access, and behavioral risk flags. Matched by exact action or, for
// the families below, by prefix.
//
// Every name here must be one the code can actually emit, or the rule built on
// it can never fire. `proxy.auth_rate_limited` sat here for a week after Phase
// 52e stopped appending it (both proxies log without auditing on the throttle
// branch, so a flood cannot amplify into the audit trail) — a classification for
// an event that no longer exists, which reads to a SIEM author as coverage.
// `breakglass.unseal_failed` was the mirror image: emitted, and classified
// nowhere.
var findingExact = map[string]bool{
	"authz.denied": true, "access.denied": true, "session.denied": true,
	"session.error": true, "db.session.denied": true, "db.session.error": true,
	"command.blocked": true, "login.failed": true, "proxy.auth_failed": true,
	"credential.decrypt_failed": true, "breakglass.unseal_failed": true,
	"access.ticket_rejected": true, "access.decision_denied": true,
	"broker.tool_call.denied": true, "broker.approval.refused": true,
	"app.secret_denied": true, "session.revoked": true, "session.killed": true,
	// Agent containment (Phase 159): a quarantined or suspended agent identity
	// that is still knocking (internal/api/broker_handlers.go). It needs an
	// entry because `_refused` is not a suffix rule at all — unlike
	// `agent.disable.failed`, which the dotted `.failed` suffix rule in
	// isFinding now covers on its own and which therefore deliberately does NOT
	// appear here. Entries that duplicate a suffix rule are not free: they are a
	// second place to keep in step, and `broker.tool_call.failed` is left out
	// for the same reason.
	"agent.quarantine_refused": true,
}

// isFinding reports whether an action maps to a Detection Finding.
func isFinding(action string) bool {
	if findingExact[action] {
		return true
	}
	switch {
	case strings.HasPrefix(action, "breakglass."),
		strings.HasPrefix(action, "analytics.risk"),
		strings.HasPrefix(action, "analytics.auto"):
		return true
	}
	// Denial and failure suffixes, matched with EITHER separator. pamv1's action
	// vocabulary genuinely uses both — `proxy.auth_failed`, where the outcome is
	// part of one compound verb, and `agent.disable.failed`, where the outcome is
	// its own dotted segment — so a rule that recognised only one of them was
	// always going to lose events. It did: this code required an underscore, and
	// `agent.disable.failed` (an agent suspension that did not stick while
	// offboarding its owner) was emitted as routine API Activity rather than a
	// finding, for exactly as long as nobody noticed the separator.
	//
	// The separator stays REQUIRED. Matching a bare "denied"/"failed" ending
	// would be looser than it looks — any future action whose last word merely
	// finishes in those letters would silently become a Detection Finding, which
	// is the same class of quiet mistake in the other direction.
	//
	// `broker.tool_call.failed` (internal/broker, Phase 161) is one of the names
	// this covers, which is why it is not listed in findingExact above.
	switch {
	case strings.HasSuffix(action, "_denied"), strings.HasSuffix(action, ".denied"),
		strings.HasSuffix(action, "_failed"), strings.HasSuffix(action, ".failed"):
		return true
	}
	return false
}

// activityID classifies an API-activity action into the OCSF activity ids
// (1 Create, 2 Read, 3 Update, 4 Delete, 99 Other).
func activityID(action string) int {
	verb := action
	if i := strings.LastIndex(action, "."); i >= 0 {
		verb = action[i+1:]
	}
	switch {
	case strings.Contains(verb, "create"), strings.Contains(verb, "add"), strings.Contains(verb, "request"), verb == "start":
		return 1
	case strings.Contains(verb, "delete"), strings.Contains(verb, "revoke"), strings.Contains(verb, "remove"), verb == "end", verb == "kill":
		return 4
	case strings.Contains(verb, "reveal"), strings.Contains(verb, "read"), strings.Contains(verb, "list"), strings.Contains(verb, "export"), strings.Contains(verb, "retrieved"), verb == "login", verb == "logout":
		return 2
	case strings.Contains(verb, "rotate"), strings.Contains(verb, "update"), strings.Contains(verb, "reconcile"), strings.Contains(verb, "set"), strings.Contains(verb, "remediate"):
		return 3
	}
	return 99
}

// severityID scores an event on the OCSF severity scale (1 Informational,
// 3 Medium, 4 High, 5 Critical).
func severityID(e store.AuditEvent) int {
	switch {
	case e.Actor == "break-glass" || strings.HasPrefix(e.Action, "breakglass."):
		return 4
	case strings.Contains(e.Detail, "level:critical") || strings.Contains(e.Action, "auto_response"):
		return 5
	case strings.HasPrefix(e.Action, "analytics.risk"):
		return 4
	case isFinding(e.Action):
		return 3
	}
	return 1
}

// statusID is OCSF status (1 Success, 2 Failure): a denial/failure/block is a
// failed operation, everything else succeeded.
func statusID(action string) int {
	if isFinding(action) && !strings.HasPrefix(action, "breakglass.") && !strings.HasPrefix(action, "analytics.") {
		return 2
	}
	return 1
}

// FromAudit maps one pamv1 audit event to an OCSF event object (a JSON-ready
// map). Security-relevant actions become Detection Findings; the rest become API
// Activity. The mapping never invents fields it cannot fill from the event.
func FromAudit(e store.AuditEvent) map[string]any {
	finding := isFinding(e.Action)
	classUID, categoryUID, activity := ClassAPIActivity, CategoryApplicationActivity, activityID(e.Action)
	if finding {
		classUID, categoryUID, activity = ClassDetectionFinding, CategoryFindings, 1 // Create (a finding was generated)
	}
	ev := map[string]any{
		"category_uid": categoryUID,
		"class_uid":    classUID,
		"activity_id":  activity,
		"type_uid":     classUID*100 + activity,
		"severity_id":  severityID(e),
		"status_id":    statusID(e.Action),
		"time":         e.TS.UTC().UnixMilli(),
		"message":      e.Detail,
		"actor": map[string]any{
			"user": map[string]any{"name": e.Actor, "type_id": userTypeID(e.Actor)},
		},
		"metadata": map[string]any{
			"uid":     e.ID,
			"version": SchemaVersion,
			"product": map[string]any{"name": "pamv1", "vendor_name": "pamv1"},
			"labels":  []string{e.Action},
		},
	}
	if finding {
		ev["finding_info"] = map[string]any{"title": e.Action, "uid": e.ID}
	} else {
		ev["api"] = map[string]any{
			"operation": e.Action,
			"service":   map[string]any{"name": "pamv1"},
		}
	}
	return ev
}

// userTypeID classifies the actor: 1 System (machine identities), 2 User.
func userTypeID(actor string) int {
	switch {
	case actor == "system" || strings.HasPrefix(actor, "agent") || strings.HasPrefix(actor, "app:"):
		return 1
	}
	return 2
}

// Events maps a slice of audit events to OCSF, preserving order.
func Events(list []store.AuditEvent) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		out = append(out, FromAudit(e))
	}
	return out
}
